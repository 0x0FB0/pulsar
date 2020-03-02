import base64
import os
from celery.utils.log import get_task_logger
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.views import generic
from django_filters.rest_framework import DjangoFilterBackend
from markdown import markdown
from rest_framework import filters
from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response as RestResponse
from xhtml2pdf import pisa
from .celery import app
from .modules.scanner_utils import checkForNewDomains, checkForNewVuln, calc_asset_by_task, Sandbox, scan_settings
from .serializers import *
from .tasks import run_scan, dispatch_scan
from django.utils import timezone

logger = get_task_logger(__name__)

class IndexView(LoginRequiredMixin, generic.TemplateView):
    """Generic view for Vue.js template."""
    template_name = 'pulsar_templates/index.html'
    paginate_by = 10

    def get_queryset(self):
        return

class PageNotFoundView(generic.TemplateView):
    """Generic view for 404 template."""
    template_name = 'pulsar_templates/404.html'

class BaseViewSet(viewsets.GenericViewSet):
    """Generic view set with strong user and group access filtering."""
    def model_field_exists(self, cls, field):
        """Check if model field exist."""
        try:
            cls._meta.get_field(field)
            return True
        except models.FieldDoesNotExist:
            return False

    def get_object(self):
        """Retrieve accessible object."""
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        """Filter object ownership by ownership and collaboration groups."""
        user = self.request.user
        assets = AssetInstance.objects.filter(Q(owner=user)|Q(collaborations__in=user.groups.all()))
        doms = DomainInstance.objects.filter(asset__in=assets)
        ips = IPv4AddrInstance.objects.filter(domain__in=doms)
        proto_model = self.serializer_class.Meta.model

        if self.model_field_exists(proto_model, 'asset'):
            return self.serializer_class.Meta.model.objects.filter(asset__in=assets)
        elif self.model_field_exists(proto_model, 'owner'):
            if self.model_field_exists(proto_model, 'collaborations'):
                return self.serializer_class.Meta.model.objects.filter(Q(owner=user)
                                                                       |Q(collaborations__in=user.groups.all()))
            else:
                return self.serializer_class.Meta.model.objects.filter(owner=self.request.user)
        elif self.model_field_exists(proto_model, 'domain'):
                return self.serializer_class.Meta.model.objects.filter(domain__in=doms)
        elif self.model_field_exists(proto_model, 'ip'):
                return self.serializer_class.Meta.model.objects.filter(ip__in=ips)
        else:
            return self.serializer_class.Meta.model.objects.all()

class LRUDViewSet(mixins.ListModelMixin,
                    mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    BaseViewSet):
    """List, Retrieve, Update, Destroy views."""
    pass

class LRCUDViewSet(mixins.ListModelMixin,
                    mixins.CreateModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    BaseViewSet):
    """List, Create, Destroy views."""
    pass

class LRUViewSet(mixins.ListModelMixin,
                 mixins.RetrieveModelMixin,
                 mixins.UpdateModelMixin,
                 BaseViewSet):
    """List, Retrieve, Update views."""
    pass

class LRDViewSet(mixins.ListModelMixin,
                 mixins.RetrieveModelMixin,
                 mixins.DestroyModelMixin,
                 BaseViewSet):
    """List, Retrieve, Destroy views."""
    pass

class RViewSet(mixins.ListModelMixin,
                 BaseViewSet):
    """List view."""
    pass

def get_markdown(asset):
    """Markdown report generation helper method."""
    last_scan = ScanInstance.objects.filter(asset=asset).order_by('-scanned_date').first()
    if last_scan:
        policy = last_scan.policy
        last_task = last_scan.last_task
        markdown = (
            '![Pulsar](/portal/pulsar/static/img/pulsar.png "Pulsar")\n\n'
            f'# Asset Scan Report\n\n'
            f'## Scan Details\n\n'
            f'|  |  |\n'
            f'|--|--|\n'
            f'| Scan ID | {str(last_scan.id)} |\n'
            f'| Execution Date | {str(last_scan.scanned_date)} |\n'
            f'| Creation Date | {str(last_scan.created_date)} |\n'
            f'| Score | **{str(round(last_scan.total_score, 2))}** |\n'
            f'| Task ID | {str(last_task.id)} |\n'
            f'| Active Scan | {str(policy.active)} |\n'
            f'| Strict Scope | {str(policy.inscope)} |\n'
            f'| Recursive | {str(policy.inscope)} |\n'
            f'| Manual | {str(not policy.repeat)} |\n\n'
            f'## Asset Details\n\n'
            f'|  |  |\n'
            f'|--|--|\n'
            f'| Name | **{str(asset.name.upper())}** |\n'
            f'| Domain| {str(asset.domain)} |\n'
            f'| Current Score | **{str(round(asset.current_score, 2))}** |\n\n'
            f'## Discovered domains\n\n'
            f'---\n\n'
        )
        doms = DomainInstance.objects.filter(last_task=last_task, false_positive=False)
        for dom in doms:
            ips = ', '.join([ip['ip'] for ip in IPv4AddrInstance.objects.filter(domain=dom).values('ip')])
            markdown += (
                f'### {str(dom.fqdn)}\n\n'
                f'---\n\n'
                f'|  |  |\n'
                f'|--|--|\n'
                f'| FQDN | **{str(dom.fqdn)}** |\n'
                f'| Country | {str(dom.country)} |\n'
                f'| IPv4 | {str(ips)} |\n'
                f'| Discovery Plugin | {str(dom.plugin)} |\n'
                f'| Discovery Date | {str(dom.found_date)} |\n'
                f'| Total Score | **{str(round(dom.total_score, 2))}** |\n'
                f'| Confidence | {str(round(dom.confidence, 2))} |\n\n'
                f'### Domain Vulnerabilities\n\n'
            )
            vulns = VulnInstance.objects.filter(domain=dom, false_positive=False)
            if len(vulns) > 0:
                for vuln in vulns:
                    markdown += (
                        f'#### **{str(vuln.name)}**\n\n'
                        f'|  |  |\n'
                        f'|--|--|\n'
                        f'| CVSS | {str(vuln.cvss)} |\n'
                        f'| Score| **{str(round(vuln.score, 2))}** |\n'
                        f'| Confidence | {str(round(vuln.confidence, 2))} |\n'
                        f'| Discovery Plugin | {str(vuln.plugin)} |\n'
                        f'| Discovery Date | {str(vuln.found_date)} |\n'
                        f'| Service | {str(vuln.service)} |\n'
                        f'| Description | {str(vuln.description)} |\n'
                        f'| Reference | [External Link]({str(vuln.reference)}) |\n\n'
                    )
            markdown += "---\n\n"
        return markdown
    else:
        return False

def get_pdf(md):
    """PDF generation helper method."""
    fname = str(uuid.uuid4())
    resultFile = open(fname, "w+b")
    pisaStatus = pisa.CreatePDF(
        markdown(md, extensions=['tables', 'fenced_code']),
        dest=resultFile)
    resultFile.close()
    with open(fname, 'rb') as f:
        b64pdf = base64.b64encode(f.read())
    os.remove(fname)
    return b64pdf


class Statistics(viewsets.GenericViewSet):
    """
    Generic database statistics view.

    list:
    Retrieve count of scanner related database objects.
    """
    def list(self, request, *args, **kwargs):
        """
        get:
        Retrieve count of scanner related database objects.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        scans = ScanInstance.objects.filter(asset__in=assets)
        domains = DomainInstance.objects.filter(asset__in=assets)
        ips = IPv4AddrInstance.objects.filter(domain__in=domains)
        services = ServiceInstance.objects.filter(ip__in=ips)
        vulns = VulnInstance.objects.filter(asset__in=assets)
        return RestResponse({"Assets": assets.count(),
                             "Scans": scans.count(),
                             "Domains": domains.count(),
                             "IPs": ips.count(),
                             "Services": services.count(),
                             "Vulnerabilities": vulns.count()
                             })

class User(viewsets.GenericViewSet):
    """
    Generic pulsar portal user view.

    list:
    Retrieve portal user details.
    """
    queryset = PortalUser.objects.all()
    serializer_class = PortalUserSerializer
    def list(self, request, *args, **kwargs):
        """
        get:
        Retrieve portal user details.
        """
        user = PortalUser.objects.get(id=request.user.id)
        serializer = PortalUserSerializer(user, many=False, context={'request': request})
        return RestResponse(serializer.data)

class Asset(mixins.CreateModelMixin,
            LRUDViewSet):
    """
    Asset instance base view.

    retrieve:
    Retrieve asset instance.

    destroy:
    Remove asset instance and all related database objects.

    detailed:
    Retrieve asset instance and all related database objects details. (custom action)

    create_scan:
    Create a new scan instance for asset including all required objects. (custom action)

    task_history:
    Retrieve all tasks related to asset. (custom action)

    delete_schedule:
    Remove all periodic tasks related to asset. (custom action)

    recalculate:
    Recalculate score for asset and all related objects. (custom action)

    markdown:
    Retrieve asset report in markdown format. (custom action)

    pdf:
    Retrieve an asset report in PDF format. (custom action)

    """
    filter_backends = (filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter)
    search_fields = ['domain', 'name']
    queryset = AssetInstance.objects.all()
    serializer_class = AssetInstanceSerializer

    def retrieve(self, request, pk=None):
        """
        get:
        Retrieve asset instance.
        """
        asset = AssetInstance.objects.get(id=pk)
        serializer = AssetDetailSerializer(asset, many=False, context={'request': request})
        return RestResponse(serializer.data)

    def destroy(self, request, pk=None):
        """
        delete:
        Remove asset instance and all related database objects.
        """
        try:
            instance = self.get_object()
            pt = PeriodicTask.objects.filter(name__contains='ps-'+str(instance.id))
            pt.update(enabled=False)
            pt.delete()
            ScanTask.objects.filter(asset=instance).delete()
            DomainInstance.objects.filter(asset=instance).delete()
            VulnInstance.objects.filter(asset=instance).delete()
            ScanInstance.objects.filter(asset=instance).delete()
            self.perform_destroy(instance)
        except Http404:
            pass
        return RestResponse(status=status.HTTP_204_NO_CONTENT)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    @action(methods=['get'], detail=False, url_name='detailed')
    def detailed(self, request, pk=None):
        """
        get:
        Retrieve asset instance and all related database objects details.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))
        serializer = AssetDetailSerializer(asset, many=True, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='markdown')
    def markdown(self, request, pk=None):
        """
        get:
        Retrieve asset report in markdown format.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all())) \
            .get(id=pk)
        markdown = get_markdown(asset)
        if markdown:
            b64_md = base64.b64encode(markdown.encode('utf-8'))
            return RestResponse({"markdown": b64_md.decode('utf-8')})
        else:
            return RestResponse(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True, url_name='pdf')
    def pdf(self, request, pk=None):
        """
        get:
        Retrieve an asset report in PDF format.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all())) \
            .get(id=pk)
        markdown = get_markdown(asset)
        if markdown:
            b64pdf = get_pdf(markdown)
            return RestResponse({"pdf": b64pdf})
        else:
            return RestResponse(status=status.HTTP_204_NO_CONTENT)


    @action(methods=['get'], detail=True, url_name='create_scan')
    def create_scan(self, request, pk=None):
        """
        get:
        Create scan for corresponding asset.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))\
            .get(id=pk)
        new_task = ScanTask.objects.create(asset=asset)
        last_scan = ScanInstance.objects.filter(asset=asset).order_by('-scanned_date').first()
        if last_scan:
            policy = last_scan.policy
            policy.pk = None
            policy.save()
        else:
            policy = ScanPolicy.objects.create()
        scaninst = ScanInstance.objects.create(asset=asset, policy=policy, last_task=new_task)
        serializer = ScanInstanceSerializer(scaninst, many=False, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='task_history')
    def task_history(self, request, pk=None):
        """
        get:
        Retrieve related task objects.
        """
        self.filter_backends = []
        self.serializer_class = ScanTaskSerializer
        asset = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))\
            .get(id=pk)
        tasks = ScanTask.objects.filter(asset=str(asset.id))
        serializer = ScanTaskSerializer(tasks, many=True, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='delete_schedule')
    def delete_schedule(self, request, pk=None):
        """
        get:
        Remove related periodic tasks.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))\
            .get(id=pk)
        pt = PeriodicTask.objects.filter(name__contains='ps-'+str(asset.id))
        pt.update(enabled=False)
        pt.delete()
        return RestResponse(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True, url_name='recalculate')
    def recalculate(self, request, pk=None):
        """
        get:
        Recalculate score for asset and all related objects.
        """
        asset = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))\
            .get(id=pk)
        print("[i] calc: FOR %s" % asset.name)
        scan = ScanInstance.objects.filter(asset=asset).order_by('-scanned_date').first()
        total_score = calc_asset_by_task(str(scan.last_task.id))
        return RestResponse({"success": True, "asset_score": total_score})

class Task(LRDViewSet):
    """
    Scan task instance base view.

    destroy:
    Remove scan task instance and all related database objects.

    run:
    Launch scan task. (custom action)

    active:
    List scan tasks in progress. (custom action)

    status:
    Retrieve scan task status and progress. (custom action)

    new:
    Create an empty scan scan task instance. (custom action)
    """

    filter_backends = (DjangoFilterBackend, filters.OrderingFilter)
    filterset_fields = ['state', 'result']
    ordering_fields = ['created_date', 'exec_date']
    queryset = ScanTask.objects.all()
    serializer_class = ScanTaskSerializer

    def destroy(self, request, pk=None):
        """
        delete:
        Remove scan task instance and all related database objects.
        """
        try:
            instance = self.get_object()
            app.control.revoke(instance.id, terminate=True)
            scan = ScanInstance.objects.filter(last_task=instance)
            ScanPolicy.objects.filter(id=scan.policy.id).delete()
            scan.delete()
            try:
                current = instance.get_queue_progress()['current'].lower()
                for heavy in scan_settings['heavy_processes']:
                    if heavy in current:
                        sandbox = Sandbox()
                        sandbox.connect()
                        sandbox.exec('rm /opt/scan_mutex')
                        break
            except Exception as e:
                pass
            self.perform_destroy(instance)
        except Http404:
            pass
        return RestResponse(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True, url_name='run')
    def run(self, request, pk=None):
        """
        get:
        Launch scan task.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))
        task = ScanTask.objects.filter(asset__in=assets).get(id=pk)
        AssetInstance.objects.filter(id=task.asset.id).update(current_score=-1.0)
        scan = ScanInstance.objects.get(last_task=task)
        task.exec_date=timezone.now()
        task.save()
        str_task_id = str(task.id)
        str_queue_id = str(task.queue_id)
        dispatch_scan(task.asset.id, request.user.id, scan.policy)
        run_scan.apply_async(
            (str_task_id, str_queue_id),
            task_id=str_queue_id
        )
        return RestResponse({"success": True, "task": task.id, "queue": task.queue_id})

    @action(methods=['get'], detail=False, url_name='status')
    def active(self, request):
        """
        get:
        List scan tasks in progress.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user)|Q(collaborations__in=request.user.groups.all()))
        tasks = ScanTask.objects.filter(asset__in=assets, state='STARTED')
        serializer = ScanTaskSerializer(tasks, many=True, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='status')
    def status(self, request, pk=None):
        """
        get:
        Retrieve scan task status and progress.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        task = ScanTask.objects.filter(asset__in=assets).get(id=pk)
        state = task.get_queue_state()
        progress = task.get_queue_progress()
        print("%s %s" % (repr(state), repr(progress)))
        return RestResponse({"state": state, "progress": progress})

    @action(methods=['get'], detail=True, url_name='change')
    def new(self, request, pk=None):
        """
        get:
        Create an empty scan scan task instance.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        task = ScanTask.objects.filter(asset__in=assets).get(id=pk)
        new_doms = checkForNewDomains(task.id)
        new_vulns = checkForNewVuln(task.id)
        return RestResponse({"domains": new_doms, "vulnerabilities": new_vulns})


class Domain(LRCUDViewSet):
    """
    Domain instance base view.

    retrieve:
    Retrieve domain instance details.

    active:
    List domain instances corresponding to last scan task. (custom action)
    """
    filter_backends = (filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter)
    search_fields = ['fqdn', 'plugin']
    filterset_fields = ['false_positive', 'total_score', 'confidence', 'asset', 'country']
    ordering_fields = ['total_score', 'confidence', 'found_date']
    queryset = DomainInstance.objects.all()
    serializer_class = DomainInstanceSerializer

    def retrieve(self, request, pk=None):
        """
        get:
        Retrieve domain instance details.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        dom = DomainInstance.objects.filter(asset__in=assets).get(id=pk)
        serializer = DomainDetailSerializer(dom, many=False, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=False, url_name='status')
    def active(self, request):
        """
        get:
        List domain instances corresponding to last scan task.
        """
        lasttasks = []
        for asset in AssetInstance.objects.filter(Q(owner=request.user)
                                                  |Q(collaborations__in=request.user.groups.all())):
            si = ScanInstance.objects.filter(asset=asset,
                                             status='SCANNED')\
                .order_by('-scanned_date')\
                .first()
            if (si):
                try:
                    id = si.last_task.id
                    lasttasks.append(id)
                except Exception:
                    pass
        domains = DomainInstance.objects.filter(last_task__id__in=lasttasks).order_by('-total_score')

        serializer = DomainInstanceSerializer(domains, many=True, context={'request': request})
        return RestResponse(serializer.data)

class IPv4Addr(LRUViewSet):
    """
    IPv4 address instance base view.

    Basic list, retrieve and update view set.
    """
    filter_backends = (filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter)
    search_fields = ['desc', 'ip']
    filterset_fields = ['asn', 'score', 'cidr', 'domain', 'asset']
    ordering_fields = ['score', 'asn']
    queryset = IPv4AddrInstance.objects.all()
    serializer_class = IPv4AddressSerializer

class Vulnerability(LRUViewSet):
    """
    Vulnerability instance base view.

    Basic list, retrieve and update view set.
    """
    filter_backends = (filters.SearchFilter, DjangoFilterBackend, filters.OrderingFilter)
    search_fields = ['description', 'plugin']
    filterset_fields = ['false_positive', 'score', 'confidence', 'ip', 'asset', 'info']
    ordering_fields = ['score', 'confidence', 'found_date']
    queryset = VulnInstance.objects.all()
    serializer_class = VulnInstanceSerializer

class Scan(LRUDViewSet):
    """
    Scan instance base view.

    destroy:
    Remove scan instance and all related database objects.

    domain_list:
    List domains related to selected scan instance. (custom action)

    vuln_list:
    List vulnerabilities related to selected scan instance. (custom action)

    run:
    Launch selected scan instance.  (custom action)
    """
    filter_backends = (DjangoFilterBackend, filters.OrderingFilter)
    filterset_fields = ['status', 'asset', 'policy']
    ordering_fields = ['created_date', 'scanned_date', 'total_score']
    queryset = ScanInstance.objects.all().order_by('created_date')
    serializer_class = ScanInstanceSerializer

    def destroy(self, request, pk=None):
        """
        delete:
        Remove scan instance and all related database objects.
        """
        try:
            instance = self.get_object()
            app.control.revoke(instance.last_task.id, terminate=True)
            try:
                current = instance.last_task.get_queue_progress()['current'].lower()
                for heavy in scan_settings['heavy_processes']:
                    if heavy in current:
                        sandbox = Sandbox()
                        sandbox.connect()
                        sandbox.exec('rm /opt/scan_mutex')
                        break
            except Exception as e:
                pass
            ScanTask.objects.filter(id=instance.last_task.id).delete()
            ScanPolicy.objects.filter(id=instance.policy.id).delete()
            self.perform_destroy(instance)
        except Http404:
            pass
        return RestResponse(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True, url_name='domain_list')
    def domain_list(self, request, pk=None):
        """
        get:
        List domains related to selected scan instance.
        """
        self.search_fields = ['fqdn', 'plugin']
        self.filterset_fields = ['false_positive', 'total_score', 'confidence', 'asset', 'country']
        self.ordering_fields = ['total_score', 'confidence', 'found_date']
        self.serializer_class = DomainInstanceSerializer
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        task = ScanInstance.objects.filter(asset__in=assets).get(id=pk).last_task
        doms = DomainInstance.objects.filter(last_task=task)
        serializer = DomainInstanceSerializer(doms, many=True, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='vuln_list')
    def vuln_list(self, request, pk=None):
        """
        get:
        List vulnerabilities related to selected scan instance.
        """
        self.search_fields = ['description', 'plugin']
        self.filterset_fields = ['false_positive', 'score', 'confidence', 'ip', 'asset', 'info']
        self.ordering_fields = ['score', 'confidence', 'found_date']
        self.serializer_class = VulnInstanceSerializer
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        scan = ScanInstance.objects.filter(asset__in=assets).get(id=pk)
        doms = DomainInstance.objects.filter(last_task=scan.last_task)
        vulns = VulnInstance.objects.filter(asset=scan.asset, domain__in=doms)
        serializer = VulnInstanceSerializer(vulns, many=True, context={'request': request})
        return RestResponse(serializer.data)

    @action(methods=['get'], detail=True, url_name='run')
    def run(self, request, pk=None):
        """
        get:
        Launch selected scan instance.
        """
        assets = AssetInstance.objects.filter(Q(owner=request.user) | Q(collaborations__in=request.user.groups.all()))
        scan = ScanInstance.objects.filter(asset__in=assets).get(id=pk)
        task = scan.last_task
        scan.scanned_date = timezone.now()
        task.exec_date = timezone.now()
        scan.save()
        task.save()
        str_task_id = str(task.id)
        str_queue_id = str(task.queue_id)
        dispatch_scan(task.asset.id, request.user.id, scan.policy)
        run_scan.apply_async(
            (str_task_id, str_queue_id),
            task_id=str_queue_id
        )
        serializer = ScanTaskSerializer(task, many=False, context={'request': request})
        return RestResponse(serializer.data)

