import datetime
import os
import time
import uuid
import traceback
import json
import pulsar.modules.plugins as plgs
from celery.exceptions import Ignore
from celery.utils.log import get_task_logger
from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from .celery import app
from .models import *
from .modules import scanner_utils

logger = get_task_logger(__name__)

def sendNotification(email, asset, dom_ids, cve_ids):
    """Send email notification about new scan results."""
    sender = settings.EMAIL_HOST_USER
    cves = [v['name'] for v in VulnInstance.objects.filter(id__in=cve_ids).values('name')]
    doms = [d['fqdn'] for d in DomainInstance.objects.filter(id__in=dom_ids).values('fqdn')]

    changes = list()
    if len(doms) == 1:
        changes.append("domain")
    elif len(doms) > 1:
        changes.append("domains")
    if len(cves) == 1:
        changes.append("vulnerability")
    elif len(cves) > 1:
        changes.append("vulnerabilities")
    subject = f"[Pulsar] New results for {asset}"
    body = f"<html></body><h2>New {' and '.join(changes)} spotted on {asset}</h2>\n<hr />"
    body += "<h2>Last scan have identified:</h2>\n"
    for change in changes:
        if 'dom' in change:
            body += f"\n<h3><p><strong>{str(len(doms))}</strong> new {change}:</p></h3>\n"
            body += '<table>'
            body += '<tbody>'
            for dom in doms:
                body += '<tr>'
                body += f"<td><big>{dom}</big></td>\n"
                body += '</tr>'
            body += '</tbody>'
            body += '</table>\n'
        elif 'vuln' in change:
            body += f"<h3><p><strong>{str(len(cves))}</strong> new {change}:</p></h3>\n"
            body += '<table>'
            body += '<tbody>'
            for cve in cves:
                body += '<tr>'
                body += f"<td><big>{cve}</big></td>\n"
                body += '</tr>'
            body += '</tbody>'
            body += '</table>\n'
    body += '<p><em><span style="color: #808080;">'
    body += 'All findings are prone to <strong>false-positives</strong>. '
    body += 'Plese log in to OpenOSINT dashboard to verify and mark them as such if needed. '
    body += 'All marked items will be omitted in future scans.</span>\n</em></p></body></html>'
    plain = strip_tags(body)

    send_mail(subject, plain, sender,
              [email,], html_message=body, fail_silently=False)

@app.task
def fetchNVD(arg):
    """Celery task wrapper for updateNVDFeed method."""
    logger.info('FETCHING NVD FEEDS AT %s' % repr(arg))
    scanner_utils.updateNVDFeed()

try:
    os.remove('/portal/nvd/feeds/mutex') # only one update at time
except OSError:
    pass

fetchNVD.apply_async(args=[str(datetime.datetime.utcnow())])

def search_in_file(work):
    """Search for CPE string occurence in NVD data feed."""
    fname = work[0]
    cpe = work[1]
    cve_list = list()
    with open(fname, 'r') as f:
        feed_data = json.loads(f.read())
    for cve in feed_data['CVE_Items']:
        for node in cve['configurations']['nodes']:
            if 'cpe_match' in node:
                for match in node['cpe_match']:
                    if cpe in match['cpe23Uri']:
                        logger.info('FOUND CPE: %s' % cpe)
                        entry = scanner_utils.CVE.objects.create(data=json.dumps(cve))
                        key = str(entry.id)
                        cve_list.append(key)
            elif 'children' in node:
                for children in node['children']:
                    for match in children['cpe_match']:
                        if cpe in match['cpe23Uri']:
                            entry = scanner_utils.CVE.objects.create(data=json.dumps(cve))
                            key = str(entry.id)
                            cve_list.extend(key)
    return cve_list


@app.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    """Celery periodic update task launcher."""
    current_tasks = PeriodicTask.objects.filter(name__contains='tasks.fetchNVD').count()
    if current_tasks == 0:
        schedule, _ = CrontabSchedule.objects.get_or_create(
            minute='*',
            hour='*8',
            day_of_week='*',
            day_of_month='*',
            month_of_year='*',
        )
        PeriodicTask.objects.create(
            crontab=schedule,
            name='tasks.fetchNVD',
            task='pulsar.tasks.fetchNVD',
            args=json.dumps([str(datetime.datetime.utcnow()),]),
        )

@app.task(bind=True)
def run_scan(self, r_task, qid):
    """Main scanner celery task method."""

    while os.path.exists('/portal/nvd/feeds/mutex'): # Wait for NVD feed download
        time.sleep(1)

    # Retrieve current scan task
    logger.info("STARTING SCAN TASK ID: %s QUEUE: %s" % (r_task, qid))
    task = ScanTask.objects.get(id=uuid.UUID(r_task))
    task.state = 'STARTED';
    task.exec_date = timezone.now()
    task.save()

    # Clone scan policy
    policy = ScanInstance.objects.filter(last_task=task).last().policy

    # Check for previously marked false positives
    false_pos_doms = []
    false_pos_vulns = []

    scan = ScanInstance.objects.filter(status='SCANNED', asset=task.asset.id) \
        .exclude(last_task=task) \
        .order_by('scanned_date') \
        .last()
    if scan:
        last_task = scan.last_task.id

        false_pos_doms = [a['fqdn'] for a in list(
                DomainInstance.objects.filter(last_task=last_task, false_positive=True).values('fqdn')
        )]

        false_pos_vulns = [[str(vuln.domain.fqdn), str(vuln.plugin)] for vuln in
                           VulnInstance.objects.filter(last_task=last_task, false_positive=True)]

    # Prepare plugin counter for progress measure
    runned = list()
    progress = 1
    plugins = plgs.__all__
    counter = 3

    for p in plugins:
        plugin = eval('plgs.'+p+'.'+p)
        if hasattr(plugin, 'custom_discovery') \
                or hasattr(plugin, 'scanner') \
                or (hasattr(plugin, 'recursive') and policy.recursive) \
                or (hasattr(plugin, 'custom_scanner') and policy.active):
            counter += 1
    if policy.handmade:
        counter += HandMadePlugin.objects.all().count()

    logger.info("PLUGINS LIST: %s" % repr(plugins))
    logger.info("RECURSIVE?: %s" % repr(policy.recursive))

    # Start discovery class plugins
    for p in plugins:
        plugin = eval('plgs.'+p+'.'+p)
        if hasattr(plugin, 'custom_discovery') or hasattr(plugin, 'scanner') \
                or (hasattr(plugin, 'recursive') and policy.recursive):
            runned.append(p)
            c = plugin()
            current = c.short
            self.update_state(state='PROGRESS',
                              meta={'current': current,
                                    'percent': int((float(progress) / counter) * 100)})
            progress += 1
            try:
                c.create(str(task.asset.id), str(task.id))
                logger.info("PLUGIN RUNNING! : %s (%s)" % (repr(p), repr(c)))
                c.run()
                c.save()
            except Exception as e:
                logger.info("PLUGIN %s - FATAL ERROR: %s" % (repr(p), repr(e)))
                raise e
                progress += 1
                pass
            if not policy.recursive:
                break

    dom_list = DomainInstance.objects.filter(asset=task.asset.id, last_task=task, false_positive=False)

    # Start scanner class plugins
    for p in plugins:
        plugin = eval('plgs.'+p+'.'+p)
        if hasattr(plugin, 'custom_scanner') and policy.active:
            c = plugin()
            current = c.short
            self.update_state(state='PROGRESS',
                              meta={'current': current,
                                    'percent': int((float(progress) / counter) * 100)})
            progress += 1
            logger.info("SCANSTART: asset_id=%s" % ( task.asset.id))
            if p not in runned:
                runned.append(p)
                for dom in dom_list:
                    ip_list = IPv4AddrInstance.objects.filter(last_task=task, domain=dom)
                    for ipaddr in ip_list:
                        logger.info("PLUGIN RUNNING! : %s (%s)" % (repr(p), repr(c)))
                        logger.info("SCANRUN: ip_id=%s asset_id=%s" % (str(ipaddr.id), task.asset.id))
                        try:
                            c.create(str(dom.id), str(ipaddr.id), task.asset.id, str(task.id))
                            c.run()
                            c.save()
                        except Exception as e:
                            logger.info("PLUGIN %s - FATAL ERROR: %s" % (repr(p), repr(e)))
                            raise e
                            progress += 1
    if policy.handmade:
        # Start custom class plugins
        for p in HandMadePlugin.objects.all():
            plugin = eval('plgs.HandMadePlugin.HandMadePlugin')
            c = plugin()
            current = c.short
            self.update_state(state='PROGRESS',
                              meta={'current': current,
                                    'percent': int((float(progress) / counter) * 100)})
            progress += 1
            logger.info("SCANSTART: asset_id=%s" % (task.asset.id))
            if p not in runned:
                runned.append(p.name)
                for dom in dom_list:
                    ip_list = IPv4AddrInstance.objects.filter(last_task=task, domain=dom)
                    for ipaddr in ip_list:
                        logger.info("PLUGIN RUNNING! : %s " % p.name)
                        logger.info("SCANRUN: ip_id=%s asset_id=%s" % (str(ipaddr.id), task.asset.id))
                        try:
                            c.create(str(dom.id), str(ipaddr.id), task.asset.id, str(task.id), str(p.id))
                            c.run()
                            c.save()
                        except Exception as e:
                            logger.info("PLUGIN %s - FATAL ERROR: %s" % (repr(p), repr(e)))
                            raise e
                            progress += 1


    self.update_state(state='PROGRESS',
                      meta={'current': 'Calculations',
                            'percent': int((float(progress) / counter) * 100)})
    progress += 1

    # Calculate asset total score.
    scanner_utils.calc_asset_by_task(r_task)

    self.update_state(state='FINISHING',
                      meta={'current': 'Notifications',
                            'percent': int((float(progress) / counter) * 100)})
    progress += 1


    # Check for result changes
    new_domains = scanner_utils.checkForNewDomains(task.id)
    new_vulns = scanner_utils.checkForNewVuln(task.id)
    logger.info("NEW DOMAINS: %s" % ','.join(new_domains))
    logger.info("NEW VULNS: %s" % ','.join(new_vulns))

    # Send notifications
    if len(new_domains) > 0 or len(new_vulns) > 0:
        if policy.notify:
            sendNotification(task.asset.owner.email, task.asset.name, new_domains, new_vulns)
    task = ScanTask.objects.get(id=uuid.UUID(r_task))
    task.state = 'SCANNED'
    task.result = "Executed %s out of %s checks." % (progress, counter)
    task.save()
    self.update_state(state='FINISHED', meta={'current': 'Finished', 'percent': 100})

    raise Ignore()

@app.task(bind=True)
def scan_wrapper(self, asset_id, user_id):
    """Small wrapper for celery periodic scan tasks."""
    asset = AssetInstance.objects.get(id=asset_id)
    user = PortalUser.objects.get(id=user_id)
    new_task = ScanTask.objects.create(asset=asset)
    policy = ScanInstance.objects.filter(asset=asset).order_by('-scanned_date').first().policy
    policy.pk = None
    policy.save()
    ScanInstance.objects.create(asset=asset, policy=policy, last_task=new_task)
    str_task_id = str(new_task.id)
    str_queue_id = str(new_task.queue_id)
    run_scan.apply_async(
        (str_task_id, str_queue_id),
        task_id=str_queue_id
    )

def dispatch_scan(asset_id, user_id, policy):
    """Main method for periodic scan task dispatching."""
    asset = AssetInstance.objects.get(id=asset_id)
    str_asset_id = str(asset.id)
    str_user_id = str(user_id)
    scheduled = PeriodicTask.objects.filter(name__contains='ps-'+str(asset.id))
    print('Checking for schedule: repeat == %s scheduled == %s' % (str(policy.repeat), repr(scheduled)))
    if policy.repeat and not scheduled:
        # Period cron definitions
        if policy.repeat_freq == 'DAILY':
            print('Adding DAILY periodic scan for '+str(asset_id))
            schedule, _ = CrontabSchedule.objects.get_or_create(
                minute='0',
                hour='8',
                day_of_week='*',
                day_of_month='*',
                month_of_year='*',
            )
        elif policy.repeat_freq == 'WEEKLY':
            print('Adding WEEKLY periodic scan for ' + str(asset_id))
            schedule, _ = CrontabSchedule.objects.get_or_create(
                minute='0',
                hour='8',
                day_of_week='mon',
                day_of_month='*',
                month_of_year='*',
            )
        else:
            print('Adding MONTHLY periodic scan for ' + str(asset_id))
            schedule, _ = CrontabSchedule.objects.get_or_create(
                minute='0',
                hour='8',
                day_of_week='mon',
                day_of_month='1-7',
                month_of_year='*',
            )
        PeriodicTask.objects.create(
            crontab=schedule,
            name='ps-'+str(asset.id)+'-'+str(policy.repeat_freq),
            task='pulsar.tasks.scan_wrapper',
            args=json.dumps([str_asset_id, str_user_id]),
        )