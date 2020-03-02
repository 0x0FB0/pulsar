import hashlib
import uuid
from celery.result import AsyncResult
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


class CollaborationGroup(Group):
    """
    Collaboration group wrapper (django.Group).
    """
    pass

class PortalUser(AbstractUser):
    """
    User wrapper model extended with API token.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    modified_date = models.DateTimeField(null=True, blank=True, auto_now=True)

    def get_meta(self):
        """
        Retrieve a list of model fields.
        :return:
        """
        return list(PortalUser.objects.filter(id=self.id).values(
            'id','first_name','last_name', 'email', 'date_joined', 'last_login'))[0].items()

    def get_token(self):
        """
        Retrieve REST API token.
        :return:
        """
        return Token.objects.get(user=self)

    def refresh_token(self):
        """
        Refresh REST API token.
        :return:
        """
        Token.objects.get(user=self).delete()
        Token.objects.create(user=self)


    @receiver(post_save, sender=settings.AUTH_USER_MODEL)
    def create_auth_token(sender, instance=None, created=False, **kwargs):
        """
        Create REST API token on user create (post save).
        :param instance:
        :param created:
        :param kwargs:
        :return:
        """
        if Token.objects.filter(user=instance).count() == 0:
            if created:
                Token.objects.create(user=instance)

class AssetInstance(models.Model):
    """
    Base model for storage of asset details.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    created_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    modified_date = models.DateTimeField(null=True, blank=True, auto_now=True)
    name = models.CharField(max_length=255)
    current_score = models.FloatField(default=-1.0)
    domain = models.CharField(max_length=255)
    result = models.CharField(max_length=255, default='none')
    owner = models.ForeignKey(PortalUser, related_name='assets', on_delete=models.SET_NULL,
                              null=True, blank=True)
    collaborations = models.ManyToManyField(Group, blank=True)

    def get_meta(self):
        """
        Retrieve a list of model fields.
        :return:
        """
        return list(AssetInstance.objects.filter(id=self.id).values())[0].items()

    def __str__(self):
        return "%s (%s)" % (str(self.name), str(self.domain))

class ScanTask(models.Model):
    """
    Base model for storage of celery scan task details and status.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    queue_id = models.CharField(max_length=50, default=uuid.uuid4, unique=True)
    state = models.CharField(max_length=255, default='none')
    result = models.TextField(default='none')
    created_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    exec_date = models.DateTimeField(null=True, blank=True, default=None)
    asset = models.ForeignKey(AssetInstance, related_name='tasks', on_delete=models.SET_NULL,
                              null=True, blank=True)

    def get_queue_id(self):
        """
        Retrieve celery queue id.
        :return:
        """
        return ScanTask.objects.filter(id=self.id).values_list('queue_id', flat=True)[0]
    def get_state(self):
        """
        Retrieve celery queue state.
        :return:
        """
        return ScanTask.objects.filter(id=self.id).values_list('state', flat=True)[0]
    def get_result(self):
        """
        Retrieve celery queue result.
        :return:
        """
        return ScanTask.objects.filter(id=self.id).values_list('result', flat=True)[0]
    def get_queue_state(self):
        """
        Retrieve async celery queue state.
        :return:
        """
        result = AsyncResult(str(self.queue_id))
        if result.state and not isinstance(result.state, Exception):
            return result.state
        else:
            return None
    def get_queue_progress(self):
        """
        Retrieve async celery queue result.
        :return:
        """
        result = AsyncResult(str(self.queue_id))
        if result.info and not isinstance(result.info, Exception):
            return result.info
        else:
            return '{"current": "None", "percent": 0}'

    def __str__(self):
        return str(self.id)



class DomainInstance(models.Model):
    """
    Base model for storage of domain details.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    fqdn = models.CharField(max_length=255, default='none')
    false_positive = models.BooleanField(default=False)
    reference = models.CharField(max_length=4096, default='', null=True, blank=True)
    country = models.CharField(max_length=3, default='USA', null=True, blank=True)
    total_score = models.FloatField(default=0.0)
    confidence = models.FloatField(default=0.0)
    source = models.CharField(max_length=255, default='Initial domain')
    plugin = models.CharField(max_length=255, default='unknown')
    found_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    last_task = models.ForeignKey(ScanTask, related_name='doms', on_delete=models.SET_NULL,
                               null=True, blank=True)
    asset = models.ForeignKey(AssetInstance, related_name='doms', on_delete=models.SET_NULL,
                              null=True, blank=True)

    def __str__(self):
        return self.fqdn



class IPv4AddrInstance(models.Model):
    """
    Base model for storage of network address details.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    ip = models.GenericIPAddressField(default='0.0.0.0')
    country = models.CharField(max_length=4, default='NA')
    cidr = models.CharField(max_length=18, default='0.0.0.0/0')
    asn = models.IntegerField(default=0)
    desc = models.CharField(max_length=255, default='None')
    score = models.FloatField(default=0.0)
    domain = models.ForeignKey(DomainInstance, related_name='ips', on_delete=models.SET_NULL,
                               null=True, blank=True)
    last_task = models.ForeignKey(ScanTask, related_name='ips', on_delete=models.SET_NULL,
                                  null=True, blank=True)
    asset = models.ForeignKey(AssetInstance, related_name='ips', on_delete=models.SET_NULL,
                              null=True, blank=True)

    def __str__(self):
        return str(self.ip)

class ServiceInstance(models.Model):
    """
    Base model for storage of network service details.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    proto = models.CharField(max_length=255, default='IP')
    port = models.IntegerField(default=0)
    cpe = models.CharField(max_length=4096, default='None')
    desc = models.CharField(max_length=2048, default='None')
    banner = models.TextField(default='')
    ip = models.ForeignKey(IPv4AddrInstance, related_name='svcs', on_delete=models.SET_NULL,
                           null=True, blank=True)
    last_task = models.ForeignKey(ScanTask, related_name='svcs', on_delete=models.SET_NULL,
                                  null=True, blank=True)
    asset = models.ForeignKey(AssetInstance, related_name='svcs', on_delete=models.SET_NULL,
                              null=True, blank=True)
    def __str__(self):
        return self.proto + ':' + str(self.port)

class CVEEntry(models.Model):
    """
    Small wrapper for CVE database storage needed in scanner_utils.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    data = models.TextField(blank=True)

class HandMadePlugin(models.Model):
    """
    Base model for custom plugins defined in admin portal.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=2048, default='Hand Made Plugin')
    cvss = models.CharField(max_length=255, default='AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')
    description = models.TextField(blank=True, default='Plugin Description')
    script = models.TextField(blank=True, default='#!/bin/bash\n\n# Put Your script contents here.\n'
                              + '# Use $DOM_SVCS and $DOM_FQDN environmental variables.')
    reference = models.TextField(blank=True, default='https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html')
    info = models.BooleanField(default=False)
    score = models.FloatField(default=5.1)
    confidence = models.FloatField(default=0.9)

class VulnInstance(models.Model):
    """
    Base model for vulnerability entry.
    """
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=2048, default='unknown')
    plugin = models.CharField(max_length=255, default='unknown')
    cvss = models.CharField(max_length=255, default='unknown')
    description = models.TextField(blank=True)
    details = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    false_positive = models.BooleanField(default=False)
    info = models.BooleanField(default=False)
    score = models.FloatField(default=0.0)
    confidence = models.FloatField(default=1.0)
    found_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    domain = models.ForeignKey(DomainInstance, related_name='vulns', on_delete=models.SET_NULL,
                               null=True, blank=True)
    ip = models.ForeignKey(IPv4AddrInstance, related_name='vulns', on_delete=models.SET_NULL,
                                null=True, blank=True)
    service = models.ForeignKey(ServiceInstance, related_name='vulns', on_delete=models.SET_NULL,
                                null=True, blank=True)
    last_task = models.ForeignKey(ScanTask, related_name='vulns', on_delete=models.SET_NULL,
                                  null=True, blank=True)
    asset = models.ForeignKey(AssetInstance, related_name='vulns', on_delete=models.SET_NULL,
                              null=True, blank=True)

    def __str__(self):
        return self.plugin

    def __sha__(self):
        """
        Calculate vulnerability hash fingerprint derived from name, plugin, fqdn and asset id.
        :return:
        """
        checksum = ''
        checksum += self.name + ':'
        checksum += self.plugin + ':'
        checksum += self.domain.fqdn + ':'
        checksum += str(self.asset.id)

        return hashlib.sha256(checksum.encode('utf-8'))

class ScanPolicy(models.Model):
    """
    Base model for scan policy.
    """
    REPEAT_FREQ = [
        ('DAILY', 'Scan will be repeated daily'),
        ('WEEKLY', 'Scan will be repeated weekly'),
        ('MONTHLY', 'Scan will be repeated mothly'),
    ]
    TOP_PORTS = [
        ('5', 'Scan top 5 ports only'),
        ('25', 'Scan top 25 ports'),
        ('50', 'Scan top 50 ports'),
        ('100', 'Scan top 100 ports'),
        ('1000', 'Scan top 1000 ports'),
    ]
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, default='default')
    active = models.BooleanField(default=True)
    inscope = models.BooleanField(default=True)
    handmade = models.BooleanField(default=True)
    recursive = models.BooleanField(default=False)
    repeat = models.BooleanField(default=False)
    repeat_freq = models.CharField(max_length=8, choices=REPEAT_FREQ, default='DAILY')
    top_ports = models.CharField(max_length=4, choices=TOP_PORTS, default='50')
    notify = models.BooleanField(default=False)

    def __str__(self):
        return "%s (%s)" % (self.name, self.id)

class ScanInstance(models.Model):
    """
    Base model for storage of scan details.
    """

    SCAN_STATUS_CHOICES = [
        ('UNSCANNED', 'Scan have not been ordered'),
        ('WAITING', 'Scan is waiting in the queue'),
        ('PROGRESS', 'Scan in progress'),
        ('SCANNED', 'Scan results are available'),
        ('FAILED', 'Scan have failed'),
    ]
    id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    created_date = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    scanned_date = models.DateTimeField(null=True, blank=True, auto_now=True)
    total_score = models.FloatField(default=0.0)
    status = models.CharField(max_length=10, choices=SCAN_STATUS_CHOICES, default='UNSCANNED')
    asset = models.ForeignKey(AssetInstance, related_name='scans', on_delete=models.SET_NULL,
                              null=True, blank=True)
    policy = models.ForeignKey(ScanPolicy, related_name='scans', on_delete=models.SET_NULL,
                                null=True, blank=True)
    last_task = models.ForeignKey(ScanTask, related_name='details', on_delete=models.SET_NULL,
                                  null=True, blank=True)
    def get_meta(self):
        """
        Retrieve a list of model fields.
        :return:
        """
        return list(ScanInstance.objects.filter(id=self.id).values())[0].items()

    def __str__(self):
        return str(self.id)
