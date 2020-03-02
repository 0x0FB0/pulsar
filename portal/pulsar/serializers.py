import ipaddress
import socket

import validators
from django.db.models import Q
from django_celery_beat.models import PeriodicTask
from rest_framework import serializers

from .models import *
from .modules.scanner_utils import aBulkRecordLookup, getCountryData


class DomainField(serializers.CharField):
    """Representation of Domain entry.
    Fully Qualified Domain Name string with additional validation"""
    def to_internal_value(self, data):
        try:
            if not validators.domain(data):
                raise serializers.ValidationError("Invalid domain name.")
            if not ipaddress.IPv4Address(socket.gethostbyname(data)).is_global:
                raise serializers.ValidationError("Invalid domain name.")
        except Exception as e:
            raise serializers.ValidationError("Domain could not be resolved.")
        return data


class CustomIPField(serializers.IPAddressField):
    """Representation of IPv4 address entry.
    IPvv4 string with additional validation"""
    def to_internal_value(self, data):
        try:
            if not ipaddress.IPv4Address(data).is_global:
                raise serializers.ValidationError("Invalid IPv4 address.")
        except Exception as e:
            raise serializers.ValidationError("Invalid IPv4 address: %s" % e)
        return data


class ScoreField(serializers.FloatField):
    """Representation of scan total score entry.
    Float field with additional validation (min 0.0, max 10.0)"""
    def to_internal_value(self, data):
        try:
            if float(data) > 10.0 or float(data) < 0.0:
                raise serializers.ValidationError("Value out of range. Must be between 0.0 and 1.0.")
            else:
                return data
        except ValueError:
            raise serializers.ValidationError("Value of incorrect type (float expected).")


class ConfidenceField(serializers.FloatField):
    """Representation of vulnerability or address confidence entry.
    Float field with additional validation (min 0.0, max 1.0)"""
    def to_internal_value(self, data):
        try:
            if float(data) > 1.0 or float(data) < 0.0:
                raise serializers.ValidationError("Value out of range. Must be between 0.0 and 1.0.")
            else:
                if data:
                    return data
                else:
                    return ""
        except ValueError:
            raise serializers.ValidationError("Value of incorrect type (float expected).")

class PortalUserSerializer(serializers.ModelSerializer):
    """Representation of pulsar application user."""
    id = serializers.PrimaryKeyRelatedField(read_only=True)
    token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = PortalUser
        fields = ['id', 'username', 'first_name', 'last_name', 'email',
                  'token', 'created_date', 'last_login', 'is_superuser']

    def get_token(self, obj):
        """Retrieve user API token."""
        return str(obj.get_token())


class ScanTaskSerializer(serializers.ModelSerializer):
    """Representation of celery scan task."""
    id = serializers.HyperlinkedRelatedField(read_only=True, view_name='scantask-detail')
    queue_id = serializers.PrimaryKeyRelatedField(read_only=True)
    state = serializers.CharField(max_length=255, read_only=True)
    asset = serializers.HyperlinkedRelatedField(read_only=True, view_name='assetinstance-detail')
    result = serializers.CharField(max_length=255, read_only=True)
    created_date = serializers.DateTimeField(read_only=True)
    exec_date = serializers.DateTimeField(read_only=True)
    status = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = ScanTask
        fields = ['id', 'queue_id', 'state', 'asset', 'result', 'created_date',
                  'exec_date', 'status']

    def get_status(self, obj):
        """Get current asynchronous task status and progress."""
        return obj.get_queue_progress()

class ServiceSerializer(serializers.ModelSerializer):
    """Representation of network service entry."""

    class Meta:
        model = ServiceInstance
        fields = '__all__'


class VulnInstanceSerializer(serializers.ModelSerializer):
    """Representation of vulnerability entry."""
    id = serializers.HyperlinkedRelatedField(read_only=True, view_name='vulninstance-detail')
    plugin = serializers.CharField(max_length=255, read_only=True)
    false_positive = serializers.BooleanField()
    info = serializers.BooleanField()
    score = ScoreField()
    confidence = ConfidenceField()
    found_date = serializers.DateTimeField(read_only=True)
    domain = serializers.HyperlinkedRelatedField(read_only=True, view_name='domaininstance-detail')
    asset = serializers.HyperlinkedRelatedField(read_only=True, many=False, view_name='assetinstance-detail')

    class Meta:
        model = VulnInstance
        fields = '__all__'


class AssetPerUserSerializer(serializers.HyperlinkedRelatedField):
    """Custom representation with additional access filtering."""
    def get_queryset(self):
        user = PortalUser.objects.get(id=self.context['request'].user.id)
        return AssetInstance.objects.filter(Q(owner=user) | Q(collaborations__in=user.groups.all()))

class DomainDetailSerializer(serializers.ModelSerializer):
    """Representation of domain entry, detailed view."""
    id = serializers.HyperlinkedRelatedField(read_only=True, view_name='domaininstance-detail')
    fqdn = DomainField(max_length=255)
    plugin = serializers.CharField(max_length=255, read_only=True)
    country = serializers.CharField(max_length=3, read_only=True)
    false_positive = serializers.BooleanField()
    reference = serializers.CharField(max_length=255, required=False)
    total_score = ScoreField(read_only=True)
    confidence = ConfidenceField(default=1.0, required=False)
    found_date = serializers.DateTimeField(read_only=True)
    ips = serializers.SerializerMethodField(read_only=True)
    vulns = serializers.SerializerMethodField(read_only=True)
    last_task = serializers.HyperlinkedRelatedField(read_only=True, view_name='scantask-detail')
    asset = AssetPerUserSerializer(view_name='assetinstance-detail')

    class Meta:
        model = DomainInstance
        fields = '__all__'

    def create(self, validated_data):
        """Create new domain object including resolved IPv4 address and its details."""
        obj = DomainInstance.objects.create(**validated_data)
        last_task = ScanInstance.objects.filter(asset=obj.asset).order_by('-scanned_date').first().last_task
        fqdn = validated_data['fqdn']
        resolved = aBulkRecordLookup([fqdn])
        ips = list()
        try:
            if len(resolved) > 0:
                for ip in resolved[0]['ip']:
                    country = getCountryData(ip['ip'])
                    if len(country) < 2:
                        country = 'NA'
                    ips.append(IPv4AddrInstance.objects.create(ip=ip['ip'], cidr=ip['cidr'], asn=ip['asn'],
                                                    desc=ip['desc'], asset=obj.asset,
                                                    domain=obj, last_task=last_task, country=country))
                obj.last_task = last_task
                obj.ips.set(ips)
                obj.save()
                return obj
            else:
                raise serializers.ValidationError("Domain could not be properly resolved.")
        except KeyError as e:
            raise serializers.ValidationError("An error occured during domain resolution: %s" % e)


    def get_vulns(self, obj):
        """Retrieve vulnerabilities associated with domain object."""
        dom = DomainInstance.objects.get(pk=obj.id)
        ips = IPv4AddrInstance.objects.filter(domain=dom, asset=dom.asset)
        serializer = VulnInstanceSerializer(instance=VulnInstance.objects.filter(ip__in=ips, domain=dom, asset=dom.asset)
                                            .order_by('-score'),
                                            many=True,
                                            context=self.context)
        return serializer.data

    def get_ips(self, obj):
        """Retrieve IPv4 addresses associated with domain object."""
        dom = DomainInstance.objects.get(pk=obj.id)
        serializer = IPv4AddressSerializer(instance=IPv4AddrInstance.objects.filter(domain=dom, asset=dom.asset),
                                            many=True,
                                            context=self.context)
        return serializer.data


class DomainInstanceSerializer(DomainDetailSerializer):
    """Basic representation of domain entry."""
    class Meta:
        model = DomainInstance
        fields = ['id', 'fqdn', 'ips', 'plugin', 'country',
                  'false_positive', 'reference', 'total_score',
                  'confidence', 'found_date', 'last_task', 'asset']

class IPv4AddressSerializer(serializers.ModelSerializer):
    """Representation of IPv4 entry."""
    id = serializers.HyperlinkedRelatedField(read_only=True, view_name='ipv4addrinstance-detail')
    ip = CustomIPField(read_only=True)
    cidr = serializers.CharField(max_length=18, read_only=True)
    asn = serializers.IntegerField(read_only=True)
    desc = serializers.CharField(max_length=255, read_only=True)
    vulns = serializers.SerializerMethodField(read_only=True)
    svcs = serializers.SerializerMethodField(read_only=True)
    last_task = serializers.HyperlinkedRelatedField(read_only=True, view_name='scantask-detail')
    domain = serializers.HyperlinkedRelatedField(read_only=True, view_name='domaininstance-detail')
    asset = serializers.HyperlinkedRelatedField(read_only=True, view_name='assetinstance-detail')

    class Meta:
        model = IPv4AddrInstance
        fields = '__all__'

    def get_svcs(self, obj):
        """Retrieve network services associated with IPv4 object."""
        ip = IPv4AddrInstance.objects.get(pk=obj.id)
        serializer = ServiceSerializer(instance=ServiceInstance.objects.filter(ip=ip),
                                            many=True,
                                            context=self.context)
        return serializer.data

    def get_vulns(self, obj):
        """Retrieve vulnerabilities associated with IPv4 object."""
        ip = IPv4AddrInstance.objects.get(pk=obj.id)
        serializer = VulnInstanceSerializer(instance=VulnInstance.objects.filter(ip=ip, asset=ip.asset)
                                            .order_by('-score'),
                                            many=True,
                                            context=self.context)
        return serializer.data


class AssetDetailSerializer(serializers.ModelSerializer):
    """Representation of asset entry, detailed view."""
    id = serializers.HyperlinkedRelatedField(read_only=True, view_name='assetinstance-detail')
    name = serializers.CharField(max_length=255)
    domain = DomainField()
    current_score = ScoreField(read_only=True)
    scans = serializers.HyperlinkedRelatedField(read_only=True, many=True, view_name='scaninstance-detail')
    doms = serializers.SerializerMethodField(read_only=True)
    schedule = serializers.SerializerMethodField(read_only=True)
    created_date = serializers.DateTimeField(read_only=True)
    modified_date = serializers.DateTimeField(read_only=True)

    class Meta:
        model = AssetInstance
        fields = ['id', 'name', 'scans', 'created_date', 'modified_date',
                  'domain', 'current_score', 'doms', 'schedule']

    def get_doms(self, obj):
        """Retrieve domains associated with asset object."""
        last_scan = AssetInstance.objects.get(pk=obj.id).scans\
            .filter(status='SCANNED')\
            .order_by('-scanned_date')\
            .first()
        if last_scan:
            last_task = last_scan.last_task
            serializer = DomainDetailSerializer(instance=DomainInstance.objects.filter(last_task=last_task),
                                             many=True,
                                             context=self.context)
            return serializer.data
        else:
            return {}

    def get_schedule(self, obj):
        """Retrieve periodic tasks associated with asset object."""
        pt = PeriodicTask.objects.filter(name__contains='ps-' + str(obj.id), enabled=True).first()
        if pt:
            return pt.name
        else:
            return None


class AssetInstanceSerializer(AssetDetailSerializer):
    """Basic representation of asset entry."""

    class Meta:
        model = AssetInstance
        fields = ['id', 'name', 'scans', 'created_date', 'modified_date',
                  'domain', 'current_score', 'schedule']


class ScanPolicySerializer(serializers.ModelSerializer):
    """Basic representation of scan policy entry."""

    class Meta:
        model = ScanPolicy
        fields = '__all__'


class ScanInstanceSerializer(serializers.ModelSerializer):
    """Representation of scan entry."""
    id = serializers.HyperlinkedRelatedField(read_only=True, many=False, view_name='scaninstance-detail')
    policy = ScanPolicySerializer(
        many=False)
    total_score = ScoreField(read_only=True)
    asset = serializers.HyperlinkedRelatedField(read_only=True, view_name='assetinstance-detail')
    created_date = serializers.DateTimeField(read_only=True)
    scanned_date = serializers.DateTimeField(read_only=True)
    status = serializers.ChoiceField(choices=ScanInstance.SCAN_STATUS_CHOICES)
    last_task = serializers.HyperlinkedRelatedField(read_only=True, view_name='scantask-detail')

    class Meta:
        model = ScanInstance
        fields = ['id', 'policy', 'total_score', 'asset', 'created_date', 'scanned_date',
                  'status', 'last_task']
        extra_kwargs = {'asset': {'required': True}}

    def update(self, instance, validated_data):
        """Update scan policy settings."""
        policy_data = validated_data.pop('policy')
        policy_id = instance.policy.id
        ScanPolicy.objects.filter(id=policy_id).update(**policy_data)
        policy = ScanPolicy.objects.get(id=policy_id)
        print(repr(policy))
        instance = ScanInstance.objects.get(id=instance.id)
        return instance
