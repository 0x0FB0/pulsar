from .models import *
from django.contrib import admin
import django.forms as forms
from django.contrib.admin.widgets import FilteredSelectMultiple

from .models import *


# Collaboration group custom form

class GroupAdminForm(forms.ModelForm):
    class Meta:
        model = CollaborationGroup
        exclude = []

    users = forms.ModelMultipleChoiceField(
         queryset=PortalUser.objects.all(),
         required=False,
         widget=FilteredSelectMultiple('users', False)
    )

    def __init__(self, *args, **kwargs):
        super(GroupAdminForm, self).__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields['users'].initial = self.instance.user_set.all()

    def save_m2m(self):
        self.instance.user_set.set(self.cleaned_data['users'])

    def save(self, *args, **kwargs):
        instance = super(GroupAdminForm, self).save()
        self.save_m2m()
        return instance

@admin.register(CollaborationGroup)
class GroupAdmin(admin.ModelAdmin):
    form = GroupAdminForm
    filter_horizontal = ['permissions']

@admin.register(PortalUser)
class PortalUserAdmin(admin.ModelAdmin):
    list_display = ( 'id', 'created_date', 'date_joined', 'email', 'first_name', 'is_active', 'is_staff',
                    'is_superuser', 'last_login', 'last_name', 'modified_date', 'username')
    list_filter = ('id', 'username', 'email')

@admin.register(AssetInstance)
class AssetInstanceAdmin(admin.ModelAdmin):
    list_display = ('name', 'domain', 'created_date', 'id', 'owner', 'result', 'modified_date')
    filter_horizontal = ('collaborations',)
    list_filter = ('name', 'created_date', 'domain', 'owner')

@admin.register(ScanInstance)
class ScanInstanceAdmin(admin.ModelAdmin):
    list_display = ('id', 'asset', 'created_date')
    list_filter = ('id', 'created_date')

@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'asset', 'state', 'result', 'queue_id')
    list_filter = ('id','asset', 'state', 'result', 'queue_id')

@admin.register(DomainInstance)
class DomainInstanceAdmin(admin.ModelAdmin):
    list_display = ('fqdn', 'confidence', 'plugin', 'found_date', 'asset')
    list_filter = ('fqdn', 'confidence', 'plugin', 'found_date', 'asset')

@admin.register(VulnInstance)
class VulnInstanceAdmin(admin.ModelAdmin):
    list_display = ('plugin', 'id', 'score', 'confidence', 'description', 'domain')
    list_filter = ('plugin', 'id', 'score', 'confidence', 'description', 'domain')

@admin.register(HandMadePlugin)
class HandMadePluginAdmin(admin.ModelAdmin):
    list_display = ('name', 'id', 'score', 'confidence')
    list_filter = ('name', 'id', 'score', 'confidence')
