from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import RedirectView
from pulsar.views import *

handler404 = PageNotFoundView.as_view()
urlpatterns = [
    re_path('^accounts/(?:password.*|reset.*).*', PageNotFoundView.as_view()),
    path('accounts/', include('django.contrib.auth.urls')),
    path('admin/', admin.site.urls),
    path('admin/doc/', include('django.contrib.admindocs.urls')),
    path('pulsar/', include('pulsar.urls')),
    path('', RedirectView.as_view(url='pulsar/')),
]
