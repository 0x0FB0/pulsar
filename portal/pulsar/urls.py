from django.urls import include, path
from rest_framework import routers

from . import views

apirouter = routers.DefaultRouter()
apirouter.register(r'assets', views.Asset)
apirouter.register(r'scans', views.Scan)
apirouter.register(r'tasks', views.Task)
apirouter.register(r'doms', views.Domain)
apirouter.register(r'ipv4addr', views.IPv4Addr)
apirouter.register(r'vulns', views.Vulnerability)
apirouter.register(r'user', views.User, base_name='user')
apirouter.register(r'stats', views.Statistics, base_name='statistics')

urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('', include('social_django.urls', namespace='social')),
    path('api/v1/', include(apirouter.urls)),
    path(r'api/v1/login/', include('rest_social_auth.urls_token')),
]
