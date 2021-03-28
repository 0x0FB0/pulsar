import os
import sys
from django.core.wsgi import get_wsgi_application

path = '/portal/portal/'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'portal.settings'

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'portal.settings')

application = get_wsgi_application()
