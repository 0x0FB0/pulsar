import os
import ssl

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'portal.settings')

app = Celery('pulsar')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.conf.update(
    worker_redirect_stdouts_level='DEBUG',
    security_key='/etc/ssl/server.key',
    security_certificate='/etc/ssl/server.crt',
    security_cert_store='/etc/ssl/*.crt',
    security_digest='sha256',
    task_serializer='auth',
    allowed_serializers=['json'],
    event_serializer='auth',
    accept_content=['auth'],
    broker_login_method = 'AMQPLAIN',
    broker_url = f'amqp://{os.environ["RABBITMQ_DEFAULT_USER"]}:{os.environ["RABBITMQ_DEFAULT_PASS"]}@queue:5671//',
    broker_use_ssl = {
      'keyfile': '/etc/ssl/celery_client/key.pem',
      'certfile': '/etc/ssl/celery_client/cert.pem',
      'ca_certs': '/etc/ssl/celery_client/cacert.pem',
      'cert_reqs': ssl.CERT_REQUIRED
        }
    )
app.setup_security()
app.autodiscover_tasks()