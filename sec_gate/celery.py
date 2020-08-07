import os
from celery import Celery 

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sec_gate.settings')

app = Celery('sec_gate')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()