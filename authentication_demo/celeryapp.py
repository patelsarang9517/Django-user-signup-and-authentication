# -*- coding: utf-8 -*-

from celery import Celery
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentication_demo.settings')

app = Celery('mysite')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
