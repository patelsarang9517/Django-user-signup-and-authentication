# -*- coding: utf-8 -*-

from celery import shared_task
from django.core.mail import send_mail


@shared_task
def send_async_email(email_from, body, subject, email_to):
    try:
        send_mail(subject, body, email_from, email_to, fail_silently=False)
        print 'email successfully sent'
    except Exception:
        print 'Cannot send email to users. Something is wrong'
