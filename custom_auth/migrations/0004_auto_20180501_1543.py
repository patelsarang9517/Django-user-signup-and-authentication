# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-05-01 15:43
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('custom_auth', '0003_passwordresettokens_used'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordresettokens',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='password_reset_token', to=settings.AUTH_USER_MODEL),
        ),
    ]
