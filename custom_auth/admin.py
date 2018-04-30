# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Profile


class ProfileAdmin(admin.ModelAdmin):

    list_display = ['user', 'mobile', 'otp']
    search_fields = [('user', 'mobile', 'otp')]


admin.site.register(Profile, ProfileAdmin)
