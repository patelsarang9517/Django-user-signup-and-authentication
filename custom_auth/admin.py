# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Profile, PasswordResetTokens, ImageUrl


class ProfileAdmin(admin.ModelAdmin):

    list_display = ['user', 'mobile']
    search_fields = [('user', 'mobile')]


class PasswordResetTokensAdmin(admin.ModelAdmin):
    model = PasswordResetTokens
    list_display = ['user', 'token', 'expiry_time', 'used']


admin.site.register(Profile, ProfileAdmin)
admin.site.register(ImageUrl)
admin.site.register(PasswordResetTokens, PasswordResetTokensAdmin)
