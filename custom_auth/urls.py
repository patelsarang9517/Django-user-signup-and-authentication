# -*- coding: utf-8 -*-

from django.conf.urls import url
from .views import Login, Signup, Profile, ResetPassword, SetPassword, ChangePassword, create_user, logout_user, change_password, reset_password
from django.contrib.auth.views import logout
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    url(r'^$', Login.as_view(), name='login'),
    url(r'^signup/$', Signup.as_view(), name='signup'),
    url(r'^profile/$', Profile.as_view(), name='profile'),
    url(r'^logout/$', logout, {'next_page': '/'}, name='logout'),
    url(r'^reset_password/$', ResetPassword.as_view(), name='reset_password'),
    url(r'^set_password/$', SetPassword.as_view(), name='set_password'),
    url(r'^change_password/$', ChangePassword.as_view(), name='change_password'),
    url(r'^api-token-auth/', obtain_auth_token),
    url(r'^api/v1/signup/', create_user, name='signup_api'),
    url(r'^api/v1/logout', logout_user, name='logout_api'),
    url(r'^api/v1/change_password/', change_password, name='change_password_api'),
    url(r'^api/v1/reset_password/', reset_password, name='reset_password_api'),

]
