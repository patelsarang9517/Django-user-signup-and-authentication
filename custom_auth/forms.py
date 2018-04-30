# -*- coding: utf-8 -*-

from django import forms


class LoginForm(forms.Form):

    username = forms.CharField(max_length=30, required=True, widget=forms.TextInput(
        attrs={'class': 'input100'}))
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(
        attrs={'class': 'input100'}))


class SignupForm(forms.Form):

    first_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(
        attrs={'class': 'input100'}))
    last_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(
        attrs={'class': 'input100'}))
    username = forms.CharField(max_length=30, required=True, widget=forms.TextInput(
        attrs={'class': 'input100'}))
    password_1 = forms.CharField(max_length=30, widget=forms.PasswordInput(
        attrs={'class': 'input100'}))
    password_2 = forms.CharField(max_length=30, widget=forms.PasswordInput(
        attrs={'class': 'input100'}))
    mobile = forms.CharField(max_length=10, required=True, widget=forms.TextInput(attrs={'class': 'input100'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'input100'}))
