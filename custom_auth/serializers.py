# -*- coding: utf-8 -*-

from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user signup endpoint.
    """
    class Meta:
        model = User
        fields = '__all__'

    def create(self, validated_data):
        user = super(UserSerializer, self).create(validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


class PasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    password_1 = serializers.CharField(required=True)
    password_2 = serializers.CharField(required=True)


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for password reset endpoint.
    """
    username = serializers.CharField(required=True)
