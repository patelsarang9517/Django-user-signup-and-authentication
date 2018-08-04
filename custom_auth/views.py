# -*- coding: utf-8 -*-

from django.views import View
from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.http import Http404
from .forms import LoginForm, SignupForm, ResetPasswordForm, ConfirmPasswordForm, ImageUrlForm
from .models import PasswordResetTokens, ImageUrl
import uuid
from datetime import datetime
import pytz
from .tasks import send_async_email
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer, PasswordSerializer, ResetPasswordSerializer


# Get redirect url from settings file or else redirect to admin page.
login_redirect_url = settings.LOGIN_REDIRECT_URL or '/admin'


class Login(View):

    def get(self, request):
        """
        Return login template
        """
        if request.user.is_authenticated():
            return redirect(login_redirect_url)
        form = LoginForm()
        return render(request, 'registration/login.html', {'form': form})

    def post(self, request):
        """
        Login user and redirect to Profile
        """
        form = LoginForm()
        login_form = LoginForm(request.POST)
        if not login_form.is_valid():
            return render(request, 'registration/login.html', {'errors': login_form.errors, 'form': form})
        username = login_form.cleaned_data.get('username')
        password = login_form.cleaned_data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            return redirect(login_redirect_url)
        else:
            error = {'general_error': 'Invalid Credentials'}
            form.fields["username"].initial = username
            return render(request, 'registration/login.html', {'errors': error, 'form': form})


class Signup(View):

    def get(self, request):
        """
        Return signup template
        """
        if request.user.is_authenticated():
            return redirect(login_redirect_url)
        form = SignupForm()
        return render(request, 'registration/signup.html', {'form': form})

    def post(self, request):
        """
        Signup and redirect to Profile
        """
        form = SignupForm()
        signup_form = SignupForm(request.POST)
        if not signup_form.is_valid():
            return render(request, 'registration/signup.html', {'errors': signup_form.errors, 'form': form})
        first_name = signup_form.cleaned_data.get('first_name')
        last_name = signup_form.cleaned_data.get('last_name')
        username = signup_form.cleaned_data.get('username')
        email = signup_form.cleaned_data.get('email')
        password_1 = signup_form.cleaned_data.get('password_1')
        password_2 = signup_form.cleaned_data.get('password_2')
        mobile = signup_form.cleaned_data.get('mobile')
        if not password_1 == password_2:
            error = {'general_error': "Passwords don't match"}
            return render(request, 'registration/signup.html', {'errors': error, 'form': form})
        try:
            user, created = User.objects.get_or_create(username=username)
            if created:
                user.set_password(password_1)
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.profile.mobile = mobile
                user.save()
                login(request, user)
                send_async_email.delay(
                    'Welcome Aboard', 'Welcome aboard. Thanks for joining the A team.', settings.FROM_EMAIL, [user.email])
                return redirect(login_redirect_url)
            else:
                error = {'general_error': 'User already registered.'}
                return render(request, 'registration/signup.html', {'errors': error, 'form': form})
        except Exception:
            error = {'general_error': 'Cannot create user at the moment..'}
            return render(request, 'registration/signup.html', {'errors': error, 'form': form})


class Profile(LoginRequiredMixin, View):

    def get(self, request):
        """
        Return Profile template with field to enter url
        """
        form = ImageUrlForm()
        return render(request, 'registration/profile.html', {"form":form})

    def post(self, request):
        """
        Save Image url
        """
        form = ImageUrlForm(request.POST)
        if form.is_valid():
            token = request.POST.get('image_url')
            # I didn't understand what compressed URL is. So i stored the same image url in the compressed field as well.
            ImageUrl.objects.create(image_url=form.cleaned_data.get('image_url'), user=request.user, short_image_url=form.cleaned_data.get('image_url'))
            return render(request, 'registration/profile.html', {"success_msg":"The url was stored successfully."})
        return render(request, 'registration/profile.html', {'form': ImageUrlForm(), 'errors': form.errors})

class Logout(View):

    def post(self, request):
        """
        Logout user
        """
        return render(request, 'registration/profile.html')


class ResetPassword(View):

    def get(self, request):
        """
        Return reset password template
        """
        form = ResetPasswordForm()
        return render(request, 'registration/reset_password.html', {'form': form})

    def post(self, request):
        """
        Reset password and redirect to email sent template
        """
        reset_password_form = ResetPasswordForm(request.POST)
        if not reset_password_form.is_valid():
            return render(request, 'registration/reset_password.html', {'form': reset_password_form, 'errors': reset_password_form.errors})
        username = reset_password_form.cleaned_data.get('username')
        user = User.objects.filter(username=username)
        if not user:
            return render(request, 'registration/reset_password.html', {'form': reset_password_form, 'errors': {'general_error': 'User doesnot exist.'}})
        token_obj = PasswordResetTokens.objects.create(
            user=user[0], token=uuid.uuid4().hex)
        url = ''
        url += request.get_host()
        url += reverse('set_password')
        url += '?token=' + token_obj.token
        message = render_to_string('registration/reset_password_email_template.html', {
            'user': user[0],
            'url': url
        }
        )
        send_async_email.delay('Password Reset', message,
                               settings.FROM_EMAIL, [user[0].email])
        return render(request, 'registration/reset_email_sent.html')


class SetPassword(View):

    def get(self, request):
        """
        Check if authorized to reset password.
        Return reset password template
        """
        form = ConfirmPasswordForm()
        token = request.GET.get('token')
        if not token:
            raise Http404('Page not found.')
        token_obj = PasswordResetTokens.objects.filter(token=token)
        if not token_obj:
            raise Http404('Fake token supplied.')
        if token_obj[0].used:
            raise Http404('Token already used')
        tz = pytz.timezone("UTC")
        if tz.localize(datetime.now(), is_dst=None) > token_obj[0].expiry_time:
            raise Http404('Token Expired. Try again')
        return render(request, 'registration/set_password.html', {'form': form, 'token': token})

    def post(self, request):
        """
        Save new password and redirect to Login
        """
        form = ConfirmPasswordForm(request.POST)
        token = request.POST.get('token')
        if not token:
            raise Http404('Page not found.')
        if not form.is_valid():
            return render(request, 'registration/set_password.html', {'form': form, 'token': token, 'errors': form.errors})
        token_obj = PasswordResetTokens.objects.filter(token=token)
        if not token_obj:
            raise Http404('Fake token supplied.')
        if token_obj[0].used:
            raise Http404('Token already used')
        tz = pytz.timezone("UTC")
        if tz.localize(datetime.now(), is_dst=None) > token_obj[0].expiry_time:
            raise Http404('Token Expired. Try again')
        password_1 = form.cleaned_data.get('password_1')
        password_2 = form.cleaned_data.get('password_2')
        if not password_1 == password_2:
            return render(request, 'registration/set_password.html', {'form': form, 'token': token, 'errors': {'general_error': "passwords don't match"}})
        user = token_obj[0].user
        user.set_password(password_1)
        user.save()
        token_obj[0].used = True
        token_obj[0].save()
        return HttpResponseRedirect(reverse('login'))


class ChangePassword(LoginRequiredMixin, View):

    def get(self, request):
        """
        Return change password template
        """
        form = ConfirmPasswordForm()
        return render(request, 'registration/change_password.html', {'form': form})

    def post(self, request):
        """
        Save new password and redirect to Login
        """
        form = ConfirmPasswordForm(request.POST)
        if not form.is_valid():
            return render(request, 'registration/change_password.html', {'form': form, 'errors': form.errors})
        password_1 = form.cleaned_data.get('password_1')
        password_2 = form.cleaned_data.get('password_2')
        if password_1 != password_2:
            return render(request, 'registration/change_password.html', {'form': form, 'errors': {'general_error': "Passwords don't match"}})
        request.user.set_password(password_1)
        request.user.save()
        logout(request)
        return HttpResponseRedirect(reverse('login'))


@api_view(['POST'])
@permission_classes((AllowAny,))
def create_user(request):
    """
    Rest Api for user signup
    """
    api_return_response = {
        'status': '',
        'data': {},
        'errors': {}
    }
    if request.method == 'POST':
        serialized = UserSerializer(data=request.data)
        if serialized.is_valid():
            user = serialized.save()
            user.is_active=True
            user.save()
            send_async_email.delay(
                    'Welcome Aboard', 'Welcome aboard. Thanks for joining the A team.', settings.FROM_EMAIL, [user.email])
            api_return_response['status'] = 'success'
            api_return_response['data'] = serialized.data
            return Response(api_return_response, status=status.HTTP_201_CREATED)
        else:
            api_return_response['status'] = 'error'
            api_return_response['errors'] = serialized.errors
            return Response(api_return_response, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
def change_password(request):
    """
    Rest Api to change password
    """
    serialized = PasswordSerializer(data=request.data)
    api_return_response = {
        'status': '',
        'data': {},
        'errors': {}
    }
    if not serialized.is_valid():
        api_return_response['status'] = 'error'
        api_return_response['errors'] = serialized.errors
        return Response(api_return_response, status=status.HTTP_400_BAD_REQUEST)
    if serialized.data.get('password_1') != serialized.data.get('password_2'):
        error = {'password_1': ["Passwords don't match"]}
        api_return_response['status'] = 'error'
        api_return_response['errors'] = error
        return Response(api_return_response, status=status.HTTP_400_BAD_REQUEST)
    request.user.set_password(serialized.data.get('password_1'))
    request.user.save()
    api_return_response['status'] = 'success'
    api_return_response['data'] = serialized.data
    return Response(api_return_response, status=status.HTTP_200_OK)


@api_view(['POST'])
def logout_user(request):
    """
    Rest Api for user logout
    """
    request.user.auth_token.delete()
    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes((AllowAny,))
def reset_password(request):
    """
    Rest Api to reset password
    """
    api_return_response = {
        'status': '',
        'data': {},
        'errors': {}
    }
    if request.method == 'POST':
        serialized = ResetPasswordSerializer(data=request.data)
        if serialized.is_valid():
            try:
                user = User.objects.get(
                    username=serialized.data.get('username'))
            except Exception:
                api_return_response['status'] = 'error'
                api_return_response['errors'] = {'error': "user doesn't exist"}
                return Response(api_return_response, status=status.HTTP_400_BAD_REQUEST)
            token_obj = PasswordResetTokens.objects.create(
                user=user, token=uuid.uuid4().hex)
            url = ''
            url += request.get_host()
            url += reverse('set_password')
            url += '?token=' + token_obj.token
            message = render_to_string('registration/reset_password_email_template.html', {
                'user': user,
                'url': url
            }
            )
            send_async_email.delay('Password Reset', message,
                                   settings.FROM_EMAIL, [user.email])
            api_return_response['status'] = 'success'
            api_return_response['data'] = {'message': 'Email has been successfully sent. Refer to instructions in the mail to reset your password.'}
            return Response(api_return_response, status=status.HTTP_200_OK)
        else:
            api_return_response['status'] = 'error'
            api_return_response['errors'] = serialized.errors
            return Response(api_return_response, status=status.HTTP_400_BAD_REQUEST)
