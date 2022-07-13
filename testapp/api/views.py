from django.contrib.auth import authenticate
from django.shortcuts import render
from django.conf import settings
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.db.models import Q
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.files.storage import FileSystemStorage
from django.shortcuts import get_object_or_404, render
from datetime import datetime,  timedelta
from django.db.models import Sum
from django.utils import timezone
from django.core import serializers
from django.http import HttpResponse
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from testapp.api.serializers import UserLoginSerializer, UserRegistrationSerializer, AdminLoginSerializer
from testapp.api.models import User
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from random import randint

class UserRegistrationView(CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data = data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user = get_object_or_404(User, email=data['email'])
        verificationCode = random_with_N_digits(16)
        user.email_verified_hash = verificationCode
        user.save()
        subject = 'Test0709 Email veryfication'
        message = 'https://test220709.herokuapp.com/email-verification/' + str(verificationCode)

        send_mail_to(user.email,subject, message)
        status_code = status.HTTP_201_CREATED
        response = {
            'success': 'True',
            'status code': status_code,
            'type': 'User registered  successfully',
        }
        return Response(response, status=status_code)

class UserLoginView(RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data= request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'status code' : status.HTTP_200_OK,
            'access_token' : serializer.data['access_token'],
            'refresh':serializer.data['refresh'],
            'email':serializer.data['email'],
            'userStatus':serializer.data['status'],
            'is_superuser':serializer.data['is_superuser']
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)

class EmailVerify(APIView):
    permission_classes = (AllowAny,)
    def get(self, request):
        token = request.GET['token']
        user = User.objects.filter(Q(email_verified_hash=token)).first()
        if user:
                user.email_verified = True
                user.status = 1
                user.save()
                status_code = status.HTTP_200_OK
                response = {
                    'success':'true',
                    'status code':status_code,
                }
                return Response(response, status=status_code)
        else:
            status_code = status.HTTP_401_UNAUTHORIZED
            response = {
                'success':'false',
                'status code':status_code,
            }
            return Response(response, status=status_code)

class ResetPassword(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        data = request.data
        email = request.user.email
        password = data['oldpassword']
        newpassword = data['newpassword']
        user = authenticate(email=email, password=password)
        if user is None:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success':'false',
                'status code':status_code,
            }
            return Response(response, status=status_code)
        else:
            user.set_password(newpassword)
            user.save()
            status_code = status.HTTP_204_NO_CONTENT
            response = {
                'success': 'True',
                'status code': status_code,
            }
            return Response(response, status=status_code)
 
class Profile(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user
        response = {
            'status code' : status.HTTP_200_OK,
            'name':user.username,
            'email':user.email
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)
    def post(self, request):
        user = request.user
        data = request.data
        name = data['name']
        user.username = name
        user.save()
        response = {
            'status code' : status.HTTP_200_OK,
            'name':user.username,
            'email':user.email
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)


class SiteInfo(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user
        if not user.is_superuser:
            response = {
                'status code' : status.HTTP_401_UNAUTHORIZED,
            }
            status_code = status.HTTP_401_UNAUTHORIZED
            return Response(response, status=status_code)
        else:
            user_number = User.objects.filter(is_superuser=0).count()
            today = datetime.today()
            enddate = today + timedelta(days=-7)
            user_number_today = User.objects.filter(last_login__year=today.year, last_login__month=today.month, last_login__day=today.day).count()
            user_number_lastweek_average = User.objects.filter(last_login__range=[enddate, today]).count() / 7
            response = {
                'user_number':user_number,
                'user_number_lastweek_average':user_number_lastweek_average,
                'user_number_today':user_number_today
            }
            status_code = status.HTTP_200_OK
            return Response(response, status=status_code)
        
class UserList(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user
        if not user.is_superuser:
            response = {
                'status code' : status.HTTP_401_UNAUTHORIZED,
            }
            status_code = status.HTTP_401_UNAUTHORIZED
            return Response(response, status=status_code)
        else:
            users  = User.objects.filter(is_superuser=0).values('pk','username','email','created_at','login_number', 'last_login')         
            response = {
                'users':users
            }
            status_code = status.HTTP_200_OK
            return Response(response, status=status_code)
        

class FacebookLogin(SocialLoginView):
    adapter_class = FacebookOAuth2Adapter

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    
def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

def send_mail_to(useremail, subject, message):
    email_from = settings.SERVER_EMAIL
    recipient_list = [useremail]
    send_mail(subject, message, email_from, recipient_list)
    return True