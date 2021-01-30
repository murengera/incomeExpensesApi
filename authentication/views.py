from django.conf import settings

from  .models import  User
from django.shortcuts import render
from rest_framework import generics, status,views
# Create your views here.
from rest_framework.response import Response
from  rest_framework_simplejwt.tokens import  RefreshToken
from .utils import  Util
from .serializers import *
from  django.contrib.sites.shortcuts import get_current_site
from  django.urls import reverse
from incomeexpenseapi import  settings

import jwt
from  drf_yasg.utils import  swagger_auto_schema
from  drf_yasg import openapi

from  django.utils.encoding import  smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from  django.contrib.auth.tokens import PasswordResetTokenGenerator
from  django.utils.http import  urlsafe_base64_decode,urlsafe_base64_encode
from  django.contrib.sites.shortcuts import  get_current_site
from  django.urls import reverse
from  .utils import  Util

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def post(self,request):
        user=request.data

        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data=serializer.data
        user=User.objects.get(email=user_data['email'])
        token=RefreshToken.for_user(user).access_token
        relativeLink=reverse('email-verify')
        current_site=get_current_site(request).domain
        absurl = 'http://' + current_site + relativeLink + "token="+str(token)
        email_body='Hi'+user.username + 'Use link below to verify your email \n' + absurl

        data = {'email_body':email_body,'to_email':user.email,'email_subject':'Verify your email'}
        Util.send_email(data)
        return  Response(user_data,status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
        serializer_class = EmailVerificationSerializer
        token_param_config=openapi.Parameter('token',in_=openapi.IN_QUERY,description='Description',type=openapi.TYPE_STRING)
        @swagger_auto_schema(manual_parameters=[token_param_config])
        def get(self, request):
            token = request.GET.get('token')
            print("token",token)
            try:
                payload=jwt.decode(token,settings.SECRET_KEY, algorithms=["HS256"],)
                print(payload)
                user=User.objects.get(id=payload['user_id'])
                print(("user",user))
                if not user.is_verified:
                    user.is_verified=True

                    user.save()
                return Response({'email':'Successfully activated'}, status=status.HTTP_200_OK)
            except jwt.ExpiredSignatureError  as identifier :
                return Response({'error': 'Activation link was expired'}, status=status.HTTP_400_BAD_REQUEST)

            except jwt.exceptions.DecodeError  as identifier :
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return  Response(serializer.data,status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer


    def post(self,request):
        data={'request':request,'data':request.data}
        serializers=self.serializer_class(data=data)
        email=request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id) )
            token = PasswordResetTokenGenerator().make_token((user))
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password \n' + absurl

            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'reset your password'}
            Util.send_email(data)
        return  Response({'success':'we have sent you a link to reset your password'},status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self,request,uidb64,token):
        try:
            id=smart_str(urlsafe_base64_decode(uidb64))
            print("user_id",id)
            user=User.objects.get(id=id)
            print("user",user)
            print(token)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return  Response({'error':'Token is not valid,please request a new one'},status=status.HTTP_401_UNAUTHORIZED)

            return  Response({'sucess':True,'message':'Credentials valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'error': 'Token is not valid,please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)




class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class =serNewPasswordSerializer
    def patch(self,request):
        serializers=self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        return  Response({'seccess':True,'message':'Password reset success'},status=status.HTTP_200_OK)

