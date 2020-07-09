from .models import SignUpModel
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.core import serializers
# from .serializers import PostSerializer
from django.shortcuts import render, get_object_or_404
from django.core.serializers import serialize
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.permissions import AllowAny
import time
import json
import jwt
# import requests
import bcrypt
from MasterHanbok.settings import SECRET_KEY
from django.db import IntegrityError
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.settings import api_settings
from django.core.exceptions import ObjectDoesNotExist


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class UserRegisterAPIView(ObtainJSONWebToken):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        user = SignUpModel(
            user_id=data['user_id'],
            nickname=data['nickname'],
            phone_num=data['phone_num'],
            password=data['password'],
        )
        password = data['password'].encode('utf-8')
#     입력된 패스워드를 바이트 형태로 인코딩
        password_crypt = bcrypt.hashpw(password, bcrypt.gensalt())
        # DB에 저장할 수 있는 유니코드 문자열 형태로 디코딩
        password_crypt = password_crypt.decode('utf-8')
        user.save()

        token = jwt.encode(
            {'user_id': data['user_id']}, SECRET_KEY, algorithm="HS256")
        # 유니코드 문자열로 디코딩
        decodedToken = token.decode('utf-8')

        # signUpModel = SignUpModel.objects.filter(nickname=data['nickname'])
        # serializedUser = json.loads(serialize('json', signUpModel))

        user_nickname = user.nickname
        return JsonResponse({'token': decodedToken, 'user_nickname': user_nickname}, status=200)
        # unique 하지 않은 id 입력했을 때 뜰 error메세지 cutomize 해야 해


def login_decorator(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            access_token = request.headers.get('Authorization', None)
            payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
            user = SignUpModel.objects.get(user_id=payload['user_id'])
            request.user = user

        except jwt.exceptions.DecodeError:
            return JsonResponse({'message': 'INVALID_TOKEN'}, status=400)

        except SignUpModel.DoesNotExist:
            return JsonResponse({'message': 'INVALID_USER'}, status=400)
        return func(self, request, *args, **kwargs)
    return wrapper


class hanbokRequestView(View):
    @login_decorator
    def post(self, request, *args, **kwargs):
        pass

# pk 쏴줘야 함. Objects.all 조지면 되겄다.
