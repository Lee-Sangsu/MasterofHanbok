from .models import SignUpModel, RequestModel
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.core import serializers
from django.forms import model_to_dict
from django.shortcuts import render, get_object_or_404
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
from .serializer import requestJSONSerializer
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.query import QuerySet


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class UserRegisterAPIView(ObtainJSONWebToken):
    def post(self, request, *args, **kwargs):
        try:
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
            return JsonResponse({'message': "SUCCESS"}, status=200)
        except KeyError:
            return JsonResponse({'message': "INVALID_KEYS"}, status=400)


class UserLoginAPIView(ObtainJSONWebToken):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        try:
            # 만약 signup의 데이터 중에 request로 받아온 data['name']키값이 존재한다면
            if SignUpModel.objects.filter(user_id=data['user_id']).exists():

                # 객체를 가져온다.SignUpModel의 데이터 중 name = data['name']인 데이터를 새로운 객체로 만든다.
                user = SignUpModel.objects.get(user_id=data['user_id'])
                user_password = user.password.encode('utf-8')

                if bcrypt.checkpw(data['password'].encode('utf-8'), user_password):

                    # 토큰발행
                    token = jwt.encode(
                        {'id': user.id}, SECRET_KEY, algorithm="HS256")
                    token = token.decode('utf-8')

                    return JsonResponse({"token": token}, status=200)

                else:

                    # 리턴해라 제이슨타입으로 {'message : 비밀번호가 틀렸습니다 !}
                    return JsonResponse({'message': "비밀번호가 틀렸습니다!"}, status=401)

            else:
                return JsonResponse({'message': "일치하는 그거가 없습니다"}, status=400)
        except KeyError:
            # 리턴해라 제이슨타입으로 {message:INVALID_KEYS}
            return JsonResponse({'mesaage': "INVALID_KEYS"}, status=400)


def login_decorator(func):
    def wrapper(self, request, *args, **kwargs):
        try:
            access_token = request.headers.get('Authorization', None)
            payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
            user = SignUpModel.objects.get(id=payload['id'])
            request.user = user

        except jwt.exceptions.DecodeError:
            return JsonResponse({'message': 'INVALID_TOKEN'}, status=400)

        except SignUpModel.DoesNotExist:
            return JsonResponse({'message': 'INVALID_USER'}, status=400)
        return func(self, request, *args, **kwargs)
    return wrapper
