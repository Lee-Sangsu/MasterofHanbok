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
            hashd_password = bcrypt.hashpw(
                data['password'].encode('utf-8'), bcrypt.gensalt())

            user = SignUpModel(
                user_id=data['user_id'],
                nickname=data['nickname'],
                phone_num=data['phone_num'],
                password=hashd_password.decode('utf-8'),
            )
            user.save()
            return JsonResponse({'message': "SUCCESS"}, status=200)
        except KeyError:
            return JsonResponse({'message': "INVALID_KEYS"}, status=400)


class UserLoginAPIView(ObtainJSONWebToken):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        try:
            if SignUpModel.objects.filter(user_id=data['user_id']).exists():

                user = SignUpModel.objects.get(user_id=data['user_id'])
                user_password = user.password.encode('utf-8')

                if bcrypt.checkpw(data['password'].encode('utf-8'), user_password):
                    # 토큰발행
                    token = jwt.encode(
                        {'id': user.id}, SECRET_KEY, algorithm="HS256").decode('utf-8')
                    nickname = user.nickname

                    return JsonResponse({"token": token, "nickname": nickname}, status=200)

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
