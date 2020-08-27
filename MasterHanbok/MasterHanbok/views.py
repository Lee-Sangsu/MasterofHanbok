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
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.query import QuerySet


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class UserRegisterAPIView(ObtainJSONWebToken):
    def post(self, request):
        try:
            hashd_password = bcrypt.hashpw(
                request.data.get('password').encode('utf-8'), bcrypt.gensalt())

            user = SignUpModel(
                user_id=request.data.get('user_id'),
                nickname=request.data.get('nickname'),
                phone_num=request.data.get('phone_num'),
                password=hashd_password.decode('utf-8'),
            )
            user.save()
            return JsonResponse({'message': "SUCCESS"}, status=200)
        except KeyError:
            return JsonResponse({'message': "INVALID_KEYS"}, status=400)


class UserLoginAPIView(ObtainJSONWebToken):
    def post(self, request):
        # data = json.loads(request.body.decode('utf-8'))
        try:
            if SignUpModel.objects.filter(user_id=request.data.get('user_id')).exists():

                user = SignUpModel.objects.get(
                    user_id=request.data.get('user_id'))
                user_password = user.password.encode('utf-8')

                if user.del_or_not == True:
                    return JsonResponse({'message': '탈퇴한 사용자입니다.'}, status=401)

                elif user.del_or_not == False:

                    if bcrypt.checkpw(request.data.get('password').encode('utf-8'), user_password):
                        # 토큰발행
                        token = jwt.encode(
                            {'id': user.id}, SECRET_KEY, algorithm="HS256").decode('utf-8')
                        nickname = user.nickname

                        return JsonResponse({"token": token, "nickname": nickname, "user_pk": user.pk, "phone_num": user.phone_num}, status=200)

                    else:
                        return JsonResponse({'message': "비밀번호가 틀렸습니다!"}, status=401)

            else:
                return JsonResponse({'message': "일치하는 아이디가 없습니다"}, status=400)
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


class DeleteUserView(View):
    @login_decorator
    def put(self, request, pk):
        try:
            user = SignUpModel.objects.get(id=pk)
            user.user_id = 'null'
            user.password = 'null'
            user.phone_num = 'null'
            user.del_or_not = True
            user.save()
            return HttpResponse(status=200)
        except:
            return HttpResponse(status=405)
