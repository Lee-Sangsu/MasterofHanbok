from .models import SignUpModel, RequestModel
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.core import serializers
from django.shortcuts import render, get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics
import time
import json
import jwt
import bcrypt
from MasterHanbok.settings import SECRET_KEY
from django.db import IntegrityError
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.settings import api_settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.query import QuerySet
from push_notifications.models import APNSDevice
from .models import Bidders


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class UserRegisterAPIView(ObtainJSONWebToken):
    def post(self, request):
        try:
            user_id = request.data.get('user_id')

            if SignUpModel.objects.filter(user_id=user_id).exists():
                return JsonResponse({'message': 'already exist user_id'}, status=401)

            else:
                hashd_password = bcrypt.hashpw(
                    request.data.get('password').encode('utf-8'), bcrypt.gensalt())

                user = SignUpModel(
                    user_id=user_id,
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
                    return JsonResponse({'message': 'deleted user'}, status=401)

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
        user = SignUpModel.objects.get(id=pk)
        user.password = 'null'
        user.phone_num = 'null'
        user.del_or_not = True
        user.save()
        return HttpResponse(status=200)


class PushNotificationView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user_pk = SignUpModel.objects.get(id=payload['id']).pk

        if APNSDevice.objects.filter(user_id=user_pk).exists():
            return JsonResponse({'message': '해당 사용자가 이미 있습니다.'}, status=400)
        else:
            device = APNSDevice(
                user_id=user_pk,
                registration_id=data['device_token']
            )
            device.save()
            return HttpResponse(status=200)


class BidderRegistrationView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        if Bidders.objects.filter(phone_num=data['phone_num']).exists():
            return JsonResponse({'message': '이미 등록된 상인입니다.'})
        else:
            bidder = Bidders(
                store_name=data['store_name'],
                phone_num=data['phone_num']
            )
            bidder.save()
            return HttpResponse(status=200)


class BidderLoginView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        bidder = Bidders.objects.get(phone_num=data['phone_num'])
        if Bidders.objects.filter(phone_num=data['phone_num']).exists():
            return HttpResponse(bidder.pk, status=200)
        else:
            return JsonResponse({'message': '등록되지 않은 상인입니다.'})
