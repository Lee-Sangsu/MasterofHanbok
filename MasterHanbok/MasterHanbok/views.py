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
            {'id': user.pk}, SECRET_KEY, algorithm="HS256")
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
            user = SignUpModel.objects.get(id=payload['id'])
            request.user = user

        except jwt.exceptions.DecodeError:
            return JsonResponse({'message': 'INVALID_TOKEN'}, status=400)

        except SignUpModel.DoesNotExist:
            return JsonResponse({'message': 'INVALID_USER'}, status=400)
        return func(self, request, *args, **kwargs)
    return wrapper


class hanbokRequestView(View):
    @login_decorator
    def get(self, request, *args, **kwargs):
        """
        1. signupmodel에 id=payload['id']인 유저의 objects는 user라는 method.
        2. 해당 user의 RequestModel을 filter구문으로 뽑아와 = request
        3. Json으로 출력하는데, 형식은 post로 받은 형식과 같음.
        4. detailreuqest objects get pk해놓고 request array에 append해.
        """

        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        # detailrequests = DetailRequestModel.objects.filter(request=requests)

        filterRequests = RequestModel.objects.filter(
            requested_user=user, ended_or_not=False).order_by('-id').values()

        # serializedFilterRequest = json.loads(serialize(filterRequests)) or
        # filterRequests.__dict__

        # filterRequestsID = filterRequests['pk']

        # getRequests = RequestModel.objects.get(
        #     requested_user=user).oreder_by('-id')[0]

        # serializedJSON = serializers.serialize('json', filterRequests, fields=(
        #     'requested_user_id', 'end_date', 'detail_requests'))

        dumpJSON = json.dumps(list(filterRequests))

        return HttpResponse(dumpJSON, status=200)

    @ login_decorator
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        """
        1. signupmodel에 id=payload['id']인 유저의 objects는 user라는 method.
        2. json.body에서 'end_date', 'detail_request' 가져와 해당 token의 id를 가진 user의 RequestModel에 저장.
        """

        end_date = data['end_date']

        json_detail_request = data['detail_requests']

        requestModel = RequestModel(
            requested_user=user,
            end_date=end_date,
            detail_requests=json_detail_request,
        )

        requestModel.save()

        # det = data['detail_requests']

        # for detail in det:
        #     DetailRequestModel(
        #         request_id=requestModel.pk,
        #         person=detail['person'],
        #         making_type=detail['making_type'],
        #         age=detail['age'],
        #         season=detail['season'],
        #         # detail_image=result['detail_image'],
        #         fabric=detail['fabric'],
        #         memo=detail['memo'],
        #     ).save

        return HttpResponse(status=200)

    @ login_decorator
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)

        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        end_date = data['end_date']

        make_end_or_not = RequestModel.objects.get(
            requested_user=user, end_date=end_date)

        make_end_or_not.end_date = end_date
        make_end_or_not.ended_or_not = True
        make_end_or_not.save()

        return HttpResponse(status=200)
