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
from .serializer import UserCreateSerializer, UserLoginSerializer
from rest_framework.permissions import AllowAny
import time
import json
import jwt
# import requests
import bcrypt
from MasterHanbok.settings import SECRET_KEY
from django.db import IntegrityError


class UserRegisterAPIView(generics.ListCreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]
    queryset = SignUpModel.objects.all()

    # def post(self, request):

    # try:
    #     hashed_password = bcrypt.hashpw(
    #         data['password'].encode('utf-8'), bcrypt.gensalt())
    #     SignUpModel(
    #         nick_name=data['nick_name'],
    #         password=hashed_password.decode('utf-8'),
    #         phone_num=data['phone_num']
    #     ).save()
    #     return JsonResponse({'message': 'SUCCESS'}, status=200)

    # except TypeError:
    #     return JsonResponse({'message': 'FAILED_HASHED'}, status=400)
    # except KeyError:
    #     return JsonResponse({'message': 'INVALID_KEYS'}, status=400)
    # except IntegrityError:
    #     data['nick_name'] in SignUpModel.objects.values_list(
    #         'nick_name', flat=True)
    #     return JsonResponse({'message': 'DUPLICATE_NICK_NAME'}, status=401)
    # except IntegrityError:
    #     data['phone_number'] in SignUpModel.objects.values_list(
    #         'phone_number', flat=True)
    #     return JsonResponse({'message': 'DUPLICATE_PHONE_NUMBER'}, status=401)

    #-----------밑에 있는 것들: 회원가입과 동시에 입력 정보들 암호화 하는 구문-----------#
    # def post(self, request):
    #     data = json.loads(request.body)
    #     try:
    #         password = data['password'].encode(
    #             'utf-8')                 # 입력된 패스워드를 바이트 형태로 인코딩
    #         password_crypt = bcrypt.hashpw(
    #             password, bcrypt.gensalt())  # 암호화된 비밀번호 생성
    #         # DB에 저장할 수 있는 유니코드 문자열 형태로 디코딩
    #         password_crypt = password_crypt.decode('utf-8')
    #         #====================#
    #         SignUpModel(
    #             nick_name=data['nick_name'],
    #             password=password_crypt

    # 암호화된 비밀번호를 DB에 저장
    #         ).save()
    #         return HttpResponse(status=200)

    #     except KeyError:
    #         return JsonResponse({"message": "INVALID_KEYS"}, status=400)


class UserLoginAPIView(APIView):

    # post를 하기 때문에 localhost:8000/api/test/login 으로 데이터를 확인할 수 없음
    # localhost:8000/api/test/login으로 확인하기 위해서는!
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    # 이게 회원가입 할떄 인코팅 하고, login때 디코딩 하는게 맞는 것 같아. 다시 뷰 수정해봐 모델은 딱히 문제없고, url도 문제는 없는데 serializer랑 view를 연결해야 해서 좀 까다롭긴 할테지만 화이팅 해라 모르면 희종썜한테 물어보고

    # @authentication_classes((JSONWebTokenAuthentication,))
    # def post(self, request, *args, **kwargs):
    #     data = request.data
    #     serializer = UserLoginSerializer(data=data)
    #     if serializer.is_valid(raise_exception=True):
    #         new_data = serializer.data
    #         return HttpResponse(new_data, status=200)
    #     return HttpResponse(serializer.errors, status=400)
    # def post(self, request):
    #     data = json.loads(request.body)
    #     try:
    #         if SignUpModel.objects.filter(nick_name=data['nick_name']).exists():
    #             user = SignUpModel.objects.get(nick_name=data['nick_name'])
    #             #---------비밀번호 확인--------#
    #             # 사용자가 입력한 비밀번호를 인코딩하고, 사용자의 별명과 매칭되는 DB의 비밀번호를 찾아와서 인코딩.
    #             # 이 두 값을 bcrypt.checkpw로 비교

    #             if bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
    #                 #----------토큰 발행----------#
    #                 token = jwt.encode(
    #                     {'nick_name': data['nick_name']}, SECRET_KEY, algorithm="HS256")
    #                 # 유니코드 문자열로 디코딩
    #                 decodedToken = token.decode('utf-8')
    #                 #-----------------------------#
    #                 # 토큰을 담아서 응답
    #                 return JsonResponse({"token": decodedToken}, status=200)

    #             else:
    #                 return HttpResponse(status=401)
    #         return HttpResponse(status=400)

    #     except KeyError:
    #         return JsonResponse({"message": "INVALID_KEYS"}, status=400)


class TokenCheckView(View):
    def post(self, request):
        data = json.loads(request.body)

        user_token_info = jwt.decode(
            data['token'], SECRET_KEY, algorithm='HS256')

        if SignUpModel.objects.filter(phone_num=user_token_info['phone_num']).exists():
            return HttpResponse(status=200)

        return HttpResponse(status=403)


# def login_decorator(func):
#     def wrapper(self, request, *args, **kwargs):
#         try:
#             access_token = request.headers.get('Authorization', None)
#             payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
#             user = SignUpModel.objects.get(email=payload['emphone_numail'])
#             request.user =user

#         except jwt.exceptions.DecodeError:
#             return JsonResponse({'message' : 'INVALID_TOKEN' }, status=400)

#         except SignUpModel.DoesNotExist:
#             return JsonResponse({'message' : 'INVALID_USER'}, status=400)
#         return func(self, request, *args, **kwargs)
#     return wrapper
