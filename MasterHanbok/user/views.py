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


class UserRegisterAPIView(generics.ListCreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]
    queryset = SignUpModel.objects.all()

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
    #             password=password_crypt                               # 암호화된 비밀번호를 DB에 저장
    #         ).save()
    #         return HttpResponse(status=200)

    #     except KeyError:
    #         return JsonResponse({"message": "INVALID_KEYS"}, status=400)


class UserLoginAPIView(APIView):

    # post를 하기 때문에 localhost:8000/api/test/login 으로 데이터를 확인할 수 없음
    # localhost:8000/api/test/login으로 확인하기 위해서는!
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    # @authentication_classes((JSONWebTokenAuthentication,))
    # def post(self, request, *args, **kwargs):
    #     data = request.data
    #     serializer = UserLoginSerializer(data=data)
    #     if serializer.is_valid(raise_exception=True):
    #         new_data = serializer.data
    #         return HttpResponse(new_data, status=200)
    #     return HttpResponse(serializer.errors, status=400)
    def post(self, request):
        data = json.loads(request.body)
        try:
            if SignUpModel.objects.filter(phone_num=data['phone_num']).exists():
                user = SignUpModel.objects.get(phone_num=data['phone_num'])
                #---------비밀번호 확인--------#
                # 사용자가 입력한 비밀번호를 인코딩하고, 사용자의 이메일과 매칭되는 DB의 비밀번호를 찾아와서 인코딩. 이 두 값을 bcrypt.checkpw로 비교하면 됨

                if bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
                    #----------토큰 발행----------#
                    token = jwt.encode(
                        {'phone_num': data['phone_num']}, SECRET_KEY, algorithm="HS256")
                    # 유니코드 문자열로 디코딩
                    token = token.decode('utf-8')
                    #-----------------------------#
                    # 토큰을 담아서 응답
                    return JsonResponse({"token": token}, status=200)

                else:
                    return HttpResponse(status=401)
            return HttpResponse(status=400)

        except KeyError:
            return JsonResponse({"message": "INVALID_KEYS"}, status=400)


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
