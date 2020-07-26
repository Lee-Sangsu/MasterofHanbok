from MasterHanbok.models import SignUpModel, RequestModel, Bidders, BiddingModel, DetailBiddingModel
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
import bcrypt
from MasterHanbok.settings import SECRET_KEY
from django.db import IntegrityError
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.settings import api_settings
from django.core.exceptions import ObjectDoesNotExist
from MasterHanbok.serializer import requestJSONSerializer
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.query import QuerySet


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


class Biddings(View):
    @ login_decorator
    def get(self, request, *args, pk):
        # """1. request pk에 해당하는 requestModel을 가져와
        # 2. 그 requestModeldms requests인데, 그게 BiddingModel의 request인 Bidding들 가져와
        # 3. 그 Bidding들이 biddings인데, 얘랑 연결된 bidder, detailBidding들도 가져와. (_set으로 가져오렴)"""
        # requests = RequestModel.objects.get(id=pk)
        # biddings = BiddingModel.objects.filter(request=requests)
        # # detailBidding = DetailBiddingModel.objects.filter(bidding=biddings)
        # bidder = BiddingModel.bidder_set.get()
        # detail_bid = BiddingModel.detail_bidding_set.all()

        # listJson = {
        #     "bidder": bidder,

        # }

        # a = json.dumps(list())

        # """
        # 1. serialize 다 해
        # 2. json으로 한꺼번에 묶자
        # 3. JsonResponse"""

        # return JsonResponse()

        pass


class specific_biddings(View):
    pass

# 코드 만지지 마세요