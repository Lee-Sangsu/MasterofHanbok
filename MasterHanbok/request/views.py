from MasterHanbok.models import SignUpModel, RequestModel, Bidders, BiddingModel, DetailBiddingModel, CertificationModel
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
from MasterHanbok.serializer import biddingJsonSerializer, certificationJsonSerializer
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

        filterRequests = RequestModel.objects.filter(
            requested_user=user, ended_or_not=False).order_by('-id').values()

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

        return HttpResponse(status=200)

    @ login_decorator
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)

        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        end_date = data['end_date']
        ended_or_not = data['ended_or_not']

        make_end_or_not = RequestModel.objects.get(
            requested_user=user, end_date=end_date)

        make_end_or_not.end_date = end_date
        make_end_or_not.ended_or_not = ended_or_not
        make_end_or_not.save()

        return HttpResponse(status=200)


class Biddings(View):
    # @ login_decorator
    def get(self, request, pk):
        if BiddingModel.objects.filter(request_id=pk).exists():
            requests = RequestModel.objects.get(id=pk)
            biddings = BiddingModel.objects.filter(request_id=requests.pk)
            a = biddingJsonSerializer(biddings, many=True)

            #a = json.dumps(list(biddings))

            return JsonResponse({'biddings': a.data}, status=200)
        else:
            return JsonResponse({'message': '해당 요청의 견적이 없습니다.'}, status=400)

        # 이 뷰에서는 id, price, bidder
        """1. request pk에 해당하는 requestModel을 가져와
        2. 그 requestModeldms requests인데, 그게 BiddingModel의 request인 Bidding들 가져와
        3. 그 Bidding들이 biddings인데, 얘랑 연결된 bidder, detailBidding들도 가져와. (_set으로 가져오렴)"""


class specific_biddings(View):
    def get(self, request, *args, pk, bpk):
        """bpk의 값을 가진 BiddingModel의 object를 가져와"""
        specific_bidding = BiddingModel.objects.get(id=bpk)
        a = biddingJsonSerializer(specific_bidding, many=False)
        """없다면 메세지 출력하게 exists() 써서 if문 만들어."""
        return JsonResponse({'bidding': a.data}, status=200)


class Certification(View):

    @login_decorator
    def get(self, request, pk, bpk):
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        if CertificationModel.objects.filter(certificated_user=user).exists():
            certifications = CertificationModel.objects.filter(
                certificated_user=user)
            b = certificationJsonSerializer(certifications, many=True)
            return JsonResponse({'certification_arr': b}, status=200)

        else:
            return JsonResponse({'message': '견적서가 없습니다.'}, status=400)

    @login_decorator
    def post(self, request, pk, bpk):
        data = json.loads(request.body)
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        certification = data['certification']

        requestModel = BiddingModel(
            certificated_user=user,
            certification=certification,
            request_id=pk,
            bidding_id=bpk
        )

        requestModel.save()
        return HttpResponse(status=200)
