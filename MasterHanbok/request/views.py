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
from MasterHanbok.serializer import biddingJsonSerializer, UserRequestIDSerializer
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.query import QuerySet
from django.db.models import F, Count


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
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        filterRequests = RequestModel.objects.filter(
            requested_user=user, ended_or_not=False).order_by('-id').annotate(bidding_count=Count(F('bidding'))).values()
        dumpJSON = json.dumps(list(filterRequests))
        return HttpResponse(dumpJSON, status=200)

    @ login_decorator
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])
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
            return JsonResponse({'biddings': a.data}, status=200)
        else:
            return JsonResponse({'message': '해당 요청의 견적이 없습니다.'}, status=400)


class specific_biddings(View):
    def get(self, request, *args, pk, bpk):
        specific_bidding = BiddingModel.objects.get(id=bpk)
        a = biddingJsonSerializer(specific_bidding, many=False)
        return JsonResponse({'bidding': a.data}, status=200)


class Certification(View):

    @login_decorator
    def get(self, request):
        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.filter(id=payload['id'])
        b = UserRequestIDSerializer(user, many=True)
        return JsonResponse(b.data, status=200, safe=False)

    @login_decorator
    def post(self, request):
        data = json.loads(request.body)

        access_token = request.headers.get('Authorization', None)
        payload = jwt.decode(access_token, SECRET_KEY, algorithm='HS256')
        user = SignUpModel.objects.get(id=payload['id'])

        user.certification = data['certification']
        user.save()
        return HttpResponse(status=200)
