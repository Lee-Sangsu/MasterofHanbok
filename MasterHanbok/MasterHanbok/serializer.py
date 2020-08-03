from rest_framework import serializers
from .models import RequestModel, BiddingModel
from django.core.validators import ValidationError
from django.db.models import Q


class biddingJsonSerializer(serializers.ModelSerializer):
    detail_requests = serializers.PrimaryKeyRelatedField(
        many=True, read_only=True)
    bidder = serializers.PrimaryKeyRelatedField(many=False, read_only=True)

    class Meta():
        model = BiddingModel
        fields = ['id', 'price', 'detail_requests', 'bidder']
