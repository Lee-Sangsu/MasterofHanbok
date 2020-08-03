from rest_framework import serializers
from .models import RequestModel, BiddingModel
from django.core.validators import ValidationError
from django.db.models import Q


class biddingJsonSerializer(serializers.ModelSerializer):
    bidder = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta():
        model = BiddingModel
        fields = ['bidder', 'id', 'bidder']
