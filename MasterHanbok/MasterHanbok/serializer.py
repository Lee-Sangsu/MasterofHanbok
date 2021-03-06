from rest_framework import serializers
from .models import RequestModel, BiddingModel, DetailBiddingModel, Bidders, SignUpModel, CertificationModel
from django.core.validators import ValidationError
from django.db.models import Q


class detailBiddingJsonSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetailBiddingModel
        fields = ('__all__')


class bidderJsonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bidders
        fields = ('__all__')


class biddingJsonSerializer(serializers.ModelSerializer):
    detail_bidding = detailBiddingJsonSerializer(read_only=True)

    # serializers.PrimaryKeyRelatedField(
    #     many=True, read_only=True)
    bidder = bidderJsonSerializer(read_only=True)

    class Meta:
        model = BiddingModel
        fields = ('id', 'price', 'detail_bidding', 'bidder')


class UserRequestIDSerializer(serializers.ModelSerializer):
    # request_id = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = SignUpModel
        fields = ('certification',)


class BidderRequstSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestModel
        fields = ('__all__')
