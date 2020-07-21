from rest_framework import serializers
from .models import RequestModel, SignUpModel
from django.core.validators import ValidationError
from django.db.models import Q


class requestJSONSerializer(serializers.ModelSerializer):
    class Meta():
        model = RequestModel
        fields = '__all__'
