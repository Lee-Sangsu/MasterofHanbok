from rest_framework import serializers
from .models import SignUpModel
from django.core.validators import ValidationError
from django.db.models import Q
from phonenumber_field.modelfields import PhoneNumberField
# from .my_settings import SECRET_KEY, ALGORITHM
import jwt


class UserCreateSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        new_id = validated_data['new_id']
        nick_name = validated_data['nick_name']
        password = validated_data['password']
        phone_num = validated_data['phone_num']

        user_obj = SignUpModel(
            new_id=new_id,
            nick_name=nick_name,
            phone_num=phone_num,
        )

        user_obj.set_password(password)
        user_obj.save()

        return validated_data

    class Meta:
        model = SignUpModel
        fields = [
            'new_id',
            'nick_name',
            'password',
            'phone_num',
        ]
        extra_kwargs = {'password': {'write_only': True}}

        # model 수정하세요 - 넵


class UserLoginSerializer(serializers.ModelSerializer):
    token = serializers.CharField(allow_blank=False, read_only=True)
    new_id = serializers.CharField(allow_blank=False)
    nick_name = serializers.CharField(required=False, allow_blank=True)
    phone_num = serializers.CharField(required=None, label=None)
    # token 생성해주는거 만들어버리기 (뷰에다가) 아 개졸려

    class Meta:
        model = SignUpModel

        fields = [
            'new_id',
            'nick_name',
            'phone_num',
            'password',
            'token',
        ]
        extra_kwargs = {'password': {"write_only": True}}

    def validate(self, data):
        new_id = data.get("new_id", None)
        phone_num = data.get("phone_num", None)
        nick_name = data.get("nick_name", None)
        password = data.get("password", None)

        if not phone_num and not new_id:
            raise ValidationError(
                "A new_id and phonenumber is required to login")

        user = SignUpModel.objects.filter(
            Q(phone_num=phone_num) |
            Q(nick_name=nick_name)
        ).distinct()

        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise ValidationError("A nickname/phone number is not valid")

        if user_obj:
            if not user_obj.check_password(password):
                raise ValidationError(
                    "Incorrect credentials please try again")

            return data
