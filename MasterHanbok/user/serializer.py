from rest_framework import serializers
from .models import SignUpModel
from django.core.validators import ValidationError
from django.db.models import Q
from phonenumber_field.modelfields import PhoneNumberField
# from .my_settings import SECRET_KEY, ALGORITHM
import jwt


class UserCreateSerializer(serializers.ModelSerializer):
    def create(self, validated_data, data):
        user_id = validated_data['user_id']
        nickname = validated_data['nickname']
        password = validated_data['password']
        phone_num = validated_data['phone_num']
        # token = serializers.CharField(allow_blank=False, read_only=True)

        if not phone_num and not user_id:
            raise ValidationError(
                "A new_id and phonenumber is required to login")

        user_obj = SignUpModel(
            user_id=user_id,
            nickname=nickname,
            phone_num=phone_num,
        )

        user_obj.set_password(password)
        user_obj.save()

        return validated_data

    class Meta:
        model = SignUpModel
        fields = [
            'new_id',
            'nickname',
            'password',
            'phone_num',
            'token',
        ]
        extra_kwargs = {'password': {'write_only': True}}

        # model 수정하세요 - 넵


class UserLoginSerializer(serializers.ModelSerializer):
    token = serializers.CharField(allow_blank=False, read_only=True)
    user_id = serializers.CharField(required=True)
    nickname = serializers.CharField(required=False, allow_blank=True)
    phone_num = serializers.CharField(required=None, label=None)
    # token 생성해주는거 만들어버리기 (뷰에다가) 아 개졸려

    class Meta:
        model = SignUpModel

        fields = [
            'user_id',
            'nickname',
            'phone_num',
            'password',
            'token',
        ]
        extra_kwargs = {'password': {"write_only": True}}

    def validate(self, data):
        user_id = data.get("user_id", None)
        phone_num = data.get("phone_num", None)
        nickname = data.get("nickname", None)
        password = data.get("password", None)

        if not phone_num and not user_id:
            raise ValidationError(
                "A new_id and phonenumber is required to login")

        user = SignUpModel.objects.filter(
            Q(phone_num=phone_num) |
            Q(nickname=nickname) |
            Q(user_id=user_id)
        ).distinct()

        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise ValidationError("A new_id/phone number is not valid")

        if user_obj:
            if not user_obj.check_password(password):
                raise ValidationError(
                    "Incorrect credentials please try again")

            return data
