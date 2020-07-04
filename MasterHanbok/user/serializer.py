from rest_framework import serializers
from .models import SignUpModel
from django.core.validators import ValidationError
from django.db.models import Q
from phonenumber_field.modelfields import PhoneNumberField
# from .my_settings import SECRET_KEY, ALGORITHM
import jwt


class UserCreateSerializer(serializers.HyperlinkedModelSerializer):
    def create(self, validated_data):
        nick_name = validated_data['nick_name']
        phone_num = validated_data['phone_num']
        password = validated_data['password']

        user_obj = SignUpModel(
            nick_name=nick_name,
            phone_num=phone_num
        )

# token 생성해주는거 만들어버리기 (뷰에다가) 아 개졸려

        user_obj.set_password(password)
        user_obj.save()

        return validated_data

    class Meta:
        model = SignUpModel
        fields = [
            'nick_name',
            'password',
            'phone_num',
        ]

        # model 수정하세요 - 넵


class UserLoginSerializer(serializers.ModelSerializer):
    token = serializers.CharField(allow_blank=False, read_only=True)
    nick_name = serializers.CharField(required=False, allow_blank=False)
    phone_num = serializers.CharField(required=None, label=None)

    class Meta:
        model = SignUpModel

        fields = [
            'nick_name',
            'phone_num',
            'password',
            'token',
        ]
        extra_kwargs = {'password': {"write_only": True}}

    def validate(self, data):
        phone_num = data.get("phone_num", None)
        nick_name = data.get("nick_name", None)
        password = data.get("password", None)

        if not phone_num and not nick_name:
            raise ValidationError(
                "A nickname and phonenumber is required to login")

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
