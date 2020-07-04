from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
# Create your models here.
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _


class UserManager(BaseUserManager):
    def create_user(self, phone_num, nick_name, password=None):
        """
        주어진 이메일, 닉네임, 비밀번호 등 개인정보로 User 인스턴스 생성
        """
        if not phone_num:
            raise ValueError(_('Users must have an email address'))

        user = self.model(
            phone_num=phone_num,
            nick_name=nick_name,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_num, nick_name, password):
        """
        주어진 이메일, 닉네임, 비밀번호 등 개인정보로 User 인스턴스 생성
        단, 최상위 사용자이므로 권한을 부여한다. 
        """
        user = self.create_user(
            phone_num=phone_num,
            password=password,
            nick_name=nick_name,
        )

        user.is_superuser = True
        user.save(using=self._db)
        return user


class SignUpModel(AbstractBaseUser, PermissionsMixin):
    # new_id = models.CharField(max_length=50, default=None, null=False)
    nick_name = models.CharField(
        max_length=4, default=None, null=False, unique=True)
    phone_num = models.CharField(max_length=15, default=None, null=False)
    objects = UserManager()
    """
    manager 부분만 고치면 달 되겄다
    """

    REQUIRED_FIELDS = ('new_id', 'password', 'phone_num')
    USERNAME_FIELD = 'nick_name'

    is_anonymxous = False
    is_authenticated = True

    def __str__(self):
        return self.nick_name

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password
