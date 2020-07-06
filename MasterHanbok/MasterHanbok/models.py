from django.db import models
# Create your models here.
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _
import bcrypt


class UserManager(BaseUserManager):
    def create_user(self, user_id, phone_num, nickname, password=None):
        if not phone_num:
            raise ValueError(_('Users must have an phone number'))

        user = self.model(
            user_id=user_id,
            phone_num=phone_num,
            nickname=nickname
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, phone_num, nickname, password):
        user = self.create_user(
            user_id=user_id,
            phone_num=phone_num,
            password=password,
            nickname=nickname,
        )

        user.is_superuser = True
        user.save(using=self._db)
        return user


class SignUpModel(AbstractBaseUser, PermissionsMixin):
    user_id = models.CharField(
        max_length=50, default='', unique=True, verbose_name=('user_id'))
    nickname = models.CharField(max_length=4, default='', null=True)
    phone_num = models.CharField(max_length=15, default=None, null=False)
    objects = UserManager()
    """
    manager 부분만 고치면 잘 되겄다 잘 고쳐서 잘 됐다 호호홍
    """

    REQUIRED_FIELDS = ('password', 'phone_num', 'nickname')
    USERNAME_FIELD = 'user_id'

    is_anonymxous = False
    is_authenticated = True
    is_active = True

    def __str__(self):
        return self.user_id

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password

    # def __init__(self):
    #     self.nick_name = SignUpModel.nick_name
    #     self.phone_num = SignUpModel.phone_num
    #     self.password = bcrypt.hashpw(password, bcrypt.gensalt())
