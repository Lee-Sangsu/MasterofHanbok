from django.db import models
# Create your models here.
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _
import bcrypt
from django.db.models.signals import post_save


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
    # id = models.AutoField(primary_key=True)
    user_id = models.CharField(
        max_length=50, default='', unique=True, verbose_name=('user_id'))
    nickname = models.CharField(max_length=4, default='')
    phone_num = models.CharField(max_length=15, default=None, null=False)
    # requests = models.ForeignKey(RequestModel)
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


class RequestModel(models.Model):
    requested_user = models.ForeignKey(
        SignUpModel, on_delete=models.CASCADE, null=True)
    end_date = models.CharField(max_length=20)
    objects = models.Manager()

    def __str__(self):
        return self.end_date

    def create_requests(self, sender, instance, created, **kwargs):
        if created:
            SignUpModel.objects.create(requested_user=instance)

    post_save.connect(create_requests, sender=requested_user)


class DetailRequestModel(models.Model):
    request = models.ForeignKey(RequestModel, on_delete=models.CASCADE)
    person = models.CharField(max_length=10)
    making_type = models.CharField(max_length=10)
    age = models.CharField(max_length=7)  # CharField?
    season = models.CharField(max_length=10)
    detailImage = models.CharField(max_length=50, null=Ture)
    fabric = models.CharField(max_length=10)
    memo = models.CharField(max_length=100)

    def __str__(self):
        return self.person

    def create_detailrequest(self, sender, instance, created, **kwargs):
        if created:
            RequestModel.objects.create(request=instance)

    post_save.connect(create_detailrequest, sender=request)
