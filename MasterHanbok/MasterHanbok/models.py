from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import ugettext_lazy as _
import bcrypt
from django.db.models.signals import post_save
from django.contrib.postgres.fields import JSONField, ArrayField


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
    nickname = models.CharField(max_length=40, default='')
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

    class Meta:
        db_table = 'usermodel'


class RequestModel(models.Model):
    requested_user = models.ForeignKey(
        SignUpModel, on_delete=models.CASCADE, null=True)
    end_date = models.CharField(max_length=20)
    detail_requests = JSONField()
    ended_or_not = models.BooleanField(default=False)
    objects = models.Manager()

    def __str__(self):
        return self.end_date

    def create_requests(self, sender, instance, created, **kwargs):
        if created:
            SignUpModel.objects.create(requested_user=instance)

    post_save.connect(create_requests, sender=requested_user)

    class Meta:
        db_table = 'requestmodel'


class Bidders(models.Model):
    store_name = models.CharField(max_length=15)
    phone_num = models.CharField(max_length=15)
    location = models.CharField(max_length=70)
    store_image = models.CharField(max_length=500, blank=True, null=True)
    introduce = models.CharField(max_length=70)
    objects = models.Manager()

    class Meta:
        db_table = 'bidder'


class DetailBiddingModel(models.Model):
    price_and_discount = models.CharField(max_length=15)
    service_product = models.CharField(max_length=30)
    design = models.CharField(max_length=30)
    design_images = ArrayField(models.CharField(max_length=500, default=''))
    color = models.CharField(max_length=30)
    color_images = ArrayField(models.CharField(max_length=500, default=''))
    detail = models.CharField(max_length=70)
    detail_images = ArrayField(models.CharField(max_length=500, default=''))
    note = models.CharField(max_length=70)
    note_images = ArrayField(models.CharField(max_length=500, default=''))
    objects = models.Manager()

    class Meta:
        db_table = 'detail_bid'


class BiddingModel(models.Model):
    bidder = models.ForeignKey(Bidders, on_delete=models.CASCADE)
    request = models.ForeignKey(RequestModel, on_delete=models.CASCADE)
    detail_bidding = models.OneToOneField(
        DetailBiddingModel, on_delete=models.SET_NULL, null=True)
    price = models.CharField(max_length=30)
    objects = models.Manager()

    class Meta:
        db_table = 'bid'
