from rest_framework_jwt.views import obtain_jwt_token
from django.conf.urls import url
# from .views import UserLoginAPIView, UserRegisterAPIView


urlpatterns = [
    url(r'^token-for-login', obtain_jwt_token),  # Token을 가져오는 url
    # url(r'^register/', UserRegisterAPIView.as_view(), name='register'),
    # url(r'^login', UserLoginAPIView.as_view(), name='login'),
    # url(r'^token-check', TokenCheckView.as_view(), name='token-check')
]
