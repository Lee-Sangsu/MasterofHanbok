from django.contrib import admin
from django.urls import path, include
from .views import UserRegisterAPIView, UserLoginAPIView, DeleteUserView
from request.views import Certification


urlpatterns = [
    path('admin/', admin.site.urls),
    path('user', UserRegisterAPIView.as_view(), name='register'),
    path('user/<int:pk>/delete/', DeleteUserView.as_view()),
    path('users', UserLoginAPIView.as_view()),
    path('users/certification', Certification.as_view()),
    path('requests/', include('request.urls'))
]
