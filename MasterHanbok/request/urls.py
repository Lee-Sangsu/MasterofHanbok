"""request URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from request.views import hanbokRequestView, Biddings, specific_biddings, DetailBiddings, AnsweredRequests, UnansweredRequests

urlpatterns = [
    path('', hanbokRequestView.as_view()),
    path('<int:pk>/unanswered-requests/', UnansweredRequests.as_view()),
    path('<int:pk>/answered-requests/', AnsweredRequests.as_view()),
    path('<int:pk>/biddings/detail', DetailBiddings.as_view()),
    path('<int:pk>/biddings/', Biddings.as_view()),
    path('<int:pk>/biddings/<int:bpk>', specific_biddings.as_view())
]
