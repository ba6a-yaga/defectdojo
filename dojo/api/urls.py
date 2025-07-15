"""
API URLs for Defect Dojo.
"""
from django.urls import path, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'vulnerabilities', views.VulnerabilityViewSet, basename='vulnerability')

urlpatterns = [
    path('', include(router.urls)),
] 