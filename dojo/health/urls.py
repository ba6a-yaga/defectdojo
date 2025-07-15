"""
Health check URLs for Defect Dojo.
"""
from django.urls import path
from . import views
 
urlpatterns = [
    path('', views.health_check, name='health_check'),
] 