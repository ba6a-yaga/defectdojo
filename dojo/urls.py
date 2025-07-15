"""
URL configuration for Defect Dojo project.
"""
from django.contrib import admin
from django.urls import path, include
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden
from dojo import views

def admin_method_check(request):
    """Проверка разрешенных HTTP методов для admin"""
    if request.method not in ['GET', 'POST']:
        return HttpResponseForbidden("Method not allowed")
    return admin.site.login(request)

urlpatterns = [
    path('', views.index, name='home'),
    path('health/', views.health, name='health'),
    path('admin/login/', admin_method_check, name='admin_login'),
    path('admin/', admin.site.urls),
    path('api/', include('dojo.api.urls')),
] 