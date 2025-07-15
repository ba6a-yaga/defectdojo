"""
Custom middleware for security improvements
"""

from django.http import HttpResponseForbidden
from django.conf import settings

class SecurityMiddleware:
    """Middleware для улучшения безопасности"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Ограничиваем HTTP методы для admin
        if request.path.startswith('/admin/'):
            if request.method not in ['GET', 'POST']:
                return HttpResponseForbidden("Method not allowed")
        
        # Ограничиваем HTTP методы для API
        if request.path.startswith('/api/'):
            if request.method not in ['GET', 'POST', 'PUT', 'DELETE']:
                return HttpResponseForbidden("Method not allowed")
        
        response = self.get_response(request)
        
        # Добавляем заголовки безопасности
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Добавляем заголовки для защиты от Spectre
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Embedder-Policy'] = 'require-corp'
        
        return response 