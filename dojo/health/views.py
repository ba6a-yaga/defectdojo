"""
Health check views for Defect Dojo.
"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def health_check(request):
    """Health check endpoint."""
    return JsonResponse({
        'status': 'healthy',
        'service': 'Defect Dojo',
        'version': '1.0.0'
    }) 