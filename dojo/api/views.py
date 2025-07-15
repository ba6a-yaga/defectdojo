"""
API Views for Defect Dojo.
"""
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action

class VulnerabilityViewSet(viewsets.ViewSet):
    """
    ViewSet for vulnerability management.
    """
    
    def list(self, request):
        """List vulnerabilities."""
        return Response({
            'message': 'Defect Dojo API is working!',
            'status': 'success'
        })
    
    @action(detail=False, methods=['get'])
    def health(self, request):
        """Health check endpoint."""
        return Response({
            'status': 'healthy',
            'service': 'Defect Dojo API'
        }) 