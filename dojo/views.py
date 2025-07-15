from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def index(request):
    return render(request, "index.html", {
        "project_title": "Дипломный проект DevSecOps: Безопасный CI/CD для Defect Dojo",
        "author": "Падалко Роман",
        "description": "Автоматизированный пайплайн с SAST, DAST, Security Gateway, деплоем и мониторингом для Defect Dojo. Реализовано на GitHub Actions, Docker, Yandex Cloud."
    })

@csrf_exempt
def health(request):
    """Health check endpoint for monitoring"""
    return JsonResponse({
        "status": "healthy",
        "service": "Defect Dojo DevSecOps",
        "version": "1.0.0"
    }) 