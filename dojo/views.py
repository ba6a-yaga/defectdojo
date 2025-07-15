from django.shortcuts import render

def index(request):
    return render(request, "index.html", {
        "project_title": "Дипломный проект DevSecOps: Безопасный CI/CD для Defect Dojo",
        "author": "Падалко Роман",
        "description": "Автоматизированный пайплайн с SAST, DAST, Security Gateway, деплоем и мониторингом для Defect Dojo. Реализовано на GitHub Actions, Docker, Yandex Cloud."
    }) 