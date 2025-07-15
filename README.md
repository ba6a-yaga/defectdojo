# DevSecOps Дипломный Проект

## Описание проекта

Данный проект демонстрирует реализацию безопасного CI/CD пайплайна для open-source проекта **Defect Dojo** - платформы для управления уязвимостями.

**Defect Dojo** - это платформа для управления уязвимостями с открытым исходным кодом, которая помогает организациям:
- Отслеживать уязвимости безопасности
- Управлять процессами исправления
- Интегрироваться с инструментами безопасности
- Предоставлять отчеты и аналитику

## Архитектура проекта

```
├── .github/workflows/          # GitHub Actions пайплайны
├── security/                   # Инструменты безопасности
├── scripts/                   # Скрипты автоматизации
└── dojo/                      # Django приложение Defect Dojo
```

## Компоненты безопасности

### 1. SAST (Static Application Security Testing)
- **Bandit** - анализ Python кода на уязвимости
- **Semgrep** - семантический анализ кода
- **Safety** - проверка зависимостей Python
- **Trivy** - сканирование Docker образов

### 2. DAST (Dynamic Application Security Testing)
- **OWASP ZAP** - динамическое тестирование безопасности
- **Nuclei** - сканирование уязвимостей

### 3. Security Checks
- **TruffleHog** - поиск секретов в коде
- **Hadolint** - проверка Dockerfile
- **Checkov** - проверка IaC (Terraform/CloudFormation)

### 4. Security Gateway
- Автоматическая блокировка при критических уязвимостях
- Комментарии в Pull Request
- Рекомендации по исправлению

## Пайплайн CI/CD

### Этапы выполнения:
1. **SAST Analysis** - статический анализ безопасности
2. **Build Application** - сборка Docker образа + Trivy сканирование
3. **DAST Analysis** - динамический анализ безопасности
4. **Security Checks** - проверка секретов и IaC
5. **Security Gateway** - анализ результатов и блокировка деплоя
6. **Deploy to Cloud** - автоматический деплой в Yandex Cloud

### Триггеры запуска:
- Push в ветки `main` и `develop`
- Pull Request в ветку `main`
- Ежедневное сканирование в 2:00

## Быстрый старт

### Локальная разработка
```bash
# Клонирование репозитория
git clone git@github.com:ba6a-yaga/defectdojo.git
cd sib-Diplom-Track-DevSecOps

# Создание .env файла с переменными окружения
./scripts/setup-env.sh

# Запуск локальной разработки
docker-compose up -d

# Запуск тестов безопасности
./scripts/security-scan.sh
```

### Автоматический деплой в облако
1. Push в ветку `main` автоматически запустит:
   - ✅ SAST анализ (Bandit, Semgrep, Safety)
   - ✅ Сборка Docker образа + Trivy сканирование
   - ✅ DAST анализ (OWASP ZAP, Nuclei)
   - ✅ Security Checks (TruffleHog, Hadolint, Checkov)
   - ✅ Security Gateway (анализ результатов)
   - ✅ Автоматический деплой на сервер в Yandex Cloud
   - ✅ Перезапуск контейнеров
   - ✅ Health check

## Автор

**Падалко Роман** - студент Netology, DevSecOps трек

## Ссылки

- **Приложение**: http://localhost:8000 (локально) / http://[SERVER_HOST]:8000 (продакшн)
- **SonarQube**: http://localhost:9000 (локально) / http://[SERVER_HOST]:9000 (продакшн)
- **Репозиторий**: https://github.com/ba6a-yaga/defectdojo