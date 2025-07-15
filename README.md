# DevSecOps Дипломный Проект

## Описание проекта

Данный проект демонстрирует реализацию безопасного CI/CD пайплайна для open-source проекта **Defect Dojo** - платформы для управления уязвимостями.

## Архитектура проекта

```
├── .github/workflows/          # GitHub Actions пайплайны
├── security/                   # Инструменты безопасности
└── scripts/                   # Скрипты автоматизации
```

## Компоненты безопасности

### 1. SAST (Static Application Security Testing)
- **SonarQube** - анализ качества кода и уязвимостей
- **Bandit** - анализ Python кода на уязвимости
- **Semgrep** - семантический анализ кода
- **Trivy** - сканирование зависимостей

### 2. DAST (Dynamic Application Security Testing)
- **OWASP ZAP** - динамическое тестирование безопасности
- **Nuclei** - сканирование уязвимостей
- **Nikto** - тестирование веб-серверов

### 3. Security Checks
- **TruffleHog** - поиск секретов в коде
- **Hadolint** - проверка Dockerfile
- **Checkov** - проверка IaC (Terraform/CloudFormation)

### 4. Security Gateway
- Автоматическая блокировка при критических уязвимостях
- Комментарии в Pull Request
- Рекомендации по исправлению

## Быстрый старт

### Локальная разработка
```bash
# Клонирование репозитория
git clone git@github.com:ba6a-yaga/defectdojo.git
cd sib-Diplom-Track-DevSecOps

# Запуск локальной разработки
docker-compose up -d

# Запуск тестов безопасности
./scripts/security-scan.sh
```

### Автоматический деплой в облако
1. Push в ветку `main` автоматически запустит:
   - ✅ SAST анализ
   - ✅ DAST анализ  
   - ✅ Security Checks
   - ✅ Security Gateway
   - ✅ Автоматический деплой на сервер
   - ✅ Перезапуск контейнеров
   - ✅ Health check