#!/bin/bash

# Скрипт для создания .env файла с переменными окружения

echo "🔧 Создание .env файла..."

cat > .env << EOF
# Django settings
SECRET_KEY=django-insecure-dev-key-for-local-development-only
DEBUG=True

# Database settings
DB_PASSWORD=defectdojo_password_123

# Redis settings
REDIS_PASSWORD=redis_password_123

# Application settings
DJANGO_SETTINGS_MODULE=dojo.settings
ALLOWED_HOSTS=localhost,127.0.0.1
EOF

echo "✅ .env файл создан успешно!"
echo "📝 Содержимое .env файла:"
cat .env 