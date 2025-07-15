#!/bin/bash
set -e

echo "🚀 Starting Django application..."

# Проверяем тип базы данных
if [ "$DB_ENGINE" = "django.db.backends.sqlite3" ]; then
    echo "📁 Using SQLite database for testing..."
    
    # Создаем миграции и применяем их
    echo "🔄 Running migrations..."
    python manage.py makemigrations --noinput || true
    python manage.py migrate --noinput
    
    # Создаем суперпользователя для тестирования
    echo "👤 Creating test superuser..."
    python manage.py shell -c "
from django.contrib.auth.models import User
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@test.com', 'admin123')
    print('Superuser created: admin/admin123')
else:
    print('Superuser already exists')
" || true
    
else
    echo "🐘 Using PostgreSQL database..."
    # Ждем подключения к базе данных
    echo "⏳ Waiting for database connection..."
    python manage.py wait_for_db --timeout=30 || true
    
    # Применяем миграции
    echo "🔄 Running migrations..."
    python manage.py migrate --noinput
fi

# Собираем статические файлы
echo "📦 Collecting static files..."
python manage.py collectstatic --noinput || true

# Запускаем сервер
echo "🌐 Starting Django development server..."
exec python manage.py runserver 0.0.0.0:8000 