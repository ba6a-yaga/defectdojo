#!/bin/bash
set -e

echo "🚀 Starting Django application..."

# Определяем путь к Python
PYTHON_CMD="/usr/local/bin/python"
if [ ! -x "$PYTHON_CMD" ]; then
    PYTHON_CMD="/usr/bin/python"
fi

# Проверяем права на выполнение
if [ ! -x "$PYTHON_CMD" ]; then
    echo "❌ Python не найден или нет прав на выполнение"
    echo "Попытка исправления прав..."
    chmod +x /usr/local/bin/python* 2>/dev/null || true
    chmod +x /usr/bin/python* 2>/dev/null || true
    PYTHON_CMD="/usr/local/bin/python"
fi

echo "🐍 Using Python: $PYTHON_CMD"

# Проверяем тип базы данных
if [ "$DB_ENGINE" = "django.db.backends.sqlite3" ]; then
    echo "📁 Using SQLite database for testing..."
    
    # Создаем миграции и применяем их
    echo "🔄 Running migrations..."
    $PYTHON_CMD manage.py makemigrations --noinput || true
    $PYTHON_CMD manage.py migrate --noinput
    
    # Создаем суперпользователя для тестирования
    echo "👤 Creating test superuser..."
    $PYTHON_CMD manage.py shell -c "
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
    $PYTHON_CMD manage.py wait_for_db --timeout=30 || true
    
    # Применяем миграции
    echo "🔄 Running migrations..."
    $PYTHON_CMD manage.py migrate --noinput
fi

# Собираем статические файлы
echo "📦 Collecting static files..."
$PYTHON_CMD manage.py collectstatic --noinput || true

# Запускаем сервер
echo "🌐 Starting Django development server..."
# Отключаем автоперезагрузку для DAST тестов
if [ "$DAST_TESTING" = "true" ]; then
    echo "🔒 Running in DAST mode - disabling auto-reload"
    exec $PYTHON_CMD manage.py runserver 0.0.0.0:8000 --noreload
else
    exec $PYTHON_CMD manage.py runserver 0.0.0.0:8000
fi 