#!/bin/bash

echo "🔍 Тестирование Python в контейнере..."

# Проверяем доступные версии Python
echo "📋 Доступные версии Python:"
which python || echo "python не найден"
which python3 || echo "python3 не найден"
which /usr/local/bin/python || echo "/usr/local/bin/python не найден"
which /usr/bin/python || echo "/usr/bin/python не найден"

echo "📋 Права на Python:"
ls -la /usr/local/bin/python* 2>/dev/null || echo "Нет файлов в /usr/local/bin/python*"
ls -la /usr/bin/python* 2>/dev/null || echo "Нет файлов в /usr/bin/python*"

echo "📋 Тестирование выполнения Python:"
/usr/local/bin/python --version 2>/dev/null || echo "Ошибка выполнения /usr/local/bin/python"
/usr/bin/python --version 2>/dev/null || echo "Ошибка выполнения /usr/bin/python"

echo "📋 Тестирование Django:"
/usr/local/bin/python manage.py check 2>/dev/null || echo "Ошибка Django check"

echo "✅ Тестирование завершено" 