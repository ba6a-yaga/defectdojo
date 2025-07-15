#!/bin/bash

echo "🔧 Диагностика и исправление проблем с SonarQube..."

# Проверка системных ресурсов
echo "📊 Проверка системных ресурсов:"
echo "  - CPU: $(nproc) ядер"
echo "  - RAM: $(free -h | grep Mem | awk '{print $2}')"
echo "  - Disk: $(df -h / | tail -1 | awk '{print $4}') свободно"

# Проверка лимитов системы
echo "🔍 Проверка лимитов системы:"
ulimit -a

# Проверка Docker ресурсов
echo "🐳 Проверка Docker ресурсов:"
docker system df

# Остановка и очистка контейнеров SonarQube
echo "🧹 Очистка контейнеров SonarQube..."
docker-compose down sonarqube 2>/dev/null || true
docker container prune -f

# Удаление старых томов SonarQube (осторожно!)
echo "🗑️ Удаление старых томов SonarQube..."
docker volume rm sib-diplom-track-devsecops_sonarqube_data 2>/dev/null || true
docker volume rm sib-diplom-track-devsecops_sonarqube_extensions 2>/dev/null || true
docker volume rm sib-diplom-track-devsecops_sonarqube_logs 2>/dev/null || true

# Создание новой конфигурации с улучшенными настройками
echo "⚙️ Создание улучшенной конфигурации SonarQube..."

# Запуск SonarQube с улучшенными настройками
echo "🚀 Запуск SonarQube с улучшенными настройками..."
docker-compose up -d sonarqube

# Ожидание запуска
echo "⏳ Ожидание запуска SonarQube..."
for i in {1..30}; do
    if curl -f -s http://localhost:9000/api/system/status > /dev/null 2>&1; then
        echo "✅ SonarQube запущен успешно!"
        break
    else
        echo "⏳ Попытка $i/30..."
        sleep 10
    fi
done

# Проверка логов
echo "📋 Логи SonarQube:"
docker-compose logs sonarqube --tail=50

# Проверка статуса
echo "📊 Статус контейнеров:"
docker-compose ps

echo "✅ Диагностика завершена!" 