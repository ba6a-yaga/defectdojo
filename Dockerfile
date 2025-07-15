FROM python:3.9-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    pkg-config \
    default-libmysqlclient-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создание пользователя для приложения
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Установка рабочей директории
WORKDIR /app

# Копирование requirements.txt и установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода приложения
COPY . .

# Создание директорий и установка прав
RUN mkdir -p /app/logs /app/static /app/media /app/db \
    && chown -R appuser:appuser /app \
    && chmod +x /usr/local/bin/python \
    && chmod +x /usr/local/bin/python3

# Экспорт порта
EXPOSE 8000

# Скрипт запуска
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Переключение на пользователя приложения
USER appuser

# Запуск приложения
CMD ["/usr/local/bin/docker-entrypoint.sh"] 