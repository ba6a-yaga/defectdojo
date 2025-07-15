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
    && chmod +x /usr/local/bin/python3 \
    && chmod +x /usr/local/bin/pip \
    && chmod +x /usr/local/bin/pip3

# Создание символических ссылок для альтернативных путей
RUN ln -sf /usr/local/bin/python /usr/bin/python \
    && ln -sf /usr/local/bin/python3 /usr/bin/python3 \
    && chmod +x /usr/bin/python \
    && chmod +x /usr/bin/python3

# Экспорт порта
EXPOSE 8000

# Скрипты запуска
COPY docker-entrypoint.sh /usr/local/bin/
COPY docker-entrypoint-dast.sh /usr/local/bin/
COPY test-python.sh /app/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint-dast.sh \
    && chmod +x /app/test-python.sh

# Переключение на пользователя приложения
USER appuser

# Запуск приложения с выбором скрипта
CMD ["/usr/local/bin/docker-entrypoint.sh"] 