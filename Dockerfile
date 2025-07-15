# Multi-stage build для безопасности
FROM python:3.11-slim as builder

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Создание пользователя без привилегий
RUN groupadd -r defectdojo && useradd -r -g defectdojo defectdojo

# Установка Python зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Финальный образ
FROM python:3.11-slim

# Установка runtime зависимостей
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Копирование пользователя
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Копирование Python пакетов
COPY --from=builder /root/.local /home/defectdojo/.local

# Установка рабочей директории
WORKDIR /app

# Копирование кода приложения
COPY . .

# Изменение владельца файлов
RUN chown -R defectdojo:defectdojo /app

# Переключение на непривилегированного пользователя
USER defectdojo

# Установка переменных окружения
ENV PYTHONPATH=/home/defectdojo/.local/lib/python3.11/site-packages
ENV PATH=/home/defectdojo/.local/bin:$PATH

# Проверка безопасности
RUN python -m bandit -r . -f json -o /tmp/bandit-results.json || true

# Экспорт порта
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# Запуск приложения
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"] 