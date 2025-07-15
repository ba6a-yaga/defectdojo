#!/bin/bash

# DAST Local Testing Script
# Автор: Падалко Роман
# Описание: Скрипт для локального тестирования DAST инструментов

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции для логирования
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Переменные
TARGET_URL="http://localhost:8000"
RESULTS_DIR="dast-results"
CONTAINER_NAME="test-app"

# Создание директории для результатов
mkdir -p $RESULTS_DIR

log "🔍 Запуск локального DAST тестирования"
log "Цель: $TARGET_URL"
log "Результаты: $RESULTS_DIR"

# Функция проверки доступности приложения
check_app_availability() {
    log "Проверка доступности приложения..."
    
    if ! curl -f -s $TARGET_URL/health/ > /dev/null; then
        error "Приложение недоступно на $TARGET_URL"
        log "Убедитесь, что приложение запущено:"
        log "docker run -d --name $CONTAINER_NAME -p 8000:8000 sib-diplom-app:latest"
        exit 1
    fi
    
    success "Приложение доступно"
}

# Функция тестирования эндпоинтов
test_endpoints() {
    log "Тестирование эндпоинтов..."
    
    endpoints=(
        "/"
        "/health/"
        "/api/"
        "/api/vulnerabilities/"
        "/api/test/"
        "/api/info/"
        "/api/status/"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f -s "$TARGET_URL$endpoint" > /dev/null; then
            success "✅ $endpoint - доступен"
        else
            warning "⚠️ $endpoint - недоступен"
        fi
    done
}

# Функция запуска OWASP ZAP
run_zap() {
    log "🔍 Запуск OWASP ZAP..."
    
    if docker ps | grep -q zap; then
        log "Использование существующего контейнера ZAP"
        docker exec zap zap-baseline.py -t $TARGET_URL -J $RESULTS_DIR/zap-results.json || true
    else
        log "Запуск ZAP в Docker..."
        docker run --rm -v "$(pwd)/$RESULTS_DIR:/zap/wrk" owasp/zap2docker-stable \
            zap-baseline.py -t $TARGET_URL -J zap-results.json || true
    fi
    
    success "ZAP сканирование завершено"
}

# Функция запуска Nuclei
run_nuclei() {
    log "🔍 Запуск Nuclei..."
    
    if command -v nuclei &> /dev/null; then
        nuclei -u $TARGET_URL -json -o $RESULTS_DIR/nuclei-results.json || true
        success "Nuclei сканирование завершено"
    else
        warning "Nuclei не установлен. Установите:"
        log "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    fi
}

# Функция запуска Nikto
run_nikto() {
    log "🔍 Запуск Nikto..."
    
    docker run --rm --network host nikitinroman/nikto \
        -h $TARGET_URL \
        -Format json \
        -output $RESULTS_DIR/nikto-results.json || true
    
    success "Nikto сканирование завершено"
}

# Функция запуска Wapiti
run_wapiti() {
    log "🔍 Запуск Wapiti..."
    
    docker run --rm --network host wapiti/wapiti \
        -u $TARGET_URL \
        -f json \
        -o $RESULTS_DIR/wapiti-results.json || true
    
    success "Wapiti сканирование завершено"
}

# Функция запуска SQLMap
run_sqlmap() {
    log "🔍 Запуск SQLMap..."
    
    docker run --rm --network host sqlmap/sqlmap \
        -u "$TARGET_URL/api/vulnerabilities/search/?q=test" \
        --batch \
        --random-agent \
        --output-dir $RESULTS_DIR/sqlmap-results || true
    
    success "SQLMap сканирование завершено"
}

# Функция анализа результатов
analyze_results() {
    log "📊 Анализ результатов..."
    
    # Проверка наличия файлов результатов
    result_files=(
        "zap-results.json"
        "nuclei-results.json"
        "nikto-results.json"
        "wapiti-results.json"
    )
    
    total_vulnerabilities=0
    high_vulnerabilities=0
    medium_vulnerabilities=0
    low_vulnerabilities=0
    
    for file in "${result_files[@]}"; do
        if [ -f "$RESULTS_DIR/$file" ]; then
            log "📄 Найден файл результатов: $file"
            
            # Простой подсчет строк с уязвимостями
            if grep -q "vulnerability\|vuln\|alert\|issue" "$RESULTS_DIR/$file" 2>/dev/null; then
                count=$(grep -c "vulnerability\|vuln\|alert\|issue" "$RESULTS_DIR/$file" 2>/dev/null || echo "0")
                log "   Обнаружено потенциальных проблем: $count"
                total_vulnerabilities=$((total_vulnerabilities + count))
            fi
        else
            warning "Файл результатов не найден: $file"
        fi
    done
    
    # Вывод сводки
    log "📊 Сводка DAST тестирования:"
    log "   Всего потенциальных проблем: $total_vulnerabilities"
    log "   Файлы результатов сохранены в: $RESULTS_DIR"
    
    if [ $total_vulnerabilities -gt 0 ]; then
        warning "⚠️ Обнаружены потенциальные уязвимости!"
        log "Рекомендуется проверить результаты в файлах:"
        ls -la $RESULTS_DIR/
    else
        success "✅ Критических уязвимостей не обнаружено"
    fi
}

# Функция очистки
cleanup() {
    log "🧹 Очистка..."
    
    # Остановка тестового контейнера
    if docker ps | grep -q $CONTAINER_NAME; then
        log "Остановка тестового контейнера..."
        docker stop $CONTAINER_NAME || true
        docker rm $CONTAINER_NAME || true
    fi
    
    success "Очистка завершена"
}

# Главная функция
main() {
    log "🚀 Запуск локального DAST тестирования"
    
    # Проверка зависимостей
    if ! command -v docker &> /dev/null; then
        error "Docker не установлен"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        error "curl не установлен"
        exit 1
    fi
    
    # Проверка доступности приложения
    check_app_availability
    
    # Тестирование эндпоинтов
    test_endpoints
    
    # Запуск DAST инструментов
    run_zap
    run_nuclei
    run_nikto
    run_wapiti
    run_sqlmap
    
    # Анализ результатов
    analyze_results
    
    success "✅ DAST тестирование завершено!"
    log "Результаты сохранены в: $RESULTS_DIR"
}

# Обработка сигналов
trap cleanup EXIT

# Запуск главной функции
main "$@" 