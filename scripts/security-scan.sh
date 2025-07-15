#!/bin/bash

# DevSecOps Security Scanner
# Автоматический запуск всех проверок безопасности

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/security-results"
SCAN_DIR="$PROJECT_DIR/security"

# Создание директорий для результатов
mkdir -p "$RESULTS_DIR"
mkdir -p "$SCAN_DIR"

echo -e "${BLUE}🔒 Запуск комплексного сканирования безопасности...${NC}"
echo "=================================================="

# Функция для логирования
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Проверка зависимостей
check_dependencies() {
    log "Проверка зависимостей..."
    
    local deps=("docker" "python3" "pip3" "curl")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Отсутствуют зависимости: ${missing_deps[*]}"
        exit 1
    fi
    
    log "Все зависимости установлены"
}

# SAST - Статический анализ
run_sast() {
    log "Запуск SAST анализа..."
    
    cd "$PROJECT_DIR"
    
    # Bandit для Python
    if [ -f "requirements.txt" ]; then
        log "Запуск Bandit..."
        pip3 install bandit
        bandit -r . -f json -o "$RESULTS_DIR/bandit-results.json" || true
    fi
    
    # Semgrep
    if command -v semgrep &> /dev/null; then
        log "Запуск Semgrep..."
        semgrep ci --json --output "$RESULTS_DIR/semgrep-results.json" || true
    else
        warning "Semgrep не установлен. Установите: pip3 install semgrep"
    fi
    
    # Safety для зависимостей
    if [ -f "requirements.txt" ]; then
        log "Запуск Safety..."
        pip3 install safety
        safety check --json --output "$RESULTS_DIR/safety-results.json" || true
    fi
    
    log "SAST анализ завершен"
}

# DAST - Динамический анализ
run_dast() {
    log "Запуск DAST анализа..."
    
    # Проверка, что приложение запущено
    if ! curl -s http://localhost:8000/health/ > /dev/null 2>&1; then
        warning "Приложение не доступно на localhost:8000. Запустите приложение перед DAST."
        return
    fi
    
    # OWASP ZAP
    if docker ps | grep -q zap; then
        log "Запуск OWASP ZAP..."
        docker run --rm -v "$RESULTS_DIR:/zap/wrk" owasp/zap2docker-stable \
            zap-baseline.py -t http://localhost:8000 -J zap-results.json || true
    else
        log "Запуск OWASP ZAP в Docker..."
        docker run --rm -v "$RESULTS_DIR:/zap/wrk" owasp/zap2docker-stable \
            zap-baseline.py -t http://localhost:8000 -J zap-results.json || true
    fi
    
    # Nuclei
    if command -v nuclei &> /dev/null; then
        log "Запуск Nuclei..."
        nuclei -u http://localhost:8000 -json -o "$RESULTS_DIR/nuclei-results.json" || true
    else
        warning "Nuclei не установлен. Установите: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    fi
    
    log "DAST анализ завершен"
}

# Security Checks
run_security_checks() {
    log "Запуск проверок безопасности..."
    
    # TruffleHog для поиска секретов
    if command -v trufflehog &> /dev/null; then
        log "Запуск TruffleHog..."
        trufflehog --only-verified --format json --output-file "$RESULTS_DIR/trufflehog-results.json" . || true
    else
        warning "TruffleHog не установлен. Установите: pip3 install trufflehog"
    fi
    
    # Hadolint для Dockerfile
    if [ -f "Dockerfile" ]; then
        log "Запуск Hadolint..."
        docker run --rm -i hadolint/hadolint < Dockerfile || true
    fi
    
    # Checkov для IaC
    if command -v checkov &> /dev/null; then
        log "Запуск Checkov..."
        checkov -d . --output json --output-file-path "$RESULTS_DIR/checkov-results.json" || true
    else
        warning "Checkov не установлен. Установите: pip3 install checkov"
    fi
    
    log "Проверки безопасности завершены"
}

# Сканирование Docker образа
scan_docker_image() {
    log "Сканирование Docker образа..."
    
    if [ -f "Dockerfile" ]; then
        # Trivy
        if command -v trivy &> /dev/null; then
            log "Запуск Trivy..."
            trivy image --format json --output "$RESULTS_DIR/trivy-results.json" . || true
        else
            warning "Trivy не установлен. Установите: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        fi
        
        # Snyk
        if command -v snyk &> /dev/null; then
            log "Запуск Snyk..."
            snyk container test . --json > "$RESULTS_DIR/snyk-results.json" || true
        else
            warning "Snyk не установлен. Установите: npm install -g snyk"
        fi
    fi
}

# Анализ результатов
analyze_results() {
    log "Анализ результатов..."
    
    cd "$PROJECT_DIR"
    
    if [ -f "scripts/security-gateway.py" ]; then
        python3 scripts/security-gateway.py
    else
        error "Security Gateway скрипт не найден"
    fi
}

# Генерация отчета
generate_report() {
    log "Генерация отчета..."
    
    local report_file="$RESULTS_DIR/security-report-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$report_file" << EOF
# Отчет по безопасности

**Дата:** $(date)
**Проект:** DevSecOps Pipeline

## Обзор

Этот отчет содержит результаты комплексного сканирования безопасности проекта.

## Результаты сканирования

### SAST (Статический анализ)
EOF
    
    # Добавление результатов SAST
    for file in "$RESULTS_DIR"/*-results.json; do
        if [ -f "$file" ]; then
            local tool_name=$(basename "$file" -results.json)
            echo "#### $tool_name" >> "$report_file"
            echo "Файл: \`$file\`" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF

### DAST (Динамический анализ)
- OWASP ZAP результаты
- Nuclei результаты

### Security Checks
- TruffleHog (поиск секретов)
- Hadolint (Dockerfile)
- Checkov (IaC)

### Docker Security
- Trivy результаты
- Snyk результаты

## Рекомендации

1. Регулярно обновляйте зависимости
2. Используйте последние версии инструментов безопасности
3. Настройте автоматические уведомления о критических уязвимостях
4. Ведите журнал всех исправлений

## Следующие шаги

1. Исправьте все критические уязвимости
2. Рассмотрите высокие уязвимости в приоритетном порядке
3. Настройте мониторинг безопасности
4. Обновите политики безопасности

---
*Отчет сгенерирован автоматически*
EOF
    
    log "Отчет сохранен в: $report_file"
}

# Основная функция
main() {
    echo -e "${BLUE}🚀 DevSecOps Security Scanner${NC}"
    echo "=================================================="
    
    # Проверка зависимостей
    check_dependencies
    
    # Создание директорий
    mkdir -p "$RESULTS_DIR"
    
    # Запуск всех проверок
    run_sast
    run_dast
    run_security_checks
    scan_docker_image
    
    # Анализ результатов
    analyze_results
    
    # Генерация отчета
    generate_report
    
    echo -e "${GREEN}✅ Сканирование безопасности завершено!${NC}"
    echo -e "${BLUE}📁 Результаты сохранены в: $RESULTS_DIR${NC}"
}

# Обработка ошибок
trap 'error "Произошла ошибка в строке $LINENO"' ERR

# Запуск основной функции
main "$@" 