#!/usr/bin/env python3
"""
Security Gateway - Анализ результатов безопасности и блокировка деплоя
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

class SecurityGateway:
    def __init__(self):
        self.results_dir = Path("all-results")
        self.security_report = {
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0,
            "total_vulnerabilities": 0,
            "recommendations": [],
            "block_deployment": False,
            "scan_results": {}
        }
        
    def analyze_sast_results(self):
        """Анализ результатов SAST сканирования"""
        print("🔍 Анализ SAST результатов...")
        
        # Bandit
        bandit_file = self.results_dir / "bandit-results.json"
        if bandit_file.exists():
            try:
                with open(bandit_file, 'r') as f:
                    bandit_data = json.load(f)
                    issues = bandit_data.get('results', [])
                    for issue in issues:
                        severity = issue.get('issue_severity', 'medium')
                        if severity == 'HIGH':
                            self.security_report['high_vulnerabilities'] += 1
                        elif severity == 'MEDIUM':
                            self.security_report['medium_vulnerabilities'] += 1
                        elif severity == 'LOW':
                            self.security_report['low_vulnerabilities'] += 1
                    
                    if issues:
                        self.security_report['recommendations'].append(
                            f"Bandit обнаружил {len(issues)} проблем безопасности в коде"
                        )
            except Exception as e:
                print(f"Ошибка при анализе Bandit: {e}")
        
        # Semgrep
        semgrep_file = self.results_dir / "semgrep-results.json"
        if semgrep_file.exists():
            try:
                with open(semgrep_file, 'r') as f:
                    semgrep_data = json.load(f)
                    results = semgrep_data.get('results', [])
                    for result in results:
                        severity = result.get('extra', {}).get('severity', 'WARNING')
                        if severity == 'ERROR':
                            self.security_report['high_vulnerabilities'] += 1
                        elif severity == 'WARNING':
                            self.security_report['medium_vulnerabilities'] += 1
                        elif severity == 'INFO':
                            self.security_report['low_vulnerabilities'] += 1
                    
                    if results:
                        self.security_report['recommendations'].append(
                            f"Semgrep обнаружил {len(results)} потенциальных проблем"
                        )
            except Exception as e:
                print(f"Ошибка при анализе Semgrep: {e}")
    
    def analyze_dast_results(self):
        """Анализ результатов DAST сканирования"""
        print("🔍 Анализ DAST результатов...")
        
        # ZAP результаты - ищем report_json.json
        zap_files = []
        
        # Поиск report_json.json в корневой директории
        zap_files.extend(list(self.results_dir.glob("report_json.json")))
        
        # Поиск в поддиректориях
        for subdir in self.results_dir.iterdir():
            if subdir.is_dir():
                zap_files.extend(list(subdir.glob("report_json.json")))
        
        # Поиск в .zap директории
        zap_dir = self.results_dir / ".zap"
        if zap_dir.exists():
            zap_files.extend(list(zap_dir.glob("*.json")))
        
        print(f"Найдено {len(zap_files)} файлов ZAP: {[f.name for f in zap_files]}")
        
        if zap_files:
            try:
                with open(zap_files[0], 'r') as f:
                    zap_data = json.load(f)
                    alerts = zap_data.get('alerts', [])
                    
                    # Анализ конкретных уязвимостей
                    spectre_count = 0
                    http_method_count = 0
                    
                    for alert in alerts:
                        risk = alert.get('risk', 'Medium')
                        alert_id = alert.get('id', '')
                        alert_name = alert.get('name', '')
                        
                        # Обработка Spectre уязвимости (90004)
                        if alert_id == '90004' or 'Spectre' in alert_name:
                            spectre_count += 1
                            self.security_report['medium_vulnerabilities'] += 1
                            continue
                        
                        # Обработка небезопасных HTTP методов (90028)
                        if alert_id == '90028' or 'Insecure HTTP Method' in alert_name:
                            http_method_count += 1
                            self.security_report['medium_vulnerabilities'] += 1
                            continue
                        
                        # Общая обработка по уровню риска
                        if risk == 'High':
                            self.security_report['high_vulnerabilities'] += 1
                        elif risk == 'Medium':
                            self.security_report['medium_vulnerabilities'] += 1
                        elif risk == 'Low':
                            self.security_report['low_vulnerabilities'] += 1
                    
                    if alerts:
                        recommendations = []
                        if spectre_count > 0:
                            recommendations.append(f"Обнаружено {spectre_count} предупреждений Spectre - рекомендуется добавить заголовки безопасности")
                        if http_method_count > 0:
                            recommendations.append(f"Обнаружено {http_method_count} небезопасных HTTP методов - рекомендуется ограничить доступные методы")
                        
                        if recommendations:
                            self.security_report['recommendations'].extend(recommendations)
                        
                        self.security_report['recommendations'].append(
                            f"OWASP ZAP обнаружил {len(alerts)} уязвимостей в приложении"
                        )
            except Exception as e:
                print(f"Ошибка при анализе ZAP: {e}")
                # Попытка найти другие файлы ZAP
                for file in self.results_dir.glob("*zap*"):
                    print(f"Найден файл ZAP: {file}")
        else:
            print("⚠️ Файлы ZAP не найдены")
        
        # Nuclei результаты
        nuclei_files = list(self.results_dir.glob("nuclei-*.json"))
        if nuclei_files:
            try:
                with open(nuclei_files[0], 'r') as f:
                    nuclei_data = json.load(f)
                    if isinstance(nuclei_data, list):
                        for result in nuclei_data:
                            severity = result.get('info', {}).get('severity', 'medium')
                            if severity == 'critical':
                                self.security_report['critical_vulnerabilities'] += 1
                            elif severity == 'high':
                                self.security_report['high_vulnerabilities'] += 1
                            elif severity == 'medium':
                                self.security_report['medium_vulnerabilities'] += 1
                            elif severity == 'low':
                                self.security_report['low_vulnerabilities'] += 1
                        
                        if nuclei_data:
                            self.security_report['recommendations'].append(
                                f"Nuclei обнаружил {len(nuclei_data)} уязвимостей"
                            )
            except Exception as e:
                print(f"Ошибка при анализе Nuclei: {e}")
    
    def analyze_security_checks(self):
        """Анализ результатов Security Checks"""
        print("🔍 Анализ Security Checks результатов...")
        
        # TruffleHog
        trufflehog_file = self.results_dir / "trufflehog-results.json"
        if trufflehog_file.exists():
            try:
                with open(trufflehog_file, 'r') as f:
                    trufflehog_data = json.load(f)
                    if isinstance(trufflehog_data, list):
                        for result in trufflehog_data:
                            self.security_report['critical_vulnerabilities'] += 1
                        
                        if trufflehog_data:
                            self.security_report['recommendations'].append(
                                f"TruffleHog обнаружил {len(trufflehog_data)} секретов в коде"
                            )
                            self.security_report['block_deployment'] = True
            except Exception as e:
                print(f"Ошибка при анализе TruffleHog: {e}")
        
        # Checkov
        checkov_file = self.results_dir / "checkov-results.json"
        if checkov_file.exists():
            try:
                with open(checkov_file, 'r') as f:
                    checkov_data = json.load(f)
                    results = checkov_data.get('results', {})
                    for result in results.values():
                        if isinstance(result, dict):
                            failed_checks = result.get('failed_checks', [])
                            for check in failed_checks:
                                severity = check.get('severity', 'MEDIUM')
                                if severity == 'CRITICAL':
                                    self.security_report['critical_vulnerabilities'] += 1
                                elif severity == 'HIGH':
                                    self.security_report['high_vulnerabilities'] += 1
                                elif severity == 'MEDIUM':
                                    self.security_report['medium_vulnerabilities'] += 1
                                elif severity == 'LOW':
                                    self.security_report['low_vulnerabilities'] += 1
                    
                    if results:
                        self.security_report['recommendations'].append(
                            f"Checkov обнаружил проблемы в инфраструктуре"
                        )
            except Exception as e:
                print(f"Ошибка при анализе Checkov: {e}")
    
    def calculate_totals(self):
        """Подсчет общих результатов"""
        self.security_report['total_vulnerabilities'] = (
            self.security_report['critical_vulnerabilities'] +
            self.security_report['high_vulnerabilities'] +
            self.security_report['medium_vulnerabilities'] +
            self.security_report['low_vulnerabilities']
        )
        
        # Блокируем деплой при критических уязвимостях
        if self.security_report['critical_vulnerabilities'] > 0:
            self.security_report['block_deployment'] = True
            self.security_report['recommendations'].append(
                "🚨 КРИТИЧЕСКИЕ УЯЗВИМОСТИ ОБНАРУЖЕНЫ! Деплой заблокирован."
            )
        
        # Блокируем деплой при высоком количестве высоких уязвимостей
        if self.security_report['high_vulnerabilities'] >= 5:
            self.security_report['block_deployment'] = True
            self.security_report['recommendations'].append(
                "⚠️ Обнаружено много высоких уязвимостей! Деплой заблокирован."
            )
    
    def generate_report(self):
        """Генерация отчета"""
        print("📊 Генерация отчета безопасности...")
        
        report = f"""
# Отчет безопасности

## Статистика уязвимостей:
- 🔴 Критические: {self.security_report['critical_vulnerabilities']}
- 🟠 Высокие: {self.security_report['high_vulnerabilities']}
- 🟡 Средние: {self.security_report['medium_vulnerabilities']}
- 🟢 Низкие: {self.security_report['low_vulnerabilities']}
- 📊 Всего: {self.security_report['total_vulnerabilities']}

## Рекомендации:
"""
        
        for rec in self.security_report['recommendations']:
            report += f"- {rec}\n"
        
        if self.security_report['block_deployment']:
            report += "\n## 🚨 РЕЗУЛЬТАТ: Деплой заблокирован!"
        else:
            report += "\n## ✅ РЕЗУЛЬТАТ: Деплой разрешен"
        
        print(report)
        
        # Сохраняем отчет в JSON
        with open('security-report.json', 'w') as f:
            json.dump(self.security_report, f, indent=2)
        
        # Возвращаем код ошибки если деплой заблокирован
        if self.security_report['block_deployment']:
            sys.exit(1)
        else:
            sys.exit(0)
    
    def run(self):
        """Запуск анализа"""
        print("🛡️ Security Gateway запущен")
        
        if not self.results_dir.exists():
            print(f"⚠️ Директория {self.results_dir} не найдена")
            return
        
        self.analyze_sast_results()
        self.analyze_dast_results()
        self.analyze_security_checks()
        self.calculate_totals()
        self.generate_report()

if __name__ == "__main__":
    gateway = SecurityGateway()
    gateway.run() 