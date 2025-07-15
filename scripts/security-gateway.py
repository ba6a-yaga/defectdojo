#!/usr/bin/env python3
"""
Security Gateway - Анализ результатов безопасности и принятие решений
"""

import json
import os
import sys
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    tool: str
    severity: Severity
    title: str
    description: str
    file_path: str = ""
    line_number: int = 0
    cve_id: str = ""
    recommendation: str = ""

class SecurityGateway:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.results_dir = "all-results"
        self.thresholds = {
            Severity.CRITICAL: 0,  # Блокируем при любых критических уязвимостях
            Severity.HIGH: 5,       # Блокируем при 5+ высоких уязвимостях
            Severity.MEDIUM: 10,    # Предупреждение при 10+ средних уязвимостях
            Severity.LOW: 20        # Предупреждение при 20+ низких уязвимостях
        }

    def load_sast_results(self) -> None:
        """Загрузка результатов SAST анализа"""
        sast_files = [
            "bandit-results.json",
            "semgrep-results.json",
            "safety-results.json"
        ]
        
        for file_name in sast_files:
            file_path = os.path.join(self.results_dir, file_name)
            if os.path.exists(file_path):
                self._parse_sast_file(file_path, file_name)

    def load_dast_results(self) -> None:
        """Загрузка результатов DAST анализа"""
        dast_files = [
            "zap-results.json",
            "nuclei-results.json"
        ]
        
        for file_name in dast_files:
            file_path = os.path.join(self.results_dir, file_name)
            if os.path.exists(file_path):
                self._parse_dast_file(file_path, file_name)

    def load_security_check_results(self) -> None:
        """Загрузка результатов проверок безопасности"""
        check_files = [
            "trufflehog-results.json",
            "checkov-results.json"
        ]
        
        for file_name in check_files:
            file_path = os.path.join(self.results_dir, file_name)
            if os.path.exists(file_path):
                self._parse_security_check_file(file_path, file_name)

    def _parse_sast_file(self, file_path: str, tool_name: str) -> None:
        """Парсинг SAST результатов"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if tool_name == "bandit-results.json":
                self._parse_bandit_results(data, tool_name)
            elif tool_name == "semgrep-results.json":
                self._parse_semgrep_results(data, tool_name)
            elif tool_name == "safety-results.json":
                self._parse_safety_results(data, tool_name)
                
        except Exception as e:
            print(f"Ошибка парсинга {file_path}: {e}")

    def _parse_bandit_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов Bandit"""
        for issue in data.get('results', []):
            severity = self._map_bandit_severity(issue.get('issue_severity', 'MEDIUM'))
            vuln = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=issue.get('issue_text', 'Unknown'),
                description=issue.get('more_info', ''),
                file_path=issue.get('filename', ''),
                line_number=issue.get('line_number', 0),
                recommendation=self._get_bandit_recommendation(issue.get('test_id', ''))
            )
            self.vulnerabilities.append(vuln)

    def _parse_semgrep_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов Semgrep"""
        for result in data.get('results', []):
            severity = self._map_semgrep_severity(result.get('extra', {}).get('severity', 'WARNING'))
            vuln = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=result.get('extra', {}).get('message', 'Unknown'),
                description=result.get('extra', {}).get('description', ''),
                file_path=result.get('path', ''),
                line_number=result.get('start', {}).get('line', 0),
                recommendation=self._get_semgrep_recommendation(result.get('check_id', ''))
            )
            self.vulnerabilities.append(vuln)

    def _parse_safety_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов Safety"""
        for vuln in data.get('vulnerabilities', []):
            severity = Severity.HIGH if vuln.get('severity') == 'high' else Severity.MEDIUM
            vuln_obj = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=f"Vulnerable package: {vuln.get('package', 'Unknown')}",
                description=vuln.get('description', ''),
                recommendation=f"Update {vuln.get('package', '')} to version {vuln.get('vulnerable_spec', '')}"
            )
            self.vulnerabilities.append(vuln_obj)

    def _parse_dast_file(self, file_path: str, tool_name: str) -> None:
        """Парсинг DAST результатов"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if tool_name == "zap-results.json":
                self._parse_zap_results(data, tool_name)
            elif tool_name == "nuclei-results.json":
                self._parse_nuclei_results(data, tool_name)
                
        except Exception as e:
            print(f"Ошибка парсинга {file_path}: {e}")

    def _parse_zap_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов OWASP ZAP"""
        for alert in data.get('alerts', []):
            severity = self._map_zap_severity(alert.get('risk', 'Medium'))
            vuln = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=alert.get('name', 'Unknown'),
                description=alert.get('description', ''),
                recommendation=alert.get('solution', '')
            )
            self.vulnerabilities.append(vuln)

    def _parse_nuclei_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов Nuclei"""
        for result in data.get('results', []):
            severity = self._map_nuclei_severity(result.get('info', {}).get('severity', 'medium'))
            vuln = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=result.get('info', {}).get('name', 'Unknown'),
                description=result.get('info', {}).get('description', ''),
                recommendation=result.get('info', {}).get('remediation', '')
            )
            self.vulnerabilities.append(vuln)

    def _parse_security_check_file(self, file_path: str, tool_name: str) -> None:
        """Парсинг результатов проверок безопасности"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if tool_name == "trufflehog-results.json":
                self._parse_trufflehog_results(data, tool_name)
            elif tool_name == "checkov-results.json":
                self._parse_checkov_results(data, tool_name)
                
        except Exception as e:
            print(f"Ошибка парсинга {file_path}: {e}")

    def _parse_trufflehog_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов TruffleHog"""
        for result in data.get('results', []):
            vuln = Vulnerability(
                tool=tool_name,
                severity=Severity.CRITICAL,  # Секреты всегда критичны
                title=f"Secret detected: {result.get('type', 'Unknown')}",
                description=f"Secret found in {result.get('path', 'Unknown')}",
                file_path=result.get('path', ''),
                line_number=result.get('line', 0),
                recommendation="Remove the secret from the code and rotate it immediately"
            )
            self.vulnerabilities.append(vuln)

    def _parse_checkov_results(self, data: Dict, tool_name: str) -> None:
        """Парсинг результатов Checkov"""
        for check in data.get('results', {}).get('failed_checks', []):
            severity = self._map_checkov_severity(check.get('severity', 'MEDIUM'))
            vuln = Vulnerability(
                tool=tool_name,
                severity=severity,
                title=check.get('check_name', 'Unknown'),
                description=check.get('check_result', {}).get('evaluated_keys', ''),
                file_path=check.get('file_path', ''),
                line_number=check.get('file_line_range', [0, 0])[0],
                recommendation=check.get('check_result', {}).get('fix', '')
            )
            self.vulnerabilities.append(vuln)

    def analyze_results(self) -> Dict[str, Any]:
        """Анализ результатов и принятие решений"""
        # Подсчет уязвимостей по уровням
        counts = {severity: 0 for severity in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1

        # Проверка пороговых значений
        should_block = (
            counts[Severity.CRITICAL] > self.thresholds[Severity.CRITICAL] or
            counts[Severity.HIGH] > self.thresholds[Severity.HIGH]
        )

        should_warn = (
            counts[Severity.MEDIUM] > self.thresholds[Severity.MEDIUM] or
            counts[Severity.LOW] > self.thresholds[Severity.LOW]
        )

        # Генерация рекомендаций
        recommendations = self._generate_recommendations()

        return {
            "critical_vulnerabilities": counts[Severity.CRITICAL],
            "high_vulnerabilities": counts[Severity.HIGH],
            "medium_vulnerabilities": counts[Severity.MEDIUM],
            "low_vulnerabilities": counts[Severity.LOW],
            "info_vulnerabilities": counts[Severity.INFO],
            "total_vulnerabilities": len(self.vulnerabilities),
            "should_block": should_block,
            "should_warn": should_warn,
            "recommendations": recommendations,
            "vulnerabilities": [
                {
                    "tool": v.tool,
                    "severity": v.severity.value,
                    "title": v.title,
                    "description": v.description,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "recommendation": v.recommendation
                }
                for v in self.vulnerabilities
            ]
        }

    def _generate_recommendations(self) -> str:
        """Генерация рекомендаций по исправлению"""
        recommendations = []
        
        critical_count = len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])
        
        if critical_count > 0:
            recommendations.append(f"🚨 КРИТИЧНО: Найдено {critical_count} критических уязвимостей. Немедленно исправьте их!")
        
        if high_count > 0:
            recommendations.append(f"⚠️ ВЫСОКИЙ РИСК: Найдено {high_count} высоких уязвимостей. Исправьте в приоритетном порядке.")
        
        # Рекомендации по инструментам
        tools_used = set(v.tool for v in self.vulnerabilities)
        if "bandit-results.json" in tools_used:
            recommendations.append("🔍 Используйте Bandit для регулярного сканирования Python кода")
        if "semgrep-results.json" in tools_used:
            recommendations.append("🔍 Настройте Semgrep правила для вашего проекта")
        if "trufflehog-results.json" in tools_used:
            recommendations.append("🔐 Обнаружены секреты! Немедленно ротируйте их и удалите из кода")
        
        return "\n".join(recommendations)

    def _map_bandit_severity(self, severity: str) -> Severity:
        """Маппинг уровней серьезности Bandit"""
        mapping = {
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)

    def _map_semgrep_severity(self, severity: str) -> Severity:
        """Маппинг уровней серьезности Semgrep"""
        mapping = {
            'ERROR': Severity.HIGH,
            'WARNING': Severity.MEDIUM,
            'INFO': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)

    def _map_zap_severity(self, severity: str) -> Severity:
        """Маппинг уровней серьезности OWASP ZAP"""
        mapping = {
            'High': Severity.HIGH,
            'Medium': Severity.MEDIUM,
            'Low': Severity.LOW,
            'Info': Severity.INFO
        }
        return mapping.get(severity, Severity.MEDIUM)

    def _map_nuclei_severity(self, severity: str) -> Severity:
        """Маппинг уровней серьезности Nuclei"""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(severity.lower(), Severity.MEDIUM)

    def _map_checkov_severity(self, severity: str) -> Severity:
        """Маппинг уровней серьезности Checkov"""
        mapping = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)

    def _get_bandit_recommendation(self, test_id: str) -> str:
        """Получение рекомендации для Bandit"""
        recommendations = {
            'B101': 'Используйте assert только для тестов, не для проверки условий',
            'B102': 'Не используйте exec() с пользовательским вводом',
            'B103': 'Не используйте set_bad_file_permissions()',
            'B104': 'Не используйте hardcoded_bind_all_interfaces',
            'B105': 'Не используйте hardcoded_password_string',
            'B106': 'Не используйте hardcoded_password_funcarg',
            'B107': 'Не используйте hardcoded_password_default',
            'B108': 'Не используйте hardcoded_tmp_directory',
            'B110': 'Не используйте try_except_pass',
            'B112': 'Не используйте try_except_continue',
            'B201': 'Не используйте flask_debug_true',
            'B301': 'Не используйте pickle',
            'B302': 'Не используйте marshal',
            'B303': 'Не используйте md5',
            'B304': 'Не используйте md5',
            'B305': 'Не используйте sha1',
            'B306': 'Не используйте mktemp_q',
            'B307': 'Не используйте eval',
            'B308': 'Не используйте mark_safe',
            'B309': 'Не используйте httpsconnection',
            'B310': 'Не используйте urllib_urlopen',
            'B311': 'Не используйте random',
            'B312': 'Не используйте telnetlib',
            'B313': 'Не используйте xml_bad_cElementTree',
            'B314': 'Не используйте xml_bad_ElementTree',
            'B315': 'Не используйте xml_bad_expatreader',
            'B316': 'Не используйте xml_bad_expatbuilder',
            'B317': 'Не используйте xml_bad_sax',
            'B318': 'Не используйте xml_bad_mindom',
            'B319': 'Не используйте xml_bad_minidom',
            'B320': 'Не используйте xml_bad_pulldom',
            'B321': 'Не используйте ftplib',
            'B322': 'Не используйте input',
            'B323': 'Не используйте unverified_context',
            'B324': 'Не используйте hashlib_new_insecure_functions',
            'B325': 'Не используйте tempnam',
            'B401': 'Не используйте import_telnetlib',
            'B402': 'Не используйте import_ftplib',
            'B403': 'Не используйте import_pickle',
            'B404': 'Не используйте import_subprocess',
            'B405': 'Не используйте import_xml_etree',
            'B406': 'Не используйте import_xml_sax',
            'B407': 'Не используйте import_xml_expat',
            'B408': 'Не используйте import_xml_minidom',
            'B409': 'Не используйте import_xml_pulldom',
            'B410': 'Не используйте import_lxml',
            'B411': 'Не используйте import_xmlrpclib',
            'B412': 'Не используйте import_httpoxy',
            'B413': 'Не используйте import_urllib3',
            'B501': 'Не используйте request_with_no_cert_validation',
            'B601': 'Не используйте paramiko_calls',
            'B602': 'Не используйте subprocess_popen_with_shell_equals_true',
            'B603': 'Не используйте subprocess_without_shell_equals_true',
            'B604': 'Не используйте any_other_function_with_shell_equals_true',
            'B605': 'Не используйте start_process_with_a_shell',
            'B606': 'Не используйте start_process_with_no_shell',
            'B607': 'Не используйте start_process_with_partial_path',
            'B701': 'Не используйте jinja2_autoescape_false',
        }
        return recommendations.get(test_id, 'Проверьте код на соответствие стандартам безопасности')

    def _get_semgrep_recommendation(self, check_id: str) -> str:
        """Получение рекомендации для Semgrep"""
        return f"Исправьте уязвимость {check_id} согласно рекомендациям Semgrep"

def main():
    """Основная функция"""
    gateway = SecurityGateway()
    
    # Загрузка всех результатов
    print("🔍 Загрузка результатов сканирования...")
    gateway.load_sast_results()
    gateway.load_dast_results()
    gateway.load_security_check_results()
    
    # Анализ результатов
    print("📊 Анализ результатов...")
    results = gateway.analyze_results()
    
    # Сохранение отчета
    with open('security-report.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Вывод результатов
    print(f"\n📋 Результаты анализа безопасности:")
    print(f"  Критические: {results['critical_vulnerabilities']}")
    print(f"  Высокие: {results['high_vulnerabilities']}")
    print(f"  Средние: {results['medium_vulnerabilities']}")
    print(f"  Низкие: {results['low_vulnerabilities']}")
    print(f"  Всего: {results['total_vulnerabilities']}")
    
    if results['should_block']:
        print("\n🚨 БЛОКИРОВКА: Обнаружены критические уязвимости!")
        sys.exit(1)
    elif results['should_warn']:
        print("\n⚠️ ПРЕДУПРЕЖДЕНИЕ: Обнаружены уязвимости, требующие внимания")
    else:
        print("\n✅ Все проверки безопасности пройдены успешно")
    
    print(f"\n💡 Рекомендации:\n{results['recommendations']}")

if __name__ == "__main__":
    main() 