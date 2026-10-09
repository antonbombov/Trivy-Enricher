#!/usr/bin/env python3
"""
Trivy Diff Analyzer
Поддерживает:
- Docker-образы (идентификация по PkgName)
- JAR-сканирования (идентификация по PkgName + UID)
- Поиск пакетов по имени в секции Packages для определения UPDATED
- Расчет остаточного срока устранения для уязвимостей со статусом UNCHANGED
- Сравнение diff-отчета с обычным отчетом Trivy: diff-отчет определяется
  по наличию _diff_metadata, используется как baseline (первое состояние)
- Перенос остаточного срока предыдущего анализа и ведение истории
  удаленных уязвимостей и пакетов
"""

import json
import sys
import re
import traceback
from pathlib import Path
from typing import Dict, Set, Any, Tuple, Optional
from enum import Enum
from copy import deepcopy
from datetime import datetime, timedelta


class ChangeType(Enum):
    NEW = "new"
    UNCHANGED = "unchanged"
    UPDATED = "updated"
    REMOVED = "removed"


class TrivyDiffAnalyzer:
    def __init__(self, report1_path: str, report2_path: str, debug: bool = False,
                 start_date: str = None, end_date: str = None):
        self.report1_path = report1_path
        self.report2_path = report2_path
        self.debug = debug

        # Загружаем отчеты как есть
        self.report1_raw = self._load_report(report1_path)
        self.report2_raw = self._load_report(report2_path)

        # Метаданные и история предыдущего сравнения (если baseline - diff-отчет)
        self.baseline_meta = self._extract_diff_metadata(self.report1_raw)
        self.baseline_history = self._extract_history(self.baseline_meta)

        # Для анализа используются нормализованные отчеты: из diff-отчета
        # удаляются служебные поля и секции предыдущего сравнения
        self.report1 = self._normalize_report(self.report1_raw)
        self.report2 = self._normalize_report(self.report2_raw)

        self.report_type = self._detect_report_type()

        # Данные предыдущего анализа по уязвимостям baseline (первое обнаружение, остаток срока)
        self.baseline_vuln_meta = self._collect_baseline_vuln_meta(self.report1_raw)

        # Парсим start_date (дата выявления)
        self.start_date = None
        if start_date:
            try:
                self.start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                print(f"⚠️ Неверный формат даты выявления '{start_date}', используется CreatedAt отчета 1")

        # Парсим end_date (дата устранения/контрольная дата)
        self.end_date = None
        if end_date:
            try:
                self.end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                print(f"⚠️ Неверный формат даты устранения '{end_date}', используется CreatedAt отчета 2")

        # Извлекаем CreatedAt из первого отчета (для даты начала)
        self.created_date_report1 = self._extract_created_date(self.report1)
        # Извлекаем CreatedAt из второго отчета (для даты устранения)
        self.created_date_report2 = self._extract_created_date(self.report2)

        if self.debug:
            print(f"📋 Detected report type: {self.report_type}")
            if self.created_date_report1:
                print(f"📅 CreatedAt отчета 1: {self.created_date_report1}")
            if self.created_date_report2:
                print(f"📅 CreatedAt отчета 2: {self.created_date_report2}")
            if self.start_date:
                print(f"📅 Дата выявления: {self.start_date}")
            else:
                print(f"📅 Дата выявления: используется CreatedAt отчета 1 ({self.created_date_report1})")
            if self.end_date:
                print(f"📅 Дата устранения: {self.end_date}")
            else:
                print(f"📅 Дата устранения: используется CreatedAt отчета 2 ({self.created_date_report2})")

        self.packages1: Dict[str, Dict] = {}
        self.packages2: Dict[str, Dict] = {}
        self.vulns1: Dict[str, Dict] = {}
        self.vulns2: Dict[str, Dict] = {}

        # Для поиска по имени (для JAR)
        self.packages_by_name1: Dict[str, Dict] = {}
        self.packages_by_name2: Dict[str, Dict] = {}

        self.package_changes: Dict[str, ChangeType] = {}
        self.vuln_changes: Dict[str, ChangeType] = {}

    def _load_report(self, path: str) -> Dict:
        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {path}: {e}", file=sys.stderr)
            sys.exit(1)

    def _extract_diff_metadata(self, report: Dict) -> Optional[Dict]:
        """Возвращает блок _diff_metadata, если отчет является diff-отчетом"""
        meta = report.get('_diff_metadata')
        return meta if isinstance(meta, dict) else None

    def _extract_history(self, meta: Optional[Dict]) -> Dict:
        """Возвращает историю предыдущих сравнений (если она есть в метаданных)"""
        if not meta:
            return {'vulnerabilities': {}, 'packages': {}}

        history = meta.get('history') or {}
        return {
            'vulnerabilities': dict(history.get('vulnerabilities') or {}),
            'packages': dict(history.get('packages') or {})
        }

    def _normalize_report(self, report: Dict) -> Dict:
        """
        Приводит отчет к виду обычного отчета Trivy.

        Для diff-отчета:
        - удаляются секции предыдущего сравнения (Type/Class == removed),
          чтобы уже устраненные уязвимости не попадали в baseline;
        - с уязвимостей снимаются служебные поля diff-анализа.
        """
        normalized = deepcopy(report)

        results = normalized.get('Results')
        if isinstance(results, list):
            filtered = []
            for result in results:
                if not isinstance(result, dict):
                    continue
                if result.get('Type') == 'removed' or result.get('Class') == 'removed':
                    continue
                filtered.append(result)
            normalized['Results'] = filtered

        for result in normalized.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                for field in ('_change_type', '_vuln_key', '_package_change_type',
                              '_package_version_change', '_remaining_days', '_first_seen'):
                    vuln.pop(field, None)

        normalized.pop('_diff_metadata', None)

        return normalized

    def _collect_baseline_vuln_meta(self, report: Dict) -> Dict[str, Dict]:
        """
        Собирает данные предыдущего анализа по уязвимостям diff-отчета:
        остаток срока и дату первого обнаружения.
        """
        meta = {}

        for result in report.get('Results', []):
            if not isinstance(result, dict):
                continue
            if result.get('Type') == 'removed' or result.get('Class') == 'removed':
                continue

            for vuln in result.get('Vulnerabilities', []):
                vuln_id = vuln.get('VulnerabilityID')
                pkg_name = vuln.get('PkgName')
                pkg_uid = vuln.get('PkgIdentifier', {}).get('UID', '')
                if not vuln_id or not pkg_name:
                    continue

                vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_uid)
                meta[vuln_key] = {
                    'remaining_days': vuln.get('_remaining_days'),
                    'first_seen': self._parse_date(vuln.get('_first_seen'))
                }

        return meta

    def _parse_date(self, value) -> Optional[datetime.date]:
        """Разбирает дату из строки формата ГГГГ-ММ-ДД"""
        if not value or not isinstance(value, str):
            return None
        try:
            return datetime.strptime(value[:10], '%Y-%m-%d').date()
        except ValueError:
            return None

    def _detect_report_type(self) -> str:
        """Определяет тип отчета по наличию PkgPath"""
        for result in self.report1.get('Results', []):
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    if vuln.get('PkgPath'):
                        return 'jar'
            if 'Packages' in result:
                for pkg in result['Packages']:
                    if pkg.get('FilePath'):
                        return 'jar'
        return 'docker'

    def _extract_created_date(self, report: Dict) -> Optional[datetime.date]:
        """Извлекает дату из поля CreatedAt отчета"""
        created = report.get('CreatedAt', '')
        if created:
            try:
                # Формат: "2026-08-31T03:48:29.664005488Z"
                return datetime.strptime(created[:10], '%Y-%m-%d').date()
            except ValueError:
                pass
        return None

    def _get_remediation_days(self, severity: str, has_exploits: bool) -> int:
        """
        Возвращает срок устранения в днях (30 дней = 1 месяц)
        Логика взята из excel_reporter.py
        """
        if severity == 'CRITICAL':
            months = 6
        elif severity == 'HIGH':
            months = 9
        else:  # MEDIUM, LOW, UNKNOWN
            months = 12

        if has_exploits:
            months = max(1, months - 3)

        return months * 30  # 30 дней в месяце

    def _calculate_remaining_days(self, severity: str, has_exploits: bool,
                                  start_override: Optional[datetime.date] = None) -> Optional[int]:
        """
        Вычисляет остаточный срок в днях.

        start_date = дата_выявления (или CreatedAt первого отчета)
        end_date = дата_устранения (контрольная дата, или CreatedAt второго отчета)

        Срок устранения (в днях) прибавляется к start_date.
        due_date = start_date + remediation_days

        remaining_days = due_date - end_date
        Если remaining_days > 0 → еще есть время
        Если remaining_days <= 0 → просрочка
        """
        # Берем start_date из первого отчета (если не указана)
        if start_override:
            start_date = start_override
        elif self.start_date:
            start_date = self.start_date
        else:
            start_date = self.created_date_report1

        # Берем end_date из второго отчета (если не указана)
        if self.end_date:
            end_date = self.end_date
        else:
            end_date = self.created_date_report2

        if not start_date or not end_date:
            return None

        # Срок устранения в днях
        days = self._get_remediation_days(severity, has_exploits)

        # Дата, до которой должны устранить
        due_date = start_date + timedelta(days=days)

        # Остаток в днях (от due_date до end_date)
        return (due_date - end_date).days

    def _resolve_end_date(self) -> Optional[datetime.date]:
        """Дата устранения (контрольная дата) текущего сравнения"""
        return self.end_date or self.created_date_report2

    def _resolve_baseline_end_date(self) -> Optional[datetime.date]:
        """
        Дата устранения, использованная в предыдущем diff-анализе
        (нужна для переноса остатка срока)
        """
        if not self.baseline_meta:
            return None

        raw_end = self.baseline_meta.get('end_date')
        if isinstance(raw_end, str) and raw_end != 'from_report2_created_date':
            parsed = self._parse_date(raw_end)
            if parsed:
                return parsed

        report2_meta = self.baseline_meta.get('report2') or {}
        return self._parse_date(report2_meta.get('created_date'))

    def _resolve_baseline_start_date(self) -> Optional[datetime.date]:
        """
        Дата выявления, использованная в предыдущем diff-анализе
        (нужна как дата первого обнаружения для унаследованных уязвимостей)
        """
        if not self.baseline_meta:
            return None

        raw_start = self.baseline_meta.get('start_date')
        if isinstance(raw_start, str) and raw_start != 'from_report1_created_date':
            parsed = self._parse_date(raw_start)
            if parsed:
                return parsed

        report1_meta = self.baseline_meta.get('report1') or {}
        return self._parse_date(report1_meta.get('created_date'))

    def _carry_over_remaining_days(self, vuln_key: str) -> Optional[int]:
        """
        Переносит остаток срока из предыдущего diff-анализа, уменьшая его
        на количество дней, прошедших между контрольными датами.

        Если в baseline остаток не рассчитывался, вернется None —
        срок будет посчитан от даты первого обнаружения.
        """
        baseline = self.baseline_vuln_meta.get(vuln_key)
        if not baseline or baseline.get('remaining_days') is None:
            return None

        baseline_end = self._resolve_baseline_end_date()
        current_end = self._resolve_end_date()

        if not baseline_end or not current_end:
            return baseline['remaining_days']

        elapsed = (current_end - baseline_end).days
        return baseline['remaining_days'] - elapsed

    def _resolve_first_seen(self, vuln_key: str, change_type: ChangeType) -> Optional[datetime.date]:
        """
        Дата первого обнаружения уязвимости.

        - для унаследованных уязвимостей берется из предыдущего анализа,
          иначе используется дата выявления baseline;
        - для новых уязвимостей берется из истории (если уязвимость
          уже появлялась ранее), иначе — контрольная дата текущего сравнения.
        """
        baseline = self.baseline_vuln_meta.get(vuln_key)
        if change_type == ChangeType.UNCHANGED and baseline and baseline.get('first_seen'):
            return baseline['first_seen']

        history_entry = self.baseline_history['vulnerabilities'].get(vuln_key)
        if history_entry:
            parsed = self._parse_date(history_entry.get('first_seen'))
            if parsed:
                return parsed

        if change_type == ChangeType.UNCHANGED:
            return self._resolve_baseline_start_date() or self.start_date or self.created_date_report1

        return self._resolve_end_date()

    def _has_exploits_from_vuln(self, vuln: Dict) -> bool:
        """Проверяет наличие эксплойтов в уязвимости"""
        sploitscan = vuln.get('sploitscan', {})
        if isinstance(sploitscan, dict) and sploitscan:
            # GitHub PoCs
            github_data = sploitscan.get('GitHub Data')
            if github_data and isinstance(github_data, dict):
                github_pocs = github_data.get('pocs', [])
                if github_pocs and len(github_pocs) > 0:
                    return True

            # ExploitDB
            exploitdb_list = sploitscan.get('ExploitDB Data', [])
            if exploitdb_list:
                for item in exploitdb_list:
                    if isinstance(item, dict) and item.get('id'):
                        return True

            # NVD exploits
            nvd_data = sploitscan.get('NVD Data')
            if nvd_data and isinstance(nvd_data, dict):
                nvd_exploits = nvd_data.get('exploits', [])
                if nvd_exploits and len(nvd_exploits) > 0:
                    return True

            # Metasploit
            metasploit_data = sploitscan.get('Metasploit Data')
            if metasploit_data and isinstance(metasploit_data, dict):
                metasploit_modules = metasploit_data.get('modules', [])
                if metasploit_modules:
                    for module in metasploit_modules:
                        if isinstance(module, dict) and module.get('url'):
                            return True

        return False

    def _build_pkg_key(self, pkg_name: str, pkg_uid: str = None) -> str:
        if not pkg_name:
            return None

        if self.report_type == 'jar' and pkg_uid:
            return f"{pkg_name}-{pkg_uid}"

        return pkg_name

    def _build_vuln_key(self, vuln_id: str, pkg_name: str, pkg_uid: str = None) -> str:
        if not vuln_id or not pkg_name:
            return None

        if self.report_type == 'jar' and pkg_uid:
            return f"{vuln_id}-{pkg_name}-{pkg_uid}"

        return f"{vuln_id}-{pkg_name}"

    def _extract_from_vulns(self, report: Dict) -> Tuple[Dict, Dict]:
        """Извлекает пакеты и уязвимости из секции Vulnerabilities"""
        packages = {}
        vulns = {}

        for result in report.get('Results', []):
            if 'Vulnerabilities' not in result:
                continue

            for vuln in result['Vulnerabilities']:
                vuln_id = vuln.get('VulnerabilityID')
                pkg_name = vuln.get('PkgName')
                pkg_version = vuln.get('InstalledVersion') or vuln.get('PkgVersion')
                pkg_path = vuln.get('PkgPath') or vuln.get('FilePath')
                pkg_uid = vuln.get('PkgIdentifier', {}).get('UID', '')

                if not vuln_id or not pkg_name:
                    continue

                vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_uid)
                pkg_key = self._build_pkg_key(pkg_name, pkg_uid)

                vulns[vuln_key] = vuln

                if pkg_key not in packages:
                    packages[pkg_key] = {
                        'name': pkg_name,
                        'version': pkg_version,
                        'path': pkg_path,
                        'uid': pkg_uid
                    }
                else:
                    if pkg_version and not packages[pkg_key]['version']:
                        packages[pkg_key]['version'] = pkg_version

        return packages, vulns

    def _extract_packages_by_name(self, report: Dict) -> Dict:
        """Извлекает пакеты по имени из секции Packages (для поиска UPDATED)"""
        packages = {}

        for result in report.get('Results', []):
            if 'Packages' not in result:
                continue

            for pkg in result['Packages']:
                pkg_name = pkg.get('Name')
                pkg_version = pkg.get('Version')
                pkg_path = pkg.get('FilePath')
                pkg_uid = pkg.get('Identifier', {}).get('UID', '')

                if not pkg_name:
                    continue

                # Сохраняем по имени
                if pkg_name not in packages:
                    packages[pkg_name] = {
                        'name': pkg_name,
                        'version': pkg_version,
                        'path': pkg_path,
                        'uid': pkg_uid
                    }
                else:
                    if pkg_version:
                        packages[pkg_name]['version'] = pkg_version

        return packages

    def analyze(self):
        print("🔍 Extracting data from reports...")

        # Извлекаем из секции Vulnerabilities
        vuln_packages1, self.vulns1 = self._extract_from_vulns(self.report1)
        vuln_packages2, self.vulns2 = self._extract_from_vulns(self.report2)

        # Извлекаем пакеты по имени из секции Packages (для JAR)
        self.packages_by_name1 = self._extract_packages_by_name(self.report1)
        self.packages_by_name2 = self._extract_packages_by_name(self.report2)

        # Объединяем (для Docker просто копируем, для JAR добавляем)
        if self.report_type == 'docker':
            self.packages1 = vuln_packages1
            self.packages2 = vuln_packages2
        else:  # jar
            # Берем пакеты из Vulnerabilities
            self.packages1 = vuln_packages1.copy()
            self.packages2 = vuln_packages2.copy()

            # Добавляем пакеты по имени (если их нет в vuln_packages)
            for name, data in self.packages_by_name1.items():
                if name not in self.packages1:
                    self.packages1[name] = data

            for name, data in self.packages_by_name2.items():
                if name not in self.packages2:
                    self.packages2[name] = data

        if self.debug:
            print(f"📦 Packages in report1: {len(self.packages1)}")
            print(f"📦 Packages in report2: {len(self.packages2)}")
            print(f"🔒 Vulnerabilities in report1: {len(self.vulns1)}")
            print(f"🔒 Vulnerabilities in report2: {len(self.vulns2)}")

        print("📦 Comparing packages...")

        all_package_keys = set(self.packages1.keys()) | set(self.packages2.keys())

        for pkg_key in all_package_keys:
            if pkg_key not in self.packages1:
                self.package_changes[pkg_key] = ChangeType.NEW
            elif pkg_key not in self.packages2:
                # Для JAR: проверяем, может пакет обновился (изменился UID)
                if self.report_type == 'jar':
                    pkg_name = self.packages1[pkg_key].get('name')
                    if pkg_name and pkg_name in self.packages_by_name2:
                        # Нашли пакет с таким же именем в report2
                        v1 = self.packages1[pkg_key].get('version')
                        v2 = self.packages_by_name2[pkg_name].get('version')

                        if v1 != v2:
                            # Версии разные -> это UPDATED
                            self.package_changes[pkg_key] = ChangeType.UPDATED
                            # Обновляем данные пакета
                            self.packages2[pkg_key] = self.packages_by_name2[pkg_name]

                            # Удаляем дубликат (пакет по имени, если он есть)
                            if pkg_name in self.packages2 and pkg_name != pkg_key:
                                del self.packages2[pkg_name]
                            if pkg_name in self.package_changes:
                                del self.package_changes[pkg_name]
                        else:
                            self.package_changes[pkg_key] = ChangeType.REMOVED
                    else:
                        self.package_changes[pkg_key] = ChangeType.REMOVED
                else:
                    self.package_changes[pkg_key] = ChangeType.REMOVED
            else:
                v1 = self.packages1[pkg_key].get('version')
                v2 = self.packages2[pkg_key].get('version')

                if v1 == v2:
                    self.package_changes[pkg_key] = ChangeType.UNCHANGED
                else:
                    self.package_changes[pkg_key] = ChangeType.UPDATED

        # Удаляем дубликаты (пакеты по имени, которые уже есть с UID)
        if self.report_type == 'jar':
            # Собираем ключи для удаления
            keys_to_remove = []
            for key in list(self.package_changes.keys()):
                # Если ключ без UID (просто имя) и есть такой же с UID
                if '-' not in key:  # это пакет по имени
                    # Ищем пакет с таким же именем но с UID
                    for other_key in self.package_changes.keys():
                        if other_key != key and other_key.startswith(key + '-'):
                            keys_to_remove.append(key)
                            break

            for key in keys_to_remove:
                del self.package_changes[key]
                if key in self.packages1:
                    del self.packages1[key]
                if key in self.packages2:
                    del self.packages2[key]

        print("🔒 Comparing vulnerabilities...")

        all_vuln_keys = set(self.vulns1.keys()) | set(self.vulns2.keys())

        for vuln_key in all_vuln_keys:
            if vuln_key not in self.vulns1:
                self.vuln_changes[vuln_key] = ChangeType.NEW
            elif vuln_key not in self.vulns2:
                self.vuln_changes[vuln_key] = ChangeType.REMOVED
            else:
                self.vuln_changes[vuln_key] = ChangeType.UNCHANGED

        print("✅ Analysis complete!")

    def build_diff_report(self) -> Dict:
        print("📝 Building diff report...")

        diff_report = deepcopy(self.report2)

        for result in diff_report.get('Results', []):
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln_id = vuln.get('VulnerabilityID')
                    pkg_name = vuln.get('PkgName')
                    pkg_uid = vuln.get('PkgIdentifier', {}).get('UID', '')

                    if vuln_id and pkg_name:
                        vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_uid)
                        pkg_key = self._build_pkg_key(pkg_name, pkg_uid)

                        if vuln_key in self.vuln_changes:
                            change_type = self.vuln_changes[vuln_key]
                            vuln['_change_type'] = change_type.value
                            vuln['_vuln_key'] = vuln_key

                            first_seen = self._resolve_first_seen(vuln_key, change_type)
                            if first_seen:
                                vuln['_first_seen'] = first_seen.isoformat()

                        if pkg_key in self.package_changes:
                            vuln['_package_change_type'] = self.package_changes[pkg_key].value

                            # Если пакет обновился, добавляем информацию о версиях
                            if self.package_changes[pkg_key] == ChangeType.UPDATED:
                                if pkg_key in self.packages1 and pkg_key in self.packages2:
                                    old_version = self.packages1[pkg_key].get('version', 'N/A')
                                    new_version = self.packages2[pkg_key].get('version', 'N/A')
                                    vuln['_package_version_change'] = {
                                        'old_version': old_version,
                                        'new_version': new_version
                                    }

                        # ===== РАСЧЕТ ОСТАТОЧНОГО СРОКА =====
                        change_type = self.vuln_changes.get(vuln_key)
                        if change_type == ChangeType.UNCHANGED:
                            # Сначала пробуем перенести остаток из предыдущего анализа
                            remaining_days = self._carry_over_remaining_days(vuln_key)

                            if remaining_days is None:
                                severity = vuln.get('Severity', 'UNKNOWN')
                                has_exploits = self._has_exploits_from_vuln(vuln)
                                remaining_days = self._calculate_remaining_days(severity, has_exploits)

                            if remaining_days is not None:
                                vuln['_remaining_days'] = remaining_days
                                if self.debug:
                                    print(f"   🔄 {vuln_id}: remaining_days = {remaining_days}")
                        elif change_type == ChangeType.NEW:
                            # Для новых уязвимостей срок считается от даты первого
                            # обнаружения: у вернувшейся уязвимости она берется
                            # из истории, поэтому срок сразу показывает просрочку
                            first_seen = self._parse_date(vuln.get('_first_seen'))
                            if first_seen and first_seen != self._resolve_end_date():
                                severity = vuln.get('Severity', 'UNKNOWN')
                                has_exploits = self._has_exploits_from_vuln(vuln)
                                remaining_days = self._calculate_remaining_days(
                                    severity, has_exploits, start_override=first_seen
                                )

                                if remaining_days is not None:
                                    vuln['_remaining_days'] = remaining_days
                                    if self.debug:
                                        print(f"   ➕ {vuln_id}: remaining_days = {remaining_days}")

        removed_vulns = []
        for vuln_key, change_type in self.vuln_changes.items():
            if change_type == ChangeType.REMOVED and vuln_key in self.vulns1:
                vuln_data = deepcopy(self.vulns1[vuln_key])
                vuln_data['_change_type'] = ChangeType.REMOVED.value
                vuln_data['_vuln_key'] = vuln_key

                # Проверяем статус пакета
                pkg_uid = vuln_data.get('PkgIdentifier', {}).get('UID', '')
                pkg_name = vuln_data.get('PkgName')
                pkg_key = self._build_pkg_key(pkg_name, pkg_uid)

                if pkg_key in self.package_changes:
                    vuln_data['_package_change_type'] = self.package_changes[pkg_key].value

                    # Если пакет обновился, добавляем информацию о версиях
                    if self.package_changes[pkg_key] == ChangeType.UPDATED:
                        if pkg_key in self.packages1 and pkg_key in self.packages2:
                            old_version = self.packages1[pkg_key].get('version', 'N/A')
                            new_version = self.packages2[pkg_key].get('version', 'N/A')
                            vuln_data['_package_version_change'] = {
                                'old_version': old_version,
                                'new_version': new_version
                            }
                else:
                    vuln_data['_package_change_type'] = ChangeType.REMOVED.value

                removed_vulns.append(vuln_data)

        if removed_vulns:
            removed_result = {
                "Target": "Removed Vulnerabilities",
                "Class": "removed",
                "Type": "removed",
                "Vulnerabilities": removed_vulns
            }
            diff_report['Results'].append(removed_result)

        diff_report['_diff_metadata'] = {
            'packages': self._calculate_stats(self.package_changes),
            'vulnerabilities': self._calculate_stats(self.vuln_changes),
            'report1': {
                'path': str(self.report1_path),
                'timestamp': datetime.fromtimestamp(Path(self.report1_path).stat().st_mtime).isoformat(),
                'created_date': self.created_date_report1.isoformat() if self.created_date_report1 else None
            },
            'report2': {
                'path': str(self.report2_path),
                'timestamp': datetime.fromtimestamp(Path(self.report2_path).stat().st_mtime).isoformat(),
                'created_date': self.created_date_report2.isoformat() if self.created_date_report2 else None
            },
            'history': self._build_history(removed_vulns)
        }

        # Добавляем информацию о датах
        if self.start_date:
            diff_report['_diff_metadata']['start_date'] = self.start_date.isoformat()
        else:
            diff_report['_diff_metadata']['start_date'] = 'from_report1_created_date'

        if self.end_date:
            diff_report['_diff_metadata']['end_date'] = self.end_date.isoformat()
        else:
            diff_report['_diff_metadata']['end_date'] = 'from_report2_created_date'

        return diff_report

    def _build_history(self, removed_vulns: list) -> Dict:
        """
        Формирует историю удаленных уязвимостей и пакетов.

        История наследуется из baseline (если это diff-отчет) и дополняется
        удалениями текущего сравнения.
        """
        removed_at = self._resolve_end_date()
        removed_at_str = removed_at.isoformat() if removed_at else None

        vuln_history = {
            key: dict(entry)
            for key, entry in self.baseline_history['vulnerabilities'].items()
        }
        pkg_history = {
            key: dict(entry)
            for key, entry in self.baseline_history['packages'].items()
        }

        for vuln_data in removed_vulns:
            vuln_id = vuln_data.get('VulnerabilityID')
            pkg_name = vuln_data.get('PkgName')
            pkg_uid = vuln_data.get('PkgIdentifier', {}).get('UID', '')
            vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_uid)
            if not vuln_key:
                continue

            entry = vuln_history.get(vuln_key)
            if entry is None:
                entry = {
                    'vulnerability_id': vuln_id,
                    'pkg_name': pkg_name,
                    'installed_version': vuln_data.get('InstalledVersion'),
                    'severity': vuln_data.get('Severity', 'UNKNOWN'),
                    'target': vuln_data.get('PkgPath') or vuln_data.get('FilePath'),
                    'first_seen': vuln_data.get('_first_seen'),
                    'removed_count': 0
                }

            entry['last_removed_at'] = removed_at_str
            entry['removed_count'] = int(entry.get('removed_count') or 0) + 1
            vuln_history[vuln_key] = entry

        for pkg_key, change_type in self.package_changes.items():
            if change_type != ChangeType.REMOVED:
                continue

            pkg_data = self.packages1.get(pkg_key)
            if not pkg_data:
                continue

            entry = pkg_history.get(pkg_key)
            if entry is None:
                entry = {
                    'pkg_name': pkg_data.get('name'),
                    'version': pkg_data.get('version'),
                    'path': pkg_data.get('path'),
                    'first_seen': self._resolve_baseline_start_date().isoformat()
                    if self._resolve_baseline_start_date() else None,
                    'removed_count': 0
                }

            entry['last_removed_at'] = removed_at_str
            entry['removed_count'] = int(entry.get('removed_count') or 0) + 1
            pkg_history[pkg_key] = entry

        return {
            'vulnerabilities': vuln_history,
            'packages': pkg_history
        }

    def _calculate_stats(self, changes: Dict) -> Dict:
        stats = {'new': 0, 'unchanged': 0, 'updated': 0, 'removed': 0}
        for change in changes.values():
            stats[change.value] += 1
        return stats

    def print_summary(self):
        print("\n" + "=" * 60)
        print("TRIVY DIFF ANALYSIS SUMMARY")
        print("=" * 60)

        pkg_stats = self._calculate_stats(self.package_changes)
        vuln_stats = self._calculate_stats(self.vuln_changes)

        print(f"\n📋 Report type: {self.report_type}")

        print("\n📦 PACKAGES:")
        for change_type in ChangeType:
            count = pkg_stats[change_type.value]
            emoji = {"new": "➕", "unchanged": "➖", "updated": "🔄", "removed": "❌"}.get(change_type.value, "•")
            print(f"  {emoji} {change_type.value.upper()}: {count}")

            packages = []
            for pkg_key, change in self.package_changes.items():
                if change == change_type:
                    pkg_data = self.packages2.get(pkg_key) or self.packages1.get(pkg_key)
                    if pkg_data:
                        path_info = f" [{pkg_data.get('path', '')}]" if pkg_data.get('path') else ""

                        if change_type == ChangeType.UPDATED and pkg_key in self.packages1 and pkg_key in self.packages2:
                            v1 = self.packages1[pkg_key].get('version', 'N/A')
                            v2 = self.packages2[pkg_key].get('version', 'N/A')
                            version_info = f" {v1} → {v2}"
                        else:
                            version_info = f" {pkg_data.get('version', 'N/A')}"

                        packages.append(f"{pkg_key}{path_info}{version_info}")

            for pkg in sorted(packages):
                print(f"     - {pkg}")

        print("\n🔒 VULNERABILITIES:")
        for change_type in [ChangeType.NEW, ChangeType.UNCHANGED, ChangeType.REMOVED]:
            count = vuln_stats[change_type.value]
            emoji = {"new": "⚠️", "unchanged": "➖", "removed": "✅"}.get(change_type.value, "•")
            print(f"  {emoji} {change_type.value.upper()}: {count}")

            vulns = []
            for vuln_key, change in self.vuln_changes.items():
                if change == change_type:
                    vuln_info = vuln_key
                    # Добавляем информацию об остаточном сроке для UNCHANGED
                    if change_type == ChangeType.UNCHANGED:
                        vuln_data = self.vulns2.get(vuln_key)
                        if vuln_data:
                            remaining = vuln_data.get('_remaining_days')
                            if remaining is not None:
                                if remaining > 0:
                                    vuln_info += f" (осталось {remaining} дн.)"
                                elif remaining == 0:
                                    vuln_info += " (истекает сегодня)"
                                else:
                                    vuln_info += f" (просрочка {abs(remaining)} дн.)"
                    vulns.append(vuln_info)

            for vuln in sorted(vulns):
                print(f"     - {vuln}")

        print(f"\n  📊 TOTAL packages: {sum(pkg_stats.values())}")
        print(f"  📊 TOTAL vulnerabilities: {sum(vuln_stats.values())}")
        print("\n" + "=" * 60)

    def save_diff_report(self, output_dir: Optional[Path] = None, prefix: str = "diff_report") -> str:
        diff_report = self.build_diff_report()

        if output_dir is None:
            output_dir = Path.cwd()
        else:
            output_dir = Path(output_dir)

        # Формируем имя из второго отчета (нового) + постфикс _diff
        report2_path = Path(self.report2_path)
        base_name = report2_path.stem  # Имя без расширения
        output_file = output_dir / f"{base_name}_diff.json"

        # Если файл с таким именем уже существует, добавляем timestamp
        if output_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"{base_name}_diff_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(diff_report, f, indent=2, ensure_ascii=False)

        return str(output_file)


def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [start_date] [end_date] [--debug]")
            print("  start_date - дата выявления уязвимостей (формат YYYY-MM-DD)")
            print("  end_date   - дата устранения/контрольная дата (формат YYYY-MM-DD)")
            print("  --debug    - enable debug output")
            print("\nПримеры:")
            print("  python trivy_diff.py old.json new.json")
            print("  python trivy_diff.py old.json new.json 2026-09-01")
            print("  python trivy_diff.py old.json new.json 2026-09-01 2026-12-01")
            print("  python trivy_diff.py old.json new.json --debug")
            sys.exit(1)

        debug = '--debug' in sys.argv

        # Собираем аргументы без флагов
        args = []
        for arg in sys.argv[1:]:
            if arg.startswith('--'):
                continue
            args.append(arg)

        if len(args) < 2:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [start_date] [end_date] [--debug]")
            sys.exit(1)

        report1 = args[0]
        report2 = args[1]
        start_date = args[2] if len(args) >= 3 else None
        end_date = args[3] if len(args) >= 4 else None

        # Проверяем формат дат, если они указаны
        if start_date:
            try:
                datetime.strptime(start_date, '%Y-%m-%d')
            except ValueError:
                print(f"❌ Ошибка: неверный формат даты выявления '{start_date}'")
                print("   Используйте формат ГГГГ-ММ-ДД (например: 2026-09-01)")
                sys.exit(1)

        if end_date:
            try:
                datetime.strptime(end_date, '%Y-%m-%d')
            except ValueError:
                print(f"❌ Ошибка: неверный формат даты устранения '{end_date}'")
                print("   Используйте формат ГГГГ-ММ-ДД (например: 2026-12-01)")
                sys.exit(1)

        print(f"📂 Loading reports:")
        print(f"  Report 1 (старый отчет): {report1}")
        print(f"  Report 2 (новый отчет): {report2}")
        if start_date:
            print(f"  📅 Дата выявления: {start_date}")
        else:
            print(f"  📅 Дата выявления: из отчета 1 (CreatedAt)")
        if end_date:
            print(f"  📅 Дата устранения: {end_date}")
        else:
            print(f"  📅 Дата устранения: из отчета 2 (CreatedAt)")
        print()

        analyzer = TrivyDiffAnalyzer(report1, report2, debug, start_date, end_date)
        analyzer.analyze()
        analyzer.print_summary()

        output_file = analyzer.save_diff_report()
        print(f"\n💾 Diff report saved to: {output_file}")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()