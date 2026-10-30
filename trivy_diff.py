#!/usr/bin/env python3
"""
Trivy Diff Analyzer
Поддерживает:
- Docker-образы (идентификация по PkgName)
- JAR-сканирования (идентификация по PkgName + PkgPath)
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

        # История из отчетов прежних версий могла быть сохранена с ключами
        # на UID пакета — пересобираем их по полям записей
        self.baseline_history['vulnerabilities'] = self._normalize_history_keys(
            self.baseline_history['vulnerabilities'], 'vulnerabilities'
        )
        self.baseline_history['packages'] = self._normalize_history_keys(
            self.baseline_history['packages'], 'packages'
        )

        if self.baseline_meta and not self._has_baseline_dates():
            print("⚠️ Baseline — diff-отчет старого формата: даты сравнения в нем не сохранены.")
            print("   Дата удаления будет взята из CreatedAt отчета, дата первого выявления — недоступна.")

        # Для анализа используются нормализованные отчеты: из diff-отчета
        # удаляются служебные поля и секции предыдущего сравнения
        self.report1 = self._normalize_report(self.report1_raw)
        self.report2 = self._normalize_report(self.report2_raw)

        self.report_type = self._detect_report_type()

        # Данные предыдущего анализа по уязвимостям baseline (первое обнаружение, срок)
        self.baseline_vuln_meta = self._collect_baseline_vuln_meta(self.report1_raw)

        # Уязвимости, уже помеченные удаленными во втором отчете (diff+diff):
        # они не должны повторно учитываться как удаления текущего сравнения
        self.report2_removed_keys = self._collect_removed_keys(self.report2_raw)

        # Пакеты, удаленные в предыдущем сравнении (для истории)
        self.baseline_removed_packages: Dict[str, Dict] = {}
        if self.baseline_meta:
            removed_pkgs = self.baseline_meta.get('removed_packages') or {}
            if isinstance(removed_pkgs, dict):
                self.baseline_removed_packages = self._normalize_history_keys(
                    {
                        key: dict(data) for key, data in removed_pkgs.items()
                        if isinstance(data, dict)
                    },
                    'packages'
                )

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
                              '_package_version_change', '_remaining_days', '_first_seen',
                              '_due_date'):
                    vuln.pop(field, None)

        normalized.pop('_diff_metadata', None)

        return normalized

    def _collect_removed_keys(self, report: Dict) -> Set[str]:
        """Собирает ключи уязвимостей из секции предыдущего сравнения (removed)"""
        keys = set()

        for result in report.get('Results', []):
            if not isinstance(result, dict):
                continue
            if result.get('Type') != 'removed' and result.get('Class') != 'removed':
                continue

            for vuln in result.get('Vulnerabilities', []):
                vuln_id = vuln.get('VulnerabilityID')
                pkg_name = vuln.get('PkgName')
                if not vuln_id or not pkg_name:
                    continue

                keys.add(self._build_vuln_key(vuln_id, pkg_name, self._vuln_pkg_path(vuln)))

        return keys

    def _collect_baseline_vuln_meta(self, report: Dict) -> Dict[str, Dict]:
        """
        Собирает данные предыдущего анализа по уязвимостям diff-отчета:
        дату, до которой нужно устранить (или остаток срока), и дату первого обнаружения.

        Для старых diff-отчетов, где _due_date отсутствует, дата устранения
        восстанавливается из остатка срока и контрольной даты предыдущего анализа.
        """
        meta = {}
        baseline_end = self._resolve_baseline_end_date()
        baseline_start = self._resolve_baseline_start_date()

        for result in report.get('Results', []):
            if not isinstance(result, dict):
                continue
            if result.get('Type') == 'removed' or result.get('Class') == 'removed':
                continue

            for vuln in result.get('Vulnerabilities', []):
                vuln_id = vuln.get('VulnerabilityID')
                pkg_name = vuln.get('PkgName')
                if not vuln_id or not pkg_name:
                    continue

                vuln_key = self._build_vuln_key(vuln_id, pkg_name, self._vuln_pkg_path(vuln))

                # Дата первого обнаружения: поле появилось в новой версии,
                # для старых отчетов выводится из статуса и дат сравнения
                first_seen = self._parse_date(vuln.get('_first_seen'))
                if first_seen is None:
                    if vuln.get('_change_type') == ChangeType.NEW.value:
                        first_seen = baseline_end
                    else:
                        first_seen = baseline_start

                # Дата, до которой нужно устранить
                due_date = self._parse_date(vuln.get('_due_date'))
                if due_date is None:
                    remaining = vuln.get('_remaining_days')
                    if remaining is not None and baseline_end:
                        due_date = baseline_end + timedelta(days=remaining)

                meta[vuln_key] = {
                    'due_date': due_date,
                    'first_seen': first_seen
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

    def _resolve_end_date(self) -> Optional[datetime.date]:
        """Дата устранения (контрольная дата) текущего сравнения"""
        return self.end_date or self.created_date_report2

    def _resolve_baseline_end_date(self) -> Optional[datetime.date]:
        """
        Дата устранения, использованная в предыдущем diff-анализе
        (нужна для переноса остатка срока)

        Для самых старых diff-отчетов, где даты в метаданных отсутствуют,
        используется CreatedAt самого отчета: diff-отчет строится копией
        второго отчета, поэтому его CreatedAt и есть контрольная дата
        предыдущего сравнения.
        """
        if not self.baseline_meta:
            return None

        raw_end = self.baseline_meta.get('end_date')
        if isinstance(raw_end, str) and raw_end != 'from_report2_created_date':
            parsed = self._parse_date(raw_end)
            if parsed:
                return parsed

        report2_meta = self.baseline_meta.get('report2') or {}
        parsed = self._parse_date(report2_meta.get('created_date'))
        if parsed:
            return parsed

        return self._extract_created_date(self.report1_raw)

    def _resolve_baseline_start_date(self) -> Optional[datetime.date]:
        """
        Дата выявления, использованная в предыдущем diff-анализе
        (нужна как дата первого обнаружения для унаследованных уязвимостей)

        В самых старых diff-отчетах даты отсутствуют полностью — тогда
        вернется None, и дата первого обнаружения останется неизвестной.
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

    def _has_baseline_dates(self) -> bool:
        """Проверяет, есть ли в метаданных baseline хоть одна дата сравнения"""
        meta = self.baseline_meta or {}

        for key in ('start_date', 'end_date'):
            value = meta.get(key)
            if isinstance(value, str) and value not in ('from_report1_created_date',
                                                        'from_report2_created_date'):
                return True

        for key in ('report1', 'report2'):
            if self._parse_date((meta.get(key) or {}).get('created_date')):
                return True

        return False

    def _resolve_due_date(self, vuln_key: str, severity: str, has_exploits: bool,
                          first_seen: Optional[datetime.date]) -> Optional[datetime.date]:
        """
        Возвращает дату, до которой уязвимость должна быть устранена.

        Для уязвимости из предыдущего анализа берется зафиксированная дата
        (в старых отчетах восстанавливается из остатка срока). Для остальных
        рассчитывается от даты первого обнаружения и больше не меняется.
        """
        baseline = self.baseline_vuln_meta.get(vuln_key)
        if baseline and baseline.get('due_date'):
            return baseline['due_date']

        if not first_seen:
            return None

        days = self._get_remediation_days(severity, has_exploits)
        return first_seen + timedelta(days=days)

    def _remaining_from_due_date(self, due_date: Optional[datetime.date]) -> Optional[int]:
        """Остаток срока в днях на контрольную дату текущего сравнения"""
        end_date = self._resolve_end_date()

        if not due_date or not end_date:
            return None

        return (due_date - end_date).days

    def _resolve_first_seen(self, vuln_key: str, change_type: ChangeType) -> Optional[datetime.date]:
        """
        Дата первого обнаружения уязвимости.

        - для унаследованных и удаленных уязвимостей берется из предыдущего
          анализа, иначе используется дата выявления baseline;
        - для новых уязвимостей берется из истории (если уязвимость
          уже появлялась ранее), иначе — контрольная дата текущего сравнения.
        """
        baseline = self.baseline_vuln_meta.get(vuln_key)
        if change_type in (ChangeType.UNCHANGED, ChangeType.REMOVED) \
                and baseline and baseline.get('first_seen'):
            return baseline['first_seen']

        history_entry = self.baseline_history['vulnerabilities'].get(vuln_key)
        if history_entry:
            parsed = self._parse_date(history_entry.get('first_seen'))
            if parsed:
                return parsed

        if change_type in (ChangeType.UNCHANGED, ChangeType.REMOVED):
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

    def _vuln_pkg_path(self, vuln: Dict) -> Optional[str]:
        """Путь пакета из записи уязвимости (для docker отсутствует)"""
        return vuln.get('PkgPath') or vuln.get('FilePath') or None

    def _pkg_dir(self, pkg_path: Optional[str]) -> str:
        """Каталог пакета: путь без имени файла (версия меняет только имя файла)"""
        if not pkg_path:
            return ''

        head, sep, _ = pkg_path.rpartition('/')
        return head if sep else ''

    def _build_pkg_key(self, pkg_name: str, pkg_path: str = None) -> Optional[str]:
        """
        Ключ пакета: имя + каталог размещения.

        UID для сравнения отчетов не подходит: он хэшируется от всех полей
        пакета, включая Licenses, поэтому любое изменение метаданных (другой
        версией Trivy) дает новый UID при том же файле. Каталог различает
        одинаковые библиотеки в разных war/jar, а версия остается вне ключа —
        обновление пакета видно по сравнению версий, а не по смене ключа.
        """
        if not pkg_name:
            return None

        directory = self._pkg_dir(pkg_path)
        if directory:
            return f"{pkg_name}|{directory}"

        return pkg_name

    def _build_vuln_key(self, vuln_id: str, pkg_name: str, pkg_path: str = None) -> Optional[str]:
        if not vuln_id or not pkg_name:
            return None

        directory = self._pkg_dir(pkg_path)
        if directory:
            return f"{vuln_id}|{pkg_name}|{directory}"

        return f"{vuln_id}|{pkg_name}"

    def _normalize_history_keys(self, entries: Dict, kind: str) -> Dict:
        """
        Пересобирает ключи истории из полей записей.

        В отчетах прежних версий ключи строились на UID пакета. Поля записи
        (id уязвимости, имя пакета, путь) позволяют восстановить актуальный
        ключ, поэтому накопленная история не теряется.
        """
        normalized = {}

        for key, entry in entries.items():
            if not isinstance(entry, dict):
                continue

            if kind == 'vulnerabilities':
                new_key = self._build_vuln_key(
                    entry.get('vulnerability_id'),
                    entry.get('pkg_name'),
                    entry.get('target')
                )
            else:
                new_key = self._build_pkg_key(
                    entry.get('pkg_name'),
                    entry.get('path')
                )

            normalized[new_key or key] = entry

        return normalized

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
                pkg_path = self._vuln_pkg_path(vuln)

                if not vuln_id or not pkg_name:
                    continue

                vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_path)
                pkg_key = self._build_pkg_key(pkg_name, pkg_path)

                vulns[vuln_key] = vuln

                if pkg_key not in packages:
                    packages[pkg_key] = {
                        'name': pkg_name,
                        'version': pkg_version,
                        'path': pkg_path
                    }
                else:
                    if pkg_version and not packages[pkg_key]['version']:
                        packages[pkg_key]['version'] = pkg_version

        return packages, vulns

    def _extract_packages_by_name(self, report: Dict) -> Dict:
        """
        Извлекает пакеты из секции Packages (для поиска UPDATED).

        Ключ тот же, что и для уязвимостей: пакеты без уязвимостей иначе
        не с чем сопоставить.
        """
        packages = {}

        for result in report.get('Results', []):
            if 'Packages' not in result:
                continue

            for pkg in result['Packages']:
                pkg_name = pkg.get('Name')
                pkg_version = pkg.get('Version')
                pkg_path = pkg.get('FilePath')

                if not pkg_name:
                    continue

                pkg_key = self._build_pkg_key(pkg_name, pkg_path)
                if pkg_key not in packages:
                    packages[pkg_key] = {
                        'name': pkg_name,
                        'version': pkg_version,
                        'path': pkg_path
                    }
                else:
                    if pkg_version:
                        packages[pkg_key]['version'] = pkg_version

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

            # Добавляем пакеты из секции Packages (если их нет в vuln_packages)
            for pkg_key, data in self.packages_by_name1.items():
                if pkg_key not in self.packages1:
                    self.packages1[pkg_key] = data

            for pkg_key, data in self.packages_by_name2.items():
                if pkg_key not in self.packages2:
                    self.packages2[pkg_key] = data

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
                self.package_changes[pkg_key] = ChangeType.REMOVED
            else:
                v1 = self.packages1[pkg_key].get('version')
                v2 = self.packages2[pkg_key].get('version')

                if v1 == v2:
                    self.package_changes[pkg_key] = ChangeType.UNCHANGED
                else:
                    self.package_changes[pkg_key] = ChangeType.UPDATED

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
                    pkg_path = self._vuln_pkg_path(vuln)

                    if vuln_id and pkg_name:
                        vuln_key = self._build_vuln_key(vuln_id, pkg_name, pkg_path)
                        pkg_key = self._build_pkg_key(pkg_name, pkg_path)

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
                        if change_type in (ChangeType.UNCHANGED, ChangeType.NEW):
                            severity = vuln.get('Severity', 'UNKNOWN')
                            has_exploits = self._has_exploits_from_vuln(vuln)
                            first_seen = self._parse_date(vuln.get('_first_seen'))

                            # Дата устранения фиксируется и переносится
                            # из предыдущего анализа без пересчета
                            due_date = self._resolve_due_date(
                                vuln_key, severity, has_exploits, first_seen
                            )
                            remaining_days = self._remaining_from_due_date(due_date)

                            if due_date is not None:
                                vuln['_due_date'] = due_date.isoformat()

                            # Остаток показывается для унаследованных уязвимостей
                            # и для вернувшихся (регрессов): у обычной новой
                            # уязвимости срок отображается как период, а не число дней
                            is_regression = (change_type == ChangeType.NEW
                                             and first_seen != self._resolve_end_date())

                            if remaining_days is not None and (
                                    change_type == ChangeType.UNCHANGED or is_regression):
                                vuln['_remaining_days'] = remaining_days
                                if self.debug:
                                    marker = "🔄" if change_type == ChangeType.UNCHANGED else "➕"
                                    print(f"   {marker} {vuln_id}: remaining_days = {remaining_days}")

        removed_vulns = []
        for vuln_key, change_type in self.vuln_changes.items():
            # Уязвимости, уже помеченные удаленными во втором отчете (diff+diff),
            # повторно как удаления текущего сравнения не учитываются
            if (change_type == ChangeType.REMOVED
                    and vuln_key not in self.report2_removed_keys
                    and vuln_key in self.vulns1):
                vuln_data = deepcopy(self.vulns1[vuln_key])
                vuln_data['_change_type'] = ChangeType.REMOVED.value
                vuln_data['_vuln_key'] = vuln_key

                first_seen = self._resolve_first_seen(vuln_key, ChangeType.REMOVED)
                if first_seen:
                    vuln_data['_first_seen'] = first_seen.isoformat()

                # Проверяем статус пакета
                pkg_name = vuln_data.get('PkgName')
                pkg_key = self._build_pkg_key(pkg_name, self._vuln_pkg_path(vuln_data))

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
            'history': self._build_history(),
            'removed_packages': self._collect_removed_packages()
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

    def _collect_removed_packages(self) -> Dict:
        """
        Собирает пакеты, удаленные в текущем сравнении.

        Отдельной секции в Results для пакетов нет, поэтому данные
        сохраняются в метаданных: следующее сравнение заберет их в историю.
        """
        removed = {}

        for pkg_key, change_type in self.package_changes.items():
            if change_type != ChangeType.REMOVED:
                continue

            pkg_data = self.packages1.get(pkg_key)
            if not pkg_data:
                continue

            removed[pkg_key] = {
                'pkg_name': pkg_data.get('name'),
                'version': pkg_data.get('version'),
                'path': pkg_data.get('path')
            }

        return removed

    def _build_history(self) -> Dict:
        """
        Формирует историю удаленных уязвимостей и пакетов.

        История показывает то, что было удалено ДО текущего сравнения:
        она наследуется из baseline (если это diff-отчет) вместе с удалениями,
        зафиксированными в самом baseline.

        Удаления текущего сравнения в историю не попадают — они уже отражены
        в секции Removed Vulnerabilities и листе SCA REMOVED. При первом
        сравнении (raw+raw) истории нет.
        """
        vuln_history = {
            key: dict(entry)
            for key, entry in self.baseline_history['vulnerabilities'].items()
        }
        pkg_history = {
            key: dict(entry)
            for key, entry in self.baseline_history['packages'].items()
        }

        if not self.baseline_meta:
            return {
                'vulnerabilities': vuln_history,
                'packages': pkg_history
            }

        # Удаления, зафиксированные в предыдущем сравнении
        removed_at = self._resolve_baseline_end_date()
        removed_at_str = removed_at.isoformat() if removed_at else None

        baseline_start = self._resolve_baseline_start_date()
        first_seen_str = baseline_start.isoformat() if baseline_start else None

        for result in self.report1_raw.get('Results', []):
            if not isinstance(result, dict):
                continue
            if result.get('Type') != 'removed' and result.get('Class') != 'removed':
                continue

            for vuln in result.get('Vulnerabilities', []):
                vuln_id = vuln.get('VulnerabilityID')
                pkg_name = vuln.get('PkgName')
                vuln_key = self._build_vuln_key(vuln_id, pkg_name, self._vuln_pkg_path(vuln))
                if not vuln_key:
                    continue

                entry = vuln_history.get(vuln_key)
                if entry is None:
                    # В старых diff-отчетах поля _first_seen нет — используется
                    # дата выявления, зафиксированная в метаданных сравнения
                    vuln_first_seen = vuln.get('_first_seen') or first_seen_str
                    entry = {
                        'vulnerability_id': vuln_id,
                        'pkg_name': pkg_name,
                        'installed_version': vuln.get('InstalledVersion'),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'target': vuln.get('PkgPath') or vuln.get('FilePath'),
                        'first_seen': vuln_first_seen,
                        'removed_count': 0
                    }

                entry['last_removed_at'] = removed_at_str
                entry['removed_count'] = int(entry.get('removed_count') or 0) + 1
                vuln_history[vuln_key] = entry

        for pkg_key, pkg_data in self.baseline_removed_packages.items():
            entry = pkg_history.get(pkg_key)
            if entry is None:
                entry = {
                    'pkg_name': pkg_data.get('pkg_name'),
                    'version': pkg_data.get('version'),
                    'path': pkg_data.get('path'),
                    'first_seen': first_seen_str,
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