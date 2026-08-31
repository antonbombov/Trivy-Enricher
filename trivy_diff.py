#!/usr/bin/env python3
"""
Trivy Diff Analyzer
Поддерживает:
- Docker-образы (идентификация по PkgName)
- JAR-сканирования (идентификация по PkgName + UID)
- Поиск пакетов по имени в секции Packages для определения UPDATED
"""

import json
import sys
import re
import traceback
from pathlib import Path
from typing import Dict, Set, Any, Tuple, Optional
from enum import Enum
from copy import deepcopy
from datetime import datetime


class ChangeType(Enum):
    NEW = "new"
    UNCHANGED = "unchanged"
    UPDATED = "updated"
    REMOVED = "removed"


class TrivyDiffAnalyzer:
    def __init__(self, report1_path: str, report2_path: str, debug: bool = False):
        self.report1_path = report1_path
        self.report2_path = report2_path
        self.debug = debug

        self.report1 = self._load_report(report1_path)
        self.report2 = self._load_report(report2_path)

        self.report_type = self._detect_report_type()

        if self.debug:
            print(f"📋 Detected report type: {self.report_type}")

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
                            vuln['_change_type'] = self.vuln_changes[vuln_key].value
                            vuln['_vuln_key'] = vuln_key

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
                'timestamp': datetime.fromtimestamp(Path(self.report1_path).stat().st_mtime).isoformat()
            },
            'report2': {
                'path': str(self.report2_path),
                'timestamp': datetime.fromtimestamp(Path(self.report2_path).stat().st_mtime).isoformat()
            }
        }

        return diff_report

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
                    vulns.append(vuln_key)

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

        output_file = output_dir / f"{prefix}.json"

        if output_file.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"{prefix}_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(diff_report, f, indent=2, ensure_ascii=False)

        return str(output_file)


def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [--debug]")
            print("  --debug - enable debug output")
            sys.exit(1)

        debug = '--debug' in sys.argv
        args = [arg for arg in sys.argv[1:] if not arg.startswith('--')]

        if len(args) != 2:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [--debug]")
            sys.exit(1)

        print(f"📂 Loading reports:")
        print(f"  Report 1 (старый отчет): {args[0]}")
        print(f"  Report 2 (новый отчет): {args[1]}")
        print()

        analyzer = TrivyDiffAnalyzer(args[0], args[1], debug)
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