#!/usr/bin/env python3
"""
Trivy Diff Analyzer
Сравнивает два JSON-отчета Trivy и создает diff-отчет с флагами изменений.
"""

import json
import sys
import re
import traceback
from typing import Dict, Set, Any, Tuple, Optional
from enum import Enum
from copy import deepcopy

class ChangeType(Enum):
    """Типы изменений"""
    NEW = "new"
    UNCHANGED = "unchanged"
    UPDATED = "updated"
    REMOVED = "removed"

class VersionComparator:
    """Сравнивает версии пакетов Debian"""
    
    @staticmethod
    def parse_debian_version(version: str) -> dict:
        """Разбирает Debian версию на компоненты"""
        result = {
            'upstream': '',
            'epoch': '',
            'revision': '',
            'debian_ver': 0,
            'debian_rev': 0,
            'suffix_num': 0,
            'components': []
        }
        
        if not version:
            return result
        
        # 1. Извлекаем epoch (если есть)
        if ':' in version:
            epoch, version = version.split(':', 1)
            result['epoch'] = epoch
        
        # 2. Разделяем upstream и revision
        if '-' in version:
            upstream, revision = version.split('-', 1)
            result['upstream'] = upstream
            result['revision'] = revision
        else:
            result['upstream'] = version
            result['revision'] = ''
        
        # 3. Извлекаем Debian ревизию (deb12uX)
        deb_match = re.search(r'deb(\d+)u(\d+)', result['revision'])
        if deb_match:
            result['debian_ver'] = int(deb_match.group(1))
            result['debian_rev'] = int(deb_match.group(2))
        
        # 4. Извлекаем суффикс (uX)
        suffix_match = re.search(r'u(\d+)$', result['revision'])
        if suffix_match:
            result['suffix_num'] = int(suffix_match.group(1))
        
        # 5. Разбираем upstream на компоненты
        for part in result['upstream'].split('.'):
            if part.isdigit():
                result['components'].append(int(part))
        
        return result
    
    @staticmethod
    def compare(v1: str, v2: str) -> int:
        """
        Сравнивает две Debian версии
        Возвращает: 1 если v1 > v2, -1 если v1 < v2, 0 если равны
        """
        p1 = VersionComparator.parse_debian_version(v1)
        p2 = VersionComparator.parse_debian_version(v2)
        
        # 1. Сравниваем upstream по компонентам
        max_len = max(len(p1['components']), len(p2['components']))
        for i in range(max_len):
            c1 = p1['components'][i] if i < len(p1['components']) else 0
            c2 = p2['components'][i] if i < len(p2['components']) else 0
            if c1 != c2:
                return 1 if c1 > c2 else -1
        
        # 2. Сравниваем Debian версию
        if p1.get('debian_ver', 0) != p2.get('debian_ver', 0):
            return 1 if p1['debian_ver'] > p2['debian_ver'] else -1
        
        # 3. Сравниваем Debian ревизию
        if p1.get('debian_rev', 0) != p2.get('debian_rev', 0):
            return 1 if p1['debian_rev'] > p2['debian_rev'] else -1
        
        # 4. Сравниваем суффикс
        if p1.get('suffix_num', 0) != p2.get('suffix_num', 0):
            return 1 if p1['suffix_num'] > p2['suffix_num'] else -1
        
        # 5. Сравниваем полную revision строку
        if p1['revision'] != p2['revision']:
            return 1 if p1['revision'] > p2['revision'] else -1
        
        return 0

class TrivyDiffAnalyzer:
    """Анализирует различия между двумя отчетами Trivy"""
    
    def __init__(self, report1_path: str, report2_path: str, debug: bool = False):
        self.report1_path = report1_path
        self.report2_path = report2_path
        self.debug = debug
        
        self.report1 = self._load_report(report1_path)
        self.report2 = self._load_report(report2_path)
        
        # Хранилища для сравнения
        self.packages1: Dict[str, str] = {}  # имя_пакета -> версия
        self.packages2: Dict[str, str] = {}
        self.vulns1: Dict[str, Dict] = {}    # VulnerabilityID-PkgName -> данные уязвимости
        self.vulns2: Dict[str, Dict] = {}
        
        # Результаты сравнения
        self.package_changes: Dict[str, ChangeType] = {}
        self.vuln_changes: Dict[str, ChangeType] = {}
        
    def _load_report(self, path: str) -> Dict:
        """Загружает JSON-отчет Trivy с поддержкой BOM"""
        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {path}: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _extract_package_name_from_id(self, pkg_id: str) -> str:
        """Извлекает имя пакета из ID"""
        if not pkg_id:
            return None
        return pkg_id.split('@')[0] if '@' in pkg_id else pkg_id
    
    def _extract_package_version_from_id(self, pkg_id: str) -> str:
        """Извлекает версию пакета из ID"""
        if not pkg_id:
            return None
        return pkg_id.split('@')[1] if '@' in pkg_id else pkg_id
    
    def _extract_package_name_from_pkg(self, pkg: Dict) -> str:
        """Извлекает имя пакета из объекта пакета"""
        pkg_name = pkg.get('Name')
        if not pkg_name:
            pkg_id = pkg.get('ID', '')
            if pkg_id:
                pkg_name = pkg_id.split('@')[0] if '@' in pkg_id else pkg_id
        return pkg_name
    
    def _build_vuln_key(self, vuln: Dict) -> str:
        """Строит ключ для уязвимости"""
        vuln_id = vuln.get('VulnerabilityID')
        pkg_name = vuln.get('PkgName')
        
        if not pkg_name:
            pkg_id = vuln.get('PkgID', '')
            if pkg_id:
                pkg_name = pkg_id.split('@')[0] if '@' in pkg_id else pkg_id
        
        if vuln_id and pkg_name:
            return f"{vuln_id}-{pkg_name}"
        return None
    
    def _extract_packages_and_vulns(self, report: Dict, report_name: str) -> Tuple[Dict[str, str], Dict[str, Dict]]:
        """Извлекает пакеты и уязвимости из отчета"""
        packages = {}  # имя_пакета -> версия
        vulns = {}     # VulnerabilityID-PkgName -> данные уязвимости
        
        if self.debug:
            print(f"\n{'='*60}")
            print(f"DEBUG: Extracting from {report_name}")
            print(f"{'='*60}")
        
        for idx, result in enumerate(report.get('Results', [])):
            target = result.get('Target', 'unknown')
            class_type = result.get('Class', 'unknown')
            
            if self.debug:
                print(f"\n  Result #{idx}: Target='{target}', Class='{class_type}'")
            
            # Извлекаем пакеты
            if 'Packages' in result:
                if self.debug:
                    print(f"    Found {len(result['Packages'])} packages")
                for pkg in result['Packages']:
                    pkg_id = pkg.get('ID')
                    if pkg_id:
                        # Извлекаем имя и версию из ID
                        pkg_name = self._extract_package_name_from_id(pkg_id)
                        pkg_version = self._extract_package_version_from_id(pkg_id)
                        
                        if pkg_name:
                            # Сохраняем по имени пакета
                            packages[pkg_name] = pkg_version
                            if self.debug:
                                print(f"      - Package: {pkg_name} ({pkg_version})")
                    else:
                        # Fallback: если ID нет, используем Name
                        pkg_name = pkg.get('Name')
                        if pkg_name:
                            pkg_version = pkg.get('Version', '')
                            packages[pkg_name] = pkg_version
                            if self.debug:
                                print(f"      - Package (fallback): {pkg_name} ({pkg_version})")
            
            # Извлекаем уязвимости
            if 'Vulnerabilities' in result:
                if self.debug:
                    print(f"    Found {len(result['Vulnerabilities'])} vulnerabilities")
                for vuln in result['Vulnerabilities']:
                    vuln_id = vuln.get('VulnerabilityID')
                    pkg_name = vuln.get('PkgName')
                    
                    # Если PkgName отсутствует, пробуем взять из PkgID
                    if not pkg_name:
                        pkg_id = vuln.get('PkgID', '')
                        if pkg_id:
                            pkg_name = self._extract_package_name_from_id(pkg_id)
                    
                    if vuln_id and pkg_name:
                        vuln_key = f"{vuln_id}-{pkg_name}"
                        vulns[vuln_key] = vuln
                        if self.debug:
                            print(f"      - Added vulnerability: {vuln_key}")
                    else:
                        if self.debug:
                            print(f"      - Skipped: vuln_id={vuln_id}, pkg_name={pkg_name}")
        
        if self.debug:
            print(f"\n  Extracted {len(packages)} packages, {len(vulns)} vulnerabilities")
        
        return packages, vulns
    
    def analyze(self):
        """Выполняет анализ различий"""
        print("🔍 Extracting packages and vulnerabilities...")
        
        # Извлекаем данные из отчетов
        self.packages1, self.vulns1 = self._extract_packages_and_vulns(self.report1, self.report1_path)
        self.packages2, self.vulns2 = self._extract_packages_and_vulns(self.report2, self.report2_path)
        
        if self.debug:
            print(f"\n{'='*60}")
            print(f"DEBUG: Package Comparison")
            print(f"{'='*60}")
            print(f"Packages in report1: {len(self.packages1)}")
            print(f"Packages in report2: {len(self.packages2)}")
        
        print("📦 Comparing packages...")
        
        # Сравниваем пакеты по ИМЕНИ
        all_package_names = set(self.packages1.keys()) | set(self.packages2.keys())
        
        for pkg_name in all_package_names:
            if pkg_name not in self.packages1:
                self.package_changes[pkg_name] = ChangeType.NEW
            elif pkg_name not in self.packages2:
                self.package_changes[pkg_name] = ChangeType.REMOVED
            else:
                # Пакет есть в обоих отчетах - сравниваем версии
                v1 = self.packages1[pkg_name]
                v2 = self.packages2[pkg_name]
                
                if v1 == v2:
                    self.package_changes[pkg_name] = ChangeType.UNCHANGED
                else:
                    # Сравниваем версии семантически
                    cmp = VersionComparator.compare(v1, v2)
                    if cmp < 0:
                        # v1 < v2 -> версия увеличилась
                        self.package_changes[pkg_name] = ChangeType.UPDATED
                    else:
                        # v1 > v2 -> версия уменьшилась
                        self.package_changes[pkg_name] = ChangeType.UPDATED
        
        print("🔒 Comparing vulnerabilities...")
        
        # Сравниваем уязвимости
        all_vulns = set(self.vulns1.keys()) | set(self.vulns2.keys())
        
        for vuln_key in all_vulns:
            # Извлекаем имя пакета из ключа уязвимости
            pkg_name = vuln_key.split('-', 1)[1] if '-' in vuln_key else None
            
            if vuln_key not in self.vulns1:
                self.vuln_changes[vuln_key] = ChangeType.NEW
            elif vuln_key not in self.vulns2:
                # Уязвимость исчезла
                if pkg_name and pkg_name in self.package_changes:
                    pkg_status = self.package_changes[pkg_name]
                    # Если пакет обновлен или удален, уязвимость считается исправленной
                    if pkg_status in [ChangeType.UPDATED, ChangeType.REMOVED]:
                        self.vuln_changes[vuln_key] = ChangeType.REMOVED
                    else:
                        self.vuln_changes[vuln_key] = ChangeType.REMOVED
                else:
                    self.vuln_changes[vuln_key] = ChangeType.REMOVED
            else:
                self.vuln_changes[vuln_key] = ChangeType.UNCHANGED
        
        print("✅ Analysis complete!")
    
    def _calculate_package_stats(self) -> Dict[str, int]:
        """Подсчитывает статистику по пакетам (по всем записям, включая дубликаты)"""
        stats = {
            'new': 0,
            'unchanged': 0,
            'updated': 0,
            'removed': 0
        }
        
        # NEW - только из второго отчета
        for result in self.report2.get('Results', []):
            if 'Packages' in result:
                for pkg in result['Packages']:
                    pkg_name = self._extract_package_name_from_pkg(pkg)
                    if pkg_name in self.package_changes:
                        change = self.package_changes[pkg_name]
                        if change == ChangeType.NEW:
                            stats['new'] += 1
        
        # REMOVED - только из первого отчета
        for result in self.report1.get('Results', []):
            if 'Packages' in result:
                for pkg in result['Packages']:
                    pkg_name = self._extract_package_name_from_pkg(pkg)
                    if pkg_name in self.package_changes:
                        change = self.package_changes[pkg_name]
                        if change == ChangeType.REMOVED:
                            stats['removed'] += 1
        
        # UPDATED - только из второго отчета
        for result in self.report2.get('Results', []):
            if 'Packages' in result:
                for pkg in result['Packages']:
                    pkg_name = self._extract_package_name_from_pkg(pkg)
                    if pkg_name in self.package_changes:
                        change = self.package_changes[pkg_name]
                        if change == ChangeType.UPDATED:
                            stats['updated'] += 1
        
        # UNCHANGED - только из второго отчета
        for result in self.report2.get('Results', []):
            if 'Packages' in result:
                for pkg in result['Packages']:
                    pkg_name = self._extract_package_name_from_pkg(pkg)
                    if pkg_name in self.package_changes:
                        change = self.package_changes[pkg_name]
                        if change == ChangeType.UNCHANGED:
                            stats['unchanged'] += 1
        
        return stats
    
    def _calculate_vuln_stats(self) -> Dict[str, int]:
        """Подсчитывает статистику по уязвимостям (по всем записям, включая дубликаты)"""
        stats = {
            'new': 0,
            'unchanged': 0,
            'removed': 0
        }
        
        # NEW - только из второго отчета
        for result in self.report2.get('Results', []):
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln_key = self._build_vuln_key(vuln)
                    if vuln_key and vuln_key in self.vuln_changes:
                        change = self.vuln_changes[vuln_key]
                        if change == ChangeType.NEW:
                            stats['new'] += 1
        
        # REMOVED - только из первого отчета
        for result in self.report1.get('Results', []):
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln_key = self._build_vuln_key(vuln)
                    if vuln_key and vuln_key in self.vuln_changes:
                        change = self.vuln_changes[vuln_key]
                        if change == ChangeType.REMOVED:
                            stats['removed'] += 1
        
        # UNCHANGED - только из второго отчета
        for result in self.report2.get('Results', []):
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln_key = self._build_vuln_key(vuln)
                    if vuln_key and vuln_key in self.vuln_changes:
                        change = self.vuln_changes[vuln_key]
                        if change == ChangeType.UNCHANGED:
                            stats['unchanged'] += 1
        
        return stats
    
    def build_diff_report(self) -> Dict:
        """Строит diff-отчет с корректной статистикой (по всем записям)"""
        print("📝 Building diff report...")
        
        # Делаем глубокую копию второго отчета
        diff_report = deepcopy(self.report2)
        
        # Проходим по всем результатам во втором отчете
        for result in diff_report.get('Results', []):
            # Добавляем флаги для пакетов
            if 'Packages' in result:
                for pkg in result['Packages']:
                    pkg_name = self._extract_package_name_from_pkg(pkg)
                    if pkg_name in self.package_changes:
                        pkg['_change_type'] = self.package_changes[pkg_name].value
            
            # Добавляем флаги для уязвимостей
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vuln_key = self._build_vuln_key(vuln)
                    if vuln_key and vuln_key in self.vuln_changes:
                        vuln['_change_type'] = self.vuln_changes[vuln_key].value
                    
                    pkg_name = vuln.get('PkgName')
                    if not pkg_name:
                        pkg_id = vuln.get('PkgID', '')
                        if pkg_id:
                            pkg_name = pkg_id.split('@')[0] if '@' in pkg_id else pkg_id
                    if pkg_name and pkg_name in self.package_changes:
                        vuln['_package_change_type'] = self.package_changes[pkg_name].value
        
        # Добавляем REMOVED уязвимости
        removed_vulns = []
        for vuln_key, change_type in self.vuln_changes.items():
            if change_type == ChangeType.REMOVED and vuln_key in self.vulns1:
                vuln_data = deepcopy(self.vulns1[vuln_key])
                vuln_data['_change_type'] = ChangeType.REMOVED.value
                
                pkg_name = vuln_data.get('PkgName')
                if not pkg_name:
                    pkg_id = vuln_data.get('PkgID', '')
                    if pkg_id:
                        pkg_name = pkg_id.split('@')[0] if '@' in pkg_id else pkg_id
                
                if pkg_name and pkg_name in self.package_changes:
                    vuln_data['_package_change_type'] = self.package_changes[pkg_name].value
                
                removed_vulns.append(vuln_data)
        
        if removed_vulns:
            removed_result = None
            for result in diff_report.get('Results', []):
                if result.get('Target') == 'Removed Vulnerabilities':
                    removed_result = result
                    break
            
            if not removed_result:
                removed_result = {
                    "Target": "Removed Vulnerabilities",
                    "Class": "removed",
                    "Type": "removed",
                    "Vulnerabilities": []
                }
                diff_report['Results'].append(removed_result)
            
            removed_result['Vulnerabilities'] = removed_vulns
        
        # Добавляем метаданные со статистикой (ПО ВСЕМ ЗАПИСЯМ!)
        diff_report['_diff_metadata'] = {
            'packages': self._calculate_package_stats(),
            'vulnerabilities': self._calculate_vuln_stats()
        }
        
        return diff_report
    
    def print_summary(self):
        """Выводит сводку изменений (с подсчетом всех записей, включая дубликаты)"""
        print("\n" + "="*60)
        print("TRIVY DIFF ANALYSIS SUMMARY")
        print("="*60)
        
        # Получаем статистику
        pkg_stats = self._calculate_package_stats()
        vuln_stats = self._calculate_vuln_stats()
        
        print("\n📦 PACKAGES:")
        for change_type in ChangeType:
            count = pkg_stats[change_type.value]
            emoji = {
                ChangeType.NEW: "➕",
                ChangeType.UNCHANGED: "➖",
                ChangeType.UPDATED: "🔄",
                ChangeType.REMOVED: "❌"
            }.get(change_type, "•")
            print(f"  {emoji} {change_type.value.upper()}: {count}")
            
            # Показываем список пакетов
            packages = []
            if change_type == ChangeType.NEW:
                for result in self.report2.get('Results', []):
                    if 'Packages' in result:
                        for pkg in result['Packages']:
                            pkg_name = self._extract_package_name_from_pkg(pkg)
                            if pkg_name in self.package_changes and self.package_changes[pkg_name] == ChangeType.NEW:
                                version = pkg.get('Version', '')
                                packages.append(f"{pkg_name} ({version})")
            elif change_type == ChangeType.REMOVED:
                for result in self.report1.get('Results', []):
                    if 'Packages' in result:
                        for pkg in result['Packages']:
                            pkg_name = self._extract_package_name_from_pkg(pkg)
                            if pkg_name in self.package_changes and self.package_changes[pkg_name] == ChangeType.REMOVED:
                                version = pkg.get('Version', '')
                                packages.append(f"{pkg_name} ({version})")
            else:
                for result in self.report2.get('Results', []):
                    if 'Packages' in result:
                        for pkg in result['Packages']:
                            pkg_name = self._extract_package_name_from_pkg(pkg)
                            if pkg_name in self.package_changes and self.package_changes[pkg_name] == change_type:
                                version = pkg.get('Version', '')
                                packages.append(f"{pkg_name} ({version})")
            
            if packages and len(packages) <= 10:
                for pkg in packages:
                    print(f"     - {pkg}")
            elif packages and len(packages) > 10:
                for pkg in packages[:5]:
                    print(f"     - {pkg}")
                print(f"     ... and {len(packages) - 5} more")
        
        print("\n🔒 VULNERABILITIES:")
        for change_type in [ChangeType.NEW, ChangeType.UNCHANGED, ChangeType.REMOVED]:
            count = vuln_stats[change_type.value]
            emoji = {
                ChangeType.NEW: "⚠️",
                ChangeType.UNCHANGED: "➖",
                ChangeType.REMOVED: "✅"
            }.get(change_type, "•")
            print(f"  {emoji} {change_type.value.upper()}: {count}")
        
        # Проверка: сумма должна соответствовать общему количеству
        total_vulns = vuln_stats['new'] + vuln_stats['unchanged'] + vuln_stats['removed']
        print(f"\n  📊 TOTAL vulnerabilities in diff: {total_vulns}")
        
        print("\n" + "="*60)

def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [--debug]")
            print("  report1.json - baseline scan")
            print("  report2.json - new scan")
            print("  --debug - enable debug output")
            sys.exit(1)
        
        # Парсим аргументы
        debug = False
        args = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
        if len(sys.argv) > 3 and '--debug' in sys.argv:
            debug = True
        
        if len(args) != 2:
            print("Usage: python trivy_diff.py <report1.json> <report2.json> [--debug]")
            sys.exit(1)
        
        report1_path = args[0]
        report2_path = args[1]
        
        print(f"📂 Loading reports:")
        print(f"  Report 1 (baseline): {report1_path}")
        print(f"  Report 2 (new): {report2_path}")
        print()
        
        analyzer = TrivyDiffAnalyzer(report1_path, report2_path, debug)
        analyzer.analyze()
        analyzer.print_summary()
        
        diff_report = analyzer.build_diff_report()
        
        # Сохраняем diff-отчет в файл
        output_file = "trivy_diff_output.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(diff_report, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Diff report saved to: {output_file}")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()