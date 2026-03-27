# ptai_processor.py
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union
from lxml import html


class PTAIParser:
    def __init__(self, html_content: str, debug: bool = False):
        self.tree = html.fromstring(html_content)
        self.debug = debug
        self.project_name = self._extract_project_name()
        self.vulnerabilities = self._extract_vulnerabilities()

    def _extract_project_name(self) -> str:
        project_xpath = "//td[contains(@class, 'option-description') and normalize-space(text())='Проект']/following-sibling::td[contains(@class, 'option-value-semibold')]/text()"
        result = self.tree.xpath(project_xpath)
        return result[0].strip() if result else "Unknown"

    def _extract_vulnerabilities(self) -> List[Dict]:
        vulns = []

        # Находим все таблицы с уязвимостями
        root_tables = self.tree.xpath("//table[@class='vulnerability-root-table']")

        if self.debug:
            print(f"   [DEBUG] Найдено таблиц vulnerability-root-table: {len(root_tables)}")

        confirmed_count = 0
        rejected_count = 0

        for tbl in root_tables:
            # Проверяем статус уязвимости
            confirmed = tbl.xpath(".//div[@class='vulnerability-statuses']//i[@title='Подтверждена']")
            rejected = tbl.xpath(".//div[@class='vulnerability-statuses']//i[@title='Опровергнута']")

            status = None
            if confirmed:
                status = 'Подтверждена'
                confirmed_count += 1
            elif rejected:
                status = 'Опровергнута'
                rejected_count += 1
            else:
                # Если нет иконки статуса, пропускаем (как в первой группе)
                continue

            vuln = {
                'id': '',
                'type': '',
                'file': '',
                'status': status,
                'comment': '',
                'cwe': ''
            }

            # ID уязвимости
            vuln_id = tbl.xpath(
                ".//table[@class='vulnerability-detail-info']//tr[td[@class='option-description' and normalize-space(text())='Идентификатор']]/td[@class='option-value']//text()")
            if vuln_id:
                vuln['id'] = ''.join(vuln_id).strip().replace('#', '')

            # Уязвимый файл
            vuln_file = tbl.xpath(
                ".//table[@class='vulnerability-detail-info']//tr[td[@class='option-description' and normalize-space(text())='Уязвимый файл']]/td[@class='option-value']//text()")
            if vuln_file:
                vuln['file'] = ''.join(vuln_file).strip()

            # Тип уязвимости (из родительского vulnerability)
            vuln_type = tbl.xpath(
                ".//ancestor::div[@class='vulnerability'][1]//div[contains(@class,'vulnerability-type-name')][1]/text()")
            if vuln_type:
                vuln['type'] = vuln_type[0].strip()

            # CWE (ищем в ссылке)
            cwe_link = tbl.xpath(".//a[contains(@href, 'cwe.mitre.org')]/text()")
            if cwe_link:
                vuln['cwe'] = cwe_link[0].strip()

            # Комментарий
            vuln_comment = tbl.xpath(".//div[@class='comments-root']//div[@class='comment']/div/div[1]/text()")
            if vuln_comment:
                vuln['comment'] = vuln_comment[0].strip()

            if vuln['id']:
                vulns.append(vuln)

        if self.debug:
            print(f"   [DEBUG] Найдено подтвержденных уязвимостей: {confirmed_count}")
            print(f"   [DEBUG] Найдено опровергнутых уязвимостей: {rejected_count}")

        return vulns

    def get_data_for_excel(self) -> List[Dict]:
        result = []
        for v in self.vulnerabilities:
            full_type = v['type']
            if v['cwe'] and v['type'] and v['cwe'] not in v['type']:
                full_type = f"{v['cwe']} {v['type']}"
            elif v['cwe']:
                full_type = v['cwe']

            result.append({
                'ID уязвимости': v['id'],
                'Тип уязвимости': full_type,
                'Класс и метод / Уязвимый файл': v['file'],
                'Комментарий': v['comment'],
                'Статус': v['status'],
                'CWSS / Vисп': '',
                'Компенсирующие меры': ''
            })
        return result


def prepare_ptai_excel_data(html_file_path: Union[str, Path], debug: bool = True) -> Tuple[List[Dict], str]:
    html_file_path = Path(html_file_path)

    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"❌ Ошибка: Файл '{html_file_path}' не найден")
        return [], "Unknown"
    except Exception as e:
        print(f"❌ Ошибка при чтении файла: {e}")
        return [], "Unknown"

    parser = PTAIParser(html_content, debug=debug)

    if not parser.vulnerabilities:
        print(f"   ⚠️ В отчете PTAI не найдено уязвимостей")
    else:
        confirmed = [v for v in parser.vulnerabilities if v['status'] == 'Подтверждена']
        rejected = [v for v in parser.vulnerabilities if v['status'] == 'Опровергнута']
        print(f"   ✅ Найдено уязвимостей в PTAI: {len(parser.vulnerabilities)}")
        print(f"      - Подтверждено: {len(confirmed)}")
        print(f"      - Опровергнуто: {len(rejected)}")

    return parser.get_data_for_excel(), parser.project_name


def find_ptai_report_for_trivy(trivy_file_path: Union[str, Path], ptai_directory: Union[str, Path]) -> Optional[Path]:
    trivy_path = Path(trivy_file_path)
    ptai_dir = Path(ptai_directory)

    if not ptai_dir.exists():
        return None

    html_files = list(ptai_dir.glob("*.html"))
    if not html_files:
        return None

    base_name = trivy_path.stem.replace('_enriched', '')
    for html_file in html_files:
        if html_file.stem == base_name:
            return html_file

    return None


def get_ptai_stats(html_file_path: Union[str, Path]) -> Dict:
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        parser = PTAIParser(html_content, debug=False)
        status_counts = {}
        for vuln in parser.vulnerabilities:
            status = vuln['status'] or 'Не указан'
            status_counts[status] = status_counts.get(status, 0) + 1
        return {
            'project_name': parser.project_name,
            'total_vulnerabilities': len(parser.vulnerabilities),
            'status_distribution': status_counts,
            'has_data': len(parser.vulnerabilities) > 0
        }
    except Exception as e:
        return {
            'project_name': 'Unknown',
            'total_vulnerabilities': 0,
            'status_distribution': {},
            'has_data': False,
            'error': str(e)
        }