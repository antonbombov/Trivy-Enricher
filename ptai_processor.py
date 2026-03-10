# ptai_processor.py
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union


class PTAIParser:
    """
    Парсер для HTML отчетов PTAI
    Извлекает информацию о проекте и уязвимостях
    """

    def __init__(self, html_content: str):
        """
        Инициализация парсера с HTML контентом
        """
        self.html = html_content
        self.project_name = self._extract_project_name()
        self.vulnerabilities = self._extract_vulnerabilities()

    def _extract_project_name(self) -> str:
        """
        Извлекает название проекта из HTML
        """
        match = re.search(
            r'<td class="option-description">Проект</td>\s*<td class="option-value-semibold">\s*([^<]+)\s*</td>',
            self.html)
        return match.group(1).strip() if match else "Unknown"

    def _extract_vulnerabilities(self) -> List[Dict]:
        """
        Извлекает все уязвимости из HTML
        """
        vulns = []

        # Ищем все группы уязвимостей
        groups = re.findall(
            r'<div class="vulnerability-group">(.*?)</div>\s*</div>\s*</div>\s*</div>\s*<div id="glossary"',
            self.html,
            re.DOTALL
        )

        for group in groups:
            # Тип уязвимости из группы
            type_match = re.search(r'<div class="vulnerability-type-name[^"]*">\s*([^<]+)\s*</div>', group)
            vuln_type = type_match.group(1).strip() if type_match else ""

            # Ищем все уязвимости в группе
            vuln_blocks = re.findall(r'<div class="vulnerability-info[^>]*>(.*?)</div>\s*</div>\s*</div>', group,
                                     re.DOTALL)

            for block in vuln_blocks:
                vuln = {
                    'id': '',
                    'type': vuln_type,
                    'file': '',
                    'status': '',
                    'comment': '',
                    'cwe': ''
                }

                # ID
                id_match = re.search(
                    r'<td class="option-description">Идентификатор</td>\s*<td class="option-value">#?([^<]+)</td>',
                    block)
                if id_match:
                    vuln['id'] = id_match.group(1).strip().replace('#', '')

                # Уязвимый файл
                file_match = re.search(
                    r'<td class="option-description">Уязвимый файл</td>\s*<td class="option-value"><pre>([^<]+)</pre></td>',
                    block)
                if file_match:
                    vuln['file'] = file_match.group(1).strip()

                # CWE
                cwe_match = re.search(
                    r'<a target="_blank" href="https://cwe\.mitre\.org/data/definitions/(\d+)\.html">', block)
                if cwe_match:
                    vuln['cwe'] = f"CWE-{cwe_match.group(1)}"

                # Статус
                status_match = re.search(r'<i class="[^"]*-icon" title="([^"]+)"', block)
                if status_match:
                    vuln['status'] = status_match.group(1).strip()

                # Комментарий
                comment_match = re.search(r'<div class="comment">.*?<div style="flex: 1 1 100%">\s*<div>([^<]+)</div>',
                                          block, re.DOTALL)
                if comment_match:
                    vuln['comment'] = comment_match.group(1).strip()

                vulns.append(vuln)

        return vulns

    def get_data_for_excel(self) -> List[Dict]:
        """
        Подготавливает данные для Excel отчета
        """
        result = []
        for v in self.vulnerabilities:
            # Формируем полный тип: CWE + название
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


def prepare_ptai_excel_data(html_file_path: Union[str, Path]) -> Tuple[List[Dict], str]:
    """
    Подготавливает данные из PTAI отчета для Excel

    Args:
        html_file_path: Путь к HTML файлу отчета PTAI

    Returns:
        Tuple[данные для Excel, имя проекта]
    """
    html_file_path = Path(html_file_path)

    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html = f.read()
    except FileNotFoundError:
        print(f"❌ Ошибка: Файл '{html_file_path}' не найден")
        return [], "Unknown"
    except Exception as e:
        print(f"❌ Ошибка при чтении файла: {e}")
        return [], "Unknown"

    parser = PTAIParser(html)

    if not parser.vulnerabilities:
        print(f"   В отчете PTAI не найдено уязвимостей")
    else:
        print(f"   Найдено уязвимостей в PTAI: {len(parser.vulnerabilities)}")

    return parser.get_data_for_excel(), parser.project_name


def find_ptai_report_for_trivy(trivy_file_path: Union[str, Path], ptai_directory: Union[str, Path]) -> Optional[Path]:
    """
    Ищет соответствующий PTAI отчет для Trivy отчета

    Args:
        trivy_file_path: Путь к Trivy отчету
        ptai_directory: Директория с PTAI отчетами

    Returns:
        Path к PTAI отчету или None
    """
    trivy_path = Path(trivy_file_path)
    ptai_dir = Path(ptai_directory)

    if not ptai_dir.exists():
        return None

    # Ищем все HTML файлы
    html_files = list(ptai_dir.glob("*.html"))
    if not html_files:
        return None

    # Получаем базовое имя Trivy отчета (без _enriched и расширения)
    base_name = trivy_path.stem
    base_name = base_name.replace('_enriched', '')

    # Пробуем найти точное совпадение по имени
    for html_file in html_files:
        if base_name in html_file.stem:
            return html_file

    # Если точного совпадения нет, возвращаем первый HTML файл
    return html_files[0]


def get_ptai_stats(html_file_path: Union[str, Path]) -> Dict:
    """
    Возвращает статистику по PTAI отчету

    Args:
        html_file_path: Путь к HTML файлу отчета PTAI

    Returns:
        Словарь со статистикой
    """
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html = f.read()

        parser = PTAIParser(html)

        # Подсчет статусов
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


def main():
    """
    Функция для тестирования
    """
    import sys

    if len(sys.argv) < 2:
        print("Использование: python ptai_processor.py <путь_к_html_файлу>")
        print("Пример: python ptai_processor.py report.html")
        sys.exit(1)

    html_file = sys.argv[1]

    # Подготавливаем данные для Excel
    data, project_name = prepare_ptai_excel_data(html_file)

    print(f"\n📊 Статистика PTAI отчета:")
    print(f"   Проект: {project_name}")
    print(f"   Уязвимостей: {len(data)}")

    if data:
        print(f"\nПервые 3 уязвимости:")
        for i, vuln in enumerate(data[:3], 1):
            print(f"\n   {i}. ID: {vuln['ID уязвимости']}")
            print(f"      Тип: {vuln['Тип уязвимости']}")
            print(f"      Файл: {vuln['Класс и метод / Уязвимый файл']}")
            print(f"      Статус: {vuln['Статус']}")


if __name__ == "__main__":
    main()