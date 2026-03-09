import re
from typing import List, Dict


class PTAIParser:
    def __init__(self, html_content: str):
        self.html = html_content
        self.project_name = self._extract_project_name()
        self.vulnerabilities = self._extract_vulnerabilities()

    def _extract_project_name(self) -> str:
        match = re.search(
            r'<td class="option-description">Проект</td>\s*<td class="option-value-semibold">\s*([^<]+)\s*</td>',
            self.html)
        return match.group(1).strip() if match else "Unknown"

    def _extract_vulnerabilities(self) -> List[Dict]:
        vulns = []

        # Ищем все группы уязвимостей
        groups = re.findall(
            r'<div class="vulnerability-group">(.*?)</div>\s*</div>\s*</div>\s*</div>\s*<div id="glossary"', self.html,
            re.DOTALL)

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