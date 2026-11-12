# trivy_parser.py
import json


def is_removed_section(result):
    """
    Проверяет, что секция Results содержит ранее удаленные уязвимости.

    Такие секции не участвуют в анализе: они лишь сохраняют историю
    предыдущего сравнения.
    """
    return result.get('Type') == 'removed' or result.get('Class') == 'removed'


def extract_cves_from_trivy(trivy_report_path):
    """
    Извлекает список CVE из отчета Trivy

    Секции удаленных уязвимостей (removed) пропускаются: их обогащение
    не используется при построении отчетов, а с ростом истории только
    увеличивает время сканирования. История в _diff_metadata также
    не содержит объектов уязвимостей и в выборку не попадает.
    """
    try:
        with open(trivy_report_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)

        cve_list = set()

        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if is_removed_section(result):
                    continue
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        if 'VulnerabilityID' in vuln:
                            cve_id = vuln['VulnerabilityID']
                            if cve_id.startswith('CVE-'):
                                cve_list.add(cve_id)

        return sorted(list(cve_list))

    except Exception as e:
        print(f"ОШИБКА ПАРСИНГА TRIVY ОТЧЕТА {trivy_report_path}: {e}")
        return []
