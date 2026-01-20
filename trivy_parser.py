# trivy_parser.py
import json
from pathlib import Path

def extract_cves_from_trivy(trivy_report_path):
    """
    Извлекает список CVE из отчета Trivy
    """
    try:
        with open(trivy_report_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)
        
        cve_list = set()
        
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
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