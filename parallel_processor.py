# parallel_processor.py
import os
from sploitscan_runner import run_sploitscan
from sploitscan_parser import parse_sploitscan_data

def process_single_cve(args):
    """
    Обрабатывает одну CVE (для параллельной обработки)
    """
    cve_id, target_dir, attempt = args
    result = run_sploitscan(cve_id, target_dir, attempt)  # <-- передаем attempt
    
    if result['status'] == 'success':
        sploit_info = parse_sploitscan_data(result['file'])
        return cve_id, {'status': 'success', 'data': sploit_info, 'execution_time': result['execution_time'], 'attempt': attempt}
    elif result['status'] == 'cached':
        sploit_info = parse_sploitscan_data(result['file'])
        return cve_id, {'status': 'cached', 'data': sploit_info, 'execution_time': result['execution_time'], 'attempt': attempt}
    else:
        return cve_id, {'status': 'failed', 'error': result['error'], 'execution_time': result['execution_time'], 'attempt': attempt}

def calculate_optimal_workers(total_cves):
    """
    Рассчитывает оптимальное количество workers
    """
    cpu_count = os.cpu_count() or 4
    
    if total_cves <= 10:
        workers = min(3, cpu_count)
    elif total_cves <= 30:
        workers = min(5, cpu_count)
    else:
        workers = min(7, cpu_count)
    
    return workers