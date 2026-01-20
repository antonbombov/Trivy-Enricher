# enrichment_core.py
import json
import os
import shutil
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from config_manager import load_config
from trivy_parser import extract_cves_from_trivy
from sploitscan_runner import find_existing_json
from sploitscan_parser import parse_sploitscan_data
from parallel_processor import process_single_cve, calculate_optimal_workers


def enrich_trivy_report(trivy_report_path, output_dir=None):
    """
    Обогащает отчет Trivy с параллельной обработкой и кэшированием
    output_dir — путь к папке для сохранения итоговых отчетов
    """
    # Загружаем конфиг из config.json
    config = load_config()
    cache_dir = Path(config.get("cache_directory"))

    # Если путь не передан — используем значение из config
    if output_dir is None:
        output_dir = Path(config.get("output_directory", "Results"))
    else:
        output_dir = Path(output_dir)

    # Создаем output директорию, если её нет
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with open(trivy_report_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)
        print(f"Обработка отчета: {trivy_report_path}")

        # Собираем CVE
        cve_list = extract_cves_from_trivy(trivy_report_path)
        total_cves = len(cve_list)

        # АВТОМАТИЧЕСКИЙ РАСЧЕТ WORKERS
        max_workers = calculate_optimal_workers(total_cves)

        # ПРОВЕРЯЕМ КЭШ ПЕРЕД ОБРАБОТКОЙ
        cached_cves = []
        uncached_cves = []
        for cve_id in cve_list:
            if find_existing_json(cve_id, cache_dir):
                cached_cves.append(cve_id)
            else:
                uncached_cves.append(cve_id)

        print(f"Найдено {total_cves} CVE")
        print(f"  [CACHE] В кэше: {len(cached_cves)} CVE")
        print(f"  [SCAN]  Требуют сканирования: {len(uncached_cves)} CVE")
        print(f"Кэш sploitscan: {cache_dir}")
        print(f"Результаты сохраняются в: {output_dir}")  # Информация о output директории
        print(f"Параллельных workers: {max_workers}")
        print(f"Процессоров в системе: {os.cpu_count()}")
        print("=" * 60)

        # ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА С КЭШИРОВАНИЕМ
        sploitscan_results = {}
        failed_cves = set()
        stats = {'cached': len(cached_cves), 'success': 0, 'failed': 0, 'retry_success': 0}

        # Сначала добавляем закэшированные CVE
        for cve_id in cached_cves:
            json_file = find_existing_json(cve_id, cache_dir)
            sploit_info = parse_sploitscan_data(json_file)
            sploitscan_results[cve_id] = sploit_info
            print(f"[CACHE] {cve_id} УСПЕХ (из кэша)")

        # Обрабатываем только те CVE, которых нет в кэше
        if uncached_cves:
            # Первая попытка
            print(f"\n[SCAN] Сканирование {len(uncached_cves)} CVE...")
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                tasks = [(cve_id, cache_dir, 1) for cve_id in uncached_cves]
                future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
                completed = 0
                for future in as_completed(future_to_cve):
                    cve_id, result = future.result()
                    completed += 1
                    if result['status'] == 'success':
                        sploitscan_results[cve_id] = result['data']
                        stats['success'] += 1
                        print(f"[{completed}/{len(uncached_cves)}] {cve_id} УСПЕХ ({result['execution_time']:.1f}с)")
                    elif result['status'] == 'cached':
                        sploitscan_results[cve_id] = result['data']
                        stats['cached'] += 1
                        print(
                            f"[{completed}/{len(uncached_cves)}] {cve_id} УСПЕХ КЭШ ({result['execution_time']:.1f}с)")
                    else:
                        failed_cves.add(cve_id)
                        stats['failed'] += 1
                        print(f"[{completed}/{len(uncached_cves)}] {cve_id} ОШИБКА ({result['execution_time']:.1f}с)")

            # Вторая попытка для неудавшихся CVE
            if failed_cves:
                print(f"\n[RETRY] Повторная попытка для {len(failed_cves)} CVE...")
                retry_cves = list(failed_cves)
                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    tasks = [(cve_id, cache_dir, 2) for cve_id in retry_cves]
                    future_to_cve = {executor.submit(process_single_cve, task): task for task in tasks}
                    completed_retry = 0
                    for future in as_completed(future_to_cve):
                        cve_id, result = future.result()
                        completed_retry += 1
                        if result['status'] == 'success':
                            sploitscan_results[cve_id] = result['data']
                            failed_cves.remove(cve_id)
                            stats['retry_success'] += 1
                            print(
                                f"[{completed_retry}/{len(retry_cves)}] {cve_id} УСПЕХ ПОВТОР ({result['execution_time']:.1f}с)")
                        else:
                            print(
                                f"[{completed_retry}/{len(retry_cves)}] {cve_id} ОШИБКА ПОВТОР ({result['execution_time']:.1f}с)")

        print("=" * 60)
        print("СТАТИСТИКА ОБРАБОТКИ:")
        print(f"  Из кэша:               {stats['cached']}")
        print(f"  Успешно с первой попытки: {stats['success']}")
        print(f"  Успешно после повтора:    {stats['retry_success']}")
        print(f"  Всего успешно:           {stats['cached'] + stats['success'] + stats['retry_success']}/{total_cves}")
        print(f"  Осталось ошибок:         {len(failed_cves)}")

        # Добавляем значения по умолчанию для оставшихся ошибок
        for cve_id in failed_cves:
            sploitscan_results[cve_id] = {
                "error": "Не удалось получить данные после 2 попыток"
            }

        # Обогащаем отчет
        enriched_count = 0
        if 'Results' in trivy_data:
            for result in trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        cve_id = vuln.get('VulnerabilityID')
                        if cve_id in sploitscan_results:
                            vuln['sploitscan'] = sploitscan_results[cve_id]
                            enriched_count += 1

        # Сохраняем обогащенный отчет в output_directory
        output_path = output_dir / f"{trivy_report_path.stem}_enriched.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(trivy_data, f, indent=2, ensure_ascii=False)

        # Показываем созданные файлы
        json_files = list(cache_dir.glob("*.json"))
        print(f"ФАЙЛОВ В КЭШЕ: {len(json_files)}")
        print(f"ОБОГАЩЕНО УЯЗВИМОСТЕЙ: {enriched_count}")
        print(f"РЕЗУЛЬТАТ: {output_path}")
        return output_path

    except Exception as e:
        print(f"ОШИБКА: {e}")
        return None