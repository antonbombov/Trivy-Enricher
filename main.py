# main.py
import argparse
import sys
import time
from pathlib import Path
from enrichment_core import enrich_trivy_report
from trivy_html_reporter import generate_trivy_html_report
from excel_reporter import generate_excel_report
from config_manager import load_config, setup_directories, find_ptai_report_for_trivy
from cache_cleaner import cleanup_old_cache, get_cache_stats
from cdn_cache_manager import get_cdn_cache_stats


def parse_arguments():
    """
    Парсинг аргументов командной строки
    """
    parser = argparse.ArgumentParser(
        description='Trivy Enricher - обогащение отчетов Trivy данными SploitScan',
        usage='python main.py [-h] [-html] [-excel]'
    )
    parser.add_argument('-html', action='store_true',
                        help='Генерировать HTML отчет')
    parser.add_argument('-excel', action='store_true',
                        help='Генерировать Excel отчет (SCA + PTAI анализы)')

    args = parser.parse_args()

    # Если аргументы не указаны - показываем help
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    return args


def cleanup_logs(output_dir):
    """
    Очищает папку с логами перед запуском
    """
    log_dir = output_dir / "logs"

    if log_dir.exists():
        try:
            for log_file in log_dir.glob("*.log"):
                try:
                    log_file.unlink()
                    print(f"Удален лог: {log_file.name}")
                except Exception as e:
                    print(f"Не удалось удалить {log_file.name}: {e}")
        except Exception as e:
            print(f"Ошибка при очистке логов: {e}")
    else:
        print(f"Папка логов не существует, создадим при необходимости: {log_dir}")


def generate_html_report(enriched_file, output_dir, cache_dir):
    """
    Генерирует HTML отчет
    """
    print(f"\nГенерация HTML отчета...")
    html_start_time = time.time()

    html_file = generate_trivy_html_report(
        enriched_file,
        output_dir,
        cache_dir
    )
    html_time = time.time() - html_start_time

    if html_file:
        print(f"HTML отчет создан за {html_time:.1f}с: {html_file}")
    else:
        print(f"Ошибка создания HTML отчета")

    return html_file


def generate_excel(enriched_file, output_dir, config):
    """
    Генерирует Excel отчет с возможным добавлением PTAI листа
    """
    print(f"\nГенерация Excel отчета...")
    excel_start_time = time.time()

    # Ищем соответствующий PTAI отчет
    ptai_report = find_ptai_report_for_trivy(enriched_file, config)
    if ptai_report:
        print(f"Найден PTAI отчет: {ptai_report.name}")
    else:
        print("PTAI отчет не найден, будет создан только лист SCA Анализ")

    excel_file = generate_excel_report(
        enriched_file,
        output_dir,
        ptai_report
    )
    excel_time = time.time() - excel_start_time

    if excel_file:
        print(f"Excel отчет создан за {excel_time:.1f}с: {excel_file}")
        if ptai_report:
            print(f"  - Добавлен лист PTAI Анализ из: {ptai_report.name}")
    else:
        print(f"Ошибка создания Excel отчета")

    return excel_file


def process_reports(trivy_files, args, config, output_dir, cache_dir):
    """
    Обрабатывает найденные отчеты согласно аргументам
    """
    processed_count = 0
    html_count = 0
    excel_count = 0

    for trivy_file in trivy_files:
        print(f"\n{'=' * 60}")
        print(f"ОБРАБОТКА: {trivy_file.name}")
        print(f"{'=' * 60}")

        # Обогащаем отчет
        start_time = time.time()
        enriched_file = enrich_trivy_report(trivy_file, output_dir)
        total_time = time.time() - start_time

        if not enriched_file:
            print(f"❌ ОШИБКА обогащения отчета {trivy_file.name}")
            continue

        print(f"✅ УСПЕШНО ЗА {total_time:.1f}с")
        print(f"📄 Обогащенный JSON: {enriched_file.name}")
        processed_count += 1

        # HTML отчет по запросу
        if args.html:
            if generate_html_report(enriched_file, output_dir, cache_dir):
                html_count += 1

        # Excel отчет по запросу
        if args.excel:
            if generate_excel(enriched_file, output_dir, config):
                excel_count += 1

    return processed_count, html_count, excel_count


def main():
    """
    Основная функция программы
    """
    # Парсим аргументы командной строки
    args = parse_arguments()

    # Загружаем конфигурацию
    config = load_config()
    scan_dir, cache_dir, output_dir = setup_directories(config)

    # Очищаем логи перед запуском
    print("=" * 60)
    print("TRIVY ENRICHER - ОБОГАЩЕНИЕ ОТЧЕТОВ TRIVY")
    print("=" * 60)
    print(f"Режимы работы:")
    if args.html:
        print("  ✅ HTML отчеты - ВКЛЮЧЕНЫ")
    if args.excel:
        print("  ✅ Excel отчеты - ВКЛЮЧЕНЫ")
    print("=" * 60)

    # Показываем статистику кэша SploitScan
    sploitscan_stats = get_cache_stats()
    print(f"\n📊 Статистика кэша:")
    print(
        f"   SploitScan: {sploitscan_stats['total_files']} файлов (макс. возраст: {sploitscan_stats['max_age_days']} дней)")

    # Показываем статистику кэша CDN
    cdn_stats = get_cdn_cache_stats(cache_dir)
    if cdn_stats['tailwind_cached']:
        print(f"   CDN: Tailwind JS {cdn_stats.get('tailwind_size', 0)} байт")
    else:
        print(f"   CDN: пуст (будет загружен при первом отчете)")

    # Автоматическая очистка старых файлов в кэше
    deleted_count = cleanup_old_cache()
    if deleted_count > 0:
        print(f"   Удалено старых файлов: {deleted_count}")

    print(f"\n🧹 Очистка старых логов...")
    cleanup_logs(output_dir)
    print("   Очистка логов завершена")

    print(f"\n📁 Директории:")
    print(f"   Входные отчеты: {scan_dir}")
    print(f"   Кэш SploitScan: {cache_dir}")
    print(f"   Кэш CDN: {cache_dir / 'cdn'}")
    print(f"   Результаты: {output_dir}")
    print(f"   Логи SploitScan: {output_dir / 'logs'}")

    # Ищем отчеты в указанной папке scan_dir
    trivy_files = list(scan_dir.glob("*.json"))

    # Исключаем config.json и уже обогащенные отчеты
    trivy_files = [
        f for f in trivy_files
        if not f.name.endswith('_enriched.json')
           and f.name != 'config.json'
    ]

    if not trivy_files:
        print(f"\n❌ Нет отчетов Trivy в папке: {scan_dir}")
        print("   Поместите JSON отчеты Trivy в указанную папку")
        return

    print(f"\n📄 Найдено отчетов Trivy: {len(trivy_files)}")

    # Обрабатываем отчеты
    total_start_time = time.time()
    processed, html_created, excel_created = process_reports(
        trivy_files, args, config, output_dir, cache_dir
    )
    total_time = time.time() - total_start_time

    # Итоговая статистика
    print(f"\n{'=' * 60}")
    print("ИТОГОВАЯ СТАТИСТИКА")
    print(f"{'=' * 60}")
    print(f"✅ Обработано отчетов: {processed}")
    if args.html:
        print(f"📊 Создано HTML отчетов: {html_created}")
    if args.excel:
        print(f"📈 Создано Excel отчетов: {excel_created}")
    print(f"⏱️ Общее время выполнения: {total_time:.1f}с")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()