# main.py
import sys
import time
from pathlib import Path
from enrichment_core import enrich_trivy_report
from trivy_html_reporter import generate_trivy_html_report
from excel_reporter import generate_excel_report
from config_manager import load_config, setup_directories, find_ptai_report_for_trivy
from cache_cleaner import cleanup_old_cache, get_cache_stats
from cdn_cache_manager import get_cdn_cache_stats
from argument_parser import parse_arguments, get_report_types


def print_banner():
    """
    Выводит ASCII-арт баннер при запуске
    """
    banner = r"""
██╗   ██╗██╗██████╗ ███████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
██║   ██║██║██╔══██╗██╔════╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██████╔╝███████╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
  ╚═══╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    """
    print(banner)
    print("=" * 70)
    print("VIBECHECKER - Trivy Enricher with SploitScan")
    print("=" * 70)


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
    generate_html, generate_excel_flag, skip_enrich, only_cache = get_report_types(args)
    processed_count = 0
    html_count = 0
    excel_count = 0

    for trivy_file in trivy_files:
        print(f"\n{'=' * 60}")
        print(f"ОБРАБОТКА: {trivy_file.name}")
        print(f"{'=' * 60}")

        # Определяем файл для отчетов
        if skip_enrich:
            print("⚡ Режим: БЕЗ обогащения SploitScan (используется исходный отчет)")
            report_file = trivy_file
        elif only_cache:
            print("💾 Режим: ТОЛЬКО КЭШ (используются только закэшированные CVE)")
            start_time = time.time()
            report_file = enrich_trivy_report(trivy_file, output_dir, only_cache=True)
            total_time = time.time() - start_time

            if not report_file:
                print(f"❌ ОШИБКА обогащения отчета {trivy_file.name}")
                continue

            print(f"✅ Обогащение из кэша выполнено за {total_time:.1f}с")
            print(f"📄 Обогащенный JSON (только кэш): {report_file.name}")
        else:
            print("🔄 Режим: С обогащением SploitScan")
            start_time = time.time()
            report_file = enrich_trivy_report(trivy_file, output_dir, only_cache=False)
            total_time = time.time() - start_time

            if not report_file:
                print(f"❌ ОШИБКА обогащения отчета {trivy_file.name}")
                continue

            print(f"✅ Обогащение выполнено за {total_time:.1f}с")
            print(f"📄 Обогащенный JSON: {report_file.name}")

        processed_count += 1

        # HTML отчет по запросу
        if generate_html:
            if generate_html_report(report_file, output_dir, cache_dir):
                html_count += 1

        # Excel отчет по запросу
        if generate_excel_flag:
            if generate_excel(report_file, output_dir, config):
                excel_count += 1

    return processed_count, html_count, excel_count


def main():
    """
    Основная функция программы
    """
    # Выводим баннер
    print_banner()

    # Парсим аргументы командной строки
    args = parse_arguments()
    generate_html, generate_excel_flag, skip_enrich, only_cache = get_report_types(args)

    # Загружаем конфигурацию
    config = load_config()
    scan_dir, cache_dir, output_dir = setup_directories(config)

    print(f"\n📋 Режимы работы:")
    print(f"   HTML отчеты: {'✅ ВКЛЮЧЕНЫ' if generate_html else '❌ ОТКЛЮЧЕНЫ'}")
    print(f"   Excel отчеты: {'✅ ВКЛЮЧЕНЫ' if generate_excel_flag else '❌ ОТКЛЮЧЕНЫ'}")
    if skip_enrich:
        print(f"   ⚡ Обогащение SploitScan: ОТКЛЮЧЕНО (используются исходные отчеты)")
    elif only_cache:
        print(f"   💾 Обогащение SploitScan: ТОЛЬКО КЭШ (без вызова SploitScan)")
    else:
        print(f"   🔄 Обогащение SploitScan: ВКЛЮЧЕНО (с вызовом SploitScan)")
    print("=" * 70)

    # Показываем статистику кэша (только если нужно обогащение или только кэш)
    if not skip_enrich:
        sploitscan_stats = get_cache_stats()
        print(f"\n📊 Статистика кэша:")
        print(
            f"   SploitScan: {sploitscan_stats['total_files']} файлов (макс. возраст: {sploitscan_stats['max_age_days']} дней)")

        cdn_stats = get_cdn_cache_stats(cache_dir)
        if cdn_stats['tailwind_cached']:
            print(f"   CDN: Tailwind JS {cdn_stats.get('tailwind_size', 0)} байт")
        else:
            print(f"   CDN: пуст (будет загружен при первом отчете)")

        # Очистка кэша нужна только если мы не в режиме only_cache (или если только_cache, но всё равно можно очистить)
        deleted_count = cleanup_old_cache()
        if deleted_count > 0:
            print(f"   🧹 Удалено старых файлов из кэша: {deleted_count}")

        # Очищаем логи только если не в режиме only_cache (там нет вызовов SploitScan)
        if not only_cache:
            print(f"\n🧹 Очистка старых логов...")
            cleanup_logs(output_dir)
            print("   Очистка логов завершена")
        else:
            print(f"\n💾 Режим only-cache: очистка логов пропущена (вызовы SploitScan не производятся)")

    print(f"\n📁 Директории:")
    print(f"   📂 Входные отчеты: {scan_dir}")
    if not skip_enrich:
        print(f"   💾 Кэш SploitScan: {cache_dir}")
        print(f"   🌐 Кэш CDN: {cache_dir / 'cdn'}")
    print(f"   📄 Результаты: {output_dir}")
    if not skip_enrich and not only_cache:
        print(f"   📋 Логи SploitScan: {output_dir / 'logs'}")

    # Ищем отчеты в указанной папке scan_dir
    trivy_files = list(scan_dir.glob("*.json"))

    # Исключаем config.json и уже обогащенные отчеты (включая _only_cache)
    trivy_files = [
        f for f in trivy_files
        if not f.name.endswith('_enriched.json')
           and not f.name.endswith('_only_cache.json')
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
    print(f"\n{'=' * 70}")
    print("ИТОГОВАЯ СТАТИСТИКА")
    print(f"{'=' * 70}")
    print(f"✅ Обработано отчетов: {processed}")
    if generate_html:
        print(f"📊 Создано HTML отчетов: {html_created}")
    if generate_excel_flag:
        print(f"📈 Создано Excel отчетов: {excel_created}")
    print(f"⏱️ Общее время выполнения: {total_time:.1f}с")
    print(f"{'=' * 70}")
    print("\n✨ VIBECHECKER завершил работу ✨")


if __name__ == "__main__":
    main()