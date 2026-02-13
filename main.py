# main.py
import time
from enrichment_core import enrich_trivy_report
from trivy_html_reporter import generate_trivy_html_report
from trivy_excel_reporter import generate_trivy_excel_report
from config_manager import load_config, setup_directories
from cache_cleaner import cleanup_old_cache, get_cache_stats
from cdn_cache_manager import get_cdn_cache_stats


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


def main():
    config = load_config()
    scan_dir, cache_dir, output_dir = setup_directories(config)

    # Очищаем логи перед запуском
    print("=" * 60)
    print("ОБОГАЩЕНИЕ TRIVY SPLOITSCAN")
    print("ПОЛНАЯ ИНФОРМАЦИЯ ОБ ЭКСПЛОЙТАХ + HTML ОТЧЕТ + EXCEL ОТЧЕТ")
    print("=" * 60)

    # Показываем статистику кэша SploitScan
    sploitscan_stats = get_cache_stats()
    print(f"Кэш SploitScan: {sploitscan_stats['total_files']} файлов (макс. возраст: {sploitscan_stats['max_age_days']} дней)")

    # Показываем статистику кэша CDN
    cdn_stats = get_cdn_cache_stats(cache_dir)
    if cdn_stats['tailwind_cached']:
        print(f"Кэш CDN: Tailwind JS {cdn_stats.get('tailwind_size', 0)} байт")
    else:
        print(f"Кэш CDN: пуст (будет загружен при первом отчете)")

    # Автоматическая очистка старых файлов в кэше
    deleted_count = cleanup_old_cache()
    if deleted_count > 0:
        print(f"Удалено старых файлов: {deleted_count}")

    print(f"\nОчистка старых логов...")
    cleanup_logs(output_dir)
    print("Очистка логов завершена\n")

    print(f"Ищем отчеты в: {scan_dir}")
    print(f"Кэш SploitScan: {cache_dir}")
    print(f"Кэш CDN: {cache_dir / 'cdn'}")
    print(f"Результаты (JSON+HTML+Excel+Логи): {output_dir}")
    print(f"Логи SploitScan: {output_dir / 'logs'} (отдельный файл для каждого CVE и попытки)")

    # Ищем отчеты в указанной папке scan_dir
    trivy_files = list(scan_dir.glob("*.json"))

    # Исключаем config.json и уже обогащенные отчеты
    trivy_files = [
        f for f in trivy_files
        if not f.name.endswith('_enriched.json')
           and f.name != 'config.json'
    ]

    if not trivy_files:
        print(f"Нет отчетов Trivy в папке: {scan_dir}")
        print("Поместите JSON отчеты Trivy в указанную папку")
        return

    print(f"Найдено отчетов: {len(trivy_files)}")

    for trivy_file in trivy_files:
        print(f"\nОБРАБОТКА: {trivy_file.name}")
        print("=" * 40)

        start_time = time.time()
        enriched_file = enrich_trivy_report(trivy_file, output_dir)
        total_time = time.time() - start_time

        if enriched_file:
            print(f"УСПЕШНО ЗА {total_time:.1f}с")
            print(f"Обогащенный JSON: {enriched_file}")

            # ГЕНЕРАЦИЯ HTML ОТЧЕТА
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

            # ГЕНЕРАЦИЯ EXCEL ОТЧЕТА
            print(f"\nГенерация Excel отчета...")
            excel_start_time = time.time()

            excel_file = generate_trivy_excel_report(enriched_file, output_dir)
            excel_time = time.time() - excel_start_time

            if excel_file:
                print(f"Excel отчет создан за {excel_time:.1f}с: {excel_file}")
            else:
                print(f"Ошибка создания Excel отчета")

        else:
            print(f"ОШИБКА обогащения отчета")


if __name__ == "__main__":
    main()