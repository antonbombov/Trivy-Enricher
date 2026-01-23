# main.py
import time
from pathlib import Path
from enrichment_core import enrich_trivy_report
from trivy_html_reporter import generate_trivy_html_report
from config_manager import load_config, setup_directories
from cache_cleaner import cleanup_old_cache, get_cache_stats


def cleanup_logs(output_dir):
    """
    Очищает папку с логами перед запуском
    """
    log_dir = output_dir / "logs"

    if log_dir.exists():
        try:
            # Удаляем все файлы в папке logs
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
    print("ПОЛНАЯ ИНФОРМАЦИЯ ОБ ЭКСПЛОЙТАХ + HTML ОТЧЕТ")
    print("=" * 60)

    # Показываем статистику кэша
    cache_stats = get_cache_stats()
    print(f"Кэш SploitScan: {cache_stats['total_files']} файлов (макс. возраст: {cache_stats['max_age_days']} дней)")

    # Автоматическая очистка старых файлов в кэше
    deleted_count = cleanup_old_cache()
    if deleted_count > 0:
        print(f"Удалено старых файлов: {deleted_count}")

    print(f"\nОчистка старых логов...")
    cleanup_logs(output_dir)
    print("Очистка логов завершена\n")

    print(f"Ищем отчеты в: {scan_dir}")
    print(f"Кэш SploitScan: {cache_dir}")
    print(f"Результаты (JSON+HTML+Логи): {output_dir}")
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
        # Передаем output_dir в функцию обогащения
        enriched_file = enrich_trivy_report(trivy_file, output_dir)
        total_time = time.time() - start_time

        if enriched_file:
            print(f"УСПЕШНО ЗА {total_time:.1f}с")
            print(f"Обогащенный JSON: {enriched_file}")

            # ГЕНЕРАЦИЯ HTML ОТЧЕТА
            print(f"\nГенерация HTML отчета...")
            html_start_time = time.time()

            # Используем output_dir для сохранения HTML
            html_file = generate_trivy_html_report(enriched_file, output_dir)
            html_time = time.time() - html_start_time

            if html_file:
                print(f"HTML отчет создан за {html_time:.1f}с: {html_file}")
            else:
                print(f"Ошибка создания HTML отчета")
        else:
            print(f"ОШИБКА")


if __name__ == "__main__":
    main()