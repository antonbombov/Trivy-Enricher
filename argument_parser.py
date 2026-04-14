# argument_parser.py
import argparse
import sys
from typing import Tuple, Optional


def parse_arguments():
    """
    Парсинг аргументов командной строки
    """
    parser = argparse.ArgumentParser(
        description='Trivy Enricher - обогащение отчетов Trivy данными SploitScan',
        usage='python main.py [-h] [-html] [-excel] [-skip-enrich] [-only-cache] [-ptai-only]',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -html                 # Только HTML отчеты (с обогащением)
  python main.py -excel                # Только Excel отчеты (с обогащением)
  python main.py -html -excel          # Оба типа отчетов (с обогащением)
  python main.py -html -skip-enrich    # HTML отчет без обогащения (только исходный Trivy)
  python main.py -excel -skip-enrich   # Excel отчет без обогащения (только исходный Trivy)
  python main.py -html -only-cache     # HTML отчет только из кэша (без вызова SploitScan)
  python main.py -excel -only-cache    # Excel отчет только из кэша (без вызова SploitScan)
  python main.py -excel -ptai-only     # Только Excel отчет с PTAI анализом (без Trivy)
  python main.py -h                    # Показать эту справку
        """
    )

    parser.add_argument(
        '-html',
        action='store_true',
        help='Генерировать HTML отчет (интерактивный с фильтрами)'
    )

    parser.add_argument(
        '-excel',
        action='store_true',
        help='Генерировать Excel отчет (SCA анализ + PTAI анализ, если доступен)'
    )

    parser.add_argument(
        '-skip-enrich', '-se',
        action='store_true',
        help='Пропустить обогащение SploitScan, использовать исходный отчет Trivy'
    )

    parser.add_argument(
        '-only-cache', '-oc',
        action='store_true',
        help='Использовать только кэшированные данные (без вызова SploitScan для отсутствующих CVE)'
    )

    parser.add_argument(
        '-ptai-only', '-po',
        action='store_true',
        help='Генерировать только Excel отчет с PTAI анализом (без Trivy SCA)'
    )

    args = parser.parse_args()

    # Если аргументы не указаны - показываем help
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    # Валидация: -ptai-only требует -excel
    if args.ptai_only and not args.excel:
        print("❌ Ошибка: ключ -ptai-only может использоваться только вместе с -excel")
        sys.exit(1)

    return args


def validate_arguments(args) -> Tuple[bool, Optional[str]]:
    """
    Валидация аргументов командной строки

    Args:
        args: Объект с аргументами

    Returns:
        Tuple[is_valid, error_message]
    """
    return True, None


def get_report_types(args) -> Tuple[bool, bool, bool, bool, bool]:
    """
    Возвращает кортеж с типами отчетов для генерации и флагами

    Args:
        args: Объект с аргументами

    Returns:
        Tuple[generate_html, generate_excel, skip_enrich, only_cache, ptai_only]
    """
    return args.html, args.excel, args.skip_enrich, args.only_cache, args.ptai_only


def print_usage():
    """
    Выводит краткую справку по использованию
    """
    print("Trivy Enricher - обогащение отчетов Trivy данными SploitScan")
    print("=" * 60)
    print("Использование: python main.py [-h] [-html] [-excel] [-skip-enrich] [-only-cache] [-ptai-only]")
    print("\nОпции:")
    print("  -html         Генерировать HTML отчет (интерактивный с фильтрами)")
    print("  -excel        Генерировать Excel отчет (SCA анализ + PTAI анализ)")
    print("  -skip-enrich, -se   Пропустить обогащение SploitScan, использовать исходный отчет")
    print("  -only-cache, -oc    Использовать только кэшированные данные (без вызова SploitScan)")
    print("  -ptai-only, -po     Генерировать только Excel отчет с PTAI анализом (без Trivy)")
    print("  -h            Показать эту справку")
    print("\nПримеры:")
    print("  python main.py -html                 # Только HTML отчеты (с обогащением)")
    print("  python main.py -excel                # Только Excel отчеты (с обогащением)")
    print("  python main.py -html -excel          # Оба типа отчетов (с обогащением)")
    print("  python main.py -html -skip-enrich    # HTML отчет без обогащения")
    print("  python main.py -html -only-cache     # HTML отчет только из кэша")
    print("  python main.py -excel -ptai-only     # Только Excel отчет с PTAI анализом")
    print("=" * 60)