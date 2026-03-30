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
        usage='python main.py [-h] [-html] [-excel] [-skip-enrich]',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -html                 # Только HTML отчеты (с обогащением)
  python main.py -excel                # Только Excel отчеты (с обогащением)
  python main.py -html -excel          # Оба типа отчетов (с обогащением)
  python main.py -html -skip-enrich    # HTML отчет без обогащения (только исходный Trivy)
  python main.py -excel -skip-enrich   # Excel отчет без обогащения (только исходный Trivy)
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

    args = parser.parse_args()

    # Если аргументы не указаны - показываем help
    if not any(vars(args).values()):
        parser.print_help()
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
    # В данном случае дополнительная валидация не требуется,
    # так как аргументы простые флаги
    return True, None


def get_report_types(args) -> Tuple[bool, bool, bool]:
    """
    Возвращает кортеж с типами отчетов для генерации и флаг пропуска обогащения

    Args:
        args: Объект с аргументами

    Returns:
        Tuple[generate_html, generate_excel, skip_enrich]
    """
    return args.html, args.excel, args.skip_enrich


def print_usage():
    """
    Выводит краткую справку по использованию
    """
    print("Trivy Enricher - обогащение отчетов Trivy данными SploitScan")
    print("=" * 60)
    print("Использование: python main.py [-h] [-html] [-excel] [-skip-enrich]")
    print("\nОпции:")
    print("  -html         Генерировать HTML отчет (интерактивный с фильтрами)")
    print("  -excel        Генерировать Excel отчет (SCA анализ + PTAI анализ)")
    print("  -skip-enrich, -se   Пропустить обогащение SploitScan, использовать исходный отчет")
    print("  -h            Показать эту справку")
    print("\nПримеры:")
    print("  python main.py -html                 # Только HTML отчеты (с обогащением)")
    print("  python main.py -excel                # Только Excel отчеты (с обогащением)")
    print("  python main.py -html -excel          # Оба типа отчетов (с обогащением)")
    print("  python main.py -html -skip-enrich    # HTML отчет без обогащения")
    print("=" * 60)


def main():
    """
    Функция для тестирования парсера аргументов
    """
    args = parse_arguments()
    html, excel, skip_enrich = get_report_types(args)

    print("📋 Режимы работы:")
    print(f"   HTML отчеты: {'✅' if html else '❌'}")
    print(f"   Excel отчеты: {'✅' if excel else '❌'}")
    print(f"   Пропуск обогащения: {'✅' if skip_enrich else '❌'}")

    is_valid, error = validate_arguments(args)
    if not is_valid:
        print(f"❌ Ошибка валидации: {error}")


if __name__ == "__main__":
    main()