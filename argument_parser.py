# argument_parser.py
import argparse
import sys
from typing import Tuple, Optional, List
from pathlib import Path


def interactive_file_selection(scan_dir: Path, prompt: str, exclude: List[str] = None) -> Optional[str]:
    """Интерактивный выбор файла"""
    exclude = exclude or []

    files = []
    for f in scan_dir.glob("*.json"):
        if f.name not in ['config.json', *exclude]:
            if not f.name.startswith('diff_report') and not f.name.endswith('_enriched.json'):
                files.append(f.name)

    files.sort()

    if not files:
        print(f"❌ Нет подходящих JSON файлов в {scan_dir}")
        return None

    print(f"\n📂 {prompt}")
    print("-" * 60)
    for i, f in enumerate(files, 1):
        try:
            size = (scan_dir / f).stat().st_size / 1024
            size_str = f"({size:.1f} KB)"
        except:
            size_str = ""
        print(f"  {i:2}. {f} {size_str}")
    print("  0. Отмена")
    print("-" * 60)

    while True:
        try:
            choice = input("Введите номер (или 0 для отмены): ").strip()
            if choice == '0':
                return None
            if choice == '':
                continue

            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return files[idx]
            print(f"❌ Неверный номер. Введите 1-{len(files)}")
        except ValueError:
            print("❌ Введите число")
        except (KeyboardInterrupt, EOFError):
            print("\n❌ Отменено")
            return None


def parse_arguments():
    """Парсинг аргументов командной строки"""

    parser = argparse.ArgumentParser(
        description='Trivy Enricher - обогащение отчетов Trivy данными SploitScan',
        usage='python main.py [-h] [-html] [-excel] [-skip-enrich] [-only-cache] [-ptai-only] [-diff [REPORT1 REPORT2]]',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -html                           # Только HTML отчеты
  python main.py -excel                          # Только Excel отчеты
  python main.py -html -excel                    # Оба типа отчетов
  python main.py -html -excel -skip-enrich       # Без обогащения
  python main.py -diff                           # Интерактивный выбор для diff
  python main.py -diff image1.json image2.json   # Diff с указанием файлов
  python main.py -diff -html -excel              # Diff + HTML + Excel
  python main.py -ptai-only -excel               # Только PTAI в Excel
  python main.py -h                              # Показать справку

Ключи:
  -html          Генерировать HTML отчет
  -excel         Генерировать Excel отчет
  -skip-enrich   Пропустить обогащение SploitScan
  -only-cache    Использовать только кэш (без вызова SploitScan)
  -ptai-only     Только Excel отчеты из PTAI (без Trivy)
  -diff          Выполнить diff анализ (0 или 2 файла)
  -h             Показать справку
        """
    )

    # Основные ключи генерации отчетов
    parser.add_argument(
        '-html',
        action='store_true',
        help='Генерировать HTML отчет'
    )

    parser.add_argument(
        '-excel',
        action='store_true',
        help='Генерировать Excel отчет'
    )

    # Ключи управления обогащением
    parser.add_argument(
        '-skip-enrich',
        action='store_true',
        help='Пропустить обогащение SploitScan'
    )

    parser.add_argument(
        '-only-cache',
        action='store_true',
        help='Использовать только кэш (без вызова SploitScan)'
    )

    # Специальные режимы
    parser.add_argument(
        '-ptai-only',
        action='store_true',
        help='Только Excel отчеты из PTAI (без Trivy)'
    )

    parser.add_argument(
        '-diff',
        nargs='*',
        help='Выполнить diff анализ (0 или 2 файла)'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # ===== ВАЛИДАЦИЯ АРГУМЕНТОВ =====

    # 1. Проверяем взаимоисключающие ключи обогащения
    if args.skip_enrich and args.only_cache:
        print("❌ Ошибка: -skip-enrich и -only-cache не могут использоваться вместе")
        print("   -skip-enrich: использует исходные отчеты без обогащения")
        print("   -only-cache:  использует только закэшированные CVE")
        print("   Выберите один режим или используйте обычный режим (без этих ключей)")
        sys.exit(1)

    # 2. Проверяем diff
    diff_active = '-diff' in sys.argv

    if diff_active:
        # Проверяем количество файлов
        if args.diff is None:
            args.diff = []  # Интерактивный режим
        elif len(args.diff) > 0 and len(args.diff) != 2:
            print("❌ Ошибка: для -diff нужно указать 0 или 2 файла")
            print("   Примеры:")
            print("     python main.py -diff                    # Интерактивный выбор")
            print("     python main.py -diff file1.json file2.json  # С указанием файлов")
            sys.exit(1)

        # -ptai-only несовместим с diff
        if args.ptai_only:
            print("❌ Ошибка: -ptai-only не может использоваться с -diff")
            print("   -ptai-only: только Excel из PTAI отчетов")
            print("   -diff:      сравнительный анализ отчетов Trivy")
            print("   Эти режимы несовместимы")
            sys.exit(1)

        return args

    # 3. -ptai-only требует -excel
    if args.ptai_only and not args.excel:
        print("❌ Ошибка: -ptai-only требует -excel")
        print("   -ptai-only генерирует Excel отчеты из PTAI HTML")
        print("   Добавьте ключ -excel: python main.py -ptai-only -excel")
        sys.exit(1)

    # 4. -ptai-only не совместим с -html
    if args.ptai_only and args.html:
        print("❌ Ошибка: -ptai-only не может использоваться с -html")
        print("   -ptai-only генерирует только Excel отчеты")
        print("   Уберите -html или используйте обычный режим")
        sys.exit(1)

    # 5. -ptai-only игнорирует ключи обогащения (предупреждение)
    if args.ptai_only:
        if args.skip_enrich:
            print("⚠️  Предупреждение: -ptai-only игнорирует -skip-enrich")
            print("   (PTAI не использует SploitScan для обогащения)")
            args.skip_enrich = False

        if args.only_cache:
            print("⚠️  Предупреждение: -ptai-only игнорирует -only-cache")
            print("   (PTAI не использует кэш SploitScan)")
            args.only_cache = False

    # 6. Проверяем, что есть хоть какой-то режим работы
    if not any([args.html, args.excel, args.ptai_only]):
        print("❌ Ошибка: не указан режим работы")
        print("   Используйте один из режимов:")
        print("     python main.py -html           # Только HTML")
        print("     python main.py -excel          # Только Excel")
        print("     python main.py -html -excel    # HTML + Excel")
        print("     python main.py -ptai-only -excel  # Только PTAI")
        print("     python main.py -diff           # Diff анализ")
        print("   Для справки: python main.py -h")
        sys.exit(1)

    return args


def get_report_types(args) -> Tuple[bool, bool, bool, bool, bool]:
    """Возвращает типы отчетов"""
    return args.html, args.excel, args.skip_enrich, args.only_cache, args.ptai_only


def get_diff_files(args, scan_dir: Path) -> Tuple[Optional[List[str]], bool]:
    """
    Возвращает список файлов для diff анализа и флаг, что diff активен

    Returns:
        (files, is_diff_active)
        files: список из 2 файлов или None
        is_diff_active: True если diff режим активен
    """
    import sys
    diff_active = '-diff' in sys.argv

    if not diff_active:
        return None, False

    # Если diff активен, но файлов нет - интерактивный режим
    if args.diff is None or len(args.diff) == 0:
        print("\n" + "=" * 60)
        print("🔍 ИНТЕРАКТИВНЫЙ ВЫБОР ФАЙЛОВ ДЛЯ DIFF АНАЛИЗА")
        print("=" * 60)
        print(f"📁 Директория: {scan_dir}")

        # Проверяем наличие файлов
        json_files = list(scan_dir.glob("*.json"))
        json_files = [f for f in json_files
                      if f.name != 'config.json'
                      and not f.name.startswith('diff_report')
                      and not f.name.endswith('_enriched.json')]

        if not json_files:
            print("❌ Нет JSON файлов для анализа")
            return None, True

        # Выбор первого файла
        print("\n📌 Шаг 1: Выбор базового отчета (baseline)")
        file1 = interactive_file_selection(scan_dir, "Выберите ПЕРВЫЙ файл (baseline):")
        if not file1:
            print("❌ Операция отменена")
            return None, True

        # Выбор второго файла
        print(f"\n📌 Шаг 2: Выбор нового отчета (после изменений)")
        file2 = interactive_file_selection(scan_dir, "Выберите ВТОРОЙ файл (новый):", exclude=[file1])
        if not file2:
            print("❌ Операция отменена")
            return None, True

        print("\n" + "=" * 60)
        print("✅ ВЫБРАНЫ ФАЙЛЫ ДЛЯ СРАВНЕНИЯ:")
        print("=" * 60)
        print(f"  📄 Отчет 1 (baseline): {file1}")
        print(f"  📄 Отчет 2 (новый):    {file2}")

        # Проверяем, нужны ли отчеты
        if args.html or args.excel:
            print("\n📋 Дополнительные режимы:")
            if args.html:
                print("  - Будет создан HTML отчет по результатам diff")
            if args.excel:
                print("  - Будет создан Excel отчет по результатам diff")

        confirm = input("\nПродолжить? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes', 'д', 'да']:
            print("❌ Отменено")
            return None, True

        return [file1, file2], True

    # Если файлы указаны - проверяем
    if len(args.diff) == 2:
        missing = []
        for f in args.diff:
            if not (scan_dir / f).exists():
                missing.append(f)

        if missing:
            print(f"❌ Ошибка: файлы не найдены: {', '.join(missing)}")
            return None, True

        return args.diff, True

    return None, True


def print_usage():
    print("Trivy Enricher - обогащение отчетов Trivy данными SploitScan")
    print("=" * 60)
    print("Использование: python main.py [-h] [-html] [-excel] [-skip-enrich] [-diff [REPORT1 REPORT2]]")
    print("\n  python main.py -html -excel          # Обычный режим")
    print("  python main.py -diff                  # Интерактивный выбор")
    print("  python main.py -diff file1 file2      # Сравнение двух файлов")
    print("  python main.py -diff -html -excel    # Diff + генерация отчетов")