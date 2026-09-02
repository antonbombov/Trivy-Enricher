# argument_parser.py
import argparse
import sys
from typing import Tuple, Optional, List
from pathlib import Path


def interactive_file_selection(scan_dir: Path, prompt: str, exclude: List[str] = None, start_dir: Path = None) -> \
Optional[str]:
    """
    Интерактивный выбор файла с возможностью навигации по каталогам

    Args:
        scan_dir: Корневая директория поиска
        prompt: Текст приглашения
        exclude: Список имен файлов для исключения
        start_dir: Начальная директория (если None, то scan_dir)

    Returns:
        Относительный путь к выбранному файлу или None
    """
    exclude = exclude or []
    current_dir = start_dir or scan_dir

    # Проверяем, что текущая директория находится внутри scan_dir
    try:
        current_dir.relative_to(scan_dir)
    except ValueError:
        print(f"⚠️  Выход за пределы корневой директории, возврат в {scan_dir}")
        current_dir = scan_dir

    while True:
        # Собираем каталоги (только те, где есть JSON файлы)
        dirs = []
        for item in sorted(current_dir.iterdir()):
            if item.is_dir() and not item.name.startswith('.'):
                # Проверяем, есть ли в каталоге JSON файлы (кроме config.json и diff_report)
                has_json = False
                for f in item.glob("*.json"):
                    if f.name == 'config.json':
                        continue
                    # Исключаем diff отчеты (старый формат diff_report*.json и новый формат *_diff*.json)
                    if f.name.startswith('diff_report') or '_diff' in f.name:
                        if exclude and f.name in exclude:
                            continue
                        continue
                    if exclude and f.name in exclude:
                        continue
                    has_json = True
                    break
                if has_json:
                    dirs.append(('dir', item.name, item))

        # Собираем JSON файлы
        files = []
        for item in sorted(current_dir.glob("*.json")):
            if item.name == 'config.json':
                continue
            # Исключаем diff отчеты (старый формат diff_report*.json и новый формат *_diff*.json)
            if item.name.startswith('diff_report') or '_diff' in item.name:
                if exclude and item.name in exclude:
                    continue
                continue
            if exclude and item.name in exclude:
                continue
            files.append(('file', item.name, item))

        # Если ничего нет - поднимаемся выше
        if not dirs and not files:
            if current_dir == scan_dir:
                print("❌ Нет файлов для выбора в корневой директории")
                return None
            else:
                print(f"⚠️  В директории {current_dir.name} нет файлов, поднимаемся выше...")
                current_dir = current_dir.parent
                continue

        # Вывод
        rel_path = current_dir.relative_to(scan_dir) if current_dir != scan_dir else Path('.')
        print(f"\n📂 {prompt}")
        print(f"   📁 Текущий путь: {rel_path}")
        print("-" * 60)

        # Собираем все элементы для отображения и маппинга индексов
        display_items = []

        # Навигация на уровень выше (если не в корне)
        if current_dir != scan_dir:
            display_items.append(('nav', '..', None))

        # Каталоги
        for dir_item in dirs:
            display_items.append(dir_item)

        # Файлы
        for file_item in files:
            display_items.append(file_item)

        # Выводим все элементы с индексами
        for i, (item_type, name, _) in enumerate(display_items, 1):
            if item_type == 'nav':
                print(f"  {i:2}. 🔙  [НА УРОВЕНЬ ВЫШЕ]")
            elif item_type == 'dir':
                print(f"  {i:2}. 📁 {name}/")
            else:  # file
                # Находим путь для размера
                path = None
                for _, _, p in files:
                    if p.name == name:
                        path = p
                        break
                if path:
                    try:
                        size = path.stat().st_size / 1024
                        size_str = f"({size:.1f} KB)"
                    except:
                        size_str = ""
                    print(f"  {i:2}. 📄 {name} {size_str}")
                else:
                    print(f"  {i:2}. 📄 {name}")

        print("  0. Отмена")
        print("-" * 60)

        # Ввод
        try:
            choice = input("Введите номер (или 0 для отмены): ").strip()

            if choice == '0':
                return None
            if choice == '':
                continue

            num = int(choice)

            # Проверяем диапазон
            if num < 0 or num > len(display_items):
                print(f"❌ Неверный номер. Введите 1-{len(display_items)} или 0 для отмены")
                continue

            # Получаем выбранный элемент
            item_type, name, path = display_items[num - 1]

            if item_type == 'nav':
                # Поднимаемся на уровень выше
                current_dir = current_dir.parent
                continue
            elif item_type == 'dir':
                # Переходим в каталог
                current_dir = path
                continue
            else:  # file
                # Возвращаем относительный путь от scan_dir
                return str(path.relative_to(scan_dir))

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

    # 5. -ptai-only игнорирует ключи обогащения (предупреждение + сброс)
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
        print(f"📁 Корневая директория: {scan_dir}")

        # Выбор первого файла
        print("\n📌 Шаг 1: Выбор первого отчета (старый)")
        file1 = interactive_file_selection(
            scan_dir,
            "Выберите ПЕРВЫЙ файл (старый отчет):",
            start_dir=scan_dir
        )
        if not file1:
            print("❌ Операция отменена")
            return None, True

        # Выбор второго файла
        print(f"\n📌 Шаг 2: Выбор нового отчета (после изменений)")
        file2 = interactive_file_selection(
            scan_dir,
            "Выберите ВТОРОЙ файл (новый отчет):",
            exclude=[file1],
            start_dir=scan_dir
        )
        if not file2:
            print("❌ Операция отменена")
            return None, True

        print("\n" + "=" * 60)
        print("✅ ВЫБРАНЫ ФАЙЛЫ ДЛЯ СРАВНЕНИЯ:")
        print("=" * 60)
        print(f"  📄 Отчет 1 (старый): {file1}")
        print(f"  📄 Отчет 2 (новый):  {file2}")

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
            # Проверяем существование файла (относительно scan_dir)
            file_path = scan_dir / f
            if not file_path.exists():
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