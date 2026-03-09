# make_html.py
from pathlib import Path
from trivy_html_reporter import generate_trivy_html_report
from config_manager import load_config  # Добавляем импорт


def main():
    # Загружаем конфигурацию
    config = load_config()

    # Определяем папку с отчетами
    reports_dir = Path("Filtredreports")

    if not reports_dir.exists():
        print("Создай папку 'Filtredreports' и положи туда JSON файлы")
        input("Нажми Enter...")
        return

    # Ищем все JSON файлы
    json_files = list(reports_dir.glob("*.json"))

    # Фильтруем ненужные файлы
    json_files = [f for f in json_files if "config" not in f.name.lower()]

    if not json_files:
        print("Нет JSON файлов в папке 'Filtredreports'")
        input("Нажми Enter...")
        return

    print(f"Найдено {len(json_files)} файлов:")
    for f in json_files:
        print(f"  - {f.name}")

    # Создаем HTML для каждого
    for json_file in json_files:
        print(f"\nСоздаю HTML для: {json_file.name}")
        try:
            # ИСПРАВЛЕНИЕ: передаём все три обязательных параметра
            html_file = generate_trivy_html_report(
                json_file,
                Path(config['output_directory']),  # output_dir из конфига
                Path(config['cache_directory'])  # cache_dir из конфига
            )
            if html_file:
                print(f"✅ Создан: {html_file.name}")
        except Exception as e:
            print(f"❌ Ошибка: {e}")

    print("\nГотово!")
    input("Нажми Enter для выхода...")


if __name__ == "__main__":
    main()