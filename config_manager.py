# config_manager.py
import json
import shutil
from pathlib import Path
from typing import Optional, Tuple


def load_config():
    """
    Загружает конфигурацию из config.json или создает default
    """
    config_path = Path(__file__).parent / "config.json"
    default_config = {
        "sploitscan_path": "sploitscan",
        "scan_directory": "Scan",
        "cache_directory": "SploitScanJsons",
        "output_directory": "Results",
        "cache_max_days": 30,
        "max_workers": None,  # None = автоопределение
        "timeout": 60,
        "project_version": "1.0.0"
    }

    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)

                # Особенная обработка для max_workers
                if "max_workers" in user_config:
                    # Если пустая строка или null - оставляем None
                    if user_config["max_workers"] in ["", None]:
                        user_config["max_workers"] = None
                    # Иначе пытаемся конвертировать в int
                    else:
                        try:
                            user_config["max_workers"] = int(user_config["max_workers"])
                        except (ValueError, TypeError):
                            user_config["max_workers"] = None

                default_config.update(user_config)
        except Exception as e:
            print(f"ОШИБКА загрузки config.json: {e}")
            print("Используются настройки по умолчанию")

    return default_config


def save_config(config):
    """
    Сохраняет конфигурацию в config.json
    """
    config_path = Path(__file__).parent / "config.json"
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"ОШИБКА сохранения config.json: {e}")
        return False


def get_sploitscan_path(config):
    """
    Возвращает путь к sploitscan в зависимости от конфигурации
    """
    sploitscan_path = config['sploitscan_path']

    if sploitscan_path == "sploitscan":
        if shutil.which("sploitscan"):
            return "sploitscan"
        else:
            print("❌ Команда 'sploitscan' не найдена в системе")
            return None
    else:
        sploitscan_path_obj = Path(sploitscan_path)
        if sploitscan_path_obj.exists():
            return str(sploitscan_path_obj)
        else:
            print(f"❌ Файл не существует: {sploitscan_path}")
            return None


def setup_directories(config):
    """
    Создает необходимые директории (использует абсолютные пути как есть)
    """
    # Используем абсолютные пути как есть
    scan_dir = Path(config['scan_directory'])
    cache_dir = Path(config['cache_directory'])
    output_dir = Path(config['output_directory'])

    # Создаем cache_dir и output_dir, scan_dir не создаем
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    return scan_dir, cache_dir, output_dir


def get_ptai_reports_path(config) -> Optional[Path]:
    """
    Возвращает путь к каталогу с PTAI отчетами

    Args:
        config: Словарь конфигурации

    Returns:
        Path к каталогу PTAI или None, если каталог не существует
    """
    scan_dir = Path(config['scan_directory'])
    ptai_dir = scan_dir / "PTAI"

    if ptai_dir.exists() and ptai_dir.is_dir():
        return ptai_dir
    else:
        return None


def find_ptai_report_for_trivy(trivy_file_path, config) -> Optional[Path]:
    """
    Ищет соответствующий PTAI отчет для Trivy отчета.
    Требует точного совпадения имен файлов (без учета расширения).

    Args:
        trivy_file_path: Путь к Trivy отчету (Path или строка)
        config: Словарь конфигурации

    Returns:
        Path к PTAI отчету или None, если отчет не найден или имена не совпадают
    """
    trivy_path = Path(trivy_file_path)
    ptai_dir = get_ptai_reports_path(config)

    if not ptai_dir:
        print("   ⚠️ Каталог PTAI не найден")
        return None

    # Ищем все HTML файлы в каталоге PTAI
    html_files = list(ptai_dir.glob("*.html"))
    if not html_files:
        print("   ⚠️ В каталоге PTAI нет HTML файлов")
        return None

    # Получаем базовое имя Trivy отчета (без _enriched и расширения)
    base_name = trivy_path.stem
    base_name = base_name.replace('_enriched', '')

    # Ищем точное совпадение по имени (без учета расширения)
    for html_file in html_files:
        if html_file.stem == base_name:
            print(f"   ✅ Найден соответствующий PTAI отчет: {html_file.name}")
            return html_file

    # Если точного совпадения нет, выводим сообщение и возвращаем None
    print(f"   ⚠️ PTAI отчет не найден: требуется файл с именем '{base_name}.html'")
    print(f"      Доступные PTAI отчеты: {[f.name for f in html_files]}")
    return None


def get_all_ptai_reports(config) -> list:
    """
    Возвращает список всех PTAI отчетов в каталоге

    Args:
        config: Словарь конфигурации

    Returns:
        Список Path объектов HTML файлов
    """
    ptai_dir = get_ptai_reports_path(config)
    if ptai_dir:
        return list(ptai_dir.glob("*.html"))
    return []


def main():
    """
    Функция для тестирования
    """
    config = load_config()
    print("📋 Текущая конфигурация:")
    for key, value in config.items():
        print(f"   {key}: {value}")

    ptai_dir = get_ptai_reports_path(config)
    print(f"\n📁 PTAI каталог: {ptai_dir}")

    if ptai_dir:
        ptai_reports = get_all_ptai_reports(config)
        print(f"📄 Найдено PTAI отчетов: {len(ptai_reports)}")
        for report in ptai_reports:
            print(f"   - {report.name}")


if __name__ == "__main__":
    main()