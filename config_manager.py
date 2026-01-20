# config_manager.py
import json
import shutil
from pathlib import Path


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
        "max_workers": None,
        "timeout": 60,
        "project_version": "1.0.0"  # <-- ДОБАВЛЕНО
    }

    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
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