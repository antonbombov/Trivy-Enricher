# config_manager.py
import json
import shutil
from pathlib import Path
from typing import Optional


def load_config():
    """
    Загружает конфигурацию из config.json
    """
    config_path = Path(__file__).parent / "config.json"

    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # Обработка max_workers (может быть null)
    if "max_workers" in config:
        if config["max_workers"] in ["", None]:
            config["max_workers"] = None
        else:
            try:
                config["max_workers"] = int(config["max_workers"])
            except (ValueError, TypeError):
                config["max_workers"] = None

    return config


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
    Создает необходимые директории
    """
    scan_dir = Path(config['scan_directory'])
    cache_dir = Path(config['cache_directory'])
    output_dir = Path(config['output_directory'])

    cache_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    return scan_dir, cache_dir, output_dir


def get_ptai_reports_path(config) -> Optional[Path]:
    """
    Возвращает путь к каталогу с PTAI отчетами
    """
    scan_dir = Path(config['scan_directory'])
    ptai_dir = scan_dir / "PTAI"

    if ptai_dir.exists() and ptai_dir.is_dir():
        return ptai_dir
    return None


def find_ptai_report_for_trivy(trivy_file_path, config) -> Optional[Path]:
    """
    Ищет соответствующий PTAI отчет для Trivy отчета
    """
    trivy_path = Path(trivy_file_path)
    ptai_dir = get_ptai_reports_path(config)

    if not ptai_dir:
        return None

    html_files = list(ptai_dir.glob("*.html"))
    if not html_files:
        return None

    base_name = trivy_path.stem
    base_name = base_name.replace('_enriched', '')
    base_name = base_name.replace('_only_cache', '')

    for html_file in html_files:
        if html_file.stem == base_name:
            return html_file

    return None


def get_all_ptai_reports(config) -> list:
    """
    Возвращает список всех PTAI отчетов
    """
    ptai_dir = get_ptai_reports_path(config)
    if ptai_dir:
        return list(ptai_dir.glob("*.html"))
    return []