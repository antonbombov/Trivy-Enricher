# cdn_cache_manager.py
import requests
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# URL Tailwind CDN — тот самый, который всегда работал
TAILWIND_CDN_URL = "https://cdn.tailwindcss.com/"


def ensure_cdn_cache_dir(cache_dir):
    """Создает директорию для кэша CDN"""
    cdn_cache_dir = Path(cache_dir) / "cdn"
    cdn_cache_dir.mkdir(parents=True, exist_ok=True)
    return cdn_cache_dir


def get_tailwind_js(cache_dir):
    """
    Возвращает содержимое Tailwind JS скрипта.
    Если есть в кэше — читает, если нет — скачивает и сохраняет.
    """
    cdn_cache_dir = ensure_cdn_cache_dir(cache_dir)
    tailwind_js_file = cdn_cache_dir / "tailwind.js"

    # Проверяем наличие в кэше
    if tailwind_js_file.exists():
        try:
            with open(tailwind_js_file, 'r', encoding='utf-8') as f:
                js_content = f.read()
                print(f"  Tailwind JS загружен из кэша ({len(js_content)} байт)")  # ← ПЕЧАТАЕМ ЗДЕСЬ
                return js_content
        except Exception as e:
            print(f"  Не удалось прочитать кэш, скачиваем заново: {e}")

    # Скачиваем с CDN
    try:
        print(f"  Скачивание Tailwind JS с CDN...")  # ← ПЕЧАТАЕМ ЗДЕСЬ
        response = requests.get(TAILWIND_CDN_URL, timeout=30, allow_redirects=True)
        response.raise_for_status()

        js_content = response.text

        with open(tailwind_js_file, 'w', encoding='utf-8') as f:
            f.write(js_content)

        print(f"  Tailwind JS скачан и сохранен в кэш ({len(js_content)} байт)")  # ← ПЕЧАТАЕМ ЗДЕСЬ
        return js_content

    except Exception as e:
        print(f"  ОШИБКА скачивания Tailwind JS: {e}")
        raise


def get_cdn_cache_stats(cache_dir):
    """Возвращает статистику по кэшу CDN"""
    cdn_cache_dir = Path(cache_dir) / "cdn"
    tailwind_js_file = cdn_cache_dir / "tailwind.js"

    stats = {
        'tailwind_cached': tailwind_js_file.exists(),
        'tailwind_path': str(tailwind_js_file) if tailwind_js_file.exists() else None
    }

    if tailwind_js_file.exists():
        stats['tailwind_size'] = tailwind_js_file.stat().st_size

    return stats


def clear_cdn_cache(cache_dir):
    """Очищает кэш CDN"""
    cdn_cache_dir = Path(cache_dir) / "cdn"
    deleted = 0

    for f in cdn_cache_dir.glob("tailwind.js"):
        try:
            f.unlink()
            deleted += 1
            logger.info(f"Удален кэш: {f}")
        except Exception as e:
            logger.error(f"Не удалось удалить {f}: {e}")

    return deleted