# cache_cleaner.py
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from config_manager import load_config


def cleanup_old_cache():
    """
    Очищает старые файлы в кэше на основе настроек cache_max_days
    Возвращает количество удаленных файлов
    """
    config = load_config()
    cache_dir = Path(config['cache_directory'])
    max_days = config.get('cache_max_days', 30)

    if not cache_dir.exists():
        print(f"⚠️  Директория кэша не существует: {cache_dir}")
        return 0

    current_time = time.time()
    max_age_seconds = max_days * 24 * 60 * 60
    cutoff_time = current_time - max_age_seconds

    deleted_count = 0

    # Просто удаляем старые файлы
    for file_path in cache_dir.glob("*.json"):
        try:
            file_stat = file_path.stat()
            file_age = current_time - file_stat.st_mtime

            if file_age > max_age_seconds:
                file_path.unlink()
                deleted_count += 1
                print(f"🗑️  Удален старый файл: {file_path.name} (возраст: {file_age / (24 * 60 * 60):.1f} дней)")
        except Exception as e:
            print(f"⚠️  Ошибка при удалении {file_path.name}: {e}")

    return deleted_count


def get_cache_stats():
    """
    Возвращает статистику по кэшу
    """
    config = load_config()
    cache_dir = Path(config['cache_directory'])
    max_days = config.get('cache_max_days', 30)

    if not cache_dir.exists():
        return {
            'total_files': 0,
            'max_age_days': max_days
        }

    total_files = 0
    for _ in cache_dir.glob("*.json"):
        total_files += 1

    return {
        'total_files': total_files,
        'max_age_days': max_days
    }


def main():
    """
    Основная функция для ручной очистки кэша
    """
    print("=" * 60)
    print("ОЧИСТКА КЭША SPLOITSCAN")
    print("=" * 60)

    stats_before = get_cache_stats()

    print(f"📊 Статистика кэша:")
    print(f"   Всего файлов: {stats_before['total_files']}")
    print(f"   Максимальный возраст: {stats_before['max_age_days']} дней")

    deleted_count = cleanup_old_cache()

    if deleted_count > 0:
        print(f"\n✅ Удалено {deleted_count} файлов")
    else:
        print(f"\n✅ Кэш уже чист")


if __name__ == "__main__":
    main()