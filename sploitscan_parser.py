# sploitscan_parser.py
import json

def parse_sploitscan_data(json_file):
    """
    Парсит JSON файл от sploitscan и возвращает оригинальные данные БЕЗ ИЗМЕНЕНИЙ
    """
    try:
        with open(json_file, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        # Если JSON содержит список, берем первый элемент
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        
        # Возвращаем оригинальные данные SploitScan без изменений
        return data
        
    except Exception as e:
        print(f"ОШИБКА ПАРСИНГА JSON {json_file}: {e}")
        return {}