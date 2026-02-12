# trivy_excel_reporter.py
import json
from pathlib import Path
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side

# Константа со статусами для выпадающего списка
STATUS_OPTIONS = [
    "Опровергнута",
    "Устранена",
    "Устранение невозможно",
    "Приняты компенсирующие меры",
    "В работе"
]

# Константа с именами колонок
COLUMN_HEADERS = [
    "№",
    "Источник",
    "Путь",
    "Пакет",
    "Версия",
    "Идентификатор уязвимости",
    "Уровень критичности",
    "Статус",
    "Комментарий"
]


def generate_trivy_excel_report(enriched_trivy_path, output_dir=None):
    """
    Генерирует Excel отчет из обогащенного отчета Trivy
    БЕЗ дедупликации - каждая строка = отдельное вхождение уязвимости
    """
    try:
        # Загружаем обогащенный отчет
        with open(enriched_trivy_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)

        # Определяем путь для сохранения
        if output_dir is None:
            from config_manager import load_config
            config = load_config()
            output_dir = Path(config.get('output_directory', Path(__file__).parent))
        else:
            output_dir = Path(output_dir)

        # Создаем директорию, если её нет
        output_dir.mkdir(parents=True, exist_ok=True)

        # Сохраняем в указанной директории
        output_path = output_dir / f"{enriched_trivy_path.stem}_report.xlsx"

        # Собираем ВСЕ вхождения уязвимостей (БЕЗ дедупликации)
        all_vulnerabilities = collect_all_vulnerabilities(trivy_data)

        # Генерируем Excel
        workbook = generate_excel_content(all_vulnerabilities, enriched_trivy_path.name)

        # Сохраняем файл
        workbook.save(output_path)

        return output_path

    except Exception as e:
        import traceback
        print(f"ОШИБКА генерации Excel отчета: {e}")
        print(f"Трассировка ошибки:")
        traceback.print_exc()
        return None


def collect_all_vulnerabilities(trivy_data):
    """
    Собирает ВСЕ вхождения уязвимостей БЕЗ какой-либо дедупликации
    Каждая запись в отчете Trivy = отдельная строка в Excel
    """
    all_vulns = []

    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            target = result.get('Target', 'Unknown')  # Берем Target как источник
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    if 'VulnerabilityID' not in vuln:
                        continue

                    pkg_path = vuln.get('PkgPath', 'N/A')

                    # Извлекаем корневой JAR для более чистого отображения пути
                    display_path = pkg_path
                    if pkg_path and pkg_path != 'N/A':
                        source_jar = extract_root_jar(pkg_path)
                        if source_jar:
                            display_path = f"{source_jar} -> {pkg_path}"

                    all_vulns.append({
                        'source': target,  # Новое поле для источника
                        'path': display_path,
                        'package': vuln.get('PkgName', 'Unknown Package'),
                        'version': vuln.get('InstalledVersion', 'Unknown'),
                        'vulnerability_id': vuln['VulnerabilityID'],
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'status': '',  # Пустой для ручного заполнения
                        'comment': ''  # Пустой для ручного заполнения
                    })

    return all_vulns


def extract_root_jar(pkg_path):
    """
    Извлекает корневой JAR файл из пути
    Полная копия функции из trivy_html_reporter.py
    """
    if not pkg_path:
        return None

    parts = pkg_path.split('/')
    root = parts[0]
    if root.endswith('.jar') or root.endswith('.war') or root.endswith('.ear'):
        return root

    return None


def generate_excel_content(vulnerabilities, report_filename):
    """
    Генерирует Excel файл с данными уязвимостей
    """
    # Создаем новую рабочую книгу
    wb = openpyxl.Workbook()
    ws = wb.active

    # Извлекаем имя артефакта из имени файла
    artifact_name = Path(report_filename).stem.replace('_enriched', '')

    # ОБРЕЗАЕМ название листа до 31 символа, чтобы избежать предупреждения openpyxl
    safe_title = f"Vulnerabilities_{artifact_name[:25]}"
    # Дополнительно обрезаем, если все еще больше 31 символа
    if len(safe_title) > 31:
        safe_title = safe_title[:31]
    ws.title = safe_title

    # Настройка стилей
    header_font = Font(name='Arial', size=11, bold=True, color='FFFFFF')
    header_fill = PatternFill(start_color='2F75B5', end_color='2F75B5', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

    border = Border(
        left=Side(style='thin', color='000000'),
        right=Side(style='thin', color='000000'),
        top=Side(style='thin', color='000000'),
        bottom=Side(style='thin', color='000000')
    )

    # Создаем заголовки
    for col_num, header in enumerate(COLUMN_HEADERS, 1):
        cell = ws.cell(row=1, column=col_num, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = border

    # Заполняем данные
    for row_num, vuln in enumerate(vulnerabilities, 2):
        # №
        cell = ws.cell(row=row_num, column=1, value=row_num - 1)
        cell.border = border
        cell.alignment = Alignment(horizontal='center', vertical='center')

        # Источник
        cell = ws.cell(row=row_num, column=2, value=vuln['source'])
        cell.border = border
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

        # Путь
        cell = ws.cell(row=row_num, column=3, value=vuln['path'])
        cell.border = border
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

        # Пакет
        cell = ws.cell(row=row_num, column=4, value=vuln['package'])
        cell.border = border
        cell.alignment = Alignment(horizontal='left', vertical='center')

        # Версия
        cell = ws.cell(row=row_num, column=5, value=vuln['version'])
        cell.border = border
        cell.alignment = Alignment(horizontal='left', vertical='center')

        # Идентификатор уязвимости
        cell = ws.cell(row=row_num, column=6, value=vuln['vulnerability_id'])
        cell.border = border
        cell.alignment = Alignment(horizontal='center', vertical='center')

        # Уровень критичности
        severity = vuln['severity']
        cell = ws.cell(row=row_num, column=7, value=severity)
        cell.border = border
        cell.alignment = Alignment(horizontal='center', vertical='center')

        # Статус (пустой)
        cell = ws.cell(row=row_num, column=8, value='')
        cell.border = border
        cell.alignment = Alignment(horizontal='center', vertical='center')

        # Комментарий (пустой)
        cell = ws.cell(row=row_num, column=9, value='')
        cell.border = border
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

    # Добавляем выпадающие списки для колонки "Статус" (колонка H, индекс 8)
    if vulnerabilities:  # Добавляем только если есть данные
        add_dropdown_lists(ws, len(vulnerabilities))

    # Настраиваем ширину колонок
    set_column_widths(ws)

    # Добавляем фильтры
    ws.auto_filter.ref = ws.dimensions

    # Замораживаем первую строку
    ws.freeze_panes = 'A2'

    return wb


def add_dropdown_lists(worksheet, num_rows):
    """
    Добавляет выпадающие списки со статусами в колонку H (Статус)
    Запрещает ввод произвольного текста - только выбор из списка
    """
    if num_rows == 0:
        return

    # Создаем отдельный лист со справочником статусов
    wb = worksheet.parent
    hidden_sheet = wb.create_sheet("_status_reference")
    hidden_sheet.sheet_state = 'hidden'  # Скрываем лист

    # Записываем статусы в скрытый лист
    for i, status in enumerate(STATUS_OPTIONS, 1):
        hidden_sheet.cell(row=i, column=1, value=status)

    # Создаем именованный диапазон для статусов
    ref_range = f"'_status_reference'!$A$1:$A${len(STATUS_OPTIONS)}"

    # Добавляем выпадающие списки для каждой строки с данными
    for row_num in range(2, num_rows + 2):
        cell_ref = f"H{row_num}"  # Изменено с G на H

        # Создаем правило валидации данных
        dv = openpyxl.worksheet.datavalidation.DataValidation(
            type='list',
            formula1=ref_range,
            allow_blank=True,  # Разрешаем пустое значение
            showErrorMessage=True,  # Показывать сообщение об ошибке
            showInputMessage=True,  # Показывать подсказку при выборе ячейки
            promptTitle='Выберите статус',
            prompt='Пожалуйста, выберите статус из выпадающего списка',
            errorTitle='Недопустимое значение',
            error='Вы можете выбрать ТОЛЬКО значение из выпадающего списка! Ввод произвольного текста запрещен.'
        )

        worksheet.add_data_validation(dv)
        dv.add(cell_ref)


def set_column_widths(worksheet):
    """
    Устанавливает оптимальную ширину колонок
    """
    # №
    worksheet.column_dimensions['A'].width = 8

    # Источник (новая колонка)
    worksheet.column_dimensions['B'].width = 30

    # Путь
    worksheet.column_dimensions['C'].width = 50

    # Пакет
    worksheet.column_dimensions['D'].width = 25

    # Версия
    worksheet.column_dimensions['E'].width = 20

    # Идентификатор уязвимости
    worksheet.column_dimensions['F'].width = 20

    # Уровень критичности
    worksheet.column_dimensions['G'].width = 15

    # Статус
    worksheet.column_dimensions['H'].width = 25

    # Комментарий
    worksheet.column_dimensions['I'].width = 40


def main():
    """
    Основная функция для тестирования
    """
    script_dir = Path(__file__).parent
    enriched_files = list(script_dir.glob("*_enriched.json"))

    if not enriched_files:
        print("Нет обогащенных отчетов Trivy")
        return

    for enriched_file in enriched_files:
        print(f"Генерация Excel отчета для: {enriched_file.name}")
        generate_trivy_excel_report(enriched_file)


if __name__ == "__main__":
    main()