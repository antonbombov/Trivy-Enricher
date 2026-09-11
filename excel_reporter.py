# excel_reporter.py
import json
from pathlib import Path
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

from ptai_processor import prepare_ptai_excel_data, PTAIParser
from excel_styles import (
    HEADER_FONT, HEADER_FILL, CELL_BORDER, INFO_FONT,
    apply_header_style, apply_cell_style, SCA_COLUMN_WIDTHS, PTAI_COLUMN_WIDTHS
)

# Константа со статусами для выпадающего списка
STATUS_OPTIONS = [
    "Опровергнута",
    "Устранена",
    "Устранение невозможно",
    "Приняты компенсирующие меры",
    "В работе"
]

# Константа с именами колонок для SCA анализа (без diff)
SCA_COLUMN_HEADERS = [
    "№",
    "Источник",
    "Путь",
    "Пакет",
    "Версия",
    "Идентификатор уязвимости",
    "Уровень критичности",
    "Срок устранения",
    "Статус",
    "Комментарий"
]

# Имена колонок для SCA с diff статусами (лист "SCA Анализ")
SCA_DIFF_COLUMN_HEADERS = [
    "№",
    "Источник",
    "Путь",
    "Пакет",
    "Версия",
    "Статус пакета",
    "Идентификатор уязвимости",
    "Статус уязвимости",
    "Уровень критичности",
    "Срок устранения",
    "Статус",
    "Комментарий"
]

# Имена колонок для листов "SCA NEW" и "SCA REMOVED" (без "Срок устранения" и "Статус")
SCA_DIFF_SHORT_COLUMN_HEADERS = [
    "№",
    "Источник",
    "Путь",
    "Пакет",
    "Версия",
    "Статус пакета",
    "Идентификатор уязвимости",
    "Статус уязвимости",
    "Уровень критичности",
    "Комментарий"
]

# Константа с именами колонок для PTAI анализа
PTAI_COLUMN_HEADERS = [
    '№',
    'ID уязвимости',
    'Тип уязвимости',
    'Класс и метод / Уязвимый файл',
    'Комментарий',
    'Статус',
    'CWSS',
    'Срок устранения',
    'Компенсирующие меры'
]


def get_remediation_period(severity, has_exploits):
    """
    Возвращает срок устранения в виде текстового периода (без привязки к дате)
    """
    if severity == 'CRITICAL':
        months = 6
    elif severity == 'HIGH':
        months = 9
    else:  # MEDIUM, LOW, UNKNOWN
        months = 12

    if has_exploits:
        months = max(1, months - 3)

    if months == 1:
        return "1 месяц"
    elif months in [2, 3, 4]:
        return f"{months} месяца"
    else:
        return f"{months} месяцев"


def get_remediation_days(severity, has_exploits):
    """
    Возвращает срок устранения в днях (30 дней = 1 месяц)
    """
    if severity == 'CRITICAL':
        months = 6
    elif severity == 'HIGH':
        months = 9
    else:  # MEDIUM, LOW, UNKNOWN
        months = 12

    if has_exploits:
        months = max(1, months - 3)

    return months * 30


def format_remaining_days(days):
    """
    Форматирует остаточный срок в днях для отображения в Excel
    """
    if days is None:
        return ''
    if days >= 0:
        return f"{days} дн."
    else:
        return f"просрочка {abs(days)} дн."


def get_remaining_days_style(days):
    """
    Возвращает стиль для ячейки с остаточным сроком
    """
    if days is None:
        return None

    # Если срок 0 или меньше (просрочка) — красный (как NEW)
    if days <= 0:
        return PatternFill(
            start_color='ffc7ce',
            end_color='ffc7ce',
            fill_type='solid'
        )
    # Если срок меньше 30 дней — желтый (как UNCHANGED)
    elif days < 30:
        return PatternFill(
            start_color='ffeb9c',
            end_color='ffeb9c',
            fill_type='solid'
        )

    return None


def get_min_remediation_days_for_group(vulns):
    """
    Вычисляет минимальный срок устранения для группы CVE.

    Для каждой CVE:
    - NEW: срок = get_remediation_days(severity, has_exploits)
    - UNCHANGED: срок = remaining_days (может быть отрицательным)

    Возвращает:
        (min_days, source_type, display_text)
    """
    if not vulns:
        return None, None, ''

    min_days = None
    min_source = None
    min_vuln = None

    for vuln in vulns:
        vuln_status = vuln.get('vuln_change_type', '') or vuln.get('vuln_status', '')
        severity = vuln.get('severity', 'UNKNOWN')
        has_exploits = vuln.get('has_exploits', False)

        if vuln_status == 'unchanged':
            remaining = vuln.get('remaining_days')
            if remaining is None:
                continue
            days = remaining
            source = 'unchanged'
        elif vuln_status == 'new':
            days = get_remediation_days(severity, has_exploits)
            source = 'new'
        else:
            continue

        if min_days is None or days < min_days:
            min_days = days
            min_source = source
            min_vuln = vuln

    if min_days is None:
        return None, None, ''

    if min_source == 'unchanged':
        if min_days >= 0:
            display_text = f"{min_days} дн."
        else:
            display_text = f"просрочка {abs(min_days)} дн."
    else:
        severity = min_vuln.get('severity', 'UNKNOWN')
        has_exploits = min_vuln.get('has_exploits', False)
        display_text = get_remediation_period(severity, has_exploits)

    return min_days, min_source, display_text


def generate_excel_report(enriched_trivy_path, output_dir, ptai_html_path=None, only_cache=False):
    """
    Основной метод генерации Excel отчета

    Если есть diff данные:
        - Лист 1: SCA Анализ (new + unchanged) - актуальные уязвимости
        - Лист 2: SCA NEW (только new) - новые уязвимости
        - Лист 3: SCA REMOVED (только removed) - исчезнувшие уязвимости
        - Лист 4: PTAI Анализ (опционально)

    Если diff данных нет:
        - Лист 1: SCA Анализ (все уязвимости)
        - Лист 2: PTAI Анализ (опционально)
    """
    try:
        with open(enriched_trivy_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)

        has_diff = '_diff_metadata' in trivy_data

        wb = openpyxl.Workbook()

        if 'Sheet' in wb.sheetnames:
            wb.remove(wb['Sheet'])

        if has_diff:
            print("   Добавление листа SCA Анализ (актуальные уязвимости: new + unchanged)...")
            add_sca_sheet(wb, enriched_trivy_path, sheet_name="SCA Анализ", diff_mode='full')

            print("   Добавление листа SCA NEW (только новые уязвимости)...")
            add_sca_sheet(wb, enriched_trivy_path, sheet_name="SCA NEW", diff_mode='new')

            print("   Добавление листа SCA REMOVED (только исчезнувшие уязвимости)...")
            add_sca_sheet(wb, enriched_trivy_path, sheet_name="SCA REMOVED", diff_mode='removed')
        else:
            print("   Добавление листа SCA Анализ (полный отчет)...")
            add_sca_sheet(wb, enriched_trivy_path, sheet_name="SCA Анализ", diff_mode='standard')

        # PTAI лист
        if ptai_html_path and Path(ptai_html_path).exists():
            trivy_name = Path(enriched_trivy_path).stem.replace('_enriched', '').replace('_only_cache', '')
            ptai_name = Path(ptai_html_path).stem

            if trivy_name == ptai_name:
                print(f"   Добавление листа PTAI Анализ из: {Path(ptai_html_path).name}...")
                create_ptai_sheet(wb, ptai_html_path)
            else:
                print(f"   ⚠️ Пропуск PTAI листа: имена файлов не совпадают")
                print(f"      Ожидалось: {trivy_name}.html, получено: {ptai_name}.html")
        else:
            if ptai_html_path is None:
                print("   ⚠️ PTAI отчет не найден, создаются только SCA листы")
            else:
                print(f"   ⚠️ PTAI отчет не существует: {ptai_html_path}")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        base_name = Path(enriched_trivy_path).stem.replace('_enriched', '').replace('_only_cache', '')
        if only_cache:
            output_path = output_dir / f"{base_name}_only_cache_report.xlsx"
        else:
            output_path = output_dir / f"{base_name}_report.xlsx"

        try:
            wb.save(output_path)
            print(f"   ✅ Excel файл сохранен: {output_path}")
        except PermissionError as e:
            print(f"   ❌ Ошибка сохранения Excel файла: {e}")
            print(f"   📁 Путь: {output_path}")
            print(f"   💡 Возможные причины:")
            print(f"      - Файл уже открыт в Excel или другой программе")
            print(f"      - Недостаточно прав для записи в папку {output_dir}")
            return None
        except Exception as e:
            print(f"   ❌ Неожиданная ошибка при сохранении Excel файла: {e}")
            print(f"   📁 Путь: {output_path}")
            return None

        sheets_created = ["SCA Анализ"]
        if has_diff:
            sheets_created.append("SCA NEW")
            sheets_created.append("SCA REMOVED")
        if ptai_html_path and Path(ptai_html_path).exists() and trivy_name == ptai_name:
            sheets_created.append("PTAI Анализ")
        print(f"   📊 Созданы листы: {', '.join(sheets_created)}")
        if has_diff:
            print(f"   🔍 Обнаружен diff анализ - созданы дополнительные листы NEW и REMOVED")

        return output_path

    except Exception as e:
        import traceback
        print(f"❌ ОШИБКА генерации Excel отчета: {e}")
        print(f"   Трассировка ошибки:")
        traceback.print_exc()
        return None


def generate_ptai_only_excel_report(ptai_html_path, output_dir):
    """
    Генерирует Excel отчет только с PTAI анализом (без SCA листа)
    """
    try:
        ptai_path = Path(ptai_html_path)

        if not ptai_path.exists():
            print(f"   ❌ PTAI файл не существует: {ptai_path}")
            return None

        wb = openpyxl.Workbook()

        if 'Sheet' in wb.sheetnames:
            wb.remove(wb['Sheet'])

        print(f"   Добавление листа PTAI Анализ из: {ptai_path.name}...")
        success = create_ptai_sheet(wb, ptai_path)

        if not success:
            return None

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / f"{ptai_path.stem}_ptai.xlsx"

        try:
            wb.save(output_path)
            print(f"   ✅ Excel файл (PTAI only) сохранен: {output_path}")
            return output_path
        except PermissionError as e:
            print(f"   ❌ Ошибка сохранения Excel файла: {e}")
            print(f"   📁 Путь: {output_path}")
            print(f"   💡 Возможные причины:")
            print(f"      - Файл уже открыт в Excel или другой программе")
            print(f"      - Недостаточно прав для записи в папку {output_dir}")
            return None
        except Exception as e:
            print(f"   ❌ Неожиданная ошибка при сохранении Excel файла: {e}")
            print(f"   📁 Путь: {output_path}")
            return None

    except Exception as e:
        import traceback
        print(f"❌ ОШИБКА генерации PTAI-only Excel отчета: {e}")
        traceback.print_exc()
        return None


def create_ptai_sheet(workbook, ptai_html_path, insert_position=None):
    """
    Создает лист PTAI Анализ в переданной книге
    """
    try:
        data, project_name = prepare_ptai_excel_data(ptai_html_path, debug=False)

        if not data:
            print(f"   ⚠️ Нет данных для PTAI листа в файле: {Path(ptai_html_path).name}")
            return False

        if insert_position is not None:
            ws = workbook.create_sheet("PTAI Анализ", insert_position)
        else:
            ws = workbook.create_sheet("PTAI Анализ")

        current_date = datetime.now()

        cell = ws.cell(row=1, column=1, value=f"Объект проверки: {project_name}")
        cell.font = INFO_FONT
        cell.alignment = Alignment(horizontal='left', vertical='center')

        cell = ws.cell(row=2, column=1, value=f"Дата построения отчета: {current_date.strftime('%d.%m.%Y')}")
        cell.font = INFO_FONT
        cell.alignment = Alignment(horizontal='left', vertical='center')

        cell = ws.cell(row=3, column=1, value=f"Источник: {Path(ptai_html_path).name}")
        cell.font = INFO_FONT
        cell.alignment = Alignment(horizontal='left', vertical='center')

        ws.row_dimensions[4].height = 10

        for col, header in enumerate(PTAI_COLUMN_HEADERS, 1):
            cell = ws.cell(row=5, column=col, value=header)
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            cell.border = CELL_BORDER

        for row, item in enumerate(data, 6):
            cell_num = ws.cell(row=row, column=1, value=row - 5)
            cell_num.border = CELL_BORDER
            cell_num.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            cell = ws.cell(row=row, column=2, value=item['ID уязвимости'])
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            cell = ws.cell(row=row, column=3, value=item['Тип уязвимости'])
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

            cell = ws.cell(row=row, column=4, value=item['Класс и метод / Уязвимый файл'])
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

            cell = ws.cell(row=row, column=5, value=item['Комментарий'])
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

            status_value = item['Статус']
            cell = ws.cell(row=row, column=6, value=status_value)
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            cwss_value = item['CWSS']
            if status_value.lower() == 'опровергнута' and not cwss_value:
                cwss_value = '—'
            cell = ws.cell(row=row, column=7, value=cwss_value)
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            cell = ws.cell(row=row, column=8)
            formula = f'''=IF(OR(ISBLANK(G{row}), NOT(ISNUMBER(G{row}))), "",
                IF(LOWER(F{row})="опровергнута", "—",
                    IF(G{row}>=75, "Устранение в текущем релизе / выпуск fix-патча",
                        IF(G{row}>=30, "Исправление в ближайших релизах / устранение в очередном патче",
                            IF(G{row}>=10, "Рекомендуется устранить в будущих релизах", "")
                        )
                    )
                )
            )'''
            cell.value = formula
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

            measures_value = item['Компенсирующие меры']
            if status_value.lower() == 'опровергнута' and not measures_value:
                measures_value = '—'
            cell = ws.cell(row=row, column=9, value=measures_value)
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        set_ptai_column_widths(ws)

        if data:
            ws.auto_filter.ref = f"A5:I{len(data) + 5}"

        ws.freeze_panes = 'A6'

        print(f"   ✅ Добавлено {len(data)} записей в лист PTAI Анализ")
        return True

    except Exception as e:
        print(f"   ❌ Ошибка создания PTAI листа: {e}")
        import traceback
        traceback.print_exc()
        return False


def add_ptai_sheet(workbook, html_file_path):
    """
    Обертка для обратной совместимости
    """
    return create_ptai_sheet(workbook, html_file_path)


def generate_ptai_only_reports_for_all(config, output_dir):
    """
    Генерирует PTAI-only Excel отчеты для всех HTML файлов в папке PTAI
    """
    from config_manager import get_ptai_reports_path

    ptai_dir = get_ptai_reports_path(config)

    if not ptai_dir:
        print(f"\n❌ Папка PTAI не найдена в {config['scan_directory']}/PTAI")
        return 0, 0

    ptai_files = list(ptai_dir.glob("*.html"))

    if not ptai_files:
        print(f"\n❌ В папке {ptai_dir} нет HTML файлов")
        return 0, 0

    print(f"\n📄 Найдено PTAI отчетов: {len(ptai_files)}")

    processed = 0
    success = 0

    for ptai_file in ptai_files:
        print(f"\n{'=' * 60}")
        print(f"ОБРАБОТКА PTAI: {ptai_file.name}")
        print(f"{'=' * 60}")

        result = generate_ptai_only_excel_report(ptai_file, output_dir)
        processed += 1
        if result:
            success += 1

    return processed, success


def collect_all_vulnerabilities(trivy_data):
    """
    Собирает ВСЕ вхождения уязвимостей БЕЗ дедупликации (standard режим)
    """
    all_vulns = []

    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            target = result.get('Target', 'Unknown')
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    if 'VulnerabilityID' not in vuln:
                        continue

                    pkg_path = vuln.get('PkgPath', 'N/A')
                    root_jar = extract_root_jar(pkg_path)

                    source_value = target
                    if root_jar and root_jar != 'N/A':
                        source_value = f"{target}\n({root_jar})"

                    path_without_root = pkg_path
                    if root_jar and pkg_path and pkg_path != 'N/A':
                        if pkg_path.startswith(root_jar + '/'):
                            path_without_root = pkg_path[len(root_jar) + 1:]
                        elif pkg_path == root_jar:
                            path_without_root = "(root)"

                        if path_without_root and path_without_root != 'N/A' and path_without_root != "(root)":
                            path_without_root = path_without_root.replace('BOOT-INF/', '')

                    sploitscan = vuln.get('sploitscan', {})
                    has_exploits = has_any_exploits(sploitscan)

                    severity = vuln.get('Severity', 'UNKNOWN')
                    remediation_period = get_remediation_period(severity, has_exploits)

                    all_vulns.append({
                        'source': source_value,
                        'path': path_without_root,
                        'package': vuln.get('PkgName', 'Unknown Package'),
                        'version': vuln.get('InstalledVersion', 'Unknown'),
                        'vulnerability_id': vuln['VulnerabilityID'],
                        'severity': severity,
                        'remediation_period': remediation_period,
                        'status': '',
                        'comment': ''
                    })

    return all_vulns


def collect_all_vulnerabilities_with_diff(trivy_data, diff_mode='standard'):
    """
    Собирает уязвимости с учетом diff статусов
    """
    if diff_mode == 'standard':
        return collect_all_vulnerabilities(trivy_data)

    all_vulns = []
    has_diff = '_diff_metadata' in trivy_data

    if not has_diff:
        return collect_all_vulnerabilities(trivy_data)

    if 'Results' not in trivy_data:
        return all_vulns

    for result in trivy_data['Results']:
        target = result.get('Target', 'Unknown')
        if 'Vulnerabilities' not in result:
            continue

        for vuln in result['Vulnerabilities']:
            if 'VulnerabilityID' not in vuln:
                continue

            vuln_change_type = vuln.get('_change_type')

            if diff_mode == 'full':
                if vuln_change_type not in ['new', 'unchanged']:
                    continue
            elif diff_mode == 'new':
                if vuln_change_type != 'new':
                    continue
            elif diff_mode == 'removed':
                if vuln_change_type != 'removed':
                    continue

            pkg_change_type = vuln.get('_package_change_type')

            version_change = ''
            if pkg_change_type == 'updated':
                version_change_data = vuln.get('_package_version_change', {})
                old_ver = version_change_data.get('old_version')
                new_ver = version_change_data.get('new_version')
                if old_ver and new_ver:
                    version_change = f"{old_ver} → {new_ver}"

            remaining_days = vuln.get('_remaining_days')

            pkg_path = vuln.get('PkgPath', 'N/A')
            root_jar = extract_root_jar(pkg_path)

            source_value = target
            if root_jar and root_jar != 'N/A':
                source_value = f"{target}\n({root_jar})"

            path_without_root = pkg_path
            if root_jar and pkg_path and pkg_path != 'N/A':
                if pkg_path.startswith(root_jar + '/'):
                    path_without_root = pkg_path[len(root_jar) + 1:]
                elif pkg_path == root_jar:
                    path_without_root = "(root)"

                if path_without_root and path_without_root != 'N/A' and path_without_root != "(root)":
                    path_without_root = path_without_root.replace('BOOT-INF/', '')

            sploitscan = vuln.get('sploitscan', {})
            has_exploits = has_any_exploits(sploitscan)

            severity = vuln.get('Severity', 'UNKNOWN')

            if vuln_change_type == 'unchanged' and remaining_days is not None:
                remediation_display = format_remaining_days(remaining_days)
            else:
                remediation_display = get_remediation_period(severity, has_exploits)

            vuln_data = {
                'source': source_value,
                'path': path_without_root,
                'package': vuln.get('PkgName', 'Unknown Package'),
                'version': vuln.get('InstalledVersion', 'Unknown'),
                'vulnerability_id': vuln['VulnerabilityID'],
                'severity': severity,
                'remediation_period': remediation_display,
                'status': '',
                'comment': '',
                'vuln_change_type': vuln_change_type,
                'package_change_type': pkg_change_type,
                'version_change': version_change,
                'remaining_days': remaining_days,
                'has_exploits': has_exploits
            }

            all_vulns.append(vuln_data)

    return all_vulns


def group_vulnerabilities_by_artifact(vulnerabilities):
    """
    Группирует уязвимости по уникальному артефакту (standard режим)
    """
    from collections import defaultdict

    groups = defaultdict(lambda: {
        'vulnerability_ids': set(),
        'severities': [],
        'severity_levels': [],
        'remediation_periods': [],
        'statuses': set(),
        'comments': set(),
        'source': None,
        'path': None,
        'package': None,
        'version': None
    })

    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}

    for vuln in vulnerabilities:
        key = (vuln['source'], vuln['path'], vuln['package'], vuln['version'])
        group = groups[key]

        group['source'] = vuln['source']
        group['path'] = vuln['path']
        group['package'] = vuln['package']
        group['version'] = vuln['version']

        group['vulnerability_ids'].add(vuln['vulnerability_id'])

        severity = vuln['severity']
        group['severities'].append(severity)
        group['severity_levels'].append((severity_order.get(severity, 0), severity))

        remediation_period = vuln['remediation_period']
        group['remediation_periods'].append((severity_order.get(severity, 0), remediation_period))

        if vuln.get('status'):
            group['statuses'].add(vuln['status'])
        if vuln.get('comment'):
            group['comments'].add(vuln['comment'])

    result = []
    for key, group in groups.items():
        vuln_ids_str = '\n'.join(sorted(group['vulnerability_ids']))

        unique_severities = []
        seen = set()
        for _, sev in sorted(group['severity_levels'], key=lambda x: x[0], reverse=True):
            if sev not in seen:
                seen.add(sev)
                unique_severities.append(sev)
        severity_str = '\n'.join(unique_severities)

        remediation_period = ''
        if group['remediation_periods']:
            sorted_periods = sorted(group['remediation_periods'], key=lambda x: x[0], reverse=True)
            remediation_period = sorted_periods[0][1]

        status_str = '\n'.join(sorted(group['statuses'])) if group['statuses'] else ''
        comment_str = '\n'.join(sorted(group['comments'])) if group['comments'] else ''

        result.append({
            'source': group['source'],
            'path': group['path'],
            'package': group['package'],
            'version': group['version'],
            'vulnerability_id': vuln_ids_str,
            'severity': severity_str,
            'remediation_period': remediation_period,
            'status': status_str,
            'comment': comment_str
        })

    return result


def group_vulnerabilities_by_package_for_diff(vulnerabilities):
    """
    Группирует уязвимости для diff режимов.
    Каждая CVE - отдельная строка.
    Дополнительно вычисляется минимальный срок устранения для группы (для листа 'SCA Анализ').
    """
    from collections import defaultdict

    groups = defaultdict(list)

    for vuln in vulnerabilities:
        key = (vuln['source'], vuln['path'], vuln['package'], vuln['version'])
        groups[key].append(vuln)

    result = []
    for (source, path, package, version), vulns in groups.items():
        package_change_type = None
        version_change = ''

        for v in vulns:
            if v.get('package_change_type'):
                package_change_type = v['package_change_type']
                if v.get('version_change'):
                    version_change = v['version_change']
                break

        # Вычисляем минимальный срок для группы
        min_days, min_source, min_display = get_min_remediation_days_for_group(vulns)

        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x['severity'], 0), reverse=True)

        group_size = len(sorted_vulns)

        for idx, vuln in enumerate(sorted_vulns):
            comment = vuln.get('comment', '')
            if package_change_type == 'updated' and version_change:
                if comment:
                    comment = f"{comment}\nВерсия пакета: {version_change}"
                else:
                    comment = f"Версия пакета: {version_change}"

            result.append({
                'source': source,
                'path': path,
                'package': package,
                'version': version,
                'package_change_type': package_change_type,
                'vulnerability_id': vuln['vulnerability_id'],
                'vuln_status': vuln.get('vuln_change_type', ''),
                'severity': vuln['severity'],
                'remediation_period': vuln['remediation_period'],
                'status': vuln.get('status', ''),
                'comment': comment,
                'remaining_days': vuln.get('remaining_days'),
                # Данные для группового срока
                'group_min_days': min_days,
                'group_min_source': min_source,
                'group_min_display': min_display,
                'is_first_in_group': (idx == 0),
                'group_size': group_size
            })

    return result


def extract_root_jar(pkg_path):
    """
    Извлекает корневой JAR файл из пути
    """
    if not pkg_path or pkg_path == 'N/A':
        return None

    parts = pkg_path.split('/')
    root = parts[0]
    if root.endswith('.jar') or root.endswith('.war') or root.endswith('.ear'):
        return root

    return None


def has_any_exploits(sploitscan):
    """
    Проверяет, есть ли эксплойты в любом источнике
    """
    if isinstance(sploitscan, list) and len(sploitscan) == 0:
        return False

    if not isinstance(sploitscan, dict) or not sploitscan:
        return False

    github_data = sploitscan.get('GitHub Data')
    if github_data and isinstance(github_data, dict):
        github_pocs = github_data.get('pocs', [])
        if github_pocs and len(github_pocs) > 0:
            return True

    exploitdb_list = sploitscan.get('ExploitDB Data', [])
    if exploitdb_list:
        for item in exploitdb_list:
            if isinstance(item, dict) and item.get('id'):
                return True

    nvd_data = sploitscan.get('NVD Data')
    if nvd_data and isinstance(nvd_data, dict):
        nvd_exploits = nvd_data.get('exploits', [])
        if nvd_exploits and len(nvd_exploits) > 0:
            return True

    metasploit_data = sploitscan.get('Metasploit Data')
    if metasploit_data and isinstance(metasploit_data, dict):
        metasploit_modules = metasploit_data.get('modules', [])
        if metasploit_modules:
            for module in metasploit_modules:
                if isinstance(module, dict) and module.get('url'):
                    return True

    return False


def get_artifact_name(report_filename):
    """
    Извлекает имя артефакта из имени файла
    """
    name = Path(report_filename).stem
    name = name.replace('_enriched', '')
    name = name.replace('_only_cache', '')
    return name


def add_info_block(worksheet, artifact_name, current_date, description, diff_mode='standard'):
    """
    Добавляет информационный блок в начало отчета
    """
    date_str = current_date.strftime('%d.%m.%Y')

    cell = worksheet.cell(row=1, column=1, value=f"Объект проверки: {artifact_name}")
    cell.font = INFO_FONT
    cell.alignment = Alignment(horizontal='left', vertical='center')

    cell = worksheet.cell(row=2, column=1, value=f"Дата построения отчета: {date_str}")
    cell.font = INFO_FONT
    cell.alignment = Alignment(horizontal='left', vertical='center')

    cell = worksheet.cell(row=3, column=1, value=description)
    cell.font = INFO_FONT
    cell.alignment = Alignment(horizontal='left', vertical='center')

    if diff_mode == 'standard':
        num_cols = len(SCA_COLUMN_HEADERS)
    elif diff_mode in ['new', 'removed']:
        num_cols = len(SCA_DIFF_SHORT_COLUMN_HEADERS)
    else:
        num_cols = len(SCA_DIFF_COLUMN_HEADERS)

    for row in range(1, 4):
        worksheet.merge_cells(start_row=row, start_column=1, end_row=row, end_column=num_cols)

    worksheet.row_dimensions[4].height = 10


def add_dropdown_lists(worksheet, num_rows, start_row, workbook):
    """
    Добавляет выпадающие списки со статусами в колонку I (Статус)
    """
    if num_rows == 0:
        return

    hidden_sheet = workbook.create_sheet("_status_reference")
    hidden_sheet.sheet_state = 'hidden'

    for i, status in enumerate(STATUS_OPTIONS, 1):
        hidden_sheet.cell(row=i, column=1, value=status)

    ref_range = f"'_status_reference'!$A$1:$A${len(STATUS_OPTIONS)}"

    for row_num in range(start_row + 1, start_row + num_rows + 1):
        cell_ref = f"I{row_num}"

        dv = openpyxl.worksheet.datavalidation.DataValidation(
            type='list',
            formula1=ref_range,
            allow_blank=True,
            showErrorMessage=True,
            showInputMessage=True,
            promptTitle='Выберите статус',
            prompt='Пожалуйста, выберите статус из выпадающего списка',
            errorTitle='Недопустимое значение',
            error='Вы можете выбрать ТОЛЬКО значение из выпадающего списка!'
        )

        worksheet.add_data_validation(dv)
        dv.add(cell_ref)


def merge_package_cells(worksheet, data, start_row, col_package, col_version, col_status=None):
    """
    Объединяет ячейки для одинаковых источник + путь + пакет + версия
    """
    if not data:
        return

    current_key = None
    start_merge_row = start_row

    for i, vuln in enumerate(data, start_row):
        key = (vuln['source'], vuln['path'], vuln['package'], vuln['version'])

        if key != current_key:
            if current_key is not None and start_merge_row < i:
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=2,
                    end_row=i - 1,
                    end_column=2
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=3,
                    end_row=i - 1,
                    end_column=3
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=col_package,
                    end_row=i - 1,
                    end_column=col_package
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=col_version,
                    end_row=i - 1,
                    end_column=col_version
                )
                if col_status:
                    worksheet.merge_cells(
                        start_row=start_merge_row,
                        start_column=col_status,
                        end_row=i - 1,
                        end_column=col_status
                    )

                for row in range(start_merge_row, i):
                    for col in [2, 3, col_package, col_version]:
                        cell = worksheet.cell(row=row, column=col)
                        cell.alignment = Alignment(horizontal='center', vertical='center')
                    if col_status:
                        cell = worksheet.cell(row=row, column=col_status)
                        cell.alignment = Alignment(horizontal='center', vertical='center')

            current_key = key
            start_merge_row = i

        if i == len(data) + start_row - 1:
            if start_merge_row <= i:
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=2,
                    end_row=i,
                    end_column=2
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=3,
                    end_row=i,
                    end_column=3
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=col_package,
                    end_row=i,
                    end_column=col_package
                )
                worksheet.merge_cells(
                    start_row=start_merge_row,
                    start_column=col_version,
                    end_row=i,
                    end_column=col_version
                )
                if col_status:
                    worksheet.merge_cells(
                        start_row=start_merge_row,
                        start_column=col_status,
                        end_row=i,
                        end_column=col_status
                    )

                for row in range(start_merge_row, i + 1):
                    for col in [2, 3, col_package, col_version]:
                        cell = worksheet.cell(row=row, column=col)
                        cell.alignment = Alignment(horizontal='center', vertical='center')
                    if col_status:
                        cell = worksheet.cell(row=row, column=col_status)
                        cell.alignment = Alignment(horizontal='center', vertical='center')


def merge_remediation_column(worksheet, data, start_row, col_remediation):
    """
    Объединяет ячейки в колонке "Срок устранения" для групп (источник + путь + пакет + версия).
    Значение в объединённой ячейке - минимальный срок группы.
    Стиль применяется к объединённой ячейке.
    """
    if not data:
        return

    current_key = None
    start_merge_row = start_row

    def _apply_group_merge(start_r, end_r, vuln):
        """Применяет объединение и стиль к группе"""
        cell = worksheet.cell(row=start_r, column=col_remediation)
        cell.value = vuln.get('group_min_display', '')
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        min_days = vuln.get('group_min_days')
        min_source = vuln.get('group_min_source')

        if min_days is not None and min_source == 'unchanged':
            style = get_remaining_days_style(min_days)
            if style:
                cell.fill = style

        if end_r > start_r:
            worksheet.merge_cells(
                start_row=start_r,
                start_column=col_remediation,
                end_row=end_r,
                end_column=col_remediation
            )

        for row in range(start_r, end_r + 1):
            c = worksheet.cell(row=row, column=col_remediation)
            c.border = CELL_BORDER
            c.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

    for i, vuln in enumerate(data, start_row):
        key = (vuln['source'], vuln['path'], vuln['package'], vuln['version'])

        if key != current_key:
            if current_key is not None and start_merge_row < i:
                # ИСПРАВЛЕНО: индекс первой CVE группы (без -1)
                prev_idx = start_merge_row - start_row
                prev_vuln = data[prev_idx]
                _apply_group_merge(start_merge_row, i - 1, prev_vuln)

            current_key = key
            start_merge_row = i

        # Последняя группа
        if i == len(data) + start_row - 1:
            if start_merge_row <= i:
                # ИСПРАВЛЕНО: индекс первой CVE группы (без -1)
                prev_idx = start_merge_row - start_row
                prev_vuln = data[prev_idx]
                _apply_group_merge(start_merge_row, i, prev_vuln)


def add_sca_sheet(workbook, enriched_trivy_path, sheet_name="SCA Анализ", diff_mode='standard'):
    """
    Добавляет лист с SCA анализом из Trivy

    Для standard режима:
        - Группировка по (источник + путь + пакет + версия)
        - Все CVE склеиваются в одну ячейку через перенос строки

    Для diff режимов:
        - 'full': полный отчет с объединением срока устранения по группе
        - 'new': только NEW, без колонок "Срок устранения" и "Статус"
        - 'removed': только REMOVED, без колонок "Срок устранения" и "Статус"
    """
    with open(enriched_trivy_path, 'r', encoding='utf-8-sig') as f:
        trivy_data = json.load(f)

    ws = workbook.create_sheet(sheet_name)

    all_vulnerabilities = collect_all_vulnerabilities_with_diff(trivy_data, diff_mode)

    if diff_mode == 'standard':
        grouped_vulnerabilities = group_vulnerabilities_by_artifact(all_vulnerabilities)
    else:
        grouped_vulnerabilities = group_vulnerabilities_by_package_for_diff(all_vulnerabilities)

    artifact_name = get_artifact_name(Path(enriched_trivy_path).name)
    current_date = datetime.now()

    if diff_mode == 'new':
        description = "📌 НОВЫЕ уязвимости и пакеты, появившиеся во втором сканировании"
    elif diff_mode == 'removed':
        description = "📌 Уязвимости и пакеты, которые ИСЧЕЗЛИ во втором сканировании"
    elif diff_mode == 'full':
        description = "📌 АКТУАЛЬНЫЕ уязвимости (новые + существующие в обоих сканированиях)"
    else:
        description = "Необходимо обновить уязвимые компоненты до актуальных версий в указанный срок или обосновать отсутствие такой возможности"

    add_info_block(ws, artifact_name, current_date, description, diff_mode)

    # Определяем заголовки
    if diff_mode == 'standard':
        headers = SCA_COLUMN_HEADERS
    elif diff_mode in ['new', 'removed']:
        headers = SCA_DIFF_SHORT_COLUMN_HEADERS
    else:
        headers = SCA_DIFF_COLUMN_HEADERS

    start_row = 5
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=start_row, column=col_num, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.border = CELL_BORDER

    # Заполняем данные
    for row_num, vuln in enumerate(grouped_vulnerabilities, start_row + 1):
        col = 1

        # №
        cell = ws.cell(row=row_num, column=col, value=row_num - start_row)
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='center', vertical='center')
        col += 1

        # Источник
        cell = ws.cell(row=row_num, column=col, value=vuln['source'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        col += 1

        # Путь
        cell = ws.cell(row=row_num, column=col, value=vuln['path'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        col += 1

        # Пакет
        cell = ws.cell(row=row_num, column=col, value=vuln['package'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        col += 1

        # Версия
        cell = ws.cell(row=row_num, column=col, value=vuln['version'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        col += 1

        # Статус пакета (только для diff режимов)
        if diff_mode != 'standard':
            pkg_status = vuln.get('package_change_type', '')
            cell = ws.cell(row=row_num, column=col, value=pkg_status.upper() if pkg_status else '')
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center')

            if pkg_status:
                apply_change_status_style(cell, pkg_status)
            col += 1

        # Идентификатор уязвимости
        cell = ws.cell(row=row_num, column=col, value=vuln['vulnerability_id'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        col += 1

        # Статус уязвимости (только для diff режимов)
        if diff_mode != 'standard':
            vuln_status = vuln.get('vuln_status', '')
            cell = ws.cell(row=row_num, column=col, value=vuln_status.upper() if vuln_status else '')
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center')

            if vuln_status:
                apply_change_status_style(cell, vuln_status)
            col += 1

        # Уровень критичности
        cell = ws.cell(row=row_num, column=col, value=vuln['severity'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        col += 1

        # ===== СРОК УСТРАНЕНИЯ (только для 'standard' и 'full') =====
        if diff_mode in ['standard', 'full']:
            if diff_mode == 'standard':
                cell = ws.cell(row=row_num, column=col, value=vuln['remediation_period'])
                cell.border = CELL_BORDER
                cell.alignment = Alignment(horizontal='center', vertical='center')
            else:  # full (diff)
                # Значение и объединение будут проставлены позже в merge_remediation_column
                cell = ws.cell(row=row_num, column=col)
                cell.border = CELL_BORDER
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            col += 1

        # Статус (только для 'standard' и 'full')
        if diff_mode in ['standard', 'full']:
            cell = ws.cell(row=row_num, column=col, value=vuln['status'])
            cell.border = CELL_BORDER
            cell.alignment = Alignment(horizontal='center', vertical='center')
            col += 1

        # Комментарий
        cell = ws.cell(row=row_num, column=col, value=vuln['comment'])
        cell.border = CELL_BORDER
        cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

    # Объединение ячеек для diff режимов (пакет/версия/статус пакета)
    if diff_mode != 'standard' and grouped_vulnerabilities:
        merge_package_cells(
            ws, grouped_vulnerabilities, start_row + 1,
            col_package=4, col_version=5, col_status=6
        )

    # Объединение срока устранения для 'full'
    if diff_mode == 'full' and grouped_vulnerabilities:
        merge_remediation_column(
            ws, grouped_vulnerabilities, start_row + 1,
            col_remediation=10
        )

    # Выпадающие списки только для standard
    if grouped_vulnerabilities and diff_mode == 'standard':
        add_dropdown_lists(ws, len(grouped_vulnerabilities), start_row, workbook)

    set_sca_column_widths(ws, diff_mode)

    if grouped_vulnerabilities:
        last_col = len(headers)
        ws.auto_filter.ref = f"A{start_row}:{get_column_letter(last_col)}{len(grouped_vulnerabilities) + start_row}"

    ws.freeze_panes = f'A{start_row + 1}'


def set_sca_column_widths(worksheet, diff_mode='standard'):
    """
    Устанавливает ширину колонок для SCA листа
    """
    if diff_mode == 'standard':
        for col, width in SCA_COLUMN_WIDTHS.items():
            worksheet.column_dimensions[col].width = width
    elif diff_mode in ['new', 'removed']:
        # 10 колонок (без "Срок устранения" и "Статус")
        short_widths = {
            'A': 8,
            'B': 40,
            'C': 50,
            'D': 35,
            'E': 20,
            'F': 18,
            'G': 20,
            'H': 18,
            'I': 15,
            'J': 45
        }
        for col, width in short_widths.items():
            worksheet.column_dimensions[col].width = width
    else:  # full
        full_widths = {
            'A': 8,
            'B': 40,
            'C': 50,
            'D': 35,
            'E': 20,
            'F': 18,
            'G': 20,
            'H': 18,
            'I': 15,
            'J': 25,
            'K': 25,
            'L': 45
        }
        for col, width in full_widths.items():
            worksheet.column_dimensions[col].width = width


def set_ptai_column_widths(worksheet):
    """
    Устанавливает ширину колонок для PTAI листа
    """
    for col, width in PTAI_COLUMN_WIDTHS.items():
        worksheet.column_dimensions[col].width = width


def apply_change_status_style(cell, status):
    """
    Применяет цветовое форматирование для статусов изменений
    """
    status_lower = status.lower().strip()

    status_colors = {
        'new': 'ffc7ce',
        'unchanged': 'ffeb9c',
        'updated': '70a1db',
        'removed': 'c6efce'
    }

    color = status_colors.get(status_lower)

    if color:
        cell.fill = PatternFill(
            start_color=color,
            end_color=color,
            fill_type='solid'
        )


def main():
    """
    Основная функция для тестирования
    """
    import sys
    from config_manager import load_config

    config = load_config()

    if len(sys.argv) > 1:
        enriched_path = Path(sys.argv[1])
        output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(config.get('output_directory', './reports'))
        ptai_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None

        if enriched_path.exists():
            result = generate_excel_report(enriched_path, output_dir, ptai_path)
            if result:
                print(f"\n✅ Отчет создан: {result}")
            else:
                print("\n❌ Ошибка при создании отчета")
        else:
            print(f"❌ Файл не найден: {enriched_path}")
    else:
        script_dir = Path(__file__).parent
        enriched_files = list(script_dir.glob("*_enriched.json"))

        if not enriched_files:
            print("Нет обогащенных отчетов Trivy")
            return

        for enriched_file in enriched_files:
            print(f"\n{'=' * 60}")
            print(f"Генерация Excel отчета для: {enriched_file.name}")
            print(f"{'=' * 60}")

            output_dir = Path(config.get('output_directory', './reports'))
            result = generate_excel_report(enriched_file, output_dir)

            if result:
                print(f"✅ Отчет создан: {result}")
            else:
                print(f"❌ Ошибка при создании отчета для {enriched_file.name}")


if __name__ == "__main__":
    main()