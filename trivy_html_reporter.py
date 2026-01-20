# trivy_html_reporter.py
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from html_templates import get_base_html, get_css_styles, get_javascript


def generate_trivy_html_report(enriched_trivy_path, output_dir=None):
    """
    Генерирует HTML отчет из обогащенного отчета Trivy в стиле SploitScan
    """
    try:
        # Загружаем обогащенный отчет
        with open(enriched_trivy_path, 'r', encoding='utf-8-sig') as f:
            trivy_data = json.load(f)

        # Определяем путь для сохранения
        if output_dir is None:
            # Если не указан, пробуем получить из конфига
            from config_manager import load_config
            config = load_config()
            output_dir = Path(config.get('output_directory', Path(__file__).parent))
        else:
            output_dir = Path(output_dir)

        # Создаем директорию, если её нет
        output_dir.mkdir(parents=True, exist_ok=True)

        # Сохраняем в указанной директории
        output_path = output_dir / f"{enriched_trivy_path.stem}_report.html"

        # Собираем статистику и данные
        stats, grouped_vulnerabilities = collect_statistics_and_group_data(trivy_data)

        # Генерируем HTML
        html_content = generate_html_content(trivy_data, stats, grouped_vulnerabilities, enriched_trivy_path.name)

        # Сохраняем файл
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"HTML отчет создан: {output_path}")
        return output_path

    except Exception as e:
        import traceback
        print(f"ОШИБКА генерации HTML отчета: {e}")
        print(f"Трассировка ошибки:")
        traceback.print_exc()
        return None


def collect_statistics_and_group_data(trivy_data):
    """
    Собирает статистику и группирует уязвимости по разделам и пакетам
    """
    stats = {
        'total_cves': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'with_exploits': 0,
        'cisa_kev': 0,
        'unique_total': 0,
        'unique_critical': 0,
        'unique_high': 0,
        'unique_medium': 0,
        'unique_low': 0,
        'unique_unknown': 0,
        'unique_exploits': 0,
        # Статистика по эксплойтам по уровням критичности (все уязвимости)
        'critical_with_exploits': 0,
        'high_with_exploits': 0,
        'medium_with_exploits': 0,
        'low_with_exploits': 0,
        'unknown_with_exploits': 0,
        # Статистика по уникальным эксплойтам по уровням критичности
        'unique_critical_with_exploits': 0,
        'unique_high_with_exploits': 0,
        'unique_medium_with_exploits': 0,
        'unique_low_with_exploits': 0,
        'unique_unknown_with_exploits': 0
    }

    grouped_vulnerabilities = defaultdict(lambda: defaultdict(list))
    processed_cves = {}  # Для отслеживания уникальных CVE и их атрибутов: {cve_id: {'severity': '', 'has_exploits': bool}}

    if 'Results' in trivy_data:
        for result in trivy_data['Results']:
            # Используем Type для группировки, если есть, иначе Target
            section_type = result.get('Type', result.get('Class', 'Unknown'))
            target = result.get('Target', 'Unknown')

            # Создаем понятное имя раздела
            if section_type and section_type != 'Unknown':
                section_name = f"{section_type} ({target})"
            else:
                section_name = target

            if 'Vulnerabilities' in result:
                # СОРТИРОВКА: Сортируем уязвимости по severity перед добавлением
                vulnerabilities_sorted = sorted(
                    result['Vulnerabilities'],
                    key=lambda x: get_severity_weight(x.get('Severity', 'UNKNOWN')),
                    reverse=True  # По убыванию критичности
                )

                for vuln in vulnerabilities_sorted:
                    if 'VulnerabilityID' in vuln:
                        cve_id = vuln['VulnerabilityID']
                        severity = vuln.get('Severity', 'UNKNOWN').upper()
                        has_exploits = has_any_exploits(vuln.get('sploitscan', {}))

                        # Общая статистика (все уязвимости, включая дубли)
                        stats['total_cves'] += 1

                        if severity == 'CRITICAL':
                            stats['critical'] += 1
                            if has_exploits:
                                stats['critical_with_exploits'] += 1
                        elif severity == 'HIGH':
                            stats['high'] += 1
                            if has_exploits:
                                stats['high_with_exploits'] += 1
                        elif severity == 'MEDIUM':
                            stats['medium'] += 1
                            if has_exploits:
                                stats['medium_with_exploits'] += 1
                        elif severity == 'LOW':
                            stats['low'] += 1
                            if has_exploits:
                                stats['low_with_exploits'] += 1
                        else:
                            stats['unknown'] += 1
                            if has_exploits:
                                stats['unknown_with_exploits'] += 1

                        if has_exploits:
                            stats['with_exploits'] += 1

                        # Уникальная статистика
                        if cve_id not in processed_cves:
                            processed_cves[cve_id] = {
                                'severity': severity,
                                'has_exploits': has_exploits
                            }
                            stats['unique_total'] += 1

                            # Уникальная статистика по severity
                            if severity == 'CRITICAL':
                                stats['unique_critical'] += 1
                                if has_exploits:
                                    stats['unique_critical_with_exploits'] += 1
                            elif severity == 'HIGH':
                                stats['unique_high'] += 1
                                if has_exploits:
                                    stats['unique_high_with_exploits'] += 1
                            elif severity == 'MEDIUM':
                                stats['unique_medium'] += 1
                                if has_exploits:
                                    stats['unique_medium_with_exploits'] += 1
                            elif severity == 'LOW':
                                stats['unique_low'] += 1
                                if has_exploits:
                                    stats['unique_low_with_exploits'] += 1
                            else:
                                stats['unique_unknown'] += 1
                                if has_exploits:
                                    stats['unique_unknown_with_exploits'] += 1

                            # Уникальная статистика по эксплойтам
                            if has_exploits:
                                stats['unique_exploits'] += 1

                            # Статистика по CISA KEV (только для уникальных CVE)
                            if is_cisa_kev(vuln):
                                stats['cisa_kev'] += 1

                        # Группировка по пакетам (все уязвимости, включая дубли)
                        pkg_name = vuln.get('PkgName', 'Unknown Package')
                        grouped_vulnerabilities[section_name][pkg_name].append(vuln)

    return stats, grouped_vulnerabilities


def get_severity_weight(severity):
    """
    Возвращает вес severity для сортировки (чем выше вес, тем критичнее)
    """
    severity_weights = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'UNKNOWN': 0
    }
    return severity_weights.get(severity.upper(), 0)


def has_any_exploits(sploitscan):
    """Проверяет, есть ли эксплойты в любом источнике"""
    # Если sploitscan - пустой список (ошибка сканирования)
    if isinstance(sploitscan, list) and len(sploitscan) == 0:
        return False

    # Если sploitscan - не словарь или пустой словарь
    if not isinstance(sploitscan, dict) or not sploitscan:
        return False

    # 1. Проверяем GitHub PoCs
    github_data = sploitscan.get('GitHub Data')
    if github_data and isinstance(github_data, dict):
        github_pocs = github_data.get('pocs', [])
        if github_pocs and len(github_pocs) > 0:
            return True

    # 2. Проверяем ExploitDB Data (по полю id)
    exploitdb_list = sploitscan.get('ExploitDB Data', [])
    if exploitdb_list:
        for item in exploitdb_list:
            if isinstance(item, dict) and item.get('id'):
                return True

    # 3. Проверяем NVD Data exploits
    nvd_data = sploitscan.get('NVD Data')
    if nvd_data and isinstance(nvd_data, dict):
        nvd_exploits = nvd_data.get('exploits', [])
        if nvd_exploits and len(nvd_exploits) > 0:
            return True

    # 4. Проверяем Metasploit Data modules
    metasploit_data = sploitscan.get('Metasploit Data')
    if metasploit_data and isinstance(metasploit_data, dict):
        metasploit_modules = metasploit_data.get('modules', [])
        if metasploit_modules:
            for module in metasploit_modules:
                if isinstance(module, dict) and module.get('url'):
                    return True

    return False


def is_cisa_kev(vuln):
    """Проверяет, есть ли CVE в CISA KEV"""
    sploitscan = vuln.get('sploitscan')

    # Если sploitscan - пустой список (ошибка сканирования)
    if isinstance(sploitscan, list) and len(sploitscan) == 0:
        return False

    # Если sploitscan - не словарь или пустой словарь
    if not isinstance(sploitscan, dict) or not sploitscan:
        return False

    cisa_data = sploitscan.get('CISA Data', {})
    cisa_status = cisa_data.get('cisa_status', 'Not scanned')  # ← Меняем дефолт

    return cisa_status in ['Listed', 'Yes', 'YES', 'listed', 'yes']


def format_epss(epss_score):
    """Форматирует EPSS score в проценты"""
    if epss_score == 'Not scanned' or epss_score == 'N/A':
        return 'Not scanned'
    try:
        # Умножаем на 100 и форматируем с 2 знаками после запятой
        return f"{float(epss_score) * 100:.2f}%"
    except (ValueError, TypeError):
        return 'Not scanned'


def get_cvss_data(vuln):
    """Извлекает CVSS данные с учетом приоритетов вендоров"""
    cvss_data = vuln.get('CVSS', {})
    severity_source = vuln.get('SeveritySource', '')
    vendor_severity = vuln.get('VendorSeverity', {})

    # 1. Пытаемся взять из того же источника что и Severity
    if severity_source and severity_source in cvss_data:
        data = cvss_data[severity_source]
        v3_score = data.get('V3Score')
        v2_score = data.get('V2Score')
        v3_vector = data.get('V3Vector')
        v2_vector = data.get('V2Vector')

        # Предпочитаем V3 над V2
        if v3_score is not None:
            return v3_score, v3_vector or v2_vector or 'N/A'
        elif v2_score is not None:
            return v2_score, v2_vector or 'N/A'

    # 2. Ищем источник с максимальным VendorSeverity
    if vendor_severity:
        # Сортируем вендоров по убыванию VendorSeverity
        sorted_vendors = sorted(vendor_severity.items(), key=lambda x: x[1], reverse=True)
        for vendor, score in sorted_vendors:
            if vendor in cvss_data:
                data = cvss_data[vendor]
                v3_score = data.get('V3Score')
                v2_score = data.get('V2Score')
                v3_vector = data.get('V3Vector')
                v2_vector = data.get('V2Vector')

                # Предпочитаем V3 над V2
                if v3_score is not None:
                    return v3_score, v3_vector or v2_vector or 'N/A'
                elif v2_score is not None:
                    return v2_score, v2_vector or 'N/A'

    # 3. Fallback: берем первого попавшегося (оригинальная логика)
    for source, data in cvss_data.items():
        v3_score = data.get('V3Score')
        v2_score = data.get('V2Score')
        v3_vector = data.get('V3Vector')
        v2_vector = data.get('V2Vector')

        # Предпочитаем V3 над V2
        if v3_score is not None:
            return v3_score, v3_vector or v2_vector or 'N/A'
        elif v2_score is not None:
            return v2_score, v2_vector or 'N/A'

    return 'N/A', 'N/A'


def generate_html_content(trivy_data, stats, grouped_vulnerabilities, report_filename):
    """
    Генерирует полный HTML контент
    """
    from config_manager import load_config

    config = load_config()
    project_version = config.get('project_version', '1.0.0')
    artifact_name = get_artifact_name(report_filename)

    main_content = generate_main_content(stats, grouped_vulnerabilities)

    html = get_base_html().format(
        main_content=main_content,
        artifact_name=artifact_name,
        project_version=project_version,
        total_cves=stats['total_cves'],
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        css_styles=get_css_styles(),
        javascript=get_javascript()
    )

    return html


def generate_main_content(stats, grouped_vulnerabilities):
    """
    Генерирует основное содержимое отчета
    """
    # Статистические карточки
    stats_cards = generate_stats_cards(stats)

    # Контент с группировкой по разделам
    vulnerabilities_content = generate_vulnerabilities_content(grouped_vulnerabilities)

    return f"""
    <div class="grid grid-cols-1 lg:grid-cols-[290px_minmax(0,1fr)] gap-6">
      <!-- Sidebar -->
      <aside class="no-print hidden lg:block">
        {generate_sidebar(grouped_vulnerabilities)}
      </aside>

      <!-- Main column -->
      <section>
        <!-- Summary dashboard -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-7 gap-4 mb-6">
          {stats_cards}
        </div>

        <!-- Counter for visible cards -->
        <div id="visibleCounter" class="mb-4 px-3 py-2 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 rounded-md text-sm font-medium hidden">
          <span id="visibleCount">0</span> of <span id="totalCount">{stats['total_cves']}</span> vulnerabilities visible
        </div>

        <!-- Vulnerabilities by section -->
        <div class="space-y-6">
          {vulnerabilities_content}
        </div>
      </section>
    </div>
    """


def generate_stats_cards(stats):
    """Генерирует карточки со статистикой"""
    total = stats["total_cves"]
    unique_total = stats["unique_total"]

    # Рассчитываем проценты для каждого уровня критичности (от общего количества)
    critical_percent = f"{(stats['critical'] / total * 100):.1f}%" if total > 0 else "0%"
    high_percent = f"{(stats['high'] / total * 100):.1f}%" if total > 0 else "0%"
    medium_percent = f"{(stats['medium'] / total * 100):.1f}%" if total > 0 else "0%"
    low_percent = f"{(stats['low'] / total * 100):.1f}%" if total > 0 else "0%"
    unknown_percent = f"{(stats['unknown'] / total * 100):.1f}%" if total > 0 else "0%"
    exploits_percent = f"{(stats['with_exploits'] / total * 100):.1f}%" if total > 0 else "0%"

    cards = [
        # Total CVEs card (без изменений)
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">Total CVEs</div>
                <div class="mt-2 text-2xl font-semibold">{total}</div>
                <div class="text-xs muted mt-1">Unique: {unique_total}</div>
            </div>
        </div>''',

        # Critical card
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">Critical</div>
                <div class="mt-2 text-2xl font-semibold text-red-600">{stats["critical"]}</div>
                <div class="text-xs muted mt-1">{critical_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_critical"]}</div>
                <div class="text-xs text-purple-600 font-medium mt-1 tooltip" data-tip="Exploits (Total / Unique)">
                    Exp: {stats["critical_with_exploits"]}/{stats["unique_critical_with_exploits"]}
                </div>
            </div>
        </div>''',

        # High card
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">High</div>
                <div class="mt-2 text-2xl font-semibold text-orange-600">{stats["high"]}</div>
                <div class="text-xs muted mt-1">{high_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_high"]}</div>
                <div class="text-xs text-purple-600 font-medium mt-1 tooltip" data-tip="Exploits (Total / Unique)">
                    Exp: {stats["high_with_exploits"]}/{stats["unique_high_with_exploits"]}
                </div>
            </div>
        </div>''',

        # Medium card
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">Medium</div>
                <div class="mt-2 text-2xl font-semibold text-yellow-600">{stats["medium"]}</div>
                <div class="text-xs muted mt-1">{medium_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_medium"]}</div>
                <div class="text-xs text-purple-600 font-medium mt-1 tooltip" data-tip="Exploits (Total / Unique)">
                    Exp: {stats["medium_with_exploits"]}/{stats["unique_medium_with_exploits"]}
                </div>
            </div>
        </div>''',

        # Low card
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">Low</div>
                <div class="mt-2 text-2xl font-semibold text-green-600">{stats["low"]}</div>
                <div class="text-xs muted mt-1">{low_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_low"]}</div>
                <div class="text-xs text-purple-600 font-medium mt-1 tooltip" data-tip="Exploits (Total / Unique)">
                    Exp: {stats["low_with_exploits"]}/{stats["unique_low_with_exploits"]}
                </div>
            </div>
        </div>''',

        # Unknown card
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">Unknown</div>
                <div class="mt-2 text-2xl font-semibold text-gray-600">{stats["unknown"]}</div>
                <div class="text-xs muted mt-1">{unknown_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_unknown"]}</div>
                <div class="text-xs text-purple-600 font-medium mt-1 tooltip" data-tip="Exploits (Total / Unique)">
                    Exp: {stats["unknown_with_exploits"]}/{stats["unique_unknown_with_exploits"]}
                </div>
            </div>
        </div>''',

        # Exploits card (без изменений)
        f'''<div class="card">
            <div class="card-body text-center">
                <div class="muted text-xs">With Exploits</div>
                <div class="mt-2 text-2xl font-semibold text-purple-600">{stats["with_exploits"]}</div>
                <div class="text-xs muted mt-1">{exploits_percent}</div>
                <div class="text-xs muted">Unique: {stats["unique_exploits"]}</div>
            </div>
        </div>'''
    ]
    return '\n'.join(cards)


def generate_sidebar(grouped_vulnerabilities):
    """Генерирует боковую панель с навигацией в виде дерева"""

    sections_list = []

    for section_name, packages in grouped_vulnerabilities.items():
        # Создаем ID для секции
        section_id = section_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')

        # Создаем список пакетов для этой секции
        packages_list = []
        for pkg_name in packages.keys():
            # Создаем ID для пакета (комбинация section_id + pkg_name)
            pkg_id = f"{section_id}__{pkg_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')}"
            packages_list.append(
                f'<a href="#{pkg_id}" class="block rounded px-2 py-1 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 pl-6 break-words" title="{pkg_name}">{pkg_name}</a>'
            )

        packages_html = '\n'.join(packages_list)

        sections_list.append(f"""
        <div class="tree-item mb-1" data-section-id="{section_id}">
          <div class="flex items-start justify-between">
            <a href="#{section_id}" class="flex-1 rounded px-2 py-1 text-sm font-medium hover:bg-gray-100 dark:hover:bg-gray-700 break-words min-w-0 section-link">
              <span class="inline-block align-middle">{section_name}</span>
            </a>
            <button class="section-toggle ml-1 p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-700 flex-shrink-0 mt-0.5" 
                    data-section="{section_id}"
                    title="Show packages">
              <svg class="h-4 w-4 transform transition-transform duration-200" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
          </div>
          <div id="section-{section_id}" class="section-content hidden pl-2 mt-1" data-packages-count="{len(packages)}">
            {packages_html if packages_html else '<div class="text-xs muted px-4 py-1">No packages</div>'}
          </div>
        </div>
        """)

    sections_html = '\n'.join(sections_list)

    return f"""
    <div class="sticky sticky-sidebar">
      <div class="sections-container scrollbar-hide">
        <!-- Filters -->
        <div class="card mb-4">
          <div class="card-header">
            <h2 class="text-sm font-semibold tracking-wide uppercase muted">Filters</h2>
          </div>
          <div class="card-body space-y-3">
            <div>
              <label class="block text-xs font-medium muted mb-1">Quick search (CVE ID or Package)</label>
              <input id="searchInput" type="text" placeholder="Search CVE or package…" class="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-gray-800" />
            </div>

            <div>
              <label class="block text-xs font-medium muted mb-1">Priority</label>
              <div class="flex flex-wrap gap-2">
                <button data-prio="A+" class="prio chip priority-A+">A+</button>
                <button data-prio="A" class="prio chip priority-A">A</button>
                <button data-prio="B" class="prio chip priority-B">B</button>
                <button data-prio="C" class="prio chip priority-C">C</button>
                <button data-prio="D" class="prio chip priority-D">D</button>
              </div>
            </div>

            <div>
              <label class="block text-xs font-medium muted mb-1">Severity</label>
              <div class="flex flex-wrap gap-2">
                <button data-severity="CRITICAL" class="severity chip bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">Critical</button>
                <button data-severity="HIGH" class="severity chip bg-orange-100 text-orange-700 dark:bg-orange-800/40 dark:text-orange-100">High</button>
                <button data-severity="MEDIUM" class="severity chip bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">Medium</button>
                <button data-severity="LOW" class="severity chip bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">Low</button>
                <button data-severity="UNKNOWN" class="severity chip bg-gray-100 text-gray-700 dark:bg-gray-800/40 dark:text-gray-100">Unknown</button>
              </div>
            </div>

            <div>
              <label class="block text-xs font-medium muted mb-1">EPSS ≥ %</label>
              <input id="filterEPSS" type="number" min="0" max="100" step="0.01" placeholder="0.00%" class="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-500 dark:border-gray-700 dark:bg-gray-800" />
            </div>

            <div>
              <div class="flex items-center gap-1 mb-1">
                <label class="text-xs font-medium muted">Status</label>
                <a href="https://docs.defectdojo.com/supported_tools/parsers/file/trivy/" 
                   target="_blank" 
                   title="Trivy vulnerability status documentation"
                   class="inline-flex items-center justify-center h-4 w-4 rounded-full bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-600 dark:text-gray-300 text-xs no-print">
                  ?
                </a>
              </div>
              <div class="flex flex-wrap gap-2">
                <button data-status="fixed" class="status chip bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">Fixed</button>
                <button data-status="affected" class="status chip bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">Affected</button>
                <button data-status="will_not_fix" class="status chip bg-gray-100 text-gray-700 dark:bg-gray-800/40 dark:text-gray-100">Will not fix</button>
                <button data-status="fix_deferred" class="status chip bg-blue-100 text-blue-700 dark:bg-blue-800/40 dark:text-blue-100">Fix deferred</button>
                <button data-status="end_of_life" class="status chip bg-purple-100 text-purple-700 dark:bg-purple-800/40 dark:text-purple-100">End of life</button>
                <button data-status="end_of_support" class="status chip bg-indigo-100 text-indigo-700 dark:bg-indigo-800/40 dark:text-indigo-100">End of support</button>
                <button data-status="end_of_service_life" class="status chip bg-pink-100 text-pink-700 dark:bg-pink-800/40 dark:text-pink-100">End of service life</button>
                <button data-status="unaffected" class="status chip bg-emerald-100 text-emerald-700 dark:bg-emerald-800/40 dark:text-emerald-100">Unaffected</button>
                <button data-status="under_investigation" class="status chip bg-amber-100 text-amber-700 dark:bg-amber-800/40 dark:text-amber-100">Under investigation</button>
                <button data-status="unknown" class="status chip bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">Unknown</button>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <input id="filterCISA" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-600 dark:border-gray-600" />
              <label for="filterCISA" class="text-sm">CISA KEV only</label>
            </div>

            <div class="flex items-center gap-2">
              <input id="filterExploit" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-600 dark:border-gray-600" />
              <label for="filterExploit" class="text-sm">Has public exploits</label>
            </div>

            <div class="pt-2">
              <button id="resetFilters" class="w-full text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">Reset filters</button>
            </div>
          </div>
        </div>

        <!-- Tree Navigation -->
        <div class="card">
          <div class="card-header">
            <h2 class="text-sm font-semibold tracking-wide uppercase muted">Sections</h2>
          </div>
          <div class="card-body py-2 tree-content">
            <div class="space-y-1">
              {sections_html}
            </div>
          </div>
        </div>
      </div>
    </div>
    """


def generate_vulnerabilities_content(grouped_vulnerabilities):
    """Генерирует контент с уязвимостями, сгруппированными по разделам"""
    content_parts = []

    for section_name, packages in grouped_vulnerabilities.items():
        section_id = section_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')

        # Заголовок раздела
        section_content = f"""
        <article id="{section_id}" class="card">
          <div class="card-header">
            <h2 class="text-lg font-semibold">{section_name}</h2>
          </div>
          <div class="card-body">
        """

        # Уязвимости по пакетам - передаем section_name
        for pkg_name, vulnerabilities in packages.items():
            section_content += generate_package_section(section_name, pkg_name, vulnerabilities)

        section_content += """
          </div>
        </article>
        """
        content_parts.append(section_content)

    return '\n'.join(content_parts)


def generate_package_section(section_name, pkg_name, vulnerabilities):
    """Генерирует секцию для одного пакета"""
    # Создаем уникальный ID для пакета
    section_id = section_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
    pkg_safe = pkg_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
    pkg_id = f"{section_id}__{pkg_safe}"

    # ДОПОЛНИТЕЛЬНАЯ СОРТИРОВКА: Сортируем уязвимости внутри пакета
    vulnerabilities_sorted = sorted(
        vulnerabilities,
        key=lambda x: get_severity_weight(x.get('Severity', 'UNKNOWN')),
        reverse=True  # По убыванию критичности
    )

    package_content = f"""
    <div id="{pkg_id}" class="mb-6 last:mb-0">
      <h3 class="font-semibold text-md mb-3 border-b pb-2">{pkg_name}</h3>
      <div class="space-y-3">
    """

    for vuln in vulnerabilities_sorted:
        package_content += generate_vulnerability_card(vuln)

    package_content += """
      </div>
    </div>
    """
    return package_content


def generate_vulnerability_card(vuln):
    """Генерирует детальную карточку для одной уязвимости"""
    cve_id = vuln.get('VulnerabilityID', 'Unknown')
    severity = vuln.get('Severity', 'UNKNOWN')
    description = vuln.get('Description', 'No description available')
    # Экранируем описание
    description = description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"',
                                                                                                      '&quot;').replace(
        "'", '&#39;')

    pkg_name = vuln.get('PkgName', 'Unknown Package')
    installed_version = vuln.get('InstalledVersion', 'Unknown')
    fixed_version = vuln.get('FixedVersion', 'Not fixed')
    status = vuln.get('Status', 'Unknown')
    references = vuln.get('References', [])

    # CVSS данные (ИСПРАВЛЕННАЯ ЛОГИКА)
    cvss_score, cvss_vector = get_cvss_data(vuln)

    # Определяем цвет для CVSS
    cvss_color = 'gray'
    if cvss_score != 'N/A':
        try:
            score = float(cvss_score)
            if score >= 9.0:
                cvss_color = 'red'
            elif score >= 7.0:
                cvss_color = 'orange'
            elif score >= 4.0:
                cvss_color = 'yellow'
            else:
                cvss_color = 'green'
        except (ValueError, TypeError):
            cvss_color = 'gray'

    # Данные из SploitScan
    sploitscan = vuln.get('sploitscan', {})

    # ОБРАБОТКА ОШИБОК SPLOITSCAN
    if isinstance(sploitscan, list) and len(sploitscan) == 0:
        # Ошибка сканирования - пустой список []
        priority = 'Not scanned'
        epss_score = 'Not scanned'
        cisa_status = 'Not scanned'
        ransomware_use = 'Not scanned'
        is_cisa_listed = False

        # Пустые данные об эксплойтах
        github_pocs = []
        exploitdb_items = []
        nvd_exploits = []
        metasploit_modules = []
        other_exploits = []
    elif not isinstance(sploitscan, dict) or not sploitscan:
        # Нет данных или неправильный формат
        priority = 'Not scanned'
        epss_score = 'Not scanned'
        cisa_status = 'Not scanned'
        ransomware_use = 'Not scanned'
        is_cisa_listed = False

        # Пустые данные об эксплойтах
        github_pocs = []
        exploitdb_items = []
        nvd_exploits = []
        metasploit_modules = []
        other_exploits = []
    else:
        # Нормальные данные
        priority = sploitscan.get('Priority', {}).get('Priority', 'Not scanned')

        epss_data = sploitscan.get('EPSS Data', {})
        if isinstance(epss_data, dict):
            epss_data_list = epss_data.get('data', [])
            epss_data_item = epss_data_list[0] if epss_data_list else {}
            epss_score = epss_data_item.get('epss', 'Not scanned')
        else:
            epss_score = 'Not scanned'

        cisa_data = sploitscan.get('CISA Data', {})
        cisa_status = cisa_data.get('cisa_status', 'Not scanned')
        ransomware_use = cisa_data.get('ransomware_use', 'Not scanned')

        # Определяем, находится ли CVE в списке CISA KEV
        is_cisa_listed = cisa_status in ['Listed', 'Yes', 'YES', 'listed', 'yes']

        # Получаем структурированные данные об эксплойтах из всех источников
        exploit_data_dict = get_exploit_data(sploitscan)
        github_pocs = exploit_data_dict['github_pocs']
        exploitdb_items = exploit_data_dict['exploitdb_items']
        nvd_exploits = exploit_data_dict['nvd_exploits']
        metasploit_modules = exploit_data_dict['metasploit_modules']
        other_exploits = exploit_data_dict['other_exploits']

    return f"""
    <div class="vulnerability-card border rounded-lg p-4 hover:shadow-md transition-shadow mb-4" 
         data-cve="{cve_id}" 
         data-package="{pkg_name}" 
         data-prio="{priority}" 
         data-severity="{severity}"
         data-epss="{epss_score if epss_score != 'Not scanned' else '0'}"
         data-cisa="{str(is_cisa_listed).lower()}" 
         data-expl="{str(has_any_exploits(sploitscan)).lower()}"
         data-status="{status.lower()}">

      <!-- Заголовок карточки -->
      <div class="flex justify-between items-start mb-3">
        <div class="flex items-center gap-2 flex-wrap">
          <h4 class="font-medium text-lg">{cve_id}</h4>
          <span class="badge bg-{cvss_color}-100 text-{cvss_color}-700 dark:bg-{cvss_color}-800/40 dark:text-{cvss_color}-100">CVSS: {cvss_score}</span>
          {f'<span class="badge bg-red-100 text-red-700 dark:bg-red-800/40 dark:text-red-100">{severity}</span>' if severity == 'CRITICAL' else ''}
          {f'<span class="badge bg-orange-100 text-orange-700 dark:bg-orange-800/40 dark:text-orange-100">{severity}</span>' if severity == 'HIGH' else ''}
          {f'<span class="badge bg-yellow-100 text-yellow-700 dark:bg-yellow-800/40 dark:text-yellow-100">{severity}</span>' if severity == 'MEDIUM' else ''}
          {f'<span class="badge bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">{severity}</span>' if severity == 'LOW' else ''}
          {f'<span class="badge bg-gray-100 text-gray-700 dark:bg-gray-800/40 dark:text-gray-100">{severity}</span>' if severity == 'UNKNOWN' else ''}
          <span class="pill priority-{priority}">{priority}</span>
        </div>
        <div class="text-right text-sm">
          <div class="muted">EPSS: {format_epss(epss_score)}</div>
          <div class="muted">Status: {status}</div>
        </div>
      </div>

      <!-- Базовая информация -->
      <div class="mb-3">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span class="font-medium">Package:</span> {pkg_name}
          </div>
          <div>
            <span class="font-medium">Version:</span> {installed_version}
          </div>
          <div>
            <span class="font-medium">Fixed in:</span> {fixed_version}
          </div>
          <div>
            <span class="font-medium">CISA KEV:</span> 
            {f'<span class="badge bg-green-100 text-green-700 dark:bg-green-800/40 dark:text-green-100">{cisa_status}</span>' if is_cisa_listed else f'<span class="badge bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200">{cisa_status}</span>'}
          </div>
        </div>
      </div>

      <!-- Описание -->
      <div class="mb-3">
        <p class="text-sm">{description}</p>
      </div>

      <!-- Детальная информация (раскрывающаяся) -->
      <details class="mt-3">
        <summary class="cursor-pointer font-medium text-sm text-brand-600 hover:text-brand-700">
          Show detailed information
        </summary>

        <div class="mt-3 space-y-0">
          <!-- CVSS Vector -->
          <div class="pb-4 border-b border-gray-200 dark:border-gray-700">
            <h5 class="font-medium mb-2">CVSS Vector</h5>
            <div class="text-sm">
              <code class="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded">{cvss_vector}</code>
            </div>
          </div>

          <!-- EPSS Score -->
          <div class="py-4 border-b border-gray-200 dark:border-gray-700">
            <h5 class="font-medium mb-2">EPSS Score</h5>
            <div class="text-sm">
              <span class="muted">Probability:</span> {format_epss(epss_score)}
            </div>
          </div>

          <!-- CISA KEV Details -->
          {f'''
          <div class="py-4 border-b border-gray-200 dark:border-gray-700">
            <h5 class="font-medium mb-2">CISA KEV Details</h5>
            <div class="text-sm">
              <div><span class="muted">Ransomware Use:</span> {ransomware_use}</div>
            </div>
          </div>
          ''' if is_cisa_listed else ''}

          <!-- Exploits -->
          {generate_exploits_section(github_pocs, exploitdb_items, nvd_exploits, metasploit_modules, other_exploits)}

          <!-- References -->
          {generate_references_section(references) if references else ''}

        </div>
      </details>
    </div>
    """


def get_exploit_data(sploitscan):
    """Извлекает структурированные данные об эксплойтах из различных источников"""
    # Если sploitscan - не словарь, то нет данных
    if isinstance(sploitscan, list) or not isinstance(sploitscan, dict):
        return {
            'github_pocs': [],
            'exploitdb_items': [],
            'nvd_exploits': [],
            'metasploit_modules': [],
            'other_exploits': []
        }

    # 1. GitHub PoCs
    github_pocs = []
    github_data = sploitscan.get('GitHub Data')
    if github_data and isinstance(github_data, dict):
        github_pocs = github_data.get('pocs', [])

    # 2. ExploitDB Data - преобразуем id в URL
    exploitdb_raw = sploitscan.get('ExploitDB Data', [])
    exploitdb_items = []
    for item in exploitdb_raw:
        if isinstance(item, dict) and item.get('id'):
            exploitdb_items.append({
                'id': item['id'],
                'url': f"https://www.exploit-db.com/exploits/{item['id']}",
                'date': item.get('date', '')
            })

    # 3. NVD Data exploits
    nvd_exploits = []
    nvd_data = sploitscan.get('NVD Data')
    if nvd_data and isinstance(nvd_data, dict):
        nvd_exploits = nvd_data.get('exploits', [])

    # 4. Metasploit Data modules
    metasploit_modules = []
    metasploit_data = sploitscan.get('Metasploit Data')
    if metasploit_data and isinstance(metasploit_data, dict):
        metasploit_modules = metasploit_data.get('modules', [])

    # 5. Другие источники
    other_exploits = []
    vulncheck_data = sploitscan.get('VulnCheck Data', {})
    if vulncheck_data and len(vulncheck_data) > 0:
        other_exploits.append({'source': 'VulnCheck', 'data': vulncheck_data})

    return {
        'github_pocs': github_pocs,
        'exploitdb_items': exploitdb_items,
        'nvd_exploits': nvd_exploits,
        'metasploit_modules': metasploit_modules,
        'other_exploits': other_exploits
    }


def generate_exploits_section(github_pocs, exploitdb_items, nvd_exploits, metasploit_modules, other_exploits=None):
    """Генерирует секцию с эксплойтами из всех источников"""
    if other_exploits is None:
        other_exploits = []

    # Проверяем, есть ли вообще какие-то данные
    has_any_exploits = (
            (github_pocs and len(github_pocs) > 0) or
            (exploitdb_items and len(exploitdb_items) > 0) or
            (nvd_exploits and len(nvd_exploits) > 0) or
            (metasploit_modules and len(metasploit_modules) > 0) or
            (other_exploits and len(other_exploits) > 0)
    )

    if not has_any_exploits:
        return '''<div></div>'''  # Пустой div вместо текста "No public exploits found"

    exploits_content = '''
    <div class="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
      <h5 class="font-medium mb-2">Public Exploits</h5>
      <div class="space-y-3 pb-3">
    '''

    # GitHub PoCs
    if github_pocs:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">GitHub PoCs</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for poc in github_pocs[:5]:
            url = poc.get('html_url', '')
            if url:
                exploits_content += f'<li><a href="{url}" target="_blank" class="link break-all">{url}</a></li>'
        exploits_content += '</ul></div>'

    # ExploitDB Items
    if exploitdb_items:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">ExploitDB</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for item in exploitdb_items[:5]:
            if item.get('url'):
                exploits_content += f'<li><a href="{item["url"]}" target="_blank" class="link break-all">{item["url"]}</a>'
                if item.get('date'):
                    exploits_content += f' <span class="text-xs muted">({item["date"]})</span>'
                exploits_content += '</li>'
        exploits_content += '</ul></div>'

    # NVD Exploits
    if nvd_exploits:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">NVD References</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for exploit_url in nvd_exploits[:5]:
            if exploit_url:
                exploits_content += f'<li><a href="{exploit_url}" target="_blank" class="link break-all">{exploit_url}</a></li>'
        exploits_content += '</ul></div>'

    # Metasploit Modules
    if metasploit_modules:
        exploits_content += '''
        <div>
          <div class="font-medium text-sm mb-1">Metasploit</div>
          <ul class="list-disc pl-5 space-y-1 text-sm">
        '''
        for module in metasploit_modules[:3]:
            if isinstance(module, dict):
                name = module.get('fullname', module.get('ref_name', 'Metasploit Module'))
                url = module.get('url', '')
                display_text = url if url else name

                if url:
                    exploits_content += f'<li><a href="{url}" target="_blank" class="link break-all">{display_text}</a>'
                else:
                    exploits_content += f'<li>{display_text}'

                if module.get('rank_label'):
                    exploits_content += f' <span class="text-xs muted">({module["rank_label"]})</span>'
                if module.get('disclosure_date'):
                    exploits_content += f' <span class="text-xs muted">{module["disclosure_date"]}</span>'
                exploits_content += '</li>'
        exploits_content += '</ul></div>'

    exploits_content += '</div></div>'
    return exploits_content


def generate_references_section(references):
    """Генерирует секцию с ссылками"""
    references_content = '''
    <div class="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
      <h5 class="font-medium mb-2">References</h5>
      <ul class="list-disc pl-5 space-y-1 text-sm pb-3">
    '''

    for ref in references[:10]:  # Ограничиваем 10 ссылками
        references_content += f'<li><a href="{ref}" target="_blank" class="link break-all">{ref}</a></li>'

    references_content += '</ul></div>'
    return references_content


def get_artifact_name(report_filename):
    """Извлекает имя артефакта из имени файла (без .json)"""
    return Path(report_filename).stem.replace('_enriched', '')


def get_scan_datetime(trivy_data):
    """Извлекает дату сканирования из отчета Trivy"""
    # Пробуем получить из Created в ImageConfig
    if 'Metadata' in trivy_data:
        metadata = trivy_data['Metadata']
        if 'ImageConfig' in metadata and metadata['ImageConfig']:
            config = metadata['ImageConfig']
            if 'created' in config:
                try:
                    # Формат: "2024-01-15T12:30:45Z"
                    created_str = config['created'].replace('Z', '+00:00')
                    dt = datetime.fromisoformat(created_str)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass

    # Если не нашли, возвращаем текущую дату генерации отчета
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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
        print(f"Генерация HTML отчета для: {enriched_file.name}")
        generate_trivy_html_report(enriched_file)


if __name__ == "__main__":
    main()