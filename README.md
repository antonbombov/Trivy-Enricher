# VIBECHECKER

Проект для автоматического обогащения отчетов уязвимостей Trivy с информацией об эксплойтах, приоритетах исправления и дополнительных метриках безопасности. Также поддерживает интеграцию с отчетами PTAI для формирования единого Excel отчета.

Проект создан с помощью DeepSeek AI.

## Возможности
📊 **Обогащение отчетов Trivy** - добавление информации об эксплойтах, EPSS, CISA KEV, priority level  
⚡ **Параллельная обработка** - ускорение работы через многопроцессную обработку CVE  
💾 **Кэширование результатов** - избежание повторных запросов к SploitScan, буст скорости работы  
🌐 **Интерактивные HTML отчеты** - с фильтрацией, поиском и древовидной навигацией  
📑 **Объединенные Excel отчеты** - два листа: SCA Анализ (Trivy) и PTAI Анализ (подтвержденные уязвимости)  
🎯 **Гибкий запуск** - выбор типа отчетов через аргументы командной строки  
🚀 **Режим без обогащения** - быстрая генерация отчетов из исходных данных Trivy

## Требования
- Python 3.7+  
- [Trivy](https://github.com/aquasecurity/trivy/releases)  
- [SploitScan](https://github.com/xaitax/SploitScan)  

<sub><sup>***рекомендуется модифицированный [sploitscan](https://github.com/antonbombov/SploitScan) (v.0.14.3) - при отсутствии эксплойтов включает информационные ссылки</sub></sup>

## Структура каталогов
Перед запуском необходимо создать следующую структуру:  
your_work_directory/  
├── config.json # Файл конфигурации (обязательно)  
├── reports/ # Папка с входными отчетами (scan_directory)  
│ ├── report1.json # JSON отчет Trivy  
│ ├── report2.json  
│ └── PTAI/ # Подпапка для PTAI отчетов  
│ ├── report1.html # HTML отчет PTAI (имя совпадает с Trivy)  
│ └── report2.html  
├── cache/ # Папка для кэша SploitScan  
└── results/ # Папка для выходных отчетов  

## Требования к отчетам

### Trivy отчет (JSON)
- Формат: UTF-8 (с BOM или без)  
- Должен содержать поле `Results` с массивом уязвимостей  
- Для отображения версии Trivy в HTML рекомендуется версия **0.69.0 или новее** (поле `Trivy.Version`)

### PTAI отчет (HTML)
- Формат: HTML, сгенерированный PTAI  
- Должен содержать таблицы с классом vulnerability-root-table  
- Имя файла должно точно совпадать с именем Trivy отчета (без расширения)  
- Пример: если Trivy отчет scan.json, то PTAI отчет должен быть PTAI/scan.html  

## Установка
1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd cd trivy\Trivy-Enricher
```

2. Установите зависимости:
```bash
pip install -r requirements.txt 
```

3. Создайте файл config.json (см. пример ниже)
```json
{
  "sploitscan_path": "путь_к_sploitscan.py",
  "scan_directory": "путь_к_папке_с_отчетами",
  "cache_directory": "путь_к_папке_кэша",
  "output_directory": "путь_к_папке_результатов",
  "cache_max_days": 30,
  "max_workers": null,
  "timeout": 60,
  "project_version": "0.7.3",
  "sploitscan_version": "0.14.3_enhanced"
}
```

``sploitscan_path`` - 	Путь к SploitScan (файл .py или команда "sploitscan")
``scan_directory``	Папка с входными JSON отчетами Trivy
``cache_directory``	Папка для кэша результатов SploitScan
``output_directory``	Папка для сохранения результатов (HTML, Excel)
``cache_max_days``	Максимальный возраст файлов в кэше (дни)
``max_workers``	Кол-во параллельных процессов (null = авто)
``timeout``	Таймаут на выполнение SploitScan (сек)
``project_version``	Версия проекта (отображается в HTML)
``sploitscan_version``	Версия SploitScan (отображается в HTML)

## Подготовка PTAI отчета (опционально)
Для добавления листа PTAI Анализ в Excel отчет:
1. Создайте подпапку `PTAI` внутри `scan_directory`
2. Поместите HTML отчет PTAI в эту папку с **точным совпадением имени** с Trivy отчетом (например, `scan.json` и `PTAI/scan.html`)

### Запуск проекта

#### Аргументы командной строки:
| Аргумент                 | Описание |
|--------------------------|----------|
| `-html`                  | Генерация HTML отчетов |
| `-excel`                 | Генерация Excel отчетов |
| `-h`                     | Показать справку |
| `--skip-enrich` / `--se` | Пропустить обогащение SploitScan (использовать исходный Trivy JSON) |
| `--only-cache` / `-oc`   | Использовать только кэшированные данные (без вызова SploitScan) |
| `--ptai-only` / `--po`   | Генерировать только Excel отчет с PTAI анализом (без SCA) |

**Примеры:**
```bash
# Только HTML отчет с обогащением
python main.py -html

# Только Excel отчет с обогащением
python main.py -excel

# Оба отчета с обогащением
python main.py -html -excel

# HTML отчет без обогащения (быстрая генерация)
python main.py -html --skip-enrich
python main.py -html --se

# Оба отчета только из кэша
python main.py -html -excel --only-cache
python main.py -html -excel --oc

# Только Excel с PTAI (без Trivy SCA)
python main.py -excel --ptai-only
python main.py -excel --po

# Оба отчета без обогащения
python main.py -html -excel --skip-enrich
```
Docker контейнер

С сохранением кэша:

```powershell
docker run --rm -it -v "${PWD}/Scan:/scan/input" -v "${PWD}/Reports:/scan/results" -v "${PWD}/Cache:/scan/cache" theunclefyodor/tve:latest -html -excel
```
Без сохранения кэша:
```
powershell
docker run --rm -it -v "${PWD}/Scan:/scan/input" -v "${PWD}/Reports:/scan/results" theunclefyodor/tve:latest -html -excel
```
<sub><sup>при использовании Docker контейнера отчет нужно положить в папку Scan.</sub></sup>
<sub><sup>при использовании контейнера с ключом --rm кэш результатов сканирования SploitScan сохраняться не будет</sub></sup>
<sub><sup>в контейнере используется модифицированный sploitscan</sub></sup>

### 4. Что делает скрипт
- Находит все JSON отчеты Trivy в указанной папке
- **При режиме с обогащением:**
  - Извлекает список CVE из каждого отчета
  - Сканирует уникальные CVE в SploitScan (с кэшированием)
  - Обогащает входной отчет Trivy результатами сканирования
- **При режиме без обогащения:**
  - Использует исходный Trivy JSON как есть
- Генерирует HTML и/или Excel отчеты в соответствии с указанными аргументами
- При наличии PTAI отчета с совпадающим именем добавляет лист PTAI Анализ в Excel

### 5. Функциональность отчетов

#### HTML отчеты
**Фильтрация и поиск:**
- Поиск по CVE ID и имени пакета  
- Фильтрация по приоритету (A+, A, B, C, D, Not scanned)  
- Фильтрация по severity (Critical, High, Medium, Low, Unknown)  
- Фильтр по EPSS score  
- Фильтрация по статусу уязвимости (fixed, affected)  
- Показ только уязвимостей из CISA KEV  
- Показ только уязвимостей с публичными эксплойтами  
- Показ уязвимостей, не отсканированных SploitScan

**Блок "Sections":**
- Древовидная структура секций (мест), в которых были найдены уязвимости
- При нажатии на имя секции осуществляется переход к соответствующему месту в отчете
- Раскрывающийся список компонентов внутри каждой секции

**Блок статистики:**
- Общее количество CVE (с указанием количества уникальных CVE)
- Распределение по уровням критичности
- Количество уязвимостей с эксплойтами

**Карточки уязвимостей:**
- CVE-ID, CVSS векторы и оценки, Severity, Priority level, EPSS, статус исправления
- Имя уязвимого пакета, версия, версия исправления
- Статус CISA KEV
- Описание уязвимости
- Информация об эксплойтах (GitHub PoCs, ExploitDB, Metasploit, NVD)
- Ссылки на релевантные ресурсы

#### Excel отчеты
**Лист "SCA Анализ":**
- Все вхождения уязвимостей из Trivy
- Колонки: №, Источник, Путь, Пакет, Версия, Идентификатор, Уровень критичности, Срок устранения, Статус, Комментарий
- Выпадающие списки для статуса
- Автоматический расчет срока устранения на основе severity и наличия эксплойтов

**Лист "PTAI Анализ" (создается при наличии PTAI отчета):**
- Только подтвержденные уязвимости из PTAI
- Колонки: №, ID уязвимости, Тип уязвимости, Класс и метод / Уязвимый файл, Комментарий, Статус, CWSS, Срок устранения, Компенсирующие меры
- Формула для "Срок устранения" на основе CWSS:
  - CWSS ≥ 75 → "Устранение в текущем релизе / выпуск fix-патча"
  - CWSS ≥ 30 → "Исправление в ближайших релизах / устранение в очередном патче"
  - CWSS ≥ 10 → "Рекомендуется устранить в будущих релизах"

### 6. Структура проекта
vibechecker/  
├── main.py # Основной скрипт (точка входа)  
├── argument_parser.py # Парсинг аргументов командной строки  
├── config_manager.py # Управление конфигурацией  
├── enrichment_core.py # Ядро обогащения отчетов  
├── trivy_parser.py # Парсер отчетов Trivy  
├── sploitscan_runner.py # Запуск SploitScan  
├── sploitscan_parser.py # Парсер результатов SploitScan  
├── parallel_processor.py # Параллельная обработка  
├── trivy_html_reporter.py # Генератор HTML отчетов  
├── html_templates.py # HTML шаблоны  
├── excel_reporter.py # Генератор Excel отчетов (SCA + PTAI)  
├── ptai_processor.py # Парсер PTAI отчетов (lxml/XPath)  
├── excel_styles.py # Единые стили для Excel  
├── cdn_cache_manager.py # Кэширование Tailwind CSS  
├── cache_cleaner.py # Очистка устаревшего кэша  
├── config.json # Файл конфигурации  
├── requirements.txt # Зависимости Python  
└── README.md # Документация  

### 7. 🔗 Ссылки
- [SploitScan](https://github.com/xaitax/SploitScan) - инструмент для сбора информации об эксплойтах  
- [Trivy](https://github.com/aquasecurity/trivy) - сканер уязвимостей контейнеров и приложений  
- [Модифицированный SploitScan](https://github.com/antonbombov/SploitScan) - версия с информационными ссылками
