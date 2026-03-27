# Trivy Enricher
Проект для автоматического обогащения отчетов уязвимостей Trivy с информацией об эксплойтах, приоритетах исправления и дополнительных метриках безопасности.
Проект создан с помощью DeepSeek AI.

## Возможности
📊 Обогащение отчетов Trivy - добавление информации об эксплойтах, EPSS, CISA KEV, priority level    
⚡ Параллельная обработка - ускорение работы через многопроцессную обработку CVE  
💾 Кэширование результатов - избежание повторных запросов к SploitScan, как следствие, буст в скорости работы  
🌐 Интерактивные HTML отчеты - с фильтрацией и поиском


## Требования
Python 3.7+  
[Trivy](https://github.com/aquasecurity/trivy/releases)  
[SploitScan](https://github.com/xaitax/SploitScan)  
<sub><sup>***рекомендуется к применению модифицированный [sploitscan](https://github.com/antonbombov/SploitScan)  (v.0.14.3 при отсутствии эксплойтов включает вместо них информационные ссылки)</sub></sup> 



## Установка
1. Клонируйте репозиторий:
```bash
git clone <repository-url>
cd trivy\trivy-sploitscan
```
2. Настройте конфигурацию:

Проект использует config.json для хранения настроек.  
```json
{
  "sploitscan_path": "путь к sploitscan.py",
  "scan_directory": "путь к папке с отчетами trivy",
  "cache_directory": "путь к папке для хранения кэша sploitscan", 
  "output_directory": "путь к папке для итоговых отчетов",
  "max_workers": null, 
  "timeout": 60,
  "cache_max_days": 30,
  "project_version": "0.4.0"
}
```
max_workers - ограничение максимально допустимого количества параллельно запускаемых процессов при сканировании SploitScan (расчитывается автоматически, можно ограничить)  
timeout - значение в секундах, за которое SploitScan должен заврешить сканирование. Если сканирование превышает время - процесс будет прерван.
cache_max_days - значение в днях, в течении которого допускается хранение кэша. При достижении указанного числа, скрипт автоматически удалит устаревший кэш. Рекомендуется использовать значение 30 дней.
project_version - версия проекта (изменять не требуется)


## Использование
### 1. Генерация отчета Trivy
Для работы проекта нужен отчет триви в формате json строго в кодировке UTF-8
Отчет можно получить следующей командой (PowerShell):
```powershell
trivy image --format json your-image:tag | Set-Content -Encoding UTF8 .\scan.json
```
Отчет необходимо разместить к каталог, указанный в scan_directory

### 2. Запуск проекта:
Локально для клонированного репозитория
```bash
python main.py
```
Docker контейнер
с сохранением кэша
```powershell
docker run --rm -it -v "${PWD}/Scan:/scan/trivy/trivy+sploitscan/input" -v "${PWD}/Reports:/scan/trivy/trivy+sploitscan/results" -v "${PWD}/Cache:/scan/trivy/trivy+sploitscan/cache" theunclefyodor/tve:latest
```
без сохранения кэша
```powershell
docker run --rm -it -v "${PWD}/Scan:/scan/trivy/trivy+sploitscan/input" -v "${PWD}/Reports:/scan/trivy/trivy+sploitscan/results" theunclefyodor/tve:latest
```
<sub><sup>*при использовании Docker контейнера, отчет нужно положить в папку Scan.</sub></sup>  
<sub><sup>**при использовании конетейнера с ключом --rm кэш реузльтатов сканирования SploitScan сохраняться не будет (теряется буст в скорости проверки артефактов)</sub></sup>
<sub><sup>***в контейнере используется модифицированный [sploitscan](https://github.com/antonbombov/SploitScan)</sub></sup>  

Скрипт выполнит следующие действия:
- Найдет все JSON отчеты Trivy в указанной папке
- Извлечет список CVE из каждого отчета
- Просканирует уникальные CVE в Sploitscan, если они не содержатся в кэше. Если сканирование завершилось ошибкой - повторит его еще 1 раз
- Закэширует результаты сканирования Sploitscan
- Обогатит входной отчет trivy результатами сканирования CVE в SploitScan
- Сгенерирует интерактивные HTML отчеты в каталоге "output_directory" (указанном в config.json)

### 3. Функциональность HTML отчетов
### Фильтрация и поиск:
- Поиск по CVE ID и имени пакета  
- Фильтрация по приоритету (A+, A, B, C, D)  
- Фильтрация по severity (Critical, High, Medium, Low, Unkmown)  
- Фильтр по EPSS score  
- Фильтрация по trivy vulnerability status 
- Показ только уязвимостей, подтвержденных CISA KEV   
- Показ только уязвимостей с публичными эксплойтами

### Блок "Sections"
- Древовидная структура секций (мест), в которых были найдены уязвимости
- При нажатии на имя секции осуществляется переход по отчету к месту, где начинается информация по уязвимостям в этой секции
- При нажатии на символ стрелочки, открывается выпадающее меню с именами компонентов, содержащих уязвимости. При нажатии на имя компонента будет осуществлен переход по отчету.

### Блок статистики:
- Общее количество CVE (с указанием количетсва уникальных CVE)
- Распределение по уровням критичности (с указанием количетсва уникальных CVE)
- Количество уязвимостей с эксплойтами

### Карточки 
Детальная информация:
- CVE-ID \ CVSS векторы и оценки \ Severity Level \ Priority level \ EPSS вероятности эксплуатации\ Статус исправления уязвимости
- Имя уязвимого пакета \ Его версия \ Fixed in
- Статус CISA KEV
- Описание узявимости
- Информация об эксплойтах (GitHub PoCs, ExploitDB, Metasploit, NVD (если используется модифицированный [sploitscan](https://github.com/antonbombov/SploitScan)))
- Ссылки на релевантные ресурсы


## Структура проекта
trivy-sploitscan/  
├── results                   # Папка для итоговых отчетов  
├── results/logs              # Папка, в которую будут сохранятся логи работы Sploitscan (создается автоматически от пути, указанного в scan_directory)  
├── cache                     # Папка для хранения кэша sploitscan  
├── reports                   # Папка с отчетами trivy  
├── main.py                   # Основной скрипт  
├── config_manager.py         # Управление конфигурацией  
├── enrichment_core.py        # Ядро обогащения отчетов  
├── trivy_parser.py           # Парсер отчетов Trivy  
├── sploitscan_runner.py      # Запуск SploitScan  
├── sploitscan_parser.py      # Парсер результатов SploitScan  
├── parallel_processor.py     # Параллельная обработка  
├── trivy_html_reporter.py    # Генератор HTML отчетов  
├── html_templates.py         # HTML шаблоны  
├── config.json               # Файл конфигурации  
└── README.md                 # Документация  


## 🔗 Ссылки
SploitScan - инструмент для сбора информации об эксплойтах (https://github.com/xaitax/SploitScan)  
Trivy - сканер уязвимостей контейнеров и приложений (https://github.com/aquasecurity/trivy)
