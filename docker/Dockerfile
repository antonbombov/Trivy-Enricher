FROM python:3.12-slim-bullseye

WORKDIR /app

RUN apt-get update -qq && apt-get install -y -qq wget git tar && rm -rf /var/lib/apt/lists/*

# Клонируем проекты
RUN git clone https://github.com/antonbombov/SploitScan /sploitscan
RUN git clone https://github.com/antonbombov/Trivy-Enricher /app

# Устанавливаем зависимости SploitScan
RUN pip install --no-cache-dir -r /sploitscan/requirements.txt

# Создаем директории для монтирования
RUN mkdir -p /scan/input /scan/cache /scan/results

# Создаем конфиг
RUN echo '{ \
  "sploitscan_path": "/sploitscan/sploitscan.py", \
  "scan_directory": "/scan/input/", \
  "cache_directory": "/scan/cache/", \
  "output_directory": "/scan/results", \
  "cache_max_days": 30, \
  "max_workers": null, \
  "timeout": 90, \
  "project_version": "0.4.0" \
}' > /app/config.json

CMD ["python", "-u", "main.py"]

VOLUME ["/scan/input", "/scan/cache", "/scan/results"]