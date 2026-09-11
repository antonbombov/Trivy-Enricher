FROM python:3.12-slim-bullseye

WORKDIR /app

# Внутренние переменные контейнера
ENV HOME=/tmp
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -qq && apt-get install -y -qq wget git tar && rm -rf /var/lib/apt/lists/*

# Клонируем проекты
RUN git clone https://github.com/antonbombov/SploitScan /sploitscan
RUN git clone https://github.com/antonbombov/Trivy-Enricher /app

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r /sploitscan/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Создаем директории для монтирования
# Права 777, чтобы любой UID (в т.ч. --user) мог писать
RUN mkdir -p /scan/input /scan/cache /scan/results && \
    chmod -R 777 /scan

# Конфиг
RUN echo '{ \
  "sploitscan_path": "/sploitscan/sploitscan.py", \
  "scan_directory": "/scan/input/", \
  "cache_directory": "/scan/cache/", \
  "output_directory": "/scan/results", \
  "cache_max_days": 30, \
  "max_workers": null, \
  "timeout": 90, \
  "project_version": "0.8.0.0", \
  "sploitscan_version": "0.14.3_enhanced" \
}' > /app/config.json

ENTRYPOINT ["python", "-u", "main.py"]
CMD []

VOLUME ["/scan/input", "/scan/cache", "/scan/results"]