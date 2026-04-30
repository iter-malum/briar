FROM python:3.11-slim
# Установка Katana
RUN apt-get update && apt-get install -y wget && \
    wget -q -O - https://github.com/projectdiscovery/katana/releases/download/v1.0.6/katana_1.0.6_linux_amd64.zip | \
    busybox unzip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana

WORKDIR /app
COPY shared/ ./shared/
COPY services/worker-katana/main.py ./
COPY services/worker-katana/requirements.txt ./ # Создайте файл с зависимостями (aio-pika, sqlalchemy, httpx)
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "main.py"]