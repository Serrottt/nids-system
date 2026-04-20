FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py nids_analyzer.py ./
COPY templates ./templates

RUN mkdir -p /app/data /app/logs

EXPOSE 5000

CMD ["python", "app.py"]