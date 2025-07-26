FROM python:3.13-alpine

WORKDIR /app

COPY requirements.txt ics_threat_feeds.py .
RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 8080

CMD ["gunicorn", "ics_threat_feeds:app", "--bind", "0.0.0.0:8080", "--log-level", "${LOG_LEVEL:-warning}"]
