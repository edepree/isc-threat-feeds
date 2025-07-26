FROM python:3.13-alpine

WORKDIR /app

# create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# copy application and setup requirements
COPY requirements.txt ics_threat_feeds.py .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# switch to non-root user
USER appuser

# ensures output is logged in real time
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["sh", "-c", "gunicorn ics_threat_feeds:app --bind 0.0.0.0:8080 --log-level ${GUNICORN_LOGGING:-info}"]
