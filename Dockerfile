FROM python:3.13-alpine

WORKDIR /app

# copy and setup requirements
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# copy application
COPY entrypoint.sh ics_threat_feeds.py .

# create and switch to non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# ensures output is logged in real time
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
