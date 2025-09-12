FROM python:3.13-alpine

WORKDIR /app

# copy and setup requirements
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# copy application
COPY entrypoint.sh isc_threat_feeds.py .
RUN chmod +x entrypoint.sh

# Add a tiny PID1 to forward signals correctly
RUN apk add --no-cache dumb-init

# create and switch to non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# ensures output is logged in real time and keep bytecode in memory
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/app/entrypoint.sh"]
