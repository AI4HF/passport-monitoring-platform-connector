FROM python:3.10-slim

WORKDIR /app
COPY main.py /app/
COPY models.py /app/
COPY crontab.template /app/
COPY entrypoint.sh /app/
COPY requirements.txt /app/
RUN chmod +x /app/entrypoint.sh

# Install cron
RUN apt-get update && apt-get install -y cron && apt-get install -y bash && apt-get clean

# Install python dependecies
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/app/entrypoint.sh"]
