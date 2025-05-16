#!/bin/bash

# Get environment variables
printenv | awk -F= '{ print "export " $1"=\""substr($0, index($0,$2))"\"" }' > /env.sh
echo "$CRON_SCHEDULE bash -c '. /env.sh && python /app/main.py >> /proc/1/fd/1 2>&1'" > /etc/cron.d/my-cron
chmod 0644 /etc/cron.d/my-cron

# Start cron
chmod 0644 /etc/cron.d/my-cron
crontab /etc/cron.d/my-cron
cron -f

