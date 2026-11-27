#!/bin/bash

# ORGANIZATION_ID is required: this site's Passport organization id, or * for every organization.
if [ -z "${ORGANIZATION_ID// /}" ]; then
    echo "[FATAL] ORGANIZATION_ID is not set. Set it to this site's Passport organization id, or to * to send the evaluation runs of all organizations." >&2
    exit 1
fi
echo "passport-monitoring-platform-connector: ORGANIZATION_ID=${ORGANIZATION_ID}, schedule '${CRON_SCHEDULE}'"

# Get environment variables
printenv | awk -F= '{ print "export " $1"=\""substr($0, index($0,$2))"\"" }' > /env.sh

# One run at a time: flock -n skips a cron tick while the previous run is still going (flock is in util-linux,
# part of every Debian base image), so two runs never send the same events or write the state file together.
cat > /run-connector.sh <<'SCRIPT'
#!/bin/bash
. /env.sh
exec >> /proc/1/fd/1 2>&1
flock -n -E 75 /tmp/passport-monitoring-platform-connector.lock python /app/main.py
if [ $? -eq 75 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] The previous run is still in progress; this one is skipped."
fi
SCRIPT
chmod 0755 /run-connector.sh

echo "$CRON_SCHEDULE /run-connector.sh" > /etc/cron.d/my-cron

# Start cron
chmod 0644 /etc/cron.d/my-cron
crontab /etc/cron.d/my-cron
cron -f
