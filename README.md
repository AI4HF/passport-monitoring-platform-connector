# Passport Monitoring Platform Connector
This connector includes a Python script scheduled with cron, which reads evaluation measures from the AI4HF Passport server and pushes them to the monitoring platform.

## Usage
Deploy the Passport server before running the connector.
```
git clone https://github.com/AI4HF/passport.git
```
Deploy monitoring platform before running the connector.
```
git clone https://github.com/AI4HF/monitoring-platform.git
```
Once both the AI4HF Passport Server and the monitoring platform have been deployed, you can deploy the connector by running the following command:
```
docker compose up -d
```