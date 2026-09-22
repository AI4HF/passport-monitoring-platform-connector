# Passport → Monitoring Platform Connector (`passport-monitoring-platform-connector`)

A **cron-scheduled Python script** that incrementally reads Models, their ModelEvaluations and the EvaluationMeasures of each run from the
**AI4HF Passport Server** (`../passport`) and forwards them as JSON events to the **AI4HF Monitoring
Platform** (https://github.com/AI4HF/monitoring-platform — ELK-based, not in this workspace) via its
Logstash HTTP input.

Remote: https://github.com/AI4HF/passport-monitoring-platform-connector · Python 3.10 · deps: `requests`,
`python-dateutil` · Docker image `srdc/passport-monitoring-platform-connector` (unversioned, `latest`).

Workspace context: the current, AI4HF-project prototype of the **monitoring feed** — note its direction is
*Passport → Monitoring* (training-time evaluation measures out to dashboards), which is the *reverse* of
integration #4 (CELS → Passport) planned in [`../design/use-case-flow.md`](../design/use-case-flow.md).

## Files

| File | Role |
|---|---|
| `main.py` | Everything: `MonitoringPlatformConnector` + `__main__` reading env vars |
| `models.py` | Plain-Python mirrors: `Model`, `ModelEvaluation`, `EvaluationMeasure`, `Experiment` (Passport side) and `MonitoringPlatformEvaluationMeasure` (the Logstash event, `event_type: "evaluation_measure"`) |
| `crontab.template`, `entrypoint.sh` | Container installs cron and runs `main.py` on `CRON_SCHEDULE` (default every minute); env is re-exported into the cron job via `/env.sh` |
| `docker-compose.yml`, `Dockerfile` | Deployment; a named volume mounted at `/data` persists incremental state |

## How a run works

1. Connector login: `POST /user/connector/login` with raw `CONNECTOR_SECRET` (offline Keycloak token) as
   body; 401s trigger one re-auth + retry (`_refreshTokenAndRetry`, hardwired to GET here — all Passport
   calls in this connector are GETs).
2. `GET /model?studyId=…` — **all** models, every run.
3. **Round map**: per experiment, models sorted by (`createdAt`, `modelId`) get round numbers 1..N. Computed
   from the full history so rounds stay stable even when only new models are sent. A model's round is its
   position in its experiment — i.e. each newly registered model version = the next "training round" on the
   monitoring dashboard.
4. **Incremental filter**: models with `createdAt` newer than the timestamp in `TIMESTAMP_FILE`
   (`/data/last_processed_timestamp.txt`) are selected; if none, exit.
5. For each new model: `GET /model-evaluation?studyId=…&modelId=…` for its evaluation runs, then
   `GET /evaluation-measure?studyId=…&modelEvaluationId=…` per run — measures belong to a run rather
   than to the model. One Logstash POST per measure (Basic auth from `LOGSTASH_BASIC_AUTH`, payload
   includes experiment id + research question as `experiment_name`, `round`, and the run's
   `executedAt` — falling back to the model's `createdAt` — as `timestamp`).
6. Timestamp file updated to the newest sent model's `createdAt`.

All timestamps are normalized to UTC (`parse_ts`); naive strings are assumed UTC by project convention.

## Configuration (env vars)

`CRON_SCHEDULE`, `PASSPORT_SERVER_URL`, `STUDY_ID`, `CONNECTOR_SECRET`, `LOGSTASH_URL`,
`LOGSTASH_BASIC_AUTH` (base64 `user:pass`), `TIMESTAMP_FILE`. Compose joins the external
`passport-network` and creates/joins `ai4hf-monitoring`.

## Gotchas

- **Single-study**: one deployment watches exactly one `STUDY_ID`.
- `EvaluationMeasure.value` must parse as `float` at send time, or the run fails for that model batch;
  errors are caught at top level and logged only (`CRON ERROR`) — the timestamp is then *not* advanced,
  so the next run retries (and may re-send measures already delivered before the failure: per-measure
  sends are not transactional).
- The monitoring platform simulation example in
  [`../passport-model-metadata-extraction-library`](../passport-model-metadata-extraction-library/CLAUDE.md)
  is the intended data generator for testing this connector end-to-end.
- Demo `LOGSTASH_BASIC_AUTH` and `CONNECTOR_SECRET` are committed in `docker-compose.yml`.

## Conventions

Gitmoji commits, kebab-case branches off `main`, PRs. No automated tests — verify against a live
Passport + Monitoring Platform stack (watch container logs; events appear in Kibana).
