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
| `models.py` | Plain-Python mirrors: `Model`, `ModelEvaluation`, `EvaluationMeasure`, `Experiment` (Passport side) and the Logstash events `MonitoringPlatformModel` (`event_type: "model"`) and `MonitoringPlatformEvaluationMeasure` (`event_type: "evaluation_measure"`) |
| `crontab.template`, `entrypoint.sh` | Container installs cron and runs `main.py` on `CRON_SCHEDULE` (default every minute) through `/run-connector.sh`, which `flock -n`s so a tick is skipped while the previous run is still going; env is re-exported into the cron job via `/env.sh`. The entrypoint refuses to start without `ORGANIZATION_ID` (`crontab.template` is unused) |
| `docker-compose.yml`, `Dockerfile` | Deployment; a named volume mounted at `/data` persists incremental state |

## How a run works

1. Keycloak `client_credentials` as `CLIENT_ID` (`ai4hf-monitoring-connector`, DATA_SCIENTIST in the study);
   401s trigger one re-auth + retry (`_refreshTokenAndRetry`, hardwired to GET — all Passport calls here are GETs).
2. `GET /model?studyId=…` — **all** models, every run.
3. **Round map**: per experiment, models sorted by (`createdAt`, `modelId`) get round numbers 1..N, computed from
   the full history — each newly registered model version = the next "training round" on the dashboard.
4. **State** (`STATE_FILE`, default `/data/sent.json`; sets in memory, sorted lists on disk):
   `models` (model id → fingerprint of the aggregate metrics last sent), `pendingRuns` (run id → `firstSeen` + the
   `measureId`s sent / skipped so far) and `settledRuns` (runs no longer read). Tracked per measure because the
   Passport client creates a run first and POSTs its measures one by one — a run seen half-written gets the rest on
   a later pass. A run is re-read every pass until `RUN_SETTLE_MINUTES` (default 60, at least 15) have passed since
   the later of its `executedAt` and when the connector first saw it; then it moves to `settledRuns` and its measure
   ids are dropped. Saved atomically (temp file + `os.replace`, fsynced) once before anything is sent (so an
   unwritable file stops the pass before the first event) and **after every delivered event**; a save failure stops
   the run (loud `[ERROR]`), and an unreadable state file refuses to run rather than re-send
   everything. No state file = a new installation: everything is sent once (there is no migration from the old
   timestamp-based version, which never ran at a site).
5. For each model: `GET /model-evaluation?studyId=…&modelId=…`, keeping only the runs for this site — not
   `trigger=monitoring` (those come from this Monitoring Platform via the node agent), and only the federated
   aggregate (no organization) and `ORGANIZATION_ID`'s runs (all organizations with `ORGANIZATION_ID=*`).
   - `model` event (`model_id`, `model_name`, `version`, `evaluation_metrics` of the aggregate training run)
     for a new model, and **again whenever its aggregate metrics change** (the aggregate run and its measures may
     be written after the model) until the aggregate run settles.
   - Each unsettled run → `GET /evaluation-measure?studyId=…&modelEvaluationId=…`, one `evaluation_measure` event
     per measure not sent yet: experiment id/name, `round`, the run's `executedAt` (fallback model `createdAt`) as
     `timestamp`, `model_id`/`model_name`, `model_evaluation_id`, `organization_id` (none for the aggregate).
     `name` is the dashboard name (`dashboard_measure_name`: lower-cased, `F1-Score`→`f1`, `precision`→`ppv`, …).
6. If `ORGANIZATION_ID` matches no run in the study while other organizations' runs exist, a typo warning is logged.

All timestamps are normalized to UTC (`parse_ts`); naive strings are assumed UTC by project convention.

## Configuration (env vars)

`CRON_SCHEDULE`, `PASSPORT_SERVER_URL`, `STUDY_ID`, `ORGANIZATION_ID` (**required**: the site's Passport
organization id, or `*` for every organization — unset/empty refuses to start; compose takes it from the shell or
`.env` via `${ORGANIZATION_ID:?…}`), `KEYCLOAK_SERVER_URL`, `KEYCLOAK_REALM`, `CLIENT_ID`, `CLIENT_SECRET`,
`LOGSTASH_URL`, `LOGSTASH_BASIC_AUTH` (base64 `user:pass`), `STATE_FILE` (default `/data/sent.json`),
`RUN_SETTLE_MINUTES` (default 60; below 15 refuses to start), `REQUEST_TIMEOUT_SECONDS` (default 60, every
Keycloak/Passport/Logstash request; a timeout is an ordinary request error). An invalid setting exits with code 2 before any request. Compose joins the external
`passport-network` and creates/joins `ai4hf-monitoring`; at a hospital `PASSPORT_SERVER_URL`/`KEYCLOAK_SERVER_URL`
are the central platform's public addresses.

## Gotchas

- **Single-study**: one deployment watches exactly one `STUDY_ID`.
- A measure whose `value` is not a finite number is skipped with a `[WARN]` once (recorded under `skipped`, so it
  is not logged again) and does not block other measures or models.
- An error while processing one model (HTTP error or timeout reading its runs/measures or sending its events, an
  unparsable date) is logged as `[ERROR] Model <id> (<name>) failed: …` and the next model goes on; its unsent
  events stay unsent in the state and are retried on the next tick. The run then ends with
  `[ERROR] N model(s) failed` and exit code 5 (unseen `pendingRuns` are not pruned in such a run). Errors that make
  the whole run meaningless stop it (`CRON ERROR`, exit code 1): authentication failure (Keycloak refuses or is
  unreachable, or the Passport rejects a fresh token — `AuthenticationError`), an unreadable or unwritable state
  file (`StateFileError`), and failures fetching the model or experiment lists. Only a crash between a delivered
  event and its state save can re-send that one event — Logstash indexes without a document id, so it would be a
  duplicate.
- A re-sent `model` event (metrics changed) is a new document in `models-*`: dashboards should take the latest
  per `model_id` (or Logstash should use `model_id` as document id — monitoring-platform follow-up).
- The connector sends lower-case measure names (`ppv`, `npv`); a dashboard querying `PPV`/`NPV` shows nothing.
- The monitoring platform simulation example in
  [`../passport-model-metadata-extraction-library`](../passport-model-metadata-extraction-library/CLAUDE.md)
  is the intended data generator for testing this connector end-to-end.
- Demo `LOGSTASH_BASIC_AUTH` is committed in `docker-compose.yml`; `CLIENT_SECRET` comes from the environment.

## Conventions

Gitmoji commits, kebab-case branches off `main`, PRs. No automated tests — verify against a live
Passport + Monitoring Platform stack (watch container logs; events appear in Kibana).
