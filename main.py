from collections import defaultdict
from dateutil.parser import isoparse
from dateutil.tz import UTC
from datetime import datetime, timedelta
from models import *
import hashlib
import json
import math
import requests
import os
import sys
import tempfile
import traceback

# Names the Monitoring Platform dashboards chart, for metric names recorded differently in the Passport
# (the Passport seed uses "F1-Score", the metadata extraction library "f1"). Others are lower-cased.
MEASURE_NAME_ALIASES = {
    "f1-score": "f1", "f1_score": "f1", "f1 score": "f1", "f1score": "f1",
    "precision": "ppv", "positive predictive value": "ppv",
    "negative predictive value": "npv",
    "true positive rate": "sensitivity",
}


def dashboard_measure_name(name: str) -> str:
    """Map a Passport measure name onto the name the Monitoring Platform dashboards use."""
    key = (name or "").strip().lower()
    return MEASURE_NAME_ALIASES.get(key, key)


class AuthenticationError(RuntimeError):
    """The service account could not get (or keep) a token: no model would get further, so the run stops."""


class StateFileError(RuntimeError):
    """The state file cannot be read or written: going on would re-send events, so the run stops."""


class MonitoringPlatformConnector:
    """
    Monitoring Connector that fetches data from AI4HF Passport Server and sends them into the monitoring platform.
    """

    def __init__(self, passport_server_url: str, study_id: str, keycloak_server_url: str,
                 client_id: str, client_secret: str, logstash_url: str,
                 logstash_basic_auth: str, state_file: str,
                 keycloak_realm: str = "AI4HF-Authorization",
                 organization_id: str = None, run_settle_minutes: int = 60,
                 request_timeout: float = 60):
        """
        Initialize the API client with authentication and study details.

        The connector authenticates as a Keycloak service account using the client_credentials grant.
        The service account must be a member of the study group with the DATA_SCIENTIST role, since
        that is what reading models and their evaluation measures requires.

        organization_id is the site this Monitoring Platform belongs to: of a model's evaluation runs, only the
        federated aggregate (no organization) and this site's own runs are sent. None or "*" sends every run.
        state_file records which models and measures were sent; without it everything is sent once. A run is
        re-read for late measures until run_settle_minutes have passed. request_timeout (seconds) applies to
        every HTTP request.
        """
        self.passport_server_url = passport_server_url.rstrip("/")
        self.study_id = study_id
        self.keycloak_server_url = keycloak_server_url.rstrip("/")
        self.keycloak_realm = keycloak_realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.logstash_url = logstash_url
        self.logstash_basic_auth = logstash_basic_auth
        self.organization_id = None if organization_id in (None, "", "*") else organization_id
        self.state_file = state_file
        self.run_settle_minutes = run_settle_minutes
        self.request_timeout = request_timeout
        self.token = self._authenticate()

    def parse_ts(self, ts_str: str) -> datetime:
        """
        Parse an ISO timestamp string into a timezone-aware UTC datetime.

        - If ts_str has timezone info (e.g., 'Z', '+00:00', '+03:00'), preserve it and convert to UTC.
        - If ts_str is naive (no timezone), assume UTC (project convention) and make it UTC-aware.
        """
        dt = isoparse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    def _authenticate(self) -> str:
        """
        Obtain an access token for this connector's Keycloak service account.

        :return token: The access token used as a bearer token for every Passport call.
        :raise AuthenticationError: when Keycloak cannot be reached or refuses the client credentials.
        """
        token_url = f"{self.keycloak_server_url}/realms/{self.keycloak_realm}/protocol/openid-connect/token"
        try:
            response = requests.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }, timeout=self.request_timeout)
            response.raise_for_status()
            return response.json().get("access_token")
        except (requests.RequestException, ValueError) as e:
            raise AuthenticationError(f"Could not authenticate as {self.client_id} at {token_url}: {e}") from e

    def fetch_experiments(self) -> list[Experiment]:
        """
        Fetch experiments from the AI4HF Passport Server.

        :return response: List of Experiments from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/experiment?studyId={self.study_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers, timeout=self.request_timeout)

        # If token is expired, refresh and retry the request.
        response = self._refreshTokenAndRetry(response, headers, payload, url)
        response.raise_for_status()

        response_array = response.json()
        response_experiments: list[Experiment] = []
        for experiment_json in response_array:
            response_experiments.append(Experiment(
                experimentId=experiment_json.get('experimentId'),
                researchQuestion=experiment_json.get('researchQuestion'),
                studyId=experiment_json.get('studyId')
            ))

        return response_experiments

    def fetch_model_evaluations(self, model_id: str) -> list[ModelEvaluation]:
        """
        Fetch the evaluation runs of a model from the AI4HF Passport Server.

        :param model_id: The related ID of the model for which the evaluation runs should be fetched.
        :return response: List of ModelEvaluations from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/model-evaluation?studyId={self.study_id}&modelId={model_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers, timeout=self.request_timeout)

        # If token is expired, refresh and retry the request.
        response = self._refreshTokenAndRetry(response, headers, payload, url)
        response.raise_for_status()

        response_array = response.json()
        response_model_evaluations: list[ModelEvaluation] = []
        for model_evaluation_json in response_array:
            response_model_evaluations.append(ModelEvaluation(
                modelEvaluationId=model_evaluation_json.get('modelEvaluationId'),
                modelId=model_evaluation_json.get('modelId'),
                organizationId=model_evaluation_json.get('organizationId'),
                trigger=model_evaluation_json.get('trigger'),
                aggregationMethod=model_evaluation_json.get('aggregationMethod'),
                executedAt=model_evaluation_json.get('executedAt'),
                executedBy=model_evaluation_json.get('executedBy'),
                description=model_evaluation_json.get('description')
            ))
        return response_model_evaluations

    def fetch_evaluation_measures(self, model_evaluation_id: str) -> list[EvaluationMeasure]:
        """
        Fetch the evaluation measures produced by an evaluation run.

        :param model_evaluation_id: The ID of the evaluation run whose measures should be fetched.
        :return response: List of EvaluationMeasures from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/evaluation-measure?studyId={self.study_id}&modelEvaluationId={model_evaluation_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers, timeout=self.request_timeout)

        # If token is expired, refresh and retry the request.
        response = self._refreshTokenAndRetry(response, headers, payload, url)
        response.raise_for_status()

        response_array = response.json()
        response_evaluation_measures: list[EvaluationMeasure] = []
        for evaluation_measure_json in response_array:
            response_evaluation_measures.append(EvaluationMeasure(
                name=evaluation_measure_json.get('name'),
                value=evaluation_measure_json.get('value'),
                dataType=evaluation_measure_json.get('dataType'),
                description=evaluation_measure_json.get('description'),
                measureId=evaluation_measure_json.get('measureId'),
                modelEvaluationId=evaluation_measure_json.get('modelEvaluationId')
            ))
        return response_evaluation_measures

    def _refreshTokenAndRetry(self, response, headers, payload, url):
        """
        Refresh the token and retry the request if the previous response indicates the token is expired.

        :param response: Response object from the previous request.
        :param headers: Headers object from the previous request.
        :param payload: Payload object from the previous request.
        :param url: The URL of the request.
        :return response: The response from the server.
        """
        if response.status_code == 401:  # Token expired, refresh and retry
            self.token = self._authenticate()
            headers["Authorization"] = f"Bearer {self.token}"
            response = requests.get(url, json=payload, headers=headers, timeout=self.request_timeout)
            if response.status_code == 401:
                raise AuthenticationError(f"The Passport rejects a fresh token of {self.client_id} (401 on {url}).")
        return response

    def fetch_models(self) -> list[Model]:
        """
        Fetch models from the AI4HF Passport Server.

        :return response: List of Models from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/model?studyId={self.study_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers, timeout=self.request_timeout)

        # If token is expired, refresh and retry the request.
        response = self._refreshTokenAndRetry(response, headers, payload, url)
        response.raise_for_status()

        response_array = response.json()
        response_models: list[Model] = []
        for model_json in response_array:
            response_models.append(Model(
                version=model_json.get('version'),
                tag=model_json.get('tag'),
                modelType=model_json.get('modelType'),
                productIdentifier=model_json.get('productIdentifier'),
                trlLevel=model_json.get('trlLevel'),
                license=model_json.get('license'),
                primaryUse=model_json.get('primaryUse'),
                secondaryUse=model_json.get('secondaryUse'),
                intendedUsers=model_json.get('intendedUsers'),
                counterIndications=model_json.get('counterIndications'),
                ethicalConsiderations=model_json.get('ethicalConsiderations'),
                limitations=model_json.get('limitations'),
                fairnessConstraints=model_json.get('fairnessConstraints'),
                createdAt=model_json.get('createdAt'),
                createdBy=model_json.get('createdBy'),
                lastUpdatedBy=model_json.get('lastUpdatedBy'),
                modelId=model_json.get('modelId'),
                learningProcessId=model_json.get('learningProcessId'),
                studyId=model_json.get('studyId'),
                experimentId=model_json.get('experimentId'),
                name=model_json.get('name'),
                ownerOrganizationId=model_json.get('ownerOrganizationId')
            ))
        return response_models

    def sent_monitoring_platform_evaluation_measure(self,
                                                    monitoring_platform_evaluation_measure: MonitoringPlatformEvaluationMeasure):
        """
        Submit an evaluation measure to the monitoring platform.

        :param monitoring_platform_evaluation_measure: The evaluation measure object to be sent.
        """
        self._post_event(monitoring_platform_evaluation_measure.to_event())

    def send_monitoring_platform_model(self, monitoring_platform_model: MonitoringPlatformModel):
        """
        Register a Passport model in the monitoring platform (the "model" event).

        :param monitoring_platform_model: The model event to be sent.
        """
        self._post_event(monitoring_platform_model.to_event())

    def _post_event(self, payload: dict):
        """Post one event to the monitoring platform's Logstash."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.logstash_basic_auth}"
        }
        response = requests.post(self.logstash_url, json=payload, headers=headers, timeout=self.request_timeout)
        response.raise_for_status()

    def _in_scope(self, model_evaluation: ModelEvaluation) -> bool:
        """
        Whether an evaluation run belongs on this site's dashboards.

        Runs with trigger "monitoring" are summaries this site's own Monitoring Platform evidence produced (the
        node agent's monitoring import); sending them back would loop. Of the rest, the federated aggregate and
        this site's own runs are sent; other sites' runs stay out of this site's dashboards.
        """
        if (model_evaluation.trigger or "").lower() == "monitoring":
            return False
        if not self.organization_id:
            return True
        return model_evaluation.organizationId in (None, "", self.organization_id)

    def _compute_round_map(self, model_list: list[Model]) -> dict[str, int]:
        """
        Compute round numbers using ALL models (not only new ones).
        Round number is the 1..N position of a model within its experiment, ordered by createdAt ascending.

        Notes:
        - If createdAt ties occur, we add a deterministic tie-breaker (modelId).
        - Models missing required fields are skipped to avoid crashes.
        """
        models_by_experiment = defaultdict(list)

        for m in model_list:
            if not getattr(m, "createdAt", None) or not getattr(m, "experimentId", None) or not getattr(m, "modelId", None):
                continue
            models_by_experiment[m.experimentId].append(m)

        round_map: dict[str, int] = {}

        for experiment_id, models in models_by_experiment.items():
            sorted_all = sorted(
                models,
                key=lambda m: (self.parse_ts(m.createdAt), m.modelId)
            )
            for round_number, model in enumerate(sorted_all, start=1):
                round_map[model.modelId] = round_number

        return round_map

    def _now(self) -> datetime:
        return datetime.now(UTC)

    def _run_time(self, model_evaluation: ModelEvaluation, model: Model) -> datetime:
        """When a run happened: its executedAt (the Passport fills it on create), else the model's createdAt."""
        return self.parse_ts(model_evaluation.executedAt or model.createdAt)

    @staticmethod
    def _fingerprint(metrics: dict) -> str:
        return hashlib.sha256(json.dumps(metrics, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    def fetch_and_send_evaluation_measures(self) -> int:
        """
        Fetch data from AI4HF Passport Server, transform it, and send it to the monitoring platform.

        Important behavior:
        - Round numbers are computed from ALL historical models first.
        - What was sent is tracked per model (with a fingerprint of its aggregate metrics) and per measure, so
          measures and runs the Passport client writes after an earlier pass are still sent on a later one.
        - A run is re-checked on every pass until it is older than run_settle_minutes (counted from its
          executedAt, or from when the connector first saw it if later); then it is "settled" and no longer read.
        - State is saved after every delivered event, so a failure never re-sends what already went out.
        - An error while processing one model (an HTTP error or timeout reading its runs or measures, an
          unparsable date, ...) is logged and the next model is processed; the failed model's unsent events stay
          unsent in the state and are retried on the next pass. Authentication and state file errors stop the pass.

        :return: the number of models that failed in this pass.
        """
        print("Fetching the data from AI4HF Passport Server...", flush=True)
        failed = 0

        # 1) Fetch ALL models first; round numbers come from the whole history.
        model_list = []
        for m in self.fetch_models():
            if not getattr(m, "createdAt", None):
                continue
            try:
                self.parse_ts(m.createdAt)
            except Exception as e:  # noqa: BLE001 - one model must not stop the others
                failed += 1
                print(f"[ERROR] Model {m.modelId} ({m.name!r}) failed: createdAt {m.createdAt!r} is not a date "
                      f"({type(e).__name__}: {e}); it is left out of this run.", flush=True)
                continue
            model_list.append(m)
        round_map = self._compute_round_map(model_list)

        # 2) What was sent before. Written back before anything is sent: a state file that cannot be written stops
        #    the pass here, instead of after the first event (which every later pass would then send again).
        state = self.load_state()
        self.save_state(state)

        experiment_name_map = {e.experimentId: e.researchQuestion for e in self.fetch_experiments()}
        counts = {"models": 0, "measures": 0, "skipped": 0}
        seen_runs: set[str] = set()
        seen_organizations: set[str] = set()

        for model in sorted(model_list, key=lambda m: (self.parse_ts(m.createdAt), m.modelId)):
            try:
                self._process_model(model, state, round_map, experiment_name_map, counts, seen_runs,
                                    seen_organizations)
            except (AuthenticationError, StateFileError):
                raise  # no other model would get further
            except Exception as e:  # noqa: BLE001 - one model must not stop the others; retried on the next run
                failed += 1
                print(f"[ERROR] Model {model.modelId} ({model.name!r}) failed: {type(e).__name__}: {e}. Its unsent "
                      f"events are retried on the next run.", flush=True)
            self.save_state(state)

        # Runs that no longer exist are dropped - unless a model failed, since its runs were not seen in this pass.
        if not failed:
            for run_id in [r for r in state["pendingRuns"] if r not in seen_runs]:
                del state["pendingRuns"][run_id]
        self.save_state(state)

        if self.organization_id and seen_organizations and self.organization_id not in seen_organizations:
            print(f"[WARN] ORGANIZATION_ID={self.organization_id} matches no evaluation run in study {self.study_id}, "
                  f"but runs exist for organization(s) {', '.join(sorted(seen_organizations))}: only the federated "
                  f"aggregate is sent. Check ORGANIZATION_ID for a typo.", flush=True)

        if any(counts.values()):
            print(f"Sent {counts['models']} model event(s) and {counts['measures']} evaluation measure(s) to the "
                  f"monitoring platform; skipped {counts['skipped']} unparsable measure(s).", flush=True)
        else:
            print("Nothing new to send.", flush=True)
        if failed:
            print(f"[ERROR] {failed} model(s) failed in this run (logged above); they are retried on the next run.",
                  flush=True)
        return failed

    def _process_model(self, model: Model, state: dict, round_map: dict, experiment_name_map: dict, counts: dict,
                       seen_runs: set, seen_organizations: set):
        """Send what is new for one model: its "model" event and the unsent measures of its unsettled runs."""
        all_runs = self.fetch_model_evaluations(model.modelId)
        seen_runs.update(r.modelEvaluationId for r in all_runs)
        seen_organizations.update(r.organizationId for r in all_runs if r.organizationId)
        runs = [r for r in all_runs if self._in_scope(r)]

        measures_cache: dict[str, list[EvaluationMeasure]] = {}

        def measures_of(run: ModelEvaluation) -> list[EvaluationMeasure]:
            if run.modelEvaluationId not in measures_cache:
                measures_cache[run.modelEvaluationId] = self.fetch_evaluation_measures(run.modelEvaluationId)
            return measures_cache[run.modelEvaluationId]

        self._send_model_if_changed(model, runs, state, measures_of, counts)

        for model_evaluation in runs:
            if model_evaluation.modelEvaluationId not in state["settledRuns"]:
                self._send_run_measures(model, model_evaluation, state, measures_of(model_evaluation),
                                        round_map, experiment_name_map, counts)

    def _send_model_if_changed(self, model: Model, runs: list[ModelEvaluation], state: dict, measures_of,
                               counts: dict):
        """
        Send the "model" event for a new model, and again whenever its aggregate metrics changed (the aggregate run,
        or its measures, may be written after the model). Once the aggregate run is settled it is not re-read.
        """
        aggregate = self._aggregate_run(runs)
        known = model.modelId in state["models"]
        if known and (aggregate is None or aggregate.modelEvaluationId in state["settledRuns"]):
            return
        metrics = self._metrics_of(measures_of(aggregate)) if aggregate else {}
        fingerprint = self._fingerprint(metrics)
        if state["models"].get(model.modelId) == fingerprint:
            return
        self.send_monitoring_platform_model(MonitoringPlatformModel(
            model_id=model.modelId,
            model_name=model.name,
            version=model.version,
            experiment_id=model.experimentId,
            owner_organization_id=model.ownerOrganizationId,
            created_at=self.parse_ts(model.createdAt).isoformat(),
            evaluation_metrics=metrics,
        ))
        state["models"][model.modelId] = fingerprint
        counts["models"] += 1
        self.save_state(state)

    def _send_run_measures(self, model: Model, model_evaluation: ModelEvaluation, state: dict, measures,
                           round_map: dict, experiment_name_map: dict, counts: dict):
        """Send the measures of a run that were not sent yet; settle the run once it is old enough."""
        run_id = model_evaluation.modelEvaluationId
        entry = state["pendingRuns"].get(run_id)
        if entry is None:
            entry = state["pendingRuns"][run_id] = {"firstSeen": self._now(), "sent": set(), "skipped": set()}

        for measure in measures:
            measure_id = measure.measureId
            if not measure_id or measure_id in entry["sent"] or measure_id in entry["skipped"]:
                continue
            try:
                value = float(measure.value)
                if not math.isfinite(value):
                    raise ValueError("not a finite number")
            except (TypeError, ValueError) as e:
                # Logged once: the measure is recorded as skipped, so later passes do not log it again.
                print(f"[WARN] Skipping evaluation measure {measure_id} ({measure.name!r}) of run {run_id}, model "
                      f"{model.modelId}: value {measure.value!r} is not a number ({e}).", flush=True)
                entry["skipped"].add(measure_id)
                counts["skipped"] += 1
                self.save_state(state)
                continue
            self.sent_monitoring_platform_evaluation_measure(MonitoringPlatformEvaluationMeasure(
                evaluation_measure_id=measure_id,
                experiment_id=model.experimentId,
                experiment_name=experiment_name_map.get(model.experimentId),
                name=dashboard_measure_name(measure.name),
                value=value,
                dataType=measure.dataType,
                round_number=round_map.get(model.modelId, 1),
                timestamp=model_evaluation.executedAt or model.createdAt,
                model_id=model.modelId,
                model_name=model.name,
                model_evaluation_id=run_id,
                organization_id=model_evaluation.organizationId or None,
            ))
            entry["sent"].add(measure_id)
            counts["measures"] += 1
            self.save_state(state)

        # Every measure read in this pass went out (or was skipped); stop re-reading the run once it has settled.
        settle_from = max(self._run_time(model_evaluation, model), entry["firstSeen"])
        if self._now() - settle_from >= timedelta(minutes=self.run_settle_minutes):
            state["settledRuns"].add(run_id)
            del state["pendingRuns"][run_id]

    @staticmethod
    def _aggregate_run(runs: list[ModelEvaluation]):
        """The model's federated aggregate training run (no organization), if any."""
        return next((r for r in runs if not r.organizationId and (r.trigger or "training") == "training"), None)

    @staticmethod
    def _metrics_of(measures: list[EvaluationMeasure]) -> dict:
        """Measures keyed by dashboard name; unparsable values are left out."""
        metrics = {}
        for measure in measures:
            try:
                value = float(measure.value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(value):
                metrics[dashboard_measure_name(measure.name)] = value
        return metrics

    def load_state(self) -> dict:
        """
        Load what was sent:
        - models: model id -> fingerprint of the aggregate metrics last sent in its "model" event
        - settledRuns: runs no longer re-read
        - pendingRuns: run id -> firstSeen and the ids of its measures sent / skipped so far

        No state file (a new installation) means nothing was sent yet, so everything is sent once.
        An unreadable state file stops the run rather than re-sending everything.
        """
        if not os.path.exists(self.state_file):
            return {"models": {}, "settledRuns": set(), "pendingRuns": {}}
        try:
            with open(self.state_file, "r") as f:
                raw = json.load(f)
            pending = {run_id: {"firstSeen": self.parse_ts(entry["firstSeen"]),
                                "sent": set(entry.get("sent", [])), "skipped": set(entry.get("skipped", []))}
                       for run_id, entry in raw.get("pendingRuns", {}).items()}
            return {"models": dict(raw.get("models", {})),
                    "settledRuns": set(raw.get("settledRuns", [])),
                    "pendingRuns": pending}
        except Exception as e:
            raise StateFileError(f"State file {self.state_file} is unreadable ({e}); refusing to run, since that would "
                               f"re-send everything. Fix or delete it.") from e

    def save_state(self, state: dict):
        """Persist what was sent, atomically (temp file in the same directory + os.replace)."""
        data = {
            "models": dict(sorted(state["models"].items())),
            "settledRuns": sorted(state["settledRuns"]),
            "pendingRuns": {run_id: {"firstSeen": entry["firstSeen"].isoformat(),
                                     "sent": sorted(entry["sent"]), "skipped": sorted(entry["skipped"])}
                            for run_id, entry in sorted(state["pendingRuns"].items())},
        }
        directory = os.path.dirname(os.path.abspath(self.state_file))
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".sent-", suffix=".tmp", dir=directory)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.state_file)
        except Exception as e:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            print(f"[ERROR] !!! Failed to save the state file {self.state_file}: {e}. Stopping, so that events "
                  f"already delivered are not sent again once it can be written. !!!", flush=True)
            raise StateFileError(f"Failed to save the state file {self.state_file}: {e}") from e


def resolve_organization_filter(raw: str):
    """
    ORGANIZATION_ID is required: this site's Passport organization id, or "*" for all organizations.

    :return: the organization id, or None for "*".
    :raise ValueError: when it is unset or empty, so a missing setting never silently widens the filter.
    """
    value = (raw or "").strip()
    if not value:
        raise ValueError("ORGANIZATION_ID is not set. Set it to this site's Passport organization id (only the "
                         "federated aggregate and this site's evaluation runs are sent), or to * to send the runs "
                         "of all organizations.")
    return None if value == "*" else value


MIN_RUN_SETTLE_MINUTES = 15


def resolve_run_settle_minutes(raw: str) -> int:
    """
    RUN_SETTLE_MINUTES (default 60): how long a run is re-read for measures written after it was first seen.

    :raise ValueError: when it is not a whole number or below 15 - a shorter window could settle a run whose
                       measures the Passport client is still writing, and those would never be sent.
    """
    value = (raw or "").strip() or "60"
    try:
        minutes = int(value)
    except ValueError:
        raise ValueError(f"RUN_SETTLE_MINUTES={value!r} is not a whole number of minutes.") from None
    if minutes < MIN_RUN_SETTLE_MINUTES:
        raise ValueError(f"RUN_SETTLE_MINUTES={minutes} is too small: it must be at least {MIN_RUN_SETTLE_MINUTES} "
                         f"minutes, so that measures written after a run was first seen are still sent.")
    return minutes


def main() -> int:
    print("passport-monitoring-platform-connector has been started.")
    passport_server_url = os.getenv("PASSPORT_SERVER_URL", "http://localhost:80/ai4hf/passport/api")
    study_id = os.getenv("STUDY_ID", "initial_study")
    keycloak_server_url = os.getenv("KEYCLOAK_SERVER_URL", "http://localhost:8081")
    keycloak_realm = os.getenv("KEYCLOAK_REALM", "AI4HF-Authorization")
    client_id = os.getenv("CLIENT_ID", "ai4hf-monitoring-connector")
    client_secret = os.getenv("CLIENT_SECRET", "")
    logstash_url = os.getenv("LOGSTASH_URL", "http://localhost:5000")
    logstash_basic_auth = os.getenv(
        "LOGSTASH_BASIC_AUTH",
        "bG9nc3Rhc2hfaW50ZXJuYWw6MnNnUWRIMEtySGE1YzJsUzBMR2c="
    )
    # What was sent (JSON), on the persistent /data volume; without it everything is sent once.
    state_file = os.getenv("STATE_FILE") or "/data/sent.json"

    try:
        # The site this Monitoring Platform belongs to (Passport organization id), or * for every organization.
        organization_id = resolve_organization_filter(os.getenv("ORGANIZATION_ID"))
        run_settle_minutes = resolve_run_settle_minutes(os.getenv("RUN_SETTLE_MINUTES"))
        request_timeout = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "60"))
        if request_timeout <= 0:
            raise ValueError("REQUEST_TIMEOUT_SECONDS must be a positive number of seconds.")
    except ValueError as e:
        print(f"[{datetime.now()}] [FATAL] Invalid configuration: {e}", flush=True)
        return 2
    if organization_id:
        print(f"Organization filter: the federated aggregate and organization {organization_id}'s evaluation runs.",
              flush=True)
    else:
        print("Organization filter: none (ORGANIZATION_ID=*), the evaluation runs of all organizations are sent.",
              flush=True)

    try:
        connector = MonitoringPlatformConnector(
            passport_server_url=passport_server_url,
            study_id=study_id,
            keycloak_server_url=keycloak_server_url,
            keycloak_realm=keycloak_realm,
            client_id=client_id,
            client_secret=client_secret,
            logstash_url=logstash_url,
            logstash_basic_auth=logstash_basic_auth,
            state_file=state_file,
            organization_id=organization_id,
            run_settle_minutes=run_settle_minutes,
            request_timeout=request_timeout,
        )

        failed = connector.fetch_and_send_evaluation_measures()
    except Exception as e:
        print(f"[{datetime.now()}] CRON ERROR: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        return 1
    # Some models failed (each logged) and are retried on the next run; the others went through.
    return 5 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
