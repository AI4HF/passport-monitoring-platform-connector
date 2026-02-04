from collections import defaultdict
from dateutil.parser import isoparse
from dateutil.tz import UTC
from datetime import datetime
from models import *
import requests
import os
import traceback


class MonitoringPlatformConnector:
    """
    Monitoring Connector that fetches data from AI4HF Passport Server and sends them into the monitoring platform.
    """

    def __init__(self, passport_server_url: str, study_id: str, connector_secret: str, logstash_url: str,
                 logstash_basic_auth: str, timestamp_file: str):
        """
        Initialize the API client with authentication and study details.
        """
        self.passport_server_url = passport_server_url
        self.study_id = study_id
        self.connector_secret = connector_secret
        self.logstash_url = logstash_url
        self.logstash_basic_auth = logstash_basic_auth
        self.timestamp_file = timestamp_file
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
        Authenticate with login endpoint and retrieve an access token.
        """
        auth_url = f"{self.passport_server_url}/user/connector/login"
        response = requests.post(auth_url, data=self.connector_secret)
        response.raise_for_status()
        return response.json().get("access_token")

    def fetch_experiments(self) -> list[Experiment]:
        """
        Fetch experiments from the AI4HF Passport Server.

        :return response: List of Experiments from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/experiment?studyId={self.study_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers)

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

    def fetch_evaluation_measures(self, model_id: str) -> list[EvaluationMeasure]:
        """
        Fetch evaluation measures from the AI4HF Passport Server.

        :param model_id: The related ID of the model for which the evaluation measures should be fetched.
        :return response: List of EvaluationMeasures from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/evaluation-measure?studyId={self.study_id}&modelId={model_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers)

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
                modelId=evaluation_measure_json.get('modelId')
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
            return requests.get(url, json=payload, headers=headers)
        return response

    def fetch_models(self) -> list[Model]:
        """
        Fetch models from the AI4HF Passport Server.

        :return response: List of Models from the AI4HF Passport Server.
        """
        url = f"{self.passport_server_url}/model?studyId={self.study_id}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        payload = {}

        response = requests.get(url, json=payload, headers=headers)

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
                owner=model_json.get('owner')
            ))
        return response_models

    def sent_monitoring_platform_evaluation_measure(self,
                                                    monitoring_platform_evaluation_measure: MonitoringPlatformEvaluationMeasure):
        """
        Submit an evaluation measure to the monitoring platform.

        :param monitoring_platform_evaluation_measure: The evaluation measure object to be sent.
        """
        url = f"{self.logstash_url}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.logstash_basic_auth}"
        }

        payload = {
            "event_type": monitoring_platform_evaluation_measure.event_type,
            "evaluation_measure_id": monitoring_platform_evaluation_measure.evaluation_measure_id,
            "experiment_id": monitoring_platform_evaluation_measure.experiment_id,
            "experiment_name": monitoring_platform_evaluation_measure.experiment_name,
            "name": monitoring_platform_evaluation_measure.name,
            "value": monitoring_platform_evaluation_measure.value,
            "dataType": monitoring_platform_evaluation_measure.dataType,
            "round": monitoring_platform_evaluation_measure.round_number,
            "timestamp": monitoring_platform_evaluation_measure.timestamp
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return

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

    def fetch_and_send_evaluation_measures(self):
        """
        Fetch data from AI4HF Passport Server, transform it, and send it to the monitoring platform.

        Important behavior:
        - Round numbers are computed from ALL historical models first.
        - Only after that, we filter by last_ts to decide what to send.
        """
        print("Fetching the data from AI4HF Passport Server...", flush=True)

        # 1) Fetch ALL models first (no filtering yet).
        model_list = self.fetch_models()
        last_ts = self.load_last_processed_timestamp()

        # 2) Compute round numbers from ALL models.
        round_map = self._compute_round_map(model_list)

        # 3) Now filter models that are newer than the last processed timestamp.
        models_to_send = [
            m for m in model_list
            if getattr(m, "createdAt", None)
               and (last_ts is None or self.parse_ts(m.createdAt) > last_ts)
        ]

        if not models_to_send:
            print("No new models to send.", flush=True)
            return

        # Fetch experiments and build a map (experimentId -> researchQuestion).
        experiment_list = self.fetch_experiments()
        experiment_name_map = {e.experimentId: e.researchQuestion for e in experiment_list}

        print("Transforming the fetched data...", flush=True)

        # Group the filtered models by experiment for stable processing order.
        models_by_experiment = defaultdict(list)
        for model in models_to_send:
            models_by_experiment[model.experimentId].append(model)

        for experiment_id, models in models_by_experiment.items():
            # Sort the NEW models, but round numbers come from the precomputed round_map.
            sorted_models = sorted(models, key=lambda m: (self.parse_ts(m.createdAt), m.modelId))

            for model in sorted_models:
                # Lookup the stable round number computed from ALL historical models.
                round_number = round_map.get(model.modelId, 1)

                # Fetch evaluation measures related to the model.
                evaluation_measures = self.fetch_evaluation_measures(model.modelId)

                # Get experiment name from the map.
                experiment_name = experiment_name_map.get(model.experimentId)

                # Send measures one by one.
                for measure in evaluation_measures:
                    monitoring_platform_evaluation_measure = MonitoringPlatformEvaluationMeasure(
                        evaluation_measure_id=measure.measureId,
                        experiment_id=model.experimentId,
                        experiment_name=experiment_name,
                        name=measure.name,
                        value=float(measure.value),
                        dataType=measure.dataType,
                        round_number=round_number,
                        timestamp=model.createdAt
                    )
                    self.sent_monitoring_platform_evaluation_measure(monitoring_platform_evaluation_measure)

        # 4) Update the timestamp to the newest model that was actually sent.
        sent_sorted = sorted(models_to_send, key=lambda m: (self.parse_ts(m.createdAt), m.modelId))
        latest_ts = self.parse_ts(sent_sorted[-1].createdAt)
        self.save_last_processed_timestamp(latest_ts)

        print("Data is sent to the monitoring platform!", flush=True)

    def load_last_processed_timestamp(self):
        """
        Load the last processed timestamp from a file as a UTC-aware datetime.
        """
        if not os.path.exists(self.timestamp_file):
            print(f"[INFO] Timestamp file not found, assuming first run.")
            return None
        try:
            with open(self.timestamp_file, "r") as f:
                content = f.read().strip()
                if not content:
                    return None

                dt = isoparse(content)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                dt = dt.astimezone(UTC)
                return dt
        except Exception as e:
            print(f"[WARN] Failed to read timestamp file: {e}")
            return None

    def save_last_processed_timestamp(self, ts: datetime):
        """
        Persist the last processed timestamp to a file in UTC ISO format.
        """
        try:
            # Always write a UTC-aware timestamp.
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            ts = ts.astimezone(UTC)

            with open(self.timestamp_file, "w") as f:
                f.write(ts.isoformat())

            print(f"[INFO] Updated last processed timestamp: {ts.isoformat()}")
        except Exception as e:
            print(f"[ERROR] Failed to write timestamp file: {e}")


if __name__ == "__main__":
    print("passport-monitoring-platform-connector has been started.")
    passport_server_url = os.getenv("PASSPORT_SERVER_URL", "http://localhost:80/ai4hf/passport/api")
    study_id = os.getenv("STUDY_ID", "initial_study")
    connector_secret = os.getenv("CONNECTOR_SECRET", "secret_here")
    logstash_url = os.getenv("LOGSTASH_URL", "http://localhost:5000")
    logstash_basic_auth = os.getenv(
        "LOGSTASH_BASIC_AUTH",
        "bG9nc3Rhc2hfaW50ZXJuYWw6MnNnUWRIMEtySGE1YzJsUzBMR2c="
    )
    timestamp_file = os.getenv("TIMESTAMP_FILE", "/data/last_processed_timestamp.txt")

    try:
        connector = MonitoringPlatformConnector(
            passport_server_url=passport_server_url,
            study_id=study_id,
            connector_secret=connector_secret,
            logstash_url=logstash_url,
            logstash_basic_auth=logstash_basic_auth,
            timestamp_file=timestamp_file
        )

        connector.fetch_and_send_evaluation_measures()
    except Exception as e:
        print(f"[{datetime.now()}] CRON ERROR: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
