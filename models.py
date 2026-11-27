import json


class EvaluationMeasure:
    def __init__(self, name:str, value: str, dataType: str, description: str, measureId: str, modelEvaluationId: str):
        """
        Initialize the EvaluationMeasure object from arguments.
        """
        self.name = name
        self.value = value
        self.dataType = dataType
        self.description = description
        self.measureId = measureId
        self.modelEvaluationId = modelEvaluationId

    def __str__(self):
        return json.dumps({"measureId": self.measureId, "modelEvaluationId": self.modelEvaluationId,
                           "name": self.name, "value": self.value,
                           "dataType": self.dataType, "description": self.description})


class ModelEvaluation:
    def __init__(self, modelEvaluationId: str, modelId: str, trigger: str = None, aggregationMethod: str = None,
                 executedAt: str = None, executedBy: str = None, organizationId: str = None, description: str = None):
        """
        Initialize the ModelEvaluation object from arguments. Measures belong to a run rather than
        directly to the model, so the connector reads the runs of a model and then their measures.
        """
        self.modelEvaluationId = modelEvaluationId
        self.modelId = modelId
        self.organizationId = organizationId
        self.trigger = trigger
        self.aggregationMethod = aggregationMethod
        self.executedAt = executedAt
        self.executedBy = executedBy
        self.description = description

    def __str__(self):
        return json.dumps({"modelEvaluationId": self.modelEvaluationId, "modelId": self.modelId,
                           "organizationId": self.organizationId, "trigger": self.trigger,
                           "aggregationMethod": self.aggregationMethod, "executedAt": self.executedAt,
                           "executedBy": self.executedBy, "description": self.description})


class Model:
    def __init__(self,
                 version: str = "",
                 tag: str = "",
                 productIdentifier: str = "",
                 trlLevel: str = "",
                 license: str = "",
                 primaryUse: str = "",
                 secondaryUse: str = "",
                 intendedUsers: str = "",
                 counterIndications: str = "",
                 ethicalConsiderations: str = "",
                 limitations: str = "",
                 fairnessConstraints: str = "",
                 createdAt: str = None,
                 createdBy: str = None,
                 lastUpdatedBy: str = None,
                 modelId: str = None,
                 learningProcessId: str = None,
                 studyId: str = None,
                 experimentId: str = None,
                 name: str = None,
                 ownerOrganizationId: str = None,
                 modelType: str = None):
        """
        Initialize the Model object from arguments.
        """
        self.modelId = modelId
        self.learningProcessId = learningProcessId
        self.studyId = studyId
        self.experimentId = experimentId
        self.name = name
        self.version = version
        self.tag = tag
        self.modelType = modelType
        self.productIdentifier = productIdentifier
        self.ownerOrganizationId = ownerOrganizationId
        self.trlLevel = trlLevel
        self.license = license
        self.primaryUse = primaryUse
        self.secondaryUse = secondaryUse
        self.intendedUsers = intendedUsers
        self.counterIndications = counterIndications
        self.ethicalConsiderations = ethicalConsiderations
        self.limitations = limitations
        self.fairnessConstraints = fairnessConstraints
        self.createdAt = createdAt
        self.createdBy = createdBy
        self.lastUpdatedBy = lastUpdatedBy

    def __str__(self):
        return json.dumps({"modelId": self.modelId,
                           "learningProcessId": self.learningProcessId,
                           "studyId": self.studyId,
                           "experimentId": self.experimentId,
                           "name": self.name,
                           "version": self.version,
                           "tag": self.tag,
                           "modelType": self.modelType,
                           "productIdentifier": self.productIdentifier,
                           "ownerOrganizationId": self.ownerOrganizationId,
                           "trlLevel": self.trlLevel,
                           "license": self.license,
                           "primaryUse": self.primaryUse,
                           "secondaryUse": self.secondaryUse,
                           "intendedUsers": self.intendedUsers,
                           "counterIndications": self.counterIndications,
                           "ethicalConsiderations": self.ethicalConsiderations,
                           "limitations": self.limitations,
                           "fairnessConstraints": self.fairnessConstraints,
                           "createdAt": self.createdAt,
                           "createdBy": self.createdBy,
                           "lastUpdatedBy": self.lastUpdatedBy})


class Experiment:
    def __init__(self, experimentId: str, researchQuestion: str, studyId: str):
        """
        Initialize the Experiment object from arguments.
        """
        self.experimentId = experimentId
        self.researchQuestion = researchQuestion
        self.studyId = studyId

    def __str__(self):
        return json.dumps({"experimentId": self.experimentId, "researchQuestion": self.researchQuestion,
                           "studyId": self.studyId})


class MonitoringPlatformEvaluationMeasure:
    def __init__(self, evaluation_measure_id: str, experiment_id: str, experiment_name: str, name: str,
                 value: float, dataType: str, round_number: int, timestamp: str,
                 model_id: str = None, model_name: str = None, model_evaluation_id: str = None,
                 organization_id: str = None):
        """
        Initialize the MonitoringPlatformEvaluationMeasure object from arguments.

        model_id is the Passport's model id, so every measure on the dashboard traces back to the passport of
        the model; organization_id is None for a federated aggregate and the site's id for a per-site run.
        name is the metric name the dashboards use.
        """
        self.event_type = "evaluation_measure"
        self.evaluation_measure_id = evaluation_measure_id
        self.experiment_id = experiment_id
        self.experiment_name = experiment_name
        self.name = name
        self.value = value
        self.dataType = dataType
        self.round_number = round_number
        self.timestamp = timestamp
        self.model_id = model_id
        self.model_name = model_name
        self.model_evaluation_id = model_evaluation_id
        self.organization_id = organization_id

    def to_event(self) -> dict:
        """The Logstash event."""
        return {"event_type": self.event_type, "evaluation_measure_id": self.evaluation_measure_id,
                "experiment_id": self.experiment_id, "experiment_name": self.experiment_name,
                "name": self.name, "value": self.value,
                "dataType": self.dataType, "round": self.round_number, "timestamp": self.timestamp,
                "model_id": self.model_id, "model_name": self.model_name,
                "model_evaluation_id": self.model_evaluation_id, "organization_id": self.organization_id}

    def __str__(self):
        return json.dumps(self.to_event())


class MonitoringPlatformModel:
    def __init__(self, model_id: str, model_name: str, version: str, experiment_id: str,
                 owner_organization_id: str, created_at: str, evaluation_metrics: dict):
        """
        Initialize the MonitoringPlatformModel object from arguments: the "model" event that registers a
        Passport model in the site's Monitoring Platform, with its aggregated training metrics.
        """
        self.event_type = "model"
        self.model_id = model_id
        self.model_name = model_name
        self.version = version
        self.experiment_id = experiment_id
        self.owner_organization_id = owner_organization_id
        self.created_at = created_at
        self.evaluation_metrics = evaluation_metrics

    def to_event(self) -> dict:
        """The Logstash event."""
        return {"event_type": self.event_type, "model_id": self.model_id, "model_name": self.model_name,
                "version": self.version, "description": f"{self.model_name} {self.version}",
                "experiment_id": self.experiment_id, "owner_organization_id": self.owner_organization_id,
                "evaluation_metrics": self.evaluation_metrics, "@timestamp": self.created_at}

    def __str__(self):
        return json.dumps(self.to_event())
