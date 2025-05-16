import json


class EvaluationMeasure:
    def __init__(self, name:str, value: str, dataType: str, description: str, measureId: str, modelId: str):
        """
        Initialize the EvaluationMeasure object from arguments.
        """
        self.name = name
        self.value = value
        self.dataType = dataType
        self.description = description
        self.measureId = measureId
        self.modelId = modelId

    def __str__(self):
        return json.dumps({"measureId": self.measureId, "modelId": self.modelId, "name": self.name, "value": self.value,
                           "dataType": self.dataType, "description": self.description})


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
                 owner: str = None,
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
        self.owner = owner
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
                           "owner": self.owner,
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
                 value: float, dataType: str, round_number: int, timestamp: str):
        """
        Initialize the MonitoringPlatformEvaluationMeasure object from arguments.
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

    def __str__(self):
        return json.dumps({"event_type": self.event_type, "evaluation_measure_id": self.evaluation_measure_id,
                           "experiment_id": self.experiment_id, "experiment_name": self.experiment_name,
                           "name": self.name, "value": self.value, "dataType": self.dataType,
                           "round_number": self.round_number, "timestamp": self.timestamp})
