import json
import requests
from datetime import datetime

from azure.eventhub import EventHubConsumerClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError


# =========================
# CONFIG
# =========================

CONSUMER_GROUP = "$Default"

# Replace this later with your real Key Vault URL
KEY_VAULT_URL = "https://anthony-keyvault2.vault.azure.net/"

# This must be the name of the blob container you already created
STORAGE_CONTAINER_NAME = "anthonycontainer"

# This is the JSONL file that will be created inside the blob container
STORAGE_BLOB_NAME = "predictions.jsonl"


# =========================
# KEY VAULT
# =========================

credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)


def get_secret(name):
    return secret_client.get_secret(name).value


EVENTHUB_CONNECTION_STR = get_secret("eventhub-connection-string2")
AML_SCORING_URI = get_secret("aml-scoring-uri")
AML_KEY = get_secret("aml-key")

# Secret in Key Vault that contains your Storage Account connection string
STORAGE_CONNECTION_STRING = get_secret("storage-connection-string2")


# =========================
# AZURE BLOB STORAGE
# =========================

blob_service_client = BlobServiceClient.from_connection_string(
    STORAGE_CONNECTION_STRING
)

container_client = blob_service_client.get_container_client(STORAGE_CONTAINER_NAME)

try:
    container_client.create_container()
    print(f"Created container: {STORAGE_CONTAINER_NAME}")
except ResourceExistsError:
    print(f"Container already exists: {STORAGE_CONTAINER_NAME}")
except Exception as e:
    print("Container check/create warning:", e)

blob_client = container_client.get_blob_client(STORAGE_BLOB_NAME)


def ensure_append_blob():
    """
    Makes sure predictions.jsonl exists as an Append Blob.
    Append Blob is best for adding one JSON line at a time.
    """
    try:
        props = blob_client.get_blob_properties()
        blob_type = str(props.blob_type)

        if "AppendBlob" not in blob_type:
            print("Existing blob is not AppendBlob. Recreating it as AppendBlob...")
            old_data = blob_client.download_blob().readall()
            blob_client.delete_blob()
            blob_client.create_append_blob()

            if old_data:
                blob_client.append_block(old_data)

    except ResourceNotFoundError:
        blob_client.create_append_blob()
        print(f"Created blob file: {STORAGE_BLOB_NAME}")


ensure_append_blob()


# =========================
# AZURE ML CONFIG
# =========================

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {AML_KEY}",
}

COLUMNS = [
    "DeviceType",
    "AveragePacketRate",
    "TotalFailedLogins",
    "SuccessfulLogins",
    "FailedLoginRate",
    "UniqueSourceIps",
    "FailedToSuccessRatio",
    "UniquePortsAccessed",
    "ConnectionAttemptsPerSecond",
    "AverageConnectionDurationMs",
    "NewConnectionsPerSecond",
    "TrafficVolumeBytes",
    "OutgoingBytes",
    "IncomingBytes",
    "OutgoingIncomingRatio",
    "AverageCpuUsage",
    "TimeOfDay",
    "AfterHoursActivity",
]

DEVICE_TYPE_MAP = {
    0: "Workstation",
    1: "WebServer",
    2: "DatabaseServer",
    3: "IoTDevice",
}

LABEL_MAP = {
    0: "Normal",
    1: "PortScan",
    2: "BruteForce",
    3: "DDoS",
    4: "Exfiltration",
}


# =========================
# NORMALIZATION
# =========================


def normalize_device_type(value):
    if isinstance(value, int):
        return DEVICE_TYPE_MAP.get(value, "Workstation")

    if isinstance(value, str):
        stripped = value.strip()

        if stripped.isdigit():
            return DEVICE_TYPE_MAP.get(int(stripped), "Workstation")

        if stripped in DEVICE_TYPE_MAP.values():
            return stripped

    return "Workstation"


def normalize_label(value):
    if isinstance(value, int):
        return LABEL_MAP.get(value, str(value))

    if isinstance(value, str):
        stripped = value.strip()

        if stripped.isdigit():
            return LABEL_MAP.get(int(stripped), stripped)

        return stripped

    return str(value)


def normalize_prediction(prediction):
    if isinstance(prediction, list) and len(prediction) > 0:
        return prediction[0]

    if isinstance(prediction, dict):
        if (
            "result" in prediction
            and isinstance(prediction["result"], list)
            and len(prediction["result"]) > 0
        ):
            return prediction["result"][0]

        if "prediction" in prediction:
            return prediction["prediction"]

        return prediction

    return prediction


# =========================
# AZURE ML SCORING
# =========================


def build_payload(msg):
    metrics = msg["Metrics"]

    row = [
        normalize_device_type(msg.get("DeviceType")),
        float(metrics.get("AveragePacketRate", 0)),
        int(metrics.get("TotalFailedLogins", 0)),
        int(metrics.get("SuccessfulLogins", 0)),
        float(metrics.get("FailedLoginRate", 0)),
        int(metrics.get("UniqueSourceIps", 0)),
        float(metrics.get("FailedToSuccessRatio", 0)),
        int(metrics.get("UniquePortsAccessed", 0)),
        float(metrics.get("ConnectionAttemptsPerSecond", 0)),
        float(metrics.get("AverageConnectionDurationMs", 0)),
        float(metrics.get("NewConnectionsPerSecond", 0)),
        float(metrics.get("TrafficVolumeBytes", 0)),
        float(metrics.get("OutgoingBytes", 0)),
        float(metrics.get("IncomingBytes", 0)),
        float(metrics.get("OutgoingIncomingRatio", 0)),
        float(metrics.get("AverageCpuUsage", 0)),
        int(metrics.get("TimeOfDay", 0)),
        int(metrics.get("AfterHoursActivity", 0)),
    ]

    return {
        "input_data": {
            "columns": COLUMNS,
            "index": [0],
            "data": [row],
        },
        "params": {},
    }


def score_with_azure_ml(msg):
    payload = build_payload(msg)

    response = requests.post(
        AML_SCORING_URI,
        headers=HEADERS,
        json=payload,
        timeout=30,
    )

    print("STATUS:", response.status_code)
    print("RESPONSE:", response.text)

    response.raise_for_status()
    return response.json()


# =========================
# SAVE TO BLOB STORAGE
# =========================


def save_prediction(msg, pred_label):
    row = {
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "device": msg.get("DeviceId", "Unknown"),
        "device_type": normalize_device_type(msg.get("DeviceType")),
        "true_label": normalize_label(msg.get("Label")),
        "prediction": str(pred_label),
    }

    json_line = json.dumps(row) + "\n"

    ensure_append_blob()

    blob_client.append_block(json_line.encode("utf-8"))

    print(
        f"Saved prediction to Blob Storage: {STORAGE_CONTAINER_NAME}/{STORAGE_BLOB_NAME}"
    )


# =========================
# EVENT HUB LISTENER
# =========================


def on_event(partition_context, event):
    raw = None

    try:
        raw = event.body_as_str(encoding="UTF-8")
        print("RAW EVENT:", raw)

        msg = json.loads(raw)

        prediction = score_with_azure_ml(msg)
        pred_label = normalize_prediction(prediction)
        true_label = normalize_label(msg.get("Label"))

        save_prediction(msg, pred_label)

        print("=" * 60)
        print("Device:", msg.get("DeviceId"))
        print("DeviceType raw:", msg.get("DeviceType"))
        print("DeviceType mapped:", normalize_device_type(msg.get("DeviceType")))
        print("True label:", true_label)
        print("Prediction:", pred_label)

        if pred_label != "Normal":
            print("🚨 ATTACK DETECTED:", pred_label)

    except KeyError as e:
        print(f"Missing field in telemetry: {e}")
        print("Telemetry received:", raw)

    except Exception as e:
        print("Error processing event:", e)


def on_error(partition_context, error):
    pid = partition_context.partition_id if partition_context else "N/A"
    print(f"ERROR on partition {pid}: {error}")


def on_partition_initialize(partition_context):
    print(f"[CONNECTED] partition={partition_context.partition_id}")


def on_partition_close(partition_context, reason):
    print(f"[CLOSED] partition={partition_context.partition_id} reason={reason}")


# =========================
# MAIN
# =========================


def main():
    client = EventHubConsumerClient.from_connection_string(
        conn_str=EVENTHUB_CONNECTION_STR,
        consumer_group=CONSUMER_GROUP,
    )

    print("Listening for live telemetry...")
    print(f"Writing predictions to: {STORAGE_CONTAINER_NAME}/{STORAGE_BLOB_NAME}")

    with client:
        client.receive(
            on_event=on_event,
            on_error=on_error,
            on_partition_initialize=on_partition_initialize,
            on_partition_close=on_partition_close,
            starting_position="@latest",
        )


if __name__ == "__main__":
    main()
