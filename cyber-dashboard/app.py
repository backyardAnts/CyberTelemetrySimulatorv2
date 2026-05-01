import json
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError


# =========================
# STREAMLIT CONFIG
# =========================

st.set_page_config(page_title="Cybersecurity Dashboard", layout="wide")

st_autorefresh(interval=5000, key="refresh")

st.title("Cybersecurity Detection Dashboard")
st.write("Live monitoring for IoT + Azure ML predictions")


# =========================
# AZURE CONFIG
# =========================

# Replace later if needed
KEY_VAULT_URL = "https://anthony-keyvault2.vault.azure.net/"

# This must match your existing blob container name
STORAGE_CONTAINER_NAME = "anthonycontainer"

# This must match the file created by finaltest.py/listener.py
STORAGE_BLOB_NAME = "predictions.jsonl"


# =========================
# KEY VAULT
# =========================

credential = DefaultAzureCredential()

secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)


def get_secret(name):
    return secret_client.get_secret(name).value


@st.cache_resource
def get_blob_client():
    storage_connection_string = get_secret("storage-connection-string2")

    blob_service_client = BlobServiceClient.from_connection_string(
        storage_connection_string
    )

    container_client = blob_service_client.get_container_client(STORAGE_CONTAINER_NAME)

    return container_client.get_blob_client(STORAGE_BLOB_NAME)


# =========================
# LOAD PREDICTIONS FROM BLOB
# =========================


def load_predictions_from_blob():
    rows = []

    try:
        blob_client = get_blob_client()
        blob_data = blob_client.download_blob().readall().decode("utf-8")

    except ResourceNotFoundError:
        return pd.DataFrame()

    except Exception as e:
        st.error(f"Could not read predictions from Blob Storage: {e}")
        return pd.DataFrame()

    for line in blob_data.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    if "time" in df.columns:
        df["time"] = pd.to_datetime(df["time"], errors="coerce")
        df = df.dropna(subset=["time"])
        df = df.sort_values("time", ascending=False)

    return df


# =========================
# DASHBOARD
# =========================

df = load_predictions_from_blob()

if df.empty:
    st.warning(
        "No live predictions yet. Start the listener script and send telemetry from the simulator."
    )

else:
    df["attack_flag"] = df["prediction"].apply(lambda x: 0 if x == "Normal" else 5)

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Events", len(df))
    col2.metric("Attacks Detected", len(df[df["prediction"] != "Normal"]))
    col3.metric("Normal Events", len(df[df["prediction"] == "Normal"]))

    st.subheader("Download Timeline as CSV")

    min_time = df["time"].min().to_pydatetime()
    max_time = df["time"].max().to_pydatetime()

    start_time = st.datetime_input(
        "Start date and time",
        value=min_time,
        step=60,
    )

    end_time = st.datetime_input(
        "End date and time",
        value=max_time,
        step=60,
    )

    timeline_df = df[
        (df["time"] >= pd.to_datetime(start_time))
        & (df["time"] <= pd.to_datetime(end_time))
    ]

    st.write(f"Events in selected timeline: {len(timeline_df)}")

    csv = (
        timeline_df.drop(columns=["attack_flag"], errors="ignore")
        .to_csv(index=False)
        .encode("utf-8")
    )

    st.download_button(
        label="Download selected timeline as CSV",
        data=csv,
        file_name="cybersecurity_timeline.csv",
        mime="text/csv",
    )

    st.subheader("Attack Alerts")
    attack_df = df[df["prediction"] != "Normal"]

    if attack_df.empty:
        st.success("No attacks detected.")
    else:
        st.error(f"{len(attack_df)} attack events detected")
        st.dataframe(
            attack_df.drop(columns=["attack_flag"], errors="ignore"),
            use_container_width=True,
        )

    st.subheader("Recent Predictions")
    st.dataframe(
        df.drop(columns=["attack_flag"], errors="ignore"),
        use_container_width=True,
    )

    st.subheader("Prediction Counts")
    prediction_counts = df["prediction"].value_counts()
    st.bar_chart(prediction_counts)

    if "device_type" in df.columns:
        st.subheader("Device Type Counts")
        device_counts = df["device_type"].value_counts()
        st.bar_chart(device_counts)

    if "device" in df.columns and "device_type" in df.columns and "time" in df.columns:
        st.subheader("Attack Activity per First Device of Each Type")

        df["time_bucket"] = df["time"].dt.floor("5s")

        first_devices = (
            df.sort_values("time").groupby("device_type")["device"].first().tolist()
        )

        filtered_df = df[df["device"].isin(first_devices)]

        attack_timeline = (
            filtered_df.groupby(["time_bucket", "device"])["attack_flag"]
            .max()
            .reset_index()
        )

        pivot_df = attack_timeline.pivot(
            index="time_bucket",
            columns="device",
            values="attack_flag",
        ).fillna(0)

        pivot_df = pivot_df.sort_index()

        pivot_df.index = pivot_df.index.strftime("%Y-%m-%d %H:%M:%S")

        st.line_chart(pivot_df)

        st.caption(f"Showing first device for each type: {', '.join(first_devices)}")
