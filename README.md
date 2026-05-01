# CyberTelemetrySimulator

`CyberTelemetrySimulator` is a .NET 8 console application that generates synthetic cybersecurity telemetry for a small mixed environment. It simulates normal behavior, injects attack episodes, labels every event, and can publish the results to local JSONL files, Azure IoT Hub, and SQL Server.

The project is useful for:

- Building demo telemetry streams for SOC or SIEM workflows.
- Generating labeled datasets for ML or analytics experiments.
- Producing repeatable attack patterns such as `BruteForce`, `PortScan`, `DDoS`, and `Exfiltration`.
- Testing simple rule-based detection and alerting logic.
- Feeding a separate live dashboard that shows Azure ML predictions over incoming telemetry.

## What the program simulates

Each loop iteration generates one telemetry event per device for this fixed fleet:

- `20` workstations: `WS-001` to `WS-020`
- `8` web servers: `WEB-001` to `WEB-008`
- `5` database servers: `DB-001` to `DB-005`
- `3` IoT devices: `IOT-001` to `IOT-003`

Each event contains:

- Timestamp, device ID, and device type
- A ground-truth attack label
- Optional `AttackId`, `AttackMode`, and `IncidentId`
- Metrics such as packet rate, failed logins, successful logins, unique source IPs, unique ports, connection attempts, traffic volume, incoming/outgoing bytes, CPU usage, time of day, and after-hours activity

The simulator tries to make the data look less random than simple toy generators by using:

- Persistent per-device baselines with gradual drift
- Time-of-day and weekday/weekend activity shaping
- Smoothed metric evolution between ticks
- Correlated attack behavior instead of isolated spikes
- Derived metric consistency such as `TrafficVolumeBytes = IncomingBytes + OutgoingBytes`

## Main project parts

- `Program.cs`: application entry point, mode selection, publisher setup, and main loop
- `Devices/`: per-device simulation logic and device profiles
- `Campaigns/`: attack scheduling and episode management
- `Detection/`: simple rule-based risk scoring used in SOC mode
- `Publishers/`: output sinks for console, JSONL, Azure IoT Hub, alerts, and SQL Server
- `Validation/`: built-in self-check for telemetry consistency
- `Config/`: runtime settings
- `scripts/`: dataset QA and conversion utilities
- `../cyber-dashboard/`: Streamlit dashboard and Azure listener for live prediction monitoring

## Requirements

- .NET 8 SDK
- Azure access to the Key Vault referenced by `Config/simulatorSettings.local.json`

Optional, depending on mode:

- Azure IoT Hub device connection string stored in Key Vault
- SQL Server connection string stored in Key Vault

## Configuration

The simulator reads two configuration files from `CyberTelemetrySimulator/Config/`:

### 1. `simulatorSettings.json`

This file contains the normal runtime settings, including:

- `tickMs`: delay between simulation ticks
- `attackChancePerTick`: probability of starting attacks in normal simulation mode
- `minDurationSec` and `maxDurationSec`: attack duration range
- `outputPath`: local JSONL output path
- `balancedDatasetMode`: enables ratio-driven label balancing
- `trainingDatasetMode`: enables scheduled training episodes
- `trainingEpisodeDurationSec`: duration of each scheduled training episode
- `businessHoursStart` and `businessHoursEnd`
- `dayBaselineMultiplier` and `nightBaselineMultiplier`
- `hoursPerTick`, `useRandomTimeOfDay`, `useManualTimeOfDay`, `manualHour`
- `afterHoursAttackMultiplier`
- `targetClassRatios`
- `totalEventsTarget`

### 2. `simulatorSettings.local.json`

This file is required by the current code. It must contain the Azure Key Vault URL:

```json
{
  "keyVaultUrl": "https://your-vault-name.vault.azure.net/"
}
```

Important: the program exits immediately if this file is missing or if `keyVaultUrl` is not set, even when you only want local file output.

## Azure Key Vault secrets

The application fetches secrets only when the matching output modes are enabled:

- `iot-connection-string`: used by `--iot-hub`
- `iot-connection-string-sql`: used by `--sql`

The application authenticates with `DefaultAzureCredential`, so your local Azure login or environment-based credentials must already work.

## How to run

From the repository root:

```bash
dotnet run --project CyberTelemetrySimulator/CyberTelemetrySimulator.csproj
```

Or from the `CyberTelemetrySimulator/` directory:

```bash
dotnet run
```

The simulator runs continuously until you stop it.

## Output behavior

By default, the program:

- Appends telemetry events to `data/raw-telemetry.jsonl`
- Prints each event to the console when not in SOC mode

When SOC mode is enabled, the console output changes from raw telemetry to detection summaries, and alerts may be written to `data/alerts.jsonl`.

## Command-line modes

### Default mode

```bash
dotnet run
```

Runs the continuous simulator with attack scheduling based on the configured probabilities and settings.

### Self-check mode

```bash
dotnet run -- --self-check
```

Runs internal validation logic and exits. This checks that:

- `TrafficVolumeBytes` matches `IncomingBytes + OutgoingBytes`
- failed-login derived metrics are consistent
- smoothing is not producing unrealistic jumps

### SOC mode

```bash
dotnet run -- --soc
```

Enables rule-based detection and device risk scoring. In this mode:

- telemetry is still written to `data/raw-telemetry.jsonl`
- the console shows per-device risk summaries instead of raw events
- alerts are written to `data/alerts.jsonl`

Risk state thresholds:

- `0-39`: `Normal`
- `40-69`: `Suspicious`
- `70-100`: `UnderAttack`

### Demo SOC mode

```bash
dotnet run -- --soc --demo
```

Runs SOC mode with incident-chain behavior enabled in a more deterministic demo-friendly way.

### Training dataset mode

```bash
dotnet run -- --training
```

Uses a scheduled round-robin style attack campaign instead of normal probabilistic attack starts. This is meant for producing more controlled labeled datasets.

### Azure IoT Hub publishing

```bash
dotnet run -- --iot-hub
```

Publishes each telemetry event to Azure IoT Hub in addition to the local JSONL file.

### SQL Server publishing

```bash
dotnet run -- --sql
```

Publishes each telemetry event into `dbo.TelemetryEvents` in SQL Server in addition to the local JSONL file.

The current code expects that table to already exist.

### Combined modes

Flags can be combined when they make sense. Example:

```bash
dotnet run -- --soc --demo --iot-hub --sql
```

## Attack labels

The simulator can emit these labels:

- `Normal`
- `BruteForce`
- `PortScan`
- `DDoS`
- `Exfiltration`

Attack episodes also carry a mode:

- `Loud`
- `Stealth`

## Detection logic in SOC mode

SOC mode uses a built-in rule-based detector. It scores events from metric thresholds such as:

- failed logins and failed/success ratios for brute force behavior
- unique ports, connection attempts, and short-lived sessions for port scanning
- packet rate, new connections, and traffic volume for DDoS behavior
- outgoing bytes, outgoing/incoming ratio, and after-hours activity for exfiltration behavior

This detector is for simulation and demonstration. It is not a production detection engine.

## Files produced by the simulator

- `data/raw-telemetry.jsonl`: line-delimited telemetry events
- `data/alerts.jsonl`: SOC alerts when `--soc` is enabled

Each line in `raw-telemetry.jsonl` is a single JSON event with enum values serialized as strings.

## Cyber dashboard

The repository also includes a separate dashboard application in the root-level `cyber-dashboard/` folder. This is a Python-based Streamlit frontend plus a listener script that connects the simulator’s Azure telemetry flow to an Azure ML endpoint.

### What it does

The dashboard side of the project is split into two pieces:

- `cyber-dashboard/finaltest.py`: listens to Azure Event Hub, sends incoming telemetry to an Azure ML scoring endpoint, and appends the prediction results into Azure Blob Storage as `predictions.jsonl`
- `cyber-dashboard/app.py`: reads `predictions.jsonl` from Azure Blob Storage and displays a live monitoring dashboard in Streamlit

In practice, the end-to-end flow is:

1. The simulator sends telemetry to Azure IoT Hub when run with `--iot-hub`.
2. That telemetry is expected to reach Event Hub.
3. `finaltest.py` consumes the live events.
4. Each event is scored by an Azure ML endpoint.
5. The prediction result is appended to Blob Storage.
6. `app.py` refreshes every 5 seconds and visualizes the stored predictions.

### Dashboard features

The Streamlit dashboard currently shows:

- total number of scored events
- number of detected attacks versus normal events
- downloadable CSV export for a selected time range
- an attack alert table for non-normal predictions
- a recent predictions table
- prediction count charts
- device-type count charts
- an attack timeline for the first device of each device type

### Dashboard dependencies

The `cyber-dashboard/requirements.txt` file includes:

- `streamlit`
- `streamlit-autorefresh`
- `pandas`
- `requests`
- `azure-eventhub`
- `azure-identity`
- `azure-keyvault-secrets`
- `azure-storage-blob`

### Azure services used by the dashboard

The dashboard code uses:

- Azure Key Vault for secrets
- Azure Event Hub for incoming live telemetry
- Azure Machine Learning for scoring
- Azure Blob Storage for storing prediction history

The code currently expects these Key Vault secrets:

- `eventhub-connection-string2`
- `aml-scoring-uri`
- `aml-key`
- `storage-connection-string2`

The dashboard code also currently hardcodes:

- Key Vault URL: `https://anthony-keyvault2.vault.azure.net/`
- Blob container: `anthonycontainer`
- Blob file: `predictions.jsonl`

### How to run the dashboard locally

From the repository root:

```bash
cd cyber-dashboard
pip install -r requirements.txt
```

Run the Event Hub listener:

```bash
python finaltest.py
```

In a separate terminal, run the Streamlit dashboard:

```bash
streamlit run app.py
```

By default, Streamlit serves the dashboard on port `8501`.

### Docker files

The `cyber-dashboard/` folder includes:

- `Dockerfile.listener`: builds a container that runs `finaltest.py`
- `Dockerfile.app`: builds a container that runs the Streamlit dashboard on port `8501`

## Example workflow

1. Create `Config/simulatorSettings.local.json` with your Key Vault URL.
2. Adjust `Config/simulatorSettings.json` if you want different timing, attack frequency, or time-of-day behavior.
3. If you want the live Azure prediction dashboard, make sure the dashboard-side Azure resources and secrets are configured.
4. Run the simulator with one of the modes above.
5. For the dashboard flow, run the listener in `cyber-dashboard/finaltest.py`.
6. Run the Streamlit UI in `cyber-dashboard/app.py`.
7. Stop the simulator after enough events have been generated.
8. Inspect `data/raw-telemetry.jsonl`, dashboard results in Blob Storage, or run one of the helper scripts.

## Helper scripts

The `scripts/` folder contains small utilities for working with generated datasets, including:

- `validate_telemetry_dataset.py`: basic schema and metric QA for JSONL telemetry
- `convert_jsonl_to_csv.py`: convert telemetry JSONL into CSV
- `check_attack_behavior.py`
- `check_device_and_time_realism.py`
- `check_distribution.py`
- `check_distribution_local.py`
- `check_time_of_day.py`
- `checkdata.py`
- `detect_ml_leakage_risks.py`

Example:

```bash
python CyberTelemetrySimulator/scripts/validate_telemetry_dataset.py CyberTelemetrySimulator/data/raw-telemetry.jsonl
```

## Notes and limitations

- The simulator currently runs forever until interrupted.
- `totalEventsTarget` exists in configuration, but the main loop does not currently stop when that target is reached.
- `simulatorSettings.local.json` is effectively mandatory because startup always requires `keyVaultUrl`.
- SQL output assumes a pre-created `dbo.TelemetryEvents` table.
- The dashboard expects Azure infrastructure and valid Key Vault secrets to already exist.
- The dashboard is stored in the repository root as `cyber-dashboard/`, not inside the .NET project folder.
- The solution file is `CyberTelemetrySimulator.slnx`, and the executable project is `CyberTelemetrySimulator/CyberTelemetrySimulator.csproj`.
