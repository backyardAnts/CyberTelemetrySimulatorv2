# CyberTelemetrySimulator

Generates labeled telemetry events for multiple device types and persists them as JSONL. The simulator models normal baselines plus attack-driven anomalies so you can prototype detection pipelines.

## Realism upgrades
- Persistent per-device baselines with slow drift instead of full re-randomization every tick.
- Poisson count modeling, log-normal byte volumes, and AR(1) smoothing for CPU/packet rates.
- Time-of-day and weekday/weekend activity multipliers by device type.
- Internal-consistency rules for traffic totals and derived ratios (TrafficVolumeBytes equals IncomingBytes + OutgoingBytes).
- Loud vs stealth attack modes with correlated metric changes.

## Run
```
dotnet run
```

## Training dataset mode
Use a round-robin attack scheduler (BruteForce → PortScan → DDoS → Exfiltration) with fixed episode durations and no probability gating. This yields balanced attack labels and a higher attack share.

```
dotnet run -- --training
```

Key settings in `Config/simulatorSettings.json`:
- `trainingDatasetMode` (default `false`)
- `trainingEpisodeDurationSec` (default `60`)

Counts per label are logged every 1000 events in the console to verify balance live.

## Self-check
```
dotnet run -- --self-check
```

## SOC demo mode
```
dotnet run -- --soc --demo
```

- Alerts are written to `data/alerts.jsonl` under the app base directory. State-change notifications emit `Severity` "Info" with `AlertType` "StateChange".
- Telemetry JSONL output remains in `data/raw-telemetry.jsonl`.

## Azure IoT Hub output
```
dotnet run -- --iot-hub
```

Set the device connection string with either of these:
- Environment variable `IOT_HUB_DEVICE_CONNECTION_STRING`
- `iotHubDeviceConnectionString` in `Config/simulatorSettings.json`

## Time-of-day realism
Baseline traffic now shifts with time of day and attack likelihood increases after hours in production mode. These settings do not affect training mode.

Configurable knobs in `Config/simulatorSettings.json`:
- `businessHoursStart` / `businessHoursEnd` (defaults `9` and `17`)
- `dayBaselineMultiplier` (default `1.3`)
- `nightBaselineMultiplier` (default `0.7`)
- `afterHoursAttackMultiplier` (default `2.0`)

Effects:
- Business hours raise baseline metrics (packet rate, traffic volume, new connections, successful logins, CPU).
- Night hours (00:00–06:00) lower baseline metrics.
- Outside business hours, attack start probability is multiplied by `afterHoursAttackMultiplier` (clamped to 1.0).
