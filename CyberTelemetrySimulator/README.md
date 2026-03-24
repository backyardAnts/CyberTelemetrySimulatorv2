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
Baseline traffic shifts with a simulated clock and attack likelihood increases after hours in production mode.

Configurable knobs in `Config/simulatorSettings.json`:
- `businessHoursStart` / `businessHoursEnd` (defaults `9` and `17`)
- `dayBaselineMultiplier` (default `1.3`)
- `nightBaselineMultiplier` (default `0.7`)
- `hoursPerTick` (default `1.0`)
- `useRandomTimeOfDay` (default `false`)
- `useManualTimeOfDay` (default `false`)
- `manualHour` (0-23, default `0`)
- `afterHoursAttackMultiplier` (default `2.0`)

Effects:
- The simulator advances a cyclic clock by `hoursPerTick` each tick, wrapping 23 → 0.
- Smooth diurnal curves scale packet rate, traffic volume, connections, and CPU usage.
- When `useRandomTimeOfDay` is enabled, each tick samples a new hour instead of using the clock.
- When `useManualTimeOfDay` is enabled, the simulator uses `manualHour` for TimeOfDay and after-hours logic.
- Outside business hours, attack start probability is multiplied by `afterHoursAttackMultiplier` (clamped to 1.0).
