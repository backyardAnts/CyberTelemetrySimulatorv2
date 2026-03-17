#!/usr/bin/env python3
import argparse
import json
from collections import Counter


ALLOWED_LABELS = {
    "Normal",
    "BruteForce",
    "PortScan",
    "DDoS",
    "Exfiltration",
}

REQUIRED_FIELDS = [
    "Timestamp",
    "DeviceId",
    "DeviceType",
    "Metrics",
    "Label",
]

REQUIRED_METRICS = [
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

NON_NEGATIVE_METRICS = {
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
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate telemetry JSONL datasets for ML training."
    )
    parser.add_argument("path", help="Path to JSONL telemetry file")
    return parser.parse_args()


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_file(path: str) -> dict:
    totals = {
        "total_events": 0,
        "json_errors": 0,
        "schema_errors": 0,
        "missing_metrics": 0,
        "negative_values": 0,
        "cpu_over_100": 0,
        "invalid_time_of_day": 0,
        "unknown_labels": 0,
    }
    label_counts = Counter()
    device_counts = Counter()

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            totals["total_events"] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                totals["json_errors"] += 1
                continue

            missing_fields = [field for field in REQUIRED_FIELDS if field not in record]
            if missing_fields:
                totals["schema_errors"] += 1
                continue

            metrics = record.get("Metrics")
            if not isinstance(metrics, dict):
                totals["schema_errors"] += 1
                continue

            label = record.get("Label")
            if label not in ALLOWED_LABELS:
                totals["unknown_labels"] += 1
            else:
                label_counts[label] += 1

            device_type = record.get("DeviceType")
            if device_type is not None:
                device_counts[device_type] += 1

            for metric in REQUIRED_METRICS:
                if metric not in metrics:
                    totals["missing_metrics"] += 1
                    continue

                value = metrics[metric]
                if metric == "AverageCpuUsage" and is_number(value):
                    if value < 0 or value > 100:
                        totals["cpu_over_100"] += 1
                elif metric == "TimeOfDay" and is_number(value):
                    if value < 0 or value > 23:
                        totals["invalid_time_of_day"] += 1
                elif metric in NON_NEGATIVE_METRICS and is_number(value):
                    if value < 0:
                        totals["negative_values"] += 1

    return {
        "totals": totals,
        "labels": label_counts,
        "devices": device_counts,
    }


def print_report(results: dict) -> None:
    totals = results["totals"]
    labels = results["labels"]
    devices = results["devices"]

    print("========================")
    print("TELEMETRY DATA QA REPORT")
    print("========================")
    print("")
    print(f"Total events: {totals['total_events']}")
    print(f"JSON errors: {totals['json_errors']}")
    print(f"Schema errors: {totals['schema_errors']}")
    print("")
    print("Label distribution:")
    for label in sorted(ALLOWED_LABELS):
        print(f"{label}: {labels.get(label, 0)}")
    print("")
    print("Device distribution:")
    for device in sorted(devices):
        print(f"{device}: {devices[device]}")
    if not devices:
        print("(none)")
    print("")
    print("Metric validation:")
    print(f"Missing metrics: {totals['missing_metrics']}")
    print(f"Negative values: {totals['negative_values']}")
    print(f"CPU >100: {totals['cpu_over_100']}")
    print(f"Invalid TimeOfDay: {totals['invalid_time_of_day']}")
    print(f"Unknown labels: {totals['unknown_labels']}")


def main() -> None:
    args = parse_args()
    results = validate_file(args.path)
    print_report(results)


if __name__ == "__main__":
    main()
