import json
import csv
import sys

def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else "raw-telemetry.jsonl"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "telemetry.csv"

    rows = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                metrics = data.get("Metrics", {})

                # Flatten everything into one row
                row = {
                    "DeviceType": data.get("DeviceType"),
                    "AveragePacketRate": metrics.get("AveragePacketRate"),
                    "TotalFailedLogins": metrics.get("TotalFailedLogins"),
                    "SuccessfulLogins": metrics.get("SuccessfulLogins"),
                    "FailedLoginRate": metrics.get("FailedLoginRate"),
                    "UniqueSourceIps": metrics.get("UniqueSourceIps"),
                    "FailedToSuccessRatio": metrics.get("FailedToSuccessRatio"),
                    "UniquePortsAccessed": metrics.get("UniquePortsAccessed"),
                    "ConnectionAttemptsPerSecond": metrics.get("ConnectionAttemptsPerSecond"),
                    "AverageConnectionDurationMs": metrics.get("AverageConnectionDurationMs"),
                    "NewConnectionsPerSecond": metrics.get("NewConnectionsPerSecond"),
                    "TrafficVolumeBytes": metrics.get("TrafficVolumeBytes"),
                    "OutgoingBytes": metrics.get("OutgoingBytes"),
                    "IncomingBytes": metrics.get("IncomingBytes"),
                    "OutgoingIncomingRatio": metrics.get("OutgoingIncomingRatio"),
                    "AverageCpuUsage": metrics.get("AverageCpuUsage"),
                    "TimeOfDay": metrics.get("TimeOfDay"),
                    "AfterHoursActivity": metrics.get("AfterHoursActivity"),

                    # 🎯 Target column
                    "Label": data.get("Label"),
                }

                rows.append(row)

            except json.JSONDecodeError:
                print(f"Skipping bad line {line_number}")

    # Write CSV
    if not rows:
        print("No valid data found.")
        return

    fieldnames = rows[0].keys()

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ CSV created: {output_path}")
    print(f"Total rows: {len(rows)}")


if __name__ == "__main__":
    main()