import json
from collections import Counter
import sys

LABEL_MAP = {
    0: "Normal",
    1: "BruteForce",
    2: "PortScan",
    3: "DDoS",
    4: "Exfiltration",
}


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "cloud-telemetry.jsonl"
    counts = Counter()
    bad_lines = 0

    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                body = data.get("Body", {})
                raw_label = body.get("Label", "Unknown")
                label = LABEL_MAP.get(raw_label, raw_label)
                counts[label] += 1
            except json.JSONDecodeError:
                bad_lines += 1
                print(f"Skipping invalid JSON on line {line_number}")

    total = sum(counts.values())
    print("Total events:", total)

    for label, count in counts.most_common():
        pct = (count / total * 100) if total else 0
        print(f"{label}: {count} ({pct:.2f}%)")

    if bad_lines:
        print("Bad lines skipped:", bad_lines)


if __name__ == "__main__":
    main()
