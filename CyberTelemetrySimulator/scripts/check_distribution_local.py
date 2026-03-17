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
    missing_label = 0

    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # ✅ FIX: Label is at root level, not inside "Body"
                raw_label = data.get("Label")

                if raw_label is None:
                    missing_label += 1
                    continue

                # Handles both numeric and string labels
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

    if missing_label:
        print("Lines missing label:", missing_label)


if __name__ == "__main__":
    main()