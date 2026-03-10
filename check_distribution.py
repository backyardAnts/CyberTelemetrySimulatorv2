import json
from collections import Counter
import sys


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "data/raw-telemetry.jsonl"
    counts = Counter()

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            data = json.loads(line)
            counts[data.get("Label", "Unknown")] += 1

    total = sum(counts.values())
    print("Total events:", total)
    for label, count in counts.most_common():
        pct = (count / total * 100) if total else 0
        print(f"{label}: {count} ({pct:.2f}%)")


if __name__ == "__main__":
    main()
