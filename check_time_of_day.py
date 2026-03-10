import json
import math
import statistics as stats
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional

# -----------------------------
# CONFIG: which metrics to compare
# -----------------------------
METRICS_TO_CHECK = [
    "AveragePacketRate",
    "AverageCpuUsage",
    "TrafficVolumeBytes",
    "IncomingBytes",
    "OutgoingBytes",
    "ConnectionAttemptsPerSecond",
    "NewConnectionsPerSecond",
    "TotalFailedLogins",
    "SuccessfulLogins",
    "UniqueSourceIps",
    "UniquePortsAccessed",
    "AverageConnectionDurationMs",
]

# Basic sanity ranges (loose, just to catch obvious bugs)
RANGE_RULES = {
    "AveragePacketRate": (0, 1_000_000),
    "AverageCpuUsage": (0, 100),
    "TrafficVolumeBytes": (0, 1e12),
    "IncomingBytes": (0, 1e12),
    "OutgoingBytes": (0, 1e12),
    "ConnectionAttemptsPerSecond": (0, 1_000_000),
    "NewConnectionsPerSecond": (0, 1_000_000),
    "TotalFailedLogins": (0, 1_000_000),
    "SuccessfulLogins": (0, 1_000_000),
    "UniqueSourceIps": (0, 1_000_000),
    "UniquePortsAccessed": (0, 1_000_000),
    "AverageConnectionDurationMs": (0, 1e9),
    "FailedLoginRate": (0, 1_000_000),  # depends on your definition; just non-negative
    "OutgoingIncomingRatio": (0, 1_000_000),  # can be >1; just non-negative
    "TimeOfDay": (0, 23),
    "AfterHoursActivity": (0, 1),
}

# If after-hours vs business hours should look different, set a minimum % change threshold.
# Example: 10 means at least 10% difference in mean (absolute) for "good separation".
MIN_PCT_CHANGE_FOR_DIFFERENCE = 10.0


@dataclass
class StatSummary:
    count: int
    mean: float
    median: float
    stdev: float
    p10: float
    p90: float


def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def percentile(sorted_vals: List[float], p: float) -> float:
    """p in [0, 100]"""
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1


def summarize(values: List[float]) -> StatSummary:
    values = [v for v in values if v is not None and not math.isnan(v)]
    if not values:
        return StatSummary(0, float("nan"), float("nan"), float("nan"), float("nan"), float("nan"))
    values_sorted = sorted(values)
    mean = sum(values_sorted) / len(values_sorted)
    median = stats.median(values_sorted)
    stdev = stats.pstdev(values_sorted) if len(values_sorted) > 1 else 0.0
    return StatSummary(
        count=len(values_sorted),
        mean=mean,
        median=median,
        stdev=stdev,
        p10=percentile(values_sorted, 10),
        p90=percentile(values_sorted, 90),
    )


def pct_change(a: float, b: float) -> float:
    """Percent change from a -> b, safe for a=0"""
    if a is None or b is None or math.isnan(a) or math.isnan(b):
        return float("nan")
    if a == 0:
        return float("inf") if b != 0 else 0.0
    return ((b - a) / abs(a)) * 100.0


def load_jsonl(path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    bad_lines = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception as e:
                bad_lines.append(f"Line {i}: {e}")
    return events, bad_lines


def validate_event_schema(ev: Dict[str, Any]) -> List[str]:
    issues = []

    # Required top-level fields
    for field in ["Timestamp", "DeviceId", "DeviceType", "Metrics", "Label", "AttackId"]:
        if field not in ev:
            issues.append(f"Missing top-level field: {field}")

    # Metrics must be dict
    m = ev.get("Metrics")
    if not isinstance(m, dict):
        issues.append("Metrics is not an object/dict")
        return issues

    # Required metrics fields (your structure)
    for field in ["TimeOfDay", "AfterHoursActivity"]:
        if field not in m:
            issues.append(f"Missing Metrics field: {field}")

    # Basic range checks
    for k, (lo, hi) in RANGE_RULES.items():
        if k in m:
            v = safe_float(m.get(k))
            if v is None:
                issues.append(f"Non-numeric Metrics.{k} = {m.get(k)!r}")
            else:
                if v < lo or v > hi:
                    issues.append(f"Out-of-range Metrics.{k} = {v} (expected {lo}..{hi})")

    # Cross-field sanity checks
    outb = safe_float(m.get("OutgoingBytes"))
    inb = safe_float(m.get("IncomingBytes"))
    ratio = safe_float(m.get("OutgoingIncomingRatio"))
    if outb is not None and inb is not None and ratio is not None:
        # Allow small error; just catch totally wrong ratios
        if inb == 0 and outb > 0:
            # ratio could be huge; acceptable
            pass
        elif inb > 0:
            expected = outb / inb
            if expected == 0:
                pass
            else:
                if abs(ratio - expected) / max(1e-9, abs(expected)) > 0.5:
                    issues.append(
                        f"OutgoingIncomingRatio seems off: got {ratio}, expected ~{expected:.3f} (OutgoingBytes/IncomingBytes)"
                    )

    return issues


def group_events(events: List[Dict[str, Any]]):
    # device_type -> after_hours_flag (0/1) -> metric -> list[float]
    grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    counts = defaultdict(lambda: Counter())

    # extra checks
    cpu_zero_counter = defaultdict(lambda: Counter())  # device_type -> {flag: count_zero_cpu}
    cpu_total_counter = defaultdict(lambda: Counter())  # device_type -> {flag: total}

    for ev in events:
        dt = str(ev.get("DeviceType", "Unknown"))
        m = ev.get("Metrics", {}) if isinstance(ev.get("Metrics"), dict) else {}
        flag = m.get("AfterHoursActivity", None)
        try:
            flag_int = int(flag)
        except Exception:
            flag_int = -1

        counts[dt][flag_int] += 1

        for metric in METRICS_TO_CHECK:
            if metric in m:
                grouped[dt][flag_int][metric].append(safe_float(m.get(metric)))

        cpu = safe_float(m.get("AverageCpuUsage"))
        if cpu is not None:
            cpu_total_counter[dt][flag_int] += 1
            if cpu == 0:
                cpu_zero_counter[dt][flag_int] += 1

    return grouped, counts, cpu_zero_counter, cpu_total_counter


def print_report(events: List[Dict[str, Any]], bad_lines: List[str], schema_issues: List[Tuple[int, List[str]]]):
    print("=" * 70)
    print("TELEMETRY QA REPORT")
    print("=" * 70)
    print(f"Total parsed events: {len(events)}")
    if bad_lines:
        print(f"JSON parse errors: {len(bad_lines)} (showing up to 5)")
        for msg in bad_lines[:5]:
            print("  -", msg)
    else:
        print("JSON parse errors: 0")

    if schema_issues:
        print(f"Schema/range issues: {len(schema_issues)} events (showing up to 5)")
        for idx, issues in schema_issues[:5]:
            print(f"  Event #{idx}:")
            for it in issues[:8]:
                print("    -", it)
            if len(issues) > 8:
                print("    ...")
    else:
        print("Schema/range issues: 0")

    print("=" * 70)


def compare_time_groups(grouped, counts, cpu_zero_counter, cpu_total_counter, min_diff):
    print("\n" + "=" * 70)
    print("TIME-OF-DAY COMPARISON BY DEVICE TYPE")
    print("AfterHoursActivity: 0=BusinessHours, 1=AfterHours")
    print("=" * 70)

    device_types = sorted(counts.keys())
    if not device_types:
        print("No device types found.")
        return

    for dt in device_types:
        c0 = counts[dt].get(0, 0)
        c1 = counts[dt].get(1, 0)
        c_other = sum(v for k, v in counts[dt].items() if k not in (0, 1))

        print(f"\n--- DeviceType: {dt} ---")
        print(f"Counts  BH(0)={c0}  AH(1)={c1}  OtherFlags={c_other}")

        # CPU zero rate check
        for flag in (0, 1):
            total = cpu_total_counter[dt].get(flag, 0)
            zeros = cpu_zero_counter[dt].get(flag, 0)
            if total > 0:
                pct0 = (zeros / total) * 100.0
                if pct0 > 5:
                    print(f"⚠️  AverageCpuUsage=0 rate for flag {flag}: {pct0:.1f}% ({zeros}/{total})")

        if c0 == 0 or c1 == 0:
            print("⚠️  Not enough data in both groups to compare (need both BH and AH).")
            continue

        # For each metric, compare summaries
        interesting_diffs = 0
        for metric in METRICS_TO_CHECK:
            v0 = grouped[dt][0].get(metric, [])
            v1 = grouped[dt][1].get(metric, [])
            s0 = summarize(v0)
            s1 = summarize(v1)

            if s0.count < 30 or s1.count < 30:
                # avoid noisy comparisons if too small
                continue

            delta = pct_change(s0.mean, s1.mean)  # BH -> AH
            abs_delta = abs(delta) if not math.isnan(delta) else float("nan")

            # "difference" heuristic
            is_diff = (not math.isnan(abs_delta)) and (abs_delta >= min_diff)

            if is_diff:
                interesting_diffs += 1

            tag = "DIFF ✅" if is_diff else "similar"

            print(
                f"{metric:26s} | BH mean={s0.mean:10.3f} med={s0.median:10.3f} "
                f"| AH mean={s1.mean:10.3f} med={s1.median:10.3f} "
                f"| Δmean={delta:8.2f}%  -> {tag}"
            )

        if interesting_diffs == 0:
            print("⚠️  No strong metric differences detected between BH and AH for this device type.")
            print("    (This might be OK if your multipliers are subtle, or if dataset is too small.)")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate telemetry JSONL and compare business-hours vs after-hours behavior per device type."
    )
    parser.add_argument("jsonl_path", help="Path to telemetry .jsonl file (one JSON object per line).")
    parser.add_argument("--min-diff", type=float, default=MIN_PCT_CHANGE_FOR_DIFFERENCE,
                        help="Minimum absolute percent change in mean to count as 'different' (default: 10).")
    args = parser.parse_args()


    events, bad_lines = load_jsonl(args.jsonl_path)

    schema_issues = []
    for i, ev in enumerate(events, 1):
        issues = validate_event_schema(ev)
        if issues:
            schema_issues.append((i, issues))

    print_report(events, bad_lines, schema_issues)

    grouped, counts, cpu_zero_counter, cpu_total_counter = group_events(events)
    compare_time_groups(
    grouped,
    counts,
    cpu_zero_counter,
    cpu_total_counter,
    min_diff=float(args.min_diff)
    )

    print("\nDone.")


if __name__ == "__main__":
    main()