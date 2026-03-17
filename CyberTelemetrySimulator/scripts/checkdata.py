import json

tele_path = "CyberTelemetrySimulator/data/raw-telemetry.jsonl"
alert_path = "CyberTelemetrySimulator/data/alerts.jsonl"

bad_vol = 0
n = 0
with open(tele_path, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        n += 1
        ev = json.loads(line)
        m = ev.get("Metrics", {})
        inc = m.get("IncomingBytes")
        out = m.get("OutgoingBytes")
        total = m.get("TrafficVolumeBytes")
        if None not in (inc, out, total) and total != inc + out:
            bad_vol += 1

bad_alert = 0
a = 0
with open(alert_path, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        a += 1
        al = json.loads(line)
        score = al.get("RiskScore", None)
        sev = al.get("Severity", None)
        if score == 0 and sev == "Suspicious":
            bad_alert += 1

print("Telemetry events:", n, "Bad volume rows:", bad_vol)
print("Alerts:", a, "Bad RiskScore==0 but Suspicious:", bad_alert)