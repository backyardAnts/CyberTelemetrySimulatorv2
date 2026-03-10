namespace CyberTelemetrySimulator.Detection;

using CyberTelemetrySimulator.Models;

public static class DetectionEngine
{
    private const int BruteForceWeight = 35;
    private const int PortScanWeight = 30;
    private const int DdosWeight = 35;
    private const int ExfilWeight = 35;

    private const int FailedLoginsHigh = 20;
    private const double FailedLoginRateHigh = 0.5;
    private const double FailedToSuccessHigh = 1.5;

    private const int PortsHigh = 30;
    private const double ConnectionAttemptsHigh = 40;
    private const double ConnectionDurationLowMs = 200;

    private const double PacketRateHigh = 1500;
    private const double NewConnectionsHigh = 200;
    private const double TrafficVolumeHigh = 1_000_000;

    private const double OutgoingBytesHigh = 300_000;
    private const double OutgoingRatioHigh = 2.0;

    public static DetectionResult Evaluate(TelemetryEvent telemetry)
    {
        var m = telemetry.Metrics;
        var reasons = new List<string>();
        var scores = new Dictionary<AttackType, int>();

        var bruteIndicators = 0;
        if (m.TotalFailedLogins >= FailedLoginsHigh)
        {
            bruteIndicators++;
            reasons.Add("failed logins high");
        }
        if (m.FailedLoginRate >= FailedLoginRateHigh)
        {
            bruteIndicators++;
            reasons.Add("failed login rate high");
        }
        if (m.FailedToSuccessRatio >= FailedToSuccessHigh)
        {
            bruteIndicators++;
            reasons.Add("failed/success ratio high");
        }
        if (bruteIndicators > 0)
        {
            scores[AttackType.BruteForce] = bruteIndicators * BruteForceWeight;
        }

        var portIndicators = 0;
        if (m.UniquePortsAccessed >= PortsHigh)
        {
            portIndicators++;
            reasons.Add("many unique ports");
        }
        if (m.ConnectionAttemptsPerSecond >= ConnectionAttemptsHigh)
        {
            portIndicators++;
            reasons.Add("connection attempts high");
        }
        if (m.AverageConnectionDurationMs <= ConnectionDurationLowMs)
        {
            portIndicators++;
            reasons.Add("short connection duration");
        }
        if (portIndicators >= 2)
        {
            scores[AttackType.PortScan] = portIndicators * PortScanWeight;
        }

        var ddosIndicators = 0;
        if (m.AveragePacketRate >= PacketRateHigh)
        {
            ddosIndicators++;
            reasons.Add("packet rate high");
        }
        if (m.NewConnectionsPerSecond >= NewConnectionsHigh)
        {
            ddosIndicators++;
            reasons.Add("new connections high");
        }
        if (m.TrafficVolumeBytes >= TrafficVolumeHigh)
        {
            ddosIndicators++;
            reasons.Add("traffic volume spike");
        }
        if (ddosIndicators >= 2)
        {
            scores[AttackType.DDoS] = ddosIndicators * DdosWeight;
        }

        var exfilIndicators = 0;
        if (m.OutgoingBytes >= OutgoingBytesHigh)
        {
            exfilIndicators++;
            reasons.Add("outgoing bytes high");
        }
        if (m.OutgoingIncomingRatio >= OutgoingRatioHigh)
        {
            exfilIndicators++;
            reasons.Add("outgoing/incoming ratio high");
        }
        if (m.AfterHoursActivity == 1 || m.TimeOfDay < 8 || m.TimeOfDay > 18)
        {
            exfilIndicators++;
            reasons.Add("after-hours activity");
        }
        if (exfilIndicators >= 2)
        {
            scores[AttackType.Exfiltration] = exfilIndicators * ExfilWeight;
        }

        var riskScore = Math.Clamp(scores.Values.Sum(), 0, 100);
        AttackType? suspected = scores.Count == 0
            ? null
            : scores.OrderByDescending(kvp => kvp.Value).First().Key;

        return new DetectionResult
        {
            RiskScore = riskScore,
            SuspectedType = suspected,
            Reasons = reasons.Distinct().ToArray()
        };
    }
}

public class DetectionResult
{
    public int RiskScore { get; init; }
    public AttackType? SuspectedType { get; init; }
    public string[] Reasons { get; init; } = Array.Empty<string>();
}
