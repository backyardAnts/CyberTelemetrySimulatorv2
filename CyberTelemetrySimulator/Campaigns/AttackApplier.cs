using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Attacks;

using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Models;
using CyberTelemetrySimulator.Utils;
//takes an AttackEpisode + current device metrics and mutates metrics + sets label (BruteForce / DDoS / etc.) for that tick/window.
public static class AttackApplier
{
    private static readonly Random _random = new();

    public static void Apply(Metrics m, AttackEpisode ep)
    {
        var p = ep.Progress01(DateTime.UtcNow); // 0 → 1
        var intensity = ep.Intensity;
        var ramp = ep.AttackType == AttackType.DDoS
            ? (p < 0.3 ? p / 0.3 : 1.0)
            : p;
        var modeScale = ep.Mode == AttackMode.Loud ? 1.0 : 0.45;
        var scaled = intensity * modeScale * (0.4 + 0.6 * ramp);
        var loudBoost = ep.Mode == AttackMode.Loud ? 1.0 : 0.7;
        // Loud vs stealth modes adjust scale while keeping correlated metrics aligned.
        // Use p to ramp effects smoothly
        switch (ep.AttackType)
        {
            case AttackType.PortScan:
                // Many ports over time + moderate packet rise
                var scanPortsScale = BlendScale(1.0 + 0.6 * scaled * loudBoost, 0.12);
                m.UniquePortsAccessed = ScaleMetricInt(m.UniquePortsAccessed, scanPortsScale, 0.2, 2)
                    + RandomDistributions.SamplePoisson(_random, 2 + 8 * scaled);
                m.ConnectionAttemptsPerSecond = ScaleMetric(m.ConnectionAttemptsPerSecond, BlendScale(1.0 + 0.7 * scaled * loudBoost, 0.1), 0.15, 1);
                m.AveragePacketRate = ScaleMetric(m.AveragePacketRate, BlendScale(1.0 + 0.5 * scaled * loudBoost, 0.1), 0.12, 2);
                m.AverageConnectionDurationMs = Math.Clamp(
                    ScaleMetric(m.AverageConnectionDurationMs, BlendScale(1.0 - 0.2 * scaled, 0.08), 0.15, 5),
                    10,
                    20000);
                m.IncomingBytes = ScaleMetric(m.IncomingBytes, BlendScale(1.0 + 0.25 * scaled, 0.1), 0.1, 25);
                m.OutgoingBytes = ScaleMetric(m.OutgoingBytes, BlendScale(1.0 + 0.18 * scaled, 0.1), 0.1, 20);
                m.AverageCpuUsage = Math.Clamp(
                    m.AverageCpuUsage + RandomDistributions.SampleNormal(_random, 3 + 6 * scaled, 3),
                    0,
                    100);
                break;

            case AttackType.BruteForce:
                // Failed logins spike + some CPU
                m.TotalFailedLogins = ScaleMetricInt(m.TotalFailedLogins, BlendScale(1.0 + 0.7 * scaled * loudBoost, 0.1), 0.3, 2)
                    + RandomDistributions.SamplePoisson(_random, 2 + 5 * scaled);
                m.SuccessfulLogins = Math.Max(
                    0,
                    (int)Math.Round(m.SuccessfulLogins * BlendScale(1.0 - 0.15 * scaled, 0.08)
                                    + RandomDistributions.SampleNormal(_random, 0, 1.2)));
                var bruteForceIps = ep.SourceIpClusters * ep.SourceIpsPerCluster;
                m.UniqueSourceIps = Math.Max(
                    1,
                    ScaleMetricInt(m.UniqueSourceIps + (int)(bruteForceIps * 0.25), BlendScale(1.0 + 0.5 * scaled, 0.12), 0.25, 1));
                m.ConnectionAttemptsPerSecond = ScaleMetric(m.ConnectionAttemptsPerSecond, BlendScale(1.0 + 0.4 * scaled, 0.1), 0.15, 1);
                m.NewConnectionsPerSecond = ScaleMetric(m.NewConnectionsPerSecond, BlendScale(1.0 + 0.35 * scaled, 0.1), 0.15, 1);
                m.AveragePacketRate = ScaleMetric(m.AveragePacketRate, BlendScale(1.0 + 0.35 * scaled, 0.1), 0.15, 2);
                m.IncomingBytes = ScaleMetric(m.IncomingBytes, BlendScale(1.0 + 0.2 * scaled, 0.1), 0.1, 25);
                m.OutgoingBytes = ScaleMetric(m.OutgoingBytes, BlendScale(1.0 + 0.18 * scaled, 0.1), 0.1, 20);
                m.AverageCpuUsage = Math.Clamp(
                    m.AverageCpuUsage + RandomDistributions.SampleNormal(_random, 4 + 8 * scaled, 4),
                    0,
                    100);
                break;

            case AttackType.DDoS:
                // Packet rate huge + CPU high
                var ddosIps = ep.SourceIpClusters * ep.SourceIpsPerCluster;
                m.UniqueSourceIps = Math.Max(
                    1,
                    ScaleMetricInt(m.UniqueSourceIps + (int)(ddosIps * 0.3), BlendScale(1.0 + 0.9 * scaled, 0.2), 0.35, 3));
                m.NewConnectionsPerSecond = ScaleMetric(m.NewConnectionsPerSecond, BlendScale(1.0 + 1.1 * scaled * loudBoost, 0.15), 0.2, 2);
                m.ConnectionAttemptsPerSecond = ScaleMetric(m.ConnectionAttemptsPerSecond, BlendScale(1.0 + 1.3 * scaled * loudBoost, 0.18), 0.2, 2);
                m.AveragePacketRate = ScaleMetric(m.AveragePacketRate, BlendScale(1.0 + 1.1 * scaled * loudBoost, 0.18), 0.2, 3);
                m.IncomingBytes = ScaleMetric(m.IncomingBytes, BlendScale(1.0 + 0.9 * scaled * loudBoost, 0.18), 0.18, 50);
                m.OutgoingBytes = ScaleMetric(m.OutgoingBytes, BlendScale(1.0 + 0.7 * scaled * loudBoost, 0.18), 0.18, 40);
                m.AverageCpuUsage = Math.Clamp(
                    m.AverageCpuUsage + RandomDistributions.SampleNormal(_random, 10 + 18 * scaled, 6),
                    0,
                    100);
                break;

            case AttackType.Exfiltration:
                // Sustained moderate-high traffic (stealthier) + odd timing signal
                var exfilScale = ep.Mode == AttackMode.Loud ? 1.1 : 0.7;
                m.OutgoingBytes = ScaleMetric(m.OutgoingBytes, BlendScale(1.0 + 0.6 * scaled * exfilScale, 0.12), 0.15, 30);
                m.IncomingBytes = ScaleMetric(m.IncomingBytes, BlendScale(1.0 - 0.2 * scaled, 0.12), 0.12, 20);
                m.AveragePacketRate = ScaleMetric(m.AveragePacketRate, BlendScale(1.0 + 0.25 * scaled, 0.1), 0.12, 2);
                m.AverageCpuUsage = Math.Clamp(
                    m.AverageCpuUsage + RandomDistributions.SampleNormal(_random, 2 + 6 * scaled, 3),
                    0,
                    100);
                if (ep.ForceAfterHours)
                {
                    m.AfterHoursActivity = 1;
                }
                break;

            case AttackType.Normal:
            default:
                break;
        }
    }

    private static double BlendScale(double scale, double jitterStdDev)
    {
        return Math.Max(0.1, scale + RandomDistributions.SampleNormal(_random, 0, jitterStdDev));
    }

    private static double ScaleMetric(double value, double scale, double noisePct, double minNoise)
    {
        var scaled = value * scale;
        var noise = RandomDistributions.SampleNormal(_random, 0, Math.Max(minNoise, Math.Abs(scaled) * noisePct));
        return Math.Max(0, scaled + noise);
    }

    private static int ScaleMetricInt(int value, double scale, double noisePct, int minNoise)
    {
        var scaled = value * scale;
        var noise = RandomDistributions.SampleNormal(_random, 0, Math.Max(minNoise, Math.Abs(scaled) * noisePct));
        return Math.Max(0, (int)Math.Round(scaled + noise));
    }
}
