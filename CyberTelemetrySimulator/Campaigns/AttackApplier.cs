using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Attacks;

using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Models;
//takes an AttackEpisode + current device metrics and mutates metrics + sets label (BruteForce / DDoS / etc.) for that tick/window.
public static class AttackApplier
{
    public static void Apply(Metrics m, AttackEpisode ep)
    {
        var p = ep.Progress01(DateTime.UtcNow); // 0 → 1
        var intensity = ep.Intensity;
        var ramp = ep.AttackType == AttackType.DDoS
            ? (p < 0.3 ? p / 0.3 : 1.0)
            : p;
        var modeScale = ep.Mode == AttackMode.Loud ? 1.0 : 0.45;
        var scaled = intensity * modeScale * (0.4 + 0.6 * ramp);
        // Loud vs stealth modes adjust scale while keeping correlated metrics aligned.
        // Use p to ramp effects smoothly
        switch (ep.AttackType)
        {
            case AttackType.PortScan:
                // Many ports over time + moderate packet rise
                m.UniquePortsAccessed = Math.Max(0, m.UniquePortsAccessed + (int)(40 * scaled + (ep.Mode == AttackMode.Loud ? 60 : 15)));
                m.ConnectionAttemptsPerSecond = Math.Max(0, m.ConnectionAttemptsPerSecond + (int)(40 * scaled + (ep.Mode == AttackMode.Loud ? 80 : 20)));
                m.AveragePacketRate = Math.Max(0, m.AveragePacketRate + (int)(120 * scaled + (ep.Mode == AttackMode.Loud ? 200 : 60)));
                m.AverageConnectionDurationMs = Math.Clamp(m.AverageConnectionDurationMs - (int)(120 * scaled + (ep.Mode == AttackMode.Loud ? 200 : 80)), 10, 20000);
                m.IncomingBytes = Math.Max(0, m.IncomingBytes + (int)(50000 * scaled));
                m.OutgoingBytes = Math.Max(0, m.OutgoingBytes + (int)(20000 * scaled));
                m.AverageCpuUsage = Math.Clamp(m.AverageCpuUsage + (int)(6 + 12 * scaled), 0, 100);
                break;

            case AttackType.BruteForce:
                // Failed logins spike + some CPU
                m.TotalFailedLogins = Math.Clamp(m.TotalFailedLogins + (int)(8 + 120 * scaled), 0, 10000);
                m.SuccessfulLogins = Math.Max(0, m.SuccessfulLogins - (int)(1 + 4 * scaled));
                var bruteForceIps = ep.SourceIpClusters * ep.SourceIpsPerCluster;
                m.UniqueSourceIps = Math.Clamp(m.UniqueSourceIps + (int)(bruteForceIps * (ep.Mode == AttackMode.Loud ? 0.6 : 1.0)), 1, 5000);
                m.ConnectionAttemptsPerSecond = Math.Max(0, m.ConnectionAttemptsPerSecond + (int)(20 + 80 * scaled));
                m.NewConnectionsPerSecond = Math.Max(0, m.NewConnectionsPerSecond + (int)(10 + 40 * scaled));
                m.AveragePacketRate = Math.Max(0, m.AveragePacketRate + (int)(60 + 140 * scaled));
                m.IncomingBytes = Math.Max(0, m.IncomingBytes + (int)(20000 * scaled));
                m.OutgoingBytes = Math.Max(0, m.OutgoingBytes + (int)(15000 * scaled));
                m.AverageCpuUsage = Math.Clamp(m.AverageCpuUsage + (int)(8 + 20 * scaled), 0, 100);
                break;

            case AttackType.DDoS:
                // Packet rate huge + CPU high
                var ddosIps = ep.SourceIpClusters * ep.SourceIpsPerCluster;
                m.UniqueSourceIps = Math.Clamp(m.UniqueSourceIps + (int)(ddosIps * scaled), 1, 20000);
                m.NewConnectionsPerSecond = Math.Max(0, m.NewConnectionsPerSecond + (int)(200 * scaled + 400));
                m.ConnectionAttemptsPerSecond = Math.Max(0, m.ConnectionAttemptsPerSecond + (int)(300 * scaled + 600));
                m.AveragePacketRate = Math.Max(0, m.AveragePacketRate + (int)(900 * scaled + 1200));
                m.IncomingBytes = Math.Max(0, m.IncomingBytes + (int)(800000 * scaled + 200000));
                m.OutgoingBytes = Math.Max(0, m.OutgoingBytes + (int)(500000 * scaled + 100000));
                m.AverageCpuUsage = Math.Clamp(m.AverageCpuUsage + (int)(25 + 50 * scaled), 0, 100);
                break;

            case AttackType.Exfiltration:
                // Sustained moderate-high traffic (stealthier) + odd timing signal
                var exfilScale = ep.Mode == AttackMode.Loud ? 1.2 : 0.6;
                m.OutgoingBytes = Math.Max(0, m.OutgoingBytes + (int)(250000 * scaled * exfilScale + 60000));
                m.IncomingBytes = Math.Max(0, m.IncomingBytes - (int)(15000 * scaled));
                m.AveragePacketRate = Math.Max(0, m.AveragePacketRate + (int)(180 * scaled + 80));
                m.AverageCpuUsage = Math.Clamp(m.AverageCpuUsage + (int)(4 + 12 * scaled), 0, 100);
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
}
