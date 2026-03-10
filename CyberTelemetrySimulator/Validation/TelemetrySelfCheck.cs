namespace CyberTelemetrySimulator.Validation;

using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Devices;
using CyberTelemetrySimulator.Models;

public static class TelemetrySelfCheck
{
    public static void Run()
    {
        var campaigns = new CampaignManager(attackChancePerTick: 0.0);
        var device = new DeviceSimulator("SELF-01", DeviceType.Workstation);

        TelemetryEvent? previous = null;
        for (var i = 0; i < 40; i++)
        {
            var current = device.GenerateTelemetry(campaigns);
            ValidatePhysics(current);
            ValidateDerived(current);
            if (previous != null)
            {
                ValidateSmoothing(previous, current);
            }
            previous = current;
        }
    }

    private static void ValidatePhysics(TelemetryEvent current)
    {
        var m = current.Metrics;
        var expected = m.IncomingBytes + m.OutgoingBytes;
        if (m.TrafficVolumeBytes != expected)
        {
            throw new InvalidOperationException("TrafficVolumeBytes not consistent with IncomingBytes + OutgoingBytes.");
        }
    }

    private static void ValidateDerived(TelemetryEvent current)
    {
        var m = current.Metrics;
        var expectedRate = m.TotalFailedLogins / 60.0;
        if (Math.Abs(m.FailedLoginRate - expectedRate) > 0.01)
        {
            throw new InvalidOperationException("FailedLoginRate does not match TotalFailedLogins / 60.");
        }

        var expectedRatio = m.SuccessfulLogins <= 0
            ? (m.TotalFailedLogins > 0 ? 1.0 : 0.0)
            : (double)m.TotalFailedLogins / m.SuccessfulLogins;
        if (Math.Abs(m.FailedToSuccessRatio - expectedRatio) > 0.01)
        {
            throw new InvalidOperationException("FailedToSuccessRatio not consistent with logins.");
        }

        var expectedOutgoingRatio = m.IncomingBytes <= 0
            ? m.OutgoingBytes
            : m.OutgoingBytes / m.IncomingBytes;
        if (Math.Abs(m.OutgoingIncomingRatio - expectedOutgoingRatio) > 0.01)
        {
            throw new InvalidOperationException("OutgoingIncomingRatio not consistent with byte totals.");
        }
    }

    private static void ValidateSmoothing(TelemetryEvent previous, TelemetryEvent current)
    {
        var cpuDelta = Math.Abs(current.Metrics.AverageCpuUsage - previous.Metrics.AverageCpuUsage);
        var packetDelta = Math.Abs(current.Metrics.AveragePacketRate - previous.Metrics.AveragePacketRate);
        if (cpuDelta > 25)
        {
            throw new InvalidOperationException("CPU usage jumped too abruptly between ticks.");
        }

        if (packetDelta > 800)
        {
            throw new InvalidOperationException("Packet rate jumped too abruptly between ticks.");
        }
    }
}
