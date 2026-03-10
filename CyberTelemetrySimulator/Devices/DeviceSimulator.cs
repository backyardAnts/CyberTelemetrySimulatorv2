using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Attacks;
namespace CyberTelemetrySimulator.Devices;

using CyberTelemetrySimulator.Config;
using CyberTelemetrySimulator.Models;
using CyberTelemetrySimulator.Utils;

public class DeviceSimulator
{
    private readonly Random _random = new();
    private readonly DeviceProfile _profile;
    private readonly DeviceBaseline _baseline;
    private double _packetRateState;
    private double _cpuUsageState;
    private readonly int _businessHoursStart;
    private readonly int _businessHoursEnd;
    private readonly double _dayBaselineMultiplier;
    private readonly double _nightBaselineMultiplier;

    public string DeviceId { get; }
    public DeviceType DeviceType { get; }

    public DeviceSimulator(string deviceId, DeviceType deviceType, SimulatorSettings? settings = null)
    {
        DeviceId = deviceId;
        DeviceType = deviceType;
        _businessHoursStart = NormalizeHour(settings?.BusinessHoursStart ?? 9);
        _businessHoursEnd = NormalizeHour(settings?.BusinessHoursEnd ?? 17);
        _dayBaselineMultiplier = Math.Max(0.1, settings?.DayBaselineMultiplier ?? 1.3);
        _nightBaselineMultiplier = Math.Max(0.1, settings?.NightBaselineMultiplier ?? 0.7);
        _profile = DeviceProfile.For(deviceType);
        _baseline = InitializeBaseline();
        _packetRateState = _baseline.PacketRate;
        _cpuUsageState = _baseline.CpuUsage;
    }

    public TelemetryEvent GenerateNormalTelemetry()
    {
        var now = DateTime.UtcNow;

        var metrics = GenerateBaselineMetrics(now);
        UpdateDerivedMetrics(metrics, now, forceAfterHours: false);

        return new TelemetryEvent
        {
            Timestamp = now,
            DeviceId = DeviceId,
            DeviceType = DeviceType,
            Metrics = metrics,
            Label = AttackType.Normal,
            AttackId = null
        };
    }

    private int NextInRange((int Min, int Max) range)
        => _random.Next(range.Min, range.Max + 1);

    private DeviceBaseline InitializeBaseline()
    {
        var incoming = NextInRange(_profile.IncomingBytesRange);
        var outgoing = NextInRange(_profile.OutgoingBytesRange);
        return new DeviceBaseline
        {
            PacketRate = NextInRange(_profile.PacketRateRange),
            CpuUsage = NextInRange(_profile.CpuUsageRange),
            FailedLoginsPerMinute = NextInRange(_profile.FailedLoginsRange),
            SuccessfulLoginsPerMinute = NextInRange(_profile.SuccessfulLoginsRange),
            UniquePortsPerTick = NextInRange(_profile.UniquePortsRange),
            ConnectionAttemptsPerSecond = NextInRange(_profile.ConnectionAttemptsPerSecondRange),
            NewConnectionsPerSecond = NextInRange(_profile.NewConnectionsPerSecondRange),
            AverageConnectionDurationMs = NextInRange(_profile.AverageConnectionDurationMsRange),
            IncomingBytesPerTick = incoming,
            OutgoingBytesPerTick = outgoing,
            UniqueSourceIps = NextInRange(_profile.UniqueSourceIpsRange),
            OutgoingIncomingRatio = incoming <= 0 ? 0.8 : (double)outgoing / incoming
        };
    }

    private void ApplyBaselineDrift()
    {
        _baseline.PacketRate = DriftWithin(_baseline.PacketRate, _profile.PacketRateRange, 0.02);
        _baseline.CpuUsage = DriftWithin(_baseline.CpuUsage, _profile.CpuUsageRange, 0.03);
        _baseline.FailedLoginsPerMinute = DriftWithin(_baseline.FailedLoginsPerMinute, _profile.FailedLoginsRange, 0.05);
        _baseline.SuccessfulLoginsPerMinute = DriftWithin(_baseline.SuccessfulLoginsPerMinute, _profile.SuccessfulLoginsRange, 0.04);
        _baseline.UniquePortsPerTick = DriftWithin(_baseline.UniquePortsPerTick, _profile.UniquePortsRange, 0.04);
        _baseline.ConnectionAttemptsPerSecond = DriftWithin(_baseline.ConnectionAttemptsPerSecond, _profile.ConnectionAttemptsPerSecondRange, 0.04);
        _baseline.NewConnectionsPerSecond = DriftWithin(_baseline.NewConnectionsPerSecond, _profile.NewConnectionsPerSecondRange, 0.04);
        _baseline.AverageConnectionDurationMs = DriftWithin(_baseline.AverageConnectionDurationMs, _profile.AverageConnectionDurationMsRange, 0.03);
        _baseline.IncomingBytesPerTick = DriftWithin(_baseline.IncomingBytesPerTick, _profile.IncomingBytesRange, 0.03);
        _baseline.OutgoingBytesPerTick = DriftWithin(_baseline.OutgoingBytesPerTick, _profile.OutgoingBytesRange, 0.03);
        _baseline.UniqueSourceIps = DriftWithin(_baseline.UniqueSourceIps, _profile.UniqueSourceIpsRange, 0.05);
    }

    private double DriftWithin(double value, (int Min, int Max) range, double driftStdDev)
    {
        var drift = RandomDistributions.SampleNormal(_random, 0, driftStdDev);
        var next = value * (1 + drift);
        return Math.Clamp(next, range.Min, range.Max);
    }

    private Metrics GenerateBaselineMetrics(DateTime now)
    {
        ApplyBaselineDrift();
        var activity = GetActivityMultiplier(
            now,
            DeviceType,
            _businessHoursStart,
            _businessHoursEnd,
            _dayBaselineMultiplier,
            _nightBaselineMultiplier);

        // AR(1) smoothing keeps rate/CPU evolution realistic between ticks.

        var packetTarget = _baseline.PacketRate * activity;
        _packetRateState = RandomDistributions.SmoothAr1(_random, _packetRateState, packetTarget, 0.85, packetTarget * 0.05);

        var cpuTarget = _baseline.CpuUsage * activity;
        _cpuUsageState = RandomDistributions.SmoothAr1(_random, _cpuUsageState, cpuTarget, 0.8, 1.5);

        var failedLogins = RandomDistributions.SamplePoisson(_random, _baseline.FailedLoginsPerMinute * activity);
        var successLogins = RandomDistributions.SamplePoisson(_random, _baseline.SuccessfulLoginsPerMinute * activity);
        var uniquePorts = RandomDistributions.SamplePoisson(_random, _baseline.UniquePortsPerTick * activity);
        var connAttempts = RandomDistributions.SamplePoisson(_random, _baseline.ConnectionAttemptsPerSecond * activity);
        var newConnections = RandomDistributions.SamplePoisson(_random, _baseline.NewConnectionsPerSecond * activity);

        var sourceIps = (int)Math.Round(RandomDistributions.SampleLogNormal(
            _random,
            Math.Max(1, _baseline.UniqueSourceIps * activity),
            0.5));

        var incomingMean = Math.Max(100, _baseline.IncomingBytesPerTick * activity);
        var incoming = RandomDistributions.SampleLogNormal(_random, incomingMean, 0.55);
        var ratioNoise = RandomDistributions.SampleLogNormal(_random, 1.0, 0.1);
        var outgoing = incoming * _baseline.OutgoingIncomingRatio * ratioNoise;

        var connectionDuration = RandomDistributions.SampleLogNormal(
            _random,
            _baseline.AverageConnectionDurationMs,
            0.35);

        return new Metrics
        {
            AveragePacketRate = Math.Max(0, _packetRateState),
            TotalFailedLogins = Math.Max(0, failedLogins),
            SuccessfulLogins = Math.Max(0, successLogins),
            UniqueSourceIps = Math.Max(1, sourceIps),
            UniquePortsAccessed = Math.Max(0, uniquePorts),
            ConnectionAttemptsPerSecond = Math.Max(0, connAttempts),
            AverageConnectionDurationMs = Math.Clamp(connectionDuration, 10, 20000),
            NewConnectionsPerSecond = Math.Max(0, newConnections),
            OutgoingBytes = Math.Max(0, outgoing),
            IncomingBytes = Math.Max(0, incoming),
            AverageCpuUsage = Math.Clamp(_cpuUsageState, 0, 100),
            TimeOfDay = now.Hour
        };
    }

    private static double GetActivityMultiplier(
        DateTime now,
        DeviceType deviceType,
        int businessHoursStart,
        int businessHoursEnd,
        double dayBaselineMultiplier,
        double nightBaselineMultiplier)
    {
        var hour = now.Hour + now.Minute / 60.0;
        var weekday = now.DayOfWeek is not DayOfWeek.Saturday and not DayOfWeek.Sunday;

        double baseMultiplier = deviceType switch
        {
            DeviceType.Workstation => DayNightCurve(hour, 0.35, 1.2),
            DeviceType.WebServer => DayNightCurve(hour, 0.7, 1.05),
            DeviceType.DatabaseServer => DayNightCurve(hour, 0.75, 1.05),
            DeviceType.IoTDevice => DayNightCurve(hour, 0.9, 1.0),
            _ => 1.0
        };

        if (!weekday)
        {
            baseMultiplier *= deviceType switch
            {
                DeviceType.Workstation => 0.55,
                DeviceType.WebServer => 0.85,
                DeviceType.DatabaseServer => 0.85,
                DeviceType.IoTDevice => 0.95,
                _ => 1.0
            };
        }

        var timeOfDayMultiplier = GetTimeOfDayBaselineMultiplier(
            now,
            businessHoursStart,
            businessHoursEnd,
            dayBaselineMultiplier,
            nightBaselineMultiplier);
        return baseMultiplier * timeOfDayMultiplier;
    }

    private static double DayNightCurve(double hour, double nightMin, double dayMax)
    {
        var radians = ((hour - 8) / 24.0) * 2.0 * Math.PI;
        var normalized = (Math.Sin(radians) + 1) / 2.0;
        return nightMin + (dayMax - nightMin) * normalized;
    }

    private static double GetTimeOfDayBaselineMultiplier(
        DateTime now,
        int businessHoursStart,
        int businessHoursEnd,
        double dayBaselineMultiplier,
        double nightBaselineMultiplier)
    {
        var hour = now.Hour;
        if (IsNightHour(hour))
        {
            return nightBaselineMultiplier;
        }

        if (IsWithinBusinessHours(hour, businessHoursStart, businessHoursEnd))
        {
            return dayBaselineMultiplier;
        }

        return 1.0;
    }

    private static bool IsAfterHours(DateTime now, int businessHoursStart, int businessHoursEnd)
    {
        return !IsWithinBusinessHours(now.Hour, businessHoursStart, businessHoursEnd);
    }

    private static bool IsWithinBusinessHours(int hour, int businessHoursStart, int businessHoursEnd)
    {
        if (businessHoursStart == businessHoursEnd)
        {
            return true;
        }

        if (businessHoursStart < businessHoursEnd)
        {
            return hour >= businessHoursStart && hour < businessHoursEnd;
        }

        return hour >= businessHoursStart || hour < businessHoursEnd;
    }

    private static bool IsNightHour(int hour)
    {
        return hour >= 0 && hour < 6;
    }

    private static int NormalizeHour(int hour)
    {
        if (hour < 0) return 0;
        if (hour > 23) return 23;
        return hour;
    }

    private void UpdateDerivedMetrics(Metrics m, DateTime now, bool forceAfterHours)
    {
        // Derived values enforce internal consistency across raw metrics.
        var incomingJitter = RandomDistributions.SampleNormal(_random, 0, m.IncomingBytes * 0.02);
        var outgoingJitter = RandomDistributions.SampleNormal(_random, 0, m.OutgoingBytes * 0.02);
        m.IncomingBytes = Math.Max(0, m.IncomingBytes + incomingJitter);
        m.OutgoingBytes = Math.Max(0, m.OutgoingBytes + outgoingJitter);
        m.TrafficVolumeBytes = m.IncomingBytes + m.OutgoingBytes;

        // FailedLoginRate is per-second from a 60-second window.
        m.FailedLoginRate = m.TotalFailedLogins / 60.0;
        m.FailedToSuccessRatio = m.SuccessfulLogins <= 0
            ? (m.TotalFailedLogins > 0 ? 1.0 : 0.0)
            : (double)m.TotalFailedLogins / m.SuccessfulLogins;

        m.OutgoingIncomingRatio = m.IncomingBytes <= 0
            ? m.OutgoingBytes
            : m.OutgoingBytes / m.IncomingBytes;

        if (forceAfterHours)
        {
            m.AfterHoursActivity = 1;
        }
        else
        {
            m.AfterHoursActivity = IsAfterHours(now, _businessHoursStart, _businessHoursEnd) ? 1 : 0;
        }
    }
    public TelemetryEvent GenerateTelemetry(CampaignManager campaigns)
    {
        var now = DateTime.UtcNow;

        // 1) Generate normal baseline
        var metrics = GenerateBaselineMetrics(now);
        UpdateDerivedMetrics(metrics, now, forceAfterHours: false);

        // 2) Check if there is an active attack episode, or start one
        var ep = campaigns.GetActiveEpisode(DeviceId, now) ?? campaigns.TryStartEpisode(DeviceId, now);

        // 3) Apply attack effects if active
        var label = AttackType.Normal;
        string? attackId = null;

        if (ep != null && ep.IsActive(now))
        {
            AttackApplier.Apply(metrics, ep);
            label = ep.AttackType;
            attackId = ep.AttackId;
        }

        UpdateDerivedMetrics(metrics, now, ep?.ForceAfterHours == true);

        // 4) Build event
        return new TelemetryEvent
        {
            Timestamp = now,
            DeviceId = DeviceId,
            DeviceType = DeviceType,
            Metrics = metrics,
            Label = label,
            AttackId = attackId,
            AttackMode = ep?.Mode,
            IncidentId = ep?.IncidentId
        };
    }

    private sealed class DeviceBaseline
    {
        public double PacketRate { get; set; }
        public double CpuUsage { get; set; }
        public double FailedLoginsPerMinute { get; set; }
        public double SuccessfulLoginsPerMinute { get; set; }
        public double UniquePortsPerTick { get; set; }
        public double ConnectionAttemptsPerSecond { get; set; }
        public double NewConnectionsPerSecond { get; set; }
        public double AverageConnectionDurationMs { get; set; }
        public double IncomingBytesPerTick { get; set; }
        public double OutgoingBytesPerTick { get; set; }
        public double UniqueSourceIps { get; set; }
        public double OutgoingIncomingRatio { get; set; }
    }
}
