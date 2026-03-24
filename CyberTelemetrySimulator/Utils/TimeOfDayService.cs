using System;
using CyberTelemetrySimulator.Config;

namespace CyberTelemetrySimulator.Utils;

public sealed class TimeOfDayService
{
    private readonly bool _useManualTimeOfDay;
    private readonly bool _useRandomTimeOfDay;
    private readonly int _manualHour;
    private readonly double _hoursPerTick;
    private double _simulatedHour;
    private readonly Random _random;

    public TimeOfDayService(SimulatorSettings? settings, Random? random = null)
    {
        _useManualTimeOfDay = settings?.UseManualTimeOfDay ?? false;
        _useRandomTimeOfDay = settings?.UseRandomTimeOfDay ?? false;
        _manualHour = NormalizeHour(settings?.ManualHour ?? 0);
        _hoursPerTick = Math.Max(0, settings?.HoursPerTick ?? 1.0);
        _random = random ?? new Random();
        _simulatedHour = _useRandomTimeOfDay
            ? SampleRandomHour()
            : (_useManualTimeOfDay ? _manualHour : NormalizeHourFraction(settings?.ManualHour ?? DateTime.UtcNow.Hour));
    }

    public int GetHour(DateTime nowUtc)
    {
        if (_useManualTimeOfDay)
        {
            return _manualHour;
        }

        if (_useRandomTimeOfDay)
        {
            return (int)Math.Floor(_simulatedHour);
        }

        return (int)Math.Floor(_simulatedHour);
    }

    public double GetHourFraction(DateTime nowUtc)
    {
        if (_useManualTimeOfDay)
        {
            return _manualHour;
        }

        if (_useRandomTimeOfDay)
        {
            return _simulatedHour;
        }

        return _simulatedHour;
    }

    public void AdvanceTime()
    {
        if (_useManualTimeOfDay)
        {
            return;
        }

        if (_useRandomTimeOfDay)
        {
            _simulatedHour = SampleRandomHour();
            return;
        }

        _simulatedHour = NormalizeHourFraction(_simulatedHour + _hoursPerTick);
    }

    public bool IsAfterHours(DateTime nowUtc, int businessHoursStart, int businessHoursEnd)
    {
        return !IsWithinBusinessHours(GetHour(nowUtc), businessHoursStart, businessHoursEnd);
    }

    public static bool IsWithinBusinessHours(int hour, int businessHoursStart, int businessHoursEnd)
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

    public static int NormalizeHour(int hour)
    {
        if (hour < 0) return 0;
        if (hour > 23) return 23;
        return hour;
    }

    public static double NormalizeHourFraction(double hour)
    {
        var normalized = hour % 24.0;
        if (normalized < 0)
        {
            normalized += 24.0;
        }

        return normalized;
    }

    private double SampleRandomHour()
    {
        var roll = _random.NextDouble();
        double sampled = roll switch
        {
            < 0.7 => RandomDistributions.SampleNormal(_random, 14, 3.2),
            < 0.9 => RandomDistributions.SampleNormal(_random, 2, 2.2),
            _ => _random.Next(0, 24)
        };

        var hour = NormalizeHour((int)Math.Round(sampled));
        return NormalizeHourFraction(hour + _random.NextDouble());
    }
}
