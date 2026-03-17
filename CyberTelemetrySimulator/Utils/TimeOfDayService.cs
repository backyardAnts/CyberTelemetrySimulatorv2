using System;
using CyberTelemetrySimulator.Config;

namespace CyberTelemetrySimulator.Utils;

public sealed class TimeOfDayService
{
    private readonly bool _useManualTimeOfDay;
    private readonly int _manualHour;

    public TimeOfDayService(SimulatorSettings? settings)
    {
        _useManualTimeOfDay = settings?.UseManualTimeOfDay ?? false;
        _manualHour = NormalizeHour(settings?.ManualHour ?? 0);
    }

    public int GetHour(DateTime nowUtc)
    {
        return _useManualTimeOfDay ? _manualHour : nowUtc.Hour;
    }

    public double GetHourFraction(DateTime nowUtc)
    {
        return _useManualTimeOfDay ? _manualHour : nowUtc.Hour + nowUtc.Minute / 60.0;
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
}
