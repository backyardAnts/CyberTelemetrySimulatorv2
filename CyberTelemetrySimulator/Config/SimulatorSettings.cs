using System.Collections.Generic;

namespace CyberTelemetrySimulator.Config;

public class SimulatorSettings
{
    public int TickMs { get; set; } = 2000;
    public double AttackChancePerTick { get; set; } = 0.10;
    public int MinDurationSec { get; set; } = 20;
    public int MaxDurationSec { get; set; } = 60;
    public string OutputPath { get; set; } = "data/raw-telemetry.jsonl";
    public bool BalancedDatasetMode { get; set; } = false;
    public bool TrainingDatasetMode { get; set; } = false;
    public int TrainingEpisodeDurationSec { get; set; } = 60;
    public int BusinessHoursStart { get; set; } = 8;
    public int BusinessHoursEnd { get; set; } = 17;
    public double DayBaselineMultiplier { get; set; } = 1.3;
    public double NightBaselineMultiplier { get; set; } = 0.7;
    public double AfterHoursAttackMultiplier { get; set; } = 2.0;
    public string? IotHubDeviceConnectionString { get; set; }
    public Dictionary<string, double> TargetClassRatios { get; set; } = new()
    {
        ["Normal"] = 0.65,
        ["BruteForce"] = 0.12,
        ["PortScan"] = 0.12,
        ["DDoS"] = 0.06,
        ["Exfiltration"] = 0.05
    };
    public int? TotalEventsTarget { get; set; }
}
