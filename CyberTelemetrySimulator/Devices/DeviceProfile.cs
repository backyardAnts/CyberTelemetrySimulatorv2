using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Devices;

using CyberTelemetrySimulator.Models;

public class DeviceProfile
{
    public DeviceType DeviceType { get; init; }

    // Normal ranges (used to seed and clamp per-device baselines)
    public (int Min, int Max) PacketRateRange { get; init; } //tupples used to store the range of each metric
    public (int Min, int Max) FailedLoginsRange { get; init; }
    public (int Min, int Max) SuccessfulLoginsRange { get; init; }
    public (int Min, int Max) UniqueSourceIpsRange { get; init; }
    public (int Min, int Max) UniquePortsRange { get; init; }
    public (int Min, int Max) ConnectionAttemptsPerSecondRange { get; init; }
    public (int Min, int Max) AverageConnectionDurationMsRange { get; init; }
    public (int Min, int Max) NewConnectionsPerSecondRange { get; init; }
    public (int Min, int Max) TrafficVolumeBytesRange { get; init; }
    public (int Min, int Max) OutgoingBytesRange { get; init; }
    public (int Min, int Max) IncomingBytesRange { get; init; }
    public (int Min, int Max) CpuUsageRange { get; init; }

    public static DeviceProfile For(DeviceType type) => type switch // there is a switch so it can choose what type of device profile to create based on the DeviceType passed in. Each case creates a new DeviceProfile with specific ranges for the metrics.
    {
        DeviceType.Workstation => new DeviceProfile
        {
            DeviceType = type,
            PacketRateRange = (50, 180),
            FailedLoginsRange = (0, 3),
            SuccessfulLoginsRange = (2, 12),
            UniqueSourceIpsRange = (1, 3),
            UniquePortsRange = (1, 6),
            ConnectionAttemptsPerSecondRange = (1, 5),
            AverageConnectionDurationMsRange = (200, 1500),
            NewConnectionsPerSecondRange = (1, 4),
            TrafficVolumeBytesRange = (50000, 200000),
            OutgoingBytesRange = (20000, 80000),
            IncomingBytesRange = (30000, 120000),
            CpuUsageRange = (5, 35)
        },

        DeviceType.WebServer => new DeviceProfile
        {
            DeviceType = type,
            PacketRateRange = (300, 900),
            FailedLoginsRange = (0, 2),
            SuccessfulLoginsRange = (10, 80),
            UniqueSourceIpsRange = (5, 50),
            UniquePortsRange = (2, 10),
            ConnectionAttemptsPerSecondRange = (30, 150),
            AverageConnectionDurationMsRange = (100, 800),
            NewConnectionsPerSecondRange = (20, 120),
            TrafficVolumeBytesRange = (500000, 2000000),
            OutgoingBytesRange = (200000, 900000),
            IncomingBytesRange = (300000, 1200000),
            CpuUsageRange = (15, 60)
        },

        DeviceType.DatabaseServer => new DeviceProfile
        {
            DeviceType = type,
            PacketRateRange = (120, 500),
            FailedLoginsRange = (0, 2),
            SuccessfulLoginsRange = (5, 30),
            UniqueSourceIpsRange = (2, 12),
            UniquePortsRange = (1, 4),
            ConnectionAttemptsPerSecondRange = (10, 60),
            AverageConnectionDurationMsRange = (300, 1500),
            NewConnectionsPerSecondRange = (8, 40),
            TrafficVolumeBytesRange = (200000, 800000),
            OutgoingBytesRange = (100000, 400000),
            IncomingBytesRange = (120000, 500000),
            CpuUsageRange = (25, 75)
        },

        DeviceType.IoTDevice => new DeviceProfile
        {
            DeviceType = type,
            PacketRateRange = (10, 60),
            FailedLoginsRange = (0, 1),
            SuccessfulLoginsRange = (0, 2),
            UniqueSourceIpsRange = (1, 3),
            UniquePortsRange = (1, 3),
            ConnectionAttemptsPerSecondRange = (1, 8),
            AverageConnectionDurationMsRange = (400, 2500),
            NewConnectionsPerSecondRange = (1, 5),
            TrafficVolumeBytesRange = (10000, 60000),
            OutgoingBytesRange = (4000, 20000),
            IncomingBytesRange = (5000, 25000),
            CpuUsageRange = (1, 20)
        },

        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown DeviceType")
    };
}
