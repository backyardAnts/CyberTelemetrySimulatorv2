using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Models;
public class Metrics
{
    public double AveragePacketRate { get; set; }
    public int TotalFailedLogins { get; set; }
    public int SuccessfulLogins { get; set; }
    public double FailedLoginRate { get; set; }
    public int UniqueSourceIps { get; set; }
    public double FailedToSuccessRatio { get; set; }
    public int UniquePortsAccessed { get; set; }
    public double ConnectionAttemptsPerSecond { get; set; }
    public double AverageConnectionDurationMs { get; set; }
    public double NewConnectionsPerSecond { get; set; }
    public double TrafficVolumeBytes { get; set; }
    public double OutgoingBytes { get; set; }
    public double IncomingBytes { get; set; }
    public double OutgoingIncomingRatio { get; set; }
    public double AverageCpuUsage { get; set; }
    public int TimeOfDay { get; set; }
    public int AfterHoursActivity { get; set; }
}
