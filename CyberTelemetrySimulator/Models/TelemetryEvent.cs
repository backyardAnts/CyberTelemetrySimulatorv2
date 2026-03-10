using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Models;

using System.Text.Json.Serialization;
public class TelemetryEvent
{
    public DateTime Timestamp { get; set; }
    public string DeviceId { get; set; } = string.Empty;
    public DeviceType DeviceType { get; set; }
    public Metrics Metrics { get; set; } = new(); // to save the "monitored" metrics
    public AttackType Label { get; set; } = AttackType.Normal; //label set to default since it is the basic one
    public string? AttackId { get; set; } //? means the value can be optional (nullable) since normal telemetry won't have an attack ID
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AttackMode? AttackMode { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IncidentId { get; set; }
}
