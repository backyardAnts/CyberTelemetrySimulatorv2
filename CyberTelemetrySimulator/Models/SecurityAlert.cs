namespace CyberTelemetrySimulator.Models;

using System.Text.Json.Serialization;

public class SecurityAlert
{
    public string AlertId { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
    public string DeviceId { get; init; } = string.Empty;
    public DeviceType DeviceType { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IncidentId { get; init; }
    public int RiskScore { get; init; }
    public string Severity { get; init; } = string.Empty;
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AlertType { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AttackType? SuspectedType { get; init; }
    public string[] Reasons { get; init; } = Array.Empty<string>();
}
