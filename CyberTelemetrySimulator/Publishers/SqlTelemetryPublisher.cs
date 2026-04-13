using System.Text.Json;
using CyberTelemetrySimulator.Models;
using Microsoft.Data.SqlClient;

namespace CyberTelemetrySimulator.Publishers;

public sealed class SqlTelemetryPublisher : ITelemetryPublisher
{
    private readonly string _connectionString;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false
    };

    public SqlTelemetryPublisher(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task PublishAsync(TelemetryEvent evnt)
    {
        const string sql = @"
INSERT INTO dbo.TelemetryEvents
(
    TimestampUtc,
    DeviceId,
    DeviceType,
    Label,
    AttackId,
    AttackMode,
    IncidentId,
    AveragePacketRate,
    TotalFailedLogins,
    SuccessfulLogins,
    FailedLoginRate,
    UniqueSourceIps,
    FailedToSuccessRatio,
    UniquePortsAccessed,
    ConnectionAttemptsPerSecond,
    AverageConnectionDurationMs,
    NewConnectionsPerSecond,
    TrafficVolumeBytes,
    OutgoingBytes,
    IncomingBytes,
    OutgoingIncomingRatio,
    AverageCpuUsage,
    TimeOfDay,
    AfterHoursActivity,
    RawJson
)
VALUES
(
    @TimestampUtc,
    @DeviceId,
    @DeviceType,
    @Label,
    @AttackId,
    @AttackMode,
    @IncidentId,
    @AveragePacketRate,
    @TotalFailedLogins,
    @SuccessfulLogins,
    @FailedLoginRate,
    @UniqueSourceIps,
    @FailedToSuccessRatio,
    @UniquePortsAccessed,
    @ConnectionAttemptsPerSecond,
    @AverageConnectionDurationMs,
    @NewConnectionsPerSecond,
    @TrafficVolumeBytes,
    @OutgoingBytes,
    @IncomingBytes,
    @OutgoingIncomingRatio,
    @AverageCpuUsage,
    @TimeOfDay,
    @AfterHoursActivity,
    @RawJson
);";

        await using var conn = new SqlConnection(_connectionString);
        await conn.OpenAsync();

        await using var cmd = new SqlCommand(sql, conn);

        cmd.Parameters.AddWithValue("@TimestampUtc", evnt.Timestamp);
        cmd.Parameters.AddWithValue("@DeviceId", evnt.DeviceId);
        cmd.Parameters.AddWithValue("@DeviceType", evnt.DeviceType.ToString());
        cmd.Parameters.AddWithValue("@Label", evnt.Label.ToString());
        cmd.Parameters.AddWithValue("@AttackId", (object?)evnt.AttackId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@AttackMode", (object?)evnt.AttackMode?.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@IncidentId", (object?)evnt.IncidentId ?? DBNull.Value);

        cmd.Parameters.AddWithValue("@AveragePacketRate", evnt.Metrics.AveragePacketRate);
        cmd.Parameters.AddWithValue("@TotalFailedLogins", evnt.Metrics.TotalFailedLogins);
        cmd.Parameters.AddWithValue("@SuccessfulLogins", evnt.Metrics.SuccessfulLogins);
        cmd.Parameters.AddWithValue("@FailedLoginRate", evnt.Metrics.FailedLoginRate);
        cmd.Parameters.AddWithValue("@UniqueSourceIps", evnt.Metrics.UniqueSourceIps);
        cmd.Parameters.AddWithValue("@FailedToSuccessRatio", evnt.Metrics.FailedToSuccessRatio);
        cmd.Parameters.AddWithValue("@UniquePortsAccessed", evnt.Metrics.UniquePortsAccessed);
        cmd.Parameters.AddWithValue("@ConnectionAttemptsPerSecond", evnt.Metrics.ConnectionAttemptsPerSecond);
        cmd.Parameters.AddWithValue("@AverageConnectionDurationMs", evnt.Metrics.AverageConnectionDurationMs);
        cmd.Parameters.AddWithValue("@NewConnectionsPerSecond", evnt.Metrics.NewConnectionsPerSecond);
        cmd.Parameters.AddWithValue("@TrafficVolumeBytes", evnt.Metrics.TrafficVolumeBytes);
        cmd.Parameters.AddWithValue("@OutgoingBytes", evnt.Metrics.OutgoingBytes);
        cmd.Parameters.AddWithValue("@IncomingBytes", evnt.Metrics.IncomingBytes);
        cmd.Parameters.AddWithValue("@OutgoingIncomingRatio", evnt.Metrics.OutgoingIncomingRatio);
        cmd.Parameters.AddWithValue("@AverageCpuUsage", evnt.Metrics.AverageCpuUsage);
        cmd.Parameters.AddWithValue("@TimeOfDay", evnt.Metrics.TimeOfDay);
        cmd.Parameters.AddWithValue("@AfterHoursActivity", evnt.Metrics.AfterHoursActivity);

        var rawJson = JsonSerializer.Serialize(evnt, _jsonOptions);
        cmd.Parameters.AddWithValue("@RawJson", rawJson);

        await cmd.ExecuteNonQueryAsync();
    }
}