namespace CyberTelemetrySimulator.Publishers;

using CyberTelemetrySimulator.Models;

public interface ITelemetryPublisher //interface that defines the contract for telemetry publishers
{
    Task PublishAsync(TelemetryEvent evnt);
}