namespace CyberTelemetrySimulator.Publishers;

using System.Text.Json;
using System.Text.Json.Serialization;
using CyberTelemetrySimulator.Models;

public class ConsolePublisher : ITelemetryPublisher
{
    private readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public Task PublishAsync(TelemetryEvent evnt)
    {
        Console.WriteLine(JsonSerializer.Serialize(evnt, _options));
        return Task.CompletedTask;
    }
}