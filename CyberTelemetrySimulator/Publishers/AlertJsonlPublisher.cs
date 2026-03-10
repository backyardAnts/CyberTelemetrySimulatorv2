namespace CyberTelemetrySimulator.Publishers;

using System.Text.Json;
using System.Text.Json.Serialization;
using CyberTelemetrySimulator.Models;

public class AlertJsonlPublisher
{
    private readonly string _filePath;
    private readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public AlertJsonlPublisher(string filePath)
    {
        _filePath = filePath;
        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
    }

    public async Task PublishAsync(SecurityAlert alert)
    {
        var line = JsonSerializer.Serialize(alert, _options);
        await File.AppendAllTextAsync(_filePath, line + Environment.NewLine);
    }
}
