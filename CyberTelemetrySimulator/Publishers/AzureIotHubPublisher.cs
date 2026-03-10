using System.Text;
using System.Text.Json;
using CyberTelemetrySimulator.Models;
using Microsoft.Azure.Devices.Client;

namespace CyberTelemetrySimulator.Publishers;

public sealed class AzureIotHubPublisher : ITelemetryPublisher, IAsyncDisposable
{
    private readonly DeviceClient _client;
    private readonly JsonSerializerOptions _options = new();

    public AzureIotHubPublisher(string connectionString)
    {
        _client = DeviceClient.CreateFromConnectionString(connectionString, TransportType.Mqtt);
    }

    public async Task PublishAsync(TelemetryEvent evnt)
    {
        var payload = JsonSerializer.Serialize(evnt, _options);
        using var message = new Message(Encoding.UTF8.GetBytes(payload))
        {
            ContentType = "application/json",
            ContentEncoding = "utf-8"
        };

        await _client.SendEventAsync(message);
    }

    public async ValueTask DisposeAsync()
    {
        await _client.CloseAsync();
        _client.Dispose();
    }
}
