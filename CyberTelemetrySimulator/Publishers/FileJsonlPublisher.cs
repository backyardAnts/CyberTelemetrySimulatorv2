namespace CyberTelemetrySimulator.Publishers;

using System.Text.Json;
using System.Text.Json.Serialization;
using CyberTelemetrySimulator.Models;

public class FileJsonlPublisher : ITelemetryPublisher //implement the publisher contract (it will include te async function)
{
    private readonly string _filePath; //define the file path where data is going to be stored
    private readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = false, //to compact the json file into 1 line
        Converters = { new JsonStringEnumConverter() } //to convert the enum indices to there actual name
    };

    public FileJsonlPublisher(string filePath) //contructor
    {
        _filePath = filePath;

        var dir = Path.GetDirectoryName(_filePath); //extract the folder path from the full file path
        if (!string.IsNullOrWhiteSpace(dir))//if folder to store is not created, create it
            Directory.CreateDirectory(dir);
    }

    public async Task PublishAsync(TelemetryEvent evnt) //using async to save data without stopping the program
    {
        var line = JsonSerializer.Serialize(evnt, _options);
        await File.AppendAllTextAsync(_filePath, line + Environment.NewLine);
    }
}