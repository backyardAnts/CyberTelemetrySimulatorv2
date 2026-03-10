using System.Text.Json;
using CyberTelemetrySimulator.Config;
using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Devices;
using CyberTelemetrySimulator.Detection;
using CyberTelemetrySimulator.Models;
using CyberTelemetrySimulator.Publishers;
using CyberTelemetrySimulator.Validation;

var settingsPath = Path.Combine(AppContext.BaseDirectory, "Config", "simulatorSettings.json"); //used to load conf settings from json file
var settingsJson = File.ReadAllText(settingsPath); //read the JSON file content into a string
var settings = JsonSerializer.Deserialize<SimulatorSettings>(
    settingsJson,
    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
) ?? new SimulatorSettings(); //convert the JSON string into a SimulatorSettings object, if deserialization fails, create a new SimulatorSettings with default values


var socMode = args.Contains("--soc", StringComparer.OrdinalIgnoreCase);
var demoMode = args.Contains("--demo", StringComparer.OrdinalIgnoreCase);
var trainingMode = args.Contains("--training", StringComparer.OrdinalIgnoreCase);
var iotHubEnabled = args.Contains("--iot-hub", StringComparer.OrdinalIgnoreCase);

var campaigns = new CampaignManager( //attack scheduling manager, it will decide when to start an attack and what type based on the settings
    attackChancePerTick: settings.AttackChancePerTick, //gets the info from the settings file 
    minDurationSec: settings.MinDurationSec,
    maxDurationSec: settings.MaxDurationSec,
    incidentChainEnabled: socMode || demoMode,
    demoMode: demoMode,
    trainingDatasetMode: trainingMode || settings.TrainingDatasetMode,
    trainingEpisodeDurationSec: settings.TrainingEpisodeDurationSec,
    businessHoursStart: settings.BusinessHoursStart,
    businessHoursEnd: settings.BusinessHoursEnd,
    afterHoursAttackMultiplier: settings.AfterHoursAttackMultiplier
);

var devices = new List<DeviceSimulator>(); //list of simulated devices, each with a unique ID and type. The DeviceSimulator class will use the DeviceProfile to generate telemetry data based on the device type and any active attack episodes.

for (int i = 1; i <= 220; i++)
{
    devices.Add(new DeviceSimulator($"WS-{i:D3}", DeviceType.Workstation, settings));
}

for (int i = 1; i <= 90; i++)
{
    devices.Add(new DeviceSimulator($"WEB-{i:D3}", DeviceType.WebServer, settings));
}

for (int i = 1; i <= 60; i++)
{
    devices.Add(new DeviceSimulator($"DB-{i:D3}", DeviceType.DatabaseServer, settings));
}

for (int i = 1; i <= 30; i++)
{
    devices.Add(new DeviceSimulator($"IOT-{i:D3}", DeviceType.IoTDevice, settings));
}

ITelemetryPublisher consolePub = new ConsolePublisher(); //publisher that outputs telemetry events to the console
ITelemetryPublisher filePub = new FileJsonlPublisher(settings.OutputPath); //publisher that appends telemetry events as JSON lines to a specified file. The OutputPath is obtained from the settings, allowing for flexible configuration of where the telemetry data should be stored.
var alertPublisher = socMode ? new AlertJsonlPublisher("data/alerts.jsonl") : null;
var deviceStates = socMode ? new Dictionary<string, DeviceSecurityState>() : null;

AzureIotHubPublisher? iotHubPublisher = null;
if (iotHubEnabled)
{
    var iotHubConnectionString = Environment.GetEnvironmentVariable("IOT_HUB_DEVICE_CONNECTION_STRING");
    if (string.IsNullOrWhiteSpace(iotHubConnectionString))
    {
        iotHubConnectionString = settings.IotHubDeviceConnectionString;
    }

    if (string.IsNullOrWhiteSpace(iotHubConnectionString))
    {
        Console.WriteLine("Missing IoT Hub device connection string. Set IOT_HUB_DEVICE_CONNECTION_STRING or Config/simulatorSettings.json (iotHubDeviceConnectionString).");
        return;
    }

    iotHubPublisher = new AzureIotHubPublisher(iotHubConnectionString);
}

while (true) //infinite loop that simulates the telemetry generation process. In each iteration, it goes through all the devices, generates a telemetry event for each device based on the current active attack episodes (if any), and publishes the event using both the console and file publishers.
{
    foreach (var d in devices)
    {
        var evnt = d.GenerateTelemetry(campaigns);
        await filePub.PublishAsync(evnt); //publish content on file, the file publisher will append the telemetry event as a JSON line

        if (iotHubPublisher != null)
        {
            await iotHubPublisher.PublishAsync(evnt);
        }

        if (!socMode)
        {
            await consolePub.PublishAsync(evnt); //publish content on console
            continue;
        }

        var detection = DetectionEngine.Evaluate(evnt); //take one telemetry and check if it is malicicious or not
        var state = MapState(detection.RiskScore); //maps the score to an actual state (normal, suspicious, under attack)
        var emoji = state switch //chose an emoji for a state
        {
            DeviceSecurityState.Normal => "Normal",
            DeviceSecurityState.Suspicious => "Sus",
            DeviceSecurityState.UnderAttack => "AHHHH",
            _ => "Well IDK"
        };
        var reasons = detection.Reasons.Length == 0 ? "none" : string.Join("; ", detection.Reasons); //to get teh reasons
        var suspectedLabel = detection.SuspectedType?.ToString() ?? "None"; //to get the suspected attack type, if there is one, otherwise "None"
        Console.WriteLine($"[{emoji}] {evnt.DeviceId} {evnt.DeviceType} Risk={detection.RiskScore} Suspected={suspectedLabel} Reasons={reasons}");

        if (deviceStates != null) //check if the device state is different from the previous state, if it is, update the state and publish an alert if the risk score is high enough or if the state changed to suspicious or under attack. 
        {
            deviceStates.TryGetValue(evnt.DeviceId, out var previousState);//to get the devices pervious state
            if (previousState != state)
            {
                deviceStates[evnt.DeviceId] = state; //if different change the state to the new one
            }

            if (previousState != state || detection.RiskScore >= 70) //condition to actually raise the alert
            {
                var alert = new SecurityAlert
                {
                    AlertId = $"alert_{Guid.NewGuid():N}".Substring(0, 12),
                    Timestamp = evnt.Timestamp,
                    DeviceId = evnt.DeviceId,
                    DeviceType = evnt.DeviceType,
                    IncidentId = evnt.IncidentId,
                    RiskScore = detection.RiskScore,
                    Severity =
                    detection.RiskScore >= 70 ? "Critical" :
                    detection.RiskScore >= 40 ? "Suspicious" :
                    "Info",
                    SuspectedType = detection.SuspectedType,
                    Reasons = detection.Reasons
                };
                if (alertPublisher != null) //if there is an alert publish it to alertpublisher
                {
                    await alertPublisher.PublishAsync(alert);
                }
            }
        }
    }

    await Task.Delay(settings.TickMs); //wait for a specified amount of time 
}

static DeviceSecurityState MapState(int riskScore)
{
    if (riskScore >= 70) return DeviceSecurityState.UnderAttack;
    if (riskScore >= 40) return DeviceSecurityState.Suspicious;
    return DeviceSecurityState.Normal;
}
