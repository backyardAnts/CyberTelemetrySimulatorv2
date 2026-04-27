using System.Text.Json;
using CyberTelemetrySimulator.Config;
using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Devices;
using CyberTelemetrySimulator.Detection;
using CyberTelemetrySimulator.Models;
using CyberTelemetrySimulator.Publishers;
using CyberTelemetrySimulator.Validation;

var configFolder = Path.Combine(AppContext.BaseDirectory, "Config");
var baseSettingsPath = Path.Combine(configFolder, "simulatorSettings.json");
var localSettingsPath = Path.Combine(configFolder, "simulatorSettings.local.json");

var jsonOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
};

var settings = new SimulatorSettings();

// Load base settings first
if (File.Exists(baseSettingsPath))
{
    var baseSettingsJson = File.ReadAllText(baseSettingsPath);
    settings = JsonSerializer.Deserialize<SimulatorSettings>(baseSettingsJson, jsonOptions)
               ?? new SimulatorSettings();
}
else
{
    Console.WriteLine($"Missing required config file: {baseSettingsPath}");
    return;
}

// Then load local settings and override secrets if present
if (File.Exists(localSettingsPath))
{
    var localSettingsJson = File.ReadAllText(localSettingsPath);
    var localSettings = JsonSerializer.Deserialize<SimulatorSettings>(localSettingsJson, jsonOptions);

    if (localSettings != null)
    {
        if (!string.IsNullOrWhiteSpace(localSettings.IotHubDeviceConnectionString))
        {
            settings.IotHubDeviceConnectionString = localSettings.IotHubDeviceConnectionString;
        }

        if (!string.IsNullOrWhiteSpace(localSettings.SqlConnectionString))
        {
            settings.SqlConnectionString = localSettings.SqlConnectionString;
        }
    }
}

if (args.Contains("--self-check", StringComparer.OrdinalIgnoreCase))
{
    TelemetrySelfCheck.Run();
    return;
}

var socMode = args.Contains("--soc", StringComparer.OrdinalIgnoreCase);
var demoMode = args.Contains("--demo", StringComparer.OrdinalIgnoreCase);
var trainingMode = args.Contains("--training", StringComparer.OrdinalIgnoreCase);
var iotHubEnabled = args.Contains("--iot-hub", StringComparer.OrdinalIgnoreCase);
var sqlEnabled = args.Contains("--sql", StringComparer.OrdinalIgnoreCase);

var timeOfDay = new CyberTelemetrySimulator.Utils.TimeOfDayService(settings);

var campaigns = new CampaignManager(
    attackChancePerTick: settings.AttackChancePerTick,
    minDurationSec: settings.MinDurationSec,
    maxDurationSec: settings.MaxDurationSec,
    incidentChainEnabled: socMode || demoMode,
    demoMode: demoMode,
    trainingDatasetMode: trainingMode || settings.TrainingDatasetMode,
    trainingEpisodeDurationSec: settings.TrainingEpisodeDurationSec,
    businessHoursStart: settings.BusinessHoursStart,
    businessHoursEnd: settings.BusinessHoursEnd,
    afterHoursAttackMultiplier: settings.AfterHoursAttackMultiplier,
    timeOfDayService: timeOfDay
);

var devices = new List<DeviceSimulator>();

for (int i = 1; i <= 20; i++)
{
    devices.Add(new DeviceSimulator($"WS-{i:D3}", DeviceType.Workstation, settings, timeOfDay));
}

for (int i = 1; i <= 8; i++)
{
    devices.Add(new DeviceSimulator($"WEB-{i:D3}", DeviceType.WebServer, settings, timeOfDay));
}

for (int i = 1; i <= 5; i++)
{
    devices.Add(new DeviceSimulator($"DB-{i:D3}", DeviceType.DatabaseServer, settings, timeOfDay));
}

for (int i = 1; i <= 3; i++)
{
    devices.Add(new DeviceSimulator($"IOT-{i:D3}", DeviceType.IoTDevice, settings, timeOfDay));
}

ITelemetryPublisher consolePub = new ConsolePublisher();
ITelemetryPublisher filePub = new FileJsonlPublisher(settings.OutputPath);
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
        Console.WriteLine("Missing IoT Hub device connection string. Set IOT_HUB_DEVICE_CONNECTION_STRING or Config/simulatorSettings.json / simulatorSettings.local.json.");
        return;
    }

    iotHubPublisher = new AzureIotHubPublisher(iotHubConnectionString);
}

SqlTelemetryPublisher? sqlPublisher = null;
if (sqlEnabled)
{
    var sqlConnectionString = Environment.GetEnvironmentVariable("SQL_CONNECTION_STRING");
    if (string.IsNullOrWhiteSpace(sqlConnectionString))
    {
        sqlConnectionString = settings.SqlConnectionString;
    }

    if (string.IsNullOrWhiteSpace(sqlConnectionString))
    {
        Console.WriteLine("Missing SQL connection string. Set SQL_CONNECTION_STRING or Config/simulatorSettings.json / simulatorSettings.local.json.");
        return;
    }

    sqlPublisher = new SqlTelemetryPublisher(sqlConnectionString);
}

while (true)
{
    foreach (var d in devices)
    {
        var evnt = d.GenerateTelemetry(campaigns);

        await filePub.PublishAsync(evnt);

        if (sqlPublisher != null)
        {
            await sqlPublisher.PublishAsync(evnt);
        }

        if (iotHubPublisher != null)
        {
            Console.WriteLine($"[DEBUG] Sending to IoT Hub: {evnt.DeviceId} {evnt.DeviceType}");
            await iotHubPublisher.PublishAsync(evnt);
            Console.WriteLine($"[DEBUG] Sent to IoT Hub: {evnt.DeviceId}");
        }
        else
        {
            Console.WriteLine("[DEBUG] IoT Hub publisher is null");
        }

        if (!socMode)
        {
            await consolePub.PublishAsync(evnt);
            continue;
        }

        var detection = DetectionEngine.Evaluate(evnt);
        var state = MapState(detection.RiskScore);
        var emoji = state switch
        {
            DeviceSecurityState.Normal => "Normal",
            DeviceSecurityState.Suspicious => "Sus",
            DeviceSecurityState.UnderAttack => "AHHHH",
            _ => "Well IDK"
        };

        var reasons = detection.Reasons.Length == 0 ? "none" : string.Join("; ", detection.Reasons);
        var suspectedLabel = detection.SuspectedType?.ToString() ?? "None";

        Console.WriteLine($"[{emoji}] {evnt.DeviceId} {evnt.DeviceType} Risk={detection.RiskScore} Suspected={suspectedLabel} Reasons={reasons}");

        if (deviceStates != null)
        {
            deviceStates.TryGetValue(evnt.DeviceId, out var previousState);
            if (previousState != state)
            {
                deviceStates[evnt.DeviceId] = state;
            }

            if (previousState != state || detection.RiskScore >= 70)
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

                if (alertPublisher != null)
                {
                    await alertPublisher.PublishAsync(alert);
                }
            }
        }
    }

    timeOfDay.AdvanceTime();
    await Task.Delay(settings.TickMs);
}

static DeviceSecurityState MapState(int riskScore)
{
    if (riskScore >= 70) return DeviceSecurityState.UnderAttack;
    if (riskScore >= 40) return DeviceSecurityState.Suspicious;
    return DeviceSecurityState.Normal;
}
