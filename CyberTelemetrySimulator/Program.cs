using System.Text.Json;
using CyberTelemetrySimulator.Config;
using CyberTelemetrySimulator.Campaigns;
using CyberTelemetrySimulator.Devices;
using CyberTelemetrySimulator.Detection;
using CyberTelemetrySimulator.Models;
using CyberTelemetrySimulator.Publishers;
using CyberTelemetrySimulator.Validation;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

// --------------------
// Load normal settings
// --------------------

var configFolder = Path.Combine(AppContext.BaseDirectory, "Config");
var baseSettingsPath = Path.Combine(configFolder, "simulatorSettings.json");
var localSettingsPath = Path.Combine(configFolder, "simulatorSettings.local.json");

var jsonOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
};

var settings = new SimulatorSettings();

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

// --------------------
// Load Key Vault URL
// --------------------

string? keyVaultUrl = null;

if (File.Exists(localSettingsPath))
{
    var localSettingsJson = File.ReadAllText(localSettingsPath);
    var localConfig = JsonSerializer.Deserialize<Dictionary<string, string>>(localSettingsJson, jsonOptions);

    if (localConfig != null && localConfig.TryGetValue("keyVaultUrl", out var vaultUrl))
    {
        keyVaultUrl = vaultUrl;
    }
}

if (string.IsNullOrWhiteSpace(keyVaultUrl))
{
    Console.WriteLine("Missing keyVaultUrl in Config/simulatorSettings.local.json");
    return;
}

// --------------------
// Load secrets from Azure Key Vault
// --------------------

var secretClient = new SecretClient(
    new Uri(keyVaultUrl),
    new DefaultAzureCredential()
);

string? iotHubDeviceConnectionString = null;
string? sqlConnectionString = null;

try
{
    if (args.Contains("--iot-hub", StringComparer.OrdinalIgnoreCase))
    {
        iotHubDeviceConnectionString =
            secretClient.GetSecret("iot-connection-string").Value.Value;
    }

    if (args.Contains("--sql", StringComparer.OrdinalIgnoreCase))
    {
        sqlConnectionString =
            secretClient.GetSecret("sql-connection-string").Value.Value;
    }
}
catch (Exception ex)
{
    Console.WriteLine("Failed to load secrets from Azure Key Vault.");
    Console.WriteLine(ex.Message);
    return;
}

// --------------------
// App modes
// --------------------

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

// --------------------
// Simulator setup
// --------------------

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

// --------------------
// Publishers
// --------------------

ITelemetryPublisher consolePub = new ConsolePublisher();
ITelemetryPublisher filePub = new FileJsonlPublisher(settings.OutputPath);

var alertPublisher = socMode ? new AlertJsonlPublisher("data/alerts.jsonl") : null;
var deviceStates = socMode ? new Dictionary<string, DeviceSecurityState>() : null;

AzureIotHubPublisher? iotHubPublisher = null;

if (iotHubEnabled)
{
    if (string.IsNullOrWhiteSpace(iotHubDeviceConnectionString))
    {
        Console.WriteLine("Missing IoT Hub device connection string from Key Vault.");
        return;
    }

    iotHubPublisher = new AzureIotHubPublisher(iotHubDeviceConnectionString);
}

SqlTelemetryPublisher? sqlPublisher = null;

if (sqlEnabled)
{
    if (string.IsNullOrWhiteSpace(sqlConnectionString))
    {
        Console.WriteLine("Missing SQL connection string from Key Vault.");
        return;
    }

    sqlPublisher = new SqlTelemetryPublisher(sqlConnectionString);
}

// --------------------
// Main loop
// --------------------

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

        var reasons = detection.Reasons.Length == 0
            ? "none"
            : string.Join("; ", detection.Reasons);

        var suspectedLabel = detection.SuspectedType?.ToString() ?? "None";

        Console.WriteLine(
            $"[{emoji}] {evnt.DeviceId} {evnt.DeviceType} Risk={detection.RiskScore} Suspected={suspectedLabel} Reasons={reasons}"
        );

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