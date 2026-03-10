using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CyberTelemetrySimulator.Campaigns;
//owns the list/queue of AttackEpisodes, decides what’s active right now, and tells AttackApplier what to apply.
using CyberTelemetrySimulator.Config;
using CyberTelemetrySimulator.Models;

public class CampaignManager
{
    private readonly Random _random = new(); //random instance for generating random numbers
    private readonly Dictionary<string, AttackEpisode> _active = new(); //dictionary to track active attack episodes by device ID
    private readonly bool _incidentChainEnabled;
    private readonly bool _demoMode;
    private string? _incidentId;
    private string? _incidentDeviceId;
    private int _incidentStageIndex;
    private bool _incidentCompleted;
    private readonly bool _balancedDatasetMode;
    private readonly bool _trainingDatasetMode;
    private readonly int _trainingEpisodeDurationSec;
    private readonly int _businessHoursStart;
    private readonly int _businessHoursEnd;
    private readonly double _afterHoursAttackMultiplier;
    private readonly Dictionary<AttackType, double> _targetRatios;
    private readonly int? _totalEventsTarget;
    private readonly Dictionary<AttackType, int> _generatedCounts;
    private int _eventsGenerated;
    private readonly AttackType[] _trainingOrder =
    {
        AttackType.BruteForce,
        AttackType.PortScan,
        AttackType.DDoS,
        AttackType.Exfiltration
    };
    private int _trainingIndex;

    // Config knobs (we’ll move to Config later)
    private readonly double _attackChancePerTick; // chance to start an attack each telemetry tick
    private readonly int _minDurationSec;
    private readonly int _maxDurationSec;

    public CampaignManager(
        double attackChancePerTick = 0.08,
        int minDurationSec = 20,
        int maxDurationSec = 90,
        bool incidentChainEnabled = false,
        bool demoMode = false,
        bool? balancedDatasetMode = null,
        bool? trainingDatasetMode = null,
        Dictionary<string, double>? targetClassRatios = null,
        int? totalEventsTarget = null,
        int? trainingEpisodeDurationSec = null,
        int? businessHoursStart = null,
        int? businessHoursEnd = null,
        double? afterHoursAttackMultiplier = null)
    {
        _attackChancePerTick = attackChancePerTick;
        _minDurationSec = minDurationSec;
        _maxDurationSec = maxDurationSec;
        _incidentChainEnabled = incidentChainEnabled;
        _demoMode = demoMode;
        var settings = LoadSettings();
        _balancedDatasetMode = balancedDatasetMode ?? settings?.BalancedDatasetMode ?? false;
        _trainingDatasetMode = trainingDatasetMode ?? settings?.TrainingDatasetMode ?? false;
        _trainingEpisodeDurationSec = trainingEpisodeDurationSec ?? settings?.TrainingEpisodeDurationSec ?? 60;
        _businessHoursStart = NormalizeHour(businessHoursStart ?? settings?.BusinessHoursStart ?? 9);
        _businessHoursEnd = NormalizeHour(businessHoursEnd ?? settings?.BusinessHoursEnd ?? 17);
        _afterHoursAttackMultiplier = Math.Max(0.1, afterHoursAttackMultiplier ?? settings?.AfterHoursAttackMultiplier ?? 2.0);
        _targetRatios = ResolveTargetRatios(targetClassRatios ?? settings?.TargetClassRatios);
        _totalEventsTarget = totalEventsTarget ?? settings?.TotalEventsTarget;
        _generatedCounts = Enum.GetValues<AttackType>().ToDictionary(type => type, _ => 0);
        if (_balancedDatasetMode)
        {
            Console.WriteLine("[CampaignManager] BalancedDatasetMode enabled.");
        }
        if (_trainingDatasetMode)
        {
            Console.WriteLine("[CampaignManager] TrainingDatasetMode enabled.");
        }
    }

    public AttackEpisode? GetActiveEpisode(string deviceId, DateTime nowUtc)
    {
        if (_active.TryGetValue(deviceId, out var ep))
        {
            if (ep.IsActive(nowUtc))
            {
                IncrementCount(ep.AttackType);
                return ep;
            }
            _active.Remove(deviceId); // expired
        }
        return null;
    }

    public AttackEpisode? TryStartEpisode(string deviceId, DateTime nowUtc)
    {
        // If one already active, do nothing
        if (GetActiveEpisode(deviceId, nowUtc) != null) return null;

        if (_trainingDatasetMode)
        {
            var trainingType = NextTrainingAttackType();
            var trainingMode = RandomAttackMode(trainingType);
            var trainingIntensity = RandomIntensity(trainingMode, trainingType);
            var (trainingClusters, trainingClusterSize) = SourceIpClustering(trainingType, trainingMode);
            var trainingForceAfterHours = trainingType == AttackType.Exfiltration && _random.NextDouble() < (trainingMode == AttackMode.Stealth ? 0.7 : 0.4);

            var trainingEpisode = new AttackEpisode
            {
                AttackId = $"attack_{Guid.NewGuid():N}".Substring(0, 12),
                AttackType = trainingType,
                Mode = trainingMode,
                Intensity = trainingIntensity,
                SourceIpClusters = trainingClusters,
                SourceIpsPerCluster = trainingClusterSize,
                ForceAfterHours = trainingForceAfterHours,
                StartUtc = nowUtc,
                EndUtc = nowUtc.AddSeconds(_trainingEpisodeDurationSec)
            };

            _active[deviceId] = trainingEpisode;
            IncrementCount(trainingEpisode.AttackType);
            return trainingEpisode;
        }

        if (_incidentChainEnabled)
        {
            if (_incidentCompleted)
            {
                IncrementCount(AttackType.Normal);
                return null;
            }

            if (_incidentId == null)
            {
                var shouldStart = _demoMode || _random.NextDouble() <= _attackChancePerTick;

                if (!shouldStart)
                {
                    IncrementCount(AttackType.Normal);
                    return null;
                }

                _incidentId = $"inc_{Guid.NewGuid():N}".Substring(0, 10);
                _incidentDeviceId = deviceId;
                _incidentStageIndex = 0;
            }

            if (deviceId != _incidentDeviceId)
            {
                IncrementCount(AttackType.Normal);
                return null;
            }

            var stage = GetIncidentStage(_incidentStageIndex);
            if (stage == null)
            {
                _incidentCompleted = true;
                IncrementCount(AttackType.Normal);
                return null;
            }

            _incidentStageIndex++;
            var episode = BuildEpisode(stage.Value, nowUtc, incidentId: _incidentId);
            _active[deviceId] = episode;
            IncrementCount(episode.AttackType);
            return episode;
        }

        if (_balancedDatasetMode)
        {
            var balancedType = SelectBalancedAttackType();
            if (balancedType == null)
            {
                IncrementCount(AttackType.Normal);
                return null;
            }

            Console.WriteLine($"[CampaignManager] Balanced selection: {balancedType}");

            var balancedDuration = _random.Next(_minDurationSec, _maxDurationSec + 1);
            var balancedMode = RandomAttackMode(balancedType.Value);
            var balancedIntensity = RandomIntensity(balancedMode, balancedType.Value);
            var (balancedClusters, balancedClusterSize) = SourceIpClustering(balancedType.Value, balancedMode);
            var balancedForceAfterHours = balancedType.Value == AttackType.Exfiltration && _random.NextDouble() < (balancedMode == AttackMode.Stealth ? 0.7 : 0.4);

            var balancedEpisode = new AttackEpisode
            {
                AttackId = $"attack_{Guid.NewGuid():N}".Substring(0, 12),
                AttackType = balancedType.Value,
                Mode = balancedMode,
                Intensity = balancedIntensity,
                SourceIpClusters = balancedClusters,
                SourceIpsPerCluster = balancedClusterSize,
                ForceAfterHours = balancedForceAfterHours,
                StartUtc = nowUtc,
                EndUtc = nowUtc.AddSeconds(balancedDuration)
            };

            _active[deviceId] = balancedEpisode;
            IncrementCount(balancedEpisode.AttackType);
            return balancedEpisode;
        }

        // Start a new one with some probability
        var attackChance = _attackChancePerTick;
        if (IsAfterHours(nowUtc))
        {
            attackChance *= _afterHoursAttackMultiplier;
        }

        attackChance = Math.Clamp(attackChance, 0.0, 1.0);
        if (_random.NextDouble() > attackChance)
        {
            IncrementCount(AttackType.Normal);
            return null;
        }

        var duration = _random.Next(_minDurationSec, _maxDurationSec + 1);
        var type = RandomAttackType();
        var mode = RandomAttackMode(type);
        var intensity = RandomIntensity(mode, type);
        var (clusters, clusterSize) = SourceIpClustering(type, mode);
        var forceAfterHours = type == AttackType.Exfiltration && _random.NextDouble() < (mode == AttackMode.Stealth ? 0.7 : 0.4);

        var ep = new AttackEpisode
        {
            AttackId = $"attack_{Guid.NewGuid():N}".Substring(0, 12),
            AttackType = type,
            Mode = mode,
            Intensity = intensity,
            SourceIpClusters = clusters,
            SourceIpsPerCluster = clusterSize,
            ForceAfterHours = forceAfterHours,
            StartUtc = nowUtc,
            EndUtc = nowUtc.AddSeconds(duration)
        };

        _active[deviceId] = ep;
        IncrementCount(ep.AttackType);
        return ep;
    }

    private AttackType NextTrainingAttackType()
    {
        var attackType = _trainingOrder[_trainingIndex];
        _trainingIndex = (_trainingIndex + 1) % _trainingOrder.Length;
        return attackType;
    }

    private AttackType RandomAttackType()
    {
        // exclude Normal
        var options = new[] { AttackType.PortScan, AttackType.BruteForce, AttackType.DDoS, AttackType.Exfiltration };
        return options[_random.Next(options.Length)];
    }

    private AttackType? SelectBalancedAttackType()
    {
        var totalSoFar = _generatedCounts.Values.Sum();
        var targetTotal = _totalEventsTarget.HasValue
            ? Math.Max(_totalEventsTarget.Value, totalSoFar + 1)
            : totalSoFar + 1;

        AttackType? selected = null;
        var bestDeficit = 0.0;

        foreach (var attackType in new[] { AttackType.PortScan, AttackType.BruteForce, AttackType.DDoS, AttackType.Exfiltration })
        {
            var ratio = _targetRatios.TryGetValue(attackType, out var targetRatio) ? targetRatio : 0.0;
            var targetCount = ratio * targetTotal;
            var deficit = targetCount - _generatedCounts[attackType];
            if (deficit <= 0.0)
            {
                continue;
            }

            if (deficit > bestDeficit + 1e-6)
            {
                bestDeficit = deficit;
                selected = attackType;
                continue;
            }

            if (selected.HasValue && Math.Abs(deficit - bestDeficit) <= 1e-6 && attackType < selected.Value)
            {
                selected = attackType;
            }
        }

        return selected;
    }

    private void IncrementCount(AttackType attackType)
    {
        _generatedCounts[attackType] = _generatedCounts[attackType] + 1;
        _eventsGenerated++;
        if (_eventsGenerated % 1000 == 0)
        {
            Console.WriteLine($"[CampaignManager] Counts @ {_eventsGenerated}: {FormatCounts()}");
        }
    }

    private bool IsAfterHours(DateTime nowUtc)
    {
        return !IsWithinBusinessHours(nowUtc.Hour, _businessHoursStart, _businessHoursEnd);
    }

    private static bool IsWithinBusinessHours(int hour, int businessHoursStart, int businessHoursEnd)
    {
        if (businessHoursStart == businessHoursEnd)
        {
            return true;
        }

        if (businessHoursStart < businessHoursEnd)
        {
            return hour >= businessHoursStart && hour < businessHoursEnd;
        }

        return hour >= businessHoursStart || hour < businessHoursEnd;
    }

    private static int NormalizeHour(int hour)
    {
        if (hour < 0) return 0;
        if (hour > 23) return 23;
        return hour;
    }

    private string FormatCounts()
    {
        return string.Join(", ", _generatedCounts.Select(kvp => $"{kvp.Key}={kvp.Value}"));
    }

    private static Dictionary<AttackType, double> ResolveTargetRatios(Dictionary<string, double>? rawRatios)
    {
        var defaults = new Dictionary<AttackType, double>
        {
            [AttackType.Normal] = 0.65,
            [AttackType.BruteForce] = 0.12,
            [AttackType.PortScan] = 0.12,
            [AttackType.DDoS] = 0.06,
            [AttackType.Exfiltration] = 0.05
        };

        if (rawRatios == null || rawRatios.Count == 0)
        {
            return new Dictionary<AttackType, double>(defaults);
        }

        var parsed = new Dictionary<AttackType, double>();
        foreach (var (key, value) in rawRatios)
        {
            if (!Enum.TryParse<AttackType>(key, true, out var attackType))
            {
                continue;
            }

            if (value <= 0)
            {
                continue;
            }

            parsed[attackType] = value;
        }

        var attackSum = parsed.Where(kvp => kvp.Key != AttackType.Normal).Sum(kvp => kvp.Value);
        if (!parsed.ContainsKey(AttackType.Normal))
        {
            parsed[AttackType.Normal] = attackSum > 0 && attackSum < 1.0
                ? 1.0 - attackSum
                : defaults[AttackType.Normal];
        }

        foreach (var (attackType, ratio) in defaults)
        {
            if (!parsed.ContainsKey(attackType))
            {
                parsed[attackType] = ratio;
            }
        }

        var total = parsed.Values.Sum();
        if (total <= 0)
        {
            return new Dictionary<AttackType, double>(defaults);
        }

        return parsed.ToDictionary(kvp => kvp.Key, kvp => kvp.Value / total);
    }

    private static SimulatorSettings? LoadSettings()
    {
        var settingsPath = Path.Combine(AppContext.BaseDirectory, "Config", "simulatorSettings.json");
        if (File.Exists(settingsPath))
        {
            var settingsJson = File.ReadAllText(settingsPath);
            return JsonSerializer.Deserialize<SimulatorSettings>(settingsJson);
        }

        var cwdSettingsPath = Path.Combine(Directory.GetCurrentDirectory(), "Config", "simulatorSettings.json");
        if (File.Exists(cwdSettingsPath))
        {
            var settingsJson = File.ReadAllText(cwdSettingsPath);
            return JsonSerializer.Deserialize<SimulatorSettings>(settingsJson);
        }

        return null;
    }

    private (AttackType Type, AttackMode Mode, int MinSec, int MaxSec)? GetIncidentStage(int index)
    {
        return index switch
        {
            0 => (AttackType.PortScan, AttackMode.Stealth, 30, 90),
            1 => (AttackType.BruteForce, AttackMode.Loud, 20, 60),
            2 => (AttackType.Exfiltration, AttackMode.Stealth, 60, 180),
            _ => null
        };
    }

    private AttackEpisode BuildEpisode(
        (AttackType Type, AttackMode Mode, int MinSec, int MaxSec) stage,
        DateTime nowUtc,
        string? incidentId)
    {
        var duration = _random.Next(stage.MinSec, stage.MaxSec + 1);
        var intensity = RandomIntensity(stage.Mode, stage.Type);
        var (clusters, clusterSize) = SourceIpClustering(stage.Type, stage.Mode);
        var forceAfterHours = stage.Type == AttackType.Exfiltration && _random.NextDouble() < 0.6;

        return new AttackEpisode
        {
            AttackId = $"attack_{Guid.NewGuid():N}".Substring(0, 12),
            AttackType = stage.Type,
            Mode = stage.Mode,
            Intensity = intensity,
            SourceIpClusters = clusters,
            SourceIpsPerCluster = clusterSize,
            ForceAfterHours = forceAfterHours,
            IncidentId = incidentId,
            StartUtc = nowUtc,
            EndUtc = nowUtc.AddSeconds(duration)
        };
    }

    private AttackMode RandomAttackMode(AttackType type)
    {
        return type switch
        {
            AttackType.Exfiltration => _random.NextDouble() < 0.7 ? AttackMode.Stealth : AttackMode.Loud,
            AttackType.DDoS => _random.NextDouble() < 0.6 ? AttackMode.Loud : AttackMode.Stealth,
            AttackType.BruteForce => _random.NextDouble() < 0.55 ? AttackMode.Loud : AttackMode.Stealth,
            AttackType.PortScan => _random.NextDouble() < 0.5 ? AttackMode.Loud : AttackMode.Stealth,
            _ => AttackMode.Loud
        };
    }

    private double RandomIntensity(AttackMode mode, AttackType type)
    {
        var baseIntensity = mode == AttackMode.Loud ? 1.0 : 0.45;
        var variability = mode == AttackMode.Loud ? 0.5 : 0.25;
        if (type == AttackType.DDoS && mode == AttackMode.Loud)
        {
            baseIntensity = 1.2;
            variability = 0.6;
        }

        return baseIntensity + _random.NextDouble() * variability;
    }

    private (int Clusters, int ClusterSize) SourceIpClustering(AttackType type, AttackMode mode)
    {
        return type switch
        {
            AttackType.DDoS => mode == AttackMode.Loud
                ? (_random.Next(6, 14), _random.Next(60, 200))
                : (_random.Next(3, 8), _random.Next(20, 80)),
            AttackType.BruteForce => mode == AttackMode.Loud
                ? (_random.Next(2, 6), _random.Next(8, 25))
                : (_random.Next(4, 10), _random.Next(4, 12)),
            _ => (1, 1)
        };
    }
}
