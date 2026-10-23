using ScoutWall.Data.Models;
using ScoutWall.Sensor.Processes;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Turns periodic kernel process lists into per-program processor, memory and I/O figures. Processor use and I/O
/// are changes between two samples, so the first sample of a process only establishes its baseline. Processes are
/// keyed by id and start time, so a reused process id never produces a negative change.
/// </summary>
public class ResourceSampler
{
    private readonly Dictionary<(int ProcessId, long CreateTime), long> previousCpuTimes = [];
    private readonly Dictionary<(int ProcessId, long CreateTime), (long Read, long Write, long Other)> previousIo = [];
    private (long Idle, long Kernel, long User)? previousSystemTimes;
    private DateTime previousSampleAt;

    public record ProgramSample(string ImagePath, int InstanceCount, double CpuPercent, long MemoryBytes, long PrivateBytes, List<int> ProcessIds,
        long ReadBytes = 0, long WriteBytes = 0, long OtherBytes = 0);

    /// <summary>
    /// <see cref="HasProcessorFigures"/> is false for the first sample, which only sets the baseline for processor use.
    /// </summary>
    public record MachineSample(DateTime TakenAt, double CpuPercent, long MemoryUsedBytes, long MemoryTotalBytes, int ProcessCount, List<ProgramSample> Programs, bool HasProcessorFigures = true);

    public MachineSample Sample()
    {
        var now = DateTime.UtcNow;
        var hasBaseline = previousSampleAt != default;
        var elapsedTicks = hasBaseline ? (now - previousSampleAt).Ticks : 0;
        var processorCount = Environment.ProcessorCount;
        var processes = NativeSystem.ListProcesses();
        var currentCpuTimes = new Dictionary<(int, long), long>();
        var currentIo = new Dictionary<(int, long), (long, long, long)>();
        var programs = new Dictionary<string, (int Instances, double Cpu, long Memory, long Private, List<int> ProcessIds, long Read, long Write, long Other)>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in processes.Where(process => process.ProcessId != 0))
        {
            var key = (process.ProcessId, process.CreateTime);
            currentCpuTimes[key] = process.CpuTime;
            currentIo[key] = (process.ReadBytes, process.WriteBytes, process.OtherBytes);
            var (readDelta, writeDelta, otherDelta) = previousIo.TryGetValue(key, out var previous)
                ? (Math.Max(0, process.ReadBytes - previous.Read), Math.Max(0, process.WriteBytes - previous.Write), Math.Max(0, process.OtherBytes - previous.Other))
                : (0L, 0L, 0L);
            var cpuPercent = elapsedTicks > 0 && previousCpuTimes.TryGetValue(key, out var previousCpuTime)
                ? Math.Clamp((process.CpuTime - previousCpuTime) * 100.0 / (elapsedTicks * processorCount), 0, 100)
                : 0;

            // Protected processes can't be opened for their path; their kernel name still identifies them.
            var imagePath = ProcessPathResolver.Resolve(process.ProcessId);
            if (imagePath == ProcessPathResolver.UnknownProcess)
                imagePath = string.IsNullOrEmpty(process.ImageName) ? ProcessPathResolver.UnknownProcess : process.ImageName;

            var program = programs.GetValueOrDefault(imagePath, (0, 0, 0, 0, [], 0, 0, 0));
            program.ProcessIds.Add(process.ProcessId);
            programs[imagePath] = (program.Instances + 1, program.Cpu + cpuPercent, program.Memory + process.WorkingSetBytes, program.Private + process.PrivateBytes,
                program.ProcessIds, program.Read + readDelta, program.Write + writeDelta, program.Other + otherDelta);
        }

        previousCpuTimes.Clear();
        foreach (var entry in currentCpuTimes)
            previousCpuTimes[entry.Key] = entry.Value;

        previousIo.Clear();
        foreach (var entry in currentIo)
            previousIo[entry.Key] = entry.Value;

        var machineCpu = 0.0;
        var systemTimes = NativeSystem.SystemTimes();
        if (systemTimes.HasValue && previousSystemTimes.HasValue)
        {
            var idle = systemTimes.Value.Idle - previousSystemTimes.Value.Idle;
            var total = systemTimes.Value.Kernel - previousSystemTimes.Value.Kernel + systemTimes.Value.User - previousSystemTimes.Value.User;
            machineCpu = total > 0 ? Math.Clamp(100.0 * (total - idle) / total, 0, 100) : 0;
        }

        previousSystemTimes = systemTimes;
        previousSampleAt = now;
        var memory = NativeSystem.Memory();

        return new MachineSample(
            now,
            machineCpu,
            memory.HasValue ? memory.Value.TotalBytes - memory.Value.AvailableBytes : 0,
            memory?.TotalBytes ?? 0,
            processes.Count,
            programs.Select(pair => new ProgramSample(pair.Key, pair.Value.Instances, Math.Min(100, pair.Value.Cpu), pair.Value.Memory, pair.Value.Private, pair.Value.ProcessIds,
                pair.Value.Read, pair.Value.Write, pair.Value.Other)).ToList(),
            hasBaseline);
    }
}

/// <summary>
/// Collects samples into one-minute machine figures and five-minute per-program figures.
/// </summary>
public class ResourceAccumulator
{
    private readonly List<ResourceSampler.MachineSample> minuteSamples = [];
    private readonly Dictionary<string, (double CpuSum, double CpuPeak, long MemoryPeak, long PrivatePeak, int InstancePeak, int SampleCount, long Read, long Write, long Other)> programTotals =
        new(StringComparer.OrdinalIgnoreCase);
    private int programSampleCount;

    public long? MinuteBucket { get; private set; }
    public long? ProgramBucket { get; private set; }

    public void Add(ResourceSampler.MachineSample sample, long minuteBucket, long programBucket)
    {
        MinuteBucket ??= minuteBucket;
        ProgramBucket ??= programBucket;
        minuteSamples.Add(sample);
        programSampleCount++;

        foreach (var program in sample.Programs)
        {
            var totals = programTotals.GetValueOrDefault(program.ImagePath);
            programTotals[program.ImagePath] = (
                totals.CpuSum + program.CpuPercent,
                Math.Max(totals.CpuPeak, program.CpuPercent),
                Math.Max(totals.MemoryPeak, program.MemoryBytes),
                Math.Max(totals.PrivatePeak, program.PrivateBytes),
                Math.Max(totals.InstancePeak, program.InstanceCount),
                totals.SampleCount + 1,
                totals.Read + program.ReadBytes,
                totals.Write + program.WriteBytes,
                totals.Other + program.OtherBytes);
        }
    }

    public SystemResourceMinute? TakeMinute()
    {
        if (MinuteBucket == null || minuteSamples.Count == 0)
            return null;

        var minute = new SystemResourceMinute
        {
            BucketStart = MinuteBucket.Value,
            CpuPercent = Math.Round(minuteSamples.Average(sample => sample.CpuPercent), 1),
            MemoryUsedBytes = (long)minuteSamples.Average(sample => sample.MemoryUsedBytes),
            MemoryTotalBytes = minuteSamples[^1].MemoryTotalBytes,
            ProcessCount = minuteSamples[^1].ProcessCount
        };

        minuteSamples.Clear();
        MinuteBucket = null;
        return minute;
    }

    /// <summary>
    /// The heaviest programs of the bucket: the top by processor use and the top by memory.
    /// </summary>
    public List<(string ImagePath, ProcessResourceSample Sample)> TakePrograms(int perMeasure)
    {
        if (ProgramBucket == null || programSampleCount == 0)
            return [];

        var bucketStart = ProgramBucket.Value;
        var sampleCount = programSampleCount;
        var rows = programTotals.Select(pair => (ImagePath: pair.Key, Sample: new ProcessResourceSample
        {
            BucketStart = bucketStart,
            CpuPercentAverage = Math.Round(pair.Value.CpuSum / sampleCount, 2),
            CpuPercentPeak = Math.Round(pair.Value.CpuPeak, 2),
            MemoryBytesPeak = pair.Value.MemoryPeak,
            PrivateBytesPeak = pair.Value.PrivatePeak,
            InstanceCount = pair.Value.InstancePeak,
            ReadBytes = pair.Value.Read,
            WriteBytes = pair.Value.Write,
            OtherBytes = pair.Value.Other
        })).ToList();

        var heaviest = rows.OrderByDescending(row => row.Sample.CpuPercentAverage).Take(perMeasure)
            .Concat(rows.OrderByDescending(row => row.Sample.MemoryBytesPeak).Take(perMeasure))
            .Concat(rows.OrderByDescending(row => row.Sample.ReadBytes + row.Sample.WriteBytes).Take(perMeasure))
            .DistinctBy(row => row.ImagePath, StringComparer.OrdinalIgnoreCase)
            .ToList();

        programTotals.Clear();
        programSampleCount = 0;
        ProgramBucket = null;
        return heaviest;
    }
}
