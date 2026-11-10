param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$ProcessId,

    [ValidateRange(1, 86400)]
    [int]$DurationSeconds = 60,

    [ValidateRange(50, 60000)]
    [int]$SampleIntervalMs = 250,

    [string]$OutputPath = ".\portmaster-process-samples.csv"
)

$process = Get-Process -Id $ProcessId -ErrorAction Stop
$processName = $process.ProcessName
$processorCount = [Math]::Max(1, [Environment]::ProcessorCount)
$samples = [System.Collections.Generic.List[object]]::new()
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$previousCpuMs = $process.TotalProcessorTime.TotalMilliseconds
$previousElapsedMs = 0.0

Write-Host "Sampling $processName (PID $ProcessId) for $DurationSeconds seconds..."
Write-Host "CPU is normalized to total logical processor capacity."

while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {
    Start-Sleep -Milliseconds $SampleIntervalMs

    try {
        $process.Refresh()
        $cpuMs = $process.TotalProcessorTime.TotalMilliseconds
        $workingSetMiB = $process.WorkingSet64 / 1MB
        $privateMiB = $process.PrivateMemorySize64 / 1MB
    }
    catch {
        Write-Warning "The process exited before sampling finished."
        break
    }

    $elapsedMs = $clock.Elapsed.TotalMilliseconds
    $wallDeltaMs = $elapsedMs - $previousElapsedMs
    $cpuDeltaMs = $cpuMs - $previousCpuMs
    $cpuTotalPercent = 0.0
    $cpuOneCorePercent = 0.0

    if ($wallDeltaMs -gt 0) {
        $cpuTotalPercent = ($cpuDeltaMs / $wallDeltaMs) * 100 / $processorCount
        $cpuOneCorePercent = ($cpuDeltaMs / $wallDeltaMs) * 100
    }

    $samples.Add([pscustomobject]@{
        Timestamp = [DateTimeOffset]::Now.ToString("o")
        ElapsedSeconds = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
        CpuTotalPercent = [Math]::Round($cpuTotalPercent, 3)
        CpuOneCorePercent = [Math]::Round($cpuOneCorePercent, 3)
        WorkingSetMiB = [Math]::Round($workingSetMiB, 2)
        PrivateMemoryMiB = [Math]::Round($privateMiB, 2)
    })

    $previousCpuMs = $cpuMs
    $previousElapsedMs = $elapsedMs
}

$clock.Stop()

if ($samples.Count -eq 0) {
    throw "No samples were collected. Check that the process remained running."
}

$samples | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8

$summary = [pscustomobject]@{
    ProcessName = $processName
    ProcessId = $ProcessId
    SampleCount = $samples.Count
    DurationSeconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2)
    AverageCpuTotalPercent = [Math]::Round(($samples | Measure-Object CpuTotalPercent -Average).Average, 3)
    PeakCpuTotalPercent = [Math]::Round(($samples | Measure-Object CpuTotalPercent -Maximum).Maximum, 3)
    AverageWorkingSetMiB = [Math]::Round(($samples | Measure-Object WorkingSetMiB -Average).Average, 2)
    PeakWorkingSetMiB = [Math]::Round(($samples | Measure-Object WorkingSetMiB -Maximum).Maximum, 2)
    AveragePrivateMemoryMiB = [Math]::Round(($samples | Measure-Object PrivateMemoryMiB -Average).Average, 2)
    PeakPrivateMemoryMiB = [Math]::Round(($samples | Measure-Object PrivateMemoryMiB -Maximum).Maximum, 2)
}

$summary | ConvertTo-Json | Set-Content -LiteralPath "$OutputPath.summary.json" -Encoding utf8
Write-Host "Results saved to $OutputPath and $OutputPath.summary.json"
$summary | Format-List