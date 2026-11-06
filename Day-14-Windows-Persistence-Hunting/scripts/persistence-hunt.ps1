param(
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    [ValidateRange(1, 10000)]
    [int]$MaxEvents = 500
)

$logName = "Microsoft-Windows-Sysmon/Operational"
$startTime = (Get-Date).AddHours(-$HoursBack)

try {
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $logName
            Id        = 12, 13, 14
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop
    )
}
catch {
    Write-Warning "Could not retrieve Sysmon events: $($_.Exception.Message)"
    return
}

$results = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.InnerText
    }

    $target = $data["TargetObject"]

    $candidate = $target -match (
        'CurrentVersion\\Run|CurrentVersion\\RunOnce|' +
        'CurrentControlSet\\Services|Winlogon|TaskCache'
    )

    [PSCustomObject]@{
        TimeCreated          = $event.TimeCreated
        EventID              = $event.Id
        EventType            = $data["EventType"]
        PersistenceCandidate = [bool]$candidate
        TargetObject         = $target
        Image                = $data["Image"]
        ProcessId            = $data["ProcessId"]
        ProcessGuid          = $data["ProcessGuid"]
        Details              = $data["Details"]
    }
}

Write-Host "`n--- Sysmon Registry Hunting Summary ---"
Write-Host "Lookback hours:" $HoursBack
Write-Host "Events collected:" $events.Count

$candidates = @($results | Where-Object PersistenceCandidate)
Write-Host "Persistence-path candidates:" $candidates.Count

if ($events.Count -ge $MaxEvents) {
    Write-Warning "The event limit was reached. Additional events may exist outside this result set."
}

if ($results.Count -gt 0) {
    $results |
        Sort-Object TimeCreated -Descending |
        Format-Table TimeCreated, EventID, EventType,
            PersistenceCandidate, Image, TargetObject -Wrap
}
else {
    Write-Host "No matching Sysmon registry events were collected in this time window."
}

Write-Host "`nNote: Candidate matches require manual investigation. They are not malware verdicts."
