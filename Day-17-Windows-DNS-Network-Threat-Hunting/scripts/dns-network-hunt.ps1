<#
.SYNOPSIS
Read-only Sysmon DNS and network hunting helper.
.PARAMETER LookbackMinutes
Minutes to search (default 60).
.PARAMETER MaxEvents
Maximum records per event ID (default 200).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 10080)][int]$LookbackMinutes = 60,
    [ValidateRange(1, 5000)][int]$MaxEvents = 200
)

$logName = 'Microsoft-Windows-Sysmon/Operational'
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

try {
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not $log.IsEnabled) { throw 'Sysmon Operational log is disabled.' }
}
catch {
    Write-Error "Unable to access $logName. $($_.Exception.Message)"
    return
}

function Get-EventField {
    param([string]$Message, [string]$Field)
    $pattern = '(?m)^\s*' + [regex]::Escape($Field) + ':\s*(.*)$'
    $match = [regex]::Match($Message, $pattern)
    if ($match.Success) { return $match.Groups[1].Value.Trim() }
    return $null
}

$dnsEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = $logName; Id = 22; StartTime = $startTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

$networkEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = $logName; Id = 3; StartTime = $startTime
} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

Write-Host "`n=== Collection summary ===" -ForegroundColor Cyan
[PSCustomObject]@{
    StartTime = $startTime
    DNS_Event22 = $dnsEvents.Count
    Network_Event3 = $networkEvents.Count
} | Format-List

Write-Host "`n=== DNS queries ===" -ForegroundColor Cyan
$dnsSummary = foreach ($event in $dnsEvents) {
    [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        ProcessId = Get-EventField $event.Message 'ProcessId'
        ProcessGuid = Get-EventField $event.Message 'ProcessGuid'
        QueryName = Get-EventField $event.Message 'QueryName'
        QueryStatus = Get-EventField $event.Message 'QueryStatus'
        QueryResults = Get-EventField $event.Message 'QueryResults'
        Image = Get-EventField $event.Message 'Image'
    }
}
$dnsSummary | Format-Table -AutoSize -Wrap

Write-Host "`n=== Network connections ===" -ForegroundColor Cyan
$networkSummary = foreach ($event in $networkEvents) {
    [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        ProcessId = Get-EventField $event.Message 'ProcessId'
        ProcessGuid = Get-EventField $event.Message 'ProcessGuid'
        Image = Get-EventField $event.Message 'Image'
        Protocol = Get-EventField $event.Message 'Protocol'
        DestinationIp = Get-EventField $event.Message 'DestinationIp'
        DestinationPort = Get-EventField $event.Message 'DestinationPort'
        Initiated = Get-EventField $event.Message 'Initiated'
    }
}
$networkSummary | Format-Table -AutoSize -Wrap

Write-Host "`nRead-only hunt complete. Validate findings against process context and other telemetry."
