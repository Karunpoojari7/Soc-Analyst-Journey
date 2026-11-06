
# Day 18 - PowerShell Threat Hunting
# Portfolio-safe summary reporting.
# Raw endpoint identifiers and event messages are never exported.

[CmdletBinding()]
param(
    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 60,

    [string]$OutputDirectory = "$PSScriptRoot\..\reports"
)

$ErrorActionPreference = "SilentlyContinue"
$StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$RunTime = Get-Date

$PowerShellLog = "Microsoft-Windows-PowerShell/Operational"
$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

New-Item -ItemType Directory -Path $OutputDirectory -Force |
    Out-Null

function Get-EventCount {
    param(
        [string]$LogName,
        [int]$EventId
    )

    $Events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Id = $EventId
            StartTime = $StartTime
        }
    )

    return $Events.Count
}

function Get-EventData {
    param($Event)

    $Data = @{}

    try {
        [xml]$Xml = $Event.ToXml()

        foreach ($Item in $Xml.Event.EventData.Data) {
            if ($Item.Name) {
                $Data[[string]$Item.Name] = [string]$Item.'#text'
            }
        }
    }
    catch {}

    return $Data
}

Write-Host "`n=== DAY 18 POWERSHELL THREAT HUNT ===" -ForegroundColor Cyan
Write-Host "Lookback: $LookbackMinutes minutes"
Write-Host "Start: $StartTime"

# PowerShell telemetry
Write-Host "`n[1] Collecting PowerShell telemetry..."

$Event4103 = @(
    Get-WinEvent -FilterHashtable @{
        LogName = $PowerShellLog
        Id = 4103
        StartTime = $StartTime
    }
)

$Event4104 = @(
    Get-WinEvent -FilterHashtable @{
        LogName = $PowerShellLog
        Id = 4104
        StartTime = $StartTime
    }
)

# Sysmon process telemetry
Write-Host "[2] Collecting process telemetry..."

$ProcessEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = $SysmonLog
        Id = 1
        StartTime = $StartTime
    }
)

$PowerShellProcesses = @(
    foreach ($Event in $ProcessEvents) {
        $Data = Get-EventData $Event

        if ([string]$Data["Image"] -match '(?i)\\(powershell|pwsh)\.exe$') {
            [PSCustomObject]@{
                ProcessGuid = $Data["ProcessGuid"]
                TimeCreated = $Event.TimeCreated
            }
        }
    }
)

# Sysmon network telemetry
Write-Host "[3] Collecting network telemetry..."

$NetworkEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = $SysmonLog
        Id = 3
        StartTime = $StartTime
    }
)

$PowerShellNetwork = @(
    foreach ($Event in $NetworkEvents) {
        $Data = Get-EventData $Event

        if ([string]$Data["Image"] -match '(?i)\\(powershell|pwsh)\.exe$') {
            [PSCustomObject]@{
                ProcessGuid = $Data["ProcessGuid"]
                TimeCreated = $Event.TimeCreated
            }
        }
    }
)

# Process/network correlation
Write-Host "[4] Correlating process and network telemetry..."

$CorrelationCount = 0

foreach ($Network in $PowerShellNetwork) {
    $Match = $PowerShellProcesses |
        Where-Object {
            $_.ProcessGuid -eq $Network.ProcessGuid -and
            $_.ProcessGuid -ne ""
        } |
        Select-Object -First 1

    if ($Match) {
        $CorrelationCount++
    }
}

# Summary
$Summary = [PSCustomObject]@{
    Investigation = "Day 18 - PowerShell Threat Hunting"
    GeneratedAt = $RunTime.ToString("yyyy-MM-dd HH:mm:ss")
    LookbackMinutes = $LookbackMinutes
    PowerShellEvent4103 = $Event4103.Count
    PowerShellEvent4104 = $Event4104.Count
    SysmonPowerShellProcesses = $PowerShellProcesses.Count
    SysmonPowerShellNetworkEvents = $PowerShellNetwork.Count
    ProcessNetworkGuidMatches = $CorrelationCount
    MaliciousVerdict = "Not assigned"
    Assessment = "Manual investigation required"
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputFile = Join-Path $OutputDirectory "Day18-Sanitized-Summary-$Timestamp.csv"

$Summary |
    Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host "`n=== INVESTIGATION SUMMARY ===" -ForegroundColor Cyan
$Summary | Format-List

Write-Host "Sanitized summary saved to reports directory."
Write-Host "No raw process identifiers, IP addresses, or command lines exported."
Write-Host "No automatic malicious verdict assigned." -ForegroundColor Yellow
