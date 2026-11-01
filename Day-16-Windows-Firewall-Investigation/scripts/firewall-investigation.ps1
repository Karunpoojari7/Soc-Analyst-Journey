# Day 16 - Windows Firewall and Network Investigation
# Purpose: Read-only SOC investigation
# Run PowerShell as Administrator for the most complete results.

$ErrorActionPreference = "Continue"

Write-Host "`n========================================"
Write-Host " DAY 16 - FIREWALL INVESTIGATION"
Write-Host "========================================"

# 1. Effective firewall profiles
Write-Host "`n[1] EFFECTIVE FIREWALL PROFILES"

Get-NetFirewallProfile -PolicyStore ActiveStore |
    Select-Object Name, Enabled, DefaultInboundAction,
        DefaultOutboundAction, AllowInboundRules |
    Format-Table -AutoSize

# 2. Firewall logging configuration
Write-Host "`n[2] FIREWALL LOGGING CONFIGURATION"

Get-NetFirewallProfile |
    Select-Object Name, LogFileName, LogAllowed,
        LogBlocked, LogMaxSizeKilobytes |
    Format-Table -AutoSize

# 3. Enabled inbound rules
Write-Host "`n[3] ENABLED INBOUND RULES (FIRST 15)"

Get-NetFirewallRule -PolicyStore ActiveStore `
    -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Select-Object -First 15 DisplayName, Action, Profile, Direction |
    Format-Table -AutoSize

# 4. Enabled outbound rules
Write-Host "`n[4] ENABLED OUTBOUND RULES (FIRST 15)"

Get-NetFirewallRule -PolicyStore ActiveStore `
    -Direction Outbound -Enabled True -ErrorAction SilentlyContinue |
    Select-Object -First 15 DisplayName, Action, Profile, Direction |
    Format-Table -AutoSize

# 5. TCP endpoint and process correlation
Write-Host "`n[5] TCP ENDPOINTS AND PROCESS OWNERS"

$tcpRows = foreach ($connection in (
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Select-Object -First 30
)) {
    $process = Get-Process -Id $connection.OwningProcess `
        -ErrorAction SilentlyContinue

    [pscustomobject]@{
        LocalPort     = $connection.LocalPort
        RemotePort    = $connection.RemotePort
        State         = $connection.State
        Process       = $process.ProcessName
        ProcessId     = $connection.OwningProcess
    }
}

$tcpRows | Format-Table -AutoSize

# 6. UDP endpoint and process correlation
Write-Host "`n[6] UDP ENDPOINTS AND PROCESS OWNERS"

$udpRows = foreach ($endpoint in (
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Select-Object -First 30
)) {
    $process = Get-Process -Id $endpoint.OwningProcess `
        -ErrorAction SilentlyContinue

    [pscustomobject]@{
        LocalPort = $endpoint.LocalPort
        Process   = $process.ProcessName
        ProcessId = $endpoint.OwningProcess
    }
}

$udpRows | Format-Table -AutoSize

# 7. Services associated with observed endpoint processes
Write-Host "`n[7] RELATED WINDOWS SERVICES"

$processIds = @(
    $tcpRows.ProcessId
    $udpRows.ProcessId
) | Where-Object { $_ } | Sort-Object -Unique

Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $processIds -contains $_.ProcessId } |
    Select-Object Name, State, StartMode, ProcessId |
    Format-Table -AutoSize

# 8. WFP audit policy
Write-Host "`n[8] WFP AUDIT POLICY"

& auditpol.exe /get /subcategory:"Filtering Platform Connection"
& auditpol.exe /get /subcategory:"Filtering Platform Packet Drop"

# 9. Recent WFP Security events
Write-Host "`n[9] RECENT WFP SECURITY EVENTS (LAST 24 HOURS)"

$eventIds = @(5152, 5156, 5157, 5158)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = $eventIds
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 50 -ErrorAction SilentlyContinue

Write-Host "Matching events returned:" @($events).Count

if ($events) {
    $events |
        Select-Object TimeCreated, Id, ProviderName |
        Format-Table -AutoSize
}

# 10. Firewall text log availability
Write-Host "`n[10] FIREWALL TEXT LOG"

$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

Write-Host "Expected log exists:" (Test-Path $logPath)

if (Test-Path $logPath) {
    Get-Item $logPath |
        Select-Object Length, LastWriteTime |
        Format-List
}

Write-Host "`n========================================"
Write-Host " INVESTIGATION COMPLETED"
Write-Host " No firewall or audit settings modified."
Write-Host "========================================"
