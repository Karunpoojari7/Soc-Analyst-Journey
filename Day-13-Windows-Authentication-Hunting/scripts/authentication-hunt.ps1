param(
    [string]$InputCsv = "$PSScriptRoot\..\data\training-auth-events.csv",
    [int]$FailureThreshold = 5,
    [int]$WindowMinutes = 5,
    [int]$SprayAccountThreshold = 3
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputCsv)) {
    throw "Input CSV not found: $InputCsv"
}

$events = @(Import-Csv -LiteralPath $InputCsv | ForEach-Object {
    [pscustomobject]@{
        Time     = [datetime]$_.Time
        Account  = [string]$_.Account
        SourceIP = [string]$_.SourceIP
        EventID  = [int]$_.EventID
    }
} | Sort-Object Time)

Write-Host "`n=== Failure followed by success ===" -ForegroundColor Cyan

$correlationFound = $false

foreach ($event in $events | Where-Object EventID -eq 4625) {
    $end = $event.Time.AddMinutes($WindowMinutes)

    $windowEvents = @($events | Where-Object {
        $_.Account -eq $event.Account -and
        $_.SourceIP -eq $event.SourceIP -and
        $_.Time -ge $event.Time -and
        $_.Time -le $end
    })

    $failures = @($windowEvents | Where-Object EventID -eq 4625)
    $successes = @($windowEvents | Where-Object {
        $_.EventID -eq 4624 -and $_.Time -gt $event.Time
    })

    if ($failures.Count -ge $FailureThreshold -and $successes.Count -gt 0) {
        [pscustomobject]@{
            Account          = $event.Account
            SourceIP         = $event.SourceIP
            WindowStart      = $event.Time
            FailedLogons     = $failures.Count
            SuccessfulLogons = $successes.Count
            Detection        = 'Failures followed by success'
        }
        $correlationFound = $true
        break
    }
}

if (-not $correlationFound) {
    Write-Host 'No matching failure-to-success sequence detected.'
}

Write-Host "`n=== Possible password spraying ===" -ForegroundColor Cyan

$sprayFound = $false

foreach ($source in ($events | Where-Object EventID -eq 4625 |
        Select-Object -ExpandProperty SourceIP -Unique)) {

    $sourceFailures = @($events | Where-Object {
        $_.EventID -eq 4625 -and $_.SourceIP -eq $source
    })

    foreach ($event in $sourceFailures) {
        $end = $event.Time.AddMinutes($WindowMinutes)

        $windowFailures = @($sourceFailures | Where-Object {
            $_.Time -ge $event.Time -and $_.Time -le $end
        })

        $accounts = @($windowFailures |
            Select-Object -ExpandProperty Account -Unique)

        if ($accounts.Count -ge $SprayAccountThreshold) {
            [pscustomobject]@{
                SourceIP       = $source
                WindowStart    = $event.Time
                FailedAttempts = $windowFailures.Count
                UniqueAccounts = $accounts.Count
                Detection      = 'Possible password spraying'
            }
            $sprayFound = $true
            break
        }
    }
}

if (-not $sprayFound) {
    Write-Host 'No possible password-spraying pattern detected.'
}

Write-Host "`nAnalysis complete. Findings require analyst validation."
