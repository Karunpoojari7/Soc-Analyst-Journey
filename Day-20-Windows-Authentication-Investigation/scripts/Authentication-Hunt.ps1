param(
    [int]$Days = 7,
    [int]$Threshold = 3
)

$StartTime = (Get-Date).AddDays(-$Days)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$Results = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Account     = $Data['TargetUserName']
        LogonType   = $Data['LogonType']
        Status      = $Data['Status']
        SubStatus   = $Data['SubStatus']
        Source      = $Data['IpAddress']
    }
}

$Results |
    Group-Object Account |
    Where-Object { $_.Count -ge $Threshold } |
    Select-Object Name, Count

Write-Host "`nTotal failed logon events: $($Results.Count)"
Write-Host "Detection threshold: $Threshold failures per account"
