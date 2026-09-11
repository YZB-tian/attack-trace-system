$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddMinutes(-45)
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4634,4663,5140,5145;StartTime=$start} -MaxEvents 1500 -ErrorAction SilentlyContinue)
$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = [ordered]@{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[[string]$item.Name] = [string]$item.'#text' }
    [pscustomobject]@{
        TimeUtc=$event.TimeCreated.ToUniversalTime().ToString('o')
        Host=$event.MachineName
        EventId=$event.Id
        RecordId=$event.RecordId
        Fields=$fields
    }
}
$rows | ConvertTo-Json -Depth 5 | Set-Content 'C:\Windows\Temp\core-smb-events.json' -Encoding UTF8
