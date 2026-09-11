$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddMinutes(-20)
$records = @()
foreach ($logName in @('Microsoft-Windows-Sysmon/Operational', 'Security')) {
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$since} -ErrorAction Stop
    } catch {
        "could not read $logName : $($_.Exception.Message)"
        continue
    }
    foreach ($event in $events) {
        $data = @{}
        try {
            $xml = [xml]$event.ToXml()
            foreach ($node in $xml.Event.EventData.Data) {
                if ($node.Name) { $data[$node.Name] = [string]$node.'#text' }
            }
        } catch { }
        $records += [pscustomobject]@{
            log = $logName
            record_id = $event.RecordId
            event_id = $event.Id
            time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
            computer = $event.MachineName
            data = $data
            message = ($event.Message -split "`n" | Select-Object -First 6) -join ' | '
        }
    }
}
"collected $($records.Count) records"
$records | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 'C:\Windows\Temp\memory-injection-events.json'
"written C:\Windows\Temp\memory-injection-events.json"
(Get-Item 'C:\Windows\Temp\memory-injection-events.json').Length
