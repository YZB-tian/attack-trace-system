$ErrorActionPreference = 'Continue'
"installing sysmon as $env:USERNAME on $(hostname)"
$process = Start-Process -FilePath 'C:\Windows\Temp\Sysmon64.exe' -ArgumentList '-accepteula','-i','C:\Windows\Temp\sysmon-config.xml' -Wait -PassThru -NoNewWindow
"installer exit code: $($process.ExitCode)"
Start-Sleep -Seconds 3
Get-Service -Name 'Sysmon*' | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
Start-Sleep -Seconds 5
$events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 -ErrorAction SilentlyContinue
if ($events) {
    "sysmon operational log has $($events.Count) recent events"
    $events | Select-Object -First 3 Id, TimeCreated | Format-Table -AutoSize | Out-String
} else {
    "no sysmon events yet"
}
