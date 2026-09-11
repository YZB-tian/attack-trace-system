$ErrorActionPreference = 'Stop'
$run = 'behavior-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$root = Join-Path 'C:\AttackTraceLab' $run
New-Item -ItemType Directory -Path $root | Out-Null
& auditpol.exe /backup /file:"$root\audit-before.csv" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Audit policy backup failed' }
foreach ($guid in @('{0CCE922B-69AE-11D9-BED3-505054503030}','{0CCE921D-69AE-11D9-BED3-505054503030}')) {
    & auditpol.exe /set /subcategory:$guid /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Audit policy update failed' }
}
$acl = Get-Acl -LiteralPath $root
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid,'ReadData,WriteData,AppendData','ContainerInherit,ObjectInherit','None','Success')
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $root -AclObject $acl
$start = Get-Date
$file = Join-Path $root 'synthetic-course-data.txt'
Set-Content -LiteralPath $file -Value 'Synthetic course test; authorized benign behavior verification.'
$null = Get-Content -LiteralPath $file -Raw
$p = Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -ArgumentList '/user' -RedirectStandardOutput (Join-Path $root 'identity.txt') -PassThru -Wait -WindowStyle Hidden
Start-Sleep -Seconds 2
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688,4663;StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $fields = @{}
    foreach ($d in $xml.Event.EventData.Data) { $fields[[string]$d.Name] = [string]$d.'#text' }
    [pscustomobject]@{TimeUtc=$_.TimeCreated.ToUniversalTime().ToString('o');Host=$env:COMPUTERNAME;EventId=$_.Id;RecordId=$_.RecordId;Fields=$fields}
})
$events | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'events.json') -Encoding UTF8
$process = @($events | Where-Object { $_.EventId -eq 4688 -and $_.Fields.NewProcessName -like '*\whoami.exe' })
$access = @($events | Where-Object { $_.EventId -eq 4663 -and $_.Fields.ObjectName -eq $file })
& wevtutil.exe epl Security "$root\security.evtx" /q:"*[System[(EventID=4688 or EventID=4663) and TimeCreated[timediff(@SystemTime) <= 300000]]]"
if ($LASTEXITCODE -ne 0) { throw 'EVTX export failed' }
$result = [pscustomobject]@{Run=$run;Root=$root;Host=$env:COMPUTERNAME;WhoamiPid=$p.Id;ProcessEvents=$process.Count;FileEvents=$access.Count;Classification='benign_telemetry_validation';Verified=($process.Count -gt 0 -and $access.Count -gt 0)}
$result | ConvertTo-Json | Set-Content C:\Windows\Temp\behavior-result.json -Encoding UTF8
if (-not $result.Verified) { throw 'Expected behavior evidence missing' }
