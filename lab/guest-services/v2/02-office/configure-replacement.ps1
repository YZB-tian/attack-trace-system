$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'WIN11-OFFICE') { throw 'Not the office guest.' }
$root='C:\AttackTraceLab'
New-Item -ItemType Directory -Force "$root\Logs\PowerShell" | Out-Null
Start-Transcript "$root\replacement-configuration.txt"
$nics=@(Get-NetAdapter | Where-Object HardwareInterface)
if($nics.Count -ne 1){throw 'Expected exactly one guest NIC.'}
$nic=$nics[0]
& netsh.exe interface ipv4 set address name=$($nic.Name) source=static address=192.168.70.20 mask=255.255.255.0 gateway=none
if($LASTEXITCODE){throw 'Address configuration failed.'}
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses
foreach($prefix in @('192.168.56.0/24','192.168.60.0/24','192.168.80.0/24')){
 if(-not(Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue)){
  & route.exe -p ADD ($prefix.Split('/')[0]) MASK 255.255.255.0 192.168.70.1 IF $nic.ifIndex
  if($LASTEXITCODE){throw "Persistent route failed: $prefix"}
 }
}
Set-TimeZone -Id 'China Standard Time'
foreach($guid in @('{0CCE922B-69AE-11D9-BED3-505054503030}','{0CCE921D-69AE-11D9-BED3-505054503030}','{0CCE9215-69AE-11D9-BED3-505054503030}')){
 & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable
 if($LASTEXITCODE){throw 'Audit configuration failed.'}
}
$audit='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item $audit -Force | Out-Null
New-ItemProperty $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
$ps='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
foreach($item in @(@('ScriptBlockLogging','EnableScriptBlockLogging'),@('ModuleLogging','EnableModuleLogging'),@('Transcription','EnableTranscripting'))){
 New-Item "$ps\$($item[0])" -Force | Out-Null
 New-ItemProperty "$ps\$($item[0])" -Name $item[1] -Value 1 -PropertyType DWord -Force | Out-Null
}
New-Item "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
New-ItemProperty "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
New-ItemProperty "$ps\Transcription" -Name OutputDirectory -Value "$root\Logs\PowerShell" -PropertyType String -Force | Out-Null
& wevtutil.exe sl Security /ms:268435456
& wevtutil.exe sl Microsoft-Windows-PowerShell/Operational /e:true /ms:134217728
Get-NetIPAddress -AddressFamily IPv4 | Format-Table
Get-NetRoute -AddressFamily IPv4 | Format-Table
if(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue){throw 'Unexpected default route.'}
Stop-Transcript
