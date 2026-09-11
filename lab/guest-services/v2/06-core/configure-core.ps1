$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\Windows\Temp\core-config.log' -Force

$labRoot = 'C:\AttackTraceLab'
$logRoot = Join-Path $labRoot 'Logs'
$shareRoot = Join-Path $labRoot 'core-data'
$verifyPath = Join-Path $labRoot 'verification.txt'

New-Item -ItemType Directory -Force -Path $labRoot, $logRoot, $shareRoot, (Join-Path $logRoot 'PowerShell') | Out-Null
Set-TimeZone -Id 'China Standard Time'

$nic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } | Sort-Object ifIndex | Select-Object -First 1
if (-not $nic) {
    throw 'No active hardware network adapter was found.'
}

Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne '192.168.56.60' } |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -IPAddress '192.168.56.60' -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress '192.168.56.60' -PrefixLength 24 -AddressFamily IPv4 | Out-Null
}
Get-NetRoute -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses

if (-not (Get-NetFirewallRule -Name 'AttackTraceLab-ICMPv4' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'AttackTraceLab-ICMPv4' -DisplayName 'AttackTraceLab ICMPv4 Echo' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
}
if (-not (Get-NetFirewallRule -Name 'AttackTraceLab-RDP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'AttackTraceLab-RDP' -DisplayName 'AttackTraceLab RDP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any | Out-Null
}
if (-not (Get-NetFirewallRule -Name 'AttackTraceLab-WinRM' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'AttackTraceLab-WinRM' -DisplayName 'AttackTraceLab WinRM' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -Profile Any | Out-Null
}
if (-not (Get-NetFirewallRule -Name 'AttackTraceLab-SMB' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'AttackTraceLab-SMB' -DisplayName 'AttackTraceLab SMB' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Profile Any | Out-Null
}

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

$userName = 'BUILTIN\Users'

Set-Content -LiteralPath (Join-Path $shareRoot 'finance-planning.txt') -Encoding UTF8 -Value @'
AttackTraceLab synthetic finance planning file
Classification: LAB-SENSITIVE
Owner: core01.attacktrace.lab
Purpose: file-access audit and data-staging trace validation
'@

if (Get-SmbShare -Name 'CORE-DATA' -ErrorAction SilentlyContinue) {
    Set-SmbShare -Name 'CORE-DATA' -FolderEnumerationMode AccessBased -CachingMode None -Force | Out-Null
} else {
    New-SmbShare -Name 'CORE-DATA' -Path $shareRoot -FullAccess 'BUILTIN\Administrators' -ChangeAccess $userName -FolderEnumerationMode AccessBased -CachingMode None | Out-Null
}

$auditGuids = @(
    '{0CCE9215-69AE-11D9-BED3-505054503030}',
    '{0CCE9216-69AE-11D9-BED3-505054503030}',
    '{0CCE921B-69AE-11D9-BED3-505054503030}',
    '{0CCE921D-69AE-11D9-BED3-505054503030}',
    '{0CCE921E-69AE-11D9-BED3-505054503030}',
    '{0CCE9226-69AE-11D9-BED3-505054503030}',
    '{0CCE922B-69AE-11D9-BED3-505054503030}'
)
foreach ($guid in $auditGuids) {
    & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null
}

New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1

$psPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psPolicy\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "$psPolicy\ScriptBlockLogging" -Name EnableScriptBlockLogging -Type DWord -Value 1
New-Item -Path "$psPolicy\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty "$psPolicy\ModuleLogging" -Name EnableModuleLogging -Type DWord -Value 1
New-ItemProperty "$psPolicy\ModuleLogging\ModuleNames" -Name '*' -PropertyType String -Value '*' -Force | Out-Null
New-Item -Path "$psPolicy\Transcription" -Force | Out-Null
Set-ItemProperty "$psPolicy\Transcription" -Name EnableTranscripting -Type DWord -Value 1
Set-ItemProperty "$psPolicy\Transcription" -Name EnableInvocationHeader -Type DWord -Value 1
Set-ItemProperty "$psPolicy\Transcription" -Name OutputDirectory -Type String -Value (Join-Path $logRoot 'PowerShell')

wevtutil.exe sl Security /ms:268435456
wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /e:true /ms:134217728

$acl = Get-Acl -LiteralPath $shareRoot
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($userName, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
$acl.SetAuditRule($auditRule)
Set-Acl -LiteralPath $shareRoot -AclObject $acl

$toolsCmd = Join-Path ${env:ProgramFiles} 'VMware\VMware Tools\VMwareToolboxCmd.exe'
if (Test-Path -LiteralPath $toolsCmd) {
    & $toolsCmd timesync enable | Out-Null
}

Start-Service LanmanServer
$hostPing = Test-Connection -ComputerName '192.168.56.1' -Count 1 -Quiet

$ipConfig = Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex
$routes = Get-NetRoute -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Sort-Object DestinationPrefix | Format-Table -AutoSize | Out-String
$neighbors = Get-NetNeighbor -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Sort-Object IPAddress | Format-Table -AutoSize | Out-String
$services = Get-Service LanmanServer, WinRM, TermService, VMTools | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
$shares = Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String
$ports = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 135, 139, 445, 3389, 5985, 5986 } | Sort-Object LocalPort | Format-Table -AutoSize | Out-String

@"
AttackTraceLab node verification
Timestamp: $(Get-Date -Format o)
Hostname: $env:COMPUTERNAME
Interface: $($nic.Name) / ifIndex $($nic.ifIndex)
MAC: $($nic.MacAddress)
IPv4: $($ipConfig.IPv4Address.IPAddress -join ', ')
Prefix: /24
DefaultGateway: $($ipConfig.IPv4DefaultGateway.NextHop -join ', ')
DNS: $($ipConfig.DNSServer.ServerAddresses -join ', ')
HostPing192.168.56.1: $hostPing

ROUTES
$routes
ARP_NEIGHBORS
$neighbors
SERVICES
$services
SMB_SHARES
$shares
LISTENERS
$ports
"@ | Set-Content -LiteralPath $verifyPath -Encoding UTF8

Write-EventLog -LogName Application -Source 'AttackTraceLab' -EntryType Information -EventId 5600 -Message 'CORE01 laboratory services and audit policy configured.' -ErrorAction SilentlyContinue
