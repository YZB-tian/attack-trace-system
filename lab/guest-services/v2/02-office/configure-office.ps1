$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\Windows\Temp\office-config.log' -Force

$labRoot = 'C:\AttackTraceLab'
$logRoot = Join-Path $labRoot 'Logs'
$documentRoot = 'C:\Users\Public\Documents\AttackTraceLab'
$verifyPath = Join-Path $labRoot 'verification.txt'

New-Item -ItemType Directory -Force -Path $labRoot, $logRoot, $documentRoot, (Join-Path $logRoot 'PowerShell') | Out-Null
Set-TimeZone -Id 'China Standard Time'

$nic = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } | Sort-Object ifIndex | Select-Object -First 1
if (-not $nic) {
    throw 'No active hardware network adapter was found.'
}

Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne '192.168.56.20' } |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -IPAddress '192.168.56.20' -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress '192.168.56.20' -PrefixLength 24 -AddressFamily IPv4 | Out-Null
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

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

Set-Content -LiteralPath (Join-Path $documentRoot 'quarterly-plan.txt') -Encoding UTF8 -Value @'
AttackTraceLab synthetic quarterly plan
Classification: LAB-INTERNAL
Purpose: document access and endpoint telemetry validation
'@
Set-Content -LiteralPath (Join-Path $documentRoot 'employee-contacts.csv') -Encoding UTF8 -Value @'
name,department,email
Alice Chen,Finance,alice.chen@attacktrace.lab
Bob Wang,IT,bob.wang@attacktrace.lab
'@

if (-not [System.Diagnostics.EventLog]::SourceExists('AttackTraceLab')) {
    New-EventLog -LogName Application -Source 'AttackTraceLab'
}

$activityScript = Join-Path $labRoot 'office-activity.ps1'
Set-Content -LiteralPath $activityScript -Encoding UTF8 -Value @'
$ErrorActionPreference = 'SilentlyContinue'
$doc = 'C:\Users\Public\Documents\AttackTraceLab\quarterly-plan.txt'
if (Test-Path -LiteralPath $doc) {
    $null = Get-Content -LiteralPath $doc -Raw
}
Write-EventLog -LogName Application -Source 'AttackTraceLab' -EntryType Information -EventId 5201 -Message "Synthetic office document activity completed by $env:USERNAME."
'@
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$activityScript`""
$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'AttackTraceLab-OfficeActivity' -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Description 'Generates benign office endpoint telemetry for the isolated lab.' -Force | Out-Null
Start-ScheduledTask -TaskName 'AttackTraceLab-OfficeActivity'

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

$acl = Get-Acl -LiteralPath $documentRoot
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule('BUILTIN\Users', 'ReadAndExecute,Write', 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
$acl.SetAuditRule($auditRule)
Set-Acl -LiteralPath $documentRoot -AclObject $acl

$toolsCmd = Join-Path ${env:ProgramFiles} 'VMware\VMware Tools\VMwareToolboxCmd.exe'
if (Test-Path -LiteralPath $toolsCmd) {
    & $toolsCmd timesync enable | Out-Null
}

$hostPing = Test-Connection -ComputerName '192.168.56.1' -Count 1 -Quiet
$corePing = Test-Connection -ComputerName '192.168.56.60' -Count 1 -Quiet
$coreSmbPort = Test-NetConnection -ComputerName '192.168.56.60' -Port 445 -InformationLevel Quiet
$smbRead = $false
try {
    $securePassword = ConvertTo-SecureString '__LAB_PASSWORD__' -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential('CORE01\Administrator', $securePassword)
    New-PSDrive -Name LABCORE -PSProvider FileSystem -Root '\\192.168.56.60\CORE-DATA' -Credential $credential -Scope Script | Out-Null
    $smbRead = Test-Path -LiteralPath 'LABCORE:\finance-planning.txt'
    if ($smbRead) {
        $null = Get-Content -LiteralPath 'LABCORE:\finance-planning.txt' -Raw
    }
} catch {
    $smbRead = $false
} finally {
    Remove-PSDrive -Name LABCORE -Force -ErrorAction SilentlyContinue
}

$ipConfig = Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex
$routes = Get-NetRoute -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Sort-Object DestinationPrefix | Format-Table -AutoSize | Out-String
$neighbors = Get-NetNeighbor -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Sort-Object IPAddress | Format-Table -AutoSize | Out-String
$services = Get-Service WinRM, TermService, Schedule, VMTools | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
$ports = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 135, 3389, 5985, 5986 } | Sort-Object LocalPort | Format-Table -AutoSize | Out-String
$task = Get-ScheduledTask -TaskName 'AttackTraceLab-OfficeActivity' | Select-Object TaskName, State, Description | Format-Table -AutoSize | Out-String

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
CorePing192.168.56.60: $corePing
CoreSMBPort445: $coreSmbPort
CoreSMBFileRead: $smbRead

ROUTES
$routes
ARP_NEIGHBORS
$neighbors
SERVICES
$services
SCHEDULED_TASK
$task
LISTENERS
$ports
"@ | Set-Content -LiteralPath $verifyPath -Encoding UTF8

Write-EventLog -LogName Application -Source 'AttackTraceLab' -EntryType Information -EventId 5200 -Message 'WIN11-OFFICE laboratory endpoint and audit policy configured.'
Stop-Transcript
