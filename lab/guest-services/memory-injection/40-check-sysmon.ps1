$ErrorActionPreference = 'Continue'
"host=$(hostname)"
"os=$((Get-CimInstance Win32_OperatingSystem).Caption)"
"user=$env:USERNAME"
"--- sysmon service ---"
Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
"--- sysmon log ---"
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Select-Object LogName, IsEnabled, RecordCount | Format-Table -AutoSize | Out-String
"--- sysmon files ---"
Get-ChildItem 'C:\Windows\Sysmon*' -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize | Out-String
"--- audit policy ---"
auditpol /get /category:* 2>$null | Select-String -Pattern 'Process Creation|Kernel Object|Logon|Handle Manipulation' | Out-String
"--- winrm ---"
(Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Status, StartType | Format-Table -AutoSize | Out-String)
"--- admin share and smb ---"
(Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | Format-Table -AutoSize | Out-String)
"--- defender ---"
(Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled | Format-Table -AutoSize | Out-String)
