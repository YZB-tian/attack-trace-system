$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\Windows\Temp\core-zone-migration.log'
$nic = @(Get-NetAdapter | Where-Object MacAddress -eq '00-0C-29-89-B2-35')
if ($nic.Count -ne 1) { throw 'Expected core adapter not found uniquely.' }
if (@(Get-SmbSession).Count) { throw 'Active SMB sessions; migration stopped.' }
$old = Get-NetIPAddress -InterfaceIndex $nic[0].ifIndex -AddressFamily IPv4
if (@($old | Where-Object { $_.IPAddress -in '192.168.56.60','192.168.80.60' }).Count -ne 1) {
    throw 'Unexpected address configuration; migration stopped.'
}
Get-NetIPConfiguration | Format-List * | Out-File 'C:\Windows\Temp\core-before-zone.txt'
Get-NetRoute -AddressFamily IPv4 | Format-Table -AutoSize | Out-File 'C:\Windows\Temp\core-before-zone.txt' -Append
& netsh.exe interface ipv4 set address name=$($nic[0].Name) source=static address=192.168.80.60 mask=255.255.255.0 gateway=none
if ($LASTEXITCODE -ne 0) { throw 'Static address update failed.' }
foreach ($prefix in @('192.168.56.0/24','192.168.60.0/24','192.168.70.0/24')) {
    $network = $prefix.Split('/')[0]
    & route.exe -p add $network mask 255.255.255.0 192.168.80.1 metric 10 if $nic[0].ifIndex
    if ($LASTEXITCODE -ne 0) { throw "Route update failed: $prefix" }
}
Stop-Transcript
shutdown.exe /s /t 15 /d p:0:0 /c 'Move core server to isolated lab server segment'
