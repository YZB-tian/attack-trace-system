$ErrorActionPreference = 'Stop'
Start-Transcript 'C:\Windows\Temp\office-zone-result.txt'
$nic = @(Get-NetAdapter | Where-Object MacAddress -eq '00-0C-29-49-78-EE')
if ($nic.Count -ne 1) { throw 'Expected office adapter not found uniquely.' }
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceIndex,IPAddress,PrefixLength
Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix,NextHop
$old = @(Get-NetIPAddress -InterfaceIndex $nic[0].ifIndex -AddressFamily IPv4)
if (@($old | Where-Object IPAddress -eq '192.168.56.20').Count -ne 1) { throw 'Unexpected address. No change made.' }
& netsh.exe interface ipv4 set address name=$($nic[0].Name) source=static address=192.168.70.20 mask=255.255.255.0 gateway=none
if ($LASTEXITCODE -ne 0) { throw 'Address update failed.' }
foreach ($network in @('192.168.56.0','192.168.60.0','192.168.80.0')) {
    & route.exe -p add $network mask 255.255.255.0 192.168.70.1 metric 10 if $nic[0].ifIndex
    if ($LASTEXITCODE -ne 0) { throw "Route update failed: $network" }
}
Get-Date -Format o
Get-NetIPAddress -AddressFamily IPv4 | Format-Table IPAddress,PrefixLength,AddressState
Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix,NextHop
Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore | Format-Table DestinationPrefix,NextHop
ping.exe -n 3 -w 1000 192.168.70.1
Get-NetNeighbor -AddressFamily IPv4 | Format-Table IPAddress,LinkLayerAddress,State
Get-Service WinRM,VMTools | Format-Table Name,Status
Stop-Transcript
