$ErrorActionPreference = 'Stop'
$report = [ordered]@{
    Time = (Get-Date).ToUniversalTime().ToString('o')
    Adapters = @(Get-NetAdapter | Select-Object Name, InterfaceIndex, Status, MacAddress)
    Addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex, IPAddress, PrefixLength)
    Routes = @(Get-NetRoute -AddressFamily IPv4 | Select-Object InterfaceIndex, DestinationPrefix, NextHop)
    Shares = @(Get-SmbShare | Select-Object Name, Path)
    Sessions = @(Get-SmbSession | Select-Object ClientComputerName, NumOpens)
    Services = @(Get-Service LanmanServer, WinRM, VMTools | Select-Object Name, Status)
}
$report | ConvertTo-Json -Depth 5 | Set-Content 'C:\Windows\Temp\core-inspection.json' -Encoding UTF8
