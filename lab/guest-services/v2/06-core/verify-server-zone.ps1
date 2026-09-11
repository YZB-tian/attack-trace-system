$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\Windows\Temp\core-zone-verification.txt'
Get-Date -Format o
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceIndex,IPAddress,PrefixLength,AddressState
Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix,NextHop,InterfaceIndex
Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore | Format-Table DestinationPrefix,NextHop,InterfaceIndex
ping.exe -n 3 -w 1500 192.168.80.1
Get-NetNeighbor -AddressFamily IPv4 | Format-Table IPAddress,LinkLayerAddress,State
Get-Service LanmanServer,WinRM,VMTools | Format-Table Name,Status
Get-SmbShare -Name CORE-DATA | Format-Table Name,Path
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 445,3389,5985 | Format-Table LocalAddress,LocalPort
Get-Content 'C:\AttackTraceLab\core-data\finance-planning.txt'
Stop-Transcript
