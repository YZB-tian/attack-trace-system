Start-Transcript 'C:\Windows\Temp\office-zone-check.txt'
Get-Date -Format o
Get-NetAdapter | Format-Table Name,Status,MacAddress
Get-NetIPAddress -AddressFamily IPv4 | Format-Table IPAddress,PrefixLength,AddressState
Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix,NextHop
ping.exe -n 3 -w 1000 192.168.70.1
Get-NetNeighbor -AddressFamily IPv4 | Format-Table IPAddress,LinkLayerAddress,State
Get-Service WinRM,VMTools | Format-Table Name,Status,StartType
Stop-Transcript
