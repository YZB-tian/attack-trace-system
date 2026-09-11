param([Parameter(Mandatory=$true)][string]$LabPassword)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{TimeUtc=(Get-Date).ToUniversalTime().ToString('o')}
$result.Addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength,AddressState)
$result.Routes = @(Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop)
$result.GatewayPing = @(Test-Connection 192.168.70.1 -Count 3 -ErrorAction SilentlyContinue | Select-Object Address,ResponseTime,StatusCode)
$result.Ports = @()
foreach ($port in @(445,3389)) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync('192.168.80.60',$port)
        $connected = $task.Wait(3000) -and $client.Connected
        $result.Ports += [pscustomobject]@{Port=$port;Connected=$connected}
    } catch {
        $result.Ports += [pscustomobject]@{Port=$port;Connected=$false;Error=$_.Exception.Message}
    } finally { $client.Dispose() }
}
$result.SmbRead = $false
try {
    $credential = New-Object System.Management.Automation.PSCredential('CORE01\Administrator',(ConvertTo-SecureString $LabPassword -AsPlainText -Force))
    New-PSDrive -Name LABVERIFY -PSProvider FileSystem -Root '\\192.168.80.60\CORE-DATA' -Credential $credential -Scope Script | Out-Null
    $result.FileContent = (Get-Content 'LABVERIFY:\finance-planning.txt' -Raw).ToString()
    $result.SmbRead = $true
} catch { $result.SmbError = $_.Exception.Message }
finally { Remove-PSDrive LABVERIFY -ErrorAction SilentlyContinue }
$result.Neighbors = @(Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State)
$result | ConvertTo-Json -Depth 6 | Set-Content 'C:\Windows\Temp\office-core-check-compact.json' -Encoding UTF8
