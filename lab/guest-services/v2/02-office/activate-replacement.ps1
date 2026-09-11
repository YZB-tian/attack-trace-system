$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'WIN11-OFFICE'){throw 'Wrong guest'}
$result=[ordered]@{Utc=(Get-Date).ToUniversalTime().ToString('o'); Completed=$false}
try {
 $nic=@(Get-NetAdapter | Where-Object HardwareInterface)
 if($nic.Count -ne 1){throw 'Expected one NIC'}
 & netsh.exe interface ipv4 set address name=$($nic[0].Name) source=dhcp
 if($LASTEXITCODE){throw 'DHCP configuration failed'}
 Set-DnsClientServerAddress -InterfaceIndex $nic[0].ifIndex -ResetServerAddresses
 Start-Sleep -Seconds 15
 $result.Addresses=@(Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,InterfaceAlias)
 $p=Start-Process -FilePath "$env:SystemRoot\System32\cscript.exe" -ArgumentList '//nologo C:\Windows\System32\slmgr.vbs /ato' -WindowStyle Hidden -PassThru -RedirectStandardOutput 'C:\Windows\Temp\activation-output.txt' -RedirectStandardError 'C:\Windows\Temp\activation-error.txt'
 if(-not $p.WaitForExit(90000)){$p.Kill(); throw 'Activation timed out'}
 $result.ExitCode=$p.ExitCode
 $result.Output=[string](Get-Content 'C:\Windows\Temp\activation-output.txt' -Raw)
 $result.Products=@(Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' -and $_.PartialProductKey} | Select-Object Name,LicenseStatus,GracePeriodRemaining,EvaluationEndDate)
 $result.Completed=$true
} catch {$result.Error=$_.Exception.Message}
finally {
 if($nic){$nic | Disable-NetAdapter -Confirm:$false}
 $result | ConvertTo-Json -Depth 5 | Set-Content 'C:\Windows\Temp\activation-result.json' -Encoding UTF8
}
