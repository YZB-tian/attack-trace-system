$ErrorActionPreference='Stop'
$result=[ordered]@{Utc=(Get-Date).ToUniversalTime().ToString('o')}
$result.Products=@(Get-CimInstance SoftwareLicensingProduct | Where-Object {$_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' -and $_.PartialProductKey} | Select-Object Name,Description,LicenseStatus,GracePeriodRemaining,EvaluationEndDate)
$result.Service=Get-CimInstance SoftwareLicensingService | Select-Object RemainingWindowsReArmCount
$result | ConvertTo-Json -Depth 4 | Set-Content C:\Windows\Temp\license-status.json -Encoding UTF8
