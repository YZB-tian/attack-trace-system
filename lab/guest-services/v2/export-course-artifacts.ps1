param([Parameter(Mandatory=$true)][ValidatePattern('^course-[0-9TZ]+$')][string]$RunId)
$ErrorActionPreference='Stop'
$v='D:\Software\VMware\vmrun.exe'
$out=Join-Path 'D:\AttackTraceLab\evidence' $RunId
if(-not(Test-Path -LiteralPath (Join-Path $out 'manifest.json'))){throw 'Unknown run'}
foreach($file in @('web-network.pcap','office-network.pcap','c2-events.jsonl','smtp-events.jsonl','core-security.evtx','firewall-live-raw.json')){
 if(Test-Path -LiteralPath (Join-Path $out $file)){throw ('Existing evidence preserved; use a new experiment run: '+$file)}
}
function Vmrun([string[]]$Arguments){
 & $v @Arguments
 if($LASTEXITCODE -ne 0){throw 'Evidence operation failed'}
}
foreach($n in @(
 @{Node='03-Ubuntu-Web';Service='attacktrace-node-capture';Source='/var/log/attacktrace/node-pcap/capture.pcap0';Name='web-network'},
 @{Node='08-Ubuntu-Sensor';Service='attacktrace-office-capture';Source='/var/log/attacktrace/office-pcap/capture.pcap0';Name='office-network'})){
 $vm='D:\AttackTraceLab\VMs-v2\'+$n.Node+'\'+$n.Node+'.vmx'
 $guest='/tmp/'+$RunId+'-'+$n.Name+'.pcap'
 $cmd='printf "%s\n" "__LAB_PASSWORD__" | sudo -S /bin/sh -c "set -e; systemctl stop '+$n.Service+'; trap ''systemctl start '+$n.Service+''' EXIT; cp '+$n.Source+' '+$guest+'; chmod 644 '+$guest+'"'
 Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','runScriptInGuest',$vm,'/bin/sh',$cmd)
 Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','copyFileFromGuestToHost',$vm,$guest,(Join-Path $out ($n.Name+'.pcap')))
}
foreach($n in @(@{Node='04-Ubuntu-C2-Sim';Log='c2-events.jsonl'},@{Node='05-Ubuntu-Mail';Log='smtp-events.jsonl'})){
 $vm='D:\AttackTraceLab\VMs-v2\'+$n.Node+'\'+$n.Node+'.vmx'
 $guest='/tmp/'+$RunId+'-'+$n.Log
 $cmd='printf "%s\n" "__LAB_PASSWORD__" | sudo -S cat /var/log/attacktrace/'+$n.Log+' > '+$guest
 Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','runScriptInGuest',$vm,'/bin/sh',$cmd)
 Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','copyFileFromGuestToHost',$vm,$guest,(Join-Path $out $n.Log))
}
$core='D:\AttackTraceLab\VMs-v2\06-WindowsServer-Core\06-WindowsServer-Core.vmx'
$guest="C:\Windows\Temp\$RunId-core.evtx"
Vmrun @('-gu','Administrator','-gp','__LAB_PASSWORD__','runProgramInGuest',$core,'C:\Windows\System32\wevtutil.exe','epl','Security',$guest,'/q:*[System[TimeCreated[timediff(@SystemTime) <= 900000]]]')
Vmrun @('-gu','Administrator','-gp','__LAB_PASSWORD__','copyFileFromGuestToHost',$core,$guest,(Join-Path $out 'core-security.evtx'))
foreach($name in @('office-security','core-security')){
 $rows=@(Get-WinEvent -Path (Join-Path $out ($name+'.evtx')) | Where-Object {$_.Id -in @(4624,4634,4663,4688,5140,5145)} | ForEach-Object {
  [xml]$x=$_.ToXml()
  $fields=@{}
  foreach($d in $x.Event.EventData.Data){$fields[[string]$d.Name]=[string]$d.'#text'}
  [pscustomobject]@{timestamp=$_.TimeCreated.ToUniversalTime().ToString('o');event_id=$_.Id;record_id=$_.RecordId;host=$_.MachineName;fields=$fields}
 })
 $rows | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $out ($name+'.json')) -Encoding UTF8
}
if($env:LAB_FW_PASSWORD){
 python (Join-Path $PSScriptRoot 'export-firewall-evidence.py') $out
 if($LASTEXITCODE -ne 0){throw 'Firewall export failed'}
}else{throw 'LAB_FW_PASSWORD is required to export firewall evidence'}
Write-Output $out
