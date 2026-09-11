param([string]$OfficeVmx='D:\AttackTraceLab\VMs-v2\02-Windows11-Office\02-Windows11-Office.vmx')
$ErrorActionPreference='Stop'
$v='D:\Software\VMware\vmrun.exe'
$base='D:\AttackTraceLab\guest-services\v2'
$run='course-'+(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$out=Join-Path 'D:\AttackTraceLab\evidence' $run
New-Item -ItemType Directory -Path $out | Out-Null
function Vmrun([string[]]$Arguments){
    & $v @Arguments
    if($LASTEXITCODE -ne 0){throw 'VMware guest operation failed'}
}
$web='D:\AttackTraceLab\VMs-v2\03-Ubuntu-Web\03-Ubuntu-Web.vmx'
$kali='D:\AttackTraceLab\VMs\01-Kali-Attacker\01-Kali-Attacker.vmx'
$office=$OfficeVmx
@{run_id=$run;classification='controlled_emulation';output=$out;started_utc=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $out 'manifest.json')
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','copyFileFromHostToGuest',$kali,(Join-Path $base 'course-kali-exercise.py'),'/tmp/course-kali-exercise.py')
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','runScriptInGuest',$kali,'/bin/sh',"python3 /tmp/course-kali-exercise.py $run > /tmp/$run-kali-result.txt 2>&1")
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','copyFileFromGuestToHost',$kali,"/tmp/$run-kali.json",(Join-Path $out 'kali-login.json'))
Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','copyFileFromHostToGuest',$web,(Join-Path $base 'course-web-exercise.py'),'/tmp/course-web-exercise.py')
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','copyFileFromHostToGuest',$kali,(Join-Path $base 'course-ssh-exercise.py'),'/tmp/course-ssh-exercise.py')
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','copyFileFromHostToGuest',$kali,'D:\AttackTraceLab\evidence\web-ssh-host-key.pub','/tmp/course-web-host-key.pub')
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','runScriptInGuest',$kali,'/bin/sh',"python3 /tmp/course-ssh-exercise.py $run > /tmp/$run-ssh-result.txt 2>&1")
Vmrun @('-gu','kali','-gp','__KALI_PASSWORD__','copyFileFromGuestToHost',$kali,"/tmp/$run-ssh.json",(Join-Path $out 'kali-ssh.json'))
foreach($pair in @(@("/tmp/$run/timeline.json",'web-timeline.json'),@("/tmp/$run-web.strace",'web-syscalls.strace'),@('/var/log/attacktrace/web-events.jsonl','web-events.jsonl'))){
 Vmrun @('-gu','labadmin','-gp','__LAB_PASSWORD__','copyFileFromGuestToHost',$web,$pair[0],(Join-Path $out $pair[1]))
}
Vmrun @('-gu','LabAdmin','-gp','__LAB_PASSWORD__','copyFileFromHostToGuest',$office,(Join-Path $base 'course-office-exercise.ps1'),'C:\Windows\Temp\course-office-exercise.ps1')
Vmrun @('-gu','LabAdmin','-gp','__LAB_PASSWORD__','runProgramInGuest',$office,'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Windows\Temp\course-office-exercise.ps1','-RunId',$run,'-LabPassword','__LAB_PASSWORD__')
foreach($file in @('timeline.json','security.evtx','powershell.evtx')){
 Vmrun @('-gu','LabAdmin','-gp','__LAB_PASSWORD__','copyFileFromGuestToHost',$office,"C:\AttackTraceLab\$run\$file",(Join-Path $out ('office-'+$file)))
}
Write-Output $out
