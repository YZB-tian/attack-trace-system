& pktmon.exe status 2>&1 | Out-File 'C:\Windows\Temp\packet-capture-help.txt'
& pktmon.exe start help 2>&1 | Out-File 'C:\Windows\Temp\packet-capture-help.txt' -Append
