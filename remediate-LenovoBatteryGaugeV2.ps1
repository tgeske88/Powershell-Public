# Remediation
Powershell.exe -Command Set-ExecutionPolicy Bypass -Scope Process -Force;
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\WLTtemp3"
mkdir C:\WLTtemp3
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/tgeske88/LenovoBatteryGauge/main/BGTestNew.exe', 'C:\WLTtemp3\BGTestNew.exe')"
C:\WLTtemp3\BGTestNew.exe -o"C:\WLTtemp3\LenovoBatteryGauge" -y
ping 8.8.8.8
Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File C:\WLTtemp3\LenovoBatteryGauge\BGTestNew\BGT.ps1' -Verb RunAs
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
ping 8.8.8.8
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\WLTtemp3"