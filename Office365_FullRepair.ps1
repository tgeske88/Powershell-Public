$command64 = @' 
cmd.exe /C "C:\Program Files\Microsoft Office 15\ClientX64\OfficeClickToRun.exe" scenario=Repair platform=x64 culture=en-us RepairType=FullRepair forceappshutdown=True DisplayLevel=False
'@

$command86 = @' 
cmd.exe /C "C:\Program Files\Microsoft Office 15\ClientX86\OfficeClickToRun.exe" scenario=Repair platform=x86 culture=en-us RepairType=FullRepair forceappshutdown=True DisplayLevel=False
'@

if(Test-Path -Path "C:\Program Files\Microsoft Office 15\ClientX64\OfficeClickToRun.exe"){
    Invoke-Expression -Command:$command64
} elseif(Test-PAth -Path "C:\Program Files\Microsoft Office 15\ClientX32\OfficeClickToRun.exe"){
    Invoke-Expression -Command:$command86
}