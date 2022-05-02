$Trigger = New-ScheduledTaskTrigger -At 11:01am -Weekly -DaysOfWeek Wednesday
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Action = New-ScheduledTaskAction -Execute "C:\Windows\System32\Dism.exe" -Argument "/Online /Cleanup-Image /CheckHealth"
Set-ExecutionPolicy Bypass -Scope Process -Force; Register-ScheduledTask -TaskName "WLT Wednesday DISM CheckHealth" -Trigger $Trigger -Principal $Principal -Action $Action -Description "Runs DISM /CheckHealth on Watermark Lodging Trust owned hardware every Wednesday afternoon at 11:01am"