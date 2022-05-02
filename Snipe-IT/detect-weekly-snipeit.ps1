# Define Variables
$taskName,$taskExists,$curTskStat,$errMsg = "","",""

# Main script

$taskName = "WLT Wednesday Snipe-IT Asset Information"
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }

if(-not ($taskExists)) {
       Write-Host "WLT Wednesday Snipe-IT Asset Information"
	exit 1  
} 
if ($taskExists) {
       Write-Host "WLT Wednesday Snipe-IT Asset Information"
	exit 0  
}
Catch {
    Write-Warning "Not Compliant"
    Exit 1
}