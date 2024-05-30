echo "Hello World"
ping 8.8.8.8

whoami
echo "whoami"
# Get the current date and time
# $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
# Define the log file path
$logFile = "\\ioaktgtest\HWInventory\PingLog_@option.example_var@.txt"

# Get the username of the user who launched the script
$currentUserName = $env:USERNAME

# Function to log messages to the log file
function Log-Message {
    param (
        [string]$message
    )
    $logEntry = "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") - $currentUserName - $message"
    $logEntry | Out-File -Append -FilePath $logFile
}

# Main script starts here
try {
    # Ping 8.8.8.8 and capture the results
    $pingResult = Test-Connection -ComputerName 8.8.8.8 -Count 4

    # Log the ping results
    Log-Message "Ping to 8.8.8.8 successful!"
    Log-Message "Ping statistics:"
    Log-Message "    Packets: $($pingResult.Count)"
    Log-Message "    Minimum: $($pingResult.RoundtripTime | Measure-Object -Minimum).Minimum ms"
    Log-Message "    Maximum: $($pingResult.RoundtripTime | Measure-Object -Maximum).Maximum ms"
    Log-Message "    Average: $($pingResult.RoundtripTime | Measure-Object -Average).Average ms"

} catch {
    # If ping fails, log an error message
    Log-Message "Ping to 8.8.8.8 failed: $_"
}

# Display a message on the console
Write-Host "Ping complete. Check log file for details: $logFile"
