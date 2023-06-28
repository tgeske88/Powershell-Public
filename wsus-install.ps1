$Session = New-Object -Com Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$SearchResult = $Searcher.Search("IsInstalled=0").Updates

try {
  # Download updates
  $Downloader = $Session.CreateUpdateDownloader()
  $Downloader.Updates = $SearchResult
  $Downloader.Download()

  # Install updates
  $Installer = $Session.CreateUpdateInstaller()
  $Installer.Updates = $SearchResult
  $InstallResult = $Installer.Install()

  # Check installation result
  if ($InstallResult.ResultCode -eq 2) {
    Write-Host "Updates installed successfully."
  } else {
    Write-Host "Failed to install updates."
  }
} catch {
  if ($_.Exception.HResult -eq -2145124330) {
    Write-Host "There is either an update in progress or there is a pending reboot blocking the install."
  } else {
    Write-Host "There was an error trying to install an update."
  }
  Continue
}
