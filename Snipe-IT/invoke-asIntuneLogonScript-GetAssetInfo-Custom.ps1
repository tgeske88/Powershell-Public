#Module name:      Invoke-asIntuneLogonScript
#Author:           Jos Lieben
#Author Blog:      http://www.lieben.nu
#Date:             11-06-2019
#Purpose:          Using this code in ANY Intune script 
#Requirements:     Windows 10 build 1803 or higher
#License:          Free to use and modify non-commercially, leave headers intact. For commercial use, contact me
#Thanks to:
#@michael_mardahl for the idea to remove the script from the registry so it automatically reruns
#@Justin Murray for a .NET example of how to impersonate a logged in user

$autoRerunMinutes = 60 #If set to 0, only runs at logon, else, runs every X minutes AND at logon, expect random delays of up to 5 minutes due to bandwidth, service availability, local resources etc. I strongly recommend 0 or >60 as input value to avoid being throttled
$visibleToUser = $False

#Uncomment for debug logs:
#Start-Transcript -Path (Join-Path $Env:temp -ChildPath "intuneRestarter.log") -Append -Confirm:$False
if($Env:USERPROFILE.EndsWith("system32\config\systemprofile")){
    $runningAsSystem = $True
    Write-Output "Running as SYSTEM"
}else{
    $runningAsSystem = $False
    Write-Output "Running as $($env:USERNAME)"
}

$source=@"
using System;
using System.Runtime.InteropServices;

namespace murrayju
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken, int targetSessionId)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive && si.SessionID == targetSessionId)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static PROCESS_INFORMATION StartProcessAsCurrentUser(int targetSessionId, string appPath, string cmdLine = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var procInfoRes = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                if (!GetSessionUserToken(ref hUserToken, targetSessionId))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken for session "+targetSessionId+" failed.");
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    null, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code " + iResultOfCreateProcessAsUser);
                }
                procInfoRes = procInfo;
                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return procInfoRes;
        }

    }
}
"@

$scriptPath = $PSCommandPath

if($runningAsSystem){
    Write-Output "Running in system context, script should be running in user context, we should auto impersonate"
    #Generate registry removal path
    $regPath = "HKLM:\Software\Microsoft\IntuneManagementExtension\Policies\$($scriptPath.Substring($scriptPath.LastIndexOf("_")-36,36))\$($scriptPath.Substring($scriptPath.LastIndexOf("_")+1,36))"
    
    #get targeted user session ID from intune management log as there is no easy way to translate the user Azure AD to the local user
    $logLocation = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    $targetUserSessionId = (Select-String -Pattern "$($scriptPath.Substring($scriptPath.LastIndexOf("_")-36,36)) in session (\d+)]" $logLocation | Select-Object -Last 1).Matches[0].Groups[1].Value

    $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $compilerParameters.CompilerOptions="/unsafe"
    $compilerParameters.GenerateInMemory = $True
    Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters
    
    if($visibleToUser){
        $res = [murrayju.ProcessExtensions]::StartProcessAsCurrentUser($targetUserSessionId, "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe", " -WindowStyle Normal -nologo -executionpolicy ByPass -Command `"& '$scriptPath'`"",$True)
    }else{
        $res = [murrayju.ProcessExtensions]::StartProcessAsCurrentUser($targetUserSessionId, "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe", " -WindowStyle Hidden -nologo -executionpolicy ByPass -Command `"& '$scriptPath'`"",$False)
    }
    
    Sleep -s 1

    #get new process info, we could use this in a future version to await completion
    $process = Get-WmiObject Win32_Process -Filter "name = 'powershell.exe'" | where {$_.CommandLine -like "*$scriptPath*"}

    #start a seperate process as SYSTEM to monitor for user logoff/logon and preferred scheduled reruns
    start-process "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList "`$slept = 0;`$script:refreshNeeded = `$false;`$sysevent = [microsoft.win32.systemevents];Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionEnding`" -Action {`$script:refreshNeeded = `$true;};Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionEnded`"  -Action {`$script:refreshNeeded = `$true;};Register-ObjectEvent -InputObject `$sysevent -EventName `"SessionSwitch`"  -Action {`$script:refreshNeeded = `$true;};while(`$true){;`$slept += 0.2;if((`$slept -gt ($autoRerunMinutes*60) -and $autoRerunMinutes -ne 0) -or `$script:refreshNeeded){;`$slept=0;`$script:refreshNeeded=`$False;Remove-Item $regPath -Force -Confirm:`$False -ErrorAction SilentlyContinue;Restart-Service -Name IntuneManagementExtension -Force;Exit;};Start-Sleep -m 200;};"    
    
    #set removal key in case computer crashes or something like that
    [Array]$runOnceEntries = @(Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
    if(([Array]@($runOnceEntries.PSObject.Properties.Name | % {if($runOnceEntries.$_ -eq "reg delete $($regPath.Replace(':','')) /f"){$_}})).Count -le 0){
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $(Get-Random) -Value "reg delete $($regPath.Replace(':','')) /f" -PropertyType String -Force -ErrorAction SilentlyContinue
    }
    start-sleep -s 10
    Exit
}

##YOUR CODE HERE
$s = $Env:Computername
#Don't do a trailing slash or your socks will start to smell funny.

$WorkStationShare = "C:\wlttemp\Hardware\Workstations"
$MonitorShare = "C:\wlttemp\Hardware\Monitors"

$WShareName = "$WorkStationShare\$s.csv"
$MShareName = "$MonitorShare\$s.csv"

$dir = "C:\wlttemp\Hardware\Workstations"
if(!(Test-Path -Path $dir )){
    New-Item -ItemType directory -Path $dir
    Write-Host "New folder created"
}
else
{
  Write-Host "Folder already exists"
}

$dir = "C:\wlttemp\Hardware\Monitors"
if(!(Test-Path -Path $dir )){
    New-Item -ItemType directory -Path $dir
    Write-Host "New folder created"
}
else
{
  Write-Host "Folder already exists"
}


#New-Item -Path 'C:\wlttemp\Hardware\Workstations' -ItemType Directory
#New-Item -Path 'C:\wlttemp\Hardware\Monitors' -ItemType Directory

Try { [io.file]::OpenWrite($WShareName).close() }
Catch { 
    Write-Warning "Unable to write to output file $WshareName" 
    return 1;
}

Try { [io.file]::OpenWrite($MShareName).close() }
Catch { 
    Write-Warning "Unable to write to output file $MshareName" 
    return 1;
}

$MonitorArray = @();

$LastUser = Get-CimInstance Win32_UserProfile -Filter 'Special=FALSE' | Sort-Object LastUseTime -Descending |
Select-Object -First 1 | ForEach-Object {
    ([System.Security.Principal.SecurityIdentifier]$_.SID).Translate([System.Security.Principal.NTAccount]).Value
}

$OSBuildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion

$CIMCS = Get-Ciminstance -class win32_ComputerSystem
$CPUInfo = $CIMcs.name
$MN = $CIMcs.Model

$OSInfo = Get-CIMinstance Win32_OperatingSystem
$OSInstallDate = $OSInfo.InstallDate

$CIMMemory = Get-CIMINStance CIM_PhysicalMemory
$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
$PhysicalMemory = [Math]::Round((($CIMMemory | Measure-Object -Property capacity -sum).sum / 1GB), 2)

$CIMBios = Get-Ciminstance Win32_BIOS
$SN = $CIMBios.serialnumber
$MF = $CIMBios.manufacturer

$CIMDisk = Get-Ciminstance Win32_logicalDisk
$DISKTOTAL = $CIMDisk | Where-Object caption -eq "C:" | foreach-object { Write-Output "$('{0:N2}' -f ($_.Size/1gb)) GB " }
$DISKFREE = $CIMDisk | Where-Object caption -eq "C:" | foreach-object { Write-Output "$('{0:N2}' -f ($_.FreeSpace/1gb)) GB " }
    
$CIMNetwork = Get-CimInstance Win32_NetworkAdapter
$WifiMac = $CIMNetwork | Where-Object { $_.Name -match ("Wireless|wifi|wi\-fi") -and ($_.name -notlike "*virtual*") } | 
Select-object -ExpandProperty MacAddress
    
$CIMNetCfg = Get-Ciminstance Win32_NetworkAdapterConfiguration    
$MAC = $CIMNetCfg | Where-Object { $_.ipenabled -EQ $true } | select-object -first 1 -ExpandProperty MacAddress

#$CIMMonitors = Get-WMIObject WmiMonitorID -Namespace root\wmi

$CIMChassis = Get-CimInstance Win32_SystemEnclosure | Select-object -ExpandProperty ChassisTypes

$BuiltInChassis = @("8","9","10","11","13","14")
if (($CIMChassis -in $BuiltInChassis) -and ($CIMMonitors.count -le 1)) {$BuiltInOnly = $true }

## Really hacky check to ensure I don't pull in thousands of built-in displays from laptops. 

if (-not($BuiltInOnly)) {
    ForEach ($Monitor in $CIMMonitors) {
        $monitorData = @();
        $Manufacturer = ($Monitor.ManufacturerName -ne 0 | ForEach-Object { [char]$_ }) -join ""
        if ($monitor.UserFriendlyName) { 
            $Name = ($Monitor.UserFriendlyName -ne 0 | ForEach-Object { [char]$_ }) -join "" 
        }
        else {
            $Name = ($Monitor.ProductCodeID -ne 0 | ForEach-Object { [char]$_ }) -join ""
        }

        #Do some voodoo to clean up Lenovo Monitor names and take out the Manufacturer code
        if ($Name -like "LEN *") {
            $Name = $name.split(' ')[1]
        }


        #If you need to beef up this list, start here: https://github.com/MaxAnderson95/Get-Monitor-Information/blob/master/Get-Monitor.ps1
        #If you need more beef:  go here : http://edid.tv/manufacturer/

        $Serial = ($Monitor.SerialNumberID -ne 0 | ForEach-Object { [char]$_ }) -join ""
        
        switch ($Manufacturer) {
            'LEN' { $Make = "Lenovo" }
            'ACI' { $Make = "ASUS" }
            'LGD' { $Make = "LG" }
            'SDC' { $Make = "Surface Display" }
            'SEC' { $Make = "Epson" }
            'SAM' { $Make = "Samsung" }
            'SNY' { $Make = "Sony" }
            'GSM' { $Make = "LG (Goldstar) TV" }
            'GWY' { $Make = "Gateway 2000" }
            'ITE' { $Make = "Integrated Tech Express" }
			'VSC' { $Make = "ViewSonic" }
			'ACR' { $Make = "Acer" }
            
            default { $Make = "Unknown: $Manufacturer" }
        }
     
        $Friendly = "[$make] ${name}: $serial"   

        $MonitorData = [PSCustomObject] @{
            Vendor        = $Make
            Model         = $Name
            Serial        = $Serial
            Friendly      = $Friendly
            'Last Seen'   = $(Get-Date)
            'Attached To' = $s
        } 
        $MonitorArray += $MonitorData
    }
}


switch ($CIMChassis) {
    ## https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
    ## Chassis types liberated from this PDF
    
    "1"	{ $Chassis = "Other" }
    "2"	{ $Chassis = "Unknown" }
    "3"	{ $Chassis = "Desktop" }
    "4"	{ $Chassis = "Low Profile Desktop" }
    "5"	{ $Chassis = "Pizza Box" }
    "6"	{ $Chassis = "Mini Tower" }
    "7"	{ $Chassis = "Tower" }
    "8"	{ $Chassis = "Portable" }
    "9"	{ $Chassis = "Laptop" }
    "10"	{ $Chassis = "Notebook" }
    "11"	{ $Chassis = "Hand Held" }
    "12"	{ $Chassis = "Docking Station" }
    "13"	{ $Chassis = "All in One" }
    "14"	{ $Chassis = "Sub Notebook" }
    "15"	{ $Chassis = "Space-saving" }
    "16"	{ $Chassis = "Lunch Box" }
    "17"	{ $Chassis = "Main Server Chassis" }
    "18"	{ $Chassis = "Expansion Chassis" }
    "19"	{ $Chassis = "SubChassis" }
    "20"	{ $Chassis = "Bus Expansion Chassis" }
    "21"	{ $Chassis = "Peripheral Chassis" }
    "22"	{ $Chassis = "RAID Chassis" }
    "23"	{ $Chassis = "Rack Mount Chassis" }
    "24"	{ $Chassis = "Sealed-case PC" }
    "25"	{ $Chassis = "Multi-system chassis" }
    "26"	{ $Chassis = "Compact PCI" }
    "27"	{ $Chassis = "Advanced TCA" }
    "28"	{ $Chassis = "Blade" }
    "29"	{ $Chassis = "Blade Enclosure" }
    "30"	{ $Chassis = "Tablet" }
    "31"	{ $Chassis = "Convertible" }
    "32"	{ $Chassis = "Detachable" }
    "33"	{ $Chassis = "ioT Gateway" }
    "34"	{ $Chassis = "Embedded PC" }
    "35"	{ $Chassis = "Mini PC" }
    "36"	{ $Chassis = "Stick PC" }
    default { $Chassis = "Invalid Chassis Type" }
}


$MonitorFriendly = $MonitorArray.Friendly -join ', '

$AT = $s
$status = "Ready to Deploy"

$IP = (Test-Connection $CPUInfo -count 1).IPv4Address.IPAddressToString

Foreach ($CPU in $CPUInfo) {
    $infoObject = [PSCustomObject][ordered]@{
        #The following add data to the infoObjects.	
        "item Name"                   	= $CPUInfo
        "Asset Tag"                    	= $AT
        "Model Number"           	= $MN
		"Model Name"           		= $MN
        "Manufacturer"           	= $MF
        "Serial Number"          	= $SN

        "Status"             		= $status
        "Inventory: Timestamp"          = $(Get-Date)
        "Inventory: Chassis"            = $Chassis

        "OS: Name"                      = $OSInfo.Caption
        "OS: Install Date"              = $OSInstallDate
        "OS: Last User"                 = $lastuser
		"OS: Build Number"              = $OSBuildNumber

        "Sub-Assets: Monitors"          = $MonitorFriendly

        "Specs: Physical RAM"           = $PhysicalMemory
        "Specs: Virtual Memory"         = $OSTotalVirtualMemory
        "Specs: Visible Memory"         = $OSTotalVisibleMemory
        "Specs: Total Disk Space"       = $DISKTOTAL
        "Specs: Free Disk Space"        = $DISKFREE

        "Network: IP Address"           = $IP
        "Network: Wireless MAC Address" = $WifiMAC
        "Network: Ethernet MAC Address" = $MAC
    }


}

$infoObject | Export-Csv -Path $WshareName -NoClobber -NoTypeInformation -Encoding UTF8 -Append -Force
$MonitorArray | Select-Object Vendor, Model, Serial, 'Last Seen', 'Attached To' | Export-Csv -Path $MShareName -NoTypeInformation -Encoding UTF8 -Force
##END OF YOUR CODE
Throw "Bye" #final line needed so intune will not stop rerunning the script
