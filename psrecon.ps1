#requires -version 2.0

  #==========================================#
  # LogRhythm Labs                           #
  # Incident Response Live Data Acquisition  #
  # greg . foss @ logrhythm . com            #
  # v0.2  --  October, 2015                  #
  #==========================================#

# Copyright 2015 LogRhythm Inc.   
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.

#=======================================================================================
# CONFIGURATION
#=======================================================================================

[CmdLetBinding()]
param( 
    [switch]$remote = $false,
    [switch]$email = $false,
    [switch]$share = $false,
    [switch]$sendEmail = $false,
    [switch]$lockdown = $false,
    [switch]$adLock = $false,
    [string]$target,
    [string]$username,
    [string]$password,
    [string]$netShare,
    [string]$smtpServer,
    [string]$emailFrom,
    [string]$emailTo,
    [string]$companyName
)

#=======================================================================================
# PSRecon
#=======================================================================================

function Invoke-Recon {

$banner = @"
    ____  _____ ____                        
   / __ \/ ___// __ \___  _________  ____   
  / /_/ /\__ \/ /_/ / _ \/ ___/ __ \/ __ \  
 / ____/___/ / _, _/  __/ /__/ /_/ / / / /  
/_/    /____/_/ |_|\___/\___/\____/_/ /_/   
]]]]]]]]]]]]============>>>>>>>>>>-----+    
"@

<#
.NAME
PSRecon

.SYNOPSIS
PowerShell Incident Response -- Live Data Acquisition Tool

.DESCRIPTION
This tool pulls data from a target Windows Vista or later systems where there is suspicious of misuse and/or infection. This will extract useful forensic data that will assist IR teams in gathering quick live data on a potentially compromised host.

.NOTES
This tool is designed to be executed from a LogRhythm SmartResponse(TM) on remote hosts via the LogRhythm agent, remotely using the LogRhythm SIEM, or locally/remotely as a standalone PowerShell script.
The safest way to run this script is locally, however remote execution is possible. Realize this will open the system up to additional risk...

.EXAMPLE
    PS C:\> .\PSRecon.ps1
        Simply run PSRecon on the local host.
        This gathers default data and stores the results in the directory that the script was executed from.

.EXAMPLE
    PS C:\> .\PSRecon.ps1 -remote -target [computer] [arguments - EX: -sendEmail -share -username -password]
        Run PSRecon Remotely.
        This gathers default data and stores the results in the script directory.
        If you do not chose the [sendEmail] and/or [share] options all local evidence will be erased on the target.
    Caveats:
        You will need to ensure that psremoting and unsigned execution is enabled on the remote host.  // dangerous to leave enabled!
        Be careful, this may inadvertently expose administrative credentials when authenticating to a remote compromised host.

.EXAMPLE
    PS C:\> .\PSRecon.ps1 -sendEmail -smtpServer ["127.0.0.1"] -emailTo ["greg.foss[at]logrhythm.com"] -emailFrom ["psrecon[at]logrhythm.com"]
        [sendEmail] parameter allows the script to send the HTML report over SMTP.
        [smtpServer] parameter sets the remote SMTP Server that will be used to forward reports.
        [emailTo] parameter deifines the email recipient. Multiple recipients can be separated by commas.
        [emailFrom] parameter defines the email sender.

.EXAMPLE
    PS C:\> .\PSRecon.ps1 -share -netShare ["\\share\"] -Credential Get-Credential
        [share] parameter allows the script to push evidence to a remote share or send the HTML report over SMTP.
        [netShare] parameter defines the remote share. This should be manually tested with the credentials you will execute the script with.
            Make sure to restrict pemrissions to this location and audit all access related to the folder!

.EXAMPLE
    PS C:\> .\PSRecon.ps1 -lockdown -adLock [username]
        [lockdown] parameter quarantine's the workstation. This disables the NIC's, locks the host and logs the user out.
        [adLock] parameter disables the target username ID within Active Directory. A username must be provided...

.EXAMPLE
    PS C:\> .\PSRecon.ps1 -email
        [email] parameter extracts client email data (from / to / subject / email links).
        
.EXAMPLE
    PS C:\> .\PSRecon.ps1 -username ["admin user"] -password ["pass"]
        [username] parameter can be supplied on the command-line or hard-coded into the script.
        [password] parameter can be supplied on the command-line or hard-coded into the script. // Bad idea...
        These parameters are used when running PSRecon on remote hosts or interacting with Active Directory; not required for local execution.
        If neither parameter is supplied, you will be prompted for credentials // safest option aside from local execution

.EXAMPLE
    Remotely enable PSRemoting and Unrestricted PowerShell Execution then, run PSRecon.
    First, enable PSRemoting
        PS C:\> .\PsExec \\10.10.10.10 -u [admin account name] -p [admin account password] -h -d powershell.exe "Enable-PSRemoting -Force"
        PS C:\> Test-WSMan 10.10.10.10
        PS C:\> Enter-PSSession 10.10.10.10
        [10.10.10.10]: PS C:\> Set-ExecutionPolicy Unrestricted -Force
        [10.10.10.10]: PS C:\> Exit
        PS C:\> .\PSRecon.ps1 -remote -target "10.10.10.10" -sendEmail -smtpServer "127.0.0.1" -emailTo "greg.foss[at]logrhythm.com" -emailFrom "psrecon[at]logrhythm.com"
    
.OUTPUTS
    The script currently gathers the following data:
      -ARP Table
      -AT Jobs
      -Anti Virus Engine(s) installed
      -Capture Host Screenshot
      -Command History
      -DNS Cache
      -Environment Variables
      -Extract Internet Explorer history
      -Extract Email History and Links
      -Firewall Configuration
      -GPSresult
      -Hash Collected Evidence Files to Verify Authenticity
      -Host File Information
      -IP Address
      -Netstat Information
	  -Last File Created
      -List Open Shares
      -Local PowerShell Scripts
      -Logon Data
      -PowerShell Versioning
      -PowerShell Executable Hashes
      -Process Information
      -Prefetch Files
      -Remote Desktop Sessions
      -Running Services
      -Scheduled Processes
      -Scheduled Tasks
      -Service Details
      -Startup Information
      -Startup Drivers
      -USB Device History
      -User and Admin Information
      -Windows Patches
      -Windows Version Information
#>

#=======================================================================================
# Prepare to Capture Live Host Data
#=======================================================================================

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

# Check for Admin Rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host 'You must run PSRecon from an elevated PowerShell session...'
    Exit 1
}

# Enable Logging
New-EventLog -LogName Application -Source "PSRecon"
Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1337 -Message "Forensic Data Acquisition Initiated"

# Define the Drive
$PSReconDir = $(get-location).path
Set-Location -Path $PSReconDir -PassThru > $null 2>&1

# Create directories
function dirs {
    mkdir PSRecon\ > $null 2>&1
    mkdir PSRecon\config\ > $null 2>&1
    mkdir PSRecon\network\ > $null 2>&1
    mkdir PSRecon\process\ > $null 2>&1
    mkdir PSRecon\system\ > $null 2>&1
    mkdir PSRecon\web\ > $null 2>&1
    mkdir PSRecon\registry\ > $null 2>&1
}
$exists = "PSRecon_*\"
If (Test-Path $exists){
    Remove-Item PSRecon_*\ -Recurse -Force
    dirs
}Else{
    dirs
}

#=======================================================================================
# Evidence Collection
#=======================================================================================

# Get user and admin info
$whoami = $env:username
qwinsta > PSRecon\config\activeUsers.html
$activeUsersA = type PSRecon\config\activeUsers.html
$activeUsers = $activeUsersA | foreach {$_ + "<br />"}

# Set environmental variables
$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$computerName = (gi env:\Computername).Value
$userDirectory = (gi env:\userprofile).value
$user = (gi env:\USERNAME).value
$date = Get-Date -format D
$dateString = Get-Date -format MM-dd-yyyy
$dateTime = Get-Date -Format MM/dd/yyyy-H:mm:ss
if (-Not ($companyName)) {
    $companyName = "Proprietary / Confidential – Not For Disclosure"
} Else {
    $companyCheck = "^[a-zA-Z0-9\s+]+$"
    if (-not ($companyName -match $companyCheck)) {
        Write-Host 'Hey now...'
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34405 -Message "Possible Attack Detected via companyName parameter: $companyName"
        Exit 1
    }
    $companyName = "Proprietary / Confidential to $companyName – Not For Disclosure"
}

# Display banner and host data
$banner
Write-Host ""
Write-Host "$dateTime : Capturing Host Data : $computerName - $ip"

# Get IP Address Details
ipconfig -all | ConvertTo-Html -Fragment > PSRecon\config\ipconfig.html
$ipconfig = type PSRecon\config\ipconfig.html

# Gathering Scheduled Processes
at > PSRecon\process\at-jobs.html
$atA = get-content PSRecon\process\at-jobs.html
$at = $atA | foreach {$_ + "<br />"}

# Gathering list of Scheduled Tasks
$schtasks = Get-ScheduledTask | where state -EQ 'ready' | Get-ScheduledTaskInfo | Sort TaskPath |Select TaskName, TaskPath | ConvertTo-Html -Fragment

# Extract Installed Hotfix 
$hotfix = get-hotfix | Where-Object {$_.Description -ne ''} | select Description,HotFixID,InstalledBy | ConvertTo-Html -Fragment

# Gathering Process Information
$taskDetail = tasklist /V /FO CSV | ConvertFrom-Csv | ConvertTo-Html -Fragment

# Gather Windows Service Data
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartName, StartMode, State, TotalSessions, Description > PSRecon\process\service-detail.html
$serviceDetailA = get-content PSRecon\process\service-detail.html
$serviceDetail = $serviceDetailA | foreach {$_ + "<br />"}

# DNS Cache
$dnsCache = Get-DnsClientCache -Status 'Success' | Select Name, Data | ConvertTo-Html -Fragment

# Netstat information
$netstat = netstat -ant | select -skip 4 | ConvertFrom-String -PropertyNames none, proto,ipsrc,ipdst,state,state2,none,none | select ipsrc,ipdst,state | ConvertTo-Html -Fragment

# Display Listening Processes
$listeningProcesses = netstat -ano | findstr -i listening | ForEach-Object { $_ -split "\s+|\t+" } | findstr /r "^[1-9+]*$" | sort | unique | ForEach-Object { Get-Process -Id $_ } | Select ProcessName,Path,Company,Description | ConvertTo-Html -Fragment > PSRecon\network\net-processes.html

# ARP table
$arp = arp -a | select -skip 3 | ConvertFrom-String -PropertyNames none,IP,MAC,Type | Select IP,MAC,Type | ConvertTo-Html -Fragment

# Gathering information about running services
$netServices = Get-Service | where-object {$_.Status -eq "Running"} | Select Name, DisplayName | ConvertTo-Html -fragment

#Gathering information about open shares
net user > PSRecon\system\netuser.html
net use > PSRecon\network\shares.html
$netUserA = get-content PSRecon\system\netuser.html
$netUser = $netUserA | foreach {$_ + "<br />"}
$sharesA = get-content PSRecon\network\shares.html
$shares = $sharesA | foreach {$_ + "<br />"}

# Gathering host file information
$hosts = Import-Csv $env:windir\system32\drivers\etc\hosts | ConvertTo-Html -Fragment
$networks = Import-Csv $env:windir\system32\drivers\etc\networks | ConvertTo-Html -Fragment

# Gather Currently Installed Software
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -Fragment > PSRecon\process\software.html

# List Recently Used USB Devices
$usb = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName | ConvertTo-Html -Fragment > PSRecon\system\usb.html

# Gather command history
$commandHist = Get-History | ConvertTo-Html -Fragment

# Dumping the firewall information
echo "Firewall State" > PSRecon\system\firewall-config.html
netsh firewall show state >> PSRecon\system\firewall-config.html
echo "Firewall Config" >> PSRecon\system\firewall-config.html
netsh firewall show config >> PSRecon\system\firewall-config.html
echo "Firewall Dump" >> PSRecon\system\firewall-config.html
netsh dump >> PSRecon\system\firewall-config.html
$firewallA = get-content PSRecon\system\firewall-config.html
$firewall = $firewallA | foreach {$_ + "<br />"}
$firewall > PSRecon\system\firewall-config.html

# Saving the Environment
$set = Get-ChildItem ENV: | Select Name, Value | ConvertTo-Html -Fragment

# Return GPResult Output
& $env:windir\system32\gpresult.exe /v > PSRecon\system\gpresult.html
$gpresultA = get-content PSRecon\system\gpresult.html
$gpresult = $gpresultA | foreach {$_ + "<br />"}

# Get active SMB sessions
Get-SmbSession > PSRecon\network\smbsessions.html
$smbSessionA = get-content PSRecon\network\smbsessions.html
$smbSession = $smbSessionS | foreach {$_ + "<br />"}

# Get ACL's
$acl = Get-Acl | Select AccessToString, Owner, Group, Sddl | ConvertTo-Html -Fragment

# Gathering Windows version information
$version = [Environment]::OSVersion | ConvertTo-Html -Fragment

# Dumping the startup information
type $env:SystemDrive\autoexec.bat > PSRecon\system\autoexecBat.html 2>&1
type $env:SystemDrive\config.sys > PSRecon\system\configSys.html 2>&1
type $env:windir\win.ini > PSRecon\system\winIni.html 2>&1
type $env:windir\system.ini > PSRecon\system\systemIni.html 2>&1
$autoexecA = get-content PSRecon\system\autoexecBat.html
$autoexec = $autoexecA | foreach {$_ + "<br />"}
$configSysA = get-content PSRecon\system\configSys.html
$configSys = $ConfigSysA | foreach {$_ + "<br />"}
$winIniA = get-content PSRecon\system\winIni.html
$winIni = $winIniA | foreach {$_ + "<br />"}
$systemIniA = get-content PSRecon\system\systemIni.html
$systemIni = $systemIniA | foreach {$_ + "<br />"}

$psversiontable > PSRecon\config\powershell-version.html
$powershellVersionA = type PSRecon\config\powershell-version.html
$powershellVersion = $powershellVersionA | foreach {$_ + "<br />"}

# Startup Drivers
# Thanks Mark Vankempen!
$startupDrivers = reg query hklm\system\currentcontrolset\services /s | Select-String -pattern "^\s*?ImagePath.*?\.sys$"
$shadyDrivers = $startupDrivers | Select-String -pattern "^\s*?ImagePath.*?(user|temp).*?\\.*?\.(sys|exe)$"
$startupDrivers = $startupDrivers | ConvertTo-Html -Fragment
$shadyDrivers = $shadyDrivers | ConvertTo-Html -Fragment
$startupDrivers > PSRecon\registry\startup-drivers.html

# Registry: Run
$hklmRun = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Html -as List -Fragment
$hkcuRun = Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Html -as List -Fragment

# Antivirus
$antiVirus = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | ConvertTo-Html -as List -Fragment 

# list downloaded files
$downloads = dir C:\Users\*\Downloads\* -Recurse | Select Name, CreationTime, LastAccessTime, Attributes | ConvertTo-Html -Fragment > PSRecon\web\downloads.html

# Extract Prefetch File Listing
# script stolen from:
#     https://github.com/davehull/Kansa/blob/master/Modules/Process/Get-PrefetchListing.ps1
$pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 
Switch -Regex ($pfconf) {
    "[1-3]" {
        $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
        ls $env:windir\Prefetch\*.pf | % {
            $o.FullName = $_.FullName;
            $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
            $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
            $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
            $o
        } | ConvertTo-Html -Fragment >> PSRecon\process\prefetch.html
    }
    default {
        echo "" >> PSRecon\process\prefetch.html
        echo "Prefetch not enabled on ${env:COMPUTERNAME}" >> PSRecon\process\prefetch.html
        echo "" >> PSRecon\process\prefetch.html
    }
}
$prefetch = type PSRecon\process\prefetch.html

# Extract Internet Explorer History
# script stolen from:
#      https://richardspowershellblog.wordpress.com/2011/06/29/ie-history-to-csv/
function get-iehistory {
[CmdletBinding()]
param ()
$shell = New-Object -ComObject Shell.Application
$hist = $shell.NameSpace(34)
$folder = $hist.Self
$hist.Items() | 
foreach {
 if ($_.IsFolder) {
   $siteFolder = $_.GetFolder
   $siteFolder.Items() | 
   foreach {
     $site = $_
     if ($site.IsFolder) {
        $pageFolder  = $site.GetFolder
        $pageFolder.Items() | 
        foreach {
           $visit = New-Object -TypeName PSObject -Property @{
               Site = $($site.Name)
               URL = $($pageFolder.GetDetailsOf($_,0))
               Date = $( $pageFolder.GetDetailsOf($_,2))
           }
           $visit
        }
     }
   }
 }
}
}
get-iehistory | select Date, URL | ConvertTo-Html -Fragment > PSRecon\web\ie-history.html
$ieHistory = type PSRecon\web\ie-history.html

# Take a screenshot of the current desktop
# script stolen from:
#      https://gallery.technet.microsoft.com/scriptcenter/eeff544a-f690-4f6b-a586-11eea6fc5eb8
Function Take-ScreenShot {   
#Requires -Version 2 
        [cmdletbinding( 
                SupportsShouldProcess = $True, 
                DefaultParameterSetName = "screen", 
                ConfirmImpact = "low" 
        )] 
Param ( 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "screen", 
            ValueFromPipeline = $True)] 
            [switch]$screen, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "window", 
            ValueFromPipeline = $False)] 
            [switch]$activewindow, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string]$file,  
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string] 
            [ValidateSet("bmp","jpeg","png")] 
            $imagetype = "bmp", 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [switch]$print                        
        
) 
# C# code 
$code = @' 
using System; 
using System.Runtime.InteropServices; 
using System.Drawing; 
using System.Drawing.Imaging; 
namespace ScreenShotDemo 
{ 
  /// <summary> 
  /// Provides functions to capture the entire screen, or a particular window, and save it to a file. 
  /// </summary> 
  public class ScreenCapture 
  { 
    /// <summary> 
    /// Creates an Image object containing a screen shot the active window 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureActiveWindow() 
    { 
      return CaptureWindow( User32.GetForegroundWindow() ); 
    } 
    /// <summary> 
    /// Creates an Image object containing a screen shot of the entire desktop 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureScreen() 
    { 
      return CaptureWindow( User32.GetDesktopWindow() ); 
    }     
    /// <summary> 
    /// Creates an Image object containing a screen shot of a specific window 
    /// </summary> 
    /// <param name="handle">The handle to the window. (In windows forms, this is obtained by the Handle property)</param> 
    /// <returns></returns> 
    private Image CaptureWindow(IntPtr handle) 
    { 
      // get te hDC of the target window 
      IntPtr hdcSrc = User32.GetWindowDC(handle); 
      // get the size 
      User32.RECT windowRect = new User32.RECT(); 
      User32.GetWindowRect(handle,ref windowRect); 
      int width = windowRect.right - windowRect.left; 
      int height = windowRect.bottom - windowRect.top; 
      // create a device context we can copy to 
      IntPtr hdcDest = GDI32.CreateCompatibleDC(hdcSrc); 
      // create a bitmap we can copy it to, 
      // using GetDeviceCaps to get the width/height 
      IntPtr hBitmap = GDI32.CreateCompatibleBitmap(hdcSrc,width,height); 
      // select the bitmap object 
      IntPtr hOld = GDI32.SelectObject(hdcDest,hBitmap); 
      // bitblt over 
      GDI32.BitBlt(hdcDest,0,0,width,height,hdcSrc,0,0,GDI32.SRCCOPY); 
      // restore selection 
      GDI32.SelectObject(hdcDest,hOld); 
      // clean up 
      GDI32.DeleteDC(hdcDest); 
      User32.ReleaseDC(handle,hdcSrc); 
      // get a .NET image object for it 
      Image img = Image.FromHbitmap(hBitmap); 
      // free up the Bitmap object 
      GDI32.DeleteObject(hBitmap); 
      return img; 
    } 
    /// <summary> 
    /// Captures a screen shot of the active window, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureActiveWindowToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureActiveWindow(); 
      img.Save(filename,format); 
    } 
    /// <summary> 
    /// Captures a screen shot of the entire desktop, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureScreenToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureScreen(); 
      img.Save(filename,format); 
    }     
    
    /// <summary> 
    /// Helper class containing Gdi32 API functions 
    /// </summary> 
    private class GDI32 
    { 
       
      public const int SRCCOPY = 0x00CC0020; // BitBlt dwRop parameter 
      [DllImport("gdi32.dll")] 
      public static extern bool BitBlt(IntPtr hObject,int nXDest,int nYDest, 
        int nWidth,int nHeight,IntPtr hObjectSource, 
        int nXSrc,int nYSrc,int dwRop); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleBitmap(IntPtr hDC,int nWidth, 
        int nHeight); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteObject(IntPtr hObject); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr SelectObject(IntPtr hDC,IntPtr hObject); 
    } 
 
    /// <summary> 
    /// Helper class containing User32 API functions 
    /// </summary> 
    private class User32 
    { 
      [StructLayout(LayoutKind.Sequential)] 
      public struct RECT 
      { 
        public int left; 
        public int top; 
        public int right; 
        public int bottom; 
      } 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetDesktopWindow(); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowDC(IntPtr hWnd); 
      [DllImport("user32.dll")] 
      public static extern IntPtr ReleaseDC(IntPtr hWnd,IntPtr hDC); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowRect(IntPtr hWnd,ref RECT rect); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetForegroundWindow();       
    } 
  } 
} 
'@ 
#User Add-Type to import the code 
add-type $code -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' 
#Create the object for the Function 
$capture = New-Object ScreenShotDemo.ScreenCapture 
 
#Take screenshot of the entire screen 
If ($Screen) { 
    Write-Verbose "Taking screenshot of entire desktop" 
    #Save to a file 
    If ($file) { 
        If ($file -eq "") { 
            $file = "$pwd\image.bmp" 
            } 
        Write-Verbose "Creating screen file: $file with imagetype of $imagetype" 
        $capture.CaptureScreenToFile($file,$imagetype) 
        } 
    ElseIf ($print) { 
        $img = $Capture.CaptureScreen() 
        $pd = New-Object System.Drawing.Printing.PrintDocument 
        $pd.Add_PrintPage({$_.Graphics.DrawImage(([System.Drawing.Image]$img), 0, 0)}) 
        $pd.Print() 
        }         
    Else { 
        $capture.CaptureScreen() 
        } 
    } 
}
Take-ScreenShot -screen -file "c:\screenshot.png" -imagetype png

# convert the image to Base64 for inclusion in the HTML report
$path = "c:\screenshot.png"
$screenshot = [convert]::ToBase64String((get-content $path -encoding byte))
move $path .\PSRecon\config\screenshot.png


# Capture Log and Registry Data using cmdlets from Get-ComputerDetails
# Awesome cmdlets stolen from:
#    https://raw.githubusercontent.com/clymb3r/PowerShell/master/Get-ComputerDetails/Get-ComputerDetails.ps1
if ( $remote -eq $true ) {
    
    # I Suck at PowerShell, anyone know how to mitigate the memory issue so that Kansa cmdlets can run remotely?

    $RDPconnections = "<p>Unfortunately his data cannot be pulled when PSRecon is run remotely<br />
    Unless the shell memory is expanded...<br /><br />
    The workaround is to set the Shell Memory Limit using the following command on the target host:<br />
    &nbsp;&nbsp;&nbsp;&nbsp;PS C:\> Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -force</p>"

    $psscripts = "<p>Unfortunately his data cannot be pulled when PSRecon is run remotely<br />
    Unless the shell memory is expanded...<br /><br />
    The workaround is to set the Shell Memory Limit using the following command on the target host:<br />
    &nbsp;&nbsp;&nbsp;&nbsp;PS C:\> Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -force</p>"

    $4624 = "<p>Unfortunately his data cannot be pulled when PSRecon is run remotely<br />
    Unless the shell memory is expanded...<br /><br />
    The workaround is to set the Shell Memory Limit using the following command on the target host:<br />
    &nbsp;&nbsp;&nbsp;&nbsp;PS C:\> Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -force</p>"

    $4648 = "<p>Unfortunately his data cannot be pulled when PSRecon is run remotely<br />
    Unless the shell memory is expanded...<br /><br />
    The workaround is to set the Shell Memory Limit using the following command on the target host:<br />
    &nbsp;&nbsp;&nbsp;&nbsp;PS C:\> Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024 -force</p>"

} Else {

    function Find-4648Logons
    {
        Param(
            $SecurityLog
        )

        $ExplicitLogons = $SecurityLog | Where {$_.InstanceID -eq 4648}
        $ReturnInfo = @{}

        foreach ($ExplicitLogon in $ExplicitLogons)
        {
            $Subject = $false
            $AccountWhosCredsUsed = $false
            $TargetServer = $false
            $SourceAccountName = ""
            $SourceAccountDomain = ""
            $TargetAccountName = ""
            $TargetAccountDomain = ""
            $TargetServer = ""
            foreach ($line in $ExplicitLogon.Message -split "\r\n")
            {
                if ($line -cmatch "^Subject:$")
                {
                    $Subject = $true
                }
                elseif ($line -cmatch "^Account\sWhose\sCredentials\sWere\sUsed:$")
                {
                    $Subject = $false
                    $AccountWhosCredsUsed = $true
                }
                elseif ($line -cmatch "^Target\sServer:")
                {
                    $AccountWhosCredsUsed = $false
                    $TargetServer = $true
                }
                elseif ($Subject -eq $true)
                {
                    if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                    {
                        $SourceAccountName = $Matches[1]
                    }
                    elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                    {
                        $SourceAccountDomain = $Matches[1]
                    }
                }
                elseif ($AccountWhosCredsUsed -eq $true)
                {
                    if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                    {
                        $TargetAccountName = $Matches[1]
                    }
                    elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                    {
                        $TargetAccountDomain = $Matches[1]
                    }
                }
                elseif ($TargetServer -eq $true)
                {
                    if ($line -cmatch "\s+Target\sServer\sName:\s+(\S.*)")
                    {
                        $TargetServer = $Matches[1]
                    }
                }
            }

            #Filter out logins that don't matter
            if (-not ($TargetAccountName -cmatch "^DWM-.*" -and $TargetAccountDomain -cmatch "^Window\sManager$"))
            {
                $Key = $SourceAccountName + $SourceAccountDomain + $TargetAccountName + $TargetAccountDomain + $TargetServer
                if (-not $ReturnInfo.ContainsKey($Key))
                {
                    $Properties = @{
                        LogType = 4648
                        LogSource = "Security"
                        SourceAccountName = $SourceAccountName
                        SourceDomainName = $SourceAccountDomain
                        TargetAccountName = $TargetAccountName
                        TargetDomainName = $TargetAccountDomain
                        TargetServer = $TargetServer
                        Count = 1
                        Times = @($ExplicitLogon.TimeGenerated)
                    }

                    $ResultObj = New-Object PSObject -Property $Properties
                    $ReturnInfo.Add($Key, $ResultObj)
                }
                else
                {
                    $ReturnInfo[$Key].Count++
                    $ReturnInfo[$Key].Times += ,$ExplicitLogon.TimeGenerated
                }
            }
        }

        return $ReturnInfo
    }
    function Find-4624Logons
    {
        Param (
            $SecurityLog
        )

        $Logons = $SecurityLog | Where {$_.InstanceID -eq 4624}
        $ReturnInfo = @{}

        foreach ($Logon in $Logons)
        {
            $SubjectSection = $false
            $NewLogonSection = $false
            $NetworkInformationSection = $false
            $AccountName = ""
            $AccountDomain = ""
            $LogonType = ""
            $NewLogonAccountName = ""
            $NewLogonAccountDomain = ""
            $WorkstationName = ""
            $SourceNetworkAddress = ""
            $SourcePort = ""

            foreach ($line in $Logon.Message -Split "\r\n")
            {
                if ($line -cmatch "^Subject:$")
                {
                    $SubjectSection = $true
                }
                elseif ($line -cmatch "^Logon\sType:\s+(\S.*)")
                {
                    $LogonType = $Matches[1]
                }
                elseif ($line -cmatch "^New\sLogon:$")
                {
                    $SubjectSection = $false
                    $NewLogonSection = $true
                }
                elseif ($line -cmatch "^Network\sInformation:$")
                {
                    $NewLogonSection = $false
                    $NetworkInformationSection = $true
                }
                elseif ($SubjectSection)
                {
                    if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                    {
                        $AccountName = $Matches[1]
                    }
                    elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                    {
                        $AccountDomain = $Matches[1]
                    }
                }
                elseif ($NewLogonSection)
                {
                    if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                    {
                        $NewLogonAccountName = $Matches[1]
                    }
                    elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                    {
                        $NewLogonAccountDomain = $Matches[1]
                    }
                }
                elseif ($NetworkInformationSection)
                {
                    if ($line -cmatch "^\s+Workstation\sName:\s+(\S.*)")
                    {
                        $WorkstationName = $Matches[1]
                    }
                    elseif ($line -cmatch "^\s+Source\sNetwork\sAddress:\s+(\S.*)")
                    {
                        $SourceNetworkAddress = $Matches[1]
                    }
                    elseif ($line -cmatch "^\s+Source\sPort:\s+(\S.*)")
                    {
                        $SourcePort = $Matches[1]
                    }
                }
            }

            #Filter out logins that don't matter
            if (-not ($NewLogonAccountDomain -cmatch "NT\sAUTHORITY" -or $NewLogonAccountDomain -cmatch "Window\sManager"))
            {
                $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
                if (-not $ReturnInfo.ContainsKey($Key))
                {
                    $Properties = @{
                        LogType = 4624
                        LogSource = "Security"
                        SourceAccountName = $AccountName
                        SourceDomainName = $AccountDomain
                        NewLogonAccountName = $NewLogonAccountName
                        NewLogonAccountDomain = $NewLogonAccountDomain
                        LogonType = $LogonType
                        WorkstationName = $WorkstationName
                        SourceNetworkAddress = $SourceNetworkAddress
                        SourcePort = $SourcePort
                        Count = 1
                        Times = @($Logon.TimeGenerated)
                    }

                    $ResultObj = New-Object PSObject -Property $Properties
                    $ReturnInfo.Add($Key, $ResultObj)
                }
                else
                {
                    $ReturnInfo[$Key].Count++
                    $ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
                }
            }
        }

        return $ReturnInfo
    }
    Function Find-PSScriptsInPSAppLog {
        $ReturnInfo = @{}
        $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4100]]" -ErrorAction SilentlyContinue

        foreach ($Log in $Logs)
        {
            $ContainsScriptName = $false
            $LogDetails = $Log.Message -split "`r`n"

            $FoundScriptName = $false
            foreach($Line in $LogDetails)
            {
                if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
                {
                    $ScriptName = $Matches[1]
                    $FoundScriptName = $true
                }
                elseif ($Line -imatch "^\s*User\s=\s(.*)")
                {
                    $User = $Matches[1]
                }
            }

            if ($FoundScriptName)
            {
                $Key = $ScriptName + "::::" + $User

                if (!$ReturnInfo.ContainsKey($Key))
                {
                    $Properties = @{
                        ScriptName = $ScriptName
                        UserName = $User
                        Count = 1
                        Times = @($Log.TimeCreated)
                    }

                    $Item = New-Object PSObject -Property $Properties
                    $ReturnInfo.Add($Key, $Item)
                }
                else
                {
                    $ReturnInfo[$Key].Count++
                    $ReturnInfo[$Key].Times += ,$Log.TimeCreated
                }
            }
        }

        return $ReturnInfo
    }
    Function Find-RDPClientConnections {
        $ReturnInfo = @{}

        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        #Attempt to enumerate the servers for all users
        $Users = Get-ChildItem -Path "HKU:\"
        foreach ($UserSid in $Users.PSChildName)
        {
            $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

            foreach ($Server in $Servers)
            {
                $Server = $Server.PSChildName
                $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint
                    
                $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

                if (!$ReturnInfo.ContainsKey($Key))
                {
                    $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                    $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

                    $Properties = @{
                        CurrentUser = $User
                        Server = $Server
                        UsernameHint = $UsernameHint
                    }

                    $Item = New-Object PSObject -Property $Properties
                    $ReturnInfo.Add($Key, $Item)
                }
            }
        }

        return $ReturnInfo
    }

    # Extract data from Get-ComputerDetails suite of cmdlets
    Find-RDPClientConnections | Format-List > PSRecon\registry\RDPconnections.html
    $RDPconnectionsA = Get-Content PSRecon\registry\RDPconnections.html
    $RDPconnections = $RDPconnectionsA | foreach {$_ + "<br />"}

    Find-PSScriptsInPSAppLog | Format-List > PSRecon\registry\psscripts.html
    $psscriptsA = Get-Content PSRecon\registry\psscripts.html
    $psscripts = $psscriptsA | foreach {$_ + "<br />"}

    $SecurityLog = Get-EventLog -LogName Security
    Find-4624Logons $SecurityLog | Format-List > PSRecon\registry\4624logons.html
    $4624A = Get-Content PSRecon\registry\4624logons.html
    $4624 = $4624A | foreach {$_ + "<br />"}

    Find-4648Logons $SecurityLog | Format-List > PSRecon\registry\4648logons.html
    $4648A = Get-Content PSRecon\registry\4648logons.html
    $4648 = $4648A | foreach {$_ + "<br />"}
#>
}

# Extract Email Details
if(-Not ($email)) {
    echo "<p><strong>emails not extracted...</strong><br /><br />" >> PSRecon\web\email-subjects.html
    echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; To extract emails, run PSRecon with the [email] command-line switch:<br /><br />" >> PSRecon\web\email-subjects.html
    echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; PS C:\> .\PSRecon.ps1 -email" >> PSRecon\web\email-subjects.html
    echo "<br /><br />" >> PSRecon\web\email-subjects.html
    echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; This was skipped because email extraction takes a very long time.<br />" >> PSRecon\web\email-subjects.html
    echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; This also closes the user's email client and tends to leave the Outlook process hanging...</strong></p><br />" >> PSRecon\web\email-subjects.html
    copy PSRecon\web\email-subjects.html PSRecon\web\email-links.html
    $emailSubjects = get-content PSRecon\web\email-subjects.html
    $emailLinks = get-content PSRecon\web\email-links.html
} else {
    if ($email -eq $true) {
    # Close outlook, so we can extract the emails
    Get-Process OUTLOOK | Foreach-Object { $_.CloseMainWindow() | Out-Null } | stop-process –force > $null 2>&1
    Write-Host "Extracting emails... This may take a few minutes!"
        Function Get-OutlookInBox {
            Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
            $olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
            $outlook = new-object -comobject outlook.application
            $namespace = $outlook.GetNameSpace("MAPI")
            $folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
            $folder.items |
            Select-Object -Property * -Last 50
        }
    $inbox = Get-OutlookInBox
    $inbox | Select-Object -Property SenderName, Subject, ReceivedTime > PSRecon\web\email-subjects.html
    $inbox | Select Body | findstr http > PSRecon\web\email-links.html
    $getEmailLinks = 'PSRecon\web\email-links.html'
    $emailLinkRegex = "([a-zA-Z]{3,})://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*).*?"
    $emailLinksA = select-string -Path $getEmailLinks -Pattern $emailLinkRegex -AllMatches | % { $_.Matches } | % { $_.Value }
    $emailSubjectsA = Get-Content PSRecon\web\email-subjects.html
    $emailSubjects = $emailSubjectsA | foreach {$_ + "<br />"}
    $emailLinks = $emailLinksA | foreach {$_ + "<br />"}
    Stop-Process -Name OUTLOOK -Force
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1234 -Message "Optional : Client Email Data Extracted"
    } Else {
        Write-Host "Missing Required Parameter [email]"
        Write-Host "     This option was specified "
        Write-Host "PS C:\> .\PSRecon.ps1 -email"
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Missing Required Parameter"
        Exit 1
    }
}

# PowerShell Profile
if ( Test-Path $profile ) {
    $PSprofileA = type $profile
    $PSProfile = $PSProfileA | foreach {$_ + "<br />"}
} else {
    $PSprofile = "<br />No PowerShell Profile File Found:<br /><br />"
}

# Last File Created
$Nb_day = -7
$Driveletter = ([System.IO.DriveInfo]::getdrives() | Where-Object {$_.DriveType -ne 'Network'} | Select-Object -ExpandProperty Name)
$MinDate = ((Get-Date).AddDays($Nb_day).ToString("MM/dd/yyyy"))

# Potential Dangerous Programs, Scripts, Shortcuts, Office Macros, PDF 

$File_Extension = @("*.exe","*.pif","*.application","*.gadget","*.msi","*.msp","*.com","*.scr","*.hta","*.cpl","*.msc","*.jar","*.bat","*.cmd","*.vb","*.vbs","*.vbe","*.js","*.jse","*.ws","*.wsf","*.wsc","*.wsh","*.wsh","*.ps1","*.ps1xml","*.ps2","*.ps2xml","*.psc1","*.psc2","*.msh","*.msh1","*.msh2","*.mshxml","*.msh1xml","*.msh2xml","*.scf","*.lnk","*.inf","*.reg","*.doc","*.xls","*.ppt","*.docm","*.dotm","*.xlsm","*.xltm","*.xlam","*.pptm","*.potm","*.ppam","*.ppsm","*.sldm","*.pdf")



Foreach ( $item in $Driveletter)
 {	
	$Drive = $item -creplace '^*\\', ''
	 $DangerousFiles = $DangerousFiles + (Get-ChildItem $Drive -Recurse -ErrorAction $ErrorActionPreference -include $File_Extension | Where-Object { $_.CreationTime -ge $MinDate } | Select-Object FullName, CreationTime, LastAccessTime, LastWriteTime, @{Name="Kbytes";Expression={$_.Length / 1Kb}} |Sort-Object CreationTime)
}
$DangerousFiles = $DangerousFiles | ConvertTo-Html -Fragment
#=======================================================================================
# Evidence Verification
#=======================================================================================

# Hash collected evidence files to verify authenticity
# script stolen from:
#      https://gallery.technet.microsoft.com/scriptcenter/Get-Hashes-of-Files-1d85de46
function Get-FileHash { 
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [Alias("PSPath","FullName")]
       [string[]]$Path, 

       [Parameter(Position=1)]
       [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
       [string[]]$Algorithm = "SHA256"
    )
    Process {  
        ForEach ($item in $Path) { 
            $item = (Resolve-Path $item).ProviderPath
            If (-Not ([uri]$item).IsAbsoluteUri) {
                Write-Verbose ("{0} is not a full path, using current directory: {1}" -f $item,$pwd)
                $item = (Join-Path $pwd ($item -replace "\.\\",""))
            }
           If(Test-Path $item -Type Container) {
              Write-Warning ("Cannot calculate hash for directory: {0}" -f $item)
              Return
           }
           $object = New-Object PSObject -Property @{ 
                Path = $item
            }
            #Open the Stream
            $stream = ([IO.StreamReader]$item).BaseStream
            foreach($Type in $Algorithm) {                
                [string]$hash = -join ([Security.Cryptography.HashAlgorithm]::Create( $Type ).ComputeHash( $stream ) | 
                ForEach { "{0:x2}" -f $_ })
                $null = $stream.Seek(0,0)
                #If multiple algorithms are used, then they will be added to existing object                
                $object = Add-Member -InputObject $Object -MemberType NoteProperty -Name $Type -Value $Hash -PassThru
            }
            $object.pstypenames.insert(0,'System.IO.FileInfo.Hash')
            #Output an object with the hash, algorithm and path
            Write-Output $object

            #Close the stream
            $stream.Close()
        }
    }
}

Get-Process | Where-Object {-not [string]::IsNullOrEmpty($_.Path)} | Select-Object Path -Unique | sort | Get-FileHash -Algorithm SHA256 | ConvertTo-Html -Fragment >> PSRecon\process\process-hashes.html
$processHashes = Get-Content PSRecon\process\process-hashes.html

$powershellHashes = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" | Get-FileHash -Algorithm SHA256 | ConvertTo-Html -Fragment

$downloadHashes = Get-ChildItem C:\Users\*\Downloads\ -Recurse | Get-FileHash -Algorithm SHA256 | ConvertTo-Html -Fragment > PSRecon\web\download-hashes.html

Get-ChildItem PSRecon\ -Recurse -Filter *.html | Get-FileHash -Algorithm SHA256 | ConvertTo-Html -Fragment > PSRecon\config\e-hashes.html
Get-Content PSRecon\config\e-hashes.html | Select-String -pattern 'e-hashes' -notmatch | Out-File PSRecon\config\evidence-hashes.html
rm PSRecon\config\e-hashes.html -Force
$evidenceHashes = type PSRecon\config\evidence-hashes.html

#=======================================================================================
# Report Generation
#=======================================================================================

# Create system profile report in HTML
$html = $("PSRecon\PSRecon_" + $dateString + "_" + $computerName + ".html")

$htmlHead = @"
<!-- &copy; LogRhythm - 2015 -->
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="user-scalable=yes, width=1000px" />
<title>PSRecon Report - $computerName</title>
"@

$htmlJS = @"
<script type="text/javascript">//<![CDATA[
/*! jQuery v2.1.3 | (c) 2005, 2014 jQuery Foundation, Inc. | jquery.org/license */
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");return b(a)}:b(a)}("undefined"!=typeof window?window:this,function(a,b){var c=[],d=c.slice,e=c.concat,f=c.push,g=c.indexOf,h={},i=h.toString,j=h.hasOwnProperty,k={},l=a.document,m="2.1.3",n=function(a,b){return new n.fn.init(a,b)},o=/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+`$/g,p=/^-ms-/,q=/-([\da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype={jquery:m,constructor:n,selector:"",length:0,toArray:function(){return d.call(this)},get:function(a){return null!=a?0>a?this[a+this.length]:this[a]:d.call(this)},pushStack:function(a){var b=n.merge(this.constructor(),a);return b.prevObject=this,b.context=this.context,b},each:function(a,b){return n.each(this,a,b)},map:function(a){return this.pushStack(n.map(this,function(b,c){return a.call(b,c,b)}))},slice:function(){return this.pushStack(d.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(a){var b=this.length,c=+a+(0>a?b:0);return this.pushStack(c>=0&&b>c?[this[c]]:[])},end:function(){return this.prevObject||this.constructor(null)},push:f,sort:c.sort,splice:c.splice},n.extend=n.fn.extend=function(){var a,b,c,d,e,f,g=arguments[0]||{},h=1,i=arguments.length,j=!1;for("boolean"==typeof g&&(j=g,g=arguments[h]||{},h++),"object"==typeof g||n.isFunction(g)||(g={}),h===i&&(g=this,h--);i>h;h++)if(null!=(a=arguments[h]))for(b in a)c=g[b],d=a[b],g!==d&&(j&&d&&(n.isPlainObject(d)||(e=n.isArray(d)))?(e?(e=!1,f=c&&n.isArray(c)?c:[]):f=c&&n.isPlainObject(c)?c:{},g[b]=n.extend(j,f,d)):void 0!==d&&(g[b]=d));return g},n.extend({expando:"jQuery"+(m+Math.random()).replace(/\D/g,""),isReady:!0,error:function(a){throw new Error(a)},noop:function(){},isFunction:function(a){return"function"===n.type(a)},isArray:Array.isArray,isWindow:function(a){return null!=a&&a===a.window},isNumeric:function(a){return!n.isArray(a)&&a-parseFloat(a)+1>=0},isPlainObject:function(a){return"object"!==n.type(a)||a.nodeType||n.isWindow(a)?!1:a.constructor&&!j.call(a.constructor.prototype,"isPrototypeOf")?!1:!0},isEmptyObject:function(a){var b;for(b in a)return!1;return!0},type:function(a){return null==a?a+"":"object"==typeof a||"function"==typeof a?h[i.call(a)]||"object":typeof a},globalEval:function(a){var b,c=eval;a=n.trim(a),a&&(1===a.indexOf("use strict")?(b=l.createElement("script"),b.text=a,l.head.appendChild(b).parentNode.removeChild(b)):c(a))},camelCase:function(a){return a.replace(p,"ms-").replace(q,r)},nodeName:function(a,b){return a.nodeName&&a.nodeName.toLowerCase()===b.toLowerCase()},each:function(a,b,c){var d,e=0,f=a.length,g=s(a);if(c){if(g){for(;f>e;e++)if(d=b.apply(a[e],c),d===!1)break}else for(e in a)if(d=b.apply(a[e],c),d===!1)break}else if(g){for(;f>e;e++)if(d=b.call(a[e],e,a[e]),d===!1)break}else for(e in a)if(d=b.call(a[e],e,a[e]),d===!1)break;return a},trim:function(a){return null==a?"":(a+"").replace(o,"")},makeArray:function(a,b){var c=b||[];return null!=a&&(s(Object(a))?n.merge(c,"string"==typeof a?[a]:a):f.call(c,a)),c},inArray:function(a,b,c){return null==b?-1:g.call(b,a,c)},merge:function(a,b){for(var c=+b.length,d=0,e=a.length;c>d;d++)a[e++]=b[d];return a.length=e,a},grep:function(a,b,c){for(var d,e=[],f=0,g=a.length,h=!c;g>f;f++)d=!b(a[f],f),d!==h&&e.push(a[f]);return e},map:function(a,b,c){var d,f=0,g=a.length,h=s(a),i=[];if(h)for(;g>f;f++)d=b(a[f],f,c),null!=d&&i.push(d);else for(f in a)d=b(a[f],f,c),null!=d&&i.push(d);return e.apply([],i)},guid:1,proxy:function(a,b){var c,e,f;return"string"==typeof b&&(c=a[b],b=a,a=c),n.isFunction(a)?(e=d.call(arguments,2),f=function(){return a.apply(b||this,e.concat(d.call(arguments)))},f.guid=a.guid=a.guid||n.guid++,f):void 0},now:Date.now,support:k}),n.each("Boolean Number String Function Array Date RegExp Object Error".split(" "),function(a,b){h["[object "+b+"]"]=b.toLowerCase()});function s(a){var b=a.length,c=n.type(a);return"function"===c||n.isWindow(a)?!1:1===a.nodeType&&b?!0:"array"===c||0===b||"number"==typeof b&&b>0&&b-1 in a}var t=function(a){var b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u="sizzle"+1*new Date,v=a.document,w=0,x=0,y=hb(),z=hb(),A=hb(),B=function(a,b){return a===b&&(l=!0),0},C=1<<31,D={}.hasOwnProperty,E=[],F=E.pop,G=E.push,H=E.push,I=E.slice,J=function(a,b){for(var c=0,d=a.length;d>c;c++)if(a[c]===b)return c;return-1},K="checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",L="[\\x20\\t\\r\\n\\f]",M="(?:\\\\.|[\\w-]|[^\\x00-\\xa0])+",N=M.replace("w","w#"),O="\\["+L+"*("+M+")(?:"+L+"*([*^`$|!~]?=)"+L+"*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|("+N+"))|)"+L+"*\\]",P=":("+M+")(?:\\((('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|((?:\\\\.|[^\\\\()[\\]]|"+O+")*)|.*)\\)|)",Q=new RegExp(L+"+","g"),R=new RegExp("^"+L+"+|((?:^|[^\\\\])(?:\\\\.)*)"+L+"+`$","g"),S=new RegExp("^"+L+"*,"+L+"*"),T=new RegExp("^"+L+"*([>+~]|"+L+")"+L+"*"),U=new RegExp("="+L+"*([^\\]'\"]*?)"+L+"*\\]","g"),V=new RegExp(P),W=new RegExp("^"+N+"`$"),X={ID:new RegExp("^#("+M+")"),CLASS:new RegExp("^\\.("+M+")"),TAG:new RegExp("^("+M.replace("w","w*")+")"),ATTR:new RegExp("^"+O),PSEUDO:new RegExp("^"+P),CHILD:new RegExp("^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\("+L+"*(even|odd|(([+-]|)(\\d*)n|)"+L+"*(?:([+-]|)"+L+"*(\\d+)|))"+L+"*\\)|)","i"),bool:new RegExp("^(?:"+K+")`$","i"),needsContext:new RegExp("^"+L+"*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\("+L+"*((?:-\\d)?\\d*)"+L+"*\\)|)(?=[^-]|`$)","i")},Y=/^(?:input|select|textarea|button)`$/i,Z=/^h\d`$/i,`$=/^[^{]+\{\s*\[native \w/,_=/^(?:#([\w-]+)|(\w+)|\.([\w-]+))`$/,ab=/[+~]/,bb=/'|\\/g,cb=new RegExp("\\\\([\\da-f]{1,6}"+L+"?|("+L+")|.)","ig"),db=function(a,b,c){var d="0x"+b-65536;return d!==d||c?b:0>d?String.fromCharCode(d+65536):String.fromCharCode(d>>10|55296,1023&d|56320)},eb=function(){m()};try{H.apply(E=I.call(v.childNodes),v.childNodes),E[v.childNodes.length].nodeType}catch(fb){H={apply:E.length?function(a,b){G.apply(a,I.call(b))}:function(a,b){var c=a.length,d=0;while(a[c++]=b[d++]);a.length=c-1}}}function gb(a,b,d,e){var f,h,j,k,l,o,r,s,w,x;if((b?b.ownerDocument||b:v)!==n&&m(b),b=b||n,d=d||[],k=b.nodeType,"string"!=typeof a||!a||1!==k&&9!==k&&11!==k)return d;if(!e&&p){if(11!==k&&(f=_.exec(a)))if(j=f[1]){if(9===k){if(h=b.getElementById(j),!h||!h.parentNode)return d;if(h.id===j)return d.push(h),d}else if(b.ownerDocument&&(h=b.ownerDocument.getElementById(j))&&t(b,h)&&h.id===j)return d.push(h),d}else{if(f[2])return H.apply(d,b.getElementsByTagName(a)),d;if((j=f[3])&&c.getElementsByClassName)return H.apply(d,b.getElementsByClassName(j)),d}if(c.qsa&&(!q||!q.test(a))){if(s=r=u,w=b,x=1!==k&&a,1===k&&"object"!==b.nodeName.toLowerCase()){o=g(a),(r=b.getAttribute("id"))?s=r.replace(bb,"\\`$&"):b.setAttribute("id",s),s="[id='"+s+"'] ",l=o.length;while(l--)o[l]=s+rb(o[l]);w=ab.test(a)&&pb(b.parentNode)||b,x=o.join(",")}if(x)try{return H.apply(d,w.querySelectorAll(x)),d}catch(y){}finally{r||b.removeAttribute("id")}}}return i(a.replace(R,"`$1"),b,d,e)}function hb(){var a=[];function b(c,e){return a.push(c+" ")>d.cacheLength&&delete b[a.shift()],b[c+" "]=e}return b}function ib(a){return a[u]=!0,a}function jb(a){var b=n.createElement("div");try{return!!a(b)}catch(c){return!1}finally{b.parentNode&&b.parentNode.removeChild(b),b=null}}function kb(a,b){var c=a.split("|"),e=a.length;while(e--)d.attrHandle[c[e]]=b}function lb(a,b){var c=b&&a,d=c&&1===a.nodeType&&1===b.nodeType&&(~b.sourceIndex||C)-(~a.sourceIndex||C);if(d)return d;if(c)while(c=c.nextSibling)if(c===b)return-1;return a?1:-1}function mb(a){return function(b){var c=b.nodeName.toLowerCase();return"input"===c&&b.type===a}}function nb(a){return function(b){var c=b.nodeName.toLowerCase();return("input"===c||"button"===c)&&b.type===a}}function ob(a){return ib(function(b){return b=+b,ib(function(c,d){var e,f=a([],c.length,b),g=f.length;while(g--)c[e=f[g]]&&(c[e]=!(d[e]=c[e]))})})}function pb(a){return a&&"undefined"!=typeof a.getElementsByTagName&&a}c=gb.support={},f=gb.isXML=function(a){var b=a&&(a.ownerDocument||a).documentElement;return b?"HTML"!==b.nodeName:!1},m=gb.setDocument=function(a){var b,e,g=a?a.ownerDocument||a:v;return g!==n&&9===g.nodeType&&g.documentElement?(n=g,o=g.documentElement,e=g.defaultView,e&&e!==e.top&&(e.addEventListener?e.addEventListener("unload",eb,!1):e.attachEvent&&e.attachEvent("onunload",eb)),p=!f(g),c.attributes=jb(function(a){return a.className="i",!a.getAttribute("className")}),c.getElementsByTagName=jb(function(a){return a.appendChild(g.createComment("")),!a.getElementsByTagName("*").length}),c.getElementsByClassName=`$.test(g.getElementsByClassName),c.getById=jb(function(a){return o.appendChild(a).id=u,!g.getElementsByName||!g.getElementsByName(u).length}),c.getById?(d.find.ID=function(a,b){if("undefined"!=typeof b.getElementById&&p){var c=b.getElementById(a);return c&&c.parentNode?[c]:[]}},d.filter.ID=function(a){var b=a.replace(cb,db);return function(a){return a.getAttribute("id")===b}}):(delete d.find.ID,d.filter.ID=function(a){var b=a.replace(cb,db);return function(a){var c="undefined"!=typeof a.getAttributeNode&&a.getAttributeNode("id");return c&&c.value===b}}),d.find.TAG=c.getElementsByTagName?function(a,b){return"undefined"!=typeof b.getElementsByTagName?b.getElementsByTagName(a):c.qsa?b.querySelectorAll(a):void 0}:function(a,b){var c,d=[],e=0,f=b.getElementsByTagName(a);if("*"===a){while(c=f[e++])1===c.nodeType&&d.push(c);return d}return f},d.find.CLASS=c.getElementsByClassName&&function(a,b){return p?b.getElementsByClassName(a):void 0},r=[],q=[],(c.qsa=`$.test(g.querySelectorAll))&&(jb(function(a){o.appendChild(a).innerHTML="<a id='"+u+"'></a><select id='"+u+"-\f]' msallowcapture=''><option selected=''></option></select>",a.querySelectorAll("[msallowcapture^='']").length&&q.push("[*^`$]="+L+"*(?:''|\"\")"),a.querySelectorAll("[selected]").length||q.push("\\["+L+"*(?:value|"+K+")"),a.querySelectorAll("[id~="+u+"-]").length||q.push("~="),a.querySelectorAll(":checked").length||q.push(":checked"),a.querySelectorAll("a#"+u+"+*").length||q.push(".#.+[+~]")}),jb(function(a){var b=g.createElement("input");b.setAttribute("type","hidden"),a.appendChild(b).setAttribute("name","D"),a.querySelectorAll("[name=d]").length&&q.push("name"+L+"*[*^`$|!~]?="),a.querySelectorAll(":enabled").length||q.push(":enabled",":disabled"),a.querySelectorAll("*,:x"),q.push(",.*:")})),(c.matchesSelector=`$.test(s=o.matches||o.webkitMatchesSelector||o.mozMatchesSelector||o.oMatchesSelector||o.msMatchesSelector))&&jb(function(a){c.disconnectedMatch=s.call(a,"div"),s.call(a,"[s!='']:x"),r.push("!=",P)}),q=q.length&&new RegExp(q.join("|")),r=r.length&&new RegExp(r.join("|")),b=`$.test(o.compareDocumentPosition),t=b||`$.test(o.contains)?function(a,b){var c=9===a.nodeType?a.documentElement:a,d=b&&b.parentNode;return a===d||!(!d||1!==d.nodeType||!(c.contains?c.contains(d):a.compareDocumentPosition&&16&a.compareDocumentPosition(d)))}:function(a,b){if(b)while(b=b.parentNode)if(b===a)return!0;return!1},B=b?function(a,b){if(a===b)return l=!0,0;var d=!a.compareDocumentPosition-!b.compareDocumentPosition;return d?d:(d=(a.ownerDocument||a)===(b.ownerDocument||b)?a.compareDocumentPosition(b):1,1&d||!c.sortDetached&&b.compareDocumentPosition(a)===d?a===g||a.ownerDocument===v&&t(v,a)?-1:b===g||b.ownerDocument===v&&t(v,b)?1:k?J(k,a)-J(k,b):0:4&d?-1:1)}:function(a,b){if(a===b)return l=!0,0;var c,d=0,e=a.parentNode,f=b.parentNode,h=[a],i=[b];if(!e||!f)return a===g?-1:b===g?1:e?-1:f?1:k?J(k,a)-J(k,b):0;if(e===f)return lb(a,b);c=a;while(c=c.parentNode)h.unshift(c);c=b;while(c=c.parentNode)i.unshift(c);while(h[d]===i[d])d++;return d?lb(h[d],i[d]):h[d]===v?-1:i[d]===v?1:0},g):n},gb.matches=function(a,b){return gb(a,null,null,b)},gb.matchesSelector=function(a,b){if((a.ownerDocument||a)!==n&&m(a),b=b.replace(U,"='`$1']"),!(!c.matchesSelector||!p||r&&r.test(b)||q&&q.test(b)))try{var d=s.call(a,b);if(d||c.disconnectedMatch||a.document&&11!==a.document.nodeType)return d}catch(e){}return gb(b,n,null,[a]).length>0},gb.contains=function(a,b){return(a.ownerDocument||a)!==n&&m(a),t(a,b)},gb.attr=function(a,b){(a.ownerDocument||a)!==n&&m(a);var e=d.attrHandle[b.toLowerCase()],f=e&&D.call(d.attrHandle,b.toLowerCase())?e(a,b,!p):void 0;return void 0!==f?f:c.attributes||!p?a.getAttribute(b):(f=a.getAttributeNode(b))&&f.specified?f.value:null},gb.error=function(a){throw new Error("Syntax error, unrecognized expression: "+a)},gb.uniqueSort=function(a){var b,d=[],e=0,f=0;if(l=!c.detectDuplicates,k=!c.sortStable&&a.slice(0),a.sort(B),l){while(b=a[f++])b===a[f]&&(e=d.push(f));while(e--)a.splice(d[e],1)}return k=null,a},e=gb.getText=function(a){var b,c="",d=0,f=a.nodeType;if(f){if(1===f||9===f||11===f){if("string"==typeof a.textContent)return a.textContent;for(a=a.firstChild;a;a=a.nextSibling)c+=e(a)}else if(3===f||4===f)return a.nodeValue}else while(b=a[d++])c+=e(b);return c},d=gb.selectors={cacheLength:50,createPseudo:ib,match:X,attrHandle:{},find:{},relative:{">":{dir:"parentNode",first:!0}," ":{dir:"parentNode"},"+":{dir:"previousSibling",first:!0},"~":{dir:"previousSibling"}},preFilter:{ATTR:function(a){return a[1]=a[1].replace(cb,db),a[3]=(a[3]||a[4]||a[5]||"").replace(cb,db),"~="===a[2]&&(a[3]=" "+a[3]+" "),a.slice(0,4)},CHILD:function(a){return a[1]=a[1].toLowerCase(),"nth"===a[1].slice(0,3)?(a[3]||gb.error(a[0]),a[4]=+(a[4]?a[5]+(a[6]||1):2*("even"===a[3]||"odd"===a[3])),a[5]=+(a[7]+a[8]||"odd"===a[3])):a[3]&&gb.error(a[0]),a},PSEUDO:function(a){var b,c=!a[6]&&a[2];return X.CHILD.test(a[0])?null:(a[3]?a[2]=a[4]||a[5]||"":c&&V.test(c)&&(b=g(c,!0))&&(b=c.indexOf(")",c.length-b)-c.length)&&(a[0]=a[0].slice(0,b),a[2]=c.slice(0,b)),a.slice(0,3))}},filter:{TAG:function(a){var b=a.replace(cb,db).toLowerCase();return"*"===a?function(){return!0}:function(a){return a.nodeName&&a.nodeName.toLowerCase()===b}},CLASS:function(a){var b=y[a+" "];return b||(b=new RegExp("(^|"+L+")"+a+"("+L+"|`$)"))&&y(a,function(a){return b.test("string"==typeof a.className&&a.className||"undefined"!=typeof a.getAttribute&&a.getAttribute("class")||"")})},ATTR:function(a,b,c){return function(d){var e=gb.attr(d,a);return null==e?"!="===b:b?(e+="","="===b?e===c:"!="===b?e!==c:"^="===b?c&&0===e.indexOf(c):"*="===b?c&&e.indexOf(c)>-1:"`$="===b?c&&e.slice(-c.length)===c:"~="===b?(" "+e.replace(Q," ")+" ").indexOf(c)>-1:"|="===b?e===c||e.slice(0,c.length+1)===c+"-":!1):!0}},CHILD:function(a,b,c,d,e){var f="nth"!==a.slice(0,3),g="last"!==a.slice(-4),h="of-type"===b;return 1===d&&0===e?function(a){return!!a.parentNode}:function(b,c,i){var j,k,l,m,n,o,p=f!==g?"nextSibling":"previousSibling",q=b.parentNode,r=h&&b.nodeName.toLowerCase(),s=!i&&!h;if(q){if(f){while(p){l=b;while(l=l[p])if(h?l.nodeName.toLowerCase()===r:1===l.nodeType)return!1;o=p="only"===a&&!o&&"nextSibling"}return!0}if(o=[g?q.firstChild:q.lastChild],g&&s){k=q[u]||(q[u]={}),j=k[a]||[],n=j[0]===w&&j[1],m=j[0]===w&&j[2],l=n&&q.childNodes[n];while(l=++n&&l&&l[p]||(m=n=0)||o.pop())if(1===l.nodeType&&++m&&l===b){k[a]=[w,n,m];break}}else if(s&&(j=(b[u]||(b[u]={}))[a])&&j[0]===w)m=j[1];else while(l=++n&&l&&l[p]||(m=n=0)||o.pop())if((h?l.nodeName.toLowerCase()===r:1===l.nodeType)&&++m&&(s&&((l[u]||(l[u]={}))[a]=[w,m]),l===b))break;return m-=e,m===d||m%d===0&&m/d>=0}}},PSEUDO:function(a,b){var c,e=d.pseudos[a]||d.setFilters[a.toLowerCase()]||gb.error("unsupported pseudo: "+a);return e[u]?e(b):e.length>1?(c=[a,a,"",b],d.setFilters.hasOwnProperty(a.toLowerCase())?ib(function(a,c){var d,f=e(a,b),g=f.length;while(g--)d=J(a,f[g]),a[d]=!(c[d]=f[g])}):function(a){return e(a,0,c)}):e}},pseudos:{not:ib(function(a){var b=[],c=[],d=h(a.replace(R,"`$1"));return d[u]?ib(function(a,b,c,e){var f,g=d(a,null,e,[]),h=a.length;while(h--)(f=g[h])&&(a[h]=!(b[h]=f))}):function(a,e,f){return b[0]=a,d(b,null,f,c),b[0]=null,!c.pop()}}),has:ib(function(a){return function(b){return gb(a,b).length>0}}),contains:ib(function(a){return a=a.replace(cb,db),function(b){return(b.textContent||b.innerText||e(b)).indexOf(a)>-1}}),lang:ib(function(a){return W.test(a||"")||gb.error("unsupported lang: "+a),a=a.replace(cb,db).toLowerCase(),function(b){var c;do if(c=p?b.lang:b.getAttribute("xml:lang")||b.getAttribute("lang"))return c=c.toLowerCase(),c===a||0===c.indexOf(a+"-");while((b=b.parentNode)&&1===b.nodeType);return!1}}),target:function(b){var c=a.location&&a.location.hash;return c&&c.slice(1)===b.id},root:function(a){return a===o},focus:function(a){return a===n.activeElement&&(!n.hasFocus||n.hasFocus())&&!!(a.type||a.href||~a.tabIndex)},enabled:function(a){return a.disabled===!1},disabled:function(a){return a.disabled===!0},checked:function(a){var b=a.nodeName.toLowerCase();return"input"===b&&!!a.checked||"option"===b&&!!a.selected},selected:function(a){return a.parentNode&&a.parentNode.selectedIndex,a.selected===!0},empty:function(a){for(a=a.firstChild;a;a=a.nextSibling)if(a.nodeType<6)return!1;return!0},parent:function(a){return!d.pseudos.empty(a)},header:function(a){return Z.test(a.nodeName)},input:function(a){return Y.test(a.nodeName)},button:function(a){var b=a.nodeName.toLowerCase();return"input"===b&&"button"===a.type||"button"===b},text:function(a){var b;return"input"===a.nodeName.toLowerCase()&&"text"===a.type&&(null==(b=a.getAttribute("type"))||"text"===b.toLowerCase())},first:ob(function(){return[0]}),last:ob(function(a,b){return[b-1]}),eq:ob(function(a,b,c){return[0>c?c+b:c]}),even:ob(function(a,b){for(var c=0;b>c;c+=2)a.push(c);return a}),odd:ob(function(a,b){for(var c=1;b>c;c+=2)a.push(c);return a}),lt:ob(function(a,b,c){for(var d=0>c?c+b:c;--d>=0;)a.push(d);return a}),gt:ob(function(a,b,c){for(var d=0>c?c+b:c;++d<b;)a.push(d);return a})}},d.pseudos.nth=d.pseudos.eq;for(b in{radio:!0,checkbox:!0,file:!0,password:!0,image:!0})d.pseudos[b]=mb(b);for(b in{submit:!0,reset:!0})d.pseudos[b]=nb(b);function qb(){}qb.prototype=d.filters=d.pseudos,d.setFilters=new qb,g=gb.tokenize=function(a,b){var c,e,f,g,h,i,j,k=z[a+" "];if(k)return b?0:k.slice(0);h=a,i=[],j=d.preFilter;while(h){(!c||(e=S.exec(h)))&&(e&&(h=h.slice(e[0].length)||h),i.push(f=[])),c=!1,(e=T.exec(h))&&(c=e.shift(),f.push({value:c,type:e[0].replace(R," ")}),h=h.slice(c.length));for(g in d.filter)!(e=X[g].exec(h))||j[g]&&!(e=j[g](e))||(c=e.shift(),f.push({value:c,type:g,matches:e}),h=h.slice(c.length));if(!c)break}return b?h.length:h?gb.error(a):z(a,i).slice(0)};function rb(a){for(var b=0,c=a.length,d="";c>b;b++)d+=a[b].value;return d}function sb(a,b,c){var d=b.dir,e=c&&"parentNode"===d,f=x++;return b.first?function(b,c,f){while(b=b[d])if(1===b.nodeType||e)return a(b,c,f)}:function(b,c,g){var h,i,j=[w,f];if(g){while(b=b[d])if((1===b.nodeType||e)&&a(b,c,g))return!0}else while(b=b[d])if(1===b.nodeType||e){if(i=b[u]||(b[u]={}),(h=i[d])&&h[0]===w&&h[1]===f)return j[2]=h[2];if(i[d]=j,j[2]=a(b,c,g))return!0}}}function tb(a){return a.length>1?function(b,c,d){var e=a.length;while(e--)if(!a[e](b,c,d))return!1;return!0}:a[0]}function ub(a,b,c){for(var d=0,e=b.length;e>d;d++)gb(a,b[d],c);return c}function vb(a,b,c,d,e){for(var f,g=[],h=0,i=a.length,j=null!=b;i>h;h++)(f=a[h])&&(!c||c(f,d,e))&&(g.push(f),j&&b.push(h));return g}function wb(a,b,c,d,e,f){return d&&!d[u]&&(d=wb(d)),e&&!e[u]&&(e=wb(e,f)),ib(function(f,g,h,i){var j,k,l,m=[],n=[],o=g.length,p=f||ub(b||"*",h.nodeType?[h]:h,[]),q=!a||!f&&b?p:vb(p,m,a,h,i),r=c?e||(f?a:o||d)?[]:g:q;if(c&&c(q,r,h,i),d){j=vb(r,n),d(j,[],h,i),k=j.length;while(k--)(l=j[k])&&(r[n[k]]=!(q[n[k]]=l))}if(f){if(e||a){if(e){j=[],k=r.length;while(k--)(l=r[k])&&j.push(q[k]=l);e(null,r=[],j,i)}k=r.length;while(k--)(l=r[k])&&(j=e?J(f,l):m[k])>-1&&(f[j]=!(g[j]=l))}}else r=vb(r===g?r.splice(o,r.length):r),e?e(null,g,r,i):H.apply(g,r)})}function xb(a){for(var b,c,e,f=a.length,g=d.relative[a[0].type],h=g||d.relative[" "],i=g?1:0,k=sb(function(a){return a===b},h,!0),l=sb(function(a){return J(b,a)>-1},h,!0),m=[function(a,c,d){var e=!g&&(d||c!==j)||((b=c).nodeType?k(a,c,d):l(a,c,d));return b=null,e}];f>i;i++)if(c=d.relative[a[i].type])m=[sb(tb(m),c)];else{if(c=d.filter[a[i].type].apply(null,a[i].matches),c[u]){for(e=++i;f>e;e++)if(d.relative[a[e].type])break;return wb(i>1&&tb(m),i>1&&rb(a.slice(0,i-1).concat({value:" "===a[i-2].type?"*":""})).replace(R,"`$1"),c,e>i&&xb(a.slice(i,e)),f>e&&xb(a=a.slice(e)),f>e&&rb(a))}m.push(c)}return tb(m)}function yb(a,b){var c=b.length>0,e=a.length>0,f=function(f,g,h,i,k){var l,m,o,p=0,q="0",r=f&&[],s=[],t=j,u=f||e&&d.find.TAG("*",k),v=w+=null==t?1:Math.random()||.1,x=u.length;for(k&&(j=g!==n&&g);q!==x&&null!=(l=u[q]);q++){if(e&&l){m=0;while(o=a[m++])if(o(l,g,h)){i.push(l);break}k&&(w=v)}c&&((l=!o&&l)&&p--,f&&r.push(l))}if(p+=q,c&&q!==p){m=0;while(o=b[m++])o(r,s,g,h);if(f){if(p>0)while(q--)r[q]||s[q]||(s[q]=F.call(i));s=vb(s)}H.apply(i,s),k&&!f&&s.length>0&&p+b.length>1&&gb.uniqueSort(i)}return k&&(w=v,j=t),r};return c?ib(f):f}return h=gb.compile=function(a,b){var c,d=[],e=[],f=A[a+" "];if(!f){b||(b=g(a)),c=b.length;while(c--)f=xb(b[c]),f[u]?d.push(f):e.push(f);f=A(a,yb(e,d)),f.selector=a}return f},i=gb.select=function(a,b,e,f){var i,j,k,l,m,n="function"==typeof a&&a,o=!f&&g(a=n.selector||a);if(e=e||[],1===o.length){if(j=o[0]=o[0].slice(0),j.length>2&&"ID"===(k=j[0]).type&&c.getById&&9===b.nodeType&&p&&d.relative[j[1].type]){if(b=(d.find.ID(k.matches[0].replace(cb,db),b)||[])[0],!b)return e;n&&(b=b.parentNode),a=a.slice(j.shift().value.length)}i=X.needsContext.test(a)?0:j.length;while(i--){if(k=j[i],d.relative[l=k.type])break;if((m=d.find[l])&&(f=m(k.matches[0].replace(cb,db),ab.test(j[0].type)&&pb(b.parentNode)||b))){if(j.splice(i,1),a=f.length&&rb(j),!a)return H.apply(e,f),e;break}}}return(n||h(a,o))(f,b,!p,e,ab.test(a)&&pb(b.parentNode)||b),e},c.sortStable=u.split("").sort(B).join("")===u,c.detectDuplicates=!!l,m(),c.sortDetached=jb(function(a){return 1&a.compareDocumentPosition(n.createElement("div"))}),jb(function(a){return a.innerHTML="<a href='#'></a>","#"===a.firstChild.getAttribute("href")})||kb("type|href|height|width",function(a,b,c){return c?void 0:a.getAttribute(b,"type"===b.toLowerCase()?1:2)}),c.attributes&&jb(function(a){return a.innerHTML="<input/>",a.firstChild.setAttribute("value",""),""===a.firstChild.getAttribute("value")})||kb("value",function(a,b,c){return c||"input"!==a.nodeName.toLowerCase()?void 0:a.defaultValue}),jb(function(a){return null==a.getAttribute("disabled")})||kb(K,function(a,b,c){var d;return c?void 0:a[b]===!0?b.toLowerCase():(d=a.getAttributeNode(b))&&d.specified?d.value:null}),gb}(a);n.find=t,n.expr=t.selectors,n.expr[":"]=n.expr.pseudos,n.unique=t.uniqueSort,n.text=t.getText,n.isXMLDoc=t.isXML,n.contains=t.contains;var u=n.expr.match.needsContext,v=/^<(\w+)\s*\/?>(?:<\/\1>|)`$/,w=/^.[^:#\[\.,]*`$/;function x(a,b,c){if(n.isFunction(b))return n.grep(a,function(a,d){return!!b.call(a,d,a)!==c});if(b.nodeType)return n.grep(a,function(a){return a===b!==c});if("string"==typeof b){if(w.test(b))return n.filter(b,a,c);b=n.filter(b,a)}return n.grep(a,function(a){return g.call(b,a)>=0!==c})}n.filter=function(a,b,c){var d=b[0];return c&&(a=":not("+a+")"),1===b.length&&1===d.nodeType?n.find.matchesSelector(d,a)?[d]:[]:n.find.matches(a,n.grep(b,function(a){return 1===a.nodeType}))},n.fn.extend({find:function(a){var b,c=this.length,d=[],e=this;if("string"!=typeof a)return this.pushStack(n(a).filter(function(){for(b=0;c>b;b++)if(n.contains(e[b],this))return!0}));for(b=0;c>b;b++)n.find(a,e[b],d);return d=this.pushStack(c>1?n.unique(d):d),d.selector=this.selector?this.selector+" "+a:a,d},filter:function(a){return this.pushStack(x(this,a||[],!1))},not:function(a){return this.pushStack(x(this,a||[],!0))},is:function(a){return!!x(this,"string"==typeof a&&u.test(a)?n(a):a||[],!1).length}});var y,z=/^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]*))`$/,A=n.fn.init=function(a,b){var c,d;if(!a)return this;if("string"==typeof a){if(c="<"===a[0]&&">"===a[a.length-1]&&a.length>=3?[null,a,null]:z.exec(a),!c||!c[1]&&b)return!b||b.jquery?(b||y).find(a):this.constructor(b).find(a);if(c[1]){if(b=b instanceof n?b[0]:b,n.merge(this,n.parseHTML(c[1],b&&b.nodeType?b.ownerDocument||b:l,!0)),v.test(c[1])&&n.isPlainObject(b))for(c in b)n.isFunction(this[c])?this[c](b[c]):this.attr(c,b[c]);return this}return d=l.getElementById(c[2]),d&&d.parentNode&&(this.length=1,this[0]=d),this.context=l,this.selector=a,this}return a.nodeType?(this.context=this[0]=a,this.length=1,this):n.isFunction(a)?"undefined"!=typeof y.ready?y.ready(a):a(n):(void 0!==a.selector&&(this.selector=a.selector,this.context=a.context),n.makeArray(a,this))};A.prototype=n.fn,y=n(l);var B=/^(?:parents|prev(?:Until|All))/,C={children:!0,contents:!0,next:!0,prev:!0};n.extend({dir:function(a,b,c){var d=[],e=void 0!==c;while((a=a[b])&&9!==a.nodeType)if(1===a.nodeType){if(e&&n(a).is(c))break;d.push(a)}return d},sibling:function(a,b){for(var c=[];a;a=a.nextSibling)1===a.nodeType&&a!==b&&c.push(a);return c}}),n.fn.extend({has:function(a){var b=n(a,this),c=b.length;return this.filter(function(){for(var a=0;c>a;a++)if(n.contains(this,b[a]))return!0})},closest:function(a,b){for(var c,d=0,e=this.length,f=[],g=u.test(a)||"string"!=typeof a?n(a,b||this.context):0;e>d;d++)for(c=this[d];c&&c!==b;c=c.parentNode)if(c.nodeType<11&&(g?g.index(c)>-1:1===c.nodeType&&n.find.matchesSelector(c,a))){f.push(c);break}return this.pushStack(f.length>1?n.unique(f):f)},index:function(a){return a?"string"==typeof a?g.call(n(a),this[0]):g.call(this,a.jquery?a[0]:a):this[0]&&this[0].parentNode?this.first().prevAll().length:-1},add:function(a,b){return this.pushStack(n.unique(n.merge(this.get(),n(a,b))))},addBack:function(a){return this.add(null==a?this.prevObject:this.prevObject.filter(a))}});function D(a,b){while((a=a[b])&&1!==a.nodeType);return a}n.each({parent:function(a){var b=a.parentNode;return b&&11!==b.nodeType?b:null},parents:function(a){return n.dir(a,"parentNode")},parentsUntil:function(a,b,c){return n.dir(a,"parentNode",c)},next:function(a){return D(a,"nextSibling")},prev:function(a){return D(a,"previousSibling")},nextAll:function(a){return n.dir(a,"nextSibling")},prevAll:function(a){return n.dir(a,"previousSibling")},nextUntil:function(a,b,c){return n.dir(a,"nextSibling",c)},prevUntil:function(a,b,c){return n.dir(a,"previousSibling",c)},siblings:function(a){return n.sibling((a.parentNode||{}).firstChild,a)},children:function(a){return n.sibling(a.firstChild)},contents:function(a){return a.contentDocument||n.merge([],a.childNodes)}},function(a,b){n.fn[a]=function(c,d){var e=n.map(this,b,c);return"Until"!==a.slice(-5)&&(d=c),d&&"string"==typeof d&&(e=n.filter(d,e)),this.length>1&&(C[a]||n.unique(e),B.test(a)&&e.reverse()),this.pushStack(e)}});var E=/\S+/g,F={};function G(a){var b=F[a]={};return n.each(a.match(E)||[],function(a,c){b[c]=!0}),b}n.Callbacks=function(a){a="string"==typeof a?F[a]||G(a):n.extend({},a);var b,c,d,e,f,g,h=[],i=!a.once&&[],j=function(l){for(b=a.memory&&l,c=!0,g=e||0,e=0,f=h.length,d=!0;h&&f>g;g++)if(h[g].apply(l[0],l[1])===!1&&a.stopOnFalse){b=!1;break}d=!1,h&&(i?i.length&&j(i.shift()):b?h=[]:k.disable())},k={add:function(){if(h){var c=h.length;!function g(b){n.each(b,function(b,c){var d=n.type(c);"function"===d?a.unique&&k.has(c)||h.push(c):c&&c.length&&"string"!==d&&g(c)})}(arguments),d?f=h.length:b&&(e=c,j(b))}return this},remove:function(){return h&&n.each(arguments,function(a,b){var c;while((c=n.inArray(b,h,c))>-1)h.splice(c,1),d&&(f>=c&&f--,g>=c&&g--)}),this},has:function(a){return a?n.inArray(a,h)>-1:!(!h||!h.length)},empty:function(){return h=[],f=0,this},disable:function(){return h=i=b=void 0,this},disabled:function(){return!h},lock:function(){return i=void 0,b||k.disable(),this},locked:function(){return!i},fireWith:function(a,b){return!h||c&&!i||(b=b||[],b=[a,b.slice?b.slice():b],d?i.push(b):j(b)),this},fire:function(){return k.fireWith(this,arguments),this},fired:function(){return!!c}};return k},n.extend({Deferred:function(a){var b=[["resolve","done",n.Callbacks("once memory"),"resolved"],["reject","fail",n.Callbacks("once memory"),"rejected"],["notify","progress",n.Callbacks("memory")]],c="pending",d={state:function(){return c},always:function(){return e.done(arguments).fail(arguments),this},then:function(){var a=arguments;return n.Deferred(function(c){n.each(b,function(b,f){var g=n.isFunction(a[b])&&a[b];e[f[1]](function(){var a=g&&g.apply(this,arguments);a&&n.isFunction(a.promise)?a.promise().done(c.resolve).fail(c.reject).progress(c.notify):c[f[0]+"With"](this===d?c.promise():this,g?[a]:arguments)})}),a=null}).promise()},promise:function(a){return null!=a?n.extend(a,d):d}},e={};return d.pipe=d.then,n.each(b,function(a,f){var g=f[2],h=f[3];d[f[1]]=g.add,h&&g.add(function(){c=h},b[1^a][2].disable,b[2][2].lock),e[f[0]]=function(){return e[f[0]+"With"](this===e?d:this,arguments),this},e[f[0]+"With"]=g.fireWith}),d.promise(e),a&&a.call(e,e),e},when:function(a){var b=0,c=d.call(arguments),e=c.length,f=1!==e||a&&n.isFunction(a.promise)?e:0,g=1===f?a:n.Deferred(),h=function(a,b,c){return function(e){b[a]=this,c[a]=arguments.length>1?d.call(arguments):e,c===i?g.notifyWith(b,c):--f||g.resolveWith(b,c)}},i,j,k;if(e>1)for(i=new Array(e),j=new Array(e),k=new Array(e);e>b;b++)c[b]&&n.isFunction(c[b].promise)?c[b].promise().done(h(b,k,c)).fail(g.reject).progress(h(b,j,i)):--f;return f||g.resolveWith(k,c),g.promise()}});var H;n.fn.ready=function(a){return n.ready.promise().done(a),this},n.extend({isReady:!1,readyWait:1,holdReady:function(a){a?n.readyWait++:n.ready(!0)},ready:function(a){(a===!0?--n.readyWait:n.isReady)||(n.isReady=!0,a!==!0&&--n.readyWait>0||(H.resolveWith(l,[n]),n.fn.triggerHandler&&(n(l).triggerHandler("ready"),n(l).off("ready"))))}});function I(){l.removeEventListener("DOMContentLoaded",I,!1),a.removeEventListener("load",I,!1),n.ready()}n.ready.promise=function(b){return H||(H=n.Deferred(),"complete"===l.readyState?setTimeout(n.ready):(l.addEventListener("DOMContentLoaded",I,!1),a.addEventListener("load",I,!1))),H.promise(b)},n.ready.promise();var J=n.access=function(a,b,c,d,e,f,g){var h=0,i=a.length,j=null==c;if("object"===n.type(c)){e=!0;for(h in c)n.access(a,b,h,c[h],!0,f,g)}else if(void 0!==d&&(e=!0,n.isFunction(d)||(g=!0),j&&(g?(b.call(a,d),b=null):(j=b,b=function(a,b,c){return j.call(n(a),c)})),b))for(;i>h;h++)b(a[h],c,g?d:d.call(a[h],h,b(a[h],c)));return e?a:j?b.call(a):i?b(a[0],c):f};n.acceptData=function(a){return 1===a.nodeType||9===a.nodeType||!+a.nodeType};function K(){Object.defineProperty(this.cache={},0,{get:function(){return{}}}),this.expando=n.expando+K.uid++}K.uid=1,K.accepts=n.acceptData,K.prototype={key:function(a){if(!K.accepts(a))return 0;var b={},c=a[this.expando];if(!c){c=K.uid++;try{b[this.expando]={value:c},Object.defineProperties(a,b)}catch(d){b[this.expando]=c,n.extend(a,b)}}return this.cache[c]||(this.cache[c]={}),c},set:function(a,b,c){var d,e=this.key(a),f=this.cache[e];if("string"==typeof b)f[b]=c;else if(n.isEmptyObject(f))n.extend(this.cache[e],b);else for(d in b)f[d]=b[d];return f},get:function(a,b){var c=this.cache[this.key(a)];return void 0===b?c:c[b]},access:function(a,b,c){var d;return void 0===b||b&&"string"==typeof b&&void 0===c?(d=this.get(a,b),void 0!==d?d:this.get(a,n.camelCase(b))):(this.set(a,b,c),void 0!==c?c:b)},remove:function(a,b){var c,d,e,f=this.key(a),g=this.cache[f];if(void 0===b)this.cache[f]={};else{n.isArray(b)?d=b.concat(b.map(n.camelCase)):(e=n.camelCase(b),b in g?d=[b,e]:(d=e,d=d in g?[d]:d.match(E)||[])),c=d.length;while(c--)delete g[d[c]]}},hasData:function(a){return!n.isEmptyObject(this.cache[a[this.expando]]||{})},discard:function(a){a[this.expando]&&delete this.cache[a[this.expando]]}};var L=new K,M=new K,N=/^(?:\{[\w\W]*\}|\[[\w\W]*\])`$/,O=/([A-Z])/g;function P(a,b,c){var d;if(void 0===c&&1===a.nodeType)if(d="data-"+b.replace(O,"-`$1").toLowerCase(),c=a.getAttribute(d),"string"==typeof c){try{c="true"===c?!0:"false"===c?!1:"null"===c?null:+c+""===c?+c:N.test(c)?n.parseJSON(c):c}catch(e){}M.set(a,b,c)}else c=void 0;return c}n.extend({hasData:function(a){return M.hasData(a)||L.hasData(a)},data:function(a,b,c){return M.access(a,b,c)
},removeData:function(a,b){M.remove(a,b)},_data:function(a,b,c){return L.access(a,b,c)},_removeData:function(a,b){L.remove(a,b)}}),n.fn.extend({data:function(a,b){var c,d,e,f=this[0],g=f&&f.attributes;if(void 0===a){if(this.length&&(e=M.get(f),1===f.nodeType&&!L.get(f,"hasDataAttrs"))){c=g.length;while(c--)g[c]&&(d=g[c].name,0===d.indexOf("data-")&&(d=n.camelCase(d.slice(5)),P(f,d,e[d])));L.set(f,"hasDataAttrs",!0)}return e}return"object"==typeof a?this.each(function(){M.set(this,a)}):J(this,function(b){var c,d=n.camelCase(a);if(f&&void 0===b){if(c=M.get(f,a),void 0!==c)return c;if(c=M.get(f,d),void 0!==c)return c;if(c=P(f,d,void 0),void 0!==c)return c}else this.each(function(){var c=M.get(this,d);M.set(this,d,b),-1!==a.indexOf("-")&&void 0!==c&&M.set(this,a,b)})},null,b,arguments.length>1,null,!0)},removeData:function(a){return this.each(function(){M.remove(this,a)})}}),n.extend({queue:function(a,b,c){var d;return a?(b=(b||"fx")+"queue",d=L.get(a,b),c&&(!d||n.isArray(c)?d=L.access(a,b,n.makeArray(c)):d.push(c)),d||[]):void 0},dequeue:function(a,b){b=b||"fx";var c=n.queue(a,b),d=c.length,e=c.shift(),f=n._queueHooks(a,b),g=function(){n.dequeue(a,b)};"inprogress"===e&&(e=c.shift(),d--),e&&("fx"===b&&c.unshift("inprogress"),delete f.stop,e.call(a,g,f)),!d&&f&&f.empty.fire()},_queueHooks:function(a,b){var c=b+"queueHooks";return L.get(a,c)||L.access(a,c,{empty:n.Callbacks("once memory").add(function(){L.remove(a,[b+"queue",c])})})}}),n.fn.extend({queue:function(a,b){var c=2;return"string"!=typeof a&&(b=a,a="fx",c--),arguments.length<c?n.queue(this[0],a):void 0===b?this:this.each(function(){var c=n.queue(this,a,b);n._queueHooks(this,a),"fx"===a&&"inprogress"!==c[0]&&n.dequeue(this,a)})},dequeue:function(a){return this.each(function(){n.dequeue(this,a)})},clearQueue:function(a){return this.queue(a||"fx",[])},promise:function(a,b){var c,d=1,e=n.Deferred(),f=this,g=this.length,h=function(){--d||e.resolveWith(f,[f])};"string"!=typeof a&&(b=a,a=void 0),a=a||"fx";while(g--)c=L.get(f[g],a+"queueHooks"),c&&c.empty&&(d++,c.empty.add(h));return h(),e.promise(b)}});var Q=/[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/.source,R=["Top","Right","Bottom","Left"],S=function(a,b){return a=b||a,"none"===n.css(a,"display")||!n.contains(a.ownerDocument,a)},T=/^(?:checkbox|radio)`$/i;!function(){var a=l.createDocumentFragment(),b=a.appendChild(l.createElement("div")),c=l.createElement("input");c.setAttribute("type","radio"),c.setAttribute("checked","checked"),c.setAttribute("name","t"),b.appendChild(c),k.checkClone=b.cloneNode(!0).cloneNode(!0).lastChild.checked,b.innerHTML="<textarea>x</textarea>",k.noCloneChecked=!!b.cloneNode(!0).lastChild.defaultValue}();var U="undefined";k.focusinBubbles="onfocusin"in a;var V=/^key/,W=/^(?:mouse|pointer|contextmenu)|click/,X=/^(?:focusinfocus|focusoutblur)`$/,Y=/^([^.]*)(?:\.(.+)|)`$/;function Z(){return!0}function `$(){return!1}function _(){try{return l.activeElement}catch(a){}}n.event={global:{},add:function(a,b,c,d,e){var f,g,h,i,j,k,l,m,o,p,q,r=L.get(a);if(r){c.handler&&(f=c,c=f.handler,e=f.selector),c.guid||(c.guid=n.guid++),(i=r.events)||(i=r.events={}),(g=r.handle)||(g=r.handle=function(b){return typeof n!==U&&n.event.triggered!==b.type?n.event.dispatch.apply(a,arguments):void 0}),b=(b||"").match(E)||[""],j=b.length;while(j--)h=Y.exec(b[j])||[],o=q=h[1],p=(h[2]||"").split(".").sort(),o&&(l=n.event.special[o]||{},o=(e?l.delegateType:l.bindType)||o,l=n.event.special[o]||{},k=n.extend({type:o,origType:q,data:d,handler:c,guid:c.guid,selector:e,needsContext:e&&n.expr.match.needsContext.test(e),namespace:p.join(".")},f),(m=i[o])||(m=i[o]=[],m.delegateCount=0,l.setup&&l.setup.call(a,d,p,g)!==!1||a.addEventListener&&a.addEventListener(o,g,!1)),l.add&&(l.add.call(a,k),k.handler.guid||(k.handler.guid=c.guid)),e?m.splice(m.delegateCount++,0,k):m.push(k),n.event.global[o]=!0)}},remove:function(a,b,c,d,e){var f,g,h,i,j,k,l,m,o,p,q,r=L.hasData(a)&&L.get(a);if(r&&(i=r.events)){b=(b||"").match(E)||[""],j=b.length;while(j--)if(h=Y.exec(b[j])||[],o=q=h[1],p=(h[2]||"").split(".").sort(),o){l=n.event.special[o]||{},o=(d?l.delegateType:l.bindType)||o,m=i[o]||[],h=h[2]&&new RegExp("(^|\\.)"+p.join("\\.(?:.*\\.|)")+"(\\.|`$)"),g=f=m.length;while(f--)k=m[f],!e&&q!==k.origType||c&&c.guid!==k.guid||h&&!h.test(k.namespace)||d&&d!==k.selector&&("**"!==d||!k.selector)||(m.splice(f,1),k.selector&&m.delegateCount--,l.remove&&l.remove.call(a,k));g&&!m.length&&(l.teardown&&l.teardown.call(a,p,r.handle)!==!1||n.removeEvent(a,o,r.handle),delete i[o])}else for(o in i)n.event.remove(a,o+b[j],c,d,!0);n.isEmptyObject(i)&&(delete r.handle,L.remove(a,"events"))}},trigger:function(b,c,d,e){var f,g,h,i,k,m,o,p=[d||l],q=j.call(b,"type")?b.type:b,r=j.call(b,"namespace")?b.namespace.split("."):[];if(g=h=d=d||l,3!==d.nodeType&&8!==d.nodeType&&!X.test(q+n.event.triggered)&&(q.indexOf(".")>=0&&(r=q.split("."),q=r.shift(),r.sort()),k=q.indexOf(":")<0&&"on"+q,b=b[n.expando]?b:new n.Event(q,"object"==typeof b&&b),b.isTrigger=e?2:3,b.namespace=r.join("."),b.namespace_re=b.namespace?new RegExp("(^|\\.)"+r.join("\\.(?:.*\\.|)")+"(\\.|`$)"):null,b.result=void 0,b.target||(b.target=d),c=null==c?[b]:n.makeArray(c,[b]),o=n.event.special[q]||{},e||!o.trigger||o.trigger.apply(d,c)!==!1)){if(!e&&!o.noBubble&&!n.isWindow(d)){for(i=o.delegateType||q,X.test(i+q)||(g=g.parentNode);g;g=g.parentNode)p.push(g),h=g;h===(d.ownerDocument||l)&&p.push(h.defaultView||h.parentWindow||a)}f=0;while((g=p[f++])&&!b.isPropagationStopped())b.type=f>1?i:o.bindType||q,m=(L.get(g,"events")||{})[b.type]&&L.get(g,"handle"),m&&m.apply(g,c),m=k&&g[k],m&&m.apply&&n.acceptData(g)&&(b.result=m.apply(g,c),b.result===!1&&b.preventDefault());return b.type=q,e||b.isDefaultPrevented()||o._default&&o._default.apply(p.pop(),c)!==!1||!n.acceptData(d)||k&&n.isFunction(d[q])&&!n.isWindow(d)&&(h=d[k],h&&(d[k]=null),n.event.triggered=q,d[q](),n.event.triggered=void 0,h&&(d[k]=h)),b.result}},dispatch:function(a){a=n.event.fix(a);var b,c,e,f,g,h=[],i=d.call(arguments),j=(L.get(this,"events")||{})[a.type]||[],k=n.event.special[a.type]||{};if(i[0]=a,a.delegateTarget=this,!k.preDispatch||k.preDispatch.call(this,a)!==!1){h=n.event.handlers.call(this,a,j),b=0;while((f=h[b++])&&!a.isPropagationStopped()){a.currentTarget=f.elem,c=0;while((g=f.handlers[c++])&&!a.isImmediatePropagationStopped())(!a.namespace_re||a.namespace_re.test(g.namespace))&&(a.handleObj=g,a.data=g.data,e=((n.event.special[g.origType]||{}).handle||g.handler).apply(f.elem,i),void 0!==e&&(a.result=e)===!1&&(a.preventDefault(),a.stopPropagation()))}return k.postDispatch&&k.postDispatch.call(this,a),a.result}},handlers:function(a,b){var c,d,e,f,g=[],h=b.delegateCount,i=a.target;if(h&&i.nodeType&&(!a.button||"click"!==a.type))for(;i!==this;i=i.parentNode||this)if(i.disabled!==!0||"click"!==a.type){for(d=[],c=0;h>c;c++)f=b[c],e=f.selector+" ",void 0===d[e]&&(d[e]=f.needsContext?n(e,this).index(i)>=0:n.find(e,this,null,[i]).length),d[e]&&d.push(f);d.length&&g.push({elem:i,handlers:d})}return h<b.length&&g.push({elem:this,handlers:b.slice(h)}),g},props:"altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),fixHooks:{},keyHooks:{props:"char charCode key keyCode".split(" "),filter:function(a,b){return null==a.which&&(a.which=null!=b.charCode?b.charCode:b.keyCode),a}},mouseHooks:{props:"button buttons clientX clientY offsetX offsetY pageX pageY screenX screenY toElement".split(" "),filter:function(a,b){var c,d,e,f=b.button;return null==a.pageX&&null!=b.clientX&&(c=a.target.ownerDocument||l,d=c.documentElement,e=c.body,a.pageX=b.clientX+(d&&d.scrollLeft||e&&e.scrollLeft||0)-(d&&d.clientLeft||e&&e.clientLeft||0),a.pageY=b.clientY+(d&&d.scrollTop||e&&e.scrollTop||0)-(d&&d.clientTop||e&&e.clientTop||0)),a.which||void 0===f||(a.which=1&f?1:2&f?3:4&f?2:0),a}},fix:function(a){if(a[n.expando])return a;var b,c,d,e=a.type,f=a,g=this.fixHooks[e];g||(this.fixHooks[e]=g=W.test(e)?this.mouseHooks:V.test(e)?this.keyHooks:{}),d=g.props?this.props.concat(g.props):this.props,a=new n.Event(f),b=d.length;while(b--)c=d[b],a[c]=f[c];return a.target||(a.target=l),3===a.target.nodeType&&(a.target=a.target.parentNode),g.filter?g.filter(a,f):a},special:{load:{noBubble:!0},focus:{trigger:function(){return this!==_()&&this.focus?(this.focus(),!1):void 0},delegateType:"focusin"},blur:{trigger:function(){return this===_()&&this.blur?(this.blur(),!1):void 0},delegateType:"focusout"},click:{trigger:function(){return"checkbox"===this.type&&this.click&&n.nodeName(this,"input")?(this.click(),!1):void 0},_default:function(a){return n.nodeName(a.target,"a")}},beforeunload:{postDispatch:function(a){void 0!==a.result&&a.originalEvent&&(a.originalEvent.returnValue=a.result)}}},simulate:function(a,b,c,d){var e=n.extend(new n.Event,c,{type:a,isSimulated:!0,originalEvent:{}});d?n.event.trigger(e,null,b):n.event.dispatch.call(b,e),e.isDefaultPrevented()&&c.preventDefault()}},n.removeEvent=function(a,b,c){a.removeEventListener&&a.removeEventListener(b,c,!1)},n.Event=function(a,b){return this instanceof n.Event?(a&&a.type?(this.originalEvent=a,this.type=a.type,this.isDefaultPrevented=a.defaultPrevented||void 0===a.defaultPrevented&&a.returnValue===!1?Z:`$):this.type=a,b&&n.extend(this,b),this.timeStamp=a&&a.timeStamp||n.now(),void(this[n.expando]=!0)):new n.Event(a,b)},n.Event.prototype={isDefaultPrevented:`$,isPropagationStopped:`$,isImmediatePropagationStopped:`$,preventDefault:function(){var a=this.originalEvent;this.isDefaultPrevented=Z,a&&a.preventDefault&&a.preventDefault()},stopPropagation:function(){var a=this.originalEvent;this.isPropagationStopped=Z,a&&a.stopPropagation&&a.stopPropagation()},stopImmediatePropagation:function(){var a=this.originalEvent;this.isImmediatePropagationStopped=Z,a&&a.stopImmediatePropagation&&a.stopImmediatePropagation(),this.stopPropagation()}},n.each({mouseenter:"mouseover",mouseleave:"mouseout",pointerenter:"pointerover",pointerleave:"pointerout"},function(a,b){n.event.special[a]={delegateType:b,bindType:b,handle:function(a){var c,d=this,e=a.relatedTarget,f=a.handleObj;return(!e||e!==d&&!n.contains(d,e))&&(a.type=f.origType,c=f.handler.apply(this,arguments),a.type=b),c}}}),k.focusinBubbles||n.each({focus:"focusin",blur:"focusout"},function(a,b){var c=function(a){n.event.simulate(b,a.target,n.event.fix(a),!0)};n.event.special[b]={setup:function(){var d=this.ownerDocument||this,e=L.access(d,b);e||d.addEventListener(a,c,!0),L.access(d,b,(e||0)+1)},teardown:function(){var d=this.ownerDocument||this,e=L.access(d,b)-1;e?L.access(d,b,e):(d.removeEventListener(a,c,!0),L.remove(d,b))}}}),n.fn.extend({on:function(a,b,c,d,e){var f,g;if("object"==typeof a){"string"!=typeof b&&(c=c||b,b=void 0);for(g in a)this.on(g,b,c,a[g],e);return this}if(null==c&&null==d?(d=b,c=b=void 0):null==d&&("string"==typeof b?(d=c,c=void 0):(d=c,c=b,b=void 0)),d===!1)d=`$;else if(!d)return this;return 1===e&&(f=d,d=function(a){return n().off(a),f.apply(this,arguments)},d.guid=f.guid||(f.guid=n.guid++)),this.each(function(){n.event.add(this,a,d,c,b)})},one:function(a,b,c,d){return this.on(a,b,c,d,1)},off:function(a,b,c){var d,e;if(a&&a.preventDefault&&a.handleObj)return d=a.handleObj,n(a.delegateTarget).off(d.namespace?d.origType+"."+d.namespace:d.origType,d.selector,d.handler),this;if("object"==typeof a){for(e in a)this.off(e,b,a[e]);return this}return(b===!1||"function"==typeof b)&&(c=b,b=void 0),c===!1&&(c=`$),this.each(function(){n.event.remove(this,a,c,b)})},trigger:function(a,b){return this.each(function(){n.event.trigger(a,b,this)})},triggerHandler:function(a,b){var c=this[0];return c?n.event.trigger(a,b,c,!0):void 0}});var ab=/<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/gi,bb=/<([\w:]+)/,cb=/<|&#?\w+;/,db=/<(?:script|style|link)/i,eb=/checked\s*(?:[^=]|=\s*.checked.)/i,fb=/^`$|\/(?:java|ecma)script/i,gb=/^true\/(.*)/,hb=/^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*`$/g,ib={option:[1,"<select multiple='multiple'>","</select>"],thead:[1,"<table>","</table>"],col:[2,"<table><colgroup>","</colgroup></table>"],tr:[2,"<table><tbody>","</tbody></table>"],td:[3,"<table><tbody><tr>","</tr></tbody></table>"],_default:[0,"",""]};ib.optgroup=ib.option,ib.tbody=ib.tfoot=ib.colgroup=ib.caption=ib.thead,ib.th=ib.td;function jb(a,b){return n.nodeName(a,"table")&&n.nodeName(11!==b.nodeType?b:b.firstChild,"tr")?a.getElementsByTagName("tbody")[0]||a.appendChild(a.ownerDocument.createElement("tbody")):a}function kb(a){return a.type=(null!==a.getAttribute("type"))+"/"+a.type,a}function lb(a){var b=gb.exec(a.type);return b?a.type=b[1]:a.removeAttribute("type"),a}function mb(a,b){for(var c=0,d=a.length;d>c;c++)L.set(a[c],"globalEval",!b||L.get(b[c],"globalEval"))}function nb(a,b){var c,d,e,f,g,h,i,j;if(1===b.nodeType){if(L.hasData(a)&&(f=L.access(a),g=L.set(b,f),j=f.events)){delete g.handle,g.events={};for(e in j)for(c=0,d=j[e].length;d>c;c++)n.event.add(b,e,j[e][c])}M.hasData(a)&&(h=M.access(a),i=n.extend({},h),M.set(b,i))}}function ob(a,b){var c=a.getElementsByTagName?a.getElementsByTagName(b||"*"):a.querySelectorAll?a.querySelectorAll(b||"*"):[];return void 0===b||b&&n.nodeName(a,b)?n.merge([a],c):c}function pb(a,b){var c=b.nodeName.toLowerCase();"input"===c&&T.test(a.type)?b.checked=a.checked:("input"===c||"textarea"===c)&&(b.defaultValue=a.defaultValue)}n.extend({clone:function(a,b,c){var d,e,f,g,h=a.cloneNode(!0),i=n.contains(a.ownerDocument,a);if(!(k.noCloneChecked||1!==a.nodeType&&11!==a.nodeType||n.isXMLDoc(a)))for(g=ob(h),f=ob(a),d=0,e=f.length;e>d;d++)pb(f[d],g[d]);if(b)if(c)for(f=f||ob(a),g=g||ob(h),d=0,e=f.length;e>d;d++)nb(f[d],g[d]);else nb(a,h);return g=ob(h,"script"),g.length>0&&mb(g,!i&&ob(a,"script")),h},buildFragment:function(a,b,c,d){for(var e,f,g,h,i,j,k=b.createDocumentFragment(),l=[],m=0,o=a.length;o>m;m++)if(e=a[m],e||0===e)if("object"===n.type(e))n.merge(l,e.nodeType?[e]:e);else if(cb.test(e)){f=f||k.appendChild(b.createElement("div")),g=(bb.exec(e)||["",""])[1].toLowerCase(),h=ib[g]||ib._default,f.innerHTML=h[1]+e.replace(ab,"<`$1></`$2>")+h[2],j=h[0];while(j--)f=f.lastChild;n.merge(l,f.childNodes),f=k.firstChild,f.textContent=""}else l.push(b.createTextNode(e));k.textContent="",m=0;while(e=l[m++])if((!d||-1===n.inArray(e,d))&&(i=n.contains(e.ownerDocument,e),f=ob(k.appendChild(e),"script"),i&&mb(f),c)){j=0;while(e=f[j++])fb.test(e.type||"")&&c.push(e)}return k},cleanData:function(a){for(var b,c,d,e,f=n.event.special,g=0;void 0!==(c=a[g]);g++){if(n.acceptData(c)&&(e=c[L.expando],e&&(b=L.cache[e]))){if(b.events)for(d in b.events)f[d]?n.event.remove(c,d):n.removeEvent(c,d,b.handle);L.cache[e]&&delete L.cache[e]}delete M.cache[c[M.expando]]}}}),n.fn.extend({text:function(a){return J(this,function(a){return void 0===a?n.text(this):this.empty().each(function(){(1===this.nodeType||11===this.nodeType||9===this.nodeType)&&(this.textContent=a)})},null,a,arguments.length)},append:function(){return this.domManip(arguments,function(a){if(1===this.nodeType||11===this.nodeType||9===this.nodeType){var b=jb(this,a);b.appendChild(a)}})},prepend:function(){return this.domManip(arguments,function(a){if(1===this.nodeType||11===this.nodeType||9===this.nodeType){var b=jb(this,a);b.insertBefore(a,b.firstChild)}})},before:function(){return this.domManip(arguments,function(a){this.parentNode&&this.parentNode.insertBefore(a,this)})},after:function(){return this.domManip(arguments,function(a){this.parentNode&&this.parentNode.insertBefore(a,this.nextSibling)})},remove:function(a,b){for(var c,d=a?n.filter(a,this):this,e=0;null!=(c=d[e]);e++)b||1!==c.nodeType||n.cleanData(ob(c)),c.parentNode&&(b&&n.contains(c.ownerDocument,c)&&mb(ob(c,"script")),c.parentNode.removeChild(c));return this},empty:function(){for(var a,b=0;null!=(a=this[b]);b++)1===a.nodeType&&(n.cleanData(ob(a,!1)),a.textContent="");return this},clone:function(a,b){return a=null==a?!1:a,b=null==b?a:b,this.map(function(){return n.clone(this,a,b)})},html:function(a){return J(this,function(a){var b=this[0]||{},c=0,d=this.length;if(void 0===a&&1===b.nodeType)return b.innerHTML;if("string"==typeof a&&!db.test(a)&&!ib[(bb.exec(a)||["",""])[1].toLowerCase()]){a=a.replace(ab,"<`$1></`$2>");try{for(;d>c;c++)b=this[c]||{},1===b.nodeType&&(n.cleanData(ob(b,!1)),b.innerHTML=a);b=0}catch(e){}}b&&this.empty().append(a)},null,a,arguments.length)},replaceWith:function(){var a=arguments[0];return this.domManip(arguments,function(b){a=this.parentNode,n.cleanData(ob(this)),a&&a.replaceChild(b,this)}),a&&(a.length||a.nodeType)?this:this.remove()},detach:function(a){return this.remove(a,!0)},domManip:function(a,b){a=e.apply([],a);var c,d,f,g,h,i,j=0,l=this.length,m=this,o=l-1,p=a[0],q=n.isFunction(p);if(q||l>1&&"string"==typeof p&&!k.checkClone&&eb.test(p))return this.each(function(c){var d=m.eq(c);q&&(a[0]=p.call(this,c,d.html())),d.domManip(a,b)});if(l&&(c=n.buildFragment(a,this[0].ownerDocument,!1,this),d=c.firstChild,1===c.childNodes.length&&(c=d),d)){for(f=n.map(ob(c,"script"),kb),g=f.length;l>j;j++)h=c,j!==o&&(h=n.clone(h,!0,!0),g&&n.merge(f,ob(h,"script"))),b.call(this[j],h,j);if(g)for(i=f[f.length-1].ownerDocument,n.map(f,lb),j=0;g>j;j++)h=f[j],fb.test(h.type||"")&&!L.access(h,"globalEval")&&n.contains(i,h)&&(h.src?n._evalUrl&&n._evalUrl(h.src):n.globalEval(h.textContent.replace(hb,"")))}return this}}),n.each({appendTo:"append",prependTo:"prepend",insertBefore:"before",insertAfter:"after",replaceAll:"replaceWith"},function(a,b){n.fn[a]=function(a){for(var c,d=[],e=n(a),g=e.length-1,h=0;g>=h;h++)c=h===g?this:this.clone(!0),n(e[h])[b](c),f.apply(d,c.get());return this.pushStack(d)}});var qb,rb={};function sb(b,c){var d,e=n(c.createElement(b)).appendTo(c.body),f=a.getDefaultComputedStyle&&(d=a.getDefaultComputedStyle(e[0]))?d.display:n.css(e[0],"display");return e.detach(),f}function tb(a){var b=l,c=rb[a];return c||(c=sb(a,b),"none"!==c&&c||(qb=(qb||n("<iframe frameborder='0' width='0' height='0'/>")).appendTo(b.documentElement),b=qb[0].contentDocument,b.write(),b.close(),c=sb(a,b),qb.detach()),rb[a]=c),c}var ub=/^margin/,vb=new RegExp("^("+Q+")(?!px)[a-z%]+`$","i"),wb=function(b){return b.ownerDocument.defaultView.opener?b.ownerDocument.defaultView.getComputedStyle(b,null):a.getComputedStyle(b,null)};function xb(a,b,c){var d,e,f,g,h=a.style;return c=c||wb(a),c&&(g=c.getPropertyValue(b)||c[b]),c&&(""!==g||n.contains(a.ownerDocument,a)||(g=n.style(a,b)),vb.test(g)&&ub.test(b)&&(d=h.width,e=h.minWidth,f=h.maxWidth,h.minWidth=h.maxWidth=h.width=g,g=c.width,h.width=d,h.minWidth=e,h.maxWidth=f)),void 0!==g?g+"":g}function yb(a,b){return{get:function(){return a()?void delete this.get:(this.get=b).apply(this,arguments)}}}!function(){var b,c,d=l.documentElement,e=l.createElement("div"),f=l.createElement("div");if(f.style){f.style.backgroundClip="content-box",f.cloneNode(!0).style.backgroundClip="",k.clearCloneStyle="content-box"===f.style.backgroundClip,e.style.cssText="border:0;width:0;height:0;top:0;left:-9999px;margin-top:1px;position:absolute",e.appendChild(f);function g(){f.style.cssText="-webkit-box-sizing:border-box;-moz-box-sizing:border-box;box-sizing:border-box;display:block;margin-top:1%;top:1%;border:1px;padding:1px;width:4px;position:absolute",f.innerHTML="",d.appendChild(e);var g=a.getComputedStyle(f,null);b="1%"!==g.top,c="4px"===g.width,d.removeChild(e)}a.getComputedStyle&&n.extend(k,{pixelPosition:function(){return g(),b},boxSizingReliable:function(){return null==c&&g(),c},reliableMarginRight:function(){var b,c=f.appendChild(l.createElement("div"));return c.style.cssText=f.style.cssText="-webkit-box-sizing:content-box;-moz-box-sizing:content-box;box-sizing:content-box;display:block;margin:0;border:0;padding:0",c.style.marginRight=c.style.width="0",f.style.width="1px",d.appendChild(e),b=!parseFloat(a.getComputedStyle(c,null).marginRight),d.removeChild(e),f.removeChild(c),b}})}}(),n.swap=function(a,b,c,d){var e,f,g={};for(f in b)g[f]=a.style[f],a.style[f]=b[f];e=c.apply(a,d||[]);for(f in b)a.style[f]=g[f];return e};var zb=/^(none|table(?!-c[ea]).+)/,Ab=new RegExp("^("+Q+")(.*)`$","i"),Bb=new RegExp("^([+-])=("+Q+")","i"),Cb={position:"absolute",visibility:"hidden",display:"block"},Db={letterSpacing:"0",fontWeight:"400"},Eb=["Webkit","O","Moz","ms"];function Fb(a,b){if(b in a)return b;var c=b[0].toUpperCase()+b.slice(1),d=b,e=Eb.length;while(e--)if(b=Eb[e]+c,b in a)return b;return d}function Gb(a,b,c){var d=Ab.exec(b);return d?Math.max(0,d[1]-(c||0))+(d[2]||"px"):b}function Hb(a,b,c,d,e){for(var f=c===(d?"border":"content")?4:"width"===b?1:0,g=0;4>f;f+=2)"margin"===c&&(g+=n.css(a,c+R[f],!0,e)),d?("content"===c&&(g-=n.css(a,"padding"+R[f],!0,e)),"margin"!==c&&(g-=n.css(a,"border"+R[f]+"Width",!0,e))):(g+=n.css(a,"padding"+R[f],!0,e),"padding"!==c&&(g+=n.css(a,"border"+R[f]+"Width",!0,e)));return g}function Ib(a,b,c){var d=!0,e="width"===b?a.offsetWidth:a.offsetHeight,f=wb(a),g="border-box"===n.css(a,"boxSizing",!1,f);if(0>=e||null==e){if(e=xb(a,b,f),(0>e||null==e)&&(e=a.style[b]),vb.test(e))return e;d=g&&(k.boxSizingReliable()||e===a.style[b]),e=parseFloat(e)||0}return e+Hb(a,b,c||(g?"border":"content"),d,f)+"px"}function Jb(a,b){for(var c,d,e,f=[],g=0,h=a.length;h>g;g++)d=a[g],d.style&&(f[g]=L.get(d,"olddisplay"),c=d.style.display,b?(f[g]||"none"!==c||(d.style.display=""),""===d.style.display&&S(d)&&(f[g]=L.access(d,"olddisplay",tb(d.nodeName)))):(e=S(d),"none"===c&&e||L.set(d,"olddisplay",e?c:n.css(d,"display"))));for(g=0;h>g;g++)d=a[g],d.style&&(b&&"none"!==d.style.display&&""!==d.style.display||(d.style.display=b?f[g]||"":"none"));return a}n.extend({cssHooks:{opacity:{get:function(a,b){if(b){var c=xb(a,"opacity");return""===c?"1":c}}}},cssNumber:{columnCount:!0,fillOpacity:!0,flexGrow:!0,flexShrink:!0,fontWeight:!0,lineHeight:!0,opacity:!0,order:!0,orphans:!0,widows:!0,zIndex:!0,zoom:!0},cssProps:{"float":"cssFloat"},style:function(a,b,c,d){if(a&&3!==a.nodeType&&8!==a.nodeType&&a.style){var e,f,g,h=n.camelCase(b),i=a.style;return b=n.cssProps[h]||(n.cssProps[h]=Fb(i,h)),g=n.cssHooks[b]||n.cssHooks[h],void 0===c?g&&"get"in g&&void 0!==(e=g.get(a,!1,d))?e:i[b]:(f=typeof c,"string"===f&&(e=Bb.exec(c))&&(c=(e[1]+1)*e[2]+parseFloat(n.css(a,b)),f="number"),null!=c&&c===c&&("number"!==f||n.cssNumber[h]||(c+="px"),k.clearCloneStyle||""!==c||0!==b.indexOf("background")||(i[b]="inherit"),g&&"set"in g&&void 0===(c=g.set(a,c,d))||(i[b]=c)),void 0)}},css:function(a,b,c,d){var e,f,g,h=n.camelCase(b);return b=n.cssProps[h]||(n.cssProps[h]=Fb(a.style,h)),g=n.cssHooks[b]||n.cssHooks[h],g&&"get"in g&&(e=g.get(a,!0,c)),void 0===e&&(e=xb(a,b,d)),"normal"===e&&b in Db&&(e=Db[b]),""===c||c?(f=parseFloat(e),c===!0||n.isNumeric(f)?f||0:e):e}}),n.each(["height","width"],function(a,b){n.cssHooks[b]={get:function(a,c,d){return c?zb.test(n.css(a,"display"))&&0===a.offsetWidth?n.swap(a,Cb,function(){return Ib(a,b,d)}):Ib(a,b,d):void 0},set:function(a,c,d){var e=d&&wb(a);return Gb(a,c,d?Hb(a,b,d,"border-box"===n.css(a,"boxSizing",!1,e),e):0)}}}),n.cssHooks.marginRight=yb(k.reliableMarginRight,function(a,b){return b?n.swap(a,{display:"inline-block"},xb,[a,"marginRight"]):void 0}),n.each({margin:"",padding:"",border:"Width"},function(a,b){n.cssHooks[a+b]={expand:function(c){for(var d=0,e={},f="string"==typeof c?c.split(" "):[c];4>d;d++)e[a+R[d]+b]=f[d]||f[d-2]||f[0];return e}},ub.test(a)||(n.cssHooks[a+b].set=Gb)}),n.fn.extend({css:function(a,b){return J(this,function(a,b,c){var d,e,f={},g=0;if(n.isArray(b)){for(d=wb(a),e=b.length;e>g;g++)f[b[g]]=n.css(a,b[g],!1,d);return f}return void 0!==c?n.style(a,b,c):n.css(a,b)},a,b,arguments.length>1)},show:function(){return Jb(this,!0)},hide:function(){return Jb(this)},toggle:function(a){return"boolean"==typeof a?a?this.show():this.hide():this.each(function(){S(this)?n(this).show():n(this).hide()})}});function Kb(a,b,c,d,e){return new Kb.prototype.init(a,b,c,d,e)}n.Tween=Kb,Kb.prototype={constructor:Kb,init:function(a,b,c,d,e,f){this.elem=a,this.prop=c,this.easing=e||"swing",this.options=b,this.start=this.now=this.cur(),this.end=d,this.unit=f||(n.cssNumber[c]?"":"px")},cur:function(){var a=Kb.propHooks[this.prop];return a&&a.get?a.get(this):Kb.propHooks._default.get(this)},run:function(a){var b,c=Kb.propHooks[this.prop];return this.pos=b=this.options.duration?n.easing[this.easing](a,this.options.duration*a,0,1,this.options.duration):a,this.now=(this.end-this.start)*b+this.start,this.options.step&&this.options.step.call(this.elem,this.now,this),c&&c.set?c.set(this):Kb.propHooks._default.set(this),this}},Kb.prototype.init.prototype=Kb.prototype,Kb.propHooks={_default:{get:function(a){var b;return null==a.elem[a.prop]||a.elem.style&&null!=a.elem.style[a.prop]?(b=n.css(a.elem,a.prop,""),b&&"auto"!==b?b:0):a.elem[a.prop]},set:function(a){n.fx.step[a.prop]?n.fx.step[a.prop](a):a.elem.style&&(null!=a.elem.style[n.cssProps[a.prop]]||n.cssHooks[a.prop])?n.style(a.elem,a.prop,a.now+a.unit):a.elem[a.prop]=a.now}}},Kb.propHooks.scrollTop=Kb.propHooks.scrollLeft={set:function(a){a.elem.nodeType&&a.elem.parentNode&&(a.elem[a.prop]=a.now)}},n.easing={linear:function(a){return a},swing:function(a){return.5-Math.cos(a*Math.PI)/2}},n.fx=Kb.prototype.init,n.fx.step={};var Lb,Mb,Nb=/^(?:toggle|show|hide)`$/,Ob=new RegExp("^(?:([+-])=|)("+Q+")([a-z%]*)`$","i"),Pb=/queueHooks`$/,Qb=[Vb],Rb={"*":[function(a,b){var c=this.createTween(a,b),d=c.cur(),e=Ob.exec(b),f=e&&e[3]||(n.cssNumber[a]?"":"px"),g=(n.cssNumber[a]||"px"!==f&&+d)&&Ob.exec(n.css(c.elem,a)),h=1,i=20;if(g&&g[3]!==f){f=f||g[3],e=e||[],g=+d||1;do h=h||".5",g/=h,n.style(c.elem,a,g+f);while(h!==(h=c.cur()/d)&&1!==h&&--i)}return e&&(g=c.start=+g||+d||0,c.unit=f,c.end=e[1]?g+(e[1]+1)*e[2]:+e[2]),c}]};function Sb(){return setTimeout(function(){Lb=void 0}),Lb=n.now()}function Tb(a,b){var c,d=0,e={height:a};for(b=b?1:0;4>d;d+=2-b)c=R[d],e["margin"+c]=e["padding"+c]=a;return b&&(e.opacity=e.width=a),e}function Ub(a,b,c){for(var d,e=(Rb[b]||[]).concat(Rb["*"]),f=0,g=e.length;g>f;f++)if(d=e[f].call(c,b,a))return d}function Vb(a,b,c){var d,e,f,g,h,i,j,k,l=this,m={},o=a.style,p=a.nodeType&&S(a),q=L.get(a,"fxshow");c.queue||(h=n._queueHooks(a,"fx"),null==h.unqueued&&(h.unqueued=0,i=h.empty.fire,h.empty.fire=function(){h.unqueued||i()}),h.unqueued++,l.always(function(){l.always(function(){h.unqueued--,n.queue(a,"fx").length||h.empty.fire()})})),1===a.nodeType&&("height"in b||"width"in b)&&(c.overflow=[o.overflow,o.overflowX,o.overflowY],j=n.css(a,"display"),k="none"===j?L.get(a,"olddisplay")||tb(a.nodeName):j,"inline"===k&&"none"===n.css(a,"float")&&(o.display="inline-block")),c.overflow&&(o.overflow="hidden",l.always(function(){o.overflow=c.overflow[0],o.overflowX=c.overflow[1],o.overflowY=c.overflow[2]}));for(d in b)if(e=b[d],Nb.exec(e)){if(delete b[d],f=f||"toggle"===e,e===(p?"hide":"show")){if("show"!==e||!q||void 0===q[d])continue;p=!0}m[d]=q&&q[d]||n.style(a,d)}else j=void 0;if(n.isEmptyObject(m))"inline"===("none"===j?tb(a.nodeName):j)&&(o.display=j);else{q?"hidden"in q&&(p=q.hidden):q=L.access(a,"fxshow",{}),f&&(q.hidden=!p),p?n(a).show():l.done(function(){n(a).hide()}),l.done(function(){var b;L.remove(a,"fxshow");for(b in m)n.style(a,b,m[b])});for(d in m)g=Ub(p?q[d]:0,d,l),d in q||(q[d]=g.start,p&&(g.end=g.start,g.start="width"===d||"height"===d?1:0))}}function Wb(a,b){var c,d,e,f,g;for(c in a)if(d=n.camelCase(c),e=b[d],f=a[c],n.isArray(f)&&(e=f[1],f=a[c]=f[0]),c!==d&&(a[d]=f,delete a[c]),g=n.cssHooks[d],g&&"expand"in g){f=g.expand(f),delete a[d];for(c in f)c in a||(a[c]=f[c],b[c]=e)}else b[d]=e}function Xb(a,b,c){var d,e,f=0,g=Qb.length,h=n.Deferred().always(function(){delete i.elem}),i=function(){if(e)return!1;for(var b=Lb||Sb(),c=Math.max(0,j.startTime+j.duration-b),d=c/j.duration||0,f=1-d,g=0,i=j.tweens.length;i>g;g++)j.tweens[g].run(f);return h.notifyWith(a,[j,f,c]),1>f&&i?c:(h.resolveWith(a,[j]),!1)},j=h.promise({elem:a,props:n.extend({},b),opts:n.extend(!0,{specialEasing:{}},c),originalProperties:b,originalOptions:c,startTime:Lb||Sb(),duration:c.duration,tweens:[],createTween:function(b,c){var d=n.Tween(a,j.opts,b,c,j.opts.specialEasing[b]||j.opts.easing);return j.tweens.push(d),d},stop:function(b){var c=0,d=b?j.tweens.length:0;if(e)return this;for(e=!0;d>c;c++)j.tweens[c].run(1);return b?h.resolveWith(a,[j,b]):h.rejectWith(a,[j,b]),this}}),k=j.props;for(Wb(k,j.opts.specialEasing);g>f;f++)if(d=Qb[f].call(j,a,k,j.opts))return d;return n.map(k,Ub,j),n.isFunction(j.opts.start)&&j.opts.start.call(a,j),n.fx.timer(n.extend(i,{elem:a,anim:j,queue:j.opts.queue})),j.progress(j.opts.progress).done(j.opts.done,j.opts.complete).fail(j.opts.fail).always(j.opts.always)}n.Animation=n.extend(Xb,{tweener:function(a,b){n.isFunction(a)?(b=a,a=["*"]):a=a.split(" ");for(var c,d=0,e=a.length;e>d;d++)c=a[d],Rb[c]=Rb[c]||[],Rb[c].unshift(b)},prefilter:function(a,b){b?Qb.unshift(a):Qb.push(a)}}),n.speed=function(a,b,c){var d=a&&"object"==typeof a?n.extend({},a):{complete:c||!c&&b||n.isFunction(a)&&a,duration:a,easing:c&&b||b&&!n.isFunction(b)&&b};return d.duration=n.fx.off?0:"number"==typeof d.duration?d.duration:d.duration in n.fx.speeds?n.fx.speeds[d.duration]:n.fx.speeds._default,(null==d.queue||d.queue===!0)&&(d.queue="fx"),d.old=d.complete,d.complete=function(){n.isFunction(d.old)&&d.old.call(this),d.queue&&n.dequeue(this,d.queue)},d},n.fn.extend({fadeTo:function(a,b,c,d){return this.filter(S).css("opacity",0).show().end().animate({opacity:b},a,c,d)},animate:function(a,b,c,d){var e=n.isEmptyObject(a),f=n.speed(b,c,d),g=function(){var b=Xb(this,n.extend({},a),f);(e||L.get(this,"finish"))&&b.stop(!0)};return g.finish=g,e||f.queue===!1?this.each(g):this.queue(f.queue,g)},stop:function(a,b,c){var d=function(a){var b=a.stop;delete a.stop,b(c)};return"string"!=typeof a&&(c=b,b=a,a=void 0),b&&a!==!1&&this.queue(a||"fx",[]),this.each(function(){var b=!0,e=null!=a&&a+"queueHooks",f=n.timers,g=L.get(this);if(e)g[e]&&g[e].stop&&d(g[e]);else for(e in g)g[e]&&g[e].stop&&Pb.test(e)&&d(g[e]);for(e=f.length;e--;)f[e].elem!==this||null!=a&&f[e].queue!==a||(f[e].anim.stop(c),b=!1,f.splice(e,1));(b||!c)&&n.dequeue(this,a)})},finish:function(a){return a!==!1&&(a=a||"fx"),this.each(function(){var b,c=L.get(this),d=c[a+"queue"],e=c[a+"queueHooks"],f=n.timers,g=d?d.length:0;for(c.finish=!0,n.queue(this,a,[]),e&&e.stop&&e.stop.call(this,!0),b=f.length;b--;)f[b].elem===this&&f[b].queue===a&&(f[b].anim.stop(!0),f.splice(b,1));for(b=0;g>b;b++)d[b]&&d[b].finish&&d[b].finish.call(this);delete c.finish})}}),n.each(["toggle","show","hide"],function(a,b){var c=n.fn[b];n.fn[b]=function(a,d,e){return null==a||"boolean"==typeof a?c.apply(this,arguments):this.animate(Tb(b,!0),a,d,e)}}),n.each({slideDown:Tb("show"),slideUp:Tb("hide"),slideToggle:Tb("toggle"),fadeIn:{opacity:"show"},fadeOut:{opacity:"hide"},fadeToggle:{opacity:"toggle"}},function(a,b){n.fn[a]=function(a,c,d){return this.animate(b,a,c,d)}}),n.timers=[],n.fx.tick=function(){var a,b=0,c=n.timers;for(Lb=n.now();b<c.length;b++)a=c[b],a()||c[b]!==a||c.splice(b--,1);c.length||n.fx.stop(),Lb=void 0},n.fx.timer=function(a){n.timers.push(a),a()?n.fx.start():n.timers.pop()},n.fx.interval=13,n.fx.start=function(){Mb||(Mb=setInterval(n.fx.tick,n.fx.interval))},n.fx.stop=function(){clearInterval(Mb),Mb=null},n.fx.speeds={slow:600,fast:200,_default:400},n.fn.delay=function(a,b){return a=n.fx?n.fx.speeds[a]||a:a,b=b||"fx",this.queue(b,function(b,c){var d=setTimeout(b,a);c.stop=function(){clearTimeout(d)}})},function(){var a=l.createElement("input"),b=l.createElement("select"),c=b.appendChild(l.createElement("option"));a.type="checkbox",k.checkOn=""!==a.value,k.optSelected=c.selected,b.disabled=!0,k.optDisabled=!c.disabled,a=l.createElement("input"),a.value="t",a.type="radio",k.radioValue="t"===a.value}();var Yb,Zb,`$b=n.expr.attrHandle;n.fn.extend({attr:function(a,b){return J(this,n.attr,a,b,arguments.length>1)},removeAttr:function(a){return this.each(function(){n.removeAttr(this,a)})}}),n.extend({attr:function(a,b,c){var d,e,f=a.nodeType;if(a&&3!==f&&8!==f&&2!==f)return typeof a.getAttribute===U?n.prop(a,b,c):(1===f&&n.isXMLDoc(a)||(b=b.toLowerCase(),d=n.attrHooks[b]||(n.expr.match.bool.test(b)?Zb:Yb)),void 0===c?d&&"get"in d&&null!==(e=d.get(a,b))?e:(e=n.find.attr(a,b),null==e?void 0:e):null!==c?d&&"set"in d&&void 0!==(e=d.set(a,c,b))?e:(a.setAttribute(b,c+""),c):void n.removeAttr(a,b))
},removeAttr:function(a,b){var c,d,e=0,f=b&&b.match(E);if(f&&1===a.nodeType)while(c=f[e++])d=n.propFix[c]||c,n.expr.match.bool.test(c)&&(a[d]=!1),a.removeAttribute(c)},attrHooks:{type:{set:function(a,b){if(!k.radioValue&&"radio"===b&&n.nodeName(a,"input")){var c=a.value;return a.setAttribute("type",b),c&&(a.value=c),b}}}}}),Zb={set:function(a,b,c){return b===!1?n.removeAttr(a,c):a.setAttribute(c,c),c}},n.each(n.expr.match.bool.source.match(/\w+/g),function(a,b){var c=`$b[b]||n.find.attr;`$b[b]=function(a,b,d){var e,f;return d||(f=`$b[b],`$b[b]=e,e=null!=c(a,b,d)?b.toLowerCase():null,`$b[b]=f),e}});var _b=/^(?:input|select|textarea|button)`$/i;n.fn.extend({prop:function(a,b){return J(this,n.prop,a,b,arguments.length>1)},removeProp:function(a){return this.each(function(){delete this[n.propFix[a]||a]})}}),n.extend({propFix:{"for":"htmlFor","class":"className"},prop:function(a,b,c){var d,e,f,g=a.nodeType;if(a&&3!==g&&8!==g&&2!==g)return f=1!==g||!n.isXMLDoc(a),f&&(b=n.propFix[b]||b,e=n.propHooks[b]),void 0!==c?e&&"set"in e&&void 0!==(d=e.set(a,c,b))?d:a[b]=c:e&&"get"in e&&null!==(d=e.get(a,b))?d:a[b]},propHooks:{tabIndex:{get:function(a){return a.hasAttribute("tabindex")||_b.test(a.nodeName)||a.href?a.tabIndex:-1}}}}),k.optSelected||(n.propHooks.selected={get:function(a){var b=a.parentNode;return b&&b.parentNode&&b.parentNode.selectedIndex,null}}),n.each(["tabIndex","readOnly","maxLength","cellSpacing","cellPadding","rowSpan","colSpan","useMap","frameBorder","contentEditable"],function(){n.propFix[this.toLowerCase()]=this});var ac=/[\t\r\n\f]/g;n.fn.extend({addClass:function(a){var b,c,d,e,f,g,h="string"==typeof a&&a,i=0,j=this.length;if(n.isFunction(a))return this.each(function(b){n(this).addClass(a.call(this,b,this.className))});if(h)for(b=(a||"").match(E)||[];j>i;i++)if(c=this[i],d=1===c.nodeType&&(c.className?(" "+c.className+" ").replace(ac," "):" ")){f=0;while(e=b[f++])d.indexOf(" "+e+" ")<0&&(d+=e+" ");g=n.trim(d),c.className!==g&&(c.className=g)}return this},removeClass:function(a){var b,c,d,e,f,g,h=0===arguments.length||"string"==typeof a&&a,i=0,j=this.length;if(n.isFunction(a))return this.each(function(b){n(this).removeClass(a.call(this,b,this.className))});if(h)for(b=(a||"").match(E)||[];j>i;i++)if(c=this[i],d=1===c.nodeType&&(c.className?(" "+c.className+" ").replace(ac," "):"")){f=0;while(e=b[f++])while(d.indexOf(" "+e+" ")>=0)d=d.replace(" "+e+" "," ");g=a?n.trim(d):"",c.className!==g&&(c.className=g)}return this},toggleClass:function(a,b){var c=typeof a;return"boolean"==typeof b&&"string"===c?b?this.addClass(a):this.removeClass(a):this.each(n.isFunction(a)?function(c){n(this).toggleClass(a.call(this,c,this.className,b),b)}:function(){if("string"===c){var b,d=0,e=n(this),f=a.match(E)||[];while(b=f[d++])e.hasClass(b)?e.removeClass(b):e.addClass(b)}else(c===U||"boolean"===c)&&(this.className&&L.set(this,"__className__",this.className),this.className=this.className||a===!1?"":L.get(this,"__className__")||"")})},hasClass:function(a){for(var b=" "+a+" ",c=0,d=this.length;d>c;c++)if(1===this[c].nodeType&&(" "+this[c].className+" ").replace(ac," ").indexOf(b)>=0)return!0;return!1}});var bc=/\r/g;n.fn.extend({val:function(a){var b,c,d,e=this[0];{if(arguments.length)return d=n.isFunction(a),this.each(function(c){var e;1===this.nodeType&&(e=d?a.call(this,c,n(this).val()):a,null==e?e="":"number"==typeof e?e+="":n.isArray(e)&&(e=n.map(e,function(a){return null==a?"":a+""})),b=n.valHooks[this.type]||n.valHooks[this.nodeName.toLowerCase()],b&&"set"in b&&void 0!==b.set(this,e,"value")||(this.value=e))});if(e)return b=n.valHooks[e.type]||n.valHooks[e.nodeName.toLowerCase()],b&&"get"in b&&void 0!==(c=b.get(e,"value"))?c:(c=e.value,"string"==typeof c?c.replace(bc,""):null==c?"":c)}}}),n.extend({valHooks:{option:{get:function(a){var b=n.find.attr(a,"value");return null!=b?b:n.trim(n.text(a))}},select:{get:function(a){for(var b,c,d=a.options,e=a.selectedIndex,f="select-one"===a.type||0>e,g=f?null:[],h=f?e+1:d.length,i=0>e?h:f?e:0;h>i;i++)if(c=d[i],!(!c.selected&&i!==e||(k.optDisabled?c.disabled:null!==c.getAttribute("disabled"))||c.parentNode.disabled&&n.nodeName(c.parentNode,"optgroup"))){if(b=n(c).val(),f)return b;g.push(b)}return g},set:function(a,b){var c,d,e=a.options,f=n.makeArray(b),g=e.length;while(g--)d=e[g],(d.selected=n.inArray(d.value,f)>=0)&&(c=!0);return c||(a.selectedIndex=-1),f}}}}),n.each(["radio","checkbox"],function(){n.valHooks[this]={set:function(a,b){return n.isArray(b)?a.checked=n.inArray(n(a).val(),b)>=0:void 0}},k.checkOn||(n.valHooks[this].get=function(a){return null===a.getAttribute("value")?"on":a.value})}),n.each("blur focus focusin focusout load resize scroll unload click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup error contextmenu".split(" "),function(a,b){n.fn[b]=function(a,c){return arguments.length>0?this.on(b,null,a,c):this.trigger(b)}}),n.fn.extend({hover:function(a,b){return this.mouseenter(a).mouseleave(b||a)},bind:function(a,b,c){return this.on(a,null,b,c)},unbind:function(a,b){return this.off(a,null,b)},delegate:function(a,b,c,d){return this.on(b,a,c,d)},undelegate:function(a,b,c){return 1===arguments.length?this.off(a,"**"):this.off(b,a||"**",c)}});var cc=n.now(),dc=/\?/;n.parseJSON=function(a){return JSON.parse(a+"")},n.parseXML=function(a){var b,c;if(!a||"string"!=typeof a)return null;try{c=new DOMParser,b=c.parseFromString(a,"text/xml")}catch(d){b=void 0}return(!b||b.getElementsByTagName("parsererror").length)&&n.error("Invalid XML: "+a),b};var ec=/#.*`$/,fc=/([?&])_=[^&]*/,gc=/^(.*?):[ \t]*([^\r\n]*)`$/gm,hc=/^(?:about|app|app-storage|.+-extension|file|res|widget):`$/,ic=/^(?:GET|HEAD)`$/,jc=/^\/\//,kc=/^([\w.+-]+:)(?:\/\/(?:[^\/?#]*@|)([^\/?#:]*)(?::(\d+)|)|)/,lc={},mc={},nc="*/".concat("*"),oc=a.location.href,pc=kc.exec(oc.toLowerCase())||[];function qc(a){return function(b,c){"string"!=typeof b&&(c=b,b="*");var d,e=0,f=b.toLowerCase().match(E)||[];if(n.isFunction(c))while(d=f[e++])"+"===d[0]?(d=d.slice(1)||"*",(a[d]=a[d]||[]).unshift(c)):(a[d]=a[d]||[]).push(c)}}function rc(a,b,c,d){var e={},f=a===mc;function g(h){var i;return e[h]=!0,n.each(a[h]||[],function(a,h){var j=h(b,c,d);return"string"!=typeof j||f||e[j]?f?!(i=j):void 0:(b.dataTypes.unshift(j),g(j),!1)}),i}return g(b.dataTypes[0])||!e["*"]&&g("*")}function sc(a,b){var c,d,e=n.ajaxSettings.flatOptions||{};for(c in b)void 0!==b[c]&&((e[c]?a:d||(d={}))[c]=b[c]);return d&&n.extend(!0,a,d),a}function tc(a,b,c){var d,e,f,g,h=a.contents,i=a.dataTypes;while("*"===i[0])i.shift(),void 0===d&&(d=a.mimeType||b.getResponseHeader("Content-Type"));if(d)for(e in h)if(h[e]&&h[e].test(d)){i.unshift(e);break}if(i[0]in c)f=i[0];else{for(e in c){if(!i[0]||a.converters[e+" "+i[0]]){f=e;break}g||(g=e)}f=f||g}return f?(f!==i[0]&&i.unshift(f),c[f]):void 0}function uc(a,b,c,d){var e,f,g,h,i,j={},k=a.dataTypes.slice();if(k[1])for(g in a.converters)j[g.toLowerCase()]=a.converters[g];f=k.shift();while(f)if(a.responseFields[f]&&(c[a.responseFields[f]]=b),!i&&d&&a.dataFilter&&(b=a.dataFilter(b,a.dataType)),i=f,f=k.shift())if("*"===f)f=i;else if("*"!==i&&i!==f){if(g=j[i+" "+f]||j["* "+f],!g)for(e in j)if(h=e.split(" "),h[1]===f&&(g=j[i+" "+h[0]]||j["* "+h[0]])){g===!0?g=j[e]:j[e]!==!0&&(f=h[0],k.unshift(h[1]));break}if(g!==!0)if(g&&a["throws"])b=g(b);else try{b=g(b)}catch(l){return{state:"parsererror",error:g?l:"No conversion from "+i+" to "+f}}}return{state:"success",data:b}}n.extend({active:0,lastModified:{},etag:{},ajaxSettings:{url:oc,type:"GET",isLocal:hc.test(pc[1]),global:!0,processData:!0,async:!0,contentType:"application/x-www-form-urlencoded; charset=UTF-8",accepts:{"*":nc,text:"text/plain",html:"text/html",xml:"application/xml, text/xml",json:"application/json, text/javascript"},contents:{xml:/xml/,html:/html/,json:/json/},responseFields:{xml:"responseXML",text:"responseText",json:"responseJSON"},converters:{"* text":String,"text html":!0,"text json":n.parseJSON,"text xml":n.parseXML},flatOptions:{url:!0,context:!0}},ajaxSetup:function(a,b){return b?sc(sc(a,n.ajaxSettings),b):sc(n.ajaxSettings,a)},ajaxPrefilter:qc(lc),ajaxTransport:qc(mc),ajax:function(a,b){"object"==typeof a&&(b=a,a=void 0),b=b||{};var c,d,e,f,g,h,i,j,k=n.ajaxSetup({},b),l=k.context||k,m=k.context&&(l.nodeType||l.jquery)?n(l):n.event,o=n.Deferred(),p=n.Callbacks("once memory"),q=k.statusCode||{},r={},s={},t=0,u="canceled",v={readyState:0,getResponseHeader:function(a){var b;if(2===t){if(!f){f={};while(b=gc.exec(e))f[b[1].toLowerCase()]=b[2]}b=f[a.toLowerCase()]}return null==b?null:b},getAllResponseHeaders:function(){return 2===t?e:null},setRequestHeader:function(a,b){var c=a.toLowerCase();return t||(a=s[c]=s[c]||a,r[a]=b),this},overrideMimeType:function(a){return t||(k.mimeType=a),this},statusCode:function(a){var b;if(a)if(2>t)for(b in a)q[b]=[q[b],a[b]];else v.always(a[v.status]);return this},abort:function(a){var b=a||u;return c&&c.abort(b),x(0,b),this}};if(o.promise(v).complete=p.add,v.success=v.done,v.error=v.fail,k.url=((a||k.url||oc)+"").replace(ec,"").replace(jc,pc[1]+"//"),k.type=b.method||b.type||k.method||k.type,k.dataTypes=n.trim(k.dataType||"*").toLowerCase().match(E)||[""],null==k.crossDomain&&(h=kc.exec(k.url.toLowerCase()),k.crossDomain=!(!h||h[1]===pc[1]&&h[2]===pc[2]&&(h[3]||("http:"===h[1]?"80":"443"))===(pc[3]||("http:"===pc[1]?"80":"443")))),k.data&&k.processData&&"string"!=typeof k.data&&(k.data=n.param(k.data,k.traditional)),rc(lc,k,b,v),2===t)return v;i=n.event&&k.global,i&&0===n.active++&&n.event.trigger("ajaxStart"),k.type=k.type.toUpperCase(),k.hasContent=!ic.test(k.type),d=k.url,k.hasContent||(k.data&&(d=k.url+=(dc.test(d)?"&":"?")+k.data,delete k.data),k.cache===!1&&(k.url=fc.test(d)?d.replace(fc,"`$1_="+cc++):d+(dc.test(d)?"&":"?")+"_="+cc++)),k.ifModified&&(n.lastModified[d]&&v.setRequestHeader("If-Modified-Since",n.lastModified[d]),n.etag[d]&&v.setRequestHeader("If-None-Match",n.etag[d])),(k.data&&k.hasContent&&k.contentType!==!1||b.contentType)&&v.setRequestHeader("Content-Type",k.contentType),v.setRequestHeader("Accept",k.dataTypes[0]&&k.accepts[k.dataTypes[0]]?k.accepts[k.dataTypes[0]]+("*"!==k.dataTypes[0]?", "+nc+"; q=0.01":""):k.accepts["*"]);for(j in k.headers)v.setRequestHeader(j,k.headers[j]);if(k.beforeSend&&(k.beforeSend.call(l,v,k)===!1||2===t))return v.abort();u="abort";for(j in{success:1,error:1,complete:1})v[j](k[j]);if(c=rc(mc,k,b,v)){v.readyState=1,i&&m.trigger("ajaxSend",[v,k]),k.async&&k.timeout>0&&(g=setTimeout(function(){v.abort("timeout")},k.timeout));try{t=1,c.send(r,x)}catch(w){if(!(2>t))throw w;x(-1,w)}}else x(-1,"No Transport");function x(a,b,f,h){var j,r,s,u,w,x=b;2!==t&&(t=2,g&&clearTimeout(g),c=void 0,e=h||"",v.readyState=a>0?4:0,j=a>=200&&300>a||304===a,f&&(u=tc(k,v,f)),u=uc(k,u,v,j),j?(k.ifModified&&(w=v.getResponseHeader("Last-Modified"),w&&(n.lastModified[d]=w),w=v.getResponseHeader("etag"),w&&(n.etag[d]=w)),204===a||"HEAD"===k.type?x="nocontent":304===a?x="notmodified":(x=u.state,r=u.data,s=u.error,j=!s)):(s=x,(a||!x)&&(x="error",0>a&&(a=0))),v.status=a,v.statusText=(b||x)+"",j?o.resolveWith(l,[r,x,v]):o.rejectWith(l,[v,x,s]),v.statusCode(q),q=void 0,i&&m.trigger(j?"ajaxSuccess":"ajaxError",[v,k,j?r:s]),p.fireWith(l,[v,x]),i&&(m.trigger("ajaxComplete",[v,k]),--n.active||n.event.trigger("ajaxStop")))}return v},getJSON:function(a,b,c){return n.get(a,b,c,"json")},getScript:function(a,b){return n.get(a,void 0,b,"script")}}),n.each(["get","post"],function(a,b){n[b]=function(a,c,d,e){return n.isFunction(c)&&(e=e||d,d=c,c=void 0),n.ajax({url:a,type:b,dataType:e,data:c,success:d})}}),n._evalUrl=function(a){return n.ajax({url:a,type:"GET",dataType:"script",async:!1,global:!1,"throws":!0})},n.fn.extend({wrapAll:function(a){var b;return n.isFunction(a)?this.each(function(b){n(this).wrapAll(a.call(this,b))}):(this[0]&&(b=n(a,this[0].ownerDocument).eq(0).clone(!0),this[0].parentNode&&b.insertBefore(this[0]),b.map(function(){var a=this;while(a.firstElementChild)a=a.firstElementChild;return a}).append(this)),this)},wrapInner:function(a){return this.each(n.isFunction(a)?function(b){n(this).wrapInner(a.call(this,b))}:function(){var b=n(this),c=b.contents();c.length?c.wrapAll(a):b.append(a)})},wrap:function(a){var b=n.isFunction(a);return this.each(function(c){n(this).wrapAll(b?a.call(this,c):a)})},unwrap:function(){return this.parent().each(function(){n.nodeName(this,"body")||n(this).replaceWith(this.childNodes)}).end()}}),n.expr.filters.hidden=function(a){return a.offsetWidth<=0&&a.offsetHeight<=0},n.expr.filters.visible=function(a){return!n.expr.filters.hidden(a)};var vc=/%20/g,wc=/\[\]`$/,xc=/\r?\n/g,yc=/^(?:submit|button|image|reset|file)`$/i,zc=/^(?:input|select|textarea|keygen)/i;function Ac(a,b,c,d){var e;if(n.isArray(b))n.each(b,function(b,e){c||wc.test(a)?d(a,e):Ac(a+"["+("object"==typeof e?b:"")+"]",e,c,d)});else if(c||"object"!==n.type(b))d(a,b);else for(e in b)Ac(a+"["+e+"]",b[e],c,d)}n.param=function(a,b){var c,d=[],e=function(a,b){b=n.isFunction(b)?b():null==b?"":b,d[d.length]=encodeURIComponent(a)+"="+encodeURIComponent(b)};if(void 0===b&&(b=n.ajaxSettings&&n.ajaxSettings.traditional),n.isArray(a)||a.jquery&&!n.isPlainObject(a))n.each(a,function(){e(this.name,this.value)});else for(c in a)Ac(c,a[c],b,e);return d.join("&").replace(vc,"+")},n.fn.extend({serialize:function(){return n.param(this.serializeArray())},serializeArray:function(){return this.map(function(){var a=n.prop(this,"elements");return a?n.makeArray(a):this}).filter(function(){var a=this.type;return this.name&&!n(this).is(":disabled")&&zc.test(this.nodeName)&&!yc.test(a)&&(this.checked||!T.test(a))}).map(function(a,b){var c=n(this).val();return null==c?null:n.isArray(c)?n.map(c,function(a){return{name:b.name,value:a.replace(xc,"\r\n")}}):{name:b.name,value:c.replace(xc,"\r\n")}}).get()}}),n.ajaxSettings.xhr=function(){try{return new XMLHttpRequest}catch(a){}};var Bc=0,Cc={},Dc={0:200,1223:204},Ec=n.ajaxSettings.xhr();a.attachEvent&&a.attachEvent("onunload",function(){for(var a in Cc)Cc[a]()}),k.cors=!!Ec&&"withCredentials"in Ec,k.ajax=Ec=!!Ec,n.ajaxTransport(function(a){var b;return k.cors||Ec&&!a.crossDomain?{send:function(c,d){var e,f=a.xhr(),g=++Bc;if(f.open(a.type,a.url,a.async,a.username,a.password),a.xhrFields)for(e in a.xhrFields)f[e]=a.xhrFields[e];a.mimeType&&f.overrideMimeType&&f.overrideMimeType(a.mimeType),a.crossDomain||c["X-Requested-With"]||(c["X-Requested-With"]="XMLHttpRequest");for(e in c)f.setRequestHeader(e,c[e]);b=function(a){return function(){b&&(delete Cc[g],b=f.onload=f.onerror=null,"abort"===a?f.abort():"error"===a?d(f.status,f.statusText):d(Dc[f.status]||f.status,f.statusText,"string"==typeof f.responseText?{text:f.responseText}:void 0,f.getAllResponseHeaders()))}},f.onload=b(),f.onerror=b("error"),b=Cc[g]=b("abort");try{f.send(a.hasContent&&a.data||null)}catch(h){if(b)throw h}},abort:function(){b&&b()}}:void 0}),n.ajaxSetup({accepts:{script:"text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"},contents:{script:/(?:java|ecma)script/},converters:{"text script":function(a){return n.globalEval(a),a}}}),n.ajaxPrefilter("script",function(a){void 0===a.cache&&(a.cache=!1),a.crossDomain&&(a.type="GET")}),n.ajaxTransport("script",function(a){if(a.crossDomain){var b,c;return{send:function(d,e){b=n("<script>").prop({async:!0,charset:a.scriptCharset,src:a.url}).on("load error",c=function(a){b.remove(),c=null,a&&e("error"===a.type?404:200,a.type)}),l.head.appendChild(b[0])},abort:function(){c&&c()}}}});var Fc=[],Gc=/(=)\?(?=&|`$)|\?\?/;n.ajaxSetup({jsonp:"callback",jsonpCallback:function(){var a=Fc.pop()||n.expando+"_"+cc++;return this[a]=!0,a}}),n.ajaxPrefilter("json jsonp",function(b,c,d){var e,f,g,h=b.jsonp!==!1&&(Gc.test(b.url)?"url":"string"==typeof b.data&&!(b.contentType||"").indexOf("application/x-www-form-urlencoded")&&Gc.test(b.data)&&"data");return h||"jsonp"===b.dataTypes[0]?(e=b.jsonpCallback=n.isFunction(b.jsonpCallback)?b.jsonpCallback():b.jsonpCallback,h?b[h]=b[h].replace(Gc,"`$1"+e):b.jsonp!==!1&&(b.url+=(dc.test(b.url)?"&":"?")+b.jsonp+"="+e),b.converters["script json"]=function(){return g||n.error(e+" was not called"),g[0]},b.dataTypes[0]="json",f=a[e],a[e]=function(){g=arguments},d.always(function(){a[e]=f,b[e]&&(b.jsonpCallback=c.jsonpCallback,Fc.push(e)),g&&n.isFunction(f)&&f(g[0]),g=f=void 0}),"script"):void 0}),n.parseHTML=function(a,b,c){if(!a||"string"!=typeof a)return null;"boolean"==typeof b&&(c=b,b=!1),b=b||l;var d=v.exec(a),e=!c&&[];return d?[b.createElement(d[1])]:(d=n.buildFragment([a],b,e),e&&e.length&&n(e).remove(),n.merge([],d.childNodes))};var Hc=n.fn.load;n.fn.load=function(a,b,c){if("string"!=typeof a&&Hc)return Hc.apply(this,arguments);var d,e,f,g=this,h=a.indexOf(" ");return h>=0&&(d=n.trim(a.slice(h)),a=a.slice(0,h)),n.isFunction(b)?(c=b,b=void 0):b&&"object"==typeof b&&(e="POST"),g.length>0&&n.ajax({url:a,type:e,dataType:"html",data:b}).done(function(a){f=arguments,g.html(d?n("<div>").append(n.parseHTML(a)).find(d):a)}).complete(c&&function(a,b){g.each(c,f||[a.responseText,b,a])}),this},n.each(["ajaxStart","ajaxStop","ajaxComplete","ajaxError","ajaxSuccess","ajaxSend"],function(a,b){n.fn[b]=function(a){return this.on(b,a)}}),n.expr.filters.animated=function(a){return n.grep(n.timers,function(b){return a===b.elem}).length};var Ic=a.document.documentElement;function Jc(a){return n.isWindow(a)?a:9===a.nodeType&&a.defaultView}n.offset={setOffset:function(a,b,c){var d,e,f,g,h,i,j,k=n.css(a,"position"),l=n(a),m={};"static"===k&&(a.style.position="relative"),h=l.offset(),f=n.css(a,"top"),i=n.css(a,"left"),j=("absolute"===k||"fixed"===k)&&(f+i).indexOf("auto")>-1,j?(d=l.position(),g=d.top,e=d.left):(g=parseFloat(f)||0,e=parseFloat(i)||0),n.isFunction(b)&&(b=b.call(a,c,h)),null!=b.top&&(m.top=b.top-h.top+g),null!=b.left&&(m.left=b.left-h.left+e),"using"in b?b.using.call(a,m):l.css(m)}},n.fn.extend({offset:function(a){if(arguments.length)return void 0===a?this:this.each(function(b){n.offset.setOffset(this,a,b)});var b,c,d=this[0],e={top:0,left:0},f=d&&d.ownerDocument;if(f)return b=f.documentElement,n.contains(b,d)?(typeof d.getBoundingClientRect!==U&&(e=d.getBoundingClientRect()),c=Jc(f),{top:e.top+c.pageYOffset-b.clientTop,left:e.left+c.pageXOffset-b.clientLeft}):e},position:function(){if(this[0]){var a,b,c=this[0],d={top:0,left:0};return"fixed"===n.css(c,"position")?b=c.getBoundingClientRect():(a=this.offsetParent(),b=this.offset(),n.nodeName(a[0],"html")||(d=a.offset()),d.top+=n.css(a[0],"borderTopWidth",!0),d.left+=n.css(a[0],"borderLeftWidth",!0)),{top:b.top-d.top-n.css(c,"marginTop",!0),left:b.left-d.left-n.css(c,"marginLeft",!0)}}},offsetParent:function(){return this.map(function(){var a=this.offsetParent||Ic;while(a&&!n.nodeName(a,"html")&&"static"===n.css(a,"position"))a=a.offsetParent;return a||Ic})}}),n.each({scrollLeft:"pageXOffset",scrollTop:"pageYOffset"},function(b,c){var d="pageYOffset"===c;n.fn[b]=function(e){return J(this,function(b,e,f){var g=Jc(b);return void 0===f?g?g[c]:b[e]:void(g?g.scrollTo(d?a.pageXOffset:f,d?f:a.pageYOffset):b[e]=f)},b,e,arguments.length,null)}}),n.each(["top","left"],function(a,b){n.cssHooks[b]=yb(k.pixelPosition,function(a,c){return c?(c=xb(a,b),vb.test(c)?n(a).position()[b]+"px":c):void 0})}),n.each({Height:"height",Width:"width"},function(a,b){n.each({padding:"inner"+a,content:b,"":"outer"+a},function(c,d){n.fn[d]=function(d,e){var f=arguments.length&&(c||"boolean"!=typeof d),g=c||(d===!0||e===!0?"margin":"border");return J(this,function(b,c,d){var e;return n.isWindow(b)?b.document.documentElement["client"+a]:9===b.nodeType?(e=b.documentElement,Math.max(b.body["scroll"+a],e["scroll"+a],b.body["offset"+a],e["offset"+a],e["client"+a])):void 0===d?n.css(b,c,g):n.style(b,c,d,g)},b,f?d:void 0,f,null)}})}),n.fn.size=function(){return this.length},n.fn.andSelf=n.fn.addBack,"function"==typeof define&&define.amd&&define("jquery",[],function(){return n});var Kc=a.jQuery,Lc=a.`$;return n.noConflict=function(b){return a.`$===n&&(a.`$=Lc),b&&a.jQuery===n&&(a.jQuery=Kc),n},typeof b===U&&(a.jQuery=a.`$=n),n});
//]]>
</script>
<script type="text/javascript">//<![CDATA[
/*! Magnific Popup - v0.9.9 - 2013-11-15
* http://dimsemenov.com/plugins/magnific-popup/
* Copyright (c) 2013 Dmitry Semenov; */
(function(e){var t,n,i,o,r,a,s,l="Close",c="BeforeClose",d="AfterClose",u="BeforeAppend",p="MarkupParse",f="Open",m="Change",g="mfp",v="."+g,h="mfp-ready",C="mfp-removing",y="mfp-prevent-close",w=function(){},b=!!window.jQuery,I=e(window),x=function(e,n){t.ev.on(g+e+v,n)},k=function(t,n,i,o){var r=document.createElement("div");return r.className="mfp-"+t,i&&(r.innerHTML=i),o?n&&n.appendChild(r):(r=e(r),n&&r.appendTo(n)),r},T=function(n,i){t.ev.triggerHandler(g+n,i),t.st.callbacks&&(n=n.charAt(0).toLowerCase()+n.slice(1),t.st.callbacks[n]&&t.st.callbacks[n].apply(t,e.isArray(i)?i:[i]))},E=function(n){return n===s&&t.currTemplate.closeBtn||(t.currTemplate.closeBtn=e(t.st.closeMarkup.replace("%title%",t.st.tClose)),s=n),t.currTemplate.closeBtn},_=function(){e.magnificPopup.instance||(t=new w,t.init(),e.magnificPopup.instance=t)},S=function(){var e=document.createElement("p").style,t=["ms","O","Moz","Webkit"];if(void 0!==e.transition)return!0;for(;t.length;)if(t.pop()+"Transition"in e)return!0;return!1};w.prototype={constructor:w,init:function(){var n=navigator.appVersion;t.isIE7=-1!==n.indexOf("MSIE 7."),t.isIE8=-1!==n.indexOf("MSIE 8."),t.isLowIE=t.isIE7||t.isIE8,t.isAndroid=/android/gi.test(n),t.isIOS=/iphone|ipad|ipod/gi.test(n),t.supportsTransition=S(),t.probablyMobile=t.isAndroid||t.isIOS||/(Opera Mini)|Kindle|webOS|BlackBerry|(Opera Mobi)|(Windows Phone)|IEMobile/i.test(navigator.userAgent),i=e(document.body),o=e(document),t.popupsCache={}},open:function(n){var i;if(n.isObj===!1){t.items=n.items.toArray(),t.index=0;var r,s=n.items;for(i=0;s.length>i;i++)if(r=s[i],r.parsed&&(r=r.el[0]),r===n.el[0]){t.index=i;break}}else t.items=e.isArray(n.items)?n.items:[n.items],t.index=n.index||0;if(t.isOpen)return t.updateItemHTML(),void 0;t.types=[],a="",t.ev=n.mainEl&&n.mainEl.length?n.mainEl.eq(0):o,n.key?(t.popupsCache[n.key]||(t.popupsCache[n.key]={}),t.currTemplate=t.popupsCache[n.key]):t.currTemplate={},t.st=e.extend(!0,{},e.magnificPopup.defaults,n),t.fixedContentPos="auto"===t.st.fixedContentPos?!t.probablyMobile:t.st.fixedContentPos,t.st.modal&&(t.st.closeOnContentClick=!1,t.st.closeOnBgClick=!1,t.st.showCloseBtn=!1,t.st.enableEscapeKey=!1),t.bgOverlay||(t.bgOverlay=k("bg").on("click"+v,function(){t.close()}),t.wrap=k("wrap").attr("tabindex",-1).on("click"+v,function(e){t._checkIfClose(e.target)&&t.close()}),t.container=k("container",t.wrap)),t.contentContainer=k("content"),t.st.preloader&&(t.preloader=k("preloader",t.container,t.st.tLoading));var l=e.magnificPopup.modules;for(i=0;l.length>i;i++){var c=l[i];c=c.charAt(0).toUpperCase()+c.slice(1),t["init"+c].call(t)}T("BeforeOpen"),t.st.showCloseBtn&&(t.st.closeBtnInside?(x(p,function(e,t,n,i){n.close_replaceWith=E(i.type)}),a+=" mfp-close-btn-in"):t.wrap.append(E())),t.st.alignTop&&(a+=" mfp-align-top"),t.fixedContentPos?t.wrap.css({overflow:t.st.overflowY,overflowX:"hidden",overflowY:t.st.overflowY}):t.wrap.css({top:I.scrollTop(),position:"absolute"}),(t.st.fixedBgPos===!1||"auto"===t.st.fixedBgPos&&!t.fixedContentPos)&&t.bgOverlay.css({height:o.height(),position:"absolute"}),t.st.enableEscapeKey&&o.on("keyup"+v,function(e){27===e.keyCode&&t.close()}),I.on("resize"+v,function(){t.updateSize()}),t.st.closeOnContentClick||(a+=" mfp-auto-cursor"),a&&t.wrap.addClass(a);var d=t.wH=I.height(),u={};if(t.fixedContentPos&&t._hasScrollBar(d)){var m=t._getScrollbarSize();m&&(u.marginRight=m)}t.fixedContentPos&&(t.isIE7?e("body, html").css("overflow","hidden"):u.overflow="hidden");var g=t.st.mainClass;return t.isIE7&&(g+=" mfp-ie7"),g&&t._addClassToMFP(g),t.updateItemHTML(),T("BuildControls"),e("html").css(u),t.bgOverlay.add(t.wrap).prependTo(document.body),t._lastFocusedEl=document.activeElement,setTimeout(function(){t.content?(t._addClassToMFP(h),t._setFocus()):t.bgOverlay.addClass(h),o.on("focusin"+v,t._onFocusIn)},16),t.isOpen=!0,t.updateSize(d),T(f),n},close:function(){t.isOpen&&(T(c),t.isOpen=!1,t.st.removalDelay&&!t.isLowIE&&t.supportsTransition?(t._addClassToMFP(C),setTimeout(function(){t._close()},t.st.removalDelay)):t._close())},_close:function(){T(l);var n=C+" "+h+" ";if(t.bgOverlay.detach(),t.wrap.detach(),t.container.empty(),t.st.mainClass&&(n+=t.st.mainClass+" "),t._removeClassFromMFP(n),t.fixedContentPos){var i={marginRight:""};t.isIE7?e("body, html").css("overflow",""):i.overflow="",e("html").css(i)}o.off("keyup"+v+" focusin"+v),t.ev.off(v),t.wrap.attr("class","mfp-wrap").removeAttr("style"),t.bgOverlay.attr("class","mfp-bg"),t.container.attr("class","mfp-container"),!t.st.showCloseBtn||t.st.closeBtnInside&&t.currTemplate[t.currItem.type]!==!0||t.currTemplate.closeBtn&&t.currTemplate.closeBtn.detach(),t._lastFocusedEl&&e(t._lastFocusedEl).focus(),t.currItem=null,t.content=null,t.currTemplate=null,t.prevHeight=0,T(d)},updateSize:function(e){if(t.isIOS){var n=document.documentElement.clientWidth/window.innerWidth,i=window.innerHeight*n;t.wrap.css("height",i),t.wH=i}else t.wH=e||I.height();t.fixedContentPos||t.wrap.css("height",t.wH),T("Resize")},updateItemHTML:function(){var n=t.items[t.index];t.contentContainer.detach(),t.content&&t.content.detach(),n.parsed||(n=t.parseEl(t.index));var i=n.type;if(T("BeforeChange",[t.currItem?t.currItem.type:"",i]),t.currItem=n,!t.currTemplate[i]){var o=t.st[i]?t.st[i].markup:!1;T("FirstMarkupParse",o),t.currTemplate[i]=o?e(o):!0}r&&r!==n.type&&t.container.removeClass("mfp-"+r+"-holder");var a=t["get"+i.charAt(0).toUpperCase()+i.slice(1)](n,t.currTemplate[i]);t.appendContent(a,i),n.preloaded=!0,T(m,n),r=n.type,t.container.prepend(t.contentContainer),T("AfterChange")},appendContent:function(e,n){t.content=e,e?t.st.showCloseBtn&&t.st.closeBtnInside&&t.currTemplate[n]===!0?t.content.find(".mfp-close").length||t.content.append(E()):t.content=e:t.content="",T(u),t.container.addClass("mfp-"+n+"-holder"),t.contentContainer.append(t.content)},parseEl:function(n){var i=t.items[n],o=i.type;if(i=i.tagName?{el:e(i)}:{data:i,src:i.src},i.el){for(var r=t.types,a=0;r.length>a;a++)if(i.el.hasClass("mfp-"+r[a])){o=r[a];break}i.src=i.el.attr("data-mfp-src"),i.src||(i.src=i.el.attr("href"))}return i.type=o||t.st.type||"inline",i.index=n,i.parsed=!0,t.items[n]=i,T("ElementParse",i),t.items[n]},addGroup:function(e,n){var i=function(i){i.mfpEl=this,t._openClick(i,e,n)};n||(n={});var o="click.magnificPopup";n.mainEl=e,n.items?(n.isObj=!0,e.off(o).on(o,i)):(n.isObj=!1,n.delegate?e.off(o).on(o,n.delegate,i):(n.items=e,e.off(o).on(o,i)))},_openClick:function(n,i,o){var r=void 0!==o.midClick?o.midClick:e.magnificPopup.defaults.midClick;if(r||2!==n.which&&!n.ctrlKey&&!n.metaKey){var a=void 0!==o.disableOn?o.disableOn:e.magnificPopup.defaults.disableOn;if(a)if(e.isFunction(a)){if(!a.call(t))return!0}else if(a>I.width())return!0;n.type&&(n.preventDefault(),t.isOpen&&n.stopPropagation()),o.el=e(n.mfpEl),o.delegate&&(o.items=i.find(o.delegate)),t.open(o)}},updateStatus:function(e,i){if(t.preloader){n!==e&&t.container.removeClass("mfp-s-"+n),i||"loading"!==e||(i=t.st.tLoading);var o={status:e,text:i};T("UpdateStatus",o),e=o.status,i=o.text,t.preloader.html(i),t.preloader.find("a").on("click",function(e){e.stopImmediatePropagation()}),t.container.addClass("mfp-s-"+e),n=e}},_checkIfClose:function(n){if(!e(n).hasClass(y)){var i=t.st.closeOnContentClick,o=t.st.closeOnBgClick;if(i&&o)return!0;if(!t.content||e(n).hasClass("mfp-close")||t.preloader&&n===t.preloader[0])return!0;if(n===t.content[0]||e.contains(t.content[0],n)){if(i)return!0}else if(o&&e.contains(document,n))return!0;return!1}},_addClassToMFP:function(e){t.bgOverlay.addClass(e),t.wrap.addClass(e)},_removeClassFromMFP:function(e){this.bgOverlay.removeClass(e),t.wrap.removeClass(e)},_hasScrollBar:function(e){return(t.isIE7?o.height():document.body.scrollHeight)>(e||I.height())},_setFocus:function(){(t.st.focus?t.content.find(t.st.focus).eq(0):t.wrap).focus()},_onFocusIn:function(n){return n.target===t.wrap[0]||e.contains(t.wrap[0],n.target)?void 0:(t._setFocus(),!1)},_parseMarkup:function(t,n,i){var o;i.data&&(n=e.extend(i.data,n)),T(p,[t,n,i]),e.each(n,function(e,n){if(void 0===n||n===!1)return!0;if(o=e.split("_"),o.length>1){var i=t.find(v+"-"+o[0]);if(i.length>0){var r=o[1];"replaceWith"===r?i[0]!==n[0]&&i.replaceWith(n):"img"===r?i.is("img")?i.attr("src",n):i.replaceWith('<img src="'+n+'" class="'+i.attr("class")+'" />'):i.attr(o[1],n)}}else t.find(v+"-"+e).html(n)})},_getScrollbarSize:function(){if(void 0===t.scrollbarSize){var e=document.createElement("div");e.id="mfp-sbm",e.style.cssText="width: 99px; height: 99px; overflow: scroll; position: absolute; top: -9999px;",document.body.appendChild(e),t.scrollbarSize=e.offsetWidth-e.clientWidth,document.body.removeChild(e)}return t.scrollbarSize}},e.magnificPopup={instance:null,proto:w.prototype,modules:[],open:function(t,n){return _(),t=t?e.extend(!0,{},t):{},t.isObj=!0,t.index=n||0,this.instance.open(t)},close:function(){return e.magnificPopup.instance&&e.magnificPopup.instance.close()},registerModule:function(t,n){n.options&&(e.magnificPopup.defaults[t]=n.options),e.extend(this.proto,n.proto),this.modules.push(t)},defaults:{disableOn:0,key:null,midClick:!1,mainClass:"",preloader:!0,focus:"",closeOnContentClick:!1,closeOnBgClick:!0,closeBtnInside:!0,showCloseBtn:!0,enableEscapeKey:!0,modal:!1,alignTop:!1,removalDelay:0,fixedContentPos:"auto",fixedBgPos:"auto",overflowY:"auto",closeMarkup:'<button title="%title%" type="button" class="mfp-close">&times;</button>',tClose:"Close (Esc)",tLoading:"Loading..."}},e.fn.magnificPopup=function(n){_();var i=e(this);if("string"==typeof n)if("open"===n){var o,r=b?i.data("magnificPopup"):i[0].magnificPopup,a=parseInt(arguments[1],10)||0;r.items?o=r.items[a]:(o=i,r.delegate&&(o=o.find(r.delegate)),o=o.eq(a)),t._openClick({mfpEl:o},i,r)}else t.isOpen&&t[n].apply(t,Array.prototype.slice.call(arguments,1));else n=e.extend(!0,{},n),b?i.data("magnificPopup",n):i[0].magnificPopup=n,t.addGroup(i,n);return i};var P,O,z,M="inline",B=function(){z&&(O.after(z.addClass(P)).detach(),z=null)};e.magnificPopup.registerModule(M,{options:{hiddenClass:"hide",markup:"",tNotFound:"Content not found"},proto:{initInline:function(){t.types.push(M),x(l+"."+M,function(){B()})},getInline:function(n,i){if(B(),n.src){var o=t.st.inline,r=e(n.src);if(r.length){var a=r[0].parentNode;a&&a.tagName&&(O||(P=o.hiddenClass,O=k(P),P="mfp-"+P),z=r.after(O).detach().removeClass(P)),t.updateStatus("ready")}else t.updateStatus("error",o.tNotFound),r=e("<div>");return n.inlineElement=r,r}return t.updateStatus("ready"),t._parseMarkup(i,{},n),i}}});var F,H="ajax",L=function(){F&&i.removeClass(F)},A=function(){L(),t.req&&t.req.abort()};e.magnificPopup.registerModule(H,{options:{settings:null,cursor:"mfp-ajax-cur",tError:'<a href="%url%">The content</a> could not be loaded.'},proto:{initAjax:function(){t.types.push(H),F=t.st.ajax.cursor,x(l+"."+H,A),x("BeforeChange."+H,A)},getAjax:function(n){F&&i.addClass(F),t.updateStatus("loading");var o=e.extend({url:n.src,success:function(i,o,r){var a={data:i,xhr:r};T("ParseAjax",a),t.appendContent(e(a.data),H),n.finished=!0,L(),t._setFocus(),setTimeout(function(){t.wrap.addClass(h)},16),t.updateStatus("ready"),T("AjaxContentAdded")},error:function(){L(),n.finished=n.loadError=!0,t.updateStatus("error",t.st.ajax.tError.replace("%url%",n.src))}},t.st.ajax.settings);return t.req=e.ajax(o),""}}});var j,N=function(n){if(n.data&&void 0!==n.data.title)return n.data.title;var i=t.st.image.titleSrc;if(i){if(e.isFunction(i))return i.call(t,n);if(n.el)return n.el.attr(i)||""}return""};e.magnificPopup.registerModule("image",{options:{markup:'<div class="mfp-figure"><div class="mfp-close"></div><figure><div class="mfp-img"></div><figcaption><div class="mfp-bottom-bar"><div class="mfp-title"></div><div class="mfp-counter"></div></div></figcaption></figure></div>',cursor:"mfp-zoom-out-cur",titleSrc:"title",verticalFit:!0,tError:'<a href="%url%">The image</a> could not be loaded.'},proto:{initImage:function(){var e=t.st.image,n=".image";t.types.push("image"),x(f+n,function(){"image"===t.currItem.type&&e.cursor&&i.addClass(e.cursor)}),x(l+n,function(){e.cursor&&i.removeClass(e.cursor),I.off("resize"+v)}),x("Resize"+n,t.resizeImage),t.isLowIE&&x("AfterChange",t.resizeImage)},resizeImage:function(){var e=t.currItem;if(e&&e.img&&t.st.image.verticalFit){var n=0;t.isLowIE&&(n=parseInt(e.img.css("padding-top"),10)+parseInt(e.img.css("padding-bottom"),10)),e.img.css("max-height",t.wH-n)}},_onImageHasSize:function(e){e.img&&(e.hasSize=!0,j&&clearInterval(j),e.isCheckingImgSize=!1,T("ImageHasSize",e),e.imgHidden&&(t.content&&t.content.removeClass("mfp-loading"),e.imgHidden=!1))},findImageSize:function(e){var n=0,i=e.img[0],o=function(r){j&&clearInterval(j),j=setInterval(function(){return i.naturalWidth>0?(t._onImageHasSize(e),void 0):(n>200&&clearInterval(j),n++,3===n?o(10):40===n?o(50):100===n&&o(500),void 0)},r)};o(1)},getImage:function(n,i){var o=0,r=function(){n&&(n.img[0].complete?(n.img.off(".mfploader"),n===t.currItem&&(t._onImageHasSize(n),t.updateStatus("ready")),n.hasSize=!0,n.loaded=!0,T("ImageLoadComplete")):(o++,200>o?setTimeout(r,100):a()))},a=function(){n&&(n.img.off(".mfploader"),n===t.currItem&&(t._onImageHasSize(n),t.updateStatus("error",s.tError.replace("%url%",n.src))),n.hasSize=!0,n.loaded=!0,n.loadError=!0)},s=t.st.image,l=i.find(".mfp-img");if(l.length){var c=document.createElement("img");c.className="mfp-img",n.img=e(c).on("load.mfploader",r).on("error.mfploader",a),c.src=n.src,l.is("img")&&(n.img=n.img.clone()),n.img[0].naturalWidth>0&&(n.hasSize=!0)}return t._parseMarkup(i,{title:N(n),img_replaceWith:n.img},n),t.resizeImage(),n.hasSize?(j&&clearInterval(j),n.loadError?(i.addClass("mfp-loading"),t.updateStatus("error",s.tError.replace("%url%",n.src))):(i.removeClass("mfp-loading"),t.updateStatus("ready")),i):(t.updateStatus("loading"),n.loading=!0,n.hasSize||(n.imgHidden=!0,i.addClass("mfp-loading"),t.findImageSize(n)),i)}}});var W,R=function(){return void 0===W&&(W=void 0!==document.createElement("p").style.MozTransform),W};e.magnificPopup.registerModule("zoom",{options:{enabled:!1,easing:"ease-in-out",duration:300,opener:function(e){return e.is("img")?e:e.find("img")}},proto:{initZoom:function(){var e,n=t.st.zoom,i=".zoom";if(n.enabled&&t.supportsTransition){var o,r,a=n.duration,s=function(e){var t=e.clone().removeAttr("style").removeAttr("class").addClass("mfp-animated-image"),i="all "+n.duration/1e3+"s "+n.easing,o={position:"fixed",zIndex:9999,left:0,top:0,"-webkit-backface-visibility":"hidden"},r="transition";return o["-webkit-"+r]=o["-moz-"+r]=o["-o-"+r]=o[r]=i,t.css(o),t},d=function(){t.content.css("visibility","visible")};x("BuildControls"+i,function(){if(t._allowZoom()){if(clearTimeout(o),t.content.css("visibility","hidden"),e=t._getItemToZoom(),!e)return d(),void 0;r=s(e),r.css(t._getOffset()),t.wrap.append(r),o=setTimeout(function(){r.css(t._getOffset(!0)),o=setTimeout(function(){d(),setTimeout(function(){r.remove(),e=r=null,T("ZoomAnimationEnded")},16)},a)},16)}}),x(c+i,function(){if(t._allowZoom()){if(clearTimeout(o),t.st.removalDelay=a,!e){if(e=t._getItemToZoom(),!e)return;r=s(e)}r.css(t._getOffset(!0)),t.wrap.append(r),t.content.css("visibility","hidden"),setTimeout(function(){r.css(t._getOffset())},16)}}),x(l+i,function(){t._allowZoom()&&(d(),r&&r.remove(),e=null)})}},_allowZoom:function(){return"image"===t.currItem.type},_getItemToZoom:function(){return t.currItem.hasSize?t.currItem.img:!1},_getOffset:function(n){var i;i=n?t.currItem.img:t.st.zoom.opener(t.currItem.el||t.currItem);var o=i.offset(),r=parseInt(i.css("padding-top"),10),a=parseInt(i.css("padding-bottom"),10);o.top-=e(window).scrollTop()-r;var s={width:i.width(),height:(b?i.innerHeight():i[0].offsetHeight)-a-r};return R()?s["-moz-transform"]=s.transform="translate("+o.left+"px,"+o.top+"px)":(s.left=o.left,s.top=o.top),s}}});var Z="iframe",q="//about:blank",D=function(e){if(t.currTemplate[Z]){var n=t.currTemplate[Z].find("iframe");n.length&&(e||(n[0].src=q),t.isIE8&&n.css("display",e?"block":"none"))}};e.magnificPopup.registerModule(Z,{options:{markup:'<div class="mfp-iframe-scaler"><div class="mfp-close"></div><iframe class="mfp-iframe" src="//about:blank" frameborder="0" allowfullscreen></iframe></div>',srcAction:"iframe_src",patterns:{youtube:{index:"youtube.com",id:"v=",src:"//www.youtube.com/embed/%id%?autoplay=1"},vimeo:{index:"vimeo.com/",id:"/",src:"//player.vimeo.com/video/%id%?autoplay=1"},gmaps:{index:"//maps.google.",src:"%id%&output=embed"}}},proto:{initIframe:function(){t.types.push(Z),x("BeforeChange",function(e,t,n){t!==n&&(t===Z?D():n===Z&&D(!0))}),x(l+"."+Z,function(){D()})},getIframe:function(n,i){var o=n.src,r=t.st.iframe;e.each(r.patterns,function(){return o.indexOf(this.index)>-1?(this.id&&(o="string"==typeof this.id?o.substr(o.lastIndexOf(this.id)+this.id.length,o.length):this.id.call(this,o)),o=this.src.replace("%id%",o),!1):void 0});var a={};return r.srcAction&&(a[r.srcAction]=o),t._parseMarkup(i,a,n),t.updateStatus("ready"),i}}});var K=function(e){var n=t.items.length;return e>n-1?e-n:0>e?n+e:e},Y=function(e,t,n){return e.replace(/%curr%/gi,t+1).replace(/%total%/gi,n)};e.magnificPopup.registerModule("gallery",{options:{enabled:!1,arrowMarkup:'<button title="%title%" type="button" class="mfp-arrow mfp-arrow-%dir%"></button>',preload:[0,2],navigateByImgClick:!0,arrows:!0,tPrev:"Previous (Left arrow key)",tNext:"Next (Right arrow key)",tCounter:"%curr% of %total%"},proto:{initGallery:function(){var n=t.st.gallery,i=".mfp-gallery",r=Boolean(e.fn.mfpFastClick);return t.direction=!0,n&&n.enabled?(a+=" mfp-gallery",x(f+i,function(){n.navigateByImgClick&&t.wrap.on("click"+i,".mfp-img",function(){return t.items.length>1?(t.next(),!1):void 0}),o.on("keydown"+i,function(e){37===e.keyCode?t.prev():39===e.keyCode&&t.next()})}),x("UpdateStatus"+i,function(e,n){n.text&&(n.text=Y(n.text,t.currItem.index,t.items.length))}),x(p+i,function(e,i,o,r){var a=t.items.length;o.counter=a>1?Y(n.tCounter,r.index,a):""}),x("BuildControls"+i,function(){if(t.items.length>1&&n.arrows&&!t.arrowLeft){var i=n.arrowMarkup,o=t.arrowLeft=e(i.replace(/%title%/gi,n.tPrev).replace(/%dir%/gi,"left")).addClass(y),a=t.arrowRight=e(i.replace(/%title%/gi,n.tNext).replace(/%dir%/gi,"right")).addClass(y),s=r?"mfpFastClick":"click";o[s](function(){t.prev()}),a[s](function(){t.next()}),t.isIE7&&(k("b",o[0],!1,!0),k("a",o[0],!1,!0),k("b",a[0],!1,!0),k("a",a[0],!1,!0)),t.container.append(o.add(a))}}),x(m+i,function(){t._preloadTimeout&&clearTimeout(t._preloadTimeout),t._preloadTimeout=setTimeout(function(){t.preloadNearbyImages(),t._preloadTimeout=null},16)}),x(l+i,function(){o.off(i),t.wrap.off("click"+i),t.arrowLeft&&r&&t.arrowLeft.add(t.arrowRight).destroyMfpFastClick(),t.arrowRight=t.arrowLeft=null}),void 0):!1},next:function(){t.direction=!0,t.index=K(t.index+1),t.updateItemHTML()},prev:function(){t.direction=!1,t.index=K(t.index-1),t.updateItemHTML()},goTo:function(e){t.direction=e>=t.index,t.index=e,t.updateItemHTML()},preloadNearbyImages:function(){var e,n=t.st.gallery.preload,i=Math.min(n[0],t.items.length),o=Math.min(n[1],t.items.length);for(e=1;(t.direction?o:i)>=e;e++)t._preloadItem(t.index+e);for(e=1;(t.direction?i:o)>=e;e++)t._preloadItem(t.index-e)},_preloadItem:function(n){if(n=K(n),!t.items[n].preloaded){var i=t.items[n];i.parsed||(i=t.parseEl(n)),T("LazyLoad",i),"image"===i.type&&(i.img=e('<img class="mfp-img" />').on("load.mfploader",function(){i.hasSize=!0}).on("error.mfploader",function(){i.hasSize=!0,i.loadError=!0,T("LazyLoadError",i)}).attr("src",i.src)),i.preloaded=!0}}}});var U="retina";e.magnificPopup.registerModule(U,{options:{replaceSrc:function(e){return e.src.replace(/\.\w+`$/,function(e){return"@2x"+e})},ratio:1},proto:{initRetina:function(){if(window.devicePixelRatio>1){var e=t.st.retina,n=e.ratio;n=isNaN(n)?n():n,n>1&&(x("ImageHasSize."+U,function(e,t){t.img.css({"max-width":t.img[0].naturalWidth/n,width:"100%"})}),x("ElementParse."+U,function(t,i){i.src=e.replaceSrc(i,n)}))}}}}),function(){var t=1e3,n="ontouchstart"in window,i=function(){I.off("touchmove"+r+" touchend"+r)},o="mfpFastClick",r="."+o;e.fn.mfpFastClick=function(o){return e(this).each(function(){var a,s=e(this);if(n){var l,c,d,u,p,f;s.on("touchstart"+r,function(e){u=!1,f=1,p=e.originalEvent?e.originalEvent.touches[0]:e.touches[0],c=p.clientX,d=p.clientY,I.on("touchmove"+r,function(e){p=e.originalEvent?e.originalEvent.touches:e.touches,f=p.length,p=p[0],(Math.abs(p.clientX-c)>10||Math.abs(p.clientY-d)>10)&&(u=!0,i())}).on("touchend"+r,function(e){i(),u||f>1||(a=!0,e.preventDefault(),clearTimeout(l),l=setTimeout(function(){a=!1},t),o())})})}s.on("click"+r,function(){a||o()})})},e.fn.destroyMfpFastClick=function(){e(this).off("touchstart"+r+" click"+r),n&&I.off("touchmove"+r+" touchend"+r)}}(),_()})(window.jQuery||window.Zepto);
//]]>
</script>
<script type="text/javascript">//<![CDATA[ 
`$(document).ready(function() {
  `$('.screenshot').magnificPopup({
    type:'image',
    mainClass: 'mfp-with-zoom',
    zoom: {
    enabled: true,
    duration: 300,
    easing: 'ease-in-out',
    opener: function(openerElement) {
      return openerElement.is('img') ? openerElement : openerElement.find('img');
    }
  }
  });
});
/*! jQuery Group Box Animations */
`$(window).load(function(){
  `$("a.group-toggle").on('click', function () {
      `$('div.box-content-system').slideToggle(200).toggleClass('active');
      `$('div.box-content1-system').slideToggle(200).toggleClass('active');
      `$('div.box-content2-system').slideToggle(200).toggleClass('active');
      `$('div.box-content3-system').slideToggle(200).toggleClass('active');
      `$('div.box-content4-system').slideToggle(200).toggleClass('active');
      `$('div.box-content5-system').slideToggle(200).toggleClass('active');
      `$('div.box-content6-system').slideToggle(200).toggleClass('active');
      `$('div.box-content7-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.group-toggle2").on('click', function () {
      `$('div.box-content1-web').slideToggle(200).toggleClass('active');
      `$('div.box-content2-web').slideToggle(200).toggleClass('active');
      `$('div.box-content3-web').slideToggle(200).toggleClass('active');
      `$('div.box-content4-web').slideToggle(200).toggleClass('active');
      `$('div.box-content5-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.group-toggle3").on('click', function () {
      `$('div.box-content1-process').slideToggle(200).toggleClass('active');
      `$('div.box-content2-process').slideToggle(200).toggleClass('active');
      `$('div.box-content3-process').slideToggle(200).toggleClass('active');
      `$('div.box-content4-process').slideToggle(200).toggleClass('active');
      `$('div.box-content5-process').slideToggle(200).toggleClass('active');
      `$('div.box-content6-process').slideToggle(200).toggleClass('active');
      `$('div.box-content7-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.group-toggle4").on('click', function () {
      `$('div.box-content1-network').slideToggle(200).toggleClass('active');
      `$('div.box-content2-network').slideToggle(200).toggleClass('active');
      `$('div.box-content3-network').slideToggle(200).toggleClass('active');
      `$('div.box-content4-network').slideToggle(200).toggleClass('active');
      `$('div.box-content5-network').slideToggle(200).toggleClass('active');
      `$('div.box-content6-network').slideToggle(200).toggleClass('active');
      `$('div.box-content7-network').slideToggle(200).toggleClass('active');
      `$('div.box-content8-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.group-toggle6").on('click', function () {
      `$('div.box-content1-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content2-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content3-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content4-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content5-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content6-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content7-registry').slideToggle(200).toggleClass('active');
      `$('div.box-content8-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.group-toggle5").on('click', function () {
      `$('div.box-content1-config').slideToggle(200).toggleClass('active');
      `$('div.box-content2-config').slideToggle(200).toggleClass('active');
      `$('div.box-content3-config').slideToggle(200).toggleClass('active');
      return false;
  });
});

/*! jQuery Single Box Animations */
`$(window).load(function(){
  `$("a.box-toggle-system").on('click', function () {
      `$('div.box-content-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-system").on('click', function () {
      `$('div.box-content1-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-system").on('click', function () {
      `$('div.box-content2-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-system").on('click', function () {
      `$('div.box-content3-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle4-system").on('click', function () {
      `$('div.box-content4-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle5-system").on('click', function () {
      `$('div.box-content5-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle6-system").on('click', function () {
      `$('div.box-content6-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle7-system").on('click', function () {
      `$('div.box-content7-system').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-web").on('click', function () {
      `$('div.box-content1-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-web").on('click', function () {
      `$('div.box-content2-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-web").on('click', function () {
      `$('div.box-content3-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle4-web").on('click', function () {
      `$('div.box-content4-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle5-web").on('click', function () {
      `$('div.box-content5-web').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-process").on('click', function () {
      `$('div.box-content1-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-process").on('click', function () {
      `$('div.box-content2-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-process").on('click', function () {
      `$('div.box-content3-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle4-process").on('click', function () {
      `$('div.box-content4-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle5-process").on('click', function () {
      `$('div.box-content5-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle6-process").on('click', function () {
      `$('div.box-content6-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle7-process").on('click', function () {
      `$('div.box-content7-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle8-process").on('click', function () {
      `$('div.box-content8-process').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-network").on('click', function () {
      `$('div.box-content1-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-network").on('click', function () {
      `$('div.box-content2-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-network").on('click', function () {
      `$('div.box-content3-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle4-network").on('click', function () {
      `$('div.box-content4-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle5-network").on('click', function () {
      `$('div.box-content5-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle6-network").on('click', function () {
      `$('div.box-content6-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle7-network").on('click', function () {
      `$('div.box-content7-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle8-network").on('click', function () {
      `$('div.box-content8-network').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-registry").on('click', function () {
      `$('div.box-content1-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-registry").on('click', function () {
      `$('div.box-content2-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-registry").on('click', function () {
      `$('div.box-content3-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle4-registry").on('click', function () {
      `$('div.box-content4-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle5-registry").on('click', function () {
      `$('div.box-content5-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle6-registry").on('click', function () {
      `$('div.box-content6-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle7-registry").on('click', function () {
      `$('div.box-content7-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle8-registry").on('click', function () {
      `$('div.box-content8-registry').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle1-config").on('click', function () {
      `$('div.box-content1-config').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle2-config").on('click', function () {
      `$('div.box-content2-config').slideToggle(200).toggleClass('active');
      return false;
  });
});
`$(window).load(function(){
  `$("a.box-toggle3-config").on('click', function () {
      `$('div.box-content3-config').slideToggle(200).toggleClass('active');
      return false;
  });
});
//]]>
</script>
"@

$htmlCSS = @"
<style>
body {
  background-color: #cccccc;
  margin: 0px;
  font: 18px Calibri, sans-serif;
}
.logo-rhythm{fill:#007bc2}
.logo-log{fill:#002d57}
h3 {
  font: 18px Calibri, sans-serif;
}
.section {
  background-color: #484848;
  color: #000000;
  width: 50%;
  border: 0px solid #ffffff;
  text-align: left;
  text-indent: 50px;
  font: 18px Calibri, sans-serif;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
.section:hover {
  -moz-box-shadow: 0 0 20px rgb(0, 41, 102);
  -webkit-box-shadow: 0 0 20px rgb(0, 41, 102);
  -o-box-shadow: 0 0 20px rgb(0, 41, 102);
  box-shadow: 0 0 20px rgb(0, 41, 102);
}
.screenshot {
  opacity: 1;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
.screenshot:hover {
  opacity: .7;
}
.content {
  border: 6px solid #0c234c;
  background-color: #ffffff;
  margin: auto;
  width: 90%;
}
.breaks {
  background-color: #0c234c;
  color: #cccccc;
  text-indent: 100px;
  margin: auto;
  width: 100%;
}
.breakButton {
  background-color: #4C4C4C;
  color: #ffffff;
  text-decoration: none;
  text-indent: 100px;
  margin: auto;
  width: 100%;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
.breakButton:hover {
  -webkit-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -moz-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -o-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  box-shadow: 0 0 20px rgba(0,0,0,0.5);
}
a {
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
a:link {color: #E8E8E8; text-decoration: none;  }
a:active {color: #ffffff; text-decoration: none; }
a:visited {color: #E8E8E8; text-decoration: none; }
a:hover {color: #FF9900; text-decoration: none; }
.data {
  background-color: #ffffff;
  margin: 0px;
  border: 5px solid #484848;
  font: 14px Calibri, sans-serif;
  font-weight: normal;
  resize: none;
  overflow-y: scroll;
  -webkit-box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
  -moz-box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
  -o-box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
  box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
}
.footer {
  opacity: 1;
  font-size: 14px;
  color: #ffffff;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
.footer:hover {
  opacity: .7;
}
a.footer {
  opacity: 1;
  font-size: 14px;
  color: #ffffff;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
a.footer:hover {
  opacity: .7;
}
#nav:link {color: #ffffff; text-decoration: none; }
#nav:active {color: #ffffff; text-decoration: none; }
#nav:visited {color: #ffffff; text-decoration: none; }
#nav:hover {color: #FF9900; text-decoration: none; }
#break:link {color: #cccccc; text-decoration: none; }
#break:active {color: #cccccc; text-decoration: none; }
#break:visited {color: #cccccc; text-decoration: none; }
#break:hover {color: #FF9900; text-decoration: none; }
#top {
  opacity: .8;
  -webkit-border-top-left-radius: 15px;
  -moz-border-top-left-radius: 15px;
  -o-border-top-left-radius: 15px;
  border-top-left-radius: 15px;
  -webkit-border-top-right-radius: 15px;
  -moz-border-top-right-radius: 15px;
  -o-border-top-right-radius: 15px;
  border-top-right-radius: 15px;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
#bottom {
  opacity: 1;
  -webkit-border-bottom-right-radius: 15px;
  -moz-border-bottom-right-radius: 15px;
  -o-border-bottom-right-radius: 15px;
  border-bottom-right-radius: 15px;
  -webkit-border-bottom-left-radius: 15px;
  -moz-border-bottom-left-radius: 15px;
  -o-border-bottom-left-radius: 15px;
  border-bottom-left-radius: 15px;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
#bottom:hover {
  opacity: 1;
  -webkit-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -moz-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -o-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  box-shadow: 0 0 20px rgba(0,0,0,0.5);
}
#left {
  -webkit-border-top-left-radius: 15px;
  -moz-border-top-left-radius: 15px;
  -o-border-top-left-radius: 15px;
  border-top-left-radius: 15px;
  -webkit-border-bottom-left-radius: 15px;
  -moz-border-bottom-left-radius: 15px;
  -o-border-bottom-left-radius: 15px;
  border-bottom-left-radius: 15px;
  -webkit-transition: all .4s ease-in-out;
  -moz-transition: all .4s ease-in-out;
  -o-transition: all .4s ease-in-out;
  transition: all .4s ease-in-out;
}
#round {
  -webkit-border-top-left-radius: 15px;
  -moz-border-top-left-radius: 15px;
  -o-border-top-left-radius: 15px;
  border-top-left-radius: 15px;
  -webkit-border-top-right-radius: 15px;
  -moz-border-top-right-radius: 15px;
  -o-border-top-right-radius: 15px;
  border-top-right-radius: 15px;
  -webkit-border-bottom-right-radius: 15px;
  -moz-border-bottom-right-radius: 15px;
  -o-border-bottom-right-radius: 15px;
  border-bottom-right-radius: 15px;
  -webkit-border-bottom-left-radius: 15px;
  -moz-border-bottom-left-radius: 15px;
  -o-border-bottom-left-radius: 15px;
  border-bottom-left-radius: 15px;
  -webkit-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -moz-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  -o-box-shadow: 0 0 20px rgba(0,0,0,0.5);
  box-shadow: 0 0 20px rgba(0,0,0,0.5);
}
/* Magnific Popup CSS */
.mfp-bg {
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 1042;
  overflow: hidden;
  position: fixed;
  background: #0b0b0b;
  opacity: 0.8;
  filter: alpha(opacity=80); }

.mfp-wrap {
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 1043;
  position: fixed;
  outline: none !important;
  -webkit-backface-visibility: hidden; }

.mfp-container {
  text-align: center;
  position: absolute;
  width: 100%;
  height: 100%;
  left: 0;
  top: 0;
  padding: 0 8px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box; }

.mfp-container:before {
  content: '';
  display: inline-block;
  height: 100%;
  vertical-align: middle; }

.mfp-align-top .mfp-container:before {
  display: none; }

.mfp-content {
  position: relative;
  display: inline-block;
  vertical-align: middle;
  margin: 0 auto;
  text-align: left;
  z-index: 1045; }

.mfp-inline-holder .mfp-content, .mfp-ajax-holder .mfp-content {
  width: 100%;
  cursor: auto; }

.mfp-ajax-cur {
  cursor: progress; }

.mfp-zoom-out-cur, .mfp-zoom-out-cur .mfp-image-holder .mfp-close {
  cursor: -moz-zoom-out;
  cursor: -webkit-zoom-out;
  cursor: zoom-out; }

.mfp-zoom {
  cursor: pointer;
  cursor: -webkit-zoom-in;
  cursor: -moz-zoom-in;
  cursor: zoom-in; }

.mfp-auto-cursor .mfp-content {
  cursor: auto; }

.mfp-close, .mfp-arrow, .mfp-preloader, .mfp-counter {
  -webkit-user-select: none;
  -moz-user-select: none;
  user-select: none; }

.mfp-loading.mfp-figure {
  display: none; }

.mfp-hide {
  display: none !important; }

.mfp-preloader {
  color: #cccccc;
  position: absolute;
  top: 50%;
  width: auto;
  text-align: center;
  margin-top: -0.8em;
  left: 8px;
  right: 8px;
  z-index: 1044; }
  .mfp-preloader a {
    color: #cccccc; }
    .mfp-preloader a:hover {
      color: white; }

.mfp-s-ready .mfp-preloader {
  display: none; }

.mfp-s-error .mfp-content {
  display: none; }

button.mfp-close, button.mfp-arrow {
  overflow: visible;
  cursor: pointer;
  background: transparent;
  border: 0;
  -webkit-appearance: none;
  display: block;
  outline: none;
  padding: 0;
  z-index: 1046;
  -webkit-box-shadow: none;
  box-shadow: none; }
button::-moz-focus-inner {
  padding: 0;
  border: 0; }

.mfp-close {
  width: 44px;
  height: 44px;
  line-height: 44px;
  position: absolute;
  right: 0;
  top: 0;
  text-decoration: none;
  text-align: center;
  opacity: 0.65;
  padding: 0 0 18px 10px;
  color: white;
  font-style: normal;
  font-size: 28px;
  font-family: Arial, Baskerville, monospace; }
  .mfp-close:hover, .mfp-close:focus {
    opacity: 1; }
  .mfp-close:active {
    top: 1px; }

.mfp-close-btn-in .mfp-close {
  color: #333333; }

.mfp-image-holder .mfp-close, .mfp-iframe-holder .mfp-close {
  color: white;
  right: -6px;
  text-align: right;
  padding-right: 6px;
  width: 100%; }

.mfp-counter {
  position: absolute;
  top: 0;
  right: 0;
  color: #cccccc;
  font-size: 12px;
  line-height: 18px; }

.mfp-arrow {
  position: absolute;
  opacity: 0.65;
  margin: 0;
  top: 50%;
  margin-top: -55px;
  padding: 0;
  width: 90px;
  height: 110px;
  -webkit-tap-highlight-color: rgba(0, 0, 0, 0); }
  .mfp-arrow:active {
    margin-top: -54px; }
  .mfp-arrow:hover, .mfp-arrow:focus {
    opacity: 1; }
  .mfp-arrow:before, .mfp-arrow:after, .mfp-arrow .mfp-b, .mfp-arrow .mfp-a {
    content: '';
    display: block;
    width: 0;
    height: 0;
    position: absolute;
    left: 0;
    top: 0;
    margin-top: 35px;
    margin-left: 35px;
    border: medium inset transparent; }
  .mfp-arrow:after, .mfp-arrow .mfp-a {
    border-top-width: 13px;
    border-bottom-width: 13px;
    top: 8px; }
  .mfp-arrow:before, .mfp-arrow .mfp-b {
    border-top-width: 21px;
    border-bottom-width: 21px; }

.mfp-arrow-left {
  left: 0; }
  .mfp-arrow-left:after, .mfp-arrow-left .mfp-a {
    border-right: 17px solid white;
    margin-left: 31px; }
  .mfp-arrow-left:before, .mfp-arrow-left .mfp-b {
    margin-left: 25px;
    border-right: 27px solid #3f3f3f; }

.mfp-arrow-right {
  right: 0; }
  .mfp-arrow-right:after, .mfp-arrow-right .mfp-a {
    border-left: 17px solid white;
    margin-left: 39px; }
  .mfp-arrow-right:before, .mfp-arrow-right .mfp-b {
    border-left: 27px solid #3f3f3f; }

.mfp-iframe-holder {
  padding-top: 40px;
  padding-bottom: 40px; }
  .mfp-iframe-holder .mfp-content {
    line-height: 0;
    width: 100%;
    max-width: 900px; }
  .mfp-iframe-holder .mfp-close {
    top: -40px; }

.mfp-iframe-scaler {
  width: 100%;
  height: 0;
  overflow: hidden;
  padding-top: 56.25%; }
  .mfp-iframe-scaler iframe {
    position: absolute;
    display: block;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    box-shadow: 0 0 8px rgba(0, 0, 0, 0.6);
    background: black; }

/* Main image in popup */
img.mfp-img {
  width: auto;
  max-width: 100%;
  height: auto;
  display: block;
  line-height: 0;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  padding: 40px 0 40px;
  margin: 0 auto; }

/* The shadow behind the image */
.mfp-figure {
  line-height: 0; }
  .mfp-figure:after {
    content: '';
    position: absolute;
    left: 0;
    top: 40px;
    bottom: 40px;
    display: block;
    right: 0;
    width: auto;
    height: auto;
    z-index: -1;
    box-shadow: 0 0 8px rgba(0, 0, 0, 0.6);
    background: #444444; }
  .mfp-figure small {
    color: #bdbdbd;
    display: block;
    font-size: 12px;
    line-height: 14px; }

.mfp-bottom-bar {
  margin-top: -36px;
  position: absolute;
  top: 100%;
  left: 0;
  width: 100%;
  cursor: auto; }

.mfp-title {
  text-align: left;
  line-height: 18px;
  color: #f3f3f3;
  word-wrap: break-word;
  padding-right: 36px; }

.mfp-image-holder .mfp-content {
  max-width: 100%; }

.mfp-gallery .mfp-image-holder .mfp-figure {
  cursor: pointer; }
/* Magnific Popup CSS */
</style>
</head>
"@

$htmlBody = @"
<body>
<div style="margin:auto;width:90%">

<!--Header-->
<table width="100%" style="background:#0c234c" id="bottom" align="center">
<tr><td valign="middle" width="50%">
<pre style="color: #ffffff" align="center">
$banner 
</pre>
</td><td valign="middle" width="50%">
<pre style="color: #ffffff" align="center">
<svg version="1.0" xmlns="http://www.w3.org/2000/svg"
 width="150pt" height="30pt" viewBox="0 0 1391.000000 260.000000"
 preserveAspectRatio="xMidYMid meet">
<g transform="translate(0.000000,260.000000) scale(0.100000,-0.100000)"
fill="#ffffff" stroke="none">
<path d="M7240 1785 l0 -815 145 0 145 0 0 456 0 455 38 17 c28 12 67 16 157
17 132 0 166 -11 209 -68 20 -28 21 -39 24 -453 l3 -424 150 0 150 0 -3 458
c-3 453 -4 458 -27 517 -33 84 -106 155 -192 185 -110 38 -333 40 -486 3 l-23
-5 0 236 0 236 -145 0 -145 0 0 -815z"/>
<path d="M10610 1785 l0 -815 150 0 150 0 0 460 0 459 43 13 c23 7 92 13 152
13 133 0 178 -17 210 -81 19 -37 20 -62 23 -451 l3 -413 150 0 149 0 0 383 c0
509 -11 598 -86 686 -43 49 -110 85 -196 106 -82 19 -282 19 -373 0 -38 -8
-71 -15 -72 -15 -2 0 -3 106 -3 235 l0 235 -150 0 -150 0 0 -815z"/>
<path d="M6135 2520 c-60 -4 -154 -13 -207 -20 l-98 -12 0 -759 0 -759 155 0
155 0 0 290 0 290 93 0 92 0 157 -287 156 -288 182 -3 c100 -1 180 1 178 6 -1
5 -76 137 -165 294 -90 157 -165 292 -168 300 -4 11 7 20 40 32 63 25 139 87
171 141 59 102 86 260 65 392 -33 210 -142 324 -351 367 -95 19 -311 27 -455
16z m365 -261 c96 -33 129 -90 130 -217 0 -93 -13 -133 -56 -174 -51 -47 -98
-61 -236 -66 -69 -2 -142 -2 -162 2 l-36 7 0 229 0 229 53 4 c87 8 270 -1 307
-14z"/>
<path d="M2152 1861 l3 -648 35 -69 c78 -154 210 -189 668 -177 l222 6 0 123
0 122 -257 4 c-226 3 -262 5 -291 21 -63 34 -62 25 -62 677 l0 590 -160 0
-161 0 3 -649z"/>
<path d="M9955 2456 l-130 -22 -3 -142 -3 -141 -97 -3 -97 -3 0 -110 0 -110
97 -3 97 -3 3 -377 3 -377 27 -57 c48 -103 146 -151 308 -152 52 -1 121 3 154
7 l59 9 -7 76 c-13 146 -9 139 -74 134 -77 -5 -135 11 -158 46 -17 25 -19 55
-22 360 l-3 332 120 0 121 0 0 115 0 115 -120 0 -120 0 0 165 c0 126 -3 165
-12 164 -7 -1 -71 -11 -143 -23z"/>
<path d="M690 2429 c-225 -23 -437 -170 -535 -373 -45 -92 -67 -176 -47 -176
6 0 13 15 17 33 13 59 84 192 139 258 132 158 341 249 546 235 249 -16 459
-162 567 -393 18 -40 36 -86 39 -103 10 -47 28 -37 20 11 -17 103 -102 247
-197 333 -103 93 -248 160 -369 172 -30 3 -66 6 -80 8 -14 1 -59 -1 -100 -5z"/>
<path d="M3498 2145 c-214 -52 -306 -187 -328 -478 -9 -124 2 -305 25 -392 59
-227 200 -318 495 -319 303 -1 438 88 506 329 24 87 31 373 11 485 -24 136
-51 196 -121 266 -64 64 -127 95 -230 115 -71 13 -292 10 -358 -6z m322 -247
c65 -34 88 -85 100 -226 12 -131 -1 -308 -26 -371 -22 -56 -63 -87 -130 -101
-63 -13 -154 -6 -195 16 -44 22 -77 70 -90 131 -19 88 -16 365 4 434 32 109
75 138 207 139 70 0 94 -4 130 -22z"/>
<path d="M4753 2141 c-167 -46 -243 -116 -300 -277 -27 -77 -28 -86 -28 -289
0 -192 2 -216 23 -285 31 -98 61 -148 122 -203 91 -82 219 -114 414 -104 67 4
133 10 149 13 27 6 27 6 27 -44 0 -64 -13 -98 -52 -138 -46 -49 -95 -58 -276
-51 -86 3 -192 11 -235 17 -44 6 -81 10 -83 8 -8 -8 -27 -209 -20 -215 13 -13
245 -42 393 -49 166 -8 268 3 363 39 75 28 153 103 182 176 23 56 23 60 26
616 2 308 0 592 -3 631 l-7 72 -58 26 c-116 52 -201 68 -390 72 -150 4 -185 1
-247 -15z m375 -231 l32 -12 -2 -331 -3 -331 -35 -8 c-55 -13 -200 -11 -250 2
-61 16 -123 81 -139 146 -19 74 -17 319 3 389 22 73 73 130 135 150 53 17 205
14 259 -5z"/>
<path d="M12184 2146 c-87 -17 -175 -42 -235 -68 -38 -16 -48 -26 -53 -50 -3
-17 -6 -262 -6 -544 l0 -514 145 0 145 0 0 373 c0 206 3 415 6 464 l7 91 37
11 c21 6 71 11 111 11 88 0 134 -20 164 -71 19 -32 20 -55 23 -456 l3 -423
149 0 150 0 -1 413 c0 226 -4 433 -8 459 l-8 47 49 17 c35 11 74 15 133 13 96
-5 128 -21 160 -85 19 -37 20 -62 23 -451 l3 -413 145 0 144 0 0 438 c0 361
-3 448 -15 497 -31 119 -104 199 -213 232 -45 14 -91 18 -217 17 -144 -1 -169
-3 -249 -28 l-88 -27 -67 28 c-60 25 -79 27 -216 30 -94 1 -176 -3 -221 -11z"/>
<path d="M8374 2135 c3 -9 109 -256 236 -549 l231 -533 -91 -252 c-49 -139
-90 -254 -90 -257 0 -2 67 -4 149 -4 l149 0 25 72 c258 755 517 1522 517 1529
0 5 -65 9 -148 9 l-147 0 -115 -361 c-82 -262 -116 -356 -122 -343 -5 11 -70
172 -146 359 l-139 340 -157 3 c-140 2 -158 1 -152 -13z"/>
<path d="M13716 2079 c-3 -17 -6 -58 -6 -90 0 -52 2 -59 20 -59 17 0 20 7 21
53 l1 52 17 -52 c13 -43 20 -53 38 -53 19 0 25 9 35 48 l13 47 5 -45 c4 -37 9
-46 28 -48 20 -3 22 0 22 50 0 29 -3 70 -6 91 -6 32 -10 37 -34 37 -25 0 -29
-5 -40 -50 -7 -27 -15 -50 -19 -50 -4 0 -13 23 -20 50 -12 45 -16 50 -41 50
-23 0 -29 -5 -34 -31z"/>
<path d="M1422 1512 c-42 -104 -96 -191 -155 -252 -46 -47 -47 -50 -23 -50 31
0 123 101 168 185 17 33 36 63 42 67 6 4 7 8 2 8 -5 0 -3 6 3 13 6 8 13 31 17
53 3 21 8 42 11 47 2 4 -4 7 -14 7 -14 0 -27 -20 -51 -78z"/>
<path d="M110 1439 c0 -6 4 -18 10 -28 8 -16 6 -17 -17 -13 l-26 5 29 -54 c37
-68 192 -224 267 -268 255 -150 574 -142 820 19 l75 48 68 -69 c38 -38 73 -69
79 -69 13 0 55 42 55 55 0 5 -32 41 -71 81 -62 63 -68 72 -54 84 14 12 26 4
93 -61 l77 -74 -74 77 -74 77 36 53 c41 58 44 68 23 68 -7 0 -36 -31 -64 -69
-192 -263 -553 -365 -862 -244 -111 44 -217 119 -288 205 -28 34 -23 31 29
-18 88 -85 146 -124 182 -124 28 0 26 3 -39 49 -82 57 -136 114 -200 210 -42
64 -74 90 -74 60z"/>
<path d="M1578 1109 c28 -32 28 -40 -3 -69 l-25 -24 -28 27 -28 27 -59 -60
-59 -60 22 -23 c26 -28 29 -45 5 -26 -10 7 157 -163 371 -379 215 -215 394
-388 399 -385 12 8 58 -39 53 -54 -3 -7 -1 -15 4 -18 18 -11 10 -25 -12 -25
-19 0 -20 -2 -8 -10 19 -13 101 -13 120 0 12 7 8 10 -15 10 -28 0 -25 4 70
100 l99 99 -23 25 c-13 14 -28 23 -33 20 -13 -8 -58 35 -58 55 0 20 -730 751
-749 751 -8 0 -26 10 -40 23 l-26 22 23 -26z"/>
<path d="M13090 620 c-95 -9 -144 -30 -164 -69 -32 -62 -15 -126 43 -156 34
-17 169 -35 268 -35 39 0 84 -5 98 -10 39 -15 29 -42 -20 -53 -77 -17 -313 6
-397 38 -16 6 -18 1 -18 -44 0 -50 0 -50 38 -60 127 -34 356 -39 445 -10 58
19 87 60 87 120 0 93 -47 113 -292 124 -145 7 -174 17 -143 49 30 30 296 17
388 -19 15 -6 17 -1 17 42 0 49 -1 50 -37 61 -37 11 -93 18 -190 26 -27 2 -82
0 -123 -4z"/>
<path d="M10610 415 l0 -205 260 0 260 0 0 50 0 50 -200 0 -200 0 0 155 0 155
-60 0 -60 0 0 -205z"/>
<path d="M11394 428 c-75 -106 -142 -199 -147 -205 -7 -10 5 -13 57 -13 66 0
66 0 94 40 l27 39 177 1 177 0 28 -40 c28 -39 28 -40 96 -40 62 0 67 2 58 18
-6 9 -70 100 -144 202 l-133 185 -76 3 -76 3 -138 -193z m271 26 l55 -79 -111
-3 c-61 -1 -114 -1 -116 2 -3 2 21 41 52 86 32 44 59 79 61 77 3 -2 29 -40 59
-83z"/>
<path d="M12130 415 l0 -206 248 3 c222 3 250 5 279 22 58 36 72 110 27 151
-15 14 -34 25 -42 25 -8 0 0 10 19 23 28 19 35 30 37 64 4 52 -9 78 -51 100
-27 15 -67 18 -274 21 l-243 4 0 -207z m418 109 c32 -7 47 -35 29 -53 -7 -7
-69 -11 -169 -11 l-158 0 0 35 0 35 134 0 c73 0 147 -3 164 -6z m26 -160 c9
-3 16 -14 16 -23 0 -37 -20 -41 -182 -41 l-158 0 0 35 0 35 154 0 c85 0 161
-3 170 -6z"/>
</g>
</svg>
#=========================================#
# Incident Response Live Data Acquisition #
#=========================================#
</pre>
</td></tr></table>
<br />

<!--Content-->
<div class="content" id="round">

<!--Case-->
<br />
<table width="80%" align="center">
<tr><td align="left">
<strong style="color:darkblue;">$date</strong>
<table style="margin-left:100px;" cellspacing="1">
<tr><td>
</td><td></td></tr>
<tr><td>
<strong>IP Address:</strong>
</td><td>$ip</td></tr>
<tr><td>
<strong>Computer Name:</strong>
</td><td>$computerName</td></tr>
<tr><td>
<strong>User Name:</strong>
</td><td>$user</td></tr>
</table>
</td><td align="right">
<a class="screenshot" href="data:image/gif;base64,$screenshot">
<img src="data:image/gif;base64,$screenshot" width="300px" alt="screenshot" /></a>
</td></tr></table>

<!--System Data-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>System Data</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="100%" align="center" cellspacing="10" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle-system" href="#">User Data</a>
<div class="box-content-system" style="display:none;align:center;">
<div class="data" style="width:98%;height:400px;overflow:auto;">
<pre align="left">

Whoami: $whoami

Current Active Users:
    $activeUsers

Local User Accounts:
    $netUser

Access Control List:
  $acl

OS Version:
  $version
</pre>
</div>
</div>
</td><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle-system" href="#">System Data</a>
<div class="box-content-system" style="display:none;align:center;">
<div class="data" style="width:98%;height:400px;overflow:auto;">
<pre align="left">

System.ini:
  $systemIni

Win.ini:
  $winIni

AutoExec:
  $autoexec

Config.sys:
  $configSys
</pre>
</div>
</div>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-system" href="#">Environment Variables</a>
<div class="box-content1-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$set
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-system" href="#">GPResult</a>
<div class="box-content2-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$gpresult
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-system" href="#">Windows Patches</a>
<div class="box-content3-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$hotfix
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle4-system" href="#">Firewall Configuration</a>
<div class="box-content4-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$firewall
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle5-system" href="#">Command Line History</a>
<div class="box-content5-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$commandHist
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle6-system" href="#">Scheduled Tasks</a>
<div class="box-content6-system" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$schtasks
</pre>
</div>
</div>
</td></tr>
</table><br />

<!--Web Data-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>Web Data</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle2" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-web" href="#">Internet Explorer History</a>
<div class="box-content1-web" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$ieHistory
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-web" href="#">Recent Emails</a>
<div class="box-content2-web" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$emailSubjects
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-web" href="#">Extracted Email Links</a>
<div class="box-content3-web" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
Extracted Email Links
     ----------
$emailLinks
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle4-web" href="#">Downloaded Files</a>
<div class="box-content4-web" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$downloads
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle5-web" href="#">Downloaded File Hashes</a>
<div class="box-content5-web" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$downloadHashes
</pre>
</div>
</div>
</td></tr>
</table><br />

<!--Registry and Log Data-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>Registry and Log Data</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle6" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-registry" href="#">USB Device History</a>
<div class="box-content1-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$usb
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-registry" href="#">Remote Desktop History</a>
<div class="box-content2-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$RDPconnections
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-registry" href="#">Successful Logons [EVID: 4624]</a>
<div class="box-content3-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$4624
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle4-registry" href="#">Successful Logons [EVID: 4648]</a>
<div class="box-content4-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$4648
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle5-registry" href="#">Registry Persistence</a>
<div class="box-content5-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">

<strong>HKLM:</strong>
$hklmRun
<strong>HKCU:</strong>
$hkcuRun
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle6-registry" href="#">Startup Drivers</a>
<div class="box-content6-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$startupDrivers
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle7-registry" href="#">User and Temp Startup Drivers</a>
<div class="box-content7-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$shadyDrivers
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle8-registry" href="#">PowerShell Scripts</a>
<div class="box-content8-registry" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$psscripts
</pre>
</div>
</div>
</td></tr>
</table><br />

<!--Process Data-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>Software and Process Data</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle3" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-process" href="#">Installed Software</a>
<div class="box-content1-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$software
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-process" href="#">Potential Dangerous Files</a>
<div class="box-content2-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$DangerousFiles
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-process" href="#">Anti Virus</a>
<div class="box-content3-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$antiVirus
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle4-process" href="#">Services</a>
<div class="box-content4-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$taskDetail
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle5-process" href="#">Process File Hashes</a>
<div class="box-content5-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$processHashes
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle6-process" href="#">Service Detail</a>
<div class="box-content6-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$serviceDetail
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle7-process" href="#">Prefetch Files</a>
<div class="box-content7-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$prefetch
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle8-process" href="#">AT Jobs</a>
<div class="box-content8-process" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$at
</pre>
</div>
</div>
</td></tr>
</table><br />

<!--Network Data-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>Network Data</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle4" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="100%" align="center" cellspacing="10" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-network" href="#">Hosts</a>
<div class="box-content1-network" style="display:none;align:center;">
<div class="data" style="width:98%;height:400px;overflow:auto;">
<p align="left">
$hosts
</p>
</div>
</div>
</td><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-network" href="#">Networks</a>
<div class="box-content1-network" style="display:none;align:center;">
<div class="data" style="width:98%;height:400px;overflow:auto;">
<p align="left">
$networks
</p>
</div>
</div>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-network" href="#">Network Shares</a>
<div class="box-content2-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$shares
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-network" href="#">SMB Sessions</a>
<div class="box-content3-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$smbSession
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle4-network" href="#">DNS Cache</a>
<div class="box-content4-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$dnsCache
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle5-network" href="#">ARP Table</a>
<div class="box-content5-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$arp
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle6-network" href="#">Network Status</a>
<div class="box-content6-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$netstat
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle7-network" href="#">Listening Processes</a>
<div class="box-content7-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$listeningProcesses
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle8-network" href="#">Network Services</a>
<div class="box-content8-network" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$netServices
</pre>
</div>
</div>
</td></tr>
</table><br />

<!--Configuration-->
<table class="breaks" width="100%" align="center"><tr><td align="left" width="70%">
<strong>Configuration</strong>
</td><td align-"right" class="breakButton" id="left" width="30%">
<strong><a id="break" class="group-toggle5" href="#">Expand/Contract All</a></strong>
</td></tr>
</table>

<table width="90%" align="center" cellspacing="10" align="center" style="table-layout:fixed">
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle1-config" href="#">Evidence Hashes</a>
<div class="box-content1-config" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$evidenceHashes
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle2-config" href="#">PowerShell Information and Hashes</a>
<div class="box-content2-config" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
<strong>PowerShell Version:</strong>
$powershellVersion

       <strong>PowerShell Hashes:</strong>
$powershellHashes
</pre>
</div>
</div>
</td></tr>
<tr><td id="top" class="section" width="50%" valign="top">
<a id="nav" class="box-toggle3-config" href="#">PowerShell Profile</a>
<div class="box-content3-config" style="display:none;align:center;">
<div class="data" style="width:99%;height:400px;overflow:auto;">
<pre align="left" width="100%">
$profile
<br />
$PSProfile
</pre>
</div>
</div>
</td></tr>
</table>
<br />
<div width="70%" valign="bottom" align="center" width="70%" style="color:darkred">
<strong>$companyName</strong>
</div><div valign="bottom" align="right" width="30%">
<!--
      logo is stored as svg partial
      so its color can be controlled with css
-->
  <svg
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   version="1.1"
   width="138.2476914"
   height="20"
   viewBox="0 0 438.52499 66.6612503"
   xml:space="preserve"><metadata
     id="metadata8"><rdf:RDF><cc:Work
         rdf:about=""><dc:format>image/svg+xml</dc:format><dc:type
           rdf:resource="http://purl.org/dc/dcmitype/StillImage" /></cc:Work></rdf:RDF></metadata><defs
     id="defs6">
        <clipPath
       id="clipPath18"><path
         d="m 0,0 3508,0 0,532.875 -3508,0 L 0,0 z"
         inkscape:connector-curvature="0"
         id="path20" /></clipPath></defs><g
     transform="matrix(1.25,0,0,-1.25,0,66.6125)"
     id="g10"><g
       transform="scale(0.1,0.1)"
       id="g12"><g
         id="g14"><g
           clip-path="url(#clipPath18)"
           id="g16"><path
             d="m 734.785,116.77 c -27.91,-1.184 -76.152,-2.708 -100.847,-2.708 -71.243,0 -136.907,3.887 -136.907,96.282 l 0,299.011 80.215,0 0,-276.679 c 0,-43.828 7.949,-53.633 55.164,-53.633 l 102.375,0 0,-62.273"
             inkscape:connector-curvature="0"
             id="path22"
             class="logo-log" /><path
             d="m 952.527,265.852 c 0,72.933 -12.515,94.25 -60.066,94.25 -47.383,0 -59.57,-18.95 -59.57,-94.25 0,-75.649 12.187,-94.258 59.57,-94.258 47.551,0 60.066,20.984 60.066,94.258 z m -195.105,0 c 0,112.355 35.879,154.668 135.039,154.668 99.336,0 135.209,-43.665 135.209,-154.668 0,-111.348 -35.873,-154.836 -135.209,-154.836 -99.16,0 -135.039,42.129 -135.039,154.836"
             inkscape:connector-curvature="0"
             id="path24"
             class="logo-log"
                            /><path
             d="m 1153.38,269.062 c 0,-52.624 3.05,-92.05 73.79,-92.05 13.19,0 29.94,2.707 42.3,6.601 l 0,129.614 c 0,13.543 -0.51,28.261 -1.86,40.445 -11.34,5.25 -30.46,7.953 -46.88,7.953 -62.1,0 -67.35,-45.516 -67.35,-92.563 z M 1102.11,68.3672 c 30.12,-4.2266 74.45,-8.7969 109.32,-8.7969 40.45,0 58.04,18.6133 58.04,55.6717 l 0,8.969 c -18.1,-3.899 -39.26,-6.438 -57.54,-6.438 -91.54,0 -134.02,36.731 -134.02,151.289 0,115.747 44.51,151.458 142.82,151.458 40.78,0 87.32,-8.125 121.16,-27.926 1.86,-19.293 2.54,-36.719 2.54,-57.199 l 0,-237.7583 C 1344.43,18.9531 1288.25,0 1220.73,0 c -44.84,0 -93.07,7.10938 -124.71,12.6953 l 6.09,55.6719"
             inkscape:connector-curvature="0"
             id="path26"
             class="logo-log" /><path
             d="m 1518.95,329.137 c 16.24,-1.864 32.32,-2.032 48.73,-2.032 49.59,0 78.85,12.696 78.85,62.782 0,43.66 -19.63,61.09 -77.15,61.09 -15.75,0 -34.19,-1.188 -50.43,-3.383 l 0,-118.457 z m 0,-214.059 -79.88,0 0,387.512 c 34.18,6.258 81.06,10.828 128.27,10.828 87.15,0 158.38,-17.262 158.38,-123.871 0,-69.719 -29.26,-102.543 -75.63,-116.598 l 90.03,-157.871 -92.06,0 -80.89,148.738 c -16.08,0 -34.36,0.852 -48.22,1.692 l 0,-150.43"
             inkscape:connector-curvature="0"
             id="path28"
             class="logo-rhythm" /><path
             d="m 1986.58,115.078 0,183.43 c 0,42.808 -7.78,60.922 -62.61,60.922 -16.74,0 -34.18,-3.391 -48.56,-9.481 l 0,-234.871 -75.14,0 0,417.797 75.14,0 0,-122.008 c 19.8,5.926 42.13,9.653 67.01,9.653 108.47,0 119.47,-51.45 119.47,-114.735 l 0,-190.707 -75.31,0"
             inkscape:connector-curvature="0"
             id="path30"
             class="logo-rhythm" /><path
             d="m 2304.55,416.453 76.49,0 -140.29,-412.3905 -76.48,0 47.37,132.1675 -121.15,280.223 79.71,0 75.46,-185.965 58.89,185.965"
             inkscape:connector-curvature="0"
             id="path32"
             class="logo-rhythm" /><path
             d="m 2536.6,501.574 0,-85.121 60.58,0 0,-57.023 -60.58,0 0,-155.856 c 0,-25.039 10.49,-34.863 35.7,-34.863 8.46,0 16.76,0.344 25.39,1.016 l 5.75,-53.465 c -16.08,-2.883 -35.53,-5.246 -51.6,-5.246 -63.46,0 -90.2,27.754 -90.2,84.941 l 0,163.473 -49.25,0 0,57.023 49.25,0 0,72.938 74.96,12.183"
             inkscape:connector-curvature="0"
             id="path34"
             class="logo-rhythm" /><path
             d="m 2851.48,115.078 0,183.43 c 0,42.808 -7.78,60.922 -62.6,60.922 -16.75,0 -34.19,-3.391 -48.57,-9.481 l 0,-234.871 -75.13,0 0,417.797 75.13,0 0,-122.008 c 19.8,5.926 42.13,9.653 67.01,9.653 108.47,0 119.48,-51.45 119.48,-114.735 l 0,-190.707 -75.32,0"
             inkscape:connector-curvature="0"
             id="path36"
             class="logo-rhythm" /><path
             d="m 3067.13,115.078 -74.81,0 0,220.317 c 0,20.48 0.86,37.906 2.54,57.199 33.52,17.937 80.9,27.926 127.6,27.926 33.17,0 56.52,-6.434 72.76,-17.262 27.08,10.32 60.07,17.262 92.07,17.262 96.44,0 110.66,-51.958 110.66,-113.551 l 0,-191.891 -74.96,0 0,185.121 c 0,39.094 -9.31,60.074 -51.62,60.074 -11.67,0 -29.27,-3.046 -42.97,-9.984 3.05,-13.535 4.06,-28.094 4.06,-43.32 l 0,-191.891 -74.97,0 0,185.121 c 0,38.414 -8.97,60.074 -50.09,60.074 -12.86,0 -29.1,-3.382 -38.42,-7.953 -1.34,-12.183 -1.85,-26.906 -1.85,-40.445 l 0,-196.797"
             inkscape:connector-curvature="0"
             id="path38"
             class="logo-rhythm" /><path
             d="m 148.145,165.852 c 0,27.964 22.695,50.64 50.695,50.64 27.976,0 50.691,-22.676 50.722,-50.64 0.008,-28.071 -22.726,-50.735 -50.722,-50.735 -28.012,0 -50.695,22.715 -50.695,50.735"
             inkscape:connector-curvature="0"
             id="path40"
             class="logo-rhythm" /><path
             d="m 296.27,313.945 c 0,27.957 22.695,50.711 50.703,50.711 28.007,0 50.695,-22.754 50.695,-50.711 0.027,-28.047 -22.688,-50.769 -50.715,-50.715 -27.988,-0.054 -50.683,22.668 -50.683,50.715"
             inkscape:connector-curvature="0"
             id="path42"
             class="logo-rhythm" /><path
             d="m 0,165.852 c 0,27.964 22.7148,50.64 50.7422,50.64 27.9883,0 50.7028,-22.676 50.7028,-50.64 0,-28.071 -22.7145,-50.786 -50.7028,-50.786 C 22.7344,115.066 0,137.832 0,165.852"
             inkscape:connector-curvature="0"
             id="path44"
             class="logo-rhythm" /><path
             d="m 148.125,313.945 c 0,28.008 22.703,50.711 50.715,50.711 27.996,0 50.691,-22.754 50.722,-50.711 0,-28.047 -22.726,-50.769 -50.722,-50.769 -28.012,0 -50.695,22.722 -50.715,50.769"
             inkscape:connector-curvature="0"
             id="path46"
             class="logo-log" /><path
             d="m 296.27,462.031 c -0.02,28.008 22.675,50.742 50.683,50.742 28.008,-0.019 50.715,-22.734 50.715,-50.769 0,-27.981 -22.707,-50.676 -50.715,-50.676 -28.008,0.012 -50.683,22.695 -50.683,50.703"
             inkscape:connector-curvature="0"
             id="path48"
             class="logo-rhythm" /><path
             d="m 0.03125,313.945 c 0,27.957 22.70315,50.711 50.71095,50.696 27.9883,0 50.7028,-22.739 50.7028,-50.715 0.008,-28.028 -22.695,-50.75 -50.7028,-50.75 -28.0274,0 -50.71095,22.722 -50.71095,50.769"
             inkscape:connector-curvature="0"
             id="path50"
             class="logo-rhythm" /><path
             d="m 148.145,462.031 c 0,27.981 22.683,50.723 50.703,50.723 28.015,0 50.714,-22.715 50.714,-50.75 0,-28 -22.726,-50.676 -50.714,-50.676 -28.02,0 -50.703,22.695 -50.703,50.703"
             inkscape:connector-curvature="0"
             id="path52"
             class="logo-rhythm" /><path
             d="m 3438.6,407.832 0,-34.59 -10.91,0 0,34.59 -12.12,0 0,9.211 34.64,0 1.53,-9.211 -13.14,0"
             inkscape:connector-curvature="0"
             id="path54"
             class="logo-rhythm" /><path
             d="m 3497.15,373.242 -1.9,29.141 -8.32,-29.199 -10.14,0 -8.31,29.199 -1.92,-29.141 -9.44,0 3.16,43.801 14.04,0 8.49,-30.148 8.57,30.148 13.64,0 3.18,-43.801 -11.05,0"
             inkscape:connector-curvature="0"
             id="path56"
             class="logo-rhythm" /></g></g></g></g>     
</svg>
</div>
</div>
</div>
"@

$htmlFooter = @"
<br />
<center>
<div style="margin:auto;width:90%;background:#0c234c;vertical-align:top;white-space:nowrap;display:inline-block" id="top">
<p class="footer"><a href="https://www.logrhythm.com/" class="footer" target="blank_">
&copy; 2015 - LogRhythm - Open Source Software</a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="mailto:greg.foss@logrhythm.com" class="footer" target="blank_">
LogRhythm Labs</a></p>
</div>
</center>
</body>
</html>
"@

$htmlHead > $html
$htmlJS >> $html
$htmlCSS >> $html
$htmlBody >> $html
$htmlFooter >> $html

$output = $("PSRecon_" + $dateString + "_" + $computerName)
Rename-Item PSRecon $output

# Send email notification with attached HTML Report upon completion when -sendEmail parameter is set
if(-Not ($sendEmail)) {
} else {
if ($sendEmail -eq $true) {
    function sendEmail {
        $att = $html.Substring(8)
        $file = "$PSReconDir\$output\$att"
        $msg = New-Object System.Net.Mail.MailMessage
        $smtp = New-Object System.Net.Mail.SMTPClient($smtpServer)
        $attachment = New-Object Net.Mail.Attachment($file)
        $msg.From = $emailFrom
        $msg.To.Add($emailTo)
        $msg.Subject = "PSRecon Live Data Acquisition - " + $computerName + "_" + $dateString
        $msg.Body = @"
<html><head></head><body>
<center><h2 style="font:Calibri,sans-serif;color:#0c234c;">Live Data Capture => <strong>$computerName</strong></h2></center>
<p style="font:Calibri,sans-serif;">Please see the attached HTML report for an overview of the system configuration.</p><br />
<table width="100%" style="background:#0c234c" align="center">
<tr><td valign="middle" width="50%">
<pre style="color: #ffffff" align="center">
$banner 
</pre>
</td><td valign="middle" width="50%">
<pre style="color: #ffffff" align="center"><center>
$date
#=========================================#
#             LogRhythm Labs              #
# Incident Response Live Data Acquisition #
#=========================================#
</center></pre>
</td></tr></table>
</body></html>
"@
        $msg.IsBodyHTML = $true
        $msg.Attachments.Add($attachment)
        $smtp.Send($msg)
    }
} else {
    Write-Host "Missing Required Parameters for [sendEmail]"
    Write-Host "     This option was specified "
    Write-Host "PS C:\> .\PSRecon.ps1 -sendEmail -smtpServer ['SMTP SERVER IP'] -emailTo ['greg.foss[at]logrhythm.com'] -emailFrom ['psrecon[at]logrhythm.com']"
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Missing Required Parameter"
    Exit 1
    }
    Write-Host "Sending email : from - $emailFrom : to - $emailTo : SMTP server - $smtpServer"
    sendEmail
    if (-Not ($share)) {
        while (Test-Path PSRecon_*) {
            rm PSRecon_* -Recurse -Force
        }
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1010 -Message "Email sent : from - $emailFrom : to - $emailTo : SMTP server - $smtpServer"
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1011 -Message "PSRecon evidence files removed from target host"
    }
}


#=======================================================================================
# Evidence Migration and Host Cleanup
#=======================================================================================

# Copy evidence to the share
if(-Not ($share)) {
} else {
if ($share -eq $true) {
    if ($remote -eq $false) {
        Write-Host "Pushing data to share : $netShare"
        Copy-Item PSRecon_* -Recurse $netShare

        # Cleanup
        $evidence = $($netShare + "\PSRecon_" + $dateString + "_" + $computerName)
        If (Test-Path $evidence){
            Remove-Item PSRecon_* -Recurse -Force
            Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1012 -Message "Evidence Pushed to Share : $netShare"
        }else{
            Write-Error "EVIDENCE MIGRATION UNSUCCESSFUL!"
            Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Evidence Migration Failure! Manual Cleanup Required!"
            Exit 1
        }
    } else {
        Write-Host "Missing Required Parameter [share]"
        Write-Host "     This option was specified "
        Write-Host "PS C:\> .\PSRecon.ps1 -share -netShare ['\\share\location']"
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Missing Required Parameter"
        Exit 1
    }
}}


#=======================================================================================
# Workstation Lockdown and Quarantine
#=======================================================================================

if (-Not ($lockdown)) {
} else {
if ($lockdown -eq $true) {
    
    Write-Host "Locking down endpoint: $computerName - $ip"

# Lockdown
    Function Invoke-Lockdown{

        # Disable Network Interfaces
        $wirelessNic = Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Wireless%'"
        $wirelessNic.disable()
        $localNic = Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Intel%'"
        $localNic.disable()
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1101 -Message "Lockdown : Network Interface Cards Disabled"

        $WmiHash = @{}
        if($Private:Credential){
            $WmiHash.Add('Credential',$credential)
        }
        Try{
            $Validate = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $C -ErrorAction Stop @WmiHash).Win32Shutdown('0x0')
        } Catch [System.Management.Automation.MethodInvocationException] {
            Write-Error 'No user session found to log off.'
            Exit 1
        } Catch {
            Throw
        }
        if($Validate.ReturnValue -ne 0){
            Write-Error "User could not be logged off, return value: $($Validate.ReturnValue)"
            Exit 1
        }
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1102 -Message "Lockdown : All Local Users Logged Out"

    # Lock Workstation
    rundll32.exe user32.dll,LockWorkStation > $null 2>&1
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 1103 -Message "Lockdown : System Locked"
    }

} else {
        Write-Host "Missing Required Parameter [lockdown]"
        Write-Host "     This option was specified "
        Write-Host "PS C:\> .\PSRecon.ps1 -lockdown"
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Missing Required Parameter"
        Exit 1
}
}

# Lock out the user's AD account
if (-Not ($adLock)) {
} else {
if ($adLock -eq $true) {
    function get-dn () {
    $root = New-Object System.DirectoryServices.DirectoryEntry
    $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
    $searcher.filter = "(&(objectClass=user)(sAMAccountName= $accountNameAD))"
    $user = $searcher.findall()
        if ($user.count -gt 1) {     
            $count = 0
                foreach($i in $user) { 
                    write-host $count ": " $i.path 
                    $count = $count + 1
                }
            $selection = Read-Host "Please select item: "
            return $user[$selection].path
          } else { 
          return $user[0].path
          }
    }
    $path = get-dn $accountNameAD
    if ($path -ne $null)    {
        $account=[ADSI]$path
        $account.psbase.invokeset("AccountDisabled", "True")
        $account.setinfo()
    Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 2101 -Message "AD Lockout : User $account Disabled within Active Directory"
  } else {
        write-host "No user account found!"
        Write-Host "Please specify a user account with the following command line switch:"
        Write-Host "PS C:\> .\PSRecon.ps1 -adLock [username]"
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Username Not Found"
        Exit 1
  }
}
}
}
if (-Not ($remote)) {
Invoke-Recon
} Else {
    if ($remote -eq $true) {
        $hostnameCheck = "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$"
        if (-not ($target -match $hostnameCheck)) {
            Write-Host "That's not a hostname..."
            Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34405 -Message "Potential Attack Detected via hostname parameter : $target"
            Exit 1
        }
        if ($sendEmail -eq $false) {
            Write-Host ""
            Write-Host "You must get the data off of the remote host..."
            Write-Host "Try using the -sendEmail parameter."
            Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Missing Parameter"
            Exit 1
        }
        try {
            if (-Not ($password)) {
                $cred = Get-Credential
            } Else {
                $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
                $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
            }
            $scriptName = $MyInvocation.MyCommand.Name
            $content = type $scriptName
        
            # send email
            if ($sendEmail -eq $true) {
                
                # extract client email data (send contents via email)
                if ($email -eq $true) {
                    Invoke-Command -ScriptBlock {
                        param ($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$email)
                        if (Test-Path \psrecon.ps1) {
                            rm \psrecon.ps1
                        }
                        $content >> \psrecon.ps1
                        C:\psrecon.ps1 -sendEmail -email -smtpServer $smtpServer -emailFrom $emailFrom -emailTo $emailTo
                        rm C:\psrecon.ps1
                    } -ArgumentList @($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$email) -ComputerName $target -Credential $cred
                } Else {
                    
                # Lockdown the endpoint (disable NIC's, log user out, lock workstation, and send results via email)
                    if ($lockdown -eq $true) {
                        Invoke-Command -ScriptBlock {
                            param ($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$lockdown)
                            if (Test-Path \psrecon.ps1) {
                                rm \psrecon.ps1
                            }
                            $content >> \psrecon.ps1
                            C:\psrecon.ps1 -sendEmail -smtpServer $smtpServer -emailFrom $emailFrom -emailTo $emailTo -lockdown
                            rm C:\psrecon.ps1
                        } -ArgumentList @($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$lockdown) -ComputerName $target -Credential $cred
                    } Else {

                # lock out an account in AD (send results via email)
                    if ($adlock -eq $true) {
                        Invoke-Command -ScriptBlock {
                            param ($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$adlock,$user,$accountNameAD,$account)
                            if (Test-Path \psrecon.ps1) {
                                rm \psrecon.ps1
                            }
                            $content >> \psrecon.ps1
                            C:\psrecon.ps1 -sendEmail -smtpServer $smtpServer -emailFrom $emailFrom -emailTo $emailTo -adlock $account
                            rm C:\psrecon.ps1
                        } -ArgumentList @($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo,$adlock,$user,$accountNameAD,$account) -ComputerName $target -Credential $cred
                    } Else {

                # default execution (send results via email)
                    Invoke-Command -ScriptBlock {
                        param ($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo)
                        if (Test-Path \psrecon.ps1) {
                            rm \psrecon.ps1
                        }
                        $content >> \psrecon.ps1
                        C:\psrecon.ps1 -sendEmail -smtpServer $smtpServer -emailFrom $emailFrom -emailTo $emailTo
                        rm \psrecon.ps1
                    } -ArgumentList @($content,$scriptName,$sendEmail,$smtpServer,$emailFrom,$emailTo) -ComputerName $target -Credential $cred
                }
            }}}
        
            # push data to share ( eventually - because I can't PowerShell  :-P  )
            if ($share -eq $true) {
                $banner
                Write-Host "currently pushing to a share from a remote host is not supported."
                Write-Host "This is due to the need to pass credentials insecurely."
                Write-Host "Please use -sendEmail for now unless executing locally..."
                Exit 1
            }
      
      } Catch {
        Write-Host "Access Denied..."
        Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 34404 -Message "Forensic Data Acquisition Failure : Access Denied"
        Exit 1
      }
    }
}
Write-EventLog -LogName Application -Source "PSRecon" -EntryType Information -EventId 31337 -Message "Forensic Data Acquisition Completed Successfully"
Exit 0


# SIG # Begin signature block
# MIIdxgYJKoZIhvcNAQcCoIIdtzCCHbMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdvQLsICvQH3fzFPPOt5OFLxy
# C+egghi2MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTTMIIDu6ADAgECAhAY2tGeJn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHK
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsT
# FlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlT
# aWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZl
# cmlTaWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgLSBHNTAeFw0wNjExMDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl
# cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWdu
# LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT
# aWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgLSBHNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWe
# YAyq50s7Ttx8vDxFHLsr4P4pAvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3
# S7P+j34HV+zvQ9tmYhVhz2ANpNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ
# 2ENjalJL0o/ocFFN0Ylpe8dw9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE
# 75C55ADk3Tq1Gf8CuvQ87uCL6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6s
# KlLHj9UESeSNY0eIPGmDy/5HvSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80
# h5aK7lPoJRUCAwEAAaOBsjCBrzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
# AwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcG
# BSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJp
# c2lnbi5jb20vdnNsb2dvLmdpZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8z
# MTMwDQYJKoZIhvcNAQEFBQADggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSn
# oHgSrWIORXBkxeeXZi2YCX5fr9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjm
# BpFAGLn4we3f20Gq4JYgyc1kFTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpY
# T2DKfoJqCwKqJRc5tdt/54RlKpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh
# 9BFvELWV/OdCBTLbzp1RXii2noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2G
# dpxEevaVXPZdMggzpFS2GD9oXPJCSoU4VINf0egs8qwR1qjtY2owggU0MIIEHKAD
# AgECAhBvzqThCU6soC46iUEXOXVFMA0GCSqGSIb3DQEBBQUAMIG0MQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWdu
# IFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRwczov
# L3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTEwMS4wLAYDVQQDEyVWZXJpU2lnbiBD
# bGFzcyAzIENvZGUgU2lnbmluZyAyMDEwIENBMB4XDTE1MDQwOTAwMDAwMFoXDTE3
# MDQwMTIzNTk1OVowZjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRAw
# DgYDVQQHEwdCb3VsZGVyMRgwFgYDVQQKFA9Mb2dSaHl0aG0sIEluYy4xGDAWBgNV
# BAMUD0xvZ1JoeXRobSwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKwJYFWf7THEfBgk4pfEUtyGbYUnZmXxJVTTtyy5f0929hCAwuy09oEHpZqD
# uregBi0oZmGo+GJT7vF6W0PZCieXFzxyNfWqJxFb1mghKo+6aweDXWXEdpp/y38k
# /+iu9MiiOFVuJzKNxMD8F6iJ14kG64K+P9gNxIu2t4ajKRDKhN5V8dSDYqdjHlM6
# Vt2WcpqUR3E2LQXrls/aYmKe1Dg9Lf8R/0OeJPLQdnXuSIhBTTdrADmhwgh9F/Q5
# Wj0hS2rURWEIdn3HQsW5xJcHuYxh3YQUIIoDybY7ZolGrRNa1gKEEZVy3iMKoK28
# HEFkuBVGtVSqRed9um99XUU1udkCAwEAAaOCAY0wggGJMAkGA1UdEwQCMAAwDgYD
# VR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9zZi5zeW1jYi5j
# b20vc2YuY3JsMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUH
# AQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vc2Yuc3ltY2QuY29tMCYGCCsGAQUF
# BzAChhpodHRwOi8vc2Yuc3ltY2IuY29tL3NmLmNydDAfBgNVHSMEGDAWgBTPmanq
# eyb0S8mOj9fwBSbv49KnnTAdBgNVHQ4EFgQUoxV4rZFrQYUJv5kT9HiDLKNevs0w
# EQYJYIZIAYb4QgEBBAQDAgQQMBYGCisGAQQBgjcCARsECDAGAQEAAQH/MA0GCSqG
# SIb3DQEBBQUAA4IBAQDtr3hDFtDn6aOruSnJYX+0YqoWREkevcGwpM0bpuJvpCRo
# Fkl8PDobpukMNQdod3/4Iee+8ZRDObYAdKygL4LbLWlaG++wxPQJUXKurRgx/xrm
# SueNFE4oXPGkGG1m3Ffvp38MfUY3VR22z5riQmc4KF2WOTl2eJFiAKTRv31Wf46X
# V3TnMeSuJU+HGNQx1+XXYuK7vgZdyxRVftjbNSW26v/6PAv7slYyiOCvYvnSVCo4
# Kdc+zHj02Nm0IfGyuO+d+992+hEEnWk/WxLwjYXMs6hcHAmuFcfMNY0/mstdWq5/
# dlT/rOBNvFOpMshhwxT1Gl5FlpLzmdj/AbGaUPDSMIIGCjCCBPKgAwIBAgIQUgDl
# qiVW/BqG7ZbJ1EszxzANBgkqhkiG9w0BAQUFADCByjELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO
# ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBh
# dXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1
# YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMTAw
# MjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtDELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3
# b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNp
# Z24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2Rl
# IFNpZ25pbmcgMjAxMCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# APUjS16l14q7MunUV/fv5Mcmfq0ZmP6onX2U9jZrENd1gTB/BGh/yyt1Hs0dCIzf
# aZSnN6Oce4DgmeHuN01fzjsU7obU0PUnNbwlCzinjGOdF6MIpauw+81qYoJM1SHa
# G9nx44Q7iipPhVuQAU/Jp3YQfycDfL6ufn3B3fkFvBtInGnnwKQ8PEEAPt+W5cXk
# lHHWVQHHACZKQDy1oSapDKdtgI6QJXvPvz8c6y+W+uWHd8a1VrJ6O1QwUxvfYjT/
# HtH0WpMoheVMF05+W/2kk5l/383vpHXv7xX2R+f4GXLYLjQaprSnTH69u08MPVfx
# MNamNo7WgHbXGS6lzX40LYkCAwEAAaOCAf4wggH6MBIGA1UdEwEB/wQIMAYBAf8C
# AQAwcAYDVR0gBGkwZzBlBgtghkgBhvhFAQcXAzBWMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMCoGCCsGAQUFBwICMB4aHGh0dHBzOi8v
# d3d3LnZlcmlzaWduLmNvbS9ycGEwDgYDVR0PAQH/BAQDAgEGMG0GCCsGAQUFBwEM
# BGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFI/l0xqGrI2O
# a8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28u
# Z2lmMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Bj
# YTMtZzUuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AudmVyaXNpZ24uY29tMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItODAdBgNVHQ4E
# FgQUz5mp6nsm9EvJjo/X8AUm7+PSp50wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
# Qzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQADggEBAFYi5jSkxGHLSLkBrVaoZA/ZjJHE
# u8wM5a16oCJ/30c4Si1s0X9xGnzscKmx8E/kDwxT+hVe/nSYSSSFgSYckRRHsExj
# jLuhNNTGRegNhSZzA9CpjGRt3HGS5kUFYBVZUTn8WBRr/tSk7XlrCAxBcuc3IgYJ
# viPpP0SaHulhncyxkFz8PdKNrEI9ZTbUtD1AKI+bEM8jJsxLIMuQH12MTDTKPNjl
# N9ZvpSC9NOsm2a4N58Wa96G0IZEzb4boWLslfHQOWP51G2M/zjF8m48blp7FU3aE
# W5ytkfqs7ZO6XcghU8KCU2OvEg1QhxEbPVRSloosnD2SGgiaBS7Hk6VIkdMxggR6
# MIIEdgIBATCByTCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJ
# bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJU
# ZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykx
# MDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBD
# QQIQb86k4QlOrKAuOolBFzl1RTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU8ATXz9nhwETXN+7x
# 7b4K5cxnJo4wDQYJKoZIhvcNAQEBBQAEggEACQs72f6jAJnlH5jVcsiFifJJ6vJJ
# GpXdC5rQX/6uTkO+ezfneqhrY/VVQ0v0FHQJSnolCZWptzcWSpiJvaAHNiXLNgc2
# jm/yxP69wB/wb8GmA0q30ypHLrxnXrw+tYho+uJP3cla1Zcl6Q2RhVHBUXTyL/8T
# vmBX4otqyVMjKTkp7qyf9fIkqAESfHuDtWU5UQ3oK4iF9K3VnKRh2mIg66mnNJS2
# TjvOvg2Q6UEHwoeom5m7XjaknWtD3pGELUnTkyLIBW3GQ5YKI325PV98xldmpuk8
# oBfHlB6v8gyO8rE3Ugh3aQrrxvngt1SrIcNcigSxdnGs498ayQ3OSj061qGCAgsw
# ggIHBgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGlt
# ZSBTdGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNjA0MTgyMTI0NTRaMCMGCSqGSIb3DQEJBDEWBBTeW1WtkuADUKxdKWqT
# rlcDxafCATANBgkqhkiG9w0BAQEFAASCAQCLIcw3bUCmiylF4rozPghegZYgm5Mp
# tV8qSwxEYKpRbVisjBA4WAf6OseL3aJf7vzbFVQAUbKVyGRB9e66xJiHlBXcVF/O
# M/xn3Q90wPznT4fYV8LGSOxEEuaHuQoBJ6shahM0scmGa1FLzHJVTiCV1HSN9mxf
# 6lKtQtetx8Z2VaCgmIpRkNKcp843eNrCUXfTg+RfE3Y8VRwU3P4OZmybTO6+QxUn
# we66214RXZimJkxWA0S+OkdXIdRkInnsoO3rSHs6p23CDkYYoQFcSRHXzbmyYnkD
# zRam4s4ZREyvkasCBriuwvwuUO7arXKcH05NbEJu2KxBghCr6+CqbOcV
# SIG # End signature block
