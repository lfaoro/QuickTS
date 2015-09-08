<#TODO:
  systeminfo.exe /FO LIST | out-file sysInfo.txt
  msinfo32.exe /nfo msinfo.nfo
  get-exchangeserver |ft  

#>

#helper functions
function Get-DCOMconfig {

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$ApplicationName
)

$dcomApp = get-wmiobject -class "Win32_DCOMApplicationSetting" -namespace "root\CIMV2" -Filter "Caption='$ApplicationName'" -EnableAllPrivileges

foreach ($object in $dcomApp) { 
      write-output "Application ID:  $($object.AppID)" 
      write-output "Authentication Level:  $($object.AuthenticationLevel)"
      write-output "Caption:  $($object.Caption) "
      write-output "Custom Surrogate:  $($object.CustomSurrogate)"
      write-output "Description: $( $object.Description) "
      write-output "Enable At Storage Activation: $($object.EnableAtStorageActivation )"
      write-output "Local Service: $( $object.LocalService )"
      write-output "Remote Server Name: $( $object.RemoteServerName )"
      write-output -ForegroundColor Yellow "Run As User: $( $object.RunAsUser )"
      write-output "Service Parameters: $( $object.ServiceParameters )"
      write-output "Setting ID: $( $object.SettingID )"
      write-output "Use Surrogate: $( $object.UseSurrogate )"
} 
}

function write-zip ($sourceDir,$zipFileName)
{
   Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceDir,
        $zipFileName, $compressionLevel, $false)
}

Clear-host

# Suppressing error messages
$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

$validCaseNumber = '^\w{3}\W\d{6}\W\d{6}$'
[String]$caseNumber
do {
    $caseNumber = Read-Host "Please enter your case number i.e. GFI-XXXX-XXXX"
    #$confirmed = read-host "Your case number is $caseNumber, correct? yes/no"

    if (!($caseNumber -match $validCaseNumber)) {
        Write-Host ""
        Write-Host -ForegroundColor Red "Case Number doesn't validate, please try again."
        Write-Host ""
    }

} while (!($caseNumber -match $validCaseNumber))

Write-Host -ForegroundColor Yellow "Troubleshooting running, please don't close this window"

$path = "C:\GFIlogs\QuickTS-$caseNumber"
$log = "$path\$caseNumber.QuickTS.log"
if (Test-Path -Path $path) {
    Remove-Item $path -Recurse
    New-Item -Path $path -ItemType directory
    Set-Location $path
} else {
    New-Item -Path $path -ItemType directory
    Set-Location $path
}

$date = get-date -format g
$OS = (Get-WmiObject Win32_OperatingSystem)
$system = Get-WmiObject win32_operatingsystem

write-output "# Date: $date" >$log
write-output "" >>$log
write-output "# Case: $caseNumber" >>$log
write-output "# OS: $($OS.Caption)" >>$log
write-output "# Architecture: $($OS.OSArchitecture)" >> $log
write-output "# Service Pack: $($OS.ServicePackMajorVersion)" >> $log
write-output "# Domain: $env:USERDNSDOMAIN" >> $log
write-output "# ComputerName: $env:COMPUTERNAME" >> $log
write-output "# Username: $env:USERNAME" >> $log
$psVersion = (get-host).Version.Major
write-output "# PowerShell version: $psVersion" >>$log

$system = Get-WmiObject win32_operatingsystem
[int]$usedMemory = (($system.TotalVisibleMemorySize - $system.FreePhysicalMemory) * 100) / $system.TotalVisibleMemorySize
[int]$freeMemory = 100 - $usedMemory
write-output "# System Memory: $usedMemory% Used / $freeMemory% Free" >>$log
#write-output "# System CPU: $freeMemory% Free / $usedMemory% Used "

$vol = Get-WmiObject win32_Volume -filter "DriveLetter='C:'"
[int]$freeSpace = $vol.FreeSpace * 100 / $vol.Capacity 
write-output "# Storage on C: $freeSpace% Free" >>$log

write-output "" >>$log
Write-Output "# Environment:" >>$log
Write-Output "" >>$log
$EnDis = @{
    0 = "Disabled";
    1 = "Enabled"
}
$UAC = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
Write-Output " UAC: $($EnDis[$UAC])" >>$log

$DEPDesc = @{
    0 = "AlwaysOff - DEP is not enabled for any processes";
    1 = "AlwaysOn - DEP is enabled for all processes";
    2 = "OptIn (default) - Only Windows system components and services have DEP applied";
    3 = "OptOut - DEP is enabled for all processes. Administrators can manually create a list of specific applications which do not have DEP applied"
}
$DEP = (Get-WmiObject -Class Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
Write-Output " DEP: $($DEPDesc[[int]$DEP])" >>$log
Get-Disk >>$log

write-output "" >>$log
write-output "# Services:" >>$log
Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName | `
Where-Object { $_.displayname -like "*gfi*" } |ft Name, DisplayName, State, StartMode, StartName -AutoSize >> $log

write-output "# GFI Processes sorted by Memory" >> $log
$memory = @{ Expression={[int] ($_.WorkingSet / 1mb)};Label="Memory (MB)" }
$cpuPercent = @{ Expression = {
    $totalSec = (New-TimeSpan -Start $_.StartTime).TotalSeconds
    [Math]::Round(($_.CPU * 100 / $totalSec),2) }
Label = 'CPU %'
}
Get-Process|where {$_.Company -like '*GFI*'}|sort -Descending WorkingSet `
|ft name,$memory,$cpuPercent,path -AutoSize >> $log


Write-output "[Gathering sysInfo.txt and msInfo.nfo (check folder)]" >>$log
systeminfo.exe /FO LIST | out-file sysInfo.txt
msinfo32.exe /nfo msInfo.nfo

do {$waitForNFO = Test-Path -path $path\msInfo.nfo} until ($waitForNFO -eq $true)

Write-Output "" >>$log
Write-output "[Gathering Application and System from Event Viewer (check folder)]" >>$log
Write-Output "" >>$log
wevtutil epl application appEvents.evtx
wevtutil epl system sysEvents.evtx

Write-Output "" >>$log
write-output "# MSMQs" >>$log
Write-Output "" >>$log
Get-MsmqQueue |ft -Property QueueName,MessageCount,JournalMessageCount >> $log


write-output "# LISTENING on: 80 (HTTP),9093 (Backend),9091 (Attendant),8015 (Autoupdater) - MailEssentials" >>$log
netstat -abno | Select-String :80,:9093,:9091,:8015 | Select-String LISTENING >>$log
Write-Output ""
write-output "# LISTENING on: 80 (HTTP),8017 (Core),8018 (Store) - Archiver" >>$log
netstat -abno | Select-String :80,:8017,:8018 | Select-String LISTENING >>$log
Write-Output ""
write-output "# LISTENING on: - WebMonitor" >>$log
netstat -abno | Select-String ":80",":443",":8080",":8081",":5995" | Select-String "LISTENING" >>$log


Write-Output "" >>$log
Write-Output "# Testing essential TCP ports" >>$log
Write-Output "# 80,443,25,1070,8017,8018,8080,8081,9093,9091,8015" >>$log
Write-Output "" >>$log
$ports = 80,443,25,1070,8017,8018,8080,8081,9093,9091,8015,5995
$ports | %{
    $tcp = New-Object System.Net.Sockets.TcpClient
    $port = $_
    Try {
        $tcp.Connect('127.0.0.1', $port)
    } Catch {
        #write-output " Failed on: $port" >>$log
    }

    if ($tcp.Connected) {
        $tcp.Close()
        Write-Output " Connection open on: $port" >>$log
    } else {
        Write-Output " Connection closed on: $port" >>$log
    }

    $tcp = $null
}

Write-Output "" >>$log
Write-Output "# Network Shares" >>$log
Get-SmbShare | FT Name, Path, Special -AutoSize >>$log

Write-Output "" >>$log
Write-Output "# IP Config" >>$log
ipconfig /all >>$log

Write-Output "" >>$log
write-output "# Gathering DCOM Config for GFI LanGuard" >>$log
Get-DCOMconfig -ApplicationName LNSSCommunicator >>$log

Write-Output "" >>$log
Write-Output "# Installed Software Packages" >>$log
Get-WmiObject Win32_Product | select-object Name,Version | sort name |ft -AutoSize >>$log

$message = @{Expression={$_.Message};Label="MessageLong";width=2000}
$SysEvent = Get-Eventlog -Logname application -Newest 20 -EntryType Warning,Error
Write-Output "" >>$log
Write-Output "# Event Viewer - Application - Errors/Warnings found in the newest 2000 entries" >>$log
$SysEvent | Sort-Object EventID | Format-Table EventID, Source, EntryType, TimeWritten, $message -AutoSize >>$log

Clear-Host
Write-Host -ForegroundColor Yellow "Troubleshooting complete, please send us the $path.zip file"
Write-Host ""
Write-Host ""
#Write-Host -ForegroundColor Green "Two windows will appear, drag $path.zip to our FTP to upload it"
pause
#$desktop = [Environment]::GetFolderPath("Desktop")
#start $desktop
#if ($Host.Name -eq 'ConsoleHost') {
#    Stop-Process $PID
#}
# AllowCtrlC 
#$a = new-object -comobject wscript.shell
#$b = $a.popup("This is a test",0,"Test Message Box",1)
# powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/QuickTS')"

remove-item "$path.zip" -Force
write-zip $path "$path.zip"
remove-item $path -Recurse -Force

# Restoring Error preference
$ErrorActionPreference = $currentErrorPref

start C:\GFIlogs
explorer.exe ftp://gfi:gfi911cust@ftp.gfisoftware.com
#start $log

Write-Host -ForegroundColor Yellow "You may safely close this Window"