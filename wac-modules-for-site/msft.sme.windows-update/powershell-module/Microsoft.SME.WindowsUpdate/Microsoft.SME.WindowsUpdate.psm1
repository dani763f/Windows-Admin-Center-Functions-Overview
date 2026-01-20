function Enable-WACWUVSM {
<#

.SYNOPSIS
Script that enables Virtual Secure Mode (VSM).

.DESCRIPTION
Script that enables Virtual Secure Mode (VSM). For kernelmode patching, Virtual Secure Mode (VSM) needs to be enabled

.ROLE
Readers

#>

# Enable Virtual Secure Mode (VSM) for Gen 2 VM set
$deviceGuardPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceGuard"
if (-Not(Test-Path $deviceGuardPath)) {
  New-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value "1" ` -PropertyType "DWORD" -Force
}

}
## [END] Enable-WACWUVSM ##
function Get-WACWUAutomaticUpdatesOptions {
<#

.SYNOPSIS
Script that get windows update automatic update options from registry key.

.DESCRIPTION
Script that get windows update automatic update options from registry key.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management

# If there is AUOptions, return it, otherwise return NoAutoUpdate value
$option = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorVariable myerror -ErrorAction SilentlyContinue
if ($option -ne $null) {
  return $option.AUOptions
} elseif ($myerror) {
    $option = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorVariable myerror -ErrorAction SilentlyContinue
    if ($option -ne $null) {
      return $option.NoAutoUpdate
    } elseif ($myerror) {
        $option = 0 # not defined
    }
}
return $option

}
## [END] Get-WACWUAutomaticUpdatesOptions ##
function Get-WACWUAvailableWindowsUpdates {
<#

.SYNOPSIS
Get available windows updates through COM object by Windows Update Agent API.

.DESCRIPTION
Get available windows updates through COM object by Windows Update Agent API.

.ROLE
Readers

.PARAMETER serverSelection
  update service server

#>

Param(
  [Parameter(Mandatory = $true)]
  [int16]$serverSelection,
  [Parameter(Mandatory = $true)]
  [string]$nodeName
)

$objSession = Microsoft.PowerShell.Utility\New-Object -ComObject "Microsoft.Update.Session"
$objSearcher = $objSession.CreateUpdateSearcher()
$objSearcher.ServerSelection = $serverSelection
$objResults = $objSearcher.Search("IsInstalled = 0")

if (!$objResults -or !$objResults.Updates) {
  return $null
}

<#
InstallationBehavior.RebootBehaviour enum
	0: NeverReboots
	1: AlwaysRequiresReboot
  2: CanRequestReboot

InstallationBehavior.Impact enum
  0: Normal
	1: Minor
	2: RequiresExclusiveHandling
#>
$objResults.Updates | ForEach-Object {
  New-Object PSObject -Property @{
    Title                       = $_.Title
    IsMandatory                 = $_.IsMandatory
    RebootRequired              = $_.RebootRequired
    MsrcSeverity                = $_.MsrcSeverity
    IsUninstallable             = $_.IsUninstallable
    UpdateID                    = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Identity).UpdateID
    KBArticleIDs                = $_ | Microsoft.PowerShell.Utility\Select-Object  KBArticleIDs | ForEach-Object { $_.KbArticleids }
    CanRequestUserInput         = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).CanRequestUserInput
    Impact                      = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).Impact
    RebootBehavior              = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).RebootBehavior
    RequiresNetworkConnectivity = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).RequiresNetworkConnectivity
  }
}

}
## [END] Get-WACWUAvailableWindowsUpdates ##
function Get-WACWUHotpatchingPackage {
<#

.SYNOPSIS
Get hotpatching enrollment KB

.DESCRIPTION
Get hotpatching enrollment KB. If result is found, it means the device is enrolled to hotpatching, otherwise, it is not

.ROLE
Administrators

.PARAMETER kbID
Enrollment KB ID

#>

param (
  [Parameter(Mandatory = $true)]
  [String]$kbID
)

$wuKBID = $kbID.TrimStart("KB")
$installedPackages = Get-WindowsPackage -Online -ErrorAction SilentlyContinue | `
  Where-Object { $_.PackageName -like "*KB$wuKBID*" } | `
  Microsoft.PowerShell.Utility\Select-Object PackageName, PackageState, ReleaseType, InstallTime

$installedPackages

}
## [END] Get-WACWUHotpatchingPackage ##
function Get-WACWUHotpatchingPreReq {
<#

.SYNOPSIS
Script that checks if Azure Turbine Registry Keys are set.

.DESCRIPTION
Script that checks if Azure Turbine Registry Keys are set.

.ROLE
Readers

#>

function getCurrentVersion() {
  $currentVersionRegPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\d1b80b24-d888-417b-9020-47c035b24341"
  if (Test-Path $currentVersionRegPath) {
    return Get-ItemProperty -Path $currentVersionRegPath -ErrorAction SilentlyContinue
  }
  return $null
}




# KVP-IC. This tells us if we're on Azure Stack HCI or Azure Stack Hub, but not Azure compute
function getVMGuestParams {
  $vmGuestRegPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
  if (Test-Path $vmGuestRegPath) {
    return Get-ItemProperty -Path $vmGuestRegPath -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object HostName, HostingSystemEditionId, HostingSystemOsMajor, HostingSystemOsMinor, HostingSystemProcessorArchitecture, HostingSystemSpMajor, HostingSystemSpMinor, PhysicalHostName, PhysicalHostNameFullyQualified, VirtualMachineId, VirtualMachineName
  }
  return $null
}


# VMType: this tells us if we're on Azure Compute, also maybe Azure Stack Hub
# "VMType"="IAAS"
function getAzureVMType {
  $azureRegPath = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Azure"
  if (Test-Path $azureRegPath) {
    return (Get-ItemProperty -Path $azureRegPath -ErrorAction SilentlyContinue).VMType
  }
  return $null
}

<#
  For kernelmode patching, Virtual Secure Mode (VSM) needs to be enabled
  Check if Virtual Secure Mode (VSM) is enabled
    - Passing state: found
    - Failing state: not found
#>
function checkIfVsmIsEnabled {
  $vsm = Get-Process -Name "Secure System" -ErrorAction SilentlyContinue
  if ($vsm) {
    return $true
  }
  return $false
}

<#
Check Hotpatch Table Size is set.
#>
function getHotPatchTableSize {
  $memoryMgmtPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
  if (Test-Path $memoryMgmtPath) {
    return Get-ItemProperty -Path $memoryMgmtPath -Name "HotPatchTableSize" -ErrorAction SilentlyContinue
  }
  return $null
}

$vmGuestParams = getVMGuestParams
$hostingSystemEditionId = $vmGuestParams.HostingSystemEditionId
$hostingSystemOsMajor = $vmGuestParams.HostingSystemOsMajor
$hostingSystemOsMinor = $vmGuestParams.HostingSystemOsMinor

$azureVMType = getAzureVMType
$vsmIsEnabled = checkIfVsmIsEnabled
$hotpatchTableSize = getHotPatchTableSize

$result = New-Object PSObject
$result | Add-Member -MemberType NoteProperty -Name 'hostingSystemEditionId' -Value $hostingSystemEditionId
$result | Add-Member -MemberType NoteProperty -Name 'hostingSystemOsMajor' -Value $hostingSystemOsMajor
$result | Add-Member -MemberType NoteProperty -Name 'hostingSystemOsMinor' -Value $hostingSystemOsMinor
$result | Add-Member -MemberType NoteProperty -Name 'azureVMType' -Value $azureVMType
$result | Add-Member -MemberType NoteProperty -Name 'vsmIsEnabled' -Value $vsmIsEnabled
$result | Add-Member -MemberType NoteProperty -Name 'hotpatchTableSize' -Value $hotpatchTableSize

$result

}
## [END] Get-WACWUHotpatchingPreReq ##
function Get-WACWUMicrosoftMonitoringAgentStatus {
<#

.SYNOPSIS
Script that returns if Microsoft Monitoring Agent is running or not.

.DESCRIPTION
Script that returns if Microsoft Monitoring Agent is running or not.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management

$MMAStatus = Get-Service -Name HealthService -ErrorAction SilentlyContinue
if ($null -eq $MMAStatus) {
  # which means no such service is found.
  return @{ Installed = $false; Running = $false;}
}

$IsAgentRunning = $MMAStatus.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

$AgentConfig = New-Object -ComObject 'AgentConfigManager.mgmtsvccfg'
$Workspaces = @($AgentConfig.GetCloudWorkspaces() | Microsoft.PowerShell.Utility\Select-Object -Property WorkspaceId, AgentId)

return @{
  Installed                     = $true;
  Running                       = $IsAgentRunning;
  Workspaces                    = $Workspaces
}
}
## [END] Get-WACWUMicrosoftMonitoringAgentStatus ##
function Get-WACWUWindowsInstalledUpdates {
<#

.SYNOPSIS
Get installed windows updates through COM object by Windows Update Agent API.

.DESCRIPTION
Get installed windows updates through COM object by Windows Update Agent API.

.ROLE
Readers

.PARAMETER serverSelection
  update service server

#>

Param(
  [Parameter(Mandatory = $true)]
  [int16]$serverSelection
)


$objSession = Microsoft.PowerShell.Utility\New-Object -ComObject "Microsoft.Update.Session"
$objSearcher = $objSession.CreateUpdateSearcher()
# $objSearcher.ServerSelection = $serverSelection
$objResults = $objSearcher.Search("IsInstalled = 1")

if (!$objResults -or !$objResults.Updates) {
  return $null
}

<#
InstallationBehavior.RebootBehaviour enum
	0: NeverReboots
	1: AlwaysRequiresReboot
  2: CanRequestReboot

InstallationBehavior.Impact enum
  0: Normal
	1: Minor
	2: RequiresExclusiveHandling
#>

$objResults.Updates | ForEach-Object {
  New-Object PSObject -Property @{
    Title                       = $_.Title
    IsMandatory                 = $_.IsMandatory
    RebootRequired              = $_.RebootRequired
    MsrcSeverity                = $_.MsrcSeverity
    IsUninstallable             = $_.IsUninstallable
    InstallState                = $_.ResultCode
    InstallDate                 = $_.Date
    UpdateID                    = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Identity).UpdateID
    KBArticleIDs                = $_ | Microsoft.PowerShell.Utility\Select-Object  KBArticleIDs | ForEach-Object { $_.KbArticleids }
    CanRequestUserInput         = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).CanRequestUserInput
    Impact                      = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).Impact
    RebootBehavior              = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).RebootBehavior
    RequiresNetworkConnectivity = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty InstallationBehavior).RequiresNetworkConnectivity
  }
}

}
## [END] Get-WACWUWindowsInstalledUpdates ##
function Get-WACWUWindowsUpdateHistory {
<#

.SYNOPSIS
Get windows update history through COM object by Windows Update Agent API.

.DESCRIPTION
Get windows update history through COM object by Windows Update Agent API.

.ROLE
Readers

.PARAMETER serverSelection
  update service server

#>

Param(
  [Parameter(Mandatory = $true)]
  [int16]$serverSelection
)

Set-Variable -Name EntryLimit -Option ReadOnly -Value 10000 -Scope Script

$objSession = Microsoft.PowerShell.Utility\New-Object -ComObject "Microsoft.Update.Session"
$objSearcher = $objSession.CreateUpdateSearcher()
$objSearcher.ServerSelection = $serverSelection
$count = $objSearcher.GetTotalHistoryCount()

# Only get up to $EntryLimit latest entries
if ($count -gt $EntryLimit) {
  $history = $objSearcher.QueryHistory(0, $EntryLimit)
}
else {
  $history = $objSearcher.QueryHistory(0, $count)
}

$history | Microsoft.PowerShell.Core\Where-Object { $_.Operation -eq 1 } | ForEach-Object {
  New-Object PSObject -Property @{
    Title           = $_.Title
    ServerSelection = $_.ServerSelection
    InstallState    = $_.ResultCode
    InstallDate     = $_.Date
    UpdateID        = ($_ | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty UpdateIdentity).UpdateID
  }
}

}
## [END] Get-WACWUWindowsUpdateHistory ##
function Get-WACWUWindowsUpdateInstallerStatus {
<#

.SYNOPSIS
Script that check scheduled task for install updates is still running or not.

.DESCRIPTION
 Script that check scheduled task for install updates is still running or not. Notcied that using the following COM object has issue: when install-WUUpdates task is running, the busy status return false;
 but right after the task finished, it returns true.

.ROLE
Readers

#>

Import-Module ScheduledTasks

$TaskName = "SMEWindowsUpdateInstallUpdates"
$ScheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Ignore
if ($ScheduledTask -ne $Null -and $ScheduledTask.State -eq 4) { # Running
    return $True
} else {
    return $False
}

}
## [END] Get-WACWUWindowsUpdateInstallerStatus ##
function Get-WACWUWindowsUpdateUninstallerStatus {
<#

.SYNOPSIS
Script that check scheduled task for uninstalling updates is still running or not.

.DESCRIPTION
 Script that check scheduled task for install updates is still running or not. 

.ROLE
Readers

#>

Import-Module ScheduledTasks

$TaskName = "SMEWindowsUpdateUninstallUpdates"
$ScheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Ignore
if ($ScheduledTask -ne $null -and $ScheduledTask.State -eq 4) { 
    # Running
    return $True
} else {
    return $False
}

}
## [END] Get-WACWUWindowsUpdateUninstallerStatus ##
function Install-WACWUMicrosoftMonitoringAgent {
<#

.SYNOPSIS
Script that returns if Microsoft Monitoring Agent is running or not.

.DESCRIPTION
Download and install MMAAgent

.ROLE
Administrators

#>

[CmdletBinding()]
param (
  [Parameter()]
  [String]
  $WorkspaceId,
  [Parameter()]
  [String]
  $WorkspacePrimaryKey,
  [Parameter()]
  [bool]
  $EnableHciHealthSettingsOnNode,
  [Parameter()]
  [int]
  $AzureCloudType
)

$ErrorActionPreference = "Stop"

$MMAAgentStatus = Get-Service -Name HealthService -ErrorAction SilentlyContinue
$IsMmaRunning = $null -eq $MMAAgentStatus -and $MMAAgentStatus.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

if (-not $IsMmaRunning) {

  # install MMA agent
  $MmaExePath = Join-Path -Path $env:temp -ChildPath 'MMASetup-AMD64.exe'
  if (Test-Path $MmaExePath) {
    Remove-Item $MmaExePath
  }
  Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkId=828603 -OutFile $MmaExePath

  $ExtractFolder = Join-Path -Path $env:temp -ChildPath 'SmeMMAInstaller'
  if (Test-Path $ExtractFolder) {
    Remove-Item $ExtractFolder -Force -Recurse
  }

  &$MmaExePath /c /t:$ExtractFolder
  $SetupExePath = Join-Path -Path $ExtractFolder -ChildPath 'setup.exe'
  for ($i = 0; $i -lt 60; $i++) {
    if (-Not(Test-Path $SetupExePath)) {
      Start-Sleep -Seconds 1
    }
  }

  &$SetupExePath /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=$AzureCloudType OPINSIGHTS_WORKSPACE_ID=$WorkspaceId OPINSIGHTS_WORKSPACE_KEY=$WorkspacePrimaryKey AcceptEndUserLicenseAgreement=1
}

# Wait for agents to completely install
for ($i = 0; $i -lt 60; $i++) {
  if ($null -eq (Get-Service -Name HealthService -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 5
  }
}

<#
 # .DESCRIPTION
 # Enable health settings on HCI cluster node to log faults into Microsoft-Windows-Health/Operational
 #>
if ($EnableHciHealthSettingsOnNode) {
  $subsystem = Get-StorageSubsystem clus*
  $subsystem | Set-StorageHealthSetting -Name "Platform.ETW.MasTypes" -Value "Microsoft.Health.EntityType.Subsystem,Microsoft.Health.EntityType.Server,Microsoft.Health.EntityType.PhysicalDisk,Microsoft.Health.EntityType.StoragePool,Microsoft.Health.EntityType.Volume,Microsoft.Health.EntityType.Cluster"
}

}
## [END] Install-WACWUMicrosoftMonitoringAgent ##
function Install-WACWUWindowsUpdates {
<#

.SYNOPSIS
Create a scheduled task to run a powershell script file to installs all available windows updates through ComObject, restart the machine if needed.

.DESCRIPTION
Create a scheduled task to run a powershell script file to installs given windows updates through ComObject, restart the machine if needed.
This is a workaround since CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
More details see https://msdn.microsoft.com/en-us/library/windows/desktop/aa387288(v=vs.85).aspx

.ROLE
Administrators

.PARAMETER restartTime
  The user-defined time to restart after update (Optional).

.PARAMETER serverSelection
  update service server

.PARAMETER updateIDs
  the list of update IDs to be installed

#>

param (
  [Parameter(Mandatory = $true)]
  [int16]$serverSelection,
  [Parameter(Mandatory = $true)]
  [String[]]$updateIDs,
  [Parameter(Mandatory = $false)]
  [String]$restartTime,
  [Parameter(Mandatory = $false)]
  [Boolean]$skipRestart,
  [Parameter(Mandatory = $true)]
  [boolean]
  $fromTaskScheduler
)

function installWindowsUpdates() {
  param (
    [String]
    $restartTime,
    [Boolean]
    $skipRestart,
    [int16]
    $serverSelection,
    [String[]]
    $updateIDs
  )
  $objServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager';
  $objSession = New-Object -ComObject 'Microsoft.Update.Session';
  $objSearcher = $objSession.CreateUpdateSearcher();
  $objSearcher.ServerSelection = $serverSelection;
  $serviceName = 'Windows Update';
  $search = 'IsInstalled = 0';
  $objResults = $objSearcher.Search($search);
  $Updates = $objResults.Updates;
  $FoundUpdatesToDownload = $Updates.Count;

  $NumberOfUpdate = 1;
  $objCollectionDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl';
  $updateCount = $updateIDs.Count;
  Foreach ($Update in $Updates) {
    If ($Update.Identity.UpdateID -in $updateIDs) {
      Write-Progress -Activity 'Downloading updates' -Status `"[$NumberOfUpdate/$updateCount]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate / $updateCount * 100));
      $NumberOfUpdate++;
      Write-Debug `"Show` update` to` download:` $($Update.Title)`" ;
      Write-Debug 'Accept Eula';
      $Update.AcceptEula();
      Write-Debug 'Send update to download collection';
      $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
      $objCollectionTmp.Add($Update) | Out-Null;

      $Downloader = $objSession.CreateUpdateDownloader();
      $Downloader.Updates = $objCollectionTmp;
      Try {
        Write-Debug 'Try download update';
        $DownloadResult = $Downloader.Download();
      } <#End Try#>
      Catch {
        If ($_ -match 'HRESULT: 0x80240044') {
          Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
        } <#End If $_ -match 'HRESULT: 0x80240044'#>

        Return
      } <#End Catch#>

      Write-Debug 'Check ResultCode';
      Switch -exact ($DownloadResult.ResultCode) {
        0 { $Status = 'NotStarted'; }
        1 { $Status = 'InProgress'; }
        2 { $Status = 'Downloaded'; }
        3 { $Status = 'DownloadedWithErrors'; }
        4 { $Status = 'Failed'; }
        5 { $Status = 'Aborted'; }
      } <#End Switch#>

      If ($DownloadResult.ResultCode -eq 2) {
        Write-Debug 'Downloaded then send update to next stage';
        $objCollectionDownload.Add($Update) | Out-Null;
      } <#End If $DownloadResult.ResultCode -eq 2#>
    }
  }

  $ReadyUpdatesToInstall = $objCollectionDownload.count;
  Write-Verbose `"Downloaded` [$ReadyUpdatesToInstall]` Updates` to` Install`" ;
  If ($ReadyUpdatesToInstall -eq 0) {
    Return;
  } <#End If $ReadyUpdatesToInstall -eq 0#>

  $NeedsReboot = $false;
  $NumberOfUpdate = 1;

  <#install updates#>
  Foreach ($Update in $objCollectionDownload) {
    Write-Progress -Activity 'Installing updates' -Status `"[$NumberOfUpdate/$ReadyUpdatesToInstall]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate / $ReadyUpdatesToInstall * 100));
    Write-Debug 'Show update to install: $($Update.Title)';

    Write-Debug 'Send update to install collection';
    $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $objCollectionTmp.Add($Update) | Out-Null;

    $objInstaller = $objSession.CreateUpdateInstaller();
    $objInstaller.Updates = $objCollectionTmp;

    Try {
      Write-Debug 'Try install update';
      $InstallResult = $objInstaller.Install();
    } <#End Try#>
    Catch {
      If ($_ -match 'HRESULT: 0x80240044') {
        Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
      } <#End If $_ -match 'HRESULT: 0x80240044'#>

      Return;
    } #End Catch

    If (!$NeedsReboot) {
      Write-Debug 'Set instalation status RebootRequired';
      $NeedsReboot = $installResult.RebootRequired;
    } <#End If !$NeedsReboot#>
    $NumberOfUpdate++;
  } <#End Foreach $Update in $objCollectionDownload#>
  If ($NeedsReboot) {
    <#Restart almost immediately, given some seconds for this PSSession to complete.#>
    $waitTime = 5
    if ($restartTime -and $skipRestart) {
      <#Restart at given time#>
      $waitTime = [decimal]::round(((Get-Date $restartTime) - (Get-Date)).TotalSeconds);
      if ($waitTime -lt 5 ) {
        $waitTime = 5
      }
    }
    Shutdown -r -t $waitTime -c "SME installing Windows updates";
  }
}

#---- Script execution starts here ----
function isSystemLockdownPolicyEnforced() {
  return [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -eq [System.Management.Automation.Security.SystemEnforcementMode]::Enforce
}
$isWdacEnforced = isSystemLockdownPolicyEnforced;

#In WDAC environment script file will already be available on the machine
#In WDAC mode the same script is executed - once normally and once through task Scheduler
if ($isWdacEnforced) {
    if ($fromTaskScheduler) {
      installWindowsUpdates $restartTime $skipRestart $serverSelection $updateIDs;
      return;
    }
}
else {
  #In non-WDAC environment script file will not be available on the machine
  #Hence, a dynamic script is created which is executed through the task Scheduler
    $ScriptFile = $env:LocalAppData + "\Install-Updates.ps1"
}

$HashArguments = @{};
if ($restartTime) {
    $HashArguments.Add("restartTime", $restartTime)
}
$HashArguments.Add("skipRestart", $skipRestart)

$tempArgs = ""
foreach ($key in $HashArguments.Keys) {
    $value = $HashArguments[$key]
    if ($value.GetType().Name -eq "String") {
      $value = "'$value'"
    }
    elseif ($value.GetType().Name -eq "Boolean") {
      $value = if ($value -eq $true) { "`$true" } else { "`$false" }
    }
    $tempArgs += " -$key $value"
}

#Create a scheduled task
$TaskName = "SMEWindowsUpdateInstallUpdates"
$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

#$OFS is a special variable that contains the string to be used as the Ouptut Field Separator.
#This string is used when an array is converted to a string.  By default, this is " " (white space).
#Change it to separate string array $updateIDs as xxxxx,yyyyyy,zzzzz etc.
$OFS = ","
$tempUpdateIds = [string]$updateIDs

if ($isWdacEnforced) {
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.WindowsUpdate; Install-WACWUWindowsUpdates -fromTaskScheduler `$true -serverSelection $serverSelection $tempArgs -updateIDs $tempUpdateIds }"""
}
else {
    (Get-Command installWindowsUpdates).ScriptBlock | Set-Content -path $ScriptFile
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command ""&{Set-Location -Path $env:LocalAppData; .\Install-Updates.ps1 -serverSelection $serverSelection $tempArgs -updateIDs $tempUpdateIds }"""
}
if (!$Role) {
  Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
}

$Scheduler = New-Object -ComObject Schedule.Service

#Try to connect to schedule service 3 time since it may fail the first time
for ($i = 1; $i -le 3; $i++) {
  Try {
    $Scheduler.Connect()
    Break
  }
  Catch {
    if ($i -ge 3) {
      Write-EventLog -LogName Application -Source "SME Windows Updates Install Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
      Write-Error "Can't connect to Schedule service" -ErrorAction Stop
    }
    else {
      Start-Sleep -s 1
    }
  }
}

$RootFolder = $Scheduler.GetFolder("\")
#Delete existing task
if ($RootFolder.GetTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Write-Debug("Deleting existing task" + $TaskName)
  $RootFolder.DeleteTask($TaskName, 0)
}

$Task = $Scheduler.NewTask(0)
$RegistrationInfo = $Task.RegistrationInfo
$RegistrationInfo.Description = $TaskName
$RegistrationInfo.Author = $User.Name

$Triggers = $Task.Triggers
$Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
$Trigger.Enabled = $true

$Settings = $Task.Settings
$Settings.Enabled = $True
$Settings.StartWhenAvailable = $True
$Settings.Hidden = $False

$Action = $Task.Actions.Create(0)
$Action.Path = "powershell"
$Action.Arguments = $arg

#Tasks will be run with the highest privileges
$Task.Principal.RunLevel = 1

#Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
#Wait for running task finished
$RootFolder.GetTask($TaskName).Run(0) | Out-Null
while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Start-Sleep -s 1
}

#Clean up
$RootFolder.DeleteTask($TaskName, 0)
if (!$isWdacEnforced) {
  Remove-Item $ScriptFile
}

}
## [END] Install-WACWUWindowsUpdates ##
function Set-WACWUAutomaticUpdatesOptions {
<#

.SYNOPSIS
Script that set windows update automatic update options in registry key.

.DESCRIPTION
Script that set windows update automatic update options in registry key.

.EXAMPLE
Set AUoptions
PS C:\> Set-AUoptions "2"

.ROLE
Administrators

#>

Param(
[Parameter(Mandatory = $true)]
[string]$AUOptions
)

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
switch($AUOptions)
{
    '0' # Not defined, delete registry folder if exist
        {
            if (Test-Path $Path) {
                Remove-Item $Path
            }
        }
    '1' # Disabled, set NoAutoUpdate to 1 and delete AUOptions if existed
        {
            if (Test-Path $Path) {
                Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
                Remove-ItemProperty -Path $Path -Name AUOptions
            }
            else {
                New-Item $Path -Force
                New-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
            }
        }
    default # else 2-5, set AUoptions
        {
             if (!(Test-Path $Path)) {
                 New-Item $Path -Force
            }
            Set-ItemProperty -Path $Path -Name AUOptions -Value $AUOptions -Force
            Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x0 -Force
        }
}

}
## [END] Set-WACWUAutomaticUpdatesOptions ##
function Set-WACWUHotpatchTableSize {
<#

.SYNOPSIS
Script that sets the HotPatch Table Size registry key.

.DESCRIPTION
Script that sets the HotPatch Table Size registry key.

.ROLE
Readers

#>

<#
Check Hotpatch Table Size is set.
Setting it requires reboot
#>

$sessionMngrPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager"
$memoryMgmtPath = "$sessionMngrPath\Memory Management"
if (-Not(Test-Path $memoryMgmtPath)) {
  New-Item $memoryMgmtPath
}

New-ItemProperty -Path $memoryMgmtPath -Name "HotPatchTableSize" -Value 0x1000 -PropertyType "DWORD"

# Alert user that system requires restart

}
## [END] Set-WACWUHotpatchTableSize ##
function Uninstall-WACWUWindowsUpdates {
<#

.SYNOPSIS
Create a scheduled task to run a powershell script file to uninstalls available windows updates through dism and restart the machine if needed.

.DESCRIPTION
Create a scheduled task to run a powershell script file to uninstalls given windows updates through dism and restart the machine if needed.
This is a workaround because we cannot use Windows Update Agent (WUA) API to uninstall updates. We get the error: 0x80240028 (WU_E_UNINSTALL_NOT_ALLOWED)

.ROLE
Administrators

.PARAMETER restartTime
  The user-defined time to restart after update (Optional).

.PARAMETER serverSelection
  update service server

.PARAMETER updateIDs
  the list of update IDs to be installed

#>

param (
  [Parameter(Mandatory = $false)]
  [String]$restartTime,
  [Parameter(Mandatory = $true)]
  [int16]$serverSelection,
  [Parameter(Mandatory = $true)]
  [String[]]$updateIDs,
  [Parameter(Mandatory = $true)]
  [boolean]
  $fromTaskScheduler
)

function uninstallWindowsUpdates() {
  param (
    [String]
    $restartTime,
    [int16]
    $serverSelection,
    [String[]]
    $updateIDs
  )

  enum RebootBehaviourEnum {
    NeverReboots = 0
    AlwaysRequiresReboot = 1
    CanRequestReboot = 2
  }

  enum ImpactEnum {
    Normal = 0
    Minor = 1
    RequiresExclusiveHandling = 2
  }

  $objSession = New-Object -ComObject 'Microsoft.Update.Session';

  # Total updates passed to uninstall
  $updateCount = $updateIDs.Count;

  # Get all installed updates
  $objSearcher = $objSession.CreateUpdateSearcher();
  $objSearcher.ServerSelection = $serverSelection;

  # From the list of available updates, get update object of those passed for uninstallation
  $installedUpdates = $objSearcher.Search('IsInstalled = 1').updates;

  $needsReboot = $false;
  $numberOfUpdate = 1;

  foreach ($updateID in $updateIDs) {
    # Get Windows Update information using Windows Update Agent (WUA) API
    $updateInfo = $installedUpdates | Where-Object { $_.Identity.UpdateID -in $updateID } | `
      Microsoft.PowerShell.Utility\Select-Object -ErrorAction SilentlyContinue `
      Title, IsUninstallable, IsMandatory, RebootRequired, MsrcSeverity, `
    @{Name = "UpdateID"; Expression = { $_.Identity | Microsoft.PowerShell.Utility\Select-Object UpdateID } }, `
    @{Name = "KBArticleIDs"; Expression = { $_.KBArticleIDs } }, `
    @{Name = "InstallationBehaviorResult"; expression = { $_.InstallationBehavior } } | `
      Microsoft.PowerShell.Utility\Select-Object -ErrorAction SilentlyContinue `
      -Property * -ExcludeProperty UpdateID -ExpandProperty UpdateID | `
      Microsoft.PowerShell.Utility\Select-Object -ErrorAction SilentlyContinue `
      -Property * -ExpandProperty InstallationBehaviorResult | `
      Microsoft.PowerShell.Utility\Select-Object -ErrorAction SilentlyContinue `
      -Property * -ExcludeProperty  InstallationBehaviorResult | `
      Microsoft.PowerShell.Utility\Select-Object -ErrorAction SilentlyContinue `
      -Property *, `
    @{Name = "RebootBehaviorDesc"; Expression = { [RebootBehaviourEnum].GetEnumName($_.RebootBehavior) } }

    # Report Progress
    Write-Progress -Activity 'Uninstalling updates' -Status `"[$numberOfUpdate/$updateCount]` $($updateInfo.Title)`" `
      -PercentComplete ([int]($numberOfUpdate / $updateCount * 100));
    $numberOfUpdate++;

    if (($updateInfo | Microsoft.PowerShell.Utility\Measure-Object).Count -eq 0) {
      continue;
    }

    # Get kbID to use to get package ingo
    $kbID = $updateInfo.KBArticleIDs
    if (!$kbID) {
      Write-Warning "Unable to uninstall update $($updateInfo.Title)";
    }

    # Set package info using dism
    $packageDetails = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like "*KB$kbID*" } | `
      Microsoft.PowerShell.Utility\Select-Object PackageName, PackageState, Path, RestartNeeded, SysDrivePath, WinPath


    if (($packageDetails | Microsoft.PowerShell.Utility\Measure-Object).Count -eq 0) {
      Write-Warning "Unable to uninstall update $($updateInfo.Title). This update is uninstallable";
      continue;
    }

    # Uninstall update
    try {
      Write-Debug "Trying uninstall update $($updateInfo.Title)";
      # $uninstallResult = Remove-WindowsPackage -Online -PackageName ($packageDetails.PackageName | Out-String) -NoRestart
      $uninstallResult = Remove-WindowsPackage -Online -PackageName $packageDetails.PackageName -NoRestart
    } <#End try#>
    catch {
      Write-Warning "Unable to uninstall update $($updateInfo.Title).`n$_";
      continue;
    } #End catch

    # Check if uninstall requires update
    if (!$needsReboot) {
      Write-Debug 'Set instalation status RebootRequired';
      $needsReboot = if (($updateInfo.RebootBehavior -gt 0) -or ($unInstallResult.RestartNeeded)) { $true } else { $false };
    } <#End if !$needsReboot#>
  }

  if ($needsReboot) {
    <#Restart almost immediately, given some seconds for this PSSession to complete.#>
    $waitTime = 5
    if ($restartTime) {
      <#Restart at given time#>
      $waitTime = [decimal]::round(((Get-Date $restartTime) - (Get-Date)).TotalSeconds);
      if ($waitTime -lt 5 ) {
        $waitTime = 5
      }
    }
    Shutdown -r -t $waitTime -c "SME uninstalling Windows updates";
  }
}

#---- Script execution starts here ----
function isSystemLockdownPolicyEnforced() {
  return [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -eq [System.Management.Automation.Security.SystemEnforcementMode]::Enforce
}
$isWdacEnforced = isSystemLockdownPolicyEnforced;

#In WDAC environment script file will already be available on the machine
#In WDAC mode the same script is executed - once normally and once through task Scheduler
if ($isWdacEnforced) {
  if ($fromTaskScheduler) {
    uninstallWindowsUpdates $restartTime $serverSelection $updateIDs;
    return;
  }
}
else {
  #In non-WDAC environment script file will not be available on the machine
  #Hence, a dynamic script is created which is executed through the task Scheduler
  $ScriptFile = $env:LocalAppData + "\Uninstall-Updates.ps1"
}

$HashArguments = @{};
if ($restartTime) {
    $HashArguments.Add("restartTime", $restartTime)
}

$tempArgs = ""
foreach ($key in $HashArguments.Keys) {
  $value = $HashArguments[$key]
  $value = """$value"""
  $tempArgs += " -$key $value"
}

#Create a scheduled task
$TaskName = "SMEWindowsUpdateUninstallUpdates"

$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

#$OFS is a special variable that contains the string to be used as the Ouptut Field Separator.
#This string is used when an array is converted to a string.  By default, this is " " (white space).
#Change it to separate string array $updateIDs as 'xxxxx','yyyyyy' etc.
$OFS = "','"
$tempUpdateIds = [string]$updateIDs

if ($isWdacEnforced) {
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.WindowsUpdate; Uninstall-WACWUWindowsUpdates -fromTaskScheduler `$true -serverSelection $serverSelection $tempArgs -updateIDs $tempUpdateIds }"""
}
else {
  (Get-Command uninstallWindowsUpdates).ScriptBlock | Set-Content -path $ScriptFile
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command ""&{Set-Location -Path $env:LocalAppData; .\Uninstall-Updates.ps1 -serverSelection $serverSelection $tempArgs -updateIDs $tempUpdateIds }"""
}

if (!$Role) {
  Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
}

$Scheduler = New-Object -ComObject Schedule.Service

#Try to connect to schedule service 3 time since it may fail the first time
for ($i = 1; $i -le 3; $i++) {
  Try {
    $Scheduler.Connect()
    Break
  }
  Catch {
    if ($i -ge 3) {
      Write-EventLog -LogName Application -Source "SME Windows Updates Uninstall Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
      Write-Error "Can't connect to Schedule service" -ErrorAction Stop
    }
    else {
      Start-Sleep -s 1
    }
  }
}

$RootFolder = $Scheduler.GetFolder("\")
#Delete existing task
if ($RootFolder.GetTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Write-Debug("Deleting existing task" + $TaskName)
  $RootFolder.DeleteTask($TaskName, 0)
}

$Task = $Scheduler.NewTask(0)
$RegistrationInfo = $Task.RegistrationInfo
$RegistrationInfo.Description = $TaskName
$RegistrationInfo.Author = $User.Name

$Triggers = $Task.Triggers
$Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
$Trigger.Enabled = $true

$Settings = $Task.Settings
$Settings.Enabled = $True
$Settings.StartWhenAvailable = $True
$Settings.Hidden = $False

$Action = $Task.Actions.Create(0)
$Action.Path = "powershell"
$Action.Arguments = $arg

#Tasks will be run with the highest privileges
$Task.Principal.RunLevel = 1

#Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
#Wait for running task finished
$RootFolder.GetTask($TaskName).Run(0) | Out-Null
while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Start-Sleep -s 1
}

#Clean up
$RootFolder.DeleteTask($TaskName, 0)
if (!$isWdacEnforced) {
  Remove-Item $ScriptFile
}

}
## [END] Uninstall-WACWUWindowsUpdates ##
function Add-WACWUAdministrators {
<#

.SYNOPSIS
Adds administrators

.DESCRIPTION
Adds administrators

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory=$true)]
    [String] $usersListString
)


$usersToAdd = ConvertFrom-Json $usersListString
$adminGroup = Get-LocalGroup | Where-Object SID -eq 'S-1-5-32-544'

Add-LocalGroupMember -Group $adminGroup -Member $usersToAdd

Register-DnsClient -Confirm:$false

}
## [END] Add-WACWUAdministrators ##
function Disconnect-WACWUAzureHybridManagement {
<#

.SYNOPSIS
Disconnects a machine from azure hybrid agent.

.DESCRIPTION
Disconnects a machine from azure hybrid agent and uninstall the hybrid instance service.
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER tenantId
    The GUID that identifies a tenant in AAD

.PARAMETER authToken
    The authentication token for connection

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $tenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $authToken
)

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Disconnect-HybridManagement.ps1" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
    Set-Variable -Name HybridAgentPackage -Option ReadOnly -Value "Azure Connected Machine Agent" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
    Remove-Variable -Name HybridAgentPackage -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Disconnects a machine from azure hybrid agent.

#>

function main(
    [string]$tenantId,
    [string]$authToken
) {
    $err = $null
    $args = @{}

   # Disconnect Azure hybrid agent
   & $HybridAgentExecutable disconnect --access-token $authToken

   # Uninstall Azure hybrid instance metadata service
   Uninstall-Package -Name $HybridAgentPackage -ErrorAction SilentlyContinue -ErrorVariable +err

   if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not uninstall the package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        throw $err
   }

}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $tenantId $authToken

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Disconnect-WACWUAzureHybridManagement ##
function Get-WACWUAzureHybridManagementConfiguration {
<#

.SYNOPSIS
Script that return the hybrid management configurations.

.DESCRIPTION
Script that return the hybrid management configurations.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.Management

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Onboards a machine for hybrid management.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-HybridManagementConfiguration.ps1" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
}

function main() {
    $config = & $HybridAgentExecutable show

    if (-not $config) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue
        return @()
    }

    $configData = @{}

    foreach ($item in $config) {
        if ($item -match '^\s*(.*?):\s*(.*)$') {
            $key = getKey($matches[1].Trim())
            $value = $matches[2].Trim()
            $configData[$key] = $value
        }
    }

    if ($configData.Count -gt 0) {
        return @{
            machine = $configData['ResourceName'];
            resourceGroup = $configData['ResourceGroupName'];
            subscriptionId = $configData['SubscriptionID'];
            tenantId = $configData['TenantID'];
            vmId = $configData['VMID'];
            azureRegion = $configData['Location'];
            agentVersion = $configData['AgentVersion'];
            agentStatus = $configData['AgentStatus'];
            agentLastHeartbeat = $configData['AgentLastHeartbeat'];
            agentErrorDetails = $configData['AgentErrorDetails'];
            agentErrorCode = $configData['AgentErrorCode'];
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }
}

function getKey([string]$key) {
    # Modify key names based on first three/two words if the words > 1 else pick first word as the key
    $newKey = ""
    $words = $key -split '\s+'
    if ($words.Count -ge 3) {
        $newKey = $words[0] + $words[1] + $words[2]
    } elseif ($words.Count -eq 2) {
        $newKey = $words[0] + $words[1]
    } else {
        $newKey = $words[0]
    }
    return $newKey
}

###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main

} finally {
    cleanupScriptEnv
}
}
## [END] Get-WACWUAzureHybridManagementConfiguration ##
function Get-WACWUAzureHybridManagementOnboardState {
<#

.SYNOPSIS
Script that returns if Azure Hybrid Agent is running or not.

.DESCRIPTION
Script that returns if Azure Hybrid Agent is running or not.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management

$status = Get-Service -Name himds -ErrorAction SilentlyContinue
if ($null -eq $status) {
    # which means no such service is found.
    @{ Installed = $false; Running = $false }
}
elseif ($status.Status -eq "Running") {
    @{ Installed = $true; Running = $true }
}
else {
    @{ Installed = $true; Running = $false }
}

}
## [END] Get-WACWUAzureHybridManagementOnboardState ##
function Get-WACWUCimServiceDetail {
<#

.SYNOPSIS
Gets services in details using MSFT_ServerManagerTasks class.

.DESCRIPTION
Gets services in details using MSFT_ServerManagerTasks class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
)

import-module CimCmdlets

Invoke-CimMethod -Namespace root/microsoft/windows/servermanager -ClassName MSFT_ServerManagerTasks -MethodName GetServerServiceDetail

}
## [END] Get-WACWUCimServiceDetail ##
function Get-WACWUCimSingleService {
<#

.SYNOPSIS
Gets the service instance of CIM Win32_Service class.

.DESCRIPTION
Gets the service instance of CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Get-CimInstance $keyInstance

}
## [END] Get-WACWUCimSingleService ##
function Resolve-WACWUDNSName {
<#

.SYNOPSIS
Resolve VM Provisioning

.DESCRIPTION
Resolve VM Provisioning

.ROLE
Administrators

#>

Param
(
    [string] $computerName
)

$succeeded = $null
$count = 0;
$maxRetryTimes = 15 * 100 # 15 minutes worth of 10 second sleep times
while ($count -lt $maxRetryTimes)
{
  $resolved =  Resolve-DnsName -Name $computerName -ErrorAction SilentlyContinue

    if ($resolved)
    {
      $succeeded = $true
      break
    }

    $count += 1

    if ($count -eq $maxRetryTimes)
    {
        $succeeded = $false
    }

    Start-Sleep -Seconds 10
}

Write-Output @{ "succeeded" = $succeeded }

}
## [END] Resolve-WACWUDNSName ##
function Resume-WACWUCimService {
<#

.SYNOPSIS
Resume a service using CIM Win32_Service class.

.DESCRIPTION
Resume a service using CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName ResumeService

}
## [END] Resume-WACWUCimService ##
function Set-WACWUAzureHybridManagement {
<#

.SYNOPSIS
Onboards a machine for hybrid management.

.DESCRIPTION
Sets up a non-Azure machine to be used as a resource in Azure
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER subscriptionId
    The GUID that identifies subscription to Azure services

.PARAMETER resourceGroup
    The container that holds related resources for an Azure solution

.PARAMETER tenantId
    The GUID that identifies a tenant in AAD

.PARAMETER azureRegion
    The region in Azure where the service is to be deployed

.PARAMETER useProxyServer
    The flag to determine whether to use proxy server or not

.PARAMETER proxyServerIpAddress
    The IP address of the proxy server

.PARAMETER proxyServerIpPort
    The IP port of the proxy server

.PARAMETER authToken
    The authentication token for connection

.PARAMETER correlationId
    The correlation ID for the connection

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $subscriptionId,
    [Parameter(Mandatory = $true)]
    [String]
    $resourceGroup,
    [Parameter(Mandatory = $true)]
    [String]
    $tenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $azureRegion,
    [Parameter(Mandatory = $true)]
    [boolean]
    $useProxyServer,
    [Parameter(Mandatory = $false)]
    [String]
    $proxyServerIpAddress,
    [Parameter(Mandatory = $false)]
    [String]
    $proxyServerIpPort,
    [Parameter(Mandatory = $true)]
    [string]
    $authToken,
    [Parameter(Mandatory = $true)]
    [string]
    $correlationId
)

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScript" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-HybridManagement.ps1" -Scope Script
    Set-Variable -Name Machine -Option ReadOnly -Value "Machine" -Scope Script
    Set-Variable -Name HybridAgentFile -Option ReadOnly -Value "AzureConnectedMachineAgent.msi" -Scope Script
    Set-Variable -Name HybridAgentPackageLink -Option ReadOnly -Value "https://aka.ms/AzureConnectedMachineAgent" -Scope Script
    Set-Variable -Name HybridAgentExecutable -Option ReadOnly -Value "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -Scope Script
    Set-Variable -Name HttpsProxy -Option ReadOnly -Value "https_proxy" -Scope Script
}

<#

.SYNOPSIS
Cleanup script runtime environment.

.DESCRIPTION
Cleanup script runtime environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name Machine -Scope Script -Force
    Remove-Variable -Name HybridAgentFile -Scope Script -Force
    Remove-Variable -Name HybridAgentPackageLink -Scope Script -Force
    Remove-Variable -Name HybridAgentExecutable -Scope Script -Force
    Remove-Variable -Name HttpsProxy -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Export the passed in virtual machine on this server.

#>

function main(
    [string]$subscriptionId,
    [string]$resourceGroup,
    [string]$tenantId,
    [string]$azureRegion,
    [boolean]$useProxyServer,
    [string]$proxyServerIpAddress,
    [string]$proxyServerIpPort,
    [string]$authToken,
    [string]$correlationId
) {
    $err = $null
    $args = @{}

    # Download the package
    Invoke-WebRequest -Uri $HybridAgentPackageLink -OutFile $HybridAgentFile -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Couldn't download the hybrid management package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }

    # Install the package
    msiexec /i $HybridAgentFile /l*v installationlog.txt /qn | Out-String -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Error while installing the hybrid agent package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }

    # Set the proxy environment variable. Note that authenticated proxies are not supported for Private Preview.
    if ($useProxyServer) {
        [System.Environment]::SetEnvironmentVariable($HttpsProxy, $proxyServerIpAddress+':'+$proxyServerIpPort, $Machine)
        $env:https_proxy = [System.Environment]::GetEnvironmentVariable($HttpsProxy, $Machine)
    }

    # Run connect command
    & $HybridAgentExecutable connect --resource-group $resourceGroup --tenant-id $tenantId --location $azureRegion `
                                     --subscription-id $subscriptionId --access-token $authToken --correlation-id $correlationId

    # Restart himds service
    Restart-Service -Name himds -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Couldn't restart the himds service. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return $err
    }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $subscriptionId $resourceGroup $tenantId $azureRegion $useProxyServer $proxyServerIpAddress $proxyServerIpPort $authToken $correlationId

} finally {
    cleanupScriptEnv
}

}
## [END] Set-WACWUAzureHybridManagement ##
function Set-WACWUVMPovisioning {
<#

.SYNOPSIS
Prepare VM Provisioning

.DESCRIPTION
Prepare VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [array]$disks
)

$output = @{ }

$requiredDriveLetters = $disks.driveLetter
$volumeLettersInUse = (Get-Volume | Sort-Object DriveLetter).DriveLetter

$output.Set_Item('restartNeeded', $false)
$output.Set_Item('pageFileLetterChanged', $false)
$output.Set_Item('pageFileLetterNew', $null)
$output.Set_Item('pageFileLetterOld', $null)
$output.Set_Item('pageFileDiskNumber', $null)
$output.Set_Item('cdDriveLetterChanged', $false)
$output.Set_Item('cdDriveLetterNew', $null)
$output.Set_Item('cdDriveLetterOld', $null)

$cdDriveLetterNeeded = $false
$cdDrive = Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Microsoft.PowerShell.Utility\Select-Object -First 1
if ($cdDrive -ne $null) {
    $cdDriveLetter = $cdDrive.DriveLetter.split(':')[0]
    $output.Set_Item('cdDriveLetterOld', $cdDriveLetter)

    if ($requiredDriveLetters.Contains($cdDriveLetter)) {
        $cdDriveLetterNeeded = $true
    }
}

$pageFileLetterNeeded = $false
$pageFile = Get-WmiObject Win32_PageFileusage
if ($pageFile -ne $null) {
    $pagingDriveLetter = $pageFile.Name.split(':')[0]
    $output.Set_Item('pageFileLetterOld', $pagingDriveLetter)

    if ($requiredDriveLetters.Contains($pagingDriveLetter)) {
        $pageFileLetterNeeded = $true
    }
}

if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $capitalCCharNumber = 67;
    $capitalZCharNumber = 90;

    for ($index = $capitalCCharNumber; $index -le $capitalZCharNumber; $index++) {
        $tempDriveLetter = [char]$index

        $willConflict = $requiredDriveLetters.Contains([string]$tempDriveLetter)
        $inUse = $volumeLettersInUse.Contains($tempDriveLetter)
        if (!$willConflict -and !$inUse) {
            if ($cdDriveLetterNeeded) {
                $output.Set_Item('cdDriveLetterNew', $tempDriveLetter)
                $cdDrive | Set-WmiInstance -Arguments @{DriveLetter = $tempDriveLetter + ':' } > $null
                $output.Set_Item('cdDriveLetterChanged', $true)
                $cdDriveLetterNeeded = $false
            }
            elseif ($pageFileLetterNeeded) {

                $computerObject = Get-WmiObject Win32_computersystem -EnableAllPrivileges
                $computerObject.AutomaticManagedPagefile = $false
                $computerObject.Put() > $null

                $currentPageFile = Get-WmiObject Win32_PageFilesetting
                $currentPageFile.delete() > $null

                $diskNumber = (Get-Partition -DriveLetter $pagingDriveLetter).DiskNumber

                $output.Set_Item('pageFileLetterNew', $tempDriveLetter)
                $output.Set_Item('pageFileDiskNumber', $diskNumber)
                $output.Set_Item('pageFileLetterChanged', $true)
                $output.Set_Item('restartNeeded', $true)
                $pageFileLetterNeeded = $false
            }

        }
        if (!$cdDriveLetterNeeded -and !$pageFileLetterNeeded) {
            break
        }
    }
}

# case where not enough drive letters available after iterating through C-Z
if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $output.Set_Item('preProvisioningSucceeded', $false)
}
else {
    $output.Set_Item('preProvisioningSucceeded', $true)
}


Write-Output $output


}
## [END] Set-WACWUVMPovisioning ##
function Start-WACWUCimService {
<#

.SYNOPSIS
Start a service using CIM Win32_Service class.

.DESCRIPTION
Start a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName StartService

}
## [END] Start-WACWUCimService ##
function Start-WACWUVMProvisioning {
<#

.SYNOPSIS
Execute VM Provisioning

.DESCRIPTION
Execute VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [bool] $partitionDisks,

    [Parameter(Mandatory = $true)]
    [array]$disks,

    [Parameter(Mandatory = $true)]
    [bool]$pageFileLetterChanged,

    [Parameter(Mandatory = $false)]
    [string]$pageFileLetterNew,

    [Parameter(Mandatory = $false)]
    [int]$pageFileDiskNumber,

    [Parameter(Mandatory = $true)]
    [bool]$systemDriveModified
)

$output = @{ }

$output.Set_Item('restartNeeded', $pageFileLetterChanged)

if ($pageFileLetterChanged) {
    Get-Partition -DiskNumber $pageFileDiskNumber | Set-Partition -NewDriveLetter $pageFileLetterNew
    $newPageFile = $pageFileLetterNew + ':\pagefile.sys'
    Set-WMIInstance -Class Win32_PageFileSetting -Arguments @{name = $newPageFile; InitialSize = 0; MaximumSize = 0 } > $null
}

if ($systemDriveModified) {
    $size = Get-PartitionSupportedSize -DriveLetter C
    Resize-Partition -DriveLetter C -Size $size.SizeMax > $null
}

if ($partitionDisks -eq $true) {
    $dataDisks = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number
    for ($index = 0; $index -lt $dataDisks.Length; $index++) {
        Initialize-Disk  $dataDisks[$index].DiskNumber -PartitionStyle GPT -PassThru |
        New-Partition -Size $disks[$index].volumeSizeInBytes -DriveLetter $disks[$index].driveLetter |
        Format-Volume -FileSystem $disks[$index].fileSystem -NewFileSystemLabel $disks[$index].name -Confirm:$false -Force > $null;
    }
}

Write-Output $output

}
## [END] Start-WACWUVMProvisioning ##
function Suspend-WACWUCimService {
<#

.SYNOPSIS
Suspend a service using CIM Win32_Service class.

.DESCRIPTION
Suspend a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName PauseService

}
## [END] Suspend-WACWUCimService ##

# SIG # Begin signature block
# MIIoVQYJKoZIhvcNAQcCoIIoRjCCKEICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAjm4bkHJKn8qbz
# 42up5s2Jbc0uDEM+wsLthERQM+W4r6CCDYUwggYDMIID66ADAgECAhMzAAAEhJji
# EuB4ozFdAAAAAASEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM1WhcNMjYwNjE3MTgyMTM1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDtekqMKDnzfsyc1T1QpHfFtr+rkir8ldzLPKmMXbRDouVXAsvBfd6E82tPj4Yz
# aSluGDQoX3NpMKooKeVFjjNRq37yyT/h1QTLMB8dpmsZ/70UM+U/sYxvt1PWWxLj
# MNIXqzB8PjG6i7H2YFgk4YOhfGSekvnzW13dLAtfjD0wiwREPvCNlilRz7XoFde5
# KO01eFiWeteh48qUOqUaAkIznC4XB3sFd1LWUmupXHK05QfJSmnei9qZJBYTt8Zh
# ArGDh7nQn+Y1jOA3oBiCUJ4n1CMaWdDhrgdMuu026oWAbfC3prqkUn8LWp28H+2S
# LetNG5KQZZwvy3Zcn7+PQGl5AgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUBN/0b6Fh6nMdE4FAxYG9kWCpbYUw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwNTM2MjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AGLQps1XU4RTcoDIDLP6QG3NnRE3p/WSMp61Cs8Z+JUv3xJWGtBzYmCINmHVFv6i
# 8pYF/e79FNK6P1oKjduxqHSicBdg8Mj0k8kDFA/0eU26bPBRQUIaiWrhsDOrXWdL
# m7Zmu516oQoUWcINs4jBfjDEVV4bmgQYfe+4/MUJwQJ9h6mfE+kcCP4HlP4ChIQB
# UHoSymakcTBvZw+Qst7sbdt5KnQKkSEN01CzPG1awClCI6zLKf/vKIwnqHw/+Wvc
# Ar7gwKlWNmLwTNi807r9rWsXQep1Q8YMkIuGmZ0a1qCd3GuOkSRznz2/0ojeZVYh
# ZyohCQi1Bs+xfRkv/fy0HfV3mNyO22dFUvHzBZgqE5FbGjmUnrSr1x8lCrK+s4A+
# bOGp2IejOphWoZEPGOco/HEznZ5Lk6w6W+E2Jy3PHoFE0Y8TtkSE4/80Y2lBJhLj
# 27d8ueJ8IdQhSpL/WzTjjnuYH7Dx5o9pWdIGSaFNYuSqOYxrVW7N4AEQVRDZeqDc
# fqPG3O6r5SNsxXbd71DCIQURtUKss53ON+vrlV0rjiKBIdwvMNLQ9zK0jy77owDy
# XXoYkQxakN2uFIBO1UNAvCYXjs4rw3SRmBX9qiZ5ENxcn/pLMkiyb68QdwHUXz+1
# fI6ea3/jjpNPz6Dlc/RMcXIWeMMkhup/XEbwu73U+uz/MIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGiYwghoiAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAASEmOIS4HijMV0AAAAA
# BIQwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFjn
# dpAqB+t8XrCaJ0alI0LmHZFPOl/2Tqu59hoyUuPMMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEACwoOOpRrKC7YlJw2SI6ROVNzSZUxWk+uJZCn
# bH9VZVKUsXNdvgDMgW3ZtDrcEGHeDiVOL4cu2KboJFY2J6gXH0bAP2LuUDJ+Uomv
# /ubNCvpODKdaHFrsqXrPXxg3ZZheNupuEdfbWr4DOJ4EblRyqRWSkkytXxAixDQl
# rcimM/On9xgmL3gT1Nv4RTKFn7mqDjZCUnheZUqCLC6AFStTTbtvY5X6nSrynZMo
# kmQzPEL/4gmC1csUT5x+RhXMgLKCXb/Eq1Fcydr8wJ4AZSHnjqKz6BiypUjsHStg
# ZcnoMqXLasb5LtIiOE54VRcdlhHcuUSvzttfxPQgJRZLHHV3MKGCF7AwghesBgor
# BgEEAYI3AwMBMYIXnDCCF5gGCSqGSIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDzRlUe2MD4gZ5j8zYu3zuUP9XzmIe8nRsm
# FW8HW/qmKwIGaQJVHpE4GBMyMDI1MTExMDE3MTczOC43MzFaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo0MDFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEf4wggcoMIIFEKADAgECAhMzAAACGV6y
# 2FR19LGNAAEAAAIZMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgyNloXDTI2MTExMzE4NDgyNlowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjQwMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# pqFIyUkzIyxpL3Q03WmLuy4G9YIUScznhKr+cHOT+/u7ParxI96gxxb1WrWuAxB8
# qjGLfsbImx8V3ouK1nUcf+R/nsnXas5/iTgV/Tl3QTRGT0DeuXBNbpHqc+wC1NiT
# yA76gLnirvSBEoBzlrpNQFEnuwdbPLCLpTS3KWSCu5J02b+RFWR/kcFzVxnhoE3g
# IaeURtrGKGBZGKLBXvqggkDENtKkvtvRT32xLvAvL/RpReu5z18ZojCs72ZSoa74
# Dy8YbaWsDm3OZOpJRZxZsPKCHZ6xNqgFKf0xNHj0t9v0Q3W+2z5gAVaasJJCvR52
# Sl0XJ2AOf3l0LSetXgUA5gD5IQ1RvEslTmNnSouTrGID3D1njY7mBu0puiIdPK2j
# K/1Weef2+YR4cQpWQkeBZmXidh9AuWdlwxKQL15LJ6K2dw8y/t/PBhmLyt6QAf0C
# epWRdgZnMytVAUuWHwlZRV9JLY7aX8D55eL9+cOLpX3bGNOmN24UpIW8qtZaqXae
# sFvIOW23JNLhaaQVvObr1eu7GE/5Mn43e+/DbtdYl/bLP2IQ1xYEJdSbcUkDFfW3
# KlZEh+nBKDtaRnNRkbgIgxIbKdT38OKQwZ/aA4uSsiAg6nEPiWBHGuytIo5wU75M
# 5VdjhEqqTHfXYu8BJi6GTzvWT+9ekfMXezqCkksxaG8CAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBSAaOo5HWatNzqZn1IF1fcD6nr3ITAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAXxzVZLLXBFfoCCCTiY7MHXdb7civJSTfrHYJC5Ok2NN75NpzTMT9V2Tc
# IQjfQ3AFUbh1NBAYtMUuwxC6D4ceEXG5lXAnbvkC9YjeLVDRyImXYYmft7z+Qpl9
# t3C/8a0tiqnOz8Ue8/DYLtMTgvWMnsqLNjILDaImOfnHI36TLCjGFe8RYLXGdCUd
# OLlfAdMGePxSTA3TAAOc+GQbmPWjrguLWbxvnl3NVjRvrBZVkxFMoVZH0f7qGwDO
# Shjpnv5nYnQ48ufL0uBz52RbPGdX4Fv9+UGOrBprmcHzmIutFtJec2Y4kujNtTK2
# wBGgWscEOVhFiaVdje8VLJ7MVNKE5TmsuGM3jTLr1nuR5AFGs3UKkP7g3cQD4cHK
# 7XdLiTm7e606QJ+WqeQsADYE9dvU9wIUbI9Dl4UcIErFw+FHaWSTrkfJ4SvLmhKn
# l5khhpJ1sF3z6e1BxepUliXHqzRLiHWihWIWESF8IHElF3POxbP4VJqHBiYvaXMV
# 0SyRgwoD6zXddbUnX9WR6JL2BlqAjjHxINwelsp/VhxAWThzuMA58LxvE/VAzjfF
# F4Wm7a1ZALmJVw3oL/s/uxo1Op4tcT+hfZ9uN1htC1JN4DuRqFfLttjuoAmUQobO
# 5zUFRzvCn8Ck/hiO+bzR15sqkjlxLMyMjpkc/ef4SUUikD468vUwggdxMIIFWaAD
# AgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3Nv
# ZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIy
# MjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5
# vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64
# NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhu
# je3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl
# 3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPg
# yY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I
# 5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2
# ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/
# TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy
# 16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y
# 1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6H
# XtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMB
# AAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQW
# BBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30B
# ATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYB
# BAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMB
# Af8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1Vffwq
# reEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27
# DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pv
# vinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9Ak
# vUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWK
# NsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2
# kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+
# c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep
# 8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+Dvk
# txW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1Zyvg
# DbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/
# 2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIDWTCCAkECAQEwggEBoYHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo0MDFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAMXYp/Wqqdyb0
# enigrLfxl0InAz6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy7/A4wIhgPMjAyNTExMTAwNTUyMTRaGA8yMDI1
# MTExMTA1NTIxNFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7Lv8DgIBADAKAgEA
# AgIilAIB/zAHAgEAAgISxjAKAgUA7L1NjgIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# CwUAA4IBAQACcQPiDyD5itZG9O4/d2xC7z0WnZKjkSkPHWDSHAk519wzikYhtOPd
# xYheP1Ec2HifUxzoOwuEBC84oFrX+ux6mXv0MX/yCEfMdHvNx/gqWW+ngQ6guwf6
# mAQR38Y5iCRPtLg76z1BQOeUoNwHkUHENH/UcAKx1KPTkvOfy2wDolcvQ5KBuLkH
# DFBO0LcHxHymQ91aKDYGH4CIstdDXuah3dnR5DIH3aWjUhQ9QdK+hLAqbpqoCX/5
# sLnyF7b0zQxSJjf8LTJ/GV4+P9gTNt4SU00TjbdIAkOOMdNz56YZrCmP9KsylcLu
# sL/FMDFHe8nMggi0cIpyXIn59lBewOlCMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIZXrLYVHX0sY0AAQAAAhkwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgOXqn0atPFqiO7zfVDeDKYyuAkYQAI6c371gTuJZRm2IwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDckX633E1y1EF32V18zQcrsgjzI9+3Le7m
# lvk2OebthjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAACGV6y2FR19LGNAAEAAAIZMCIEINfmUBOfTKkmch2H35do0fQRcx2J69yqX9bm
# sSdzYtvZMA0GCSqGSIb3DQEBCwUABIICAIDmZ2LD2qHNqnqlKRARx1lqAUBgWdHP
# 7jbpaTrCABQJGIrZhI3jBZMVfdeJNTzDpeRQwM/2GYQqyYnJ1I8UCnxIbumyxcIv
# t/1/pxOYrDdzWpvrj7bQARQ5/QFPpN4MfLztmA4KDMH6+712azHl9xVU8LLOUuI1
# 84QiEpKpz8l2iPjdw+SmM1QjDJu9VNi+G9Nm4aiSUujDlzYe7hY1r5BrArRDyJSn
# oE3bxLwkNcArXPsMxDnmgHE0ArCnBo+pYy7K6ZdT1lkBaIDv7xaknJCVSU6niTHl
# jC9BZsZwETS9ZBdiHkazw6FGWKA4caJ8JRsdlLb2PMWfUmG08NJHgGhVUKOzNnQk
# 8uH9PIhMayvmc8xYef3q0oj2mOePe/GwUp+umDvbI+Drbdtmbmej3jWTvmxK22tB
# 10dQwEebnSi7ADkq9qFqj+tt5VsIpXC/6PaRWFabXClQ8CHpE595UBsFpIMIPtxO
# CRVxrxj9cK4jA3bkt3HDFmuORlnoGKcuVjf9RBhbVlfG9IbYIx/qVaiiwvb565nX
# iWOLjYzgredJGzkARNTut+wZfyJALdLOlqRlSuhj0gTjITmYw0Nh63SciFMES8Wt
# 2LgV+kTqofSCkDmofu4K46GmX/iPtDFf7FPiORZO2UFAnpjOEbK2gjTcDsHKWu0j
# 6G3mii0Jkzwk
# SIG # End signature block
