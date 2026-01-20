function Get-WACAFSAgentFromRegistrykey {
<#########################################################################################################
# File: Read-AgentFromRegistryKey.ps1
#
# .DESCRIPTION
#
#  checks HKLM for AFS agent
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#########################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$agentPath = 'HKLM:\SOFTWARE\Microsoft\Azure\StorageSync\Agent'
$agent = Get-ItemProperty -Path $agentPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

$agent | Write-Output

}
## [END] Get-WACAFSAgentFromRegistrykey ##
function Get-WACAFSStorageSyncAgentUpdate {
<#################################################################################################################################################
# File: Get-StorageSyncAgentUpdate.ps1
#
# .DESCRIPTION
#
#  Gets information on current and Storage Sync Agent versions
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$err = $null
$result = $null
$agentNotInstalled = $false;

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\Kailani.Afs.Updater.Cmdlets.dll"

$moduleExists = Test-Path $path

try
{
  if ($moduleExists)
  {
    # agent has been installed so we can get version
    Import-Module $path
    $result = Get-StorageSyncAgentUpdate
  }
  else
  {
    # agent not installed
    $agentNotInstalled = $true
  }
}
catch {
  $err = $_
}

@{'error' = $err; 'result' = $result; 'agentNotInstalled' = $agentNotInstalled } | Write-Output

}
## [END] Get-WACAFSStorageSyncAgentUpdate ##
function Get-WACAFSStorageSyncProxyConfiguration {
<#################################################################################################################################################
 # File: Get-StorageSyncProxyConfiguration.ps1
 #
 # .DESCRIPTION
 #
 #  Calls Get-StorageSyncProxyConfiguration
 #
 #  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\StorageSync.Management.ServerCmdlets.dll"

$moduleExists = Test-Path $path

if ($moduleExists)
{
    # agent has been installed so we can get version
    Import-Module $path

    Get-StorageSyncProxyConfiguration
}
else
{
    # agent not installed
    $null | Write-Output
}


}
## [END] Get-WACAFSStorageSyncProxyConfiguration ##
function Get-WACAFSStorageSyncServer {
<#################################################################################################################################################
# File: Get-StorageSyncServer.ps1
#
# .DESCRIPTION
#
#  Calls Get-StorageSyncServer
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\StorageSync.Management.ServerCmdlets.dll"

$moduleExists = Test-Path $path

if ($moduleExists)
{
    # agent has been installed so we can get version
    Import-Module $path


    Get-StorageSyncServer
}
else
{
    # agent not installed
    $null | Write-Output
}

}
## [END] Get-WACAFSStorageSyncServer ##
function Get-WACAFSStorageSyncServerEndpoint {
<#################################################################################################################################################
# File: Get-StorageSyncServerEndpoint.ps1
#
# .DESCRIPTION
#
#  Invokes Get-StorageServerEndpoint
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\StorageSync.Management.ServerCmdlets.dll"

$moduleExists = Test-Path $path

if ($moduleExists)
{
    Import-Module $path
    Get-StorageSyncServerEndpoint
}
else
{
    # agent not installed
    $null | Write-Output
}

}
## [END] Get-WACAFSStorageSyncServerEndpoint ##
function Get-WACAFSStorageVolume {
<#

.SYNOPSIS
Enumerates all of the local volumes of the system.

.DESCRIPTION
Enumerates all of the local volumes of the system.

.ROLE
Readers

#>

############################################################################################################################

# Global settings for the script.

############################################################################################################################

$ErrorActionPreference = "Stop"

Set-StrictMode -Version 5.0

Import-Module CimCmdlets
Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility

############################################################################################################################

# Helper functions.

############################################################################################################################

<#
.Synopsis
    Name: Get-VolumePathToPartition
    Description: Gets the list of partitions (that have volumes) in hashtable where key is volume path.

.Returns
    The list of partitions (that have volumes) in hashtable where key is volume path.
#>
function Get-VolumePathToPartition
{
    $volumePaths = @{}
    $partitions =  @(Get-CimInstance -ClassName MSFT_Partition -Namespace Root\Microsoft\Windows\Storage)
    foreach($partition in $partitions)
    {
        foreach($volumePath in @($partition.AccessPaths))
        {
            if($volumePath -and (-not $volumePaths.Contains($volumePath)))
            {
                $volumePaths.Add($volumePath, $partition)
            }
        }
    }

    $volumePaths
}

<#
.Synopsis
    Name: Get-DiskIdToDisk
    Description: Gets the list of all the disks in hashtable where key is:
                 "Disk.Path" in case of WS2016 and above.
                 OR
                 "Disk.ObjectId" in case of WS2012 and WS2012R2.

.Returns
    The list of partitions (that have volumes) in hashtable where key is volume path.
#>
function Get-DiskIdToDisk
{
    $diskIds = @{}

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;

    # In downlevel Operating systems. MSFT_Partition.DiskId is equal to MSFT_Disk.ObjectId
    # However, In WS2016 and above,   MSFT_Partition.DiskId is equal to MSFT_Disk.Path
    $disks = @(Get-CimInstance -ClassName MSFT_Disk -Namespace Root\Microsoft\Windows\Storage)
    foreach ($disk in $disks)
    {
        if($isDownlevel)
        {
            $diskId = $disk.ObjectId
        }
        else
        {
            $diskId = $disk.Path
        }

        if(-not $diskIds.Contains($diskId))
        {
            $diskIds.Add($diskId, $disk)
        }
    }

    return $diskIds
}

<#
.Synopsis
    Name: Get-VolumeWs2016AndAboveOS
    Description: Gets the list of all applicable volumes from WS2012 and Ws2012R2 Operating Systems.

.Returns
    The list of all applicable volumes
#>
function Get-VolumeDownlevelOS
{
    $volumes = @()

    $allVolumes = @(Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage)
    foreach($volume in $allVolumes)
    {
       $partition = $script:partitions.Get_Item($volume.Path)

       # Check if this volume is associated with a partition.
       if($partition)
       {
            # If this volume is associated with a partition, then get the disk to which this partition belongs.
            $disk = $script:disks.Get_Item($partition.DiskId)

            # If the disk is a clustered disk then simply ignore this volume.
            if($disk -and $disk.IsClustered) {continue}
       }

       $volumes += $volume
    }
    $allVolumes = $null
    $volumes
}

<#
.Synopsis
    Name: Get-VolumeWs2016AndAboveOS
    Description: Gets the list of all applicable volumes from WS2016 and above Operating System.

.Returns
    The list of all applicable volumes
#>
function Get-VolumeWs2016AndAboveOS
{
    $volumes = @()

    $applicableVolumePaths = @{}

    $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" }
    $allVolumes = @($subSystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume)

    foreach($volume in $allVolumes)
    {
        if(-not $applicableVolumePaths.Contains($volume.Path))
        {
            $applicableVolumePaths.Add($volume.Path, $null)
        }
    }

    $allVolumes = @(Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage)
    foreach($volume in $allVolumes)
    {
        if(-not $applicableVolumePaths.Contains($volume.Path)) { continue }

        $volumes += $volume
    }

    $allVolumes = $null
    $volumes
}

<#
.Synopsis
    Name: Get-VolumesList
    Description: Gets the list of all applicable volumes w.r.t to the target Operating System.

.Returns
    The list of all applicable volumes.
#>
function Get-VolumesList
{
    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;

    if($isDownlevel)
    {
         return Get-VolumeDownlevelOS
    }

    Get-VolumeWs2016AndAboveOS
}

############################################################################################################################

# Helper Variables

############################################################################################################################

 $script:fixedDriveType = 3

 $script:disks = Get-DiskIdToDisk

 $script:partitions = Get-VolumePathToPartition

############################################################################################################################

# Main script.

############################################################################################################################


$resultantVolumes = @()

$volumes = Get-VolumesList

  foreach($volume in $volumes)
  {
    $partition = $script:partitions.Get_Item($volume.Path)

    if($partition -and $volume.DriveType -eq $script:fixedDriveType)
    {
        $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $partition.IsSystem
        $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $partition.IsBoot
        $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $partition.IsActive
        $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue $partition.PartitionNumber
        $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue $partition.DiskNumber

        $resultantVolumes += $volume
    }
  }

 foreach($volume in $resultantVolumes)
 {
    $sbName = [System.Text.StringBuilder]::new()

    # On the downlevel OS, the drive letter is showing charachter. The ASCII code for that char is 0.
    # So rather than checking null or empty, code is checking the ASCII code of the drive letter and updating
    # the drive letter field to null explicitly to avoid discrepencies on UI.
    if ($volume.FileSystemLabel -and [byte]$volume.DriveLetter -ne 0 )
    {
         $sbName.AppendFormat('{0} ({1}:)', $volume.FileSystemLabel, $volume.DriveLetter)| Out-Null
    }
    elseif (!$volume.FileSystemLabel -and [byte]$volume.DriveLetter -ne 0 )
    {
          $sbName.AppendFormat('({0}:)', $volume.DriveLetter) | Out-Null
    }
    elseif ($volume.FileSystemLabel -and [byte]$volume.DriveLetter -eq 0)
    {
         $sbName.Append($volume.FileSystemLabel) | Out-Null
    }
    else
    {
         $sbName.Append('')| Out-Null
    }

    if ([byte]$volume.DriveLetter -eq 0)
    {
        $volume.DriveLetter = $null
    }

    $volume | Add-Member -Force -NotePropertyName "Name" -NotePropertyValue $sbName.ToString()

}

$isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
$resultantVolumes = $resultantVolumes | ForEach-Object {

$volume = @{
        Name = $_.Name;
        DriveLetter = $_.DriveLetter;
        HealthStatus = $_.HealthStatus;
        DriveType = $_.DriveType;
        FileSystem = $_.FileSystem;
        FileSystemLabel = $_.FileSystemLabel;
        Path = $_.Path;
        PartitionNumber = $_.PartitionNumber;
        DiskNumber = $_.DiskNumber;
        Size = $_.Size;
        SizeRemaining = $_.SizeRemaining;
        IsSystem = $_.IsSystem;
        IsBoot = $_.IsBoot;
        IsActive = $_.IsActive;
    }

if ($isDownlevel)
{
    $volume.FileSystemType = $_.FileSystem;
}
else {

    $volume.FileSystemType = $_.FileSystemType;
    $volume.OperationalStatus = $_.OperationalStatus;
    $volume.HealthStatus = $_.HealthStatus;
    $volume.DriveType = $_.DriveType;
    $volume.DedupMode = $_.DedupMode;
    $volume.UniqueId = $_.UniqueId;
    $volume.AllocationUnitSize = $_.AllocationUnitSize;

   }

   return $volume;
}

$resultantVolumes
$volumes = $null
$resultantVolumes = $null

}
## [END] Get-WACAFSStorageVolume ##
function Import-WACAFSStorageSyncAgent {
<#################################################################################################################################################
# File: Import-StorageSyncAgent.ps1
#
# .DESCRIPTION
#
#  Downloads Storage Sync Agent msi
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#  Docs: https://docs.microsoft.com/en-us/azure/storage/file-sync/file-sync-deployment-guide?tabs=azure-powershell%2Cproactive-portal
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

function Get-Config() {
  # Gather the OS version
  $osVersion = [System.Environment]::OSVersion.Version
  $shouldUseBasicParsing = $true
  $shouldSetTLS12 = $true
  $uri = $null

  # version would be 6.3.9600
  if ($osVersion.Equals([System.Version]::new(6, 3, 9600, 0))) {
    $uri = "https://aka.ms/afs/agent/Server2012R2"
  }

  # version would for WS16 be 10.0.14393
  if ($osVersion.Equals([System.Version]::new(10, 0, 14393, 0))) {
    $uri = "https://aka.ms/afs/agent/Server2016"
  }

  # version for WS19 would be 10.0.17763
  if ($osVersion.Equals([System.Version]::new(10, 0, 17763, 0))) {
    $uri = "https://aka.ms/afs/agent/Server2019"
  }

  # version for WS22 would be 10.0.20348
  if ($osVersion.Equals([System.Version]::new(10, 0, 20348 , 0))) {
    $uri = "https://aka.ms/afs/agent/Server2022"
    $shouldUseBasicParsing = $false # basic parsing not needed for WS22
    $shouldSetTLS12 = $false # WS22 uses TLS 1.3 so we will not lower it to 1.2
  }

  # version for WS25 would be 10.0.20348
  if ($osVersion.Equals([System.Version]::new(10, 0, 26100 , 0))) {
    $uri = "https://aka.ms/afs/agent/Server2025"
    $shouldUseBasicParsing = $false # basic parsing not needed for WS25
    $shouldSetTLS12 = $false # WS25 uses TLS 1.3 so we will not lower it to 1.2
  }


  if ($uri -ne $null)
  {
    return @{
      "uri" = $uri;
      "shouldUseBasicParsing" = $shouldUseBasicParsing;
      "shouldSetTLS12" = $shouldSetTLS12
    }
  }
  else
  {
    throw [System.PlatformNotSupportedException]::new("PlatformNotSupportedException")
  }
}

Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$afs = Join-Path -Path $env:TEMP -ChildPath "azure-file-sync"
$msi = Join-Path -Path $afs -ChildPath "storage-sync-agent.msi"

$test = Test-Path $afs

if ($test -eq $false) {
  New-Item -ItemType Directory -Force -Path  $afs  | Out-Null
}

$config = Get-Config

if ($config.shouldSetTLS12)
{
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # ensure we use TLS1.2
}


if ($config.useBasicParsing)
{
  Invoke-WebRequest -Uri $config.uri -OutFile $msi -UseBasicParsing
}
else
{
  Invoke-WebRequest -Uri $config.uri -OutFile $msi
}

}
## [END] Import-WACAFSStorageSyncAgent ##
function Install-WACAFSStorageSyncAgent {
<#################################################################################################################################################
# File: Install-StorageSyncAgent.ps1
#
# .DESCRIPTION
#
#  Installs Storage Sync Agent msi using the answer file
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

Import-Module Microsoft.PowerShell.Management

$afs = Join-Path -Path $env:TEMP -ChildPath "azure-file-sync"
$msi = Join-Path -Path $afs -ChildPath "storage-sync-agent.msi"
$answerFile = Join-Path -Path $afs -ChildPath "answer-file.ini"
$log = Join-Path -Path $afs -ChildPath "afs-agent-install.log"

$testMsi = Test-Path $msi
$testAnswer = Test-Path $answerFile

if ($testMsi -eq $false)
{
  Throw "The msi installer has not yet been downloaded"
}

if ($testAnswer -eq $false)
{
  Throw "The answer file has not yet been created"
}

$proc = Start-Process "msiexec.exe" -ArgumentList "/i $msi /q /L*v $log UNATTEND_ANSWER_FILE=$answerFile" -PassThru
Wait-Process -InputObject $proc

#  clean up by removing the ini file that might contain the password
Remove-Item -path $answerFile

if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne $null) {
  Throw "The AFS installation process exited with code $($proc.ExitCode)"
}


}
## [END] Install-WACAFSStorageSyncAgent ##
function Install-WACAFSStorageSyncAgentUpdate {
<#################################################################################################################################################
# File: Install-StorageSyncAgentUpdate.ps1
#
# .DESCRIPTION
#
#  Installs latest available Storage Sync Agent version
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

Import-Module Microsoft.PowerShell.Management

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\Kailani.Afs.Updater.Cmdlets.dll"
Import-Module $path

Install-StorageSyncAgentUpdate -Force

}
## [END] Install-WACAFSStorageSyncAgentUpdate ##
function New-WACAFSAnswerFile {
<#################################################################################################################################################
# File: New-AnswerFile.ps1
#
# .DESCRIPTION
#
#  Creates answer file to use when installing Storage Sync Agent msi file
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

 param (
  [Parameter(Mandatory = $true)]
  [string]
  $installSubPath,

  [Parameter(Mandatory = $true)]
  [uint32]
  $agentUpdate,

  [Parameter(Mandatory = $true)]
  [bool]
  $useCustomProxy,

  [Parameter(Mandatory = $false)]
  [string]
  $address,

  [Parameter(Mandatory = $false)]
  [uint32]
  $port,

  [Parameter(Mandatory = $true)]
  [bool]
  $useCreds,

  [Parameter(Mandatory = $false)]
  [string]
  $username,

  [Parameter(Mandatory = $false)]
  [string]
  $password,

  [Parameter(Mandatory = $true)]
  [bool]
  $installLatest,

  [Parameter(Mandatory = $true)]
  [string]
  $updateDay,

  [Parameter(Mandatory = $true)]
  [uint16]
  $updateHour
)
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$enableAutoUpdate = 0

if ($installLatest -eq $true)
{
  $enableAutoUpdate = 1
}

$afs =  Join-Path -Path $env:TEMP -ChildPath "azure-file-sync"
$ini = Join-Path -Path $afs -ChildPath "answer-file.ini"

$test = Test-Path $afs

if ($test -eq $false)
{
   New-Item -ItemType Directory -Force -Path  $afs | Out-Null
}

$installDir = $installSubPath
$useUpdates = $agentUpdate

$useCredsEnum = 0
if ($useCreds) {
  $useCredsEnum = 1
}

$customProxySettingsEnum = 0
if ($useCustomProxy) {
  $customProxySettingsEnum = 1
}

@"
ACCEPTEULA=1
ENABLE_AZUREFILESYNC_FEATURE=1

AGENTINSTALLDIR=$installDir

USE_CUSTOM_PROXY_SETTINGS=$customProxySettingsEnum
PROXY_ADDRESS=$address
PROXY_PORT=$port
PROXY_AUTHREQUIRED_FLAG=$useCredsEnum
PROXY_USERNAME=$username
PROXY_PASSWORD=$password

ENABLE_MU_ENROLL=$useUpdates

ENABLE_DATA_COLLECTION=1
ENABLE_AGENT_UPDATE_POSTINSTALL=1

ENABLE_AGENT_AUTO_UPDATE=$enableAutoUpdate

AGENT_AUTO_UPDATE_SCHEDULED_DAY=$updateDay

AGENT_AUTO_UPDATE_SCHEDULED_HOUR=$updateHour

"@ | Out-File $ini


}
## [END] New-WACAFSAnswerFile ##
function New-WACAFSCloudEndpoint {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $armToken,

    [Parameter(Mandatory = $true)]
    [string]
    $graphToken,

    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionId,

    [Parameter(Mandatory = $true)]
    [string]
    $accountId,

    [Parameter(Mandatory = $true)]
    [string]
    $cloudEndpointName,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]
    $storageSyncServiceName,

    [Parameter(Mandatory = $true)]
    [string]
    $syncGroupName,

    [Parameter(Mandatory = $true)]
    [string]
    $storageAccountResourceId,

    [Parameter(Mandatory = $true)]
    [string]
    $fileShareName,

    [Parameter(Mandatory = $true)]
    [string]
    $storageAccountTenantId
)

Import-Module PackageManagement, PowerShellGet

try
{
    $storageSyncModule = Get-Module -Name Az.StorageSync -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

    if (($storageSyncModule.version.major -lt 1) -or ($storageSyncModule.version.major -eq 1 -and $storageSyncModule.version.minor -lt 7) ) # we need  at least 1.7.0
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.StorageSync -Force | Out-Null
    }
    else
    {
      Import-Module $storageSyncModule -ErrorAction Stop
    }
}
catch
{
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module Az.StorageSync -Force -AllowClobber
    Import-Module -Name Az.StorageSync
}

try
{
    $accountsModule = Get-Module -Name Az.Accounts -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

    if (($accountsModule.version.major -lt 2) -or ($accountsModule.version.major -eq 2 -and $accountsModule.version.minor -lt 9) ) # we need  at least 2.9.0
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.Accounts -Force | Out-Null
    }
    else
    {
      Import-Module $accountsModule -ErrorAction Stop
    }
}
catch
{
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module -Name Az.Accounts -Force -AllowClobber
    Import-Module -Name Az.Accounts
}

Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

Connect-AzAccount -AccountId $accountId -AccessToken $armToken -MicrosoftGraphAccessToken $graphToken -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

New-AzStorageSyncCloudEndpoint -ResourceGroupName $resourceGroupName -StorageSyncServiceName $storageSyncServiceName -SyncGroupName $syncGroupName -Name $cloudEndpointName -StorageAccountResourceId $storageAccountResourceId -AzureFileShareName $fileShareName -StorageAccountTenantId $storageAccountTenantId

}
## [END] New-WACAFSCloudEndpoint ##
function Read-WACAFSServerRegistration {
<#########################################################################################################
# File: Read-ServerResgistration.ps1
#
# .DESCRIPTION
#
#  checks HKLM for server regsitration reg key and agent installed directory
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#########################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers
#>
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$serverRegistrationPath = 'HKLM:\SOFTWARE\Microsoft\Azure\StorageSync\ServerRegistration'
$serverIsRegistered = $false;
$serverRegistration = Get-ItemProperty -Path $serverRegistrationPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

if (($serverRegistration -ne $null) ) #-and ($serverRegistration.ServerRegistration.FileStoreName=someName -ne $null)
{
    # todo get the correct property name for someName  (name of storage sync service that server is registered to)
    $serverIsRegistered = $true;
}
else {
    $serverIsRegistered = $false;
}

$agentPath = 'HKLM:\SOFTWARE\Microsoft\Azure\StorageSync\Agent'
$agentIsInstalled = $false;
$agent = Get-ItemProperty -Path $agentPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

if (($agent -ne $null) -and ($agent.InstallDir -ne $null))
{
    $agentIsInstalled = $true;
}
else {
    $agentIsInstalled = $false;
}

@{
    serverIsRegistered = $serverIsRegistered;
    agentIsInstalled = $agentIsInstalled;
} | Write-Output

}
## [END] Read-WACAFSServerRegistration ##
function Register-WACAFSStorageSyncServer {
<#################################################################################################################################################
 # File: Register-StorageSyncServer.ps1
 #
 # .DESCRIPTION
 #
 #  Calls Connect-AzAccount followed by Register-AzStorageSyncServer
 #
 #  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

 param (
  [Parameter(Mandatory = $true)]
  [string]
  $armToken,

  [Parameter(Mandatory = $true)]
  [string]
  $graphToken,

  [Parameter(Mandatory = $true)]
  [string]
  $accountId,

  [Parameter(Mandatory = $true)]
  [string]
  $subscriptionId,

  [Parameter(Mandatory = $true)]
  [string]
  $resourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]
  $storageSyncServiceName
)

Import-Module PowerShellGet

try
{
    $storageSyncModule = Get-Module -Name Az.StorageSync -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

    if (($storageSyncModule.version.major -lt 1) -or ($storageSyncModule.version.major -eq 1 -and $storageSyncModule.version.minor -lt 7) ) # we need  at least 1.7.0
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.StorageSync -Force | Out-Null
    }
    else
    {
      Import-Module $storageSyncModule -ErrorAction Stop
    }
}
catch
{
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module Az.StorageSync -Force -AllowClobber
    Import-Module -Name Az.StorageSync
}

try
{
    $accountsModule = Get-Module -Name Az.Accounts -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

    if (($accountsModule.version.major -lt 2) -or ($accountsModule.version.major -eq 2 -and $accountsModule.version.minor -lt 9) ) # we need  at least 2.9.0
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.Accounts -Force | Out-Null
    }
    else
    {
      Import-Module $accountsModule -ErrorAction Stop
    }
}
catch
{
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module -Name Az.Accounts -Force -AllowClobber
    Import-Module -Name Az.Accounts
}

Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

Connect-AzAccount -AccountId $accountId -AccessToken $armToken -MicrosoftGraphAccessToken $graphToken -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

Register-AzStorageSyncServer -Resourcegroup $resourceGroupName -StorageSyncServiceName $storageSyncServiceName

}
## [END] Register-WACAFSStorageSyncServer ##
function Set-WACAFSStorageAccountCORS {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $accountName,

    [Parameter(Mandatory = $true)]
    [string]
    $accountKey,

    [Parameter(Mandatory = $true)]
    [array]
    $allowedOrigins,

    [Parameter(Mandatory = $true)]
    [array]
    $allowedMethods
)
Import-Module Microsoft.PowerShell.Utility, PowerShellGet

try
{
    Import-Module -Name Az.Storage -ErrorAction Stop
}
catch
{
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module -Name Az.Storage -Force -AllowClobber
    Import-Module -Name Az.Storage
}

$storageAccountName = $accountName
$key = $accountKey
$context = New-AzStorageContext -StorageAccountKey $key -StorageAccountName $storageAccountName

$corsRules = (@{
    AllowedHeaders=@("x-ms-date","x-ms-version","Content-Type","Authorization","x-xsrf-token");
    AllowedOrigins=@($allowedOrigins);
    ExposedHeaders=@("x-ms-meta-data*", "x-ms-meta-customheader");
    MaxAgeInSeconds=0;
    AllowedMethods=@($allowedMethods)
})

Set-AzStorageCORSRule -ServiceType File -CorsRules $corsRules -Context $context

$succeeded = $null
$allowedOriginsSet = $true
$allowedMethodsSet = $true
$count = 0
$maxRetryTimes = 15 # 15 retries of 2-second intervals = 30 seconds total
while ($count -lt $maxRetryTimes)
{
    Start-Sleep -Seconds 2

    $allowedOriginsSet = $true
    $allowedMethodsSet = $true

    $storageAccountCors = Get-AzStorageCORSRule -ServiceType File -Context $context
    Write-Host ($storageAccountCors)

    # check that our relevant CORS fields are set
    if ($null -ne $storageAccountCors)
    {
        ForEach ($origin in $allowedOrigins)
        {
            if (-Not $storageAccountCors.AllowedOrigins -contains $origin)
            {
                $allowedOriginsSet = $false
            }
        }

        ForEach ($method in $allowedMethods)
        {
            if (-Not $storageAccountCors.AllowedMethods -contains $method)
            {
                $allowedMethodsSet = $false
            }
        }
    }
    else
    {
        $allowedOriginsSet = $false
        $allowedMethodsSet = $false
    }

    if ($allowedOriginsSet -and $allowedMethodsSet)
    {
        $succeeded = $true
        break
    }

    $count += 1

    if ($count -eq $maxRetryTimes)
    {
        $succeeded = $false
    }

}

Write-Output @{ "succeeded" = $succeeded }

}
## [END] Set-WACAFSStorageAccountCORS ##
function Set-WACAFSStorageSyncProxyConfiguration {
<#################################################################################################################################################
# File: Set-StorageSyncProxyConfiguration.ps1
#
# .DESCRIPTION
#
#  Calls Set-StorageSyncProxyConfiguration
#
#  The supported Operating Systems are Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019.
#
#  Copyright (c) Microsoft Corp 2018.
#
#################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators
#>

param (
  [Parameter(Mandatory = $true)]
  [bool]
  $useCustomProxy,

  [Parameter(Mandatory = $false)]
  [string]
  $address,

  [Parameter(Mandatory = $false)]
  [uint32]
  $port,

  [Parameter(Mandatory = $true)]
  [bool]
  $useCreds,

  [Parameter(Mandatory = $false)]
  [string]
  $username,

  [Parameter(Mandatory = $false)]
  [string]
  $password
)
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$path = Join-Path -Path $env:ProgramFiles -ChildPath "Azure\StorageSyncAgent\StorageSync.Management.ServerCmdlets.dll"

$moduleExists = Test-Path $path

if ($moduleExists)
{
    # agent has been installed so we can get version
    Import-Module $path

    if ($useCustomProxy) {
      $args = @{}

      $args += @{"Address" = $address}

      if ($port) {
        $args += @{"Port" = $port}
      }

      if ($useCreds) {
        $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
        $cred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $username, $securePass
        $args += @{"ProxyCredential" = $cred}
      }

      Set-StorageSyncProxyConfiguration @args
    }
    else {
      Remove-StorageSyncProxyConfiguration
    }
}
else
{
    # agent not installed
    $null | Write-Output
}

}
## [END] Set-WACAFSStorageSyncProxyConfiguration ##

# SIG # Begin signature block
# MIIoKgYJKoZIhvcNAQcCoIIoGzCCKBcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7+crinyKk/pez
# wwAOOQa0fbEJr0rfYWi8XzXd92zqbaCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
# 7A5ZL83XAAAAAASFMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM3WhcNMjYwNjE3MTgyMTM3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDASkh1cpvuUqfbqxele7LCSHEamVNBfFE4uY1FkGsAdUF/vnjpE1dnAD9vMOqy
# 5ZO49ILhP4jiP/P2Pn9ao+5TDtKmcQ+pZdzbG7t43yRXJC3nXvTGQroodPi9USQi
# 9rI+0gwuXRKBII7L+k3kMkKLmFrsWUjzgXVCLYa6ZH7BCALAcJWZTwWPoiT4HpqQ
# hJcYLB7pfetAVCeBEVZD8itKQ6QA5/LQR+9X6dlSj4Vxta4JnpxvgSrkjXCz+tlJ
# 67ABZ551lw23RWU1uyfgCfEFhBfiyPR2WSjskPl9ap6qrf8fNQ1sGYun2p4JdXxe
# UAKf1hVa/3TQXjvPTiRXCnJPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUuCZyGiCuLYE0aU7j5TFqY05kko0w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwNTM1OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACjmqAp2Ci4sTHZci+qk
# tEAKsFk5HNVGKyWR2rFGXsd7cggZ04H5U4SV0fAL6fOE9dLvt4I7HBHLhpGdE5Uj
# Ly4NxLTG2bDAkeAVmxmd2uKWVGKym1aarDxXfv3GCN4mRX+Pn4c+py3S/6Kkt5eS
# DAIIsrzKw3Kh2SW1hCwXX/k1v4b+NH1Fjl+i/xPJspXCFuZB4aC5FLT5fgbRKqns
# WeAdn8DsrYQhT3QXLt6Nv3/dMzv7G/Cdpbdcoul8FYl+t3dmXM+SIClC3l2ae0wO
# lNrQ42yQEycuPU5OoqLT85jsZ7+4CaScfFINlO7l7Y7r/xauqHbSPQ1r3oIC+e71
# 5s2G3ClZa3y99aYx2lnXYe1srcrIx8NAXTViiypXVn9ZGmEkfNcfDiqGQwkml5z9
# nm3pWiBZ69adaBBbAFEjyJG4y0a76bel/4sDCVvaZzLM3TFbxVO9BQrjZRtbJZbk
# C3XArpLqZSfx53SuYdddxPX8pvcqFuEu8wcUeD05t9xNbJ4TtdAECJlEi0vvBxlm
# M5tzFXy2qZeqPMXHSQYqPgZ9jvScZ6NwznFD0+33kbzyhOSz/WuGbAu4cHZG8gKn
# lQVT4uA2Diex9DMs2WHiokNknYlLoUeWXW1QrJLpqO82TLyKTbBM/oZHAdIc0kzo
# STro9b3+vjn2809D0+SOOCVZMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGgowghoGAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJXRfmWuBqhLZmeRHDTV9Ceb
# RUQmNgWwV2q7DK+3iSVNMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdOaje4Uxgx1iSDbwlESprOCmdlfWroFOD+y2PA2Fxc3ZB1I4OA5S2SZl
# j1XxXJEmS/4rVmXnvTj0sOE9AtRo8eyQRX7/x8nhYJTSqGKmLQQOk1fU/V1tB0Uy
# vDyTPPSgUk4Y5+z0LMKqbvJMgY8s4nhpqac2zYDyopKtPNBvjzEgF3Oj3Vib2MIb
# jrXXNUkcg+2K235Gw89xRZbO4iUwfmFbgIHjReQX+mpuedki1mLjfo26m95vxfkg
# eZbC8aGOe+b0kwxq2L1gOmOBx0/ETqJVO9MZlY3hMb49juigcP5v5o1Cpf23VARy
# LV4vLwqQjdk0rH98ps0bnXgnJAA1m6GCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCC
# F3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCIM+gm8vf6jrSEvNNeuwxbSf3OFbvqp7v18oJ1Lq7XUgIGaPBHyj6G
# GBMyMDI1MTExMDE3MTczMy4yNDFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0YwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHqMIIHIDCCBQigAwIBAgITMwAAAgbXvFE4mCPsLAABAAACBjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTBaFw0yNjA0MjIxOTQyNTBaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0YwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDpRIWbIM3Rlr397cjHaYx85l7I+ZVWGMCBCM911BpU
# 6+IGWCqksqgqefZFEjKzNVDYC9YcgITAz276NGgvECm4ZfNv/FPwcaSDz7xbDbsO
# oxbwQoHUNRro+x5ubZhT6WJeU97F06+vDjAw/Yt1vWOgRTqmP/dNr9oqIbE5oCLY
# dH3wI/noYmsJVc7966n+B7UAGAWU2se3Lz+xdxnNsNX4CR6zIMVJTSezP/2STNcx
# JTu9k2sl7/vzOhxJhCQ38rdaEoqhGHrXrmVkEhSv+S00DMJc1OIXxqfbwPjMqEVp
# 7K3kmczCkbum1BOIJ2wuDAbKuJelpteNZj/S58NSQw6khfuJAluqHK3igkS/Oux4
# 9qTP+rU+PQeNuD+GtrCopFucRmanQvxISGNoxnBq3UeDTqphm6aI7GMHtFD6DOjJ
# lllH1gVWXPTyivf+4tN8TmO6yIgB4uP00bH9jn/dyyxSjxPQ2nGvZtgtqnvq3h3T
# RjRnkc+e1XB1uatDa1zUcS7r3iodTpyATe2hgkVX3m4DhRzI6A4SJ6fbJM9isLH8
# AGKcymisKzYupAeFSTJ10JEFa6MjHQYYohoCF77R0CCwMNjvE4XfLHu+qKPY8GQf
# sZdigQ9clUAiydFmVt61hytoxZP7LmXbzjD0VecyzZoL4Equ1XszBsulAr5Ld2Kw
# cwIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFO0wsLKdDGpT97cx3Iymyo/SBm4SMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQB23GZOfe9ThTUvD29i4t6lDpxJhpVRMme+
# UbyZhBFCZhoGTtjDdphAArU2Q61WYg3YVcl2RdJm5PUbZ2bA77zk+qtLxC+3dNxV
# sTcdtxPDSSWgwBHxTj6pCmoDNXolAYsWpvHQFCHDqEfAiBxX1dmaXbiTP1d0Xffv
# gR6dshUcqaH/mFfjDZAxLU1s6HcVgCvBQJlJ7xEG5jFKdtqapKWcbUHwTVqXQGbI
# lHVClNJ3yqW6Z3UJH/CFcYiLV/e68urTmGtiZxGSYb4SBSPArTrTYeHOlQIj/7lo
# VWmfWX2y4AGV/D+MzyZMyvFw4VyL0Vgq96EzQKyteiVeBaVEjxQKo3AcPULRF4Uz
# z98P2tCM5XbFZ3Qoj9PLg3rgFXr0oJEhfh2tqUrhTJd13+i4/fek9zWicoshlwXg
# Fu002ZWBVzASEFuqED48qyulZ/2jGJBcta+Fdk2loP2K3oSj4PQQe1MzzVZO52AX
# O42MHlhm3SHo3/RhQ+I1A0Ny+9uAehkQH6LrxkrVNvZG4f0PAKMbqUcXG7xznKJ0
# x0HYr5ayWGbHKZRcObU+/34ZpL9NrXOedVDXmSd2ylKSl/vvi1QwNJqXJl/+gJkQ
# EetqmHAUFQkFtemi8MUXQG2w/RDHXXwWAjE+qIDZLQ/k4z2Z216tWaR6RDKHGkwe
# CoDtQtzkHTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNN
# MIICNQIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjdGMDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAE
# a0f118XHM/VNdqKBs4QXxNnN96CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LxhRTAiGA8yMDI1MTExMDEzMDQw
# NVoYDzIwMjUxMTExMTMwNDA1WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDsvGFF
# AgEAMAcCAQACAiRXMAcCAQACAhSEMAoCBQDsvbLFAgEAMDYGCisGAQQBhFkKBAIx
# KDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZI
# hvcNAQELBQADggEBAMQBiruQ5J9hu8kPDnZ7y6s2TX0QHs6ocraq5/g6q2rGbCOP
# HB6F7BsuKItQzKZvmdqzxeZMT3p7D6jW6qRNHYRPv9dXGzec82eLEJ+OEJ7i2iLu
# MV64y6ie/5QjasrKfwoRuG5Khi6HF5zwvdZGIYPSaE57q8vcJyr/LMYJGMFL3EnW
# k4qse7J9vlRykJT4QLvP+VxEZbm2ix9P/2cxdDt6iot+poXNlumUSzRTzB/Oo2yI
# kNxaSgjb5daS6U6tgt0cB01b+4jW6ErQmsJD7FYbKIZe8bOyObpEiMgCHWOoif0H
# I967V4xcjPZKs2jWyL7oSk660BQ7qTqhdZlEIwMxggQNMIIECQIBATCBkzB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgbXvFE4mCPsLAABAAACBjAN
# BglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8G
# CSqGSIb3DQEJBDEiBCCJcEM2qeZdPpTqXPHvcAECTrDBlkGMSSv+G1wfb8QjmDCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIODo9ZSIkZ6dVtKT+E/uZx2WAy7K
# iXM5R1JIOhNJf0vSMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAIG17xROJgj7CwAAQAAAgYwIgQg4i54rDd3CfYvU+X1VHvXQnPWc4/h
# e2GXfTNYDhy/aegwDQYJKoZIhvcNAQELBQAEggIABTDo0Hrom2NrZw8tSWnEOWgH
# OjFhS9Wt5Hmmkv7ezksmidg4eWJ/wKPiWp2lb3uWCmNk/b/iChSWk50BDIjguq/S
# qNDd3w92kdTArYDHA7H5XNtb6aArefdrX5u3yi9EuOkZwBK4ZUqQfYD+XWs2IGMt
# oVNWArrdeJjjfE0YjH8ScxT+QMlJx5OQxC1AmC5l3so0uG9oiZ7OoKFNQWmFC2W+
# 9W7MytHugBfr7Rgctojxe40Qv1N3b0vwGeYjDWYUl73oPKjdunNA88T6EdXZYUGD
# 1Gp6tS53G9fLGYAYR6SMFdIkglWFikN4t4LqiD+x6l5jl4Il4OZgi9FLuQUj7gGa
# IZCZ09/GgAgu1SuRjIRTtdvtJpt7SXmHBOGcYcKZuileyTmlA2DQsCj0f2vVanGU
# CTji/lc+HiUukseoVIOjh3JgLSeq+TTvhJBGWqfOFpGL23P009isCfiHSeWdWPNI
# d+paODb8h3GCMbl+u5tYUYHuVpVwDbB6RSkNBICX3AXPUFAiFI/ZF7u9LTPv9nwe
# Y29ia6riq4GEn6cC1GhqDal9iZ0M7meqqIybViounve+DbGLJzaRAhtAO7BtMYZn
# aatz5sCcP4XvKGdUq/n39sui6JntVgdETvNdzmbGblSQpYsUUbK9Zu3Zdu0Vqg/J
# xTCbBziZ5WstsZyAxwg=
# SIG # End signature block
