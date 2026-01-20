function Add-WACSRVolumes {
<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER sourceAddVolumePartnership

.PARAMETER destinationAddVolumePartnership

.PARAMETER sourceRGName

.PARAMETER sourceComputerName

.PARAMETER destinationRGName

.PARAMETER destinationComputerName

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory=$true)]
  [array] $sourceAddVolumePartnership,
  [Parameter(Mandatory=$true)]
  [array] $destinationAddVolumePartnership,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName,
  [Parameter(Mandatory=$true)]
  [String] $destinationRGName,
  [Parameter(Mandatory=$true)]
  [String] $destinationComputerName
)
Import-Module CimCmdlets
Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'SetPartnershipAddVolumes' -Arguments @{'SourceComputerName'= $sourceComputerName; 'SourceRGName'= $sourceRGName;  'DestinationComputerName'= $destinationComputerName; 'DestinationRGName'= $destinationRGName;  'SourceAddVolumePartnership'=$sourceAddVolumePartnership; 'DestinationAddVolumePartnership' = $destinationAddVolumePartnership}

}
## [END] Add-WACSRVolumes ##
function Dismount-WACSRSRDestination {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $resourceGroupName
)

Import-Module CimCmdlets, Microsoft.PowerShell.Utility
Dismount-SRDestination -Name $resourceGroupName -Force
}
## [END] Dismount-WACSRSRDestination ##
function Edit-WACSRSRParnership {

<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory=$true)]
  [Uint32] $asyncRPO,
  [Parameter(Mandatory=$true)]
  [bool] $encryption,
  [Parameter(Mandatory=$true)]
  [Uint32] $replicationMode,
  [Parameter(Mandatory=$true)]
  [Uint64] $logSizeInBytes,
  [Parameter(Mandatory=$true)]
  [String] $destinationComputerName,
  [Parameter(Mandatory=$true)]
  [String] $destinationRGName,
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory = $true)]
  [bool] $compression,
  [Parameter(Mandatory = $true)]
  [bool] $osVersion23H2OrLater
)
Import-Module CimCmdlets
$customArgs =  @{
  'SourceComputerName'= $sourceComputerName;
  'SourceRGName' = $sourceRGName;
  'DestinationComputerName'= $destinationComputerName;
  'DestinationRGName' = $destinationRGName;
  'Encryption' = $encryption;
  'LogSizeInBytes' = $logSizeInBytes;
  'ReplicationMode' = $replicationMode;
  # no asyncRPO property unless we need it
};

if ($asyncRPO -gt 0)
{
    $customArgs.AsyncRPO = $asyncRPO
}

if ($osVersion23H2OrLater) {
    $customArgs.Compression = $compression
} 

Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'SetPartnershipModifyPartnership' -Arguments $customArgs | Out-Null
}
## [END] Edit-WACSRSRParnership ##
function Get-WACSRClusterNetwork {
<#
.SYNOPSIS
  TODO: fill out synopsis

.DESCRIPTION
  TODO: fill out description

.ROLE
Readers

#>

Import-Module FailoverClusters

Get-ClusterNetwork | Where-Object Role -ne 0
# 0 is the enum for network role 'None', which is what we want to filter out


}
## [END] Get-WACSRClusterNetwork ##
function Get-WACSRCounterData {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
 Param
 (
     [Parameter(Mandatory=$true)]
     [uint16] $counterType,
     [Parameter(Mandatory=$true)]
     [String] $partitionId
 )
Import-Module CimCmdlets, Microsoft.PowerShell.Utility

$result = Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'QueryCounterData' -Arguments @{'partitionId'= $partitionId; 'counterType'= $counterType}

Write-Output $result.itemValue

}
## [END] Get-WACSRCounterData ##
function Get-WACSRDisk {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Import-Module Storage
Get-Disk

}
## [END] Get-WACSRDisk ##
function Get-WACSRFileSystemRoot {
<#
.SYNOPSIS
    Name: Get-FileSystemRoot
    Description: Gets the local file system root entities of the machine.
.DESCRIPTION

.ROLE
Administrators

.Returns
    The local file system root entities.
#>
param(
    [Parameter(Mandatory = $true)]
    [bool]
    $osVersion23H2OrLater,

    [Parameter(Mandatory = $false)]
    [bool]
    $getVolumesOnlyFromAvailableStorage
)
function Get-FileSystemRoot
{
    Import-Module  Storage, Microsoft.PowerShell.Utility

    $localVolumes = Get-LocalVolumes;

    return $localVolumes | % {
        $disk = $_ | Get-Partition | Get-Disk

        $caption = $null;
        $displayName = $null;

        if ([string]::IsNullOrWhiteSpace($_.DriveLetter))
        {
          $caption = $_.Path
        } else
        {
          $caption = $_.DriveLetter + ':\'
        }

        if ([string]::IsNullOrWhiteSpace($_.FileSystemLabel))
        {
          $displayName = $caption
        }
        else
        {
          $displayName =  $_.FileSystemLabel + ' (' + $caption + ')' # e.g. MyVolumeLabel (F:\) or MyVolumeLabel (\\?\VOLUME{EB824AA2-6E0A-4D29-BEB8-56112CAD3B5C}\)
        }

        $_ | Microsoft.PowerShell.Utility\Select-Object @{ Name = 'Caption'; Expression = { $caption } },
            @{ Name = 'DisplayName'; Expression = { $displayName } },
            @{ Name = 'Size'; Expression = { $_.Size} },
            @{ Name = 'SizeRemaining'; Expression = { $_.SizeRemaining } },
            @{ Name = 'DiskLogicalSectorSize'; Expression = { $disk.LogicalSectorSize } },
            @{ Name = 'DiskPhysicalSectorSize'; Expression = { $disk.PhysicalSectorSize } },
            @{ Name = 'DriveLetter'; Expression = { $_.DriveLetter } },
            @{ Name = 'FileSystem'; Expression = { $_.FileSystemType  } },
            @{ Name = 'isCSV'; Expression = { $false } },
            @{ Name = 'clusterFQDN'; Expression = { $null } },
            @{ Name = 'FileSystemNumber'; Expression = { $_.psBase.CimInstanceProperties["FileSystemType"].Value } }
        }
}


<#
.Synopsis
    Name: Get-LocalVolumes
    Description: Gets the local volumes of the machine.

.Returns
    The local volumes.
#>
function Get-LocalVolumes
{
    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    Import-Module Storage, StorageReplica

    $partitionsInReplication = @{}
    $localVolumes = @()
    $subsystem = Get-StorageSubSystem -FriendlyName Win*

    #
    # Lets find all partitions that are participating in replication
    # either as log / data
    #
    $allGroups = Get-SRGroup

    foreach ($group in $allGroups)
    {
        #
        # We will assume that SRGroup.LogVolume is either
        # a) drive letter in the 'C:\' format
        # b) OR a volume guid
        #
        $logVolume = $null;

        #  first try getting volume by drive letter
        $logVolumeDriveLetter = $group.LogVolume.Substring(0,1)
        $logVolume = Get-Volume -DriveLetter $logVolumeDriveLetter -ErrorAction SilentlyContinue

        # fall back to path if cannot find by drive letter
        if ($logVolume -eq $null)
        {
            $logVolume = Get-Volume -Path $group.LogVolume -ErrorAction SilentlyContinue
        }

        if ($logVolume -ne $null)
        {
            $partition = $logVolume | Get-Partition

            if ($partition -ne $null)
            {
                $partitionsInReplication.Add($partition.Guid, $true)
            }
        }

        #
        # Now just add all data partitions
        #
        foreach ($dp in $group.Partitions)
        {
            $partitionsInReplication.Add(('{' + $dp + '}'), $true)
        }
    }

    #
    # Now lets get the rest of the volumes
    #

    $disks = $subsystem | Get-Disk | Where-Object { ($_.IsSystem -eq $false) -and ($_.PartitionStyle -eq 'GPT') }
    foreach ($disk in $disks)
    {
        $partitions = $disk | Get-Partition

        foreach ($part in $partitions)
        {
            # Skip partitions that are not in replication already
            if ($part.Guid -ne $null -and -not $partitionsInReplication.ContainsKey($part.Guid))
            {
                $currentVolume = $part | Get-Volume

                if ($currentVolume -ne $null)
                {
                    $localVolumes += $currentVolume
                }
            }
        }
    }

    if ($localVolumes.Count -gt 0)
    {
        return Get-StandAloneServerVolumes -localVolumes $localVolumes -osVersion23H2OrLater $osVersion23H2OrLater
    }
    else
    {
        return $localVolumes
    }

}

<#
.Synopsis
    Name: Get-StandAloneServerVolumes
    Description: Gets the required volumes to return for a standalone server.

.Returns
    The local volumes.
#>
function Get-StandAloneServerVolumes {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Array] $localVolumes,

        [Parameter(Mandatory=$true)]
        [bool] $osVersion23H2OrLater
    )

    # Seperate the volumes to ones with size > 0
    # If there volumes with size 0 then check for type, keep ones wih "Basic" type
    $filteredLocalVolumes = @()

    foreach($volume in $localVolumes) {
        if ($volume.Size -gt 0) {
            $filteredLocalVolumes += $volume
        } elseif ($volume | Get-Partition | Where-Object { $_.type -eq "Basic" }) {
            $filteredLocalVolumes += $volume
        }
    }

    if ($osVersion23H2OrLater) {
        return $filteredLocalVolumes
    } else {
        # we now have logic to allow for drive paths if no drive letter so let's show them all as long as they have some size
        return $localVolumes | Where-Object { $_.Size -gt 0 }
    }
}

<#
.Synopsis
    Name: Get-ClusterVolumes
    Description: Gets the volumes on the cluster primary or secondary.

.Returns
    The cluster volumes.
#>
function Get-ClusterVolumes {
    Param
    (
        [Parameter(Mandatory=$true)]
        [System.Object] $cluster
    )

    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    Import-Module FailoverClusters, Storage, Microsoft.PowerShell.Utility

    $clusterVolumes            = @();
    $s2dEnabled         = (($cluster).S2DEnabled -eq 1)
    $node               = $env:COMPUTERNAME
    $available_storage  = Get-ClusterGroup | Where-Object { $_.GroupType -eq 'AvailableStorage' }

    $result = Move-ClusterGroup -InputObject $available_storage -Node $node

    if ($result -ne $null) {
        $availableResources = @()

        #
        # Find all groups, that are online on this node
        #
        $groups = Get-ClusterGroup | Where-Object { $_.OwnerNode -eq $env:COMPUTERNAME -and ( $_.State -eq 'Online' -or $_.State -eq 'PartialOnline' ) }

        #
        # Filter them
        # a) remove resources which are not online
        # b) remove groups which contain SR resources
        #
        if ($getVolumesOnlyFromAvailableStorage) {

            $availableResources += $available_storage | Get-ClusterResource | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }

        } else {
            foreach ($group in $groups) {
                $srResources = $group | Get-ClusterResource | ? ResourceType -eq 'Storage Replica'
                $isReplicationParticipant = (($srResources | Microsoft.PowerShell.Utility\Measure-Object).Count -ne 0)

                if ($isReplicationParticipant -eq $false) {

                    $diskResources = $group | Get-ClusterResource | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }

                    foreach ($disk in $diskResources) {
                        $availableResources += $disk
                    }
                }
            }
        }

        # Find disks which are physically connected to this node
        $physicallyConnectedDisks = Get-PhysicalDiskSNV | ? IsPhysicallyConnected -eq $true

        # Find all CSVs
        $csvs = Get-ClusterSharedVolume

        #
        # filter them
        # a) remove groups which contain SR resources
        # b) remove CSVs that are not physically connected to this node
        #
        foreach ($csv in $csvs) {

            $csvGroup                 = $csv | Get-ClusterGroup
            $srResources              = $csvGroup | Get-ClusterResource | ? ResourceType -eq 'Storage Replica'
            $isReplicationParticipant = (($srResources | Microsoft.PowerShell.Utility\Measure-Object).Count -ne 0)

            if ($isReplicationParticipant -eq $false) {

                $diskIdGuid = ($csv | Get-ClusterParameter -Name 'DiskIdGuid').Value
                $msftDisk   = Get-Disk | ? Guid -eq $diskIdGuid

                if ($msftDisk.PartitionStyle -eq 'GPT') {
                    if ($s2dEnabled -eq $true) {
                        $availableResources += $csv
                    }
                    else {
                        $pd = Get-PhysicalDisk | ? UniqueId -eq $msftDisk.UniqueId
                        if ($pd -ne $null) {
                            if (($physicallyConnectedDisks).PhysicalDisk | ? ObjectId -eq $pd.ObjectId) {
                                $availableResources += $csv
                            }
                        }
                    }
                }
            }
        }


        $csvType = [Microsoft.FailoverClusters.PowerShell.ClusterSharedVolume].FullName

        foreach ($resource in $availableResources) {
            $paramGuid = $resource | Get-ClusterParameter -Name DiskIdGuid
            $disk = Get-Disk | Where-Object { $_.Guid -eq $paramGuid.Value }

            if ($disk.PartitionStyle -eq 'GPT') {
                $volume = $disk | Get-Partition | Get-Volume

                $caption = $null;
                $displayName = $null;
                $isCSV = $false;

                if ([string]::IsNullOrWhiteSpace($volume.DriveLetter))
                {
                  $caption = $volume.Path
                } else
                {
                  $caption = $volume.DriveLetter + ':\'
                }

                if ([string]::IsNullOrWhiteSpace($volume.FileSystemLabel))
                {
                  $displayName = $caption
                }
                else
                {
                  $displayName = $volume.FileSystemLabel + ' (' + $caption + ')' # e.g. MyVolumeLabel (F:\) or MyVolumeLabel (\\?\VOLUME{EB824AA2-6E0A-4D29-BEB8-56112CAD3B5C}\)
                }

                if ($resource.GetType().FullName -eq $csvType) {
                    $caption = $resource.SharedVolumeInfo.FriendlyVolumeName
                    $displayName = $resource.SharedVolumeInfo.FriendlyVolumeName
                    $isCSV = $true;
                }

                $volumeObject = $volume | Microsoft.PowerShell.Utility\Select-Object @{ Name = 'Caption'; Expression = { $caption } },
                    @{ Name = 'DisplayName'; Expression = { $displayName } },
                    @{ Name = 'Size'; Expression = { $_.Size } },
                    @{ Name = 'SizeRemaining'; Expression = { $_.SizeRemaining } },
                    @{ Name = 'DiskLogicalSectorSize'; Expression = { $disk.LogicalSectorSize } },
                    @{ Name = 'DiskPhysicalSectorSize'; Expression = { $disk.PhysicalSectorSize } },
                    @{ Name = 'DriveLetter'; Expression = { $_.DriveLetter } },
                    @{ Name = 'FileSystem'; Expression = { $_.FileSystemType  } },
                    @{ Name = 'isCSV'; Expression = { $isCSV } },
                    @{ Name = 'clusterFQDN'; Expression = { "{0}.{1}" -f $cluster.Name, $cluster.Domain } },
                    @{ Name = 'FileSystemNumber'; Expression = { $_.psBase.CimInstanceProperties["FileSystemType"].Value } }

                $clusterVolumes += $volumeObject
            }
        }
    }

    if ($clusterVolumes.Count -gt 0) {
        return Get-FilteredClusterSharedVolumes -clusterVolumes $clusterVolumes -osVersion23H2OrLater $osVersion23H2OrLater
    } else {
        return $clusterVolumes
    }
}


<#
.Synopsis
    Name: Get-FilteredClusterSharedVolumes
    Description: Gets the required volumes to return for a CSV.

.Returns
    The cluster volumes.
#>
function Get-FilteredClusterSharedVolumes {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Array] $clusterVolumes,

        [Parameter(Mandatory=$true)]
        [bool] $osVersion23H2OrLater
    )

    if ($osVersion23H2OrLater) {
        return $clusterVolumes
    }

    $filteredClusterVolumes = @()

    foreach($volumeObject in $clusterVolumes) {
        if ($volumeObject.FileSystemNumber -ne 0) {
            $filteredClusterVolumes += $volumeObject
        }
    }

    return $filteredClusterVolumes;
}

$cluster = $null
try {
  Import-Module FailoverClusters -ErrorAction SilentlyContinue
  $cluster = Get-Cluster -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}
catch {
  # swallow the err if Get-Cluster cmdlet is not recognized because FailoverClustering is not installed
}

if ($cluster -ne $null) {
  Get-ClusterVolumes -Cluster $cluster
} else {
  Get-FileSystemRoot
}

}
## [END] Get-WACSRFileSystemRoot ##
function Get-WACSRNetIPConfiguration {
<#
.SYNOPSIS
  TODO: fill out synopsis

.DESCRIPTION
  TODO: fill out description

.ROLE
Readers

#>

Import-Module NetTCPIP

Get-NetIPConfiguration | Where-Object { $null -ne $_.NetProfile }
# Any networks that contains NULL for the property NetProfile is not usable for SR Network Constraints
# Filter them out.

}
## [END] Get-WACSRNetIPConfiguration ##
function Get-WACSRNodeClusteredState {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>


try {
    Import-Module FailoverClusters -ErrorAction Stop
    $cluster = Get-Cluster -ErrorAction SilentlyContinue
    if ($cluster)
    {
        return $true
    }
    return $false

}
catch {
    # swallow the error - it is not a cluster because get-cluster failed
    $_ | Out-Null
}


}
## [END] Get-WACSRNodeClusteredState ##
function Get-WACSRNodeFqdnsAndState {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

$nodes = @()


Get-Clusternode | ForEach-Object {
  $fqdn = $null
  $err = $null

  try {
      #  there could be a DNS lookup issue
      $fqdn = [System.Net.Dns]::GetHostEntry($_.Name).HostName;
  }
  catch {
      $err = $_
  }

    $nodes += @{
        name = $_.Name
        fqdn = $fqdn
        state = $_.State.value__;
        error = $err
    }

}

$nodes

}
## [END] Get-WACSRNodeFqdnsAndState ##
function Get-WACSROSBuild {
<#
.SYNOPSIS
Gets OS Build and UBR

.DESCRIPTION
Gets OS Build and UBR

.ROLE
Readers

#>
Import-Module  Microsoft.PowerShell.Management
$item = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Write-Output @{
"buildNumber" = $item.CurrentBuildNumber;
"ubr" = $item.UBR;
}

}
## [END] Get-WACSROSBuild ##
function Get-WACSRPartitionInfo {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $PartitionId,
    [Parameter(Mandatory=$true)]
    [String] $ReplicationGroupName
)
Import-Module CimCmdlets, Storage, Microsoft.PowerShell.Utility
$result = Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'QueryPartitionInfo' -Arguments @{'partitionId'= $PartitionId; 'replicationGroupName'= $ReplicationGroupName}
$partitionIdArgument = '{' + $PartitionId + '}'
$partitionResult = Get-Partition | ? Guid -eq $partitionIdArgument | Get-Volume
if ($partitionResult -ne $null)
{
    $result | Add-Member -NotePropertyName PartitionFreeSpaceInBytes -NotePropertyValue $partitionResult.SizeRemaining
}
Write-Output $result

}
## [END] Get-WACSRPartitionInfo ##
function Get-WACSRSRGroup {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $name
)

# function Get-PartitionInfo {
#     Param (
#       [Parameter(Mandatory=$true)]
#       [String] $PartitionId,
#       [Parameter(Mandatory=$true)]
#       [String] $ReplicationGroupName,
#       [Parameter(Mandatory=$true)]
#       [String] $ComputerName
#     )

#     $result = Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'QueryPartitionInfo' -Arguments @{'partitionId'= $PartitionId; 'replicationGroupName'= $ReplicationGroupName} -ComputerName $ComputerName
#     $partitionIdArgument = '{' + $PartitionId + '}'
#     $partitionResult = Get-Partition | ? Guid -eq $partitionIdArgument | Get-Volume

#     if ($partitionResult -ne $null)
#     {
#         $result | Add-Member -NotePropertyName PartitionFreeSpaceInBytes -NotePropertyValue $partitionResult.SizeRemaining
#     }

#     Write-Output $result
# }


Import-Module StorageReplica, Microsoft.PowerShell.Utility
$group = Get-SRGroup -Name $name
$result = @{
  "group" = $group;
  "ownerNode" = $null;
}

# $computerName = $group.computerName;

# used to set group.computerName to be the owner node's name instead of cluster's name
if ($group.isCluster)
{
    Import-Module FailoverClusters -ErrorAction SilentlyContinue
    $replicationIds = Get-ClusterResource | Where-Object { $_.resourcetype -eq "storage replica" }  | Get-ClusterParameter  -Name "replicationGroupId"
    $resource = $replicationIds | Where-Object { $_.value -eq  ('{' + $group.id + '}') }

    if (($resource -ne $null) -and ($resource.ClusterObject -ne $null -and $resource.ClusterObject.OwnerNode -ne $null))
    {
      $result.ownerNode = $resource.ClusterObject.OwnerNode.Name
      # $computerName =  $resource.ClusterObject.OwnerNode.Name
    }
}

# foreach ($replica in $group.replicas)
# {
#     $partitionInfo = get-PartitionInfo -PartitionId $replica.partitionId -ReplicationGroupName $group.Name -ComputerName $computerName
# }
# #todo need to get this info merged with the group data somehow otherwise need seperate call as before....



Write-Output $result


}
## [END] Get-WACSRSRGroup ##
function Get-WACSRSRNetworkConstraint {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory=$true)]
  [String] $destinationComputerName,
  [Parameter(Mandatory=$true)]
  [String] $destinationRGName
)

Import-Module StorageReplica

Get-SRNetworkConstraint -SourceRGName $sourceRGName -SourceComputerName $sourceComputerName -DestinationRGName $destinationRGName -DestinationComputerName $destinationComputerName

}
## [END] Get-WACSRSRNetworkConstraint ##
function Get-WACSRSRPartnership {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Import-Module StorageReplica
$partnerships = Get-SRPartnership
$partnershipData = @()

$fqdns = @{}

$partnerships | ForEach-Object {
  $partnerhipInfo = @{
    "partnership" = $_
    "sourceComputerFqdn" = $null;
    "destinationComputerFqdn" = $null;
  }


  try {
    if ($fqdns.ContainsKey($_.sourceComputerName)) {
      $partnerhipInfo.sourceComputerFqdn = $fqdns[$_.sourceComputerName]
    } else {
      $partnerhipInfo.sourceComputerFqdn = [System.Net.Dns]::GetHostByName($_.sourceComputerName).hostname
      $fqdns.Add($_.sourceComputerName, $partnerhipInfo.sourceComputerFqdn)
    }
  } catch {
    ## swallow it, we'll just leave it null
  }
  try {
    if ($fqdns.ContainsKey($_.destinationComputerName)) {
      $partnerhipInfo.destinationComputerFqdn = $fqdns[$_.destinationComputerName]
    } else {
      $partnerhipInfo.destinationComputerFqdn = [System.Net.Dns]::GetHostByName($_.destinationComputerName).hostname
      $fqdns.Add($_.destinationComputerName, $partnerhipInfo.destinationComputerFqdn)
    }
  }
  catch {
    ## swallow it, we'll just leave it null

  }
  $partnershipData += $partnerhipInfo
}

Write-Output $partnershipData

}
## [END] Get-WACSRSRPartnership ##
function Get-WACSRSRServerFeature {
<#################################################################################################################################################
 # File: Get-SRFeature.ps1
 #
 # .DESCRIPTION
 #
 # Gets the Windows Feature Storage Replica and returns if it is installed.
 #
 #  The supported Operating Systems are Windows Server 2016.
 #
 #  Copyright (c) Microsoft Corp 2016.
 #
 #################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Import-Module ServerManager
Get-WindowsFeature -Name Storage-Replica, RSAT-Storage-Replica
}
## [END] Get-WACSRSRServerFeature ##
function Install-WACSRSRFeature {
<#################################################################################################################################################
 # File: Install-SRFeature.ps1
 #
 # .DESCRIPTION
 #
 # Installs Storage Replica Feature and all management tools. 
 #
 #  The supported Operating Systems are Windows Server 2016.
 #
 #  Copyright (c) Microsoft Corp 2016.
 #
 #################################################################################################################################################>
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Boolean] $RestartMachine
)
Import-Module ServerManager
Add-WindowsFeature -Name Storage-Replica -IncludeManagementTools -Restart:$RestartMachine
}
## [END] Install-WACSRSRFeature ##
function Mount-WACSRSRDestination {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $resourceGroupName,
    [Parameter(Mandatory=$true)]
    [String] $temporaryPath
)

Import-Module CimCmdlets, Microsoft.PowerShell.Utility
Mount-SRDestination -Name $resourceGroupName -TemporaryPath $temporaryPath -Force

}
## [END] Mount-WACSRSRDestination ##
function New-WACSRSrPartnership {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $sourceComputerName,

  [Parameter(Mandatory = $true)]
  [string]
  $destinationComputerName,

  [Parameter(Mandatory = $true)]
  [string]
  $sourceRGName,

  [Parameter(Mandatory = $true)]
  [string]
  $destinationRGName,

  [Parameter(Mandatory = $true)]
  [array]
  $sourceVolumeName,

  [Parameter(Mandatory = $true)]
  [string]
  $sourceLogVolumeName,

  [Parameter(Mandatory = $true)]
  [array]
  $destinationVolumeName,

  [Parameter(Mandatory = $true)]
  [string]
  $destinationLogVolumeName,

  [Parameter(Mandatory=$true)]
  [bool]
  $enableEncryption,

  [Parameter(Mandatory=$true)]
  [bool]
  $enableConsistencyGroups,

  [Parameter(Mandatory=$true)]
  [Uint64]
  $logSizeInBytes,

  [Parameter(Mandatory = $true)]
  [bool]
  $seeded,

  [Parameter(Mandatory = $true)]
  [Uint32]
  $replicationMode,

  [Parameter(Mandatory = $true)]
  [uint32]
  $asyncRPO,

  [Parameter(Mandatory = $true)]
  [bool]
  $enableCompression,

  [Parameter(Mandatory = $true)]
  [int]
  $logType,

  [Parameter(Mandatory = $true)]
  [bool]
  $osVersion23H2OrLater
)
Import-Module StorageReplica
$customArgs = @{
    "SourceComputerName" =  $sourceComputerName;
    "DestinationComputerName" =  $destinationComputerName;
    "SourceRGName" =  $sourceRGName;
    "DestinationRGName" =  $destinationRGName;
    "ReplicationMode" =  $replicationMode;
    "SourceVolumeName" = $sourceVolumeName;
    "SourceLogVolumeName" = $sourceLogVolumeName;
    "DestinationVolumeName" = $destinationVolumeName;
    "DestinationLogVolumeName" = $destinationLogVolumeName;
    "LogSizeInBytes" = $logSizeInBytes;
}

if ($asyncRPO -gt 0)
{
    $customArgs.AsyncRPO = $asyncRPO
}

# Older OS versions do not support compression, so even if it's false we don't want to pass the flag in
if ($osVersion23H2OrLater) {
  New-SRPartnership @customArgs -Seeded:$seeded -EnableConsistencyGroups:$enableConsistencyGroups -EnableEncryption:$enableEncryption -LogType $logType -EnableCompression:$enableCompression -Force
} else {
  New-SRPartnership @customArgs -Seeded:$seeded -EnableConsistencyGroups:$enableConsistencyGroups -EnableEncryption:$enableEncryption -Force
}


}
## [END] New-WACSRSrPartnership ##
function Remove-WACSRSRGroup {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $computerName,
    [String] $rgName
)
Import-Module CimCmdlets

Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'RemoveSrGroup' -Arguments @{'ComputerName'= $computerName; 'Name'= $rgName;}

}
## [END] Remove-WACSRSRGroup ##
function Remove-WACSRSRNetworkConstraint {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory=$true)]
  [String] $destinationComputerName,
  [Parameter(Mandatory=$true)]
  [String] $destinationRGName
)

Import-Module StorageReplica

Remove-SRNetworkConstraint -SourceComputerName $sourceComputerName -SourceRGName $sourceRGName -DestinationComputerName $destinationComputerName -DestinationRGName $destinationRGName -Force

}
## [END] Remove-WACSRSRNetworkConstraint ##
function Remove-WACSRSRPartnership {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $sourceComputerName,
    [Parameter(Mandatory=$true)]
    [String] $sourceRGName,
    [Parameter(Mandatory=$true)]
    [String] $destinationComputerName,
    [Parameter(Mandatory=$true)]
    [String] $destinationRGName
)
Import-Module CimCmdlets

Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'RemovePartnership' -Arguments @{'SourceComputerName'= $sourceComputerName; 'SourceRGName'= $sourceRGName; "DestinationComputerName"=$destinationComputerName; 'DestinationRGName' = $destinationRGName; IgnoreRemovalFailure = $true;}

}
## [END] Remove-WACSRSRPartnership ##
function Remove-WACSRVolumes {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory=$true)]
  [array] $removeVolumeNames,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName
)

Import-Module CimCmdlets

Invoke-CimMethod -Namespace 'root/Microsoft/Windows/StorageReplica' -ClassName 'MSFT_WvrAdminTasks' -MethodName 'SetGroupRemoveVolumes' -Arguments @{'ComputerName'= $sourceComputerName; 'Name'= $sourceRGName; "RemoveVolumeName"=$removeVolumeNames;}

}
## [END] Remove-WACSRVolumes ##
function Set-WACSRSRNetworkConstraint {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory=$true)]
  [String] $sourceComputerName,
  [Parameter(Mandatory=$true)]
  [String] $sourceRGName,
  [Parameter(Mandatory=$true)]
  [String[]] $sourceNWInterfaces,
  [Parameter(Mandatory=$true)]
  [String] $destinationComputerName,
  [Parameter(Mandatory=$true)]
  [String] $destinationRGName,
  [Parameter(Mandatory=$true)]
  [String[]] $destinationNWInterfaces,
  [Parameter(Mandatory=$true)]
  [bool] $isServerToServerPartnership
)

Import-Module StorageReplica

Set-SRNetworkConstraint -SourceComputerName $sourceComputerName -SourceRGName $sourceRGName -SourceNWInterface $sourceNWInterfaces -DestinationComputerName $destinationComputerName -DestinationRGName $destinationRGName -DestinationNWInterface $destinationNWInterfaces

if ($isServerToServerPartnership -eq $true)
{
  # Only if running on server to server case
  Update-SmbMultichannelConnection
}


}
## [END] Set-WACSRSRNetworkConstraint ##
function Set-WACSRSRPartnershipRoles {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $destinationComputerName,
    [Parameter(Mandatory=$true)]
    [String] $destinationRGName,
    [Parameter(Mandatory=$true)]
    [String] $newSourceComputerName,
    [Parameter(Mandatory=$true)]
    [String] $sourceRGName
)
Import-Module StorageReplica

Set-SRPartnership -NewSourceComputerName $newSourceComputerName -SourceRGName $sourceRGName -DestinationComputerName $destinationComputerName -DestinationRGName $destinationRGName -Force

}
## [END] Set-WACSRSRPartnershipRoles ##
function Suspend-WACSRSRGroup {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $name
)
Import-Module StorageReplica

Suspend-SRGroup -Name $name -Force

}
## [END] Suspend-WACSRSRGroup ##
function Sync-WACSRSRGroup {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory=$true)]
    [String] $name
)
Import-Module StorageReplica

Sync-SRGroup -Name $name -Force

}
## [END] Sync-WACSRSRGroup ##
function Test-WACSRConnection {
<#
.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
param (
		[Parameter(Mandatory = $true)]
		[String]
    $nodeName
)
Import-Module Microsoft.PowerShell.Management

Test-Connection -ComputerName $nodeName -Quiet

}
## [END] Test-WACSRConnection ##
function Clear-WACSREventLogChannel {
<#

.SYNOPSIS
Clear the event log channel specified.

.DESCRIPTION
Clear the event log channel specified.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>
 
Param(
    [string]$channel
)

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
}
## [END] Clear-WACSREventLogChannel ##
function Clear-WACSREventLogChannelAfterExport {
<#

.SYNOPSIS
Clear the event log channel after export the event log channel file (.evtx).

.DESCRIPTION
Clear the event log channel after export the event log channel file (.evtx).
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /ow:true

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 

return $ResultFile

}
## [END] Clear-WACSREventLogChannelAfterExport ##
function Export-WACSREventLogChannel {
<#

.SYNOPSIS
Export the event log channel file (.evtx) with filter XML.

.DESCRIPTION
Export the event log channel file (.evtx) with filter XML.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [string]$filterXml
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /q:"$filterXml" /ow:true

return $ResultFile

}
## [END] Export-WACSREventLogChannel ##
function Get-WACSRCimEventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Server Manager CIM provider.

.DESCRIPTION
Get Log records of event channel by using Server Manager CIM provider.

.ROLE
Readers

#>

Param(
    [string]$FilterXml,
    [bool]$ReverseDirection
)

import-module CimCmdlets

$machineName = [System.Net.DNS]::GetHostByName('').HostName
Invoke-CimMethod -Namespace root/Microsoft/Windows/ServerManager -ClassName MSFT_ServerManagerTasks -MethodName GetServerEventDetailEx -Arguments @{FilterXml = $FilterXml; ReverseDirection = $ReverseDirection; } |
    ForEach-Object {
        $result = $_
        if ($result.PSObject.Properties.Match('ItemValue').Count) {
            foreach ($item in $result.ItemValue) {
                @{
                    ItemValue = 
                    @{
                        Description  = $item.description
                        Id           = $item.id
                        Level        = $item.level
                        Log          = $item.log
                        Source       = $item.source
                        Timestamp    = $item.timestamp
                        __ServerName = $machineName
                    }
                }
            }
        }
    }

}
## [END] Get-WACSRCimEventLogRecords ##
function Get-WACSRClusterEvents {
<#
.SYNOPSIS
Gets CIM instance

.DESCRIPTION
Gets CIM instance

.ROLE
Readers

#>

param (
		[Parameter(Mandatory = $true)]
		[string]
    $namespace,

    [Parameter(Mandatory = $true)]
		[string]
    $className

)
Import-Module CimCmdlets
Get-CimInstance -Namespace  $namespace -ClassName $className

}
## [END] Get-WACSRClusterEvents ##
function Get-WACSREventLogDisplayName {
<#

.SYNOPSIS
Get the EventLog log name and display name by using Get-EventLog cmdlet.

.DESCRIPTION
Get the EventLog log name and display name by using Get-EventLog cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>


return (Get-EventLog -LogName * | Microsoft.PowerShell.Utility\Select-Object Log,LogDisplayName)
}
## [END] Get-WACSREventLogDisplayName ##
function Get-WACSREventLogFilteredCount {
<#

.SYNOPSIS
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$filterXml
)

return (Get-WinEvent -FilterXml "$filterXml" -ErrorAction 'SilentlyContinue').count
}
## [END] Get-WACSREventLogFilteredCount ##
function Get-WACSREventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Get-WinEvent cmdlet.

.DESCRIPTION
Get Log records of event channel by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers
#>

Param(
    [string]
    $filterXml,
    [bool]
    $reverseDirection
)

$ErrorActionPreference = 'SilentlyContinue'
Import-Module Microsoft.PowerShell.Diagnostics;

#
# Prepare parameters for command Get-WinEvent
#
$winEventscmdParams = @{
    FilterXml = $filterXml;
    Oldest    = !$reverseDirection;
}

Get-WinEvent  @winEventscmdParams -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object recordId,
id, 
@{Name = "Log"; Expression = {$_."logname"}}, 
level, 
timeCreated, 
machineName, 
@{Name = "Source"; Expression = {$_."ProviderName"}}, 
@{Name = "Description"; Expression = {$_."Message"}}



}
## [END] Get-WACSREventLogRecords ##
function Get-WACSREventLogSummary {
<#

.SYNOPSIS
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$channel
)

Import-Module Microsoft.PowerShell.Diagnostics

$channelList = $channel.split(",")

Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue |`
    Microsoft.PowerShell.Utility\Select-Object LogName, IsEnabled, RecordCount, IsClassicLog, LogType, OwningProviderName
}
## [END] Get-WACSREventLogSummary ##
function Set-WACSREventLogChannelStatus {
 <#

.SYNOPSIS
 Change the current status (Enabled/Disabled) for the selected channel.

.DESCRIPTION
Change the current status (Enabled/Disabled) for the selected channel.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [boolean]$status
)

$ch = Get-WinEvent -ListLog $channel
$ch.set_IsEnabled($status)
$ch.SaveChanges()
}
## [END] Set-WACSREventLogChannelStatus ##

# SIG # Begin signature block
# MIIoUgYJKoZIhvcNAQcCoIIoQzCCKD8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBBPw9Oev0t/iEu
# dJCb2VBIwq5SQFAvEkpuExVnhfna0KCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGiMwghofAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAASEmOIS4HijMV0AAAAA
# BIQwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOWi
# /MXuEVtKo7tkmIvqX++WMCZ5GFdUOti+Us5yXky3MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEA7OY/XWpgFqGSJ6zfy10kMeR3wwj43sf75LBl
# hgpy17w9c9RqS529nEvVjpUBXWNGBKSKB+/vKYtQtimihfaP9oDjnceChrmbDOgt
# nNOyle+Xg1H8rfBXvh9v68q79JV7Rp2WXY+ZUySQJtOU8I4uGbr11hvMjHBMEJVg
# k3MqZknQJkqbxSnFBDS6sITY/XFZgReFVgpQ6ZzPXSvb4PKhV2AA6QHIoawFU3wi
# SnmaU1m4gKHudSQa3VpVUOvd/+A29EM3+wRh+Evj0rz2hGhIiUMT+PToDS0KkeV+
# 0rFUMMRcib1F8apsYdFzEHg4wSZI5wMvx3JuB8NJjvaAH/N+haGCF60wghepBgor
# BgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCCF4YwgheCAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCC8Ix8E0WA0dF2QmVqLwcf2FU0amLwvbsyN
# vmHVtjBcMAIGaQJQq6D9GBMyMDI1MTExMDE3MTcxMy41NzdaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo2RjFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggcoMIIFEKADAgECAhMzAAACHAlV
# FdfDWQfRAAEAAAIcMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgzMVoXDTI2MTExMzE4NDgzMVowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjZGMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# ow0xEAUaFIyyLIXeFzeI8IKyBON2u0Dr02ISE5p9G5CUXfnFu2S0E1gWCMvDWpop
# X6lRxjmgnqaL3BtnWlBVTo8xUNRZu23ie4YBMAJB7Ut6mnqnHVwvDJxGO4TD3Snr
# Cd+yg35B9QFejq3o4+OByvXjynaypZyukcQaLsKQvoxE8ElHH7zcOXEJWmU3rnXz
# aW/S4SH3OPhoUbTTcy6nUgKx5pRWiQ24UEPLYzcxGJjqjkz+GiCWGPFHDMdW86la
# WvmCslouQPsN2eBk8dxJcEZmW4l6p4TthoXcfexEA9YdYaMz10aMhZNpdsNaDtDQ
# UMDEC3k1D1My69MXSPlUmD9xFyDlkXiVa7BCEp3XcVtqTgzHGwr28JD6oE7zEPYe
# uZOiuCBXTZSo/wk3tbDlsESbIPV6inYqrzxiMYqlxfCdzC3Cimh9/NT/Lk9/aU+I
# yyc9b3OaT0dZ8wgLaVDCGELRMrqyImdFHv0MudctzW/kPsV3Ja9ufpKWujEiN3CW
# //X8hFa9j5ImNeQzcMit3MoSaoGwnbiZJX1IyibIphlqccXFk4oTTSOQBsAUw8U0
# gwOnM5UJD8mBUBd65Np6NBkx2cviJ4I34GyXFCWyy5Ft1QsBYyVfAG3KOhCfPHQf
# 8lQzJvLr57YW0bD/xVs4Ag4gTS6KZNyFEfX9jFdRlr0CAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBRa3mOCzB8u7zpvDh8MGKVYLCk7ZDAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAklb6w/deaid3BujQCtWFBe0n9pkyRy+yyWEg70iDwoJ5u0e0O+4GerNz
# dZb1zTPsHJ8EGMyo1K7ytL21+pmdFMTl19PC8OJ5Y2p+XKUQy2dD+hggRMmJgDQs
# gbOCxHYeO+jg4t+vg61wUrovzzLkH3z0PJXXvoNuBj9Lda9CiNMd60451Kube99A
# rSf6ZMj3t0p4rFbgSazDs+8TJ+8KA5GVaYjPHj9rlMuI3WjohEc9apnQ6hMjMck3
# jlHZIwluVYeUQE0qjmApfMtTAEzbMUdY8sLTunL1GkbDSeKn9O7llBGnNtyM1uM9
# Mdv1VyWh0z/IriQKIjntqqGyoF0HvDHOFZCyUDBPLflyiu7Y1zQ/sPounsb96aBf
# Qdq3h3LOn6t+m9EnNz/G6MzzWvpJk6YgTHTIqeQN/F/XpiPvbfek3nq/PYbL3au+
# kBfRUHiCFXSvt6lor0HC626vUmz9ZNPOxwEWLuccomxsy3JwWH79vsM/7ARqoG5h
# 6d6NahfaOuRP4XI9xtdH3Pa/NCLyQjxKXyLxzwQzjddkX2EpTJnlypuhPmEdea59
# Uz2E303LxyXSnKBvGsAnyWYAfnejr3YAiL9YrN2l2dn198RpA4DCm9QtZYiwC0q2
# fuUvui34PfPIUZByf7wHuuWu50hY9WLx1kOMI8xyo7AI6TaNrnIwggdxMIIFWaAD
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
# 2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIDVjCCAj4CAQEwggEBoYHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo2RjFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAWmTiA01u5mxq
# /nVxiRJLMOskVGeggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy795MwIhgPMjAyNTExMTAwNTMzMDdaGA8yMDI1
# MTExMTA1MzMwN1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7Lv3kwIBADAHAgEA
# AgIIDTAHAgEAAgIT6jAKAgUA7L1JEwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQBLekvBsUWFvaZSaR8pet3IZ2sSs2NCitsAwL7Oa4F8LdG12L3BPAyofesz
# wljkD/KYB4U+HahdkMVI6+XeWvdQHibZKIuYddSbmiJ9mkGrFRdhFmWQbpu6/oWr
# 1UE0tmqnWLEssUa9Liluik/DaX/t0PsPTXFlSDZW2WFEiAiYpyxrKBGQJ19g8T/3
# QDONmcg62D9sPzGs2sAwxvZQKFFH7VIxDnLIqwXnDhYXZMBIHPaBwndOmbBOZ8Hy
# Yiu7GcpmpGV/5d8wg8mKkcbLx7X4k+RXozJXt/jIIcdqxQEoovxSSiRMjWuWiJEB
# Ib3e2bMBpAG0CWOKy1W3tAOuNC9rMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAIcCVUV18NZB9EAAQAAAhwwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgntnm/6EjMKyBBVe8HcdRvPdmFy9PPJiBQCdjx8lOYOgwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCCgIGkmNhdo7+KE7dWhI+E2Ctx2RLWoYvvJodCI
# ciHHaDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAC
# HAlVFdfDWQfRAAEAAAIcMCIEIHeDNdvBGQMhi6ws4jIBZXkSdigLXM0sXhmRZcg+
# 6v5VMA0GCSqGSIb3DQEBCwUABIICAJUwEmAae9YYbVBcJ1hde6uYwEScnFVvQBE8
# LgigRxMEy0LcGEHhq8ln7/GPZCGrg51IestbVkKrtKiHGae9WsiBVb6dEQfCwLAD
# Lc7m3Yu/xAFgokdcOKF0oEr7+XHLXkBytm13uW3CTv7DfYpTARPYOpMw/+1+TLIC
# M2zeuzFhjQQbNCi5LYknQuEFNbi9kPIbSte6L8BWZGwSThKthvxvVOTZWCNGVyAY
# gel4SFmkSbSWk0ul5gDWl/7ueA4RfSuWyoRCDKBPyLO3e76d7poh1pdthkb2YNCX
# mS0BkCNyz7OqtuozYLxoEl1NfF8NNNu1NzX8naZpcH9mtAnflsD2xWNIISDZ8ikX
# rp4DauXMYCpxVxzd3lCaOYKdbAQ83zCxBU9B60xcsT0hRR7sWQ9ebjwZC4nNykBe
# RR/u+5OwSUddK15aXwAtaiA+wosVg+IoHXax/9FmFQn6gH4fdR6KbRVVXHAId77/
# 9uC5Ttik7xE+lxoW5Y47o6LjI9yUcpPlYd+trW0OCsu6p02pfC6xpJ/Dk+3I6YJN
# XmbZYk41/OEpsJ6lBk+IuZLSd9542EPf+XC7Kin+WnY/b/VxQioySXI0vXZzeFOD
# BH6/LmbNel5aNT7IXFl497zSMPceSvksTWTzywRcsfe3N/llWndcXETjvwfO9Src
# CzRizpJW
# SIG # End signature block
