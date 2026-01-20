function Dismount-WACSOStorageVHD {
<#
.SYNOPSIS
Detaches the VHD.

.DESCRIPTION
Detaches the VHD.

.ROLE
Administrators

.PARAMETER path
    The disk path.
#>
param (
    [parameter(Mandatory=$true)]
    [String]
    $path
)

Import-Module Storage

Dismount-DiskImage -DevicePath $path

}
## [END] Dismount-WACSOStorageVHD ##
function Edit-WACSOStorageVolume {
 <#

.SYNOPSIS
Update volume properties.

.DESCRIPTION
Update volume properties.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER diskNumber
    The disk number.

.PARAMETER partitionNumber
    The partition number.

.PARAMETER oldDriveLetter
    Volume old dirve letter.

.PARAMETER newVolumeName
    Volume new name.    

.PARAMETER newDriveLetter
    Volume new dirve letter.

.PARAMETER driveType
    Volume drive type.

#>

 param (
    [String]
    $diskNumber,
    [uint32]
    $partitionNumber,
    [char]
    $newDriveLetter,
    [int]
    $driveType,
    [char]
    $oldDriveLetter,
    [String]
    $newVolumeName
)

Import-Module Microsoft.PowerShell.Management
Import-Module Storage

if($oldDriveLetter -ne $newDriveLetter) {
    if($driveType -eq 5 -or $driveType -eq 2)
    {
        $drv = Get-WmiObject win32_volume -filter "DriveLetter = '$($oldDriveLetter):'"
        $drv.DriveLetter = "$($newDriveLetter):"
        $drv.Put() | out-null
    } 
    else
    {
        Set-Partition -DiskNumber $diskNumber -PartitionNumber $partitionNumber -NewDriveLetter $newDriveLetter
    }

    # In case of CD ROM, volume label update is not supported.
    if ($driveType -ne 5)
    {
        Set-Volume -DriveLetter $newDriveLetter -NewFileSystemLabel $newVolumeName
    }
} 
else 
{
    Set-Volume -DriveLetter $newDriveLetter -NewFileSystemLabel $newVolumeName
}
}
## [END] Edit-WACSOStorageVolume ##
function Format-WACSOStorageVolume {
<#

.SYNOPSIS
Formats a drive by drive letter.

.DESCRIPTION
Formats a drive by drive letter.

.ROLE
Administrators

.PARAMETER driveLetter
    The drive letter.

.PARAMETER allocationUnitSizeInBytes
    The allocation unit size.

.PARAMETER fileSystem
    The file system type.

.PARAMETER fileSystemLabel
    The file system label.    

.PARAMETER compress
    True to compress, false otherwise.

.PARAMETER quickFormat
    True to run a quick format.
#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $driveLetter,

    [UInt32]
    $allocationUnitSizeInBytes,

    [String]
    $fileSystem,

    [String]
    $newFileSystemLabel,

    [Boolean]
    $compress = $false,

    [Boolean]
    $quickFormat = $true
)

Import-Module Storage

#
# Prepare parameters for command Format-Volume
#
$FormatVolumecmdParams = @{
    DriveLetter = $driveLetter;
    Compress = $compress;
    Full = -not $quickFormat}

if($allocationUnitSizeInBytes -ne 0)
{
    $FormatVolumecmdParams.AllocationUnitSize = $allocationUnitSizeInBytes
}

if ($fileSystem)
{
    $FormatVolumecmdParams.FileSystem = $fileSystem
}

if ($newFileSystemLabel)
{
    $FormatVolumecmdParams.NewFileSystemLabel = $newFileSystemLabel
}

Format-Volume @FormatVolumecmdParams -confirm:$false

}
## [END] Format-WACSOStorageVolume ##
function Get-WACSOBitLocker {
<#

.SYNOPSIS
Gets all of the local volumes information which BitLocker Drive Encryption can protect of the system

.DESCRIPTION
Gets all of the local volumes information which BitLocker Drive Encryption can protect of the system
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>
if (Get-Module -ListAvailable -Name BitLocker) {
  $bitLockerInfo = @()
  $allBitLocker = Get-BitLockerVolume
  foreach ($bitLocker in $allBitLocker) {
    $curBitLocker = New-Object -TypeName PSObject
    $curBitLocker | Add-Member -NotePropertyName driveLetter -NotePropertyValue $bitLocker.MountPoint[0]
    $curBitLocker | Add-Member -NotePropertyName volumeStatus -NotePropertyValue $bitLocker.VolumeStatus
    $curBitLocker | Add-Member -NotePropertyName encryptionPercentage -NotePropertyValue $bitLocker.EncryptionPercentage
    $bitLockerInfo += $curBitLocker
  }
  $bitLockerInfo
} else {
  $False
}



}
## [END] Get-WACSOBitLocker ##
function Get-WACSOStorageDisk {
<#

.SYNOPSIS
Enumerates all of the local disks of the system.

.DESCRIPTION
Enumerates all of the local disks of the system.

.ROLE
Readers

#>
param (
    [Parameter(Mandatory = $false)]
    [String]
    $DiskId
)

Import-Module CimCmdlets
Import-Module Microsoft.PowerShell.Utility

<#
.Synopsis
    Name: Get-Disks
    Description: Gets all the local disks of the machine.

.Parameters
    $DiskId: The unique identifier of the disk desired (Optional - for cases where only one disk is desired).

.Returns
    The local disk(s).
#>
function Get-DisksInternal {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $DiskId
    )

    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel) {
        $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace Root\Microsoft\Windows\Storage;
    }
    else {
        $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage | Where-Object { $_.FriendlyName -like "*Win*" };
        $disks = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Disk;
    }

    if ($DiskId) {
        $disks = $disks | Where-Object { $_.UniqueId -eq $DiskId };
    }


    $disks | ForEach-Object {
        $partitions = $_ | Get-CimAssociatedInstance -ResultClassName MSFT_Partition
        $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume
        $volumeIds = @()
        $volumes | ForEach-Object {

            $volumeIds += $_.path
        }

        $_ | Add-Member -NotePropertyName VolumeIds -NotePropertyValue $volumeIds

    }

    $disks = $disks | ForEach-Object {

        $disk = @{
            AllocatedSize      = $_.AllocatedSize;
            BootFromDisk       = $_.BootFromDisk;
            BusType            = $_.BusType;
            FirmwareVersion    = $_.FirmwareVersion;
            FriendlyName       = $_.FriendlyName;
            HealthStatus       = $_.HealthStatus;
            IsBoot             = $_.IsBoot;
            IsClustered        = $_.IsClustered;
            IsOffline          = $_.IsOffline;
            IsReadOnly         = $_.IsReadOnly;
            IsSystem           = $_.IsSystem;
            LargestFreeExtent  = $_.LargestFreeExtent;
            Location           = $_.Location;
            LogicalSectorSize  = $_.LogicalSectorSize;
            Model              = $_.Model;
            NumberOfPartitions = $_.NumberOfPartitions;
            OfflineReason      = $_.OfflineReason;
            OperationalStatus  = $_.OperationalStatus;
            PartitionStyle     = $_.PartitionStyle;
            Path               = $_.Path;
            PhysicalSectorSize = $_.PhysicalSectorSize;
            ProvisioningType   = $_.ProvisioningType;
            SerialNumber       = $_.SerialNumber;
            Signature          = $_.Signature;
            Size               = $_.Size;
            UniqueId           = $_.UniqueId;
            UniqueIdFormat     = $_.UniqueIdFormat;
            volumeIds          = $_.volumeIds;
            Number             = $_.Number;
        }
        if (-not $isDownLevel) {
            $disk.IsHighlyAvailable = $_.IsHighlyAvailable;
            $disk.IsScaleOut = $_.IsScaleOut;
        }
        return $disk;
    }

    if ($isDownlevel) {
        $healthStatusMap = @{
            0 = 3;
            1 = 0;
            4 = 1;
            8 = 2;
        };

        $operationalStatusMap = @{
            0 = @(0); # Unknown
            1 = @(53264); # Online
            2 = @(53265); # Not ready
            3 = @(53266); # No media
            4 = @(53267); # Offline
            5 = @(53268); # Error
            6 = @(13); # Lost communication
        };

        $disks = $disks | ForEach-Object {
            $_.HealthStatus = $healthStatusMap[[int32]$_.HealthStatus];
            $_.OperationalStatus = $operationalStatusMap[[int32]$_.OperationalStatus[0]];
            $_;
        };
    }

    return $disks;
}

if ($DiskId) {
    Get-DisksInternal -DiskId $DiskId
}
else {
    Get-DisksInternal
}

}
## [END] Get-WACSOStorageDisk ##
function Get-WACSOStorageQuota {

<#

.SYNOPSIS
Get all Quotas.

.DESCRIPTION
Get all Quotas.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#> 
if (Get-Module -ListAvailable -Name FileServerResourceManager) {
    Import-Module FileServerResourceManager
    Get-FsrmQuota
} else {
    $False
}
}
## [END] Get-WACSOStorageQuota ##
function Get-WACSOStorageResizeDetails {

<#

.SYNOPSIS
Get disk and volume space details required for resizing volume.

.DESCRIPTION
Get disk and volume space details required for resizing volume.

.ROLE
Readers

.PARAMETER driveLetter
The drive letter

#> 
 param (
		[Parameter(Mandatory = $true)]
	    [String]
        $driveLetter
    )
Import-Module Storage

# Get volume details
$volume = get-Volume -DriveLetter $driveLetter

$volumeTotalSize = $volume.Size

# Get partition details by drive letter
$partition = get-Partition -DriveLetter $driveLetter

$partitionNumber =$partition.PartitionNumber
$diskNumber = $partition.DiskNumber

$disk = Get-Disk -Number $diskNumber

$totalSize = $disk.Size

$allocatedSize = $disk.AllocatedSize

# get unallocated space on the disk
$unAllocatedSize = $totalSize - $allocatedSize

$sizes = Get-PartitionSupportedSize -DiskNumber $diskNumber -PartitionNumber $partitionNumber

$resizeDetails=@{
  "volumeTotalSize" = $volumeTotalSize;
  "unallocatedSpaceSize" = $unAllocatedSize;
  "minSize" = $sizes.sizeMin;
  "maxSize" = $sizes.sizeMax;
 }

 return $resizeDetails
}
## [END] Get-WACSOStorageResizeDetails ##
function Get-WACSOStorageVolume {
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

    $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "*Win*" }
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

    }
    else
    {
        # This volume is not associated with partition, as such it is representing devices like CD-ROM, Floppy drive etc.
        $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $true
        $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $true
        $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $true
        $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue -1
        $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue -1
    }

    $resultantVolumes += $volume
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
## [END] Get-WACSOStorageVolume ##
function Initialize-WACSOStorageDisk {
<#

.SYNOPSIS
Initializes a disk

.DESCRIPTION
Initializes a disk

.ROLE
Administrators

.PARAMETER diskNumber
The disk number

.PARAMETER partitionStyle
The partition style

#> 
param (
    [Parameter(Mandatory = $true)]
    [String]
    $diskNumber,

    [Parameter(Mandatory = $true)]
    [String]
    $partitionStyle
)

Import-Module Storage

Initialize-Disk -Number $diskNumber -PartitionStyle $partitionStyle
}
## [END] Initialize-WACSOStorageDisk ##
function Install-WACSOStorageFSRM {

<#

.SYNOPSIS
Install File serve resource manager.

.DESCRIPTION
Install File serve resource manager.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#> 
Import-Module ServerManager

Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
}
## [END] Install-WACSOStorageFSRM ##
function Mount-WACSOStorageVHD {
<#

.SYNOPSIS
Attaches a VHD as disk.

.DESCRIPTION
Attaches a VHD as disk.

.ROLE
Administrators

.PARAMETER path
The VHD path

#> 
param (
    [Parameter(Mandatory = $true)]
    [String]
    $path
)

Import-Module Storage

Mount-DiskImage -ImagePath $path
}
## [END] Mount-WACSOStorageVHD ##
function New-WACSOStorageQuota {
<#

.SYNOPSIS
Creates a new Quota for volume.

.DESCRIPTION
Creates a new Quota for volume.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER disabledQuota
    Enable or disable quota.

.PARAMETER path
    Path of the quota.

.PARAMETER size
    The size of quota.

.PARAMETER softLimit
    Deny if usage exceeding quota limit.

#>

param
(
    # Enable or disable quota.
    [Boolean]
    $disabledQuota,

    # Path of the quota.
    [String]
    $path,

    # The size of quota.
    [String]
    $size,

    # Deny if usage exceeding quota limit.
    [Boolean]
    $softLimit
)

Import-Module FileServerResourceManager

$scriptArgs = @{
    Path = $path;
}

if ($size) {
    $scriptArgs.Size = $size
}
if ($disabledQuota) {
    $scriptArgs.Disabled = $true
}
if ($softLimit) {
    $scriptArgs.SoftLimit = $true
}

New-FsrmQuota @scriptArgs
}
## [END] New-WACSOStorageQuota ##
function New-WACSOStorageVHD {
<#

.SYNOPSIS
Creates a new VHD.

.DESCRIPTION
Creates a new VHD.

.ROLE
Administrators

.PARAMETER filePath
The path to the VHD that will be created.

.PARAMETER size
The size of the VHD.

.PARAMETER dynamic
True for a dynamic VHD, false otherwise.

.PARAMETER overwrite
True to overwrite an existing VHD.

#> 
param
(
	# Path to the resultant vhd/vhdx file name.
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[String]
    [ValidateLength(1, 259)]
	$filepath,

    # The size of vhd/vhdx.
    [Parameter(Mandatory = $true)]
    [System.UInt64]
    $size,

    # Whether it is a dynamic vhd/vhdx.
    [Parameter(Mandatory = $true)]
    [Boolean]
    $dynamic,

    # Overwrite if already exists.
    [Boolean]
    $overwrite=$false
)

$NativeCode=@"

    namespace SME
    {
        using Microsoft.Win32.SafeHandles;
        using System;
        using System.ComponentModel;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Security;

        public static class VirtualDisk
        {
            const uint ERROR_SUCCESS = 0x0;

            const uint DEFAULT_SECTOR_SIZE = 0x200;

            const uint DEFAULT_BLOCK_SIZE = 0x200000;

            private static Guid VirtualStorageTypeVendorUnknown = new Guid("00000000-0000-0000-0000-000000000000");

            private static Guid VirtualStorageTypeVendorMicrosoft = new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SecurityDescriptor
            {
                public byte revision;
                public byte size;
                public short control;
                public IntPtr owner;
                public IntPtr group;
                public IntPtr sacl;
                public IntPtr dacl;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct CreateVirtualDiskParametersV1
            {
                public CreateVirtualDiskVersion Version;
                public Guid UniqueId;
                public ulong MaximumSize;
                public uint BlockSizeInBytes;
                public uint SectorSizeInBytes;
                public string ParentPath;
                public string SourcePath;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct CreateVirtualDiskParametersV2
            {
                public CreateVirtualDiskVersion Version;
                public Guid UniqueId;
                public ulong MaximumSize;
                public uint BlockSizeInBytes;
                public uint SectorSizeInBytes;
                public uint PhysicalSectorSizeInBytes;
                public string ParentPath;
                public string SourcePath;
                public OpenVirtualDiskFlags OpenFlags;
                public VirtualStorageType ParentVirtualStorageType;
                public VirtualStorageType SourceVirtualStorageType;
                public Guid ResiliencyGuid;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct VirtualStorageType
            {
                public VirtualStorageDeviceType DeviceId;
                public Guid VendorId;
            }

            public enum CreateVirtualDiskVersion : int
            {
                VersionUnspecified = 0x0,
                Version1 = 0x1,
                Version2 = 0x2
            }

            public enum VirtualStorageDeviceType : int
            {
                Unknown = 0x0,
                Iso = 0x1,
                Vhd = 0x2,
                Vhdx = 0x3
            }

            [Flags]
            public enum OpenVirtualDiskFlags
            {
                None = 0x0,
                NoParents = 0x1,
                BlankFile = 0x2,
                BootDrive = 0x4,
            }

            [Flags]
            public enum VirtualDiskAccessMask
            {
                None = 0x00000000,
                AttachReadOnly = 0x00010000,
                AttachReadWrite = 0x00020000,
                Detach = 0x00040000,
                GetInfo = 0x00080000,
                Create = 0x00100000,
                MetaOperations = 0x00200000,
                Read = 0x000D0000,
                All = 0x003F0000,
                Writable = 0x00320000
            }

            [Flags]
            public enum CreateVirtualDiskFlags
            {
                None = 0x0,
                FullPhysicalAllocation = 0x1
            }

            [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern uint CreateVirtualDisk(
                [In, Out] ref VirtualStorageType VirtualStorageType,
                [In]          string Path,
                [In]          VirtualDiskAccessMask VirtualDiskAccessMask,
                [In, Out] ref SecurityDescriptor SecurityDescriptor,
                [In]          CreateVirtualDiskFlags Flags,
                [In]          uint ProviderSpecificFlags,
                [In, Out] ref CreateVirtualDiskParametersV2 Parameters,
                [In]          IntPtr Overlapped,
                [Out]     out SafeFileHandle Handle);

            [DllImport("advapi32", SetLastError = true)]
            public static extern bool InitializeSecurityDescriptor(
                [Out]     out SecurityDescriptor pSecurityDescriptor,
                [In]          uint dwRevision);


            public static void Create(string path, ulong size, bool dynamic, bool overwrite)
            {
                if(string.IsNullOrWhiteSpace(path))
                {
                    throw new ArgumentNullException("path");
                }

                // Validate size.  It needs to be a multiple of 512...  
                if ((size % 512) != 0)
                {
                    throw (
                        new ArgumentOutOfRangeException(
                            "size",
                            size,
                            "The size of the virtual disk must be a multiple of 512."));
                }

                bool isVhd = false;

                VirtualStorageType virtualStorageType = new VirtualStorageType();
                virtualStorageType.VendorId = VirtualStorageTypeVendorMicrosoft;

                if (Path.GetExtension(path) == ".vhdx")
                {
                    virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhdx;
                }
                else if (Path.GetExtension(path) == ".vhd")
                {
                    virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhd;

                    isVhd = true;
                }
                else
                {
                    throw new ArgumentException("The path should have either of the following two extensions: .vhd or .vhdx");
                }

                if ((overwrite) && (System.IO.File.Exists(path)))
                {
                    System.IO.File.Delete(path);
                }

                CreateVirtualDiskParametersV2 createParams = new CreateVirtualDiskParametersV2();
                createParams.Version = CreateVirtualDiskVersion.Version2;
                createParams.UniqueId = Guid.NewGuid();
                createParams.MaximumSize = size;
                createParams.BlockSizeInBytes = 0;
                createParams.SectorSizeInBytes = DEFAULT_SECTOR_SIZE;
                createParams.PhysicalSectorSizeInBytes = 0;
                createParams.ParentPath = null;
                createParams.SourcePath = null;
                createParams.OpenFlags = OpenVirtualDiskFlags.None;
                createParams.ParentVirtualStorageType = new VirtualStorageType();
                createParams.SourceVirtualStorageType = new VirtualStorageType();

                if(isVhd && dynamic)
                {
                    createParams.BlockSizeInBytes = DEFAULT_BLOCK_SIZE;
                }

                CreateVirtualDiskFlags flags;

                if (dynamic)
                {
                    flags = CreateVirtualDiskFlags.None;
                }
                else
                {
                    flags = CreateVirtualDiskFlags.FullPhysicalAllocation;
                }

                SecurityDescriptor securityDescriptor;

                if (!InitializeSecurityDescriptor(out securityDescriptor, 1))
                {
                    throw (
                        new SecurityException(
                            "Unable to initialize the security descriptor for the virtual disk."
                    ));
                }

                SafeFileHandle vhdHandle = null;

                try
                {
                    uint returnCode = CreateVirtualDisk(
                        ref virtualStorageType,
                            path,
                            VirtualDiskAccessMask.None,
                        ref securityDescriptor,
                            flags,
                            0,
                        ref createParams,
                            IntPtr.Zero,
                        out vhdHandle);

                    if (ERROR_SUCCESS != returnCode)
                    {
                        throw (new Win32Exception((int)returnCode));
                    }
                }
                finally
                {
                    if (vhdHandle != null && !vhdHandle.IsClosed)
                    {
                        vhdHandle.Close();
                        vhdHandle.SetHandleAsInvalid();
                    }
                }
            }
        }
    }
"@

############################################################################################################################

# Global settings for the script.

############################################################################################################################

$ErrorActionPreference = "Stop"

Set-StrictMode -Version 3.0

Import-Module -Name Storage -Force -Global -WarningAction SilentlyContinue
Import-Module Microsoft.PowerShell.Utility

############################################################################################################################

# Main script.

############################################################################################################################

Add-Type -TypeDefinition $NativeCode
Remove-Variable NativeCode

# Resolve $abc and ..\ from the File path.
$filepath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExecutionContext.InvokeCommand.ExpandString($filepath))

# Create the virtual disk drive.
try
{
    [SME.VirtualDisk]::Create($filepath, $size, $dynamic, $overwrite)
}
catch
{
    if($_.Exception.InnerException)
    {
        throw $_.Exception.InnerException
    }
    elseif($_.Exception)
    {
        throw $_.Exception
    }
    else
    {
        throw $_
    }
}

# Mount the virtual disk drive.
Mount-DiskImage -ImagePath $filepath 


}
## [END] New-WACSOStorageVHD ##
function New-WACSOStorageVolume {
<#

.SYNOPSIS
Creates a volume.

.DESCRIPTION
Creates a volume.

.ROLE
Administrators

.PARAMETER diskNumber
The disk number.

.PARAMETER driveLetter
The drive letter.

.PARAMETER sizeInBytes
The size in bytes.

.PARAMETER fileSystem
The file system.

.PARAMETER allocationUnitSizeInBytes
The allocation unit size.

.PARAMETER fileSystemLabel
The file system label.

.PARAMETER useMaxSize
True to use the maximum size.

#>
param (
    [parameter(Mandatory=$true)]
    [String]
    $diskNumber,
    [parameter(Mandatory=$true)]
    [Char]
    $driveLetter,
    [uint64]
    $sizeInBytes,
    [parameter(Mandatory=$true)]
    [string]
    $fileSystem,
    [parameter(Mandatory=$true)]
    [uint32]
    $allocationUnitSizeInBytes,
    [string]
    $fileSystemLabel,
    [boolean]
    $useMaxSize = $false
)

Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
Import-Module Storage

# This is a work around for getting rid of format dialog on the machine when format fails for reasons. Get rid of this code once we make changes on the UI to identify correct combinations.
$service = Get-WmiObject -Class Win32_Service -Filter "Name='ShellHWDetection'" -ErrorAction SilentlyContinue | out-null
if($service)
{
    $service.StopService();
}


if ($useMaxSize)
{
    $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -UseMaximumSize
}
else
{
    $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -Size $sizeInBytes
}

# Format only when partition is created
if ($p)
{
    try {
      Format-Volume -DriveLetter $driveLetter -FileSystem $fileSystem -NewFileSystemLabel "$fileSystemLabel" -AllocationUnitSize $allocationUnitSizeInBytes -confirm:$false
    } catch {
      Remove-Partition -DriveLetter $driveLetter -Confirm:$false
      throw
    }
}

if($service)
{
    $service.StartService();
}

$volume = Get-Volume -DriveLetter $driveLetter
if ($volume) {

  if ($volume.FileSystemLabel) {
      $volumeName = $volume.FileSystemLabel + " (" + $volume.DriveLetter + ":)"
  } else {
      $volumeName = "(" + $volume.DriveLetter + ":)"
  }

  return @{
      Name = $volumeName;
      HealthStatus = $volume.HealthStatus;
      DriveType = $volume.DriveType;
      DriveLetter = $volume.DriveLetter;
      FileSystem = $volume.FileSystem;
      FileSystemLabel = $volume.FileSystemLabel;
      Path = $volume.Path;
      Size = $volume.Size;
      SizeRemaining = $volume.SizeRemaining;
      }
}

}
## [END] New-WACSOStorageVolume ##
function Remove-WACSOStorageQuota {
<#

.SYNOPSIS
Remove Quota with the path.

.DESCRIPTION
Remove Quota with the path.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER path
    Path of the quota.
#> 
param
(
	# Path of the quota.
	[String]
	$path
)
Import-Module FileServerResourceManager

Remove-FsrmQuota -Path $path -Confirm:$false
}
## [END] Remove-WACSOStorageQuota ##
function Remove-WACSOStorageVolume {
<#

.SYNOPSIS
Remove a volume.

.DESCRIPTION
Remove a volume.

.ROLE
Administrators

.PARAMETER driveLetter
    The drive letter.
#> 
param (
    [Parameter(Mandatory = $true)]
    [String]
    $driveLetter
)
Import-Module Storage

Remove-Partition -DriveLetter $driveLetter -Confirm:$false


}
## [END] Remove-WACSOStorageVolume ##
function Resize-WACSOStorageVolume {
<#

.SYNOPSIS
Resizes the volume.

.DESCRIPTION
Resizes the volume.

.ROLE
Administrators

.PARAMETER driveLetter
	The drive letter.

.PARAMETER newSize
	The new size.
#> 
param (
	[Parameter(Mandatory = $true)]
	[String]
	$driveLetter,

	[UInt64]
	$newSize

)

Import-Module Storage

Resize-Partition -DriveLetter $driveLetter -Size $newSize
}
## [END] Resize-WACSOStorageVolume ##
function Set-WACSOStorageDiskOffline {
<#

.SYNOPSIS
Sets the disk offline.

.DESCRIPTION
Sets the disk offline.

.ROLE
Administrators

.PARAMETER diskNumber
	The disk number.

.PARAMETER isOffline
	True to set the disk offline.
#> 
param (
    [UInt32]
    $diskNumber,
    [Boolean]
    $isOffline = $true
)

Import-Module Storage

Set-Disk -Number $diskNumber -IsOffline $isOffline
}
## [END] Set-WACSOStorageDiskOffline ##
function Update-WACSOStorageQuota {
 <#

.SYNOPSIS
Update a new Quota for volume.

.DESCRIPTION
Update a new Quota for volume.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER disabledQuota
    Enable or disable quota.

.PARAMETER path
    Path of the quota.

.PARAMETER size
    The size of quota.

.PARAMETER softLimit
    Deny if usage exceeding quota limit.

#>

param
(
    # Enable or disable quota.
    [Parameter(Mandatory = $true)]
    [Boolean]
    $disabledQuota,

	# Path of the quota.
    [Parameter(Mandatory = $true)]
	[String]
	$path,

    # The size of quota.
    [Parameter(Mandatory = $true)]
    [String]
    $size,

    # Deny if usage exceeding quota limit.
    [Parameter(Mandatory = $true)]
    [Boolean]
    $softLimit
)
Import-Module FileServerResourceManager

$scriptArguments = @{
    Path = $path
    Disabled = $disabledQuota
    SoftLimit = $softLimit
}

if ($size) {
    $scriptArguments.Size = $size
}

Set-FsrmQuota @scriptArguments

}
## [END] Update-WACSOStorageQuota ##
function Add-WACSOFolderShare {
<#

.SYNOPSIS
Gets a new share name for the folder.

.DESCRIPTION
Gets a new share name for the folder. It starts with the folder name. Then it keeps appending "2" to the name
until the name is free. Finally return the name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder to be shared.

.PARAMETER Name
    String -- The suggested name to be shared (the folder name).

.PARAMETER Force
    boolean -- override any confirmations

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,    

    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

Set-StrictMode -Version 5.0

while([bool](Get-SMBShare -Name $Name -ea 0)){
    $Name = $Name + '2';
}

New-SmbShare -Name "$Name" -Path "$Path"
@{ shareName = $Name }

}
## [END] Add-WACSOFolderShare ##
function Add-WACSOFolderShareNameUser {
<#

.SYNOPSIS
Adds a user to the folder share.

.DESCRIPTION
Adds a user to the folder share.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Name
    String -- Name of the share.

.PARAMETER AccountName
    String -- The user identification (AD / Local user).

.PARAMETER AccessRight
    String -- Access rights of the user.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name,

    [Parameter(Mandatory = $true)]
    [String]
    $AccountName,

    [Parameter(Mandatory = $true)]
    [String]
    $AccessRight
)

Set-StrictMode -Version 5.0

Grant-SmbShareAccess -Name "$Name" -AccountName "$AccountName" -AccessRight "$AccessRight" -Force


}
## [END] Add-WACSOFolderShareNameUser ##
function Add-WACSOFolderShareUser {
<#

.SYNOPSIS
Adds a user access to the folder.

.DESCRIPTION
Adds a user access to the folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

If ($AccessControlType -eq 'Deny') {
    $FileSystemRights = 'FullControl'
    Remove-UserPermission $Path $Identity 'Allow'
} else {
    Remove-UserPermission $Path $Identity 'Deny'
}

$Acl = Get-Acl $Path
$AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', $AccessControlType)
$Acl.AddAccessRule($AccessRule)
Set-Acl $Path $Acl

}
## [END] Add-WACSOFolderShareUser ##
function Compress-WACSOArchiveFileSystemEntity {
<#

.SYNOPSIS
Compresses the specified file system entity (files, folders) of the system.

.DESCRIPTION
Compresses the specified file system entity (files, folders) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER pathSource
    String -- The path to compress.

.PARAMETER PathDestination
    String -- The destination path to compress into.

.PARAMETER Force
    boolean -- override any confirmations

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $PathSource,    

    [Parameter(Mandatory = $true)]
    [String]
    $PathDestination,

    [Parameter(Mandatory = $false)]
    [boolean]
    $Force
)

Set-StrictMode -Version 5.0

if ($Force) {
    Compress-Archive -Path $PathSource -Force -DestinationPath $PathDestination
} else {
    Compress-Archive -Path $PathSource -DestinationPath $PathDestination
}
if ($error) {
    $code = $error[0].Exception.HResult
    @{ status = "error"; code = $code; message = $error }
} else {
    @{ status = "ok"; }
}

}
## [END] Compress-WACSOArchiveFileSystemEntity ##
function Disable-WACSOKdcProxy {
<#
.SYNOPSIS
Disables kdc proxy on the server

.DESCRIPTION
Disables kdc proxy on the server

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $KdcPort
)

$urlLeft = "https://+:"
$urlRight = "/KdcProxy/"
$url = $urlLeft + $KdcPort + $urlRight
$deleteOutput = netsh http delete urlacl url=$url
if ($LASTEXITCODE -ne 0) {
    throw $deleteOutput
}
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth"
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth"
Stop-Service -Name kpssvc
Set-Service -Name kpssvc -StartupType Disabled
$firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
Remove-NetFirewallRule -DisplayName $firewallString -ErrorAction SilentlyContinue
}
## [END] Disable-WACSOKdcProxy ##
function Disable-WACSOSmbOverQuic {
<#

.SYNOPSIS
Disables smb over QUIC on the server.

.DESCRIPTION
Disables smb over QUIC on the server.

.ROLE
Administrators

#>

Set-SmbServerConfiguration -EnableSMBQUIC $false -Force
}
## [END] Disable-WACSOSmbOverQuic ##
function Edit-WACSOFolderShareInheritanceFlag {
<#

.SYNOPSIS
Modifies all users' IsInherited flag to false

.DESCRIPTION
Modifies all users' IsInherited flag to false
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Acl = Get-Acl $Path
$Acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $Path -AclObject $Acl

}
## [END] Edit-WACSOFolderShareInheritanceFlag ##
function Edit-WACSOFolderShareUser {
<#

.SYNOPSIS
Edits a user access to the folder.

.DESCRIPTION
Edits a user access to the folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

If ($AccessControlType -eq 'Deny') {
    $FileSystemRights = 'FullControl'
    Remove-UserPermission $Path $Identity 'Allow'
} else {
    Remove-UserPermission $Path $Identity 'Deny'
}

$Acl = Get-Acl $Path
$AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', $AccessControlType)
$Acl.SetAccessRule($AccessRule)
Set-Acl $Path $Acl




}
## [END] Edit-WACSOFolderShareUser ##
function Edit-WACSOSmbFileShare {
<#

.SYNOPSIS
Edits the smb file share details on the server.

.DESCRIPTION
Edits the smb file share details on the server.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $name,

    [Parameter(Mandatory = $false)]
    [String[]]
    $noAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $fullAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $changeAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $readAccess,
    
    [Parameter(Mandatory = $false)]
    [String[]]
    $unblockAccess,

    [Parameter(Mandatory = $false)]
    [Int]
    $cachingMode,

    [Parameter(Mandatory = $false)]
    [boolean]
    $encryptData,

    # TODO: 
    # [Parameter(Mandatory = $false)]
    # [Int]
    # $folderEnumerationMode

    [Parameter(Mandatory = $false)]
    [boolean]
    $compressData,

    [Parameter(Mandatory = $false)]
    [boolean]
    $isCompressDataEnabled
)

if($fullAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $fullAccess -AccessRight Full -SmbInstance Default -Force
}
if($changeAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $changeAccess -AccessRight Change -SmbInstance Default -Force
}
if($readAccess.count -gt 0){
    Grant-SmbShareAccess -Name "$name" -AccountName $readAccess -AccessRight Read -SmbInstance Default -Force
}
if($noAccess.count -gt 0){
    Revoke-SmbShareAccess -Name "$name" -AccountName $noAccess -SmbInstance Default  -Force
    Block-SmbShareAccess -Name "$name" -AccountName $noAccess -SmbInstance Default -Force
}
if($unblockAccess.count -gt 0){
    Unblock-SmbShareAccess -Name "$name" -AccountName $unblockAccess -SmbInstance Default  -Force
}
if($isCompressDataEnabled){
    Set-SmbShare -Name "$name" -CompressData $compressData -Force
}

Set-SmbShare -Name "$name" -CachingMode "$cachingMode" -EncryptData  $encryptData -Force




}
## [END] Edit-WACSOSmbFileShare ##
function Edit-WACSOSmbServerCertificateMapping {
<#
.SYNOPSIS
Edit SMB Server Certificate Mapping

.DESCRIPTION
Edits smb over QUIC certificate.

.ROLE
Administrators

.PARAMETER IsWS2025
    Boolean -- Specifies whether the Windows Server version is 2025. This is not a mandatory parameter.

.PARAMETER CurrentServerDnsNames
    String[] -- Specifies the current DNS names of the server. This is not a mandatory parameter.

.PARAMETER thumbprint
    String -- The thumbprint of the certificate selected.

.PARAMETER newSelectedDnsNames
    String[] -- The addresses newly added to the certificate mapping.

.PARAMETER unSelectedDnsNames
    String[] -- To addresses to be removed from the certificate mapping.

.PARAMETER IsKdcProxyEnabled
    Boolean -- Specifies whether the KDC proxy is enabled. This is a mandatory parameter.

.PARAMETER KdcProxyOptionSelected
    String -- Specifies the selected KDC proxy option. This is a mandatory parameter.

.PARAMETER IsKdcProxyMappedForSmbOverQuic
    Boolean -- Specifies whether the KDC proxy is mapped for SMB over QUIC. This is a mandatory parameter.

.PARAMETER KdcPort
    String -- Specifies the KDC port. This is not a mandatory parameter.

.PARAMETER CurrentkdcPort
    String -- Specifies the current KDC port. This is not a mandatory parameter.

.PARAMETER IsSameCertificate
    Boolean -- Specifies whether the certificate is the same. This is not a mandatory parameter.

.PARAMETER RequireClientAuthentication
    Boolean -- Specifies whether client authentication is required. This is not a mandatory parameter.

.PARAMETER ClientAuthIdentifierType
    String -- Specifies the type of client authentication identifier. This is not a mandatory parameter.

.PARAMETER AddedClientAccessTrustedSignatures
    String[] -- Specifies the added trusted signatures for client access. This is not a mandatory parameter.

.PARAMETER AddedClientAccessTrustedIssuers
    String[] -- Specifies the added trusted issuers for client access. This is not a mandatory parameter.

.PARAMETER DeletedClientAccessTrustedSignatures
    String[] -- Specifies the deleted trusted signatures for client access. This is not a mandatory parameter.

.PARAMETER DeletedClientAccessTrustedIssuers
    String[] -- Specifies the deleted trusted issuers for client access. This is not a mandatory parameter.
#>

param (
  [Parameter(Mandatory = $false)]
  [boolean]
  $IsWS2025,

  [Parameter(Mandatory = $false)]
  [String[]]
  $CurrentServerDnsNames,

  [Parameter(Mandatory = $true)]
  [String]
  $Thumbprint,

  [Parameter(Mandatory = $false)]
  [String[]]
  $NewSelectedDnsNames,

  [Parameter(Mandatory = $false)]
  [String[]]
  $UnSelectedDnsNames,

  [Parameter(Mandatory = $true)]
  [boolean]
  $IsKdcProxyEnabled,

  [Parameter(Mandatory = $true)]
  [String]
  $KdcProxyOptionSelected,

  [Parameter(Mandatory = $true)]
  [boolean]
  $IsKdcProxyMappedForSmbOverQuic,

  [Parameter(Mandatory = $false)]
  [String]
  $KdcPort,

  [Parameter(Mandatory = $false)]
  [String]
  $CurrentkdcPort,

  [Parameter(Mandatory = $false)]
  [boolean]
  $IsSameCertificate,

  [Parameter(Mandatory = $false)]
  [boolean]
  $RequireClientAuthentication,

  [Parameter(Mandatory = $false)]
  [String]
  $ClientAuthIdentifierType,

  [Parameter(Mandatory = $false)]
  [String[]]
  $AddedClientAccessTrustedSignatures,

  [Parameter(Mandatory = $false)]
  [String[]]
  $AddedClientAccessTrustedIssuers,

  [Parameter(Mandatory = $false)]
  [String[]]
  $DeletedClientAccessTrustedSignatures,

  [Parameter(Mandatory = $false)]
  [String[]]
  $DeletedClientAccessTrustedIssuers)

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeScripts-ConfigureKdcProxy" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message $logMessage -ErrorAction SilentlyContinue
}

Set-Location Cert:\LocalMachine\My

$port = "0.0.0.0:"
$urlLeft = "https://+:"
$urlRight = "/KdcProxy"

function Modify-CAAC([string]$dnsName) {
  if(!$RequireClientAuthentication) {
    return;
  }
  else {
    if ($ClientAuthIdentifierType -eq 'SHA256') {
      if ($AddedClientAccessTrustedSignatures.count -gt 0) {
        foreach ($addedClientAccessTrustedSignature in $AddedClientAccessTrustedSignatures) {
          Grant-SmbClientAccessToServer -Name $dnsName -IdentifierType $ClientAuthIdentifierType -Identifier $addedClientAccessTrustedSignature -Force
        }
      } else {
        if ($DeletedClientAccessTrustedSignatures.count -gt 0) {
          foreach ($deletedClientAccessTrustedSignature in $DeletedClientAccessTrustedSignatures) {
            Revoke-SmbClientAccessToServer -Name $dnsName -IdentifierType $ClientAuthIdentifierType -Identifier $deletedClientAccessTrustedSignature -Force
          }
        }
      }
    } else {
      if ($ClientAuthIdentifierType -eq 'ISSUER') {
        if ($AddedClientAccessTrustedIssuers.count -gt 0) {
          foreach ($addedClientAccessTrustedIssuer in $AddedClientAccessTrustedIssuers) {
            Grant-SmbClientAccessToServer -Name $dnsName -IdentifierType $ClientAuthIdentifierType -Identifier $addedClientAccessTrustedIssuer -Force
          }
        } else {
          if($DeletedClientAccessTrustedIssuers.count -gt 0) {
            foreach($deletedClientAccessTrustedIssuer in $DeletedClientAccessTrustedIssuers) {
              Revoke-SmbClientAccessToServer -Name $dnsName -IdentifierType $ClientAuthIdentifierType -Identifier $deletedClientAccessTrustedIssuer -Force
            }
          }
        }
      }
    }
  }
}

if ($IsSameCertificate -and $UnSelectedDnsNames.count -gt 0) {
  foreach ($unSelectedDnsName in $UnSelectedDnsNames) {
    Remove-SmbServerCertificateMapping -Name $unSelectedDnsName -Force
  }
}

if (!$IsSameCertificate) {
  foreach ($currentServerDnsName in $CurrentServerDnsNames) {
    Remove-SmbServerCertificateMapping -Name $currentServerDnsName -Force
  }
}

if ($IsSameCertificate -and $IsWS2025) {
  foreach ($currentServerDnsName in $CurrentServerDnsNames) {
    Modify-CAAC $currentServerDnsName
  }
}

if ($NewSelectedDnsNames.count -gt 0) {
  foreach ($newSelectedDnsName in $NewSelectedDnsNames) {
    if ($IsWS2025) {
      New-SmbServerCertificateMapping -Name $newSelectedDnsName -Thumbprint $Thumbprint -StoreName My -requireClientAuthentication $RequireClientAuthentication -Force
      Modify-CAAC $newSelectedDnsName
    }
    else {
      New-SmbServerCertificateMapping -Name $newSelectedDnsName -Thumbprint $Thumbprint -StoreName My -Force
    }
  }
}

function Delete-KdcSSLCert([string]$deletePort) {
  $ipport = $port + $deletePort
  $deleteCertKdc = netsh http delete sslcert ipport=$ipport
  if ($LASTEXITCODE -ne 0) {
    throw $deleteCertKdc
  }
  $message = 'Completed deleting ssl certificate port'
  writeInfoLog $message
  return;
}

function Enable-KdcProxy {

  $ipport = $port + $KdcPort
  $ComputerName = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain
  try {
    if (!$IsSameCertificate -or ($KdcPort -ne $CurrentkdcPort) -or (!$IsKdcProxyMappedForSmbOverQuic) ) {
      $guid = [Guid]::NewGuid()
      $netshAddCertBinding = netsh http add sslcert ipport=$ipport certhash=$Thumbprint certstorename="my" appid="{$guid}"
      if ($LASTEXITCODE -ne 0) {
        throw $netshAddCertBinding
      }
      $message = 'Completed adding ssl certificate port'
      writeInfoLog $message
    }
    if ($NewSelectedDnsNames.count -gt 0) {
      foreach ($newSelectedDnsName in $NewSelectedDnsNames) {
        if ($ComputerName.trim() -ne $newSelectedDnsName.trim()) {
          $output = Echo 'Y' | netdom computername $ComputerName /add $newSelectedDnsName
          if ($LASTEXITCODE -ne 0) {
            throw $output
          }
        }
        $message = 'Completed adding alternate names for the computer'
        writeInfoLog $message
      }
    }
    if (!$IsKdcProxyEnabled) {
      $url = $urlLeft + $KdcPort + $urlRight
      $netshOutput = netsh http add urlacl url=$url user="NT authority\Network Service"
      if ($LASTEXITCODE -ne 0) {
        throw $netshOutput
      }
      $message = 'Completed adding urlacl'
      writeInfoLog $message
      New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -force
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -Value 0x0 -type DWORD
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -Value 0x0 -type DWORD
      Set-Service -Name kpssvc -StartupType Automatic
      Start-Service -Name kpssvc
    }
    $message = 'Returning from call Enable-KdcProxy'
    writeInfoLog $message
    return $true;
  }
  catch {
    throw $_
  }
}

if ($IsKdcProxyEnabled -and $KdcProxyOptionSelected -eq "enabled" -and ($KdcPort -ne $CurrentkdcPort)) {
  $url = $urlLeft + $CurrentkdcPort + $urlRight
  $deleteOutput = netsh http delete urlacl url=$url
  if ($LASTEXITCODE -ne 0) {
    throw $deleteOutput
  }
  $message = 'Completed deleting urlacl'
  writeInfoLog $message
  $newUrl = $urlLeft + $KdcPort + $urlRight
  $netshOutput = netsh http add urlacl url=$newUrl user="NT authority\Network Service"
  if ($LASTEXITCODE -ne 0) {
    throw $netshOutput
  }
  $message = 'Completed adding urlacl'
  writeInfoLog $message
}

if ($KdcProxyOptionSelected -eq "enabled" -and $KdcPort -ne $null) {
  if ($IsKdcProxyMappedForSmbOverQuic -and (!$IsSameCertificate -or ($KdcPort -ne $CurrentkdcPort))) {
    Delete-KdcSSLCert $CurrentkdcPort
  }
  $result = Enable-KdcProxy
  if ($result) {
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    $firewallDesc = "The KDC Proxy Server service runs on edge servers to proxy Kerberos protocol messages to domain controllers on the corporate network. Default port is TCP/443."
    New-NetFirewallRule -DisplayName $firewallString -Description $firewallDesc -Protocol TCP -LocalPort $KdcPort -Direction Inbound -Action Allow
  }
}

if ($IsKdcProxyMappedForSmbOverQuic -and $KdcProxyOptionSelected -ne "enabled" ) {
  Delete-KdcSSLCert $CurrentKdcPort
  $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
  Remove-NetFirewallRule -DisplayName $firewallString
}



}
## [END] Edit-WACSOSmbServerCertificateMapping ##
function Enable-WACSOSmbOverQuic {
<#

.SYNOPSIS
Disables smb over QUIC on the server.

.DESCRIPTION
Disables smb over QUIC on the server.

.ROLE
Administrators

#>

Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
}
## [END] Enable-WACSOSmbOverQuic ##
function Expand-WACSOArchiveFileSystemEntity {
<#
.SYNOPSIS
Expands the specified file system entity (files, folders) of the system.

.DESCRIPTION
Expands the specified file system entity (files, folders) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER PathSource
  String -- The path to expand.

.PARAMETER PathDestination
  String -- The destination path to expand into.

.PARAMETER Force
  boolean -- override any confirmations
#>

param (
    [Parameter(Mandatory = $true)]
    [String] $PathSource,

    [Parameter(Mandatory = $true)]
    [String] $PathDestination,

    [Parameter(Mandatory = $false)]
    [boolean] $Force
)

Set-StrictMode -Version 5.0

try {
    # Expand the archive
    if ($Force) {
        Expand-Archive -Path $PathSource -Force -DestinationPath $PathDestination
    } else {
        Expand-Archive -Path $PathSource -DestinationPath $PathDestination
    }

    # Check if source zip has Zone.Identifier (Mark of the Web)
    $motw = $null
    if (Get-Item -Path $PathSource -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
        try {
            $motw = Get-Content -Path $PathSource -Stream Zone.Identifier -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to read Zone.Identifier from ${PathSource}: $($_.Exception.Message)"
        }
    } else {
        Write-Verbose "No Zone.Identifier stream found on source zip."
    }

    # If we found a MoTW stream, propagate it to extracted files
    if ($motw -and $motw.Length -gt 0) {
        Write-Verbose "Propagating Zone.Identifier stream to extracted files..."
        $motwText = $motw -join "`r`n"

        $extensions = @(
          ".md", ".appref-ms", ".appx", ".appxbundle", ".bat", ".chm", ".cmd", ".com",
          ".cpl", ".dll", ".drv", ".gadget", ".hta", ".iso", ".js", ".jse", ".lnk",
          ".msc", ".msp", ".ocx", ".pif", ".ppkg", ".printerexport", ".ps1", ".rdp",
          ".reg", ".scf", ".scr", ".settingcontent-ms", ".sys", ".url", ".vb", ".vbe",
          ".vbs", ".vhd", ".vhdx", ".vxd", ".wcx", ".website", ".wsf", ".wsh"
        )

        Get-ChildItem -Path $PathDestination -Recurse | Where-Object { -not $_.PSIsContainer -and $extensions -contains $_.Extension } | ForEach-Object {
            try {
                Set-Content -Path $_.FullName -Stream Zone.Identifier -Value $motwText -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to set MoTW on $($_.FullName): $($_.Exception.Message)"
            }
        }
    }

    @{ status = "ok" }
} catch {
    $code = $_.Exception.HResult
    @{ status = "error"; code = $code; message = $_.Exception.Message }
}

}
## [END] Expand-WACSOArchiveFileSystemEntity ##
function Get-WACSOBestHostNode {
<#

.SYNOPSIS
Returns the list of available cluster node names, and the best node name to host a new virtual machine.

.DESCRIPTION
Use the cluster CIM provider (MSCluster) to ask the cluster which node is the best to host a new virtual machine.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue


<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name clusterCimNameSpace -Option ReadOnly -Value "root/MSCluster" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-BestHostNode.ps1" -Scope Script
    Set-Variable -Name BestNodePropertyName -Option ReadOnly -Value "BestNode" -Scope Script
    Set-Variable -Name StateUp -Option ReadOnly -Value "0" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name clusterCimNameSpace -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name BestNodePropertyName -Scope Script -Force
    Remove-Variable -Name StateUp -Scope Script -Force
}

<#

.SYNOPSIS
Get the fully qualified domain name for the passed in server name from DNS.

.DESCRIPTION
Get the fully qualified domain name for the passed in server name from DNS.

#>

function GetServerFqdn([string]$netBIOSName) {
    try {
        $fqdn = [System.Net.DNS]::GetHostByName($netBIOSName).HostName

        return $fqdn.ToLower()
    } catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: There was an error looking up the FQDN for server $netBIOSName.  Error: $errMessage"  -ErrorAction SilentlyContinue

        return $netBIOSName
    }
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletsAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
is the cluster CIM (WMI) provider installed on this server?

.DESCRIPTION
Returns true when the cluster CIM provider is installed on this server.

#>

function isClusterCimProviderAvailable() {
    $namespace = Get-CimInstance -Namespace $clusterCimNamespace -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    return !!$namespace
}

<#

.SYNOPSIS
Get the MSCluster Cluster Service CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster Service CIM instance from this server.

#>

function getClusterServiceCimInstance() {
    return Get-CimInstance -Namespace $clusterCimNamespace MSCluster_ClusterService -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using PowerShell.

#>

function getAllUpClusterNodeNames() {
    # Constants
    Set-Variable -Name stateUp -Option Readonly -Value "up" -Scope Local

    try {
        return Get-ClusterNode | Where-Object { $_.State -eq $stateUp } | ForEach-Object { (GetServerFqdn $_.Name) }
    } finally {
        Remove-Variable -Name stateUp -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the list of the cluster nodes that are running.

.DESCRIPTION
Returns a list of cluster node names that are running using CIM.

#>

function getAllUpClusterCimNodeNames() {
##SkipCheck=true##
    $query = "select name, state from MSCluster_Node Where state = '{0}'" -f $StateUp
##SkipCheck=false##
    return Get-CimInstance -Namespace $clusterCimNamespace -Query $query | ForEach-Object { (GetServerFqdn $_.Name) }
}

<#

.SYNOPSIS
Create a new instance of the "results" PS object.

.DESCRIPTION
Create a new PS object and set the passed in nodeNames to the appropriate property.

#>

function newResult([string []] $nodeNames) {
    $result = new-object PSObject
    $result | Add-Member -Type NoteProperty -Name Nodes -Value $nodeNames

    return $result;
}

<#

.SYNOPSIS
Remove any old lingering reservation for our typical VM.

.DESCRIPTION
Remove the reservation from the passed in id.

#>

function removeReservation($clusterService, [string] $rsvId) {
    Set-Variable removeReservationMethodName -Option Constant -Value "RemoveVmReservation"

    Invoke-CimMethod -CimInstance $clusterService -MethodName $removeReservationMethodName -Arguments @{ReservationId = $rsvId} -ErrorVariable +err | Out-Null
}

<#

.SYNOPSIS
Create a reservation for our typical VM.

.DESCRIPTION
Create a reservation for the passed in id.

#>

function createReservation($clusterService, [string] $rsvId) {
    Set-Variable -Name createReservationMethodName -Option ReadOnly -Value "CreateVmReservation" -Scope Local
    Set-Variable -Name reserveSettings -Option ReadOnly -Value @{VmMemory = 2048; VmVirtualCoreCount = 2; VmCpuReservation = 0; VmFlags = 0; TimeSpan = 2000; ReservationId = $rsvId; LocalDiskSize = 0; Version = 0} -Scope Local

    try {
        $vmReserve = Invoke-CimMethod -CimInstance $clusterService -MethodName $createReservationMethodName -ErrorAction SilentlyContinue -ErrorVariable va -Arguments $reserveSettings

        if (!!$vmReserve -and $vmReserve.ReturnValue -eq 0 -and !!$vmReserve.NodeId) {
            return $vmReserve.NodeId
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not create a reservation for a virtual machine. Output from $createReservationMethodName is $vmReserve"  -ErrorAction SilentlyContinue

        return $null
    } finally {
        Remove-Variable -Name createReservationMethodName -Scope Local -Force
        Remove-Variable -Name reserveSettings -Scope Local -Force
    }
}

<#

.SYNOPSIS
Use the Cluster CIM provider to find the best host name for a typical VM.

.DESCRIPTION
Returns the best host node name, or null when none are found.

#>

function askClusterServiceForBestHostNode() {
    # API parameters
    Set-Variable -Name rsvId -Option ReadOnly -Value "TempVmId1" -Scope Local

    try {
        # If the class exist, using api to get optimal host
        $clusterService = getClusterServiceCimInstance
        if (!!$clusterService) {
            $nodeNames = @(getAllUpClusterCimNodeNames)
            $result = newResult $nodeNames

            # remove old reserveration if there is any
            removeReservation $clusterService $rsvId

            $id = createReservation $clusterService $rsvId

            if (!!$id) {
    ##SkipCheck=true##
                $query = "select name, id from MSCluster_Node where id = '{0}'" -f $id
    ##SkipCheck=false##
                $bestNode = Get-CimInstance -Namespace $clusterCimNamespace -Query $query -ErrorAction SilentlyContinue

                if ($bestNode) {
                    $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNode.Name)

                    return $result
                }
            }
        }

        return $null
    } finally {
        Remove-Variable -Name rsvId -Scope Local -Force
    }
}

<#

.SYNOPSIS
Get the name of the cluster node that has the least number of VMs running on it.

.DESCRIPTION
Return the name of the cluster node that has the least number of VMs running on it.

#>

function getLeastLoadedNode() {
    # Constants
    Set-Variable -Name vmResourceTypeName -Option ReadOnly -Value "Virtual Machine" -Scope Local
    Set-Variable -Name OwnerNodePropertyName -Option ReadOnly -Value "OwnerNode" -Scope Local

    try {
        $nodeNames = @(getAllUpClusterNodeNames)
        $bestNodeName = $null;

        $result = newResult $nodeNames

        $virtualMachinesPerNode = @{}

        # initial counts as 0
        $nodeNames | ForEach-Object { $virtualMachinesPerNode[$_] = 0 }

        $ownerNodes = Get-ClusterResource | Where-Object { $_.ResourceType -eq $vmResourceTypeName } | Microsoft.PowerShell.Utility\Select-Object $OwnerNodePropertyName
        $ownerNodes | ForEach-Object { $virtualMachinesPerNode[$_.OwnerNode.Name]++ }

        # find node with minimum count
        $bestNodeName = $nodeNames[0]
        $min = $virtualMachinesPerNode[$bestNodeName]

        $nodeNames | ForEach-Object {
            if ($virtualMachinesPerNode[$_] -lt $min) {
                $bestNodeName = $_
                $min = $virtualMachinesPerNode[$_]
            }
        }

        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value (GetServerFqdn $bestNodeName)

        return $result
    } finally {
        Remove-Variable -Name vmResourceTypeName -Scope Local -Force
        Remove-Variable -Name OwnerNodePropertyName -Scope Local -Force
    }
}

<#

.SYNOPSIS
Main

.DESCRIPTION
Use the various mechanism available to determine the best host node.

#>

function main() {
    if (isClusterCimProviderAvailable) {
        $bestNode = askClusterServiceForBestHostNode
        if (!!$bestNode) {
            return $bestNode
        }
    }

    if (getIsClusterCmdletsAvailable) {
        return getLeastLoadedNode
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

        Write-Warning $strings.FailoverClustersModuleRequired
    }

    return $null
}

###############################################################################
# Script execution begins here.
###############################################################################

if (-not ($env:pester)) {
    setupScriptEnv

    try {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        $result = main
        if (!!$result) {
            return $result
        }

        # If neither cluster CIM provider or PowerShell cmdlets are available then simply
        # return this computer's name as the best host node...
        $nodeName = GetServerFqdn $env:COMPUTERNAME

        $result = newResult @($nodeName)
        $result | Add-Member -Type NoteProperty -Name $BestNodePropertyName -Value $nodeName

        return $result
    } finally {
        cleanupScriptEnv
    }
}

}
## [END] Get-WACSOBestHostNode ##
function Get-WACSOCertificates {
<#

.SYNOPSIS
Get the certificates stored in my\store

.DESCRIPTION
Get the certificates stored in my\store

.ROLE
Readers

#>

$nearlyExpiredThresholdInDays = 60

$dnsNameList = @{}

<#
.Synopsis
    Name: Compute-ExpirationStatus
    Description: Computes expiration status based on notAfter date.
.Parameters
    $notAfter: A date object refering to certificate expiry date.

.Returns
    Enum values "Expired", "NearlyExpired" and "Healthy"
#>
function Compute-ExpirationStatus {
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$notAfter
    )

    if ([DateTime]::Now -gt $notAfter) {
        $expirationStatus = "Expired"
    }
    else {
        $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);

        if ($nearlyExpired -ge $notAfter) {
            $expirationStatus = "NearlyExpired"
        }
        else {
            $expirationStatus = "Healthy"
        }
    }

    $expirationStatus
}

<# main - script starts here #>

Set-Location Cert:\LocalMachine\My

$certificates = Get-ChildItem -Recurse | Microsoft.PowerShell.Utility\Select-Object Subject, FriendlyName, NotBefore, NotAfter,
 Thumbprint, Issuer, @{n="DnsNameList";e={$_.DnsNameList}}, @{n="SignatureAlgorithm";e={$_.SignatureAlgorithm.FriendlyName}} |
ForEach-Object {
    return @{
        CertificateName = $_.Subject;
        FriendlyName = $_.FriendlyName;
        NotBefore = $_.NotBefore;
        NotAfter = $_.NotAfter;
        Thumbprint = $_.Thumbprint;
        Issuer = $_.Issuer;
        DnsNameList = $_.DnsNameList;
        Status = $(Compute-ExpirationStatus $_.NotAfter);
        SignatureAlgorithm  = $_.SignatureAlgorithm;
    }
}

return $certificates;

}
## [END] Get-WACSOCertificates ##
function Get-WACSOComputerName {
<#

.SYNOPSIS
Gets the computer name.

.DESCRIPTION
Gets the compuiter name.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$ComputerName = $env:COMPUTERNAME
@{ computerName = $ComputerName }

}
## [END] Get-WACSOComputerName ##
function Get-WACSOFileNamesInPath {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFolders
    switch -- 

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $false)]
    [switch]
    $OnlyFolders
)

Set-StrictMode -Version 5.0

function isFolder($item) {
    return $item.Attributes -match "Directory"
}

function getName($item) {
    $slash = '';

    if (isFolder $item) {
        $slash = '\';
    }

    return "$($_.Name)$slash"
}

if ($onlyFolders) {
    return (Get-ChildItem -Path $Path | Where-Object {isFolder $_}) | ForEach-Object { return "$($_.Name)\"} | Sort-Object
}

return (Get-ChildItem -Path $Path) | ForEach-Object { return getName($_)} | Sort-Object

}
## [END] Get-WACSOFileNamesInPath ##
function Get-WACSOFileSystemEntities {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFiles
    switch --

.PARAMETER OnlyFolders
    switch --

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $false)]
    [Switch]
    $OnlyFiles,

    [Parameter(Mandatory = $false)]
    [Switch]
    $OnlyFolders
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntities
    Description: Gets all the local file system entities of the machine.

.Parameter Path
    String -- The path to enumerate.

.Returns
    The local file system entities.
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    $folderShares = Get-CimInstance -Class Win32_Share;

    if ($Path -match '\[' -or $Path -match '\]') {
        return Get-ChildItem -LiteralPath $Path -Force |
        Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
        @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
        Extension,
        @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
        @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
        Name,
        @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
        @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
        @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
    }


    return Get-ChildItem -Path $Path -Force |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
    @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
    Extension,
    @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
    @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
    Name,
    @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
    @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
    @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
}

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameter Attributes
    The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType {
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory") {
        return "Folder";
    }
    else {
        return "File";
    }
}

$entities = Get-FileSystemEntities -Path $Path;
if ($OnlyFiles -and $OnlyFolders) {
    return $entities;
}

if ($OnlyFiles) {
    return $entities | Where-Object { $_.Type -eq "File" };
}

if ($OnlyFolders) {
    return $entities | Where-Object { $_.Type -eq "Folder" };
}

return $entities;

}
## [END] Get-WACSOFileSystemEntities ##
function Get-WACSOFileSystemRoot {
<#

.SYNOPSIS
Enumerates the root of the file system (volumes and related entities) of the system.

.DESCRIPTION
Enumerates the root of the file system (volumes and related entities) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
import-module CimCmdlets

<#
.Synopsis
    Name: Get-FileSystemRoot
    Description: Gets the local file system root entities of the machine.

.Returns
    The local file system root entities.
#>
function Get-FileSystemRoot
{
    $volumes = Enumerate-Volumes;

    return $volumes |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.DriveLetter +":\"}},
                      @{Name="CreationDate"; Expression={$null}},
                      @{Name="Extension"; Expression={$null}},
                      @{Name="IsHidden"; Expression={$false}},
                      @{Name="Name"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
                      @{Name="Type"; Expression={"Volume"}},
                      @{Name="LastModifiedDate"; Expression={$null}},
                      @{Name="Size"; Expression={$_.Size}},
                      @{Name="SizeRemaining"; Expression={$_.SizeRemaining}}
}

<#
.Synopsis
    Name: Get-Volumes
    Description: Gets the local volumes of the machine.

.Returns
    The local volumes.
#>
function Enumerate-Volumes
{
    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace root/Microsoft/Windows/Storage | Where-Object { !$_.IsClustered };
        $partitions = @($disks | Get-CimAssociatedInstance -ResultClassName MSFT_Partition)
        if ($partitions.Length -eq 0) {
            $volumes = Get-CimInstance -ClassName MSFT_Volume -Namespace root/Microsoft/Windows/Storage;
        } else {
            $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
        }
    }
    else
    {
        $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "*Win*" };
        $volumes = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
    }

    return $volumes | Where-Object {
        try {
            [byte]$_.DriveLetter -ne 0 -and $_.DriveLetter -ne $null -and $_.Size -gt 0
        } catch {
            $false
        }
    };
}

Get-FileSystemRoot;

}
## [END] Get-WACSOFileSystemRoot ##
function Get-WACSOFolderItemCount {
<#

.SYNOPSIS
Gets the count of elements in the folder

.DESCRIPTION
Gets the count of elements in the folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$directoryInfo = Get-ChildItem $Path | Microsoft.PowerShell.Utility\Measure-Object
$directoryInfo.count

}
## [END] Get-WACSOFolderItemCount ##
function Get-WACSOFolderOwner {
<#

.SYNOPSIS
Gets the owner of a folder.

.DESCRIPTION
Gets the owner of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Owner = (Get-Acl $Path).Owner
@{ owner = $Owner; }

}
## [END] Get-WACSOFolderOwner ##
function Get-WACSOFolderShareNames {
<#

.SYNOPSIS
Gets the existing share names of a shared folder

.DESCRIPTION
Gets the existing share names of a shared folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Get-CimInstance -Class Win32_Share -Filter Path="'$Path'" | Microsoft.PowerShell.Utility\Select-Object Name

}
## [END] Get-WACSOFolderShareNames ##
function Get-WACSOFolderSharePath {
<#

.SYNOPSIS
Gets the existing share names of a shared folder

.DESCRIPTION
Gets the existing share names of a shared folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Name
    String -- The share name to the shared folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

Set-StrictMode -Version 5.0

Get-SmbShare -Includehidden | Where-Object { $_.Name -eq $Name } | Microsoft.PowerShell.Utility\Select-Object Path

}
## [END] Get-WACSOFolderSharePath ##
function Get-WACSOFolderShareStatus {
<#

.SYNOPSIS
Checks if a folder is shared

.DESCRIPTION
Checks if a folder is shared
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

$Shared = [bool](Get-CimInstance -Class Win32_Share -Filter Path="'$Path'")
@{ isShared = $Shared }

}
## [END] Get-WACSOFolderShareStatus ##
function Get-WACSOFolderShareUsers {
<#

.SYNOPSIS
Gets the user access rights of a folder

.DESCRIPTION
Gets the user access rights of a folder
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Get-Acl $Path |  Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Access | Microsoft.PowerShell.Utility\Select-Object IdentityReference, FileSystemRights, AccessControlType

}
## [END] Get-WACSOFolderShareUsers ##
function Get-WACSOIsAzureTurbineServer {
<#
.SYNOPSIS
Checks if the current server is Azure Turbine edition.

.DESCRIPTION
Returns true if the current server is Azure Turbine which supports smb over QUIC.

.ROLE
Readers

#>

Set-Variable -Name Server21H2SkuNumber -Value 407 -Scope Script
Set-Variable -Name Server21H2VersionNumber -Value 10.0.20348 -Scope Script
Set-Variable -Name WS2025VersionNumber -Value 10.0.25398 -Scope Script
Set-Variable -Name Server2012R2VersionNumber -Value 6.3 -Scope Script

$result = Get-WmiObject -Class Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object OperatingSystemSKU, Version
$isAzureTurbineServer = $result.OperatingSystemSKU -eq $Server21H2SkuNumber -and [version]$result.version -ge [version]$Server21H2VersionNumber
$isWS2025 = [version]$result.version -ge [version]$WS2025VersionNumber

$version = [System.Environment]::OSVersion.Version
$ver = $version.major.toString() + "." + $version.minor.toString()
$isWS2012R2orGreater = [version]$ver -ge [version]$Server2012R2VersionNumber

return @{ isAzureTurbineServer = $isAzureTurbineServer;
  isWS2012R2orGreater =  $isWS2012R2orGreater
  isWS2025 = $isWS2025 }

}
## [END] Get-WACSOIsAzureTurbineServer ##
function Get-WACSOItemProperties {
<#

.SYNOPSIS
Get item's properties.

.DESCRIPTION
Get item's properties on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the item whose properites are requested.

.PARAMETER ItemType
    String -- What kind of item?

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $ItemType
)

Set-StrictMode -Version 5.0

switch ($ItemType) {
    0 {
        Get-Volume $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
    }
    default {
        Get-ItemProperty -Path $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
    }
}

}
## [END] Get-WACSOItemProperties ##
function Get-WACSOItemType {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- the path to the folder where enumeration should start.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameter Attributes
    The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType
{
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory")
    {
        return "Folder";
    }
    else
    {
        return "File";
    }
}

if (Test-Path -LiteralPath $Path) {
    return Get-FileSystemEntityType -Attributes (Get-Item $Path -Force).Attributes
} else {
    return ''
}

}
## [END] Get-WACSOItemType ##
function Get-WACSOLocalGroups {
<#

.SYNOPSIS
Gets the local groups.

.DESCRIPTION
Gets the local groups. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel

    if ($isWinServer2016OrNewer)
    {
       return  Get-LocalGroup | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name
                                
    }
    else
    {
       return  Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name
    }


}
## [END] Get-WACSOLocalGroups ##
function Get-WACSOLocalUsers {
<#

.SYNOPSIS
Gets the local users.

.DESCRIPTION
Gets the local users. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>


$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;

if ($isWinServer2016OrNewer){

	return Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Name

}
else{
    return Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object  Name;
}
}
## [END] Get-WACSOLocalUsers ##
function Get-WACSOOSDetails {
<#

.SYNOPSIS
Get OS details

.DESCRIPTION
i) Get OS Version to determine if compression is supported on the server.
ii) Returns translated name of SID - S-1-5-32-544 "BUILTIN\Administrators" on the system. This name can differ on OS's with languages that are not English.

.ROLE
Readers

#>

$result = Get-WmiObject -Class Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object Version

$isOSVersionCompatibleForCompression =[version]$result.version -ge [version]"10.0.20348"

# Get translated SID
$SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$name = $SID.Translate([System.Security.Principal.NTAccount])
$translatedSidName = $name.value;

return @{
  isOSVersionCompatibleForCompression = $isOSVersionCompatibleForCompression;
  translatedSidName = $translatedSidName;
}


}
## [END] Get-WACSOOSDetails ##
function Get-WACSOShareEntities {
<#

.SYNOPSIS
Enumerates all of the file system entities (files, folders, volumes) of the system.

.DESCRIPTION
Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

.PARAMETER Path
    String -- The path to enumerate.

.PARAMETER OnlyFiles
    switch --

.PARAMETER OnlyFolders
    switch --

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $ComputerName
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntities
    Description: Gets all the local file system entities of the machine.

.Parameter Path
    String -- The path to enumerate.

.Returns
    The local file system entities.
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ComputerName
    )

    return Invoke-Command -ComputerName $ComputerName -ScriptBlock { get-smbshare | Where-Object { -not ($_.name.EndsWith('$')) } } |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { "\\" + $_.PSComputerName + "\" + $_.Name } },
    @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
    Extension,
    @{Name = "IsHidden"; Expression = { [bool]$false } },
    @{Name = "IsShared"; Expression = { [bool]$true } },
    Name,
    @{Name = "Type"; Expression = { "FileShare" } },
    @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
    @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };
}

$entities = Get-FileSystemEntities -ComputerName $ComputerName;

return $entities;

}
## [END] Get-WACSOShareEntities ##
function Get-WACSOSmb1InstallationStatus {
<#

.SYNOPSIS
Get SMB1 installation status.

.DESCRIPTION
Get SMB1 installation status.

.ROLE
Readers

#>

Import-Module DISM

$Enabled = [bool]( Get-WindowsOptionalFeature -online -featurename SMB1Protocol | Where-Object State -eq "Enabled")
@{ isEnabled = $Enabled }

}
## [END] Get-WACSOSmb1InstallationStatus ##
function Get-WACSOSmbFileShareDetails {
<#

.SYNOPSIS
Enumerates all of the smb local file shares of the system.

.DESCRIPTION
Enumerates all of the smb local file shares of the system.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbFileShareDetails
    Description: Retrieves the SMB shares on the computer.
.Returns
    The local smb file share(s).
#>

$shares = Get-SmbShare -includehidden | Where-Object {-not ($_.Name -eq "IPC$")} | Microsoft.PowerShell.Utility\Select-Object Name, Path, CachingMode, EncryptData, CurrentUsers, Special, LeasingMode, FolderEnumerationMode, CompressData

$uncPath = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain

return @{
    shares = $shares;
    uncPath = $uncPath
}
   
}
## [END] Get-WACSOSmbFileShareDetails ##
function Get-WACSOSmbOverQuicSettings {
<#

.SYNOPSIS
Retrieves smb over QUIC settings from the server.

.DESCRIPTION
Returns smb over QUIC settings and server dns name

.ROLE
Readers

#>

Import-Module SmbShare

$serverConfigurationSettings = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object DisableSmbEncryptionOnSecureConnection, RestrictNamedpipeAccessViaQuic

return @{
    serverConfigurationSettings = $serverConfigurationSettings
}

}
## [END] Get-WACSOSmbOverQuicSettings ##
function Get-WACSOSmbServerCertificateHealth {
<#

.SYNOPSIS
Retrieves health of the current certificate for smb over QUIC.

.DESCRIPTION
Retrieves health of the current certificate for smb over QUIC based on if the certificate is self signed or not.

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $thumbprint,
  [Parameter(Mandatory = $true)]
  [boolean]
  $isSelfSigned,
  [Parameter(Mandatory = $true)]
  [boolean]
  $fromTaskScheduler,
  [Parameter(Mandatory = $false)]
  [String]
  $ResultFile,
  [Parameter(Mandatory = $false)]
  [String]
  $WarningsFile,
  [Parameter(Mandatory = $false)]
  [String]
  $ErrorFile
)

Set-StrictMode -Version 5.0



function getSmbServerCertificateHealth() {
  param (
    [String]
    $thumbprint,
    [boolean]
    $isSelfSigned,
    [String]
    $ResultFile,
    [String]
    $WarningsFile,
    [String]
    $ErrorFile
  )

  # create local runspace
  $ps = [PowerShell]::Create()
  # define input data but make it completed
  $inData = New-Object -Typename  System.Management.Automation.PSDataCollection[PSObject]
  $inData.Complete()
  # define output data to receive output
  $outData = New-Object -Typename  System.Management.Automation.PSDataCollection[PSObject]
  # register the script
  if ($isSelfSigned) {
    $ps.Commands.AddScript("Get-Item -Path " + $thumbprint + "| Test-Certificate -AllowUntrustedRoot") | Out-Null
  }
  else {
    $ps.Commands.AddScript("Get-Item -Path " + $thumbprint + "| Test-Certificate") | Out-Null
  }
  # execute async way.
  $async = $ps.BeginInvoke($inData, $outData)
  # wait for completion (callback will be called if any)
  $ps.EndInvoke($async)
  Start-Sleep -MilliSeconds 10
  # read output
  if ($outData.Count -gt 0) {
    @{ Output = $outData[0]; } | ConvertTo-Json | Out-File -FilePath $ResultFile
  }
  # read warnings
  if ($ps.Streams.Warning.Count -gt 0) {
    $ps.Streams.Warning | % { $_.ToString() } | Out-File -FilePath $WarningsFile
  }
  # read errors
  if ($ps.HadErrors) {
    $ps.Streams.Error | % { $_.ToString() } | Out-File -FilePath $ErrorFile
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
    getSmbServerCertificateHealth $thumbprint $isSelfSigned $ResultFile $WarningsFile $ErrorFile;
    return;
  }
}
else {
  #In non-WDAC environment script file will not be available on the machine
  #Hence, a dynamic script is created which is executed through the task Scheduler
  $ScriptFile = $env:temp + "\smbOverQuic-certificateHealth.ps1"
}

$thumbprint = Join-Path "Cert:\LocalMachine\My" $thumbprint

# Pass parameters tpt and generate script file in temp folder
$ResultFile = $env:temp + "\smbOverQuic-certificateHealth_result.txt"
$WarningsFile = $env:temp + "\smbOverQuic-certificateHealth_warnings.txt"
$ErrorFile = $env:temp + "\smbOverQuic-certificateHealth_error.txt"
if (Test-Path $ErrorFile) {
  Remove-Item $ErrorFile
}

if (Test-Path $ResultFile) {
  Remove-Item $ResultFile
}

if (Test-Path $WarningsFile) {
  Remove-Item $WarningsFile
}
$isSelfSignedtemp = if ($isSelfSigned) { "`$true" } else { "`$false" }

if ($isWdacEnforced) {
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.FileExplorer; Get-WACFESmbServerCertificateHealth -fromTaskScheduler `$true -thumbprint $thumbprint -isSelfSigned $isSelfSignedtemp -ResultFile $ResultFile -WarningsFile $WarningsFile -ErrorFile $ErrorFile }"""
}
else {
  (Get-Command getSmbServerCertificateHealth).ScriptBlock | Set-Content -path $ScriptFile
  $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Set-Location -Path $env:temp; .\smbOverQuic-certificateHealth.ps1 -thumbprint $thumbprint -isSelfSigned $isSelfSignedtemp -ResultFile $ResultFile -WarningsFile $WarningsFile -ErrorFile $ErrorFile }"""
}

# Create a scheduled task
$TaskName = "SMESmbOverQuicCertificate"
$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
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
      writeErrorLog "Can't connect to Schedule service"
      throw "Can't connect to Schedule service"
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
  try {
    $RootFolder.DeleteTask($TaskName, 0)
  }
  catch {

  }
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

#### example Start the task with user specified invoke username and password
####$Task.Principal.LogonType = 1
####$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, $invokeUserName, $invokePassword, 1) | Out-Null

#### Start the task with SYSTEM creds
$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
#Wait for running task finished
$RootFolder.GetTask($TaskName).Run(0) | Out-Null
while ($RootFolder.GetTask($TaskName).State -ne 4) {
  Start-Sleep -MilliSeconds 10
}
while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
  Start-Sleep -Seconds 1
}

#Clean up
try {
  $RootFolder.DeleteTask($TaskName, 0)
}
catch {

}
if (!$isWdacEnforced) {
  Remove-Item $ScriptFile
}

#Return result
if (Test-Path $ResultFile) {
  $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
  Remove-Item $ResultFile
  if ($result.Output) {
    return $result.Output;
  }
  else {
    if (Test-Path $WarningsFile) {
      $result = Get-Content -Path $WarningsFile
      Remove-Item $WarningsFile
    }
    if (Test-Path $ErrorFile) {
      Remove-Item $ErrorFile
    }
  }
  return $result;
}
else {
  if (Test-Path $ErrorFile) {
    $result = Get-Content -Path $ErrorFile
    Remove-Item $ErrorFile
    throw $result
  }
}

}
## [END] Get-WACSOSmbServerCertificateHealth ##
function Get-WACSOSmbServerCertificateMapping {
<#

.SYNOPSIS
Retrieves the current certifcate installed for smb over QUIC and smboverQuic status on the server.

.DESCRIPTION
Retrieves the current certifcate installed for smb over QUIC and smboverQuic status on the server.

.ROLE
Readers

.PARAMETER IsWS2025
To determine if the current operating system is WS2025 or not
#>

param (
[Parameter(Mandatory = $true)]
[boolean]
$IsWS2025
)

Import-Module SmbShare

$certHash = $null;
$kdcPort = $null;
$requireClientAuthentication = $false;
$clientAccessTrustedSignatures = @();
$clientAccessTrustedIssuers = @();

function Retrieve-WACPort {
  $details = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManagementGateway -ErrorAction SilentlyContinue
  if ($details) {
    $smePort = $details | Microsoft.PowerShell.Utility\Select-Object SmePort;
    return $smePort.smePort -eq 443
  }
  else {
    return $false;
  }
}

# retrieving smbcertificate mappings, if any
if($IsWS2025) {
  $smbCertificateMapping = @(Get-SmbServerCertificateMapping | Microsoft.PowerShell.Utility\Select-Object Thumbprint, Name, RequireClientAuthentication)
} else {
  $smbCertificateMapping = @(Get-SmbServerCertificateMapping | Microsoft.PowerShell.Utility\Select-Object Thumbprint, Name)
}

if ($smbCertificateMapping.count -gt 0 -and $IsWS2025) {
  $requireClientAuthentication = $smbCertificateMapping[0].RequireClientAuthentication;
  if ($requireClientAuthentication) {
    $clientAccessTrustedSignatures = @(Get-SmbClientAccessToServer -Name $smbCertificateMapping[0].Name | Microsoft.PowerShell.Utility\Select-Object IdentifierType, Identifier | Where-Object { $_.IdentifierType -eq 'SHA256' })
    $clientAccessTrustedIssuers = @(Get-SmbClientAccessToServer -Name $smbCertificateMapping[0].Name | Microsoft.PowerShell.Utility\Select-Object IdentifierType, Identifier | Where-Object { $_.IdentifierType -eq 'ISSUER' })
  }
}

# determining if WAC is installed on port 443
$isWacOnPort443 = Retrieve-WACPort;

# retrieving if smbOverQuic is enable on the server
$isSmbOverQuicEnabled = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object EnableSMBQUIC

try {
  # retrieving kdc Proxy status on the server
  $kdcUrl = netsh http show urlacl | findstr /i "KdcProxy"
  if ($kdcUrl) {
    $pos = $kdcUrl.IndexOf("+")
    $rightPart = $kdcUrl.Substring($pos + 1)
    $pos1 = $rightPart.IndexOf("/")
    $kdcPort = $rightPart.SubString(1, $pos1 - 1)
  }

  [array]$path = Get-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -ErrorAction SilentlyContinue

  [array]$clientAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -ErrorAction SilentlyContinue

  [array]$passwordAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -ErrorAction SilentlyContinue

  $status = Get-Service -Name kpssvc | Microsoft.PowerShell.Utility\Select-Object Status

  if ($null -ne $kdcPort) {
    $port = "0.0.0.0:"
    $ipport = $port + $kdcPort
    $certBinding = @(netsh http show sslcert ipport=$ipport | findstr "Hash")
    if ($null -ne $certBinding -and $certBinding.count -gt 0) {
      $index = $certBinding[0].IndexOf(":")
      $certHash = $certBinding[0].Substring($index + 1).trim()
    }
  }

  $isKdcProxyMappedForSmbOverQuic = $false;
  $moreThanOneCertMapping = $false;

  if (($null -ne $certHash) -and ($null -ne $smbCertificateMapping) -and ($smbCertificateMapping.count -eq 1)) {
    $isKdcProxyMappedForSmbOverQuic = $smbCertificateMapping.thumbprint -eq $certHash
  }
  elseif ($null -ne $smbCertificateMapping -and $smbCertificateMapping.count -gt 1) {
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($mapping in $smbCertificateMapping) {
      # Adding Out null as set.Add always returns true/false and we do not want that.
      $set.Add($smbCertificateMapping.thumbprint) | Out-Null;
    }
    if ($set.Count -gt 1) {
      $moreThanOneCertMapping = $true;
    }
    if (!$moreThanOneCertMapping -and $null -ne $certHash) {
      $isKdcProxyMappedForSmbOverQuic = $smbCertificateMapping[0].thumbprint -eq $certHash
    }
  }
}
catch {
  throw $_
}

return @{
  smbCertificateMapping          = $smbCertificateMapping
  isSmbOverQuicEnabled           = $isSmbOverQuicEnabled
  isKdcProxyMappedForSmbOverQuic = $isKdcProxyMappedForSmbOverQuic
  kdcPort                        = $kdcPort
  isKdcProxyEnabled              = $kdcPort -and ($null -ne $path -and $path.count -gt 0) -and ($null -ne $clientAuthproperty -and $clientAuthproperty.count -gt 0) -and ($null -ne $passwordAuthproperty -and $passwordAuthproperty.count -gt 0) -and $status.status -eq "Running"
  isWacOnPort443                 = $isWacOnPort443
  requireClientAuthentication    = $requireClientAuthentication
  clientAccessTrustedSignatures  = $clientAccessTrustedSignatures
  clientAccessTrustedIssuers     = $clientAccessTrustedIssuers;
}

}
## [END] Get-WACSOSmbServerCertificateMapping ##
function Get-WACSOSmbServerCertificateValues {
<#

.SYNOPSIS
Retrieves other values based on the installed certifcate for smb over QUIC.

.DESCRIPTION
Retrieves other values based on the installed certifcate for smb over QUIC.

.ROLE 
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $thumbprint
)

Set-Location Cert:\LocalMachine\My

[array] $smbServerDnsNames = Get-SmbServerCertificateMapping | Where-Object { $_.Thumbprint -eq $thumbprint } | Microsoft.PowerShell.Utility\Select-Object Name

$smbCertificateValues = Get-ChildItem -Recurse | Where-Object { $_.Thumbprint -eq $thumbprint } | Microsoft.PowerShell.Utility\Select-Object Subject, Thumbprint, Issuer, NotBefore, NotAfter

return @{ 
    smbServerDnsNames = $smbServerDnsNames
    smbCertificateValues = $smbCertificateValues
}

}
## [END] Get-WACSOSmbServerCertificateValues ##
function Get-WACSOSmbServerSettings {

<#

.SYNOPSIS
Enumerates the SMB server configuration settings on the computer.

.DESCRIPTION
Enumerates  the SMB server configuration settings on the computer.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbServerConfiguration
    Description: Retrieves the SMB server configuration settings on the computer.
.Returns
    SMB server configuration settings
#>

Import-Module SmbShare

$alternateQuicPorts = @()

Set-Variable -Name WS2025VersionNumber -Value 10.0.25398 -Scope Script
$result = Get-WmiObject -Class Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object Version
$isWS2025 = [version]$result.version -ge [version]$WS2025VersionNumber

$compressionSettings = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -ErrorAction SilentlyContinue

if($isWS2025) {
  $settings = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object RequireSecuritySignature,RejectUnencryptedAccess,AuditSmb1Access,EncryptData,RequestCompression, InvalidAuthenticationDelayTimeInMs, Smb2DialectMin, Smb2DialectMax
  $alternateQuicPorts = @(Get-SmbServerAlternativePort -TransportType QUIC -ErrorAction SilentlyContinue | Select-Object Port)
}
else{
  $settings = Get-SmbServerConfiguration | Microsoft.PowerShell.Utility\Select-Object RequireSecuritySignature,RejectUnencryptedAccess,AuditSmb1Access,EncryptData,RequestCompression
}


@{ settings = $settings
    alternateQuicPorts = $alternateQuicPorts
    compressionSettings = $compressionSettings
    isWS2025 = $isWS2025 }

}
## [END] Get-WACSOSmbServerSettings ##
function Get-WACSOSmbShareAccess {
<#

.SYNOPSIS
Enumerates the SMB server access rights and details on the server.

.DESCRIPTION
Enumerates the SMB server access rights and details on the server.

.ROLE
Readers

#>

<#
.Synopsis
    Name: Get-SmbShareAccess
    Description: Retrieves the SMB server access rights and details on the server.
.Returns
    Retrieves the SMB server access rights and details on the server.
#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name
)

[array]$shareAccess = Get-SmbShareAccess -Name "$Name" | Microsoft.PowerShell.Utility\Select-Object AccountName, AccessRight, AccessControlType

$details = Get-SmbShare -Name "$Name" | Microsoft.PowerShell.Utility\Select-Object CachingMode, EncryptData, FolderEnumerationMode, CompressData

return @{ 
    details = $details
    shareAccess = $shareAccess
  }   
}
## [END] Get-WACSOSmbShareAccess ##
function Get-WACSOStorageFileShare {
<#

.SYNOPSIS
Enumerates all of the local file shares of the system.

.DESCRIPTION
Enumerates all of the local file shares of the system.

.ROLE
Readers

.PARAMETER FileShareId
    The file share ID.
#>
param (
    [Parameter(Mandatory = $false)]
    [String]
    $FileShareId
)

Import-Module CimCmdlets

<#
.Synopsis
    Name: Get-FileShares-Internal
    Description: Gets all the local file shares of the machine.

.Parameters
    $FileShareId: The unique identifier of the file share desired (Optional - for cases where only one file share is desired).

.Returns
    The local file share(s).
#>
function Get-FileSharesInternal
{
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $FileShareId
    )

    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        # Map downlevel status to array of [health status, operational status, share state] uplevel equivalent
        $statusMap = @{
            "OK" =         @(0, 2, 1);
            "Error" =      @(2, 6, 2);
            "Degraded" =   @(1, 3, 2);
            "Unknown" =    @(5, 0, 0);
            "Pred Fail" =  @(1, 5, 2);
            "Starting" =   @(1, 8, 0);
            "Stopping" =   @(1, 9, 0);
            "Service" =    @(1, 11, 1);
            "Stressed" =   @(1, 4, 1);
            "NonRecover" = @(2, 7, 2);
            "No Contact" = @(2, 12, 2);
            "Lost Comm" =  @(2, 13, 2);
        };
        
        $shares = Get-CimInstance -ClassName Win32_Share |
            ForEach-Object {
                return @{
                    ContinuouslyAvailable = $false;
                    Description = $_.Description;
                    EncryptData = $false;
                    FileSharingProtocol = 3;
                    HealthStatus = $statusMap[$_.Status][0];
                    IsHidden = $_.Name.EndsWith("`$");
                    Name = $_.Name;
                    OperationalStatus = ,@($statusMap[$_.Status][1]);
                    ShareState = $statusMap[$_.Status][2];
                    UniqueId = "smb|" + (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain + "\" + $_.Name;
                    VolumePath = $_.Path;
                }
            }
    }
    else
    {        
        $shares = Get-CimInstance -ClassName MSFT_FileShare -Namespace Root\Microsoft\Windows/Storage |
            ForEach-Object {
                return @{
                    IsHidden = $_.Name.EndsWith("`$");
                    VolumePath = $_.VolumeRelativePath;
                    ContinuouslyAvailable = $_.ContinuouslyAvailable;
                    Description = $_.Description;
                    EncryptData = $_.EncryptData;
                    FileSharingProtocol = $_.FileSharingProtocol;
                    HealthStatus = $_.HealthStatus;
                    Name = $_.Name;
                    OperationalStatus = $_.OperationalStatus;
                    UniqueId = $_.UniqueId;
                    ShareState = $_.ShareState;
                }
            }
    }

    if ($FileShareId)
    {
        $shares = $shares | Where-Object { $_.UniqueId -eq $FileShareId };
    }

    return $shares;
}

if ($FileShareId)
{
    Get-FileSharesInternal -FileShareId $FileShareId;
}
else
{
    Get-FileSharesInternal;
}

}
## [END] Get-WACSOStorageFileShare ##
function Get-WACSOTempFolderPath {
<#

.SYNOPSIS
Gets the temporary folder (%temp%) for the user.

.DESCRIPTION
Gets the temporary folder (%temp%) for the user.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

return $env:TEMP

}
## [END] Get-WACSOTempFolderPath ##
function Move-WACSOFile {
<#

.SYNOPSIS
Moves or Copies a file or folder

.DESCRIPTION
Moves or Copies a file or folder from the source location to the destination location
Folders will be copied recursively

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the source file/folder to copy

.PARAMETER Destination
    String -- the path to the new location

.PARAMETER Copy
    boolean -- Determine action to be performed

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $path,

    [Parameter(Mandatory = $true)]
    [String]
    $destination,

    [Parameter(Mandatory = $true)]
    [boolean]
    $copy,

    [Parameter(Mandatory = $true)]
    [string]
    $entityType,

    [Parameter(Mandatory = $false)]
    [string]
    $existingPath
)

Set-StrictMode -Version 5.0

if($copy){
  $result = Copy-Item -Path $path -Destination $destination -Recurse -Force -PassThru -ErrorAction SilentlyContinue
  if(!$result){
    return $Error[0].Exception.Message
  }
} else {
  if ($entityType -eq "File" -Or  !$existingPath) {
    $result = Move-Item -Path $path -Destination $destination -Force -PassThru -ErrorAction SilentlyContinue
    if(!$result){
      return $Error[0].Exception.Message
    }
  }
  else {
    # Move-Item -Force doesn't work when replacing folders, remove destination folder before replacing
    Remove-Item -Path $existingPath -Confirm:$false -Force -Recurse
    $forceResult = Move-Item -Path $path -Destination $destination -Force -PassThru -ErrorAction SilentlyContinue
    if (!$forceResult) {
      return $Error[0].Exception.Message
    }
  }
}
return $result

}
## [END] Move-WACSOFile ##
function New-WACSOFile {
<#

.SYNOPSIS
Create a new file.

.DESCRIPTION
Create a new file on this server. If the file already exists, it will be overwritten.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the parent of the new file.

.PARAMETER NewName
    String -- the file name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

$newItem = New-Item -ItemType File -Path (Join-Path -Path $Path -ChildPath $NewName) -Force

return $newItem |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
                  @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
                  Extension,
                  @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
                  @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
                  Name,
                  @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
                  @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
                  @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } };

}
## [END] New-WACSOFile ##
function New-WACSOFolder {
<#

.SYNOPSIS
Create a new folder.

.DESCRIPTION
Create a new folder on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the parent of the new folder.

.PARAMETER NewName
    String -- the folder name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

$pathSeparator = [System.IO.Path]::DirectorySeparatorChar;
$newItem = New-Item -ItemType Directory -Path ($Path.TrimEnd($pathSeparator) + $pathSeparator + $NewName)

return $newItem |
    Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                  @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                  Extension,
                  @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                  Name,
                  @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                  @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                  @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};

}
## [END] New-WACSOFolder ##
function New-WACSOSmbFileShare {
<#

.SYNOPSIS
Gets the SMB file share  details on the server.

.DESCRIPTION
Gets the SMB file share  details on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: New-SmbFileShare
    Description: Gets the SMB file share  details on the server.
.Returns
    Retrieves all the SMB file share  details on the server.
#>


param (
    [Parameter(Mandatory = $true)]
    [String]
    $path,    

    [Parameter(Mandatory = $true)]
    [String]
    $name,

    [Parameter(Mandatory = $false)]
    [String[]]
    $fullAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $changeAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $readAccess,

    [Parameter(Mandatory = $false)]
    [String[]]
    $noAccess,

    [Parameter(Mandatory = $false)]
    [Int]
    $cachingMode,

    [Parameter(Mandatory = $false)]
    [boolean]
    $encryptData,

    # TODO:
    # [Parameter(Mandatory = $false)]
    # [Int]
    # $FolderEnumerationMode

    [Parameter(Mandatory = $false)]
    [boolean]
    $compressData,

    [Parameter(Mandatory = $false)]
    [boolean]
    $isCompressDataEnabled
)

$HashArguments = @{
  Name = "$name"
}

if($fullAccess.count -gt 0){
    $HashArguments.Add("FullAccess", $fullAccess)
}
if($changeAccess.count -gt 0){
    $HashArguments.Add("ChangeAccess", $changeAccess)
}
if($readAccess.count -gt 0){
    $HashArguments.Add("ReadAccess", $readAccess)
}
if($noAccess.count -gt 0){
    $HashArguments.Add("NoAccess", $noAccess)
}
if($cachingMode){
     $HashArguments.Add("CachingMode", "$cachingMode")
}
if($encryptData -ne $null){
    $HashArguments.Add("EncryptData", $encryptData)
}
# TODO: if($FolderEnumerationMode -eq 0){
#     $HashArguments.Add("FolderEnumerationMode", "AccessBased")
# } else {
#     $HashArguments.Add("FolderEnumerationMode", "Unrestricted")
# }
if($isCompressDataEnabled){
    $HashArguments.Add("CompressData", $compressData)
}

New-SmbShare -Path "$path" @HashArguments
@{ shareName = $name } 

}
## [END] New-WACSOSmbFileShare ##
function Remove-WACSOAllShareNames {
<#

.SYNOPSIS
Removes all shares of a folder.

.DESCRIPTION
Removes all shares of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path    
)

Set-StrictMode -Version 5.0

$CimInstance = Get-CimInstance -Class Win32_Share -Filter Path="'$Path'"
$RemoveShareCommand = ''
if ($CimInstance.name -And $CimInstance.name.GetType().name -ne 'String') { $RemoveShareCommand = $CimInstance.ForEach{ 'Remove-SmbShare -Name "' + $_.name + '" -Force'} } 
Else { $RemoveShareCommand = 'Remove-SmbShare -Name "' + $CimInstance.Name + '" -Force'}
if($RemoveShareCommand) { $RemoveShareCommand.ForEach{ Invoke-Expression $_ } }


}
## [END] Remove-WACSOAllShareNames ##
function Remove-WACSOFileSystemEntity {
<#

.SYNOPSIS
Remove the passed in file or path.

.DESCRIPTION
Remove the passed in file or path from this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER path
    String -- the file or path to remove.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path
)

Set-StrictMode -Version 5.0

Remove-Item -Path $Path -Confirm:$false -Force -Recurse

}
## [END] Remove-WACSOFileSystemEntity ##
function Remove-WACSOFolderShareUser {
<#

.SYNOPSIS
Removes a user from the folder access.

.DESCRIPTION
Removes a user from the folder access.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to the folder.

.PARAMETER Identity
    String -- The user identification (AD / Local user).

.PARAMETER FileSystemRights
    String -- File system rights of the user.

.PARAMETER AccessControlType
    String -- Access control type of the user.    

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $Identity,

    [Parameter(Mandatory = $true)]
    [String]
    $FileSystemRights,

    [ValidateSet('Deny','Allow')]
    [Parameter(Mandatory = $true)]
    [String]
    $AccessControlType
)

Set-StrictMode -Version 5.0

function Remove-UserPermission
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
        
        [ValidateSet('Deny','Allow')]
        [Parameter(Mandatory = $true)]
        [String]
        $ACT
    )

    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, 'ReadAndExecute','ContainerInherit, ObjectInherit', 'None', $ACT)
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
}

Remove-UserPermission $Path $Identity 'Allow'
Remove-UserPermission $Path $Identity 'Deny'
}
## [END] Remove-WACSOFolderShareUser ##
function Remove-WACSOSmbServerCertificateMapping {
<#
.SYNOPSIS
Removes the currently installed certificate for smb over QUIC on the server.

.DESCRIPTION
Removes the currently installed certificate for smb over QUIC on the server and also sets the status of smbOverQuic to enabled on the server.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $false)]
    [String[]]
    $ServerDNSNames,

    [Parameter(Mandatory = $false)]
    [String]
    $KdcPort,

    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyMappedForSmbOverQuic
)

Set-Location Cert:\LocalMachine\My


if($ServerDNSNames.count -gt 0){
    foreach($serverDNSName in $ServerDNSNames){
        Remove-SmbServerCertificateMapping -Name $serverDNSName -Force
    }
}

if($IsKdcProxyMappedForSmbOverQuic -and $KdcPort -ne $null){
    $port = "0.0.0.0:"
    $ipport = $port+$KdcPort
    $deleteCertKdc = netsh http delete sslcert ipport=$ipport
    if ($LASTEXITCODE -ne 0) {
        throw $deleteCertKdc
    }
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    Remove-NetFirewallRule -DisplayName $firewallString
}

Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
}
## [END] Remove-WACSOSmbServerCertificateMapping ##
function Remove-WACSOSmbShare {
<#

.SYNOPSIS
Removes shares of a folder.

.DESCRIPTION
Removes selected shares of a folder.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER name
    String -- The name of the folder.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Name    
)

Remove-SmbShare -Name $Name -Force


}
## [END] Remove-WACSOSmbShare ##
function Rename-WACSOFileSystemEntity {
<#

.SYNOPSIS
Rename a folder.

.DESCRIPTION
Rename a folder on this server.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- the path to the folder.

.PARAMETER NewName
    String -- the new folder name.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path,

    [Parameter(Mandatory = $true)]
    [String]
    $NewName
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: Get-FileSystemEntityType
    Description: Gets the type of a local file system entity.

.Parameters
    $Attributes: The System.IO.FileAttributes of the FileSystemEntity.

.Returns
    The type of the local file system entity.
#>
function Get-FileSystemEntityType
{
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileAttributes]
        $Attributes
    )

    if ($Attributes -match "Directory")
    {
        return "Folder";
    }
    else
    {
        return "File";
    }
}

Rename-Item -Path $Path -NewName $NewName -PassThru |
    Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                Extension,
                @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                Name,
                @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};

}
## [END] Rename-WACSOFileSystemEntity ##
function Restore-WACSOConfigureSmbServerCertificateMapping {
<#
.SYNOPSIS
Rolls back to the previous state of certificate maping if configure/edit action failed.

.DESCRIPTION
Rolls back to the previous state of certificate maping if configure/edit action failed.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $IsKdcProxyEnabled,

    [Parameter(Mandatory = $false)]
    [string]
    $KdcPort,

    [Parameter(Mandatory = $true)]
    [string]
    $KdcProxyOptionSelected
)

[array]$smbCertificateMappings = Get-SmbServerCertificateMapping | Microsoft.PowerShell.Utility\Select-Object Name
[array]$mappingNames = $smbCertificateMappings.name

if ($mappingNames.count -eq 0) {
    return;
}
if ($mappingNames.count -gt 0) {
    foreach ($mappingName in $mappingNames) {
        Remove-SmbServerCertificateMapping -Name $mappingName -Force
    }
}

if (!$IsKdcProxyEnabled -and $KdcProxyOptionSelected -eq 'enabled' -and $KdcPort -ne $null) {
    $urlLeft = "https://+:"
    $urlRight = "/KdcProxy/"
    $url = $urlLeft + $KdcPort + $urlRight
    $output = @(netsh http show urlacl | findstr /i "KdcProxy")
    if ($LASTEXITCODE -ne 0) {
        throw $output
    }

    if ($null -ne $output -and $output.count -gt 0) {
        $deleteOutput = netsh http delete urlacl url=$url
        if ($LASTEXITCODE -ne 0) {
            throw $deleteOutput
        }
    }
    [array]$clientAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -ErrorAction SilentlyContinue
    if ($null -ne $clientAuthproperty -and $clientAuthproperty.count -gt 0) {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth"
    }
    [array]$passwordAuthproperty = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -ErrorAction SilentlyContinue
    if ($null -ne $passwordAuthproperty -and $passwordAuthproperty.count -gt 0) {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth"
    }
    [array]$path = Get-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -ErrorAction SilentlyContinue
    if ($null -ne $path -and $path.count -gt 0) {
        Remove-Item  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"
    }
    Stop-Service -Name kpssvc
    $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
    $rule = @(Get-NetFirewallRule -DisplayName $firewallString -ErrorAction SilentlyContinue)
    if($null -ne $rule -and $rule.count -gt 0) {
        Remove-NetFirewallRule -DisplayName $firewallString
    }

    $port = "0.0.0.0:"
    $ipport = $port+$KdcPort
    $certBinding =  @(netsh http show sslcert ipport=$ipport | findstr "Hash")
    if ($LASTEXITCODE -ne 0) {
        throw $certBinding
    }
    if($null -ne $certBinding -and $certBinding.count -gt 0) {
        $deleteCertKdc = netsh http delete sslcert ipport=$ipport
        if ($LASTEXITCODE -ne 0) {
            throw $deleteCertKdc
        } 
    }
}


}
## [END] Restore-WACSOConfigureSmbServerCertificateMapping ##
function Set-WACSOSmbOverQuicServerSettings {
<#

.SYNOPSIS
Sets smb server settings for QUIC.

.DESCRIPTION
Sets smb server settings for QUIC.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER disableSmbEncryptionOnSecureConnection
To enable or disable smbEncryption on the server.

.PARAMETER restrictNamedPipeAccessViaQuic
To enable or diable namedPipeAccess on the server.

#>

param (
[Parameter(Mandatory = $true)]
[boolean]
$disableSmbEncryptionOnSecureConnection,

[Parameter(Mandatory = $true)]
[boolean]
$restrictNamedPipeAccessViaQuic
)


Set-SmbServerConfiguration -DisableSmbEncryptionOnSecureConnection $disableSmbEncryptionOnSecureConnection -RestrictNamedPipeAccessViaQuic $restrictNamedPipeAccessViaQuic -Force;

}
## [END] Set-WACSOSmbOverQuicServerSettings ##
function Set-WACSOSmbServerCertificateMapping {
<#
.SYNOPSIS
Set Smb Server Certificate Mapping

.DESCRIPTION
Configures smb over QUIC.

.ROLE
Administrators

.PARAMETER IsWS2025
    Boolean -- Specifies whether the Windows Server version is 2025. This is not a mandatory parameter.

.PARAMETER Thumbprint
    String -- The thumbprint of the certifiacte selected.

.PARAMETER ServerDNSNames
    String[] -- The addresses of the server for certificate mapping.

.PARAMETER IsKdcProxyEnabled
    Boolean -- Specifies whether the KDC proxy is enabled. This is a mandatory parameter.

.PARAMETER KdcProxyOptionSelected
    String -- Specifies the selected KDC proxy option. This is a mandatory parameter.

.PARAMETER KdcPort
    String -- Specifies the KDC port. This is not a mandatory parameter.
.PARAMETER RequireClientAuthentication
    Boolean -- Specifies whether client authentication is required. This is not a mandatory parameter.

.PARAMETER ClientAuthIdentifierType
    String -- Specifies the type of client authentication identifier. This is not a mandatory parameter.

.PARAMETER clientAccessTrustedSignatures
    String[] -- Specifies the added trusted signatures for client access. This is not a mandatory parameter.

.PARAMETER ClientAccessTrustedIssuers
    String[] -- Specifies the added trusted issuers for client access. This is not a mandatory parameter.
#>

param (
  [Parameter(Mandatory = $false)]
  [boolean]
  $IsWS2025,

  [Parameter(Mandatory = $true)]
  [String]
  $Thumbprint,

  [Parameter(Mandatory = $true)]
  [String[]]
  $ServerDNSNames,

  [Parameter(Mandatory = $true)]
  [boolean]
  $IsKdcProxyEnabled,

  [Parameter(Mandatory = $true)]
  [String]
  $KdcProxyOptionSelected,

  [Parameter(Mandatory = $false)]
  [String]
  $KdcPort,

  [Parameter(Mandatory = $false)]
  [boolean]
  $RequireClientAuthentication,

  [Parameter(Mandatory = $false)]
  [String]
  $ClientAuthIdentifierType,

  [Parameter(Mandatory = $false)]
  [String[]]
  $clientAccessTrustedSignatures,

  [Parameter(Mandatory = $false)]
  [String[]]
  $ClientAccessTrustedIssuers
)

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeScripts-ConfigureKdcProxy" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message $logMessage -ErrorAction SilentlyContinue
}

Set-Location Cert:\LocalMachine\My

function Enable-KdcProxy {

  $urlLeft = "https://+:"
  $urlRight = "/KdcProxy"
  $url = $urlLeft + $KdcPort + $urlRight

  $port = "0.0.0.0:"
  $ipport = $port + $KdcPort

  $ComputerName = (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain

  try {
    $certBinding = @(netsh http show sslcert ipport=$ipport | findstr "Hash")
    if ($null -ne $certBinding -and $certBinding.count -gt 0) {
      $deleteCertKdc = netsh http delete sslcert ipport=$ipport
      if ($LASTEXITCODE -ne 0) {
        throw $deleteCertKdc
      }
    }
    $guid = [Guid]::NewGuid()
    $netshAddCertBinding = netsh http add sslcert ipport=$ipport certhash=$Thumbprint certstorename="my" appid="{$guid}"
    if ($LASTEXITCODE -ne 0) {
      throw $netshAddCertBinding
    }
    $message = 'Completed adding ssl certificate port'
    writeInfoLog $message
    if ($ServerDNSNames.count -gt 0) {
      foreach ($serverDnsName in $ServerDnsNames) {
        if ($ComputerName.trim() -ne $serverDnsName.trim()) {
          $output = Echo 'Y' | netdom computername $ComputerName /add $serverDnsName
          if ($LASTEXITCODE -ne 0) {
            throw $output
          }
        }
      }
      $message = 'Completed adding alternative names'
      writeInfoLog $message
    }
    if (!$IsKdcProxyEnabled) {
      $netshOutput = netsh http add urlacl url=$url user="NT authority\Network Service"
      if ($LASTEXITCODE -ne 0) {
        throw $netshOutput
      }
      $message = 'Completed adding urlacl'
      writeInfoLog $message
      New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"  -force
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "HttpsClientAuth" -Value 0x0 -type DWORD
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" -Name "DisallowUnprotectedPasswordAuth" -Value 0x0 -type DWORD
      Set-Service -Name kpssvc -StartupType Automatic
      Start-Service -Name kpssvc
    }
    $message = 'Returning method Enable-KdcProxy'
    writeInfoLog $message
    return $true;
  }
  catch {
    throw $_
  }
}

function Modify-CAAC([string]$dnsName) {
  if ($RequireClientAuthentication -and $ClientAuthIdentifierType -eq 'SHA256') {
    foreach ($ClientAccessCertSignature in $clientAccessTrustedSignatures) {
      Grant-SmbClientAccessToServer -Name $serverDNSName -IdentifierType $ClientAuthIdentifierType -Identifier $ClientAccessCertSignature -Force
    }
  } if ($RequireClientAuthentication -and $ClientAuthIdentifierType -eq 'ISSUER') {
    foreach ($ClientAccessTrustedIssuer in $ClientAccessTrustedIssuers) {
      Grant-SmbClientAccessToServer -Name $serverDNSName -IdentifierType $ClientAuthIdentifierType -Identifier $ClientAccessTrustedIssuer -Force
    }
  }
}
function New-SmbCertificateMapping {
  if ($ServerDNSNames.count -gt 0) {
    $message = 'Setting server dns names'
    writeInfoLog $message
    foreach ($serverDNSName in $ServerDNSNames) {
      if ($IsWS2025) {
        New-SmbServerCertificateMapping -Name $serverDNSName -Thumbprint $Thumbprint -StoreName My -requireClientAuthentication $RequireClientAuthentication -Force
        Modify-CAAC $serverDNSName
      }
      else {
        New-SmbServerCertificateMapping -Name $serverDNSName -Thumbprint $Thumbprint -StoreName My -Force
      }
    }
    if ($KdcProxyOptionSelected -eq "enabled" -and $null -ne $KdcPort) {
      $message = 'Enabling Kdc Proxy'
      writeInfoLog $message
      $result = Enable-KdcProxy
      if ($result) {
        $firewallString = "KDC Proxy Server service (KPS) for SMB over QUIC"
        $firewallDesc = "The KDC Proxy Server service runs on edge servers to proxy Kerberos protocol messages to domain controllers on the corporate network. Default port is TCP/443."
        New-NetFirewallRule -DisplayName $firewallString -Description $firewallDesc -Protocol TCP -LocalPort $KdcPort -Direction Inbound -Action Allow
      }
    }
    return $true;
  }
  $message = 'Exiting method smb certificate mapping '
  writeInfoLog $message
  return $true;
}

return New-SmbCertificateMapping;

}
## [END] Set-WACSOSmbServerCertificateMapping ##
function Set-WACSOSmbServerSettings {
<#
.SYNOPSIS
Updates the server configuration settings on the server.

.DESCRIPTION
Updates the server configuration settings on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: Set-SmbServerSettings
    Description: Updates the server configuration settings on the server.
#>


param (
    [Parameter(Mandatory = $false)]
    [Nullable[boolean]]
    $AuditSmb1Access,

    [Parameter(Mandatory = $true)]
    [boolean]
    $RequireSecuritySignature,

    [Parameter(Mandatory = $false)]
    [boolean]
    $RejectUnencryptedAccess,

    [Parameter(Mandatory = $true)]
    [boolean]
    $EncryptData,

    [Parameter(Mandatory = $true)]
    [boolean]
    $CompressionSettingsClicked,

    [Parameter(Mandatory = $false)]
    [Nullable[boolean]]
    $RequestCompression,

    [Parameter(Mandatory = $false)]
    [String]
    $InvalidAuthenticationDelayTimeInMs,

    [Parameter(Mandatory = $false)]
    [String]
    $Smb2DialectMin,

    [Parameter(Mandatory = $false)]
    [String]
    $Smb2DialectMax,

    [Parameter(Mandatory = $false)]
    [String[]]
    $NewAlternatePorts,

    [Parameter(Mandatory = $false)]
    [String[]]
    $DeletedAlternatePorts,

    [Parameter(Mandatory = $false)]
    [boolean]
    $isWS2025
)

$HashArguments = @{
}

if($CompressionSettingsClicked) {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -Value 0x1 -type DWORD
} else {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\parameters" -Name "DisableCompression" -Value 0x0 -type DWORD
}

if($null -ne $RejectUnencryptedAccess){
    $HashArguments.Add("RejectUnencryptedAccess", $RejectUnencryptedAccess)
}

if($null -ne $AuditSmb1Access){
  $HashArguments.Add("AuditSmb1Access", $AuditSmb1Access)
}

if($null -ne $RequestCompression) {
  $HashArguments.Add("RequestCompression", $RequestCompression)
}

if($isWS2025 -and $InvalidAuthenticationDelayTimeInMs) {
  $HashArguments.Add("InvalidAuthenticationDelayTimeInMs", $InvalidAuthenticationDelayTimeInMs)
}

if($isWS2025 -and $Smb2DialectMin) {
  $HashArguments.Add("Smb2DialectMin", $Smb2DialectMin)
}

if($isWS2025 -and $Smb2DialectMax) {
  $HashArguments.Add("Smb2DialectMax", $Smb2DialectMax)
}

Set-SmbServerConfiguration -RequireSecuritySignature $RequireSecuritySignature -EncryptData $EncryptData @HashArguments -Force

if($isWS2025 -and $NewAlternatePorts.count -gt 0) {
  foreach($newAlternatePort in $NewAlternatePorts) {
    Set-SmbServerAlternativePort -TransportType QUIC -Port $newAlternatePort -EnableInstances Default -Force
  }
}

if($isWS2025 -and $DeletedAlternatePorts.count -gt 0) {
  foreach($deletedAlternatePort in $DeletedAlternatePorts) {
    Remove-SmbServerAlternativePort -TransportType QUIC -Port $deletedAlternatePort -Force
  }
}

}
## [END] Set-WACSOSmbServerSettings ##
function Test-WACSOFileSystemEntity {
<#

.SYNOPSIS
Checks if a file or folder exists

.DESCRIPTION
Checks if a file or folder exists
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

.PARAMETER Path
    String -- The path to check if it exists

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $Path    
)

Set-StrictMode -Version 5.0

Test-Path -path $Path

}
## [END] Test-WACSOFileSystemEntity ##
function Uninstall-WACSOSmb1 {
<#
.SYNOPSIS
Disables SMB1 on the server.

.DESCRIPTION
Disables SMB1 on the server.

.ROLE
Administrators

#>

<#
.Synopsis
    Name: UninstallSmb1
    Description: Disables SMB1 on the server.
#>

Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
}
## [END] Uninstall-WACSOSmb1 ##

# SIG # Begin signature block
# MIIoUgYJKoZIhvcNAQcCoIIoQzCCKD8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDPFNl2ROlOltiE
# CWDkcl7B/pa+gI+RFBJUvu5ia0E8W6CCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIC6j
# pFBp1iM2C9PJ+/w/5p1tDLf/Pz2H+f7lGnwqyj/5MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAGId/pXqYwG/ENokXCOrYyGiU42By97S+OE0e
# OcrpqnPzcuF5WL9vq+FtXMBOvZr45UHos+8B+KIIlB/ZIMU3GNzaPio1NVBuc/8Y
# eserLpJ+XlHaLRMY7GVxYnjznyAdO5JzJr7wSMeHjnbGpFLfX0lga1Hgk2NQtpSA
# jPXTVozc6JpZ4dbvUPYDCef0tSPzserR+wgyApoJpKlFXznYoe9qb3+rN6m5id0v
# BXh7pFLlVgHViPyLX/rRJlVGpudwfGEcCIM1dpy1T3QOsa4a4z7iEshrEjpL2+Ip
# zuHziAmmC3eHmRbwIynVvsfh21WO6jxVo8angWQ9RC3L+Hch3qGCF60wghepBgor
# BgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCCF4YwgheCAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBAlRny+F5riA+YKFn57FhtlS1zAf/to0p8
# e8zAHNOemAIGaQJIJL8SGBMyMDI1MTExMDE3MTYxNS4yMjZaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjoyQTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggcoMIIFEKADAgECAhMzAAACEKvN
# 5BYY7zmwAAEAAAIQMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgxMloXDTI2MTExMzE4NDgxMlowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjJBMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# jcc4q057ZwIgpKu4pTXWLejvYEduRf+1mIpbiJEMFWWmU2xpip+zK7xFxKGB1Ccl
# UXBU0/ZQZ6LG8H0gI7yvosrsPEI1DPB/XccGCvswKbAKckngOuGTEPGk7K/vEZa9
# h0Xt02b7m2n9MdIjkLrFl0pDriKyz0QHGpdh93X6+NApfE1TL24Vo0xkeoFGpL3r
# X9gXhIOF59EMnTd2o45FW/oxMgY9q0y0jGO0HrCLTCZr50e7TZRSNYAy2lyKbvKI
# 2MKlN1wLzJvZbbc//L3s1q3J6KhS0KC2VNEImYdFgVkJej4zZqHfScTbx9hjFgFp
# VkJl4xH5VJ8tyJdXE9+vU0k9AaT2QP1Zm3WQmXedSoLjjI7LWznuHwnoGIXLiJMQ
# zPqKqRIFL3wzcrDrZeWgtAdBPbipglZ5CQns6Baj5Mb6a/EZC9G3faJYK5QVHeE6
# eLoSEwp1dz5WurLXNPsp0VWplpl/FJb8jrRT/jOoHu85qRcdYpgByU9W7IWPdrth
# myfqeAw0omVWN5JxcogYbLo2pANJHlsMdWnxIpN5YwHbGEPCuosBHPk2Xd9+E/pZ
# PQUR6v+D85eEN5A/ZM/xiPpxa8dJZ87BpTvui7/2uflUMJf2Yc9ZLPgEdhQQo0Lw
# MDSTDT48y3sV7Pdo+g5q+MqnJztN/6qt1cgUTe9u+ykCAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBSe42+FrpdF2avbUhlk86BLSH5kejAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAvs4rO3oo8czOrxPqnnSEkUVq718QzlrIiy7/EW7JmQXsJoFxHWUF0Ux0
# PDyKFDRXPJVv29F7kpJkBJJmcQg5HQV7blUXIMWQ1qX0KdtFQXI/MRL77Z+pK5x1
# jX+tbRkA7a5Ft7vWuRoAEi02HpFH5m/Akh/dfsbx8wOpecJbYvuHuy4aG0/tGzOW
# FCxMMNhGAIJ4qdV87JnY/uMBmiodlm+Gz357XWW5tg3HrtNZXuQ0tWUv26ud4nGK
# Jo/oLZHP75p4Rpt7dMdYKUF9AuVFBwxYZYpvgk12tfK+/yOwq84/fjXVCdM83Qna
# wtbenbk/lnbc9KsZom+GnvA4itAMUpSXFWrcRkqdUQLN+JrG6fPBoV8+D8U2Q2F4
# XkiCR6EU9JzYKwTuvL6t3nFuxnkLdNjbTg2/yv2j3WaDuCK5lSPgsndIiH6Bku2U
# i3A0aUo6D9z9v+XEuBs9ioVJaOjf/z+Urqg7ESnxG0/T1dKci7vLQ2XNgWFYO+/O
# lDjtGoma1ijX4m14N9qgrXTuWEGwgC7hhBgp3id/LAOf9BSTWA5lBrilsEoexXBr
# On/1wM3rjG0hIsxvF5/YOK78mVRGY6Y7zYJ+uXt4OTOFBwadPv8MklreQZLPnQPt
# iwop4rlLUYaPCiD4YUqRNbLp8Sgyo9g0iAcZYznTuc+8Q8ZIrgwwggdxMIIFWaAD
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
# Hm5TaGllbGQgVFNTIEVTTjoyQTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAOsyf2b6riPKn
# nXlIgIL2f53PUsKggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy8l80wIhgPMjAyNTExMTAxNjU2NDVaGA8yMDI1
# MTExMTE2NTY0NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7LyXzQIBADAHAgEA
# AgILiTAHAgEAAgISMDAKAgUA7L3pTQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQCT5h2KYFNIRXfVWA5jq0CDS3mBsPqKc6rNWOY8KVE3ffKm+Ua+YyFncYOD
# mCi2/mWVy+U7K0fFr7ujl322brmKhjeCI/drArgTdn+qE9X6biSwmVPb4GzKHgde
# CCZzIoMb8rebF0yKBeaBb9YJwg5Za0XocUn4LL4Km87p/uNRlWAdE5Wpwy/QDzT+
# asW0JSf+XxlEt1DTwYOlZrHXAO0HZLdiiH8TK7ap3Hc/YxnsAJM11MSKnpyyMwJj
# VVdTfcui5ikgczSVd27mzLbtLeUMum3Omca80lwWVbFjlTW3iTtJLbWMEZUrDtR/
# kc6RyBxefLNggDum+9ZjnSPY2zGJMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAIQq83kFhjvObAAAQAAAhAwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQg4d/yhy2YpXc8YX/BfqndHXSDdw3VaLB7cUzsWNfxLlIwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCDD1SHufsjzY59S1iHUQY9hnsKSrJPg5a9Mc4Yn
# GmPHxjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAC
# EKvN5BYY7zmwAAEAAAIQMCIEII6Og6RxC8cYttxJJkrPX2tlvn+mMoXxv5VgZBBz
# 20JtMA0GCSqGSIb3DQEBCwUABIICAF0Y6ebKJ4gymQckoOOJY6PfA0tl0V5iAcwb
# ps7f5DyKByzrkcmaoNXhGUoFbs5yW1Eqvn8DKowb/qv7K4nFTn2AYp8xVwlqU7qL
# CIiHc79mMRtJAvha1qhb2Wwqnrl5bNMzdqJg/jQMWB0I0T87MjDCjGTjwkV9fSL/
# p95zxtILtfBWUyaeNI/RQisFo9ldusrxjbobthKopDnVsKwEISISnR9eLWed5Rql
# a2+m4sbL4cHQhog7mZKxKpumHK9tH89sIKPscY5LpUKH8A5V33GjP6K2cYWhMpLo
# VgHks53wKwv4V88mMrppXnuv119bptV1TKFP/quDlP2S8GfSQNOmq1PTejsOENoO
# yJrTSxLUsGgliyLVxsRzPXuiPi7q/lMJhg9OfDBH9kyRIhkDvoxvOoXPvIzK7ooi
# sSBCr7mBrJyI7vluuyE002W6nbA2tZZa4Xru9p4ecde6MuT76DaGgJIvF9mtZenY
# kTBwOHJdbNVs2ihKKG5k6Je499Qi9ThMAzXVW7CdhP/GFFE0GfQ5YOxS4ytgkMyU
# nMyeTtWekpclSNsztMFO8FCc7cIThS8CcyNbhA/qdyS6V4D5cUhCB4RDGTH1TnUO
# uRC6jnJln7Vgn5vlGqKUE7i9rN4hA6h9jo8yqw+f2i0X4LQ9426Ms/Ki/s13jEHb
# LxXy5CfJ
# SIG # End signature block
