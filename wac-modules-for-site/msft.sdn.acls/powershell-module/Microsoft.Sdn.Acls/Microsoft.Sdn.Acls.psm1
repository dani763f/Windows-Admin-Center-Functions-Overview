function Convert-AclLogs {
<#

.SYNOPSIS
Converts ACL Logs for the specified time duration at the specific path to Azure Network Watcher Format

.DESCRIPTION
Converts ACL Logs for the specified time duration at the specific path to Azure Network Watcher Format

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String]
    $FromTime,

    [Parameter(Mandatory = $true)]
    [String]
    $ToTime,

    [Parameter(Mandatory = $true)]
    [String]
    $LogPath
)

$EpochStartTime = Get-Date 01.01.1970;
$FromTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($FromTime));
$ToTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($ToTime));

$Logs = Get-ChildItem $LogPath -File -Filter *.json | Where-Object {
    $LogTimestamp = $_.Name.Split('.')[2];
    $LogTimestamp = Get-Date -Year $LogTimestamp.Substring(0,4) -Month $LogTimestamp.Substring(4,2) -Day $LogTimestamp.Substring(6,2) -Hour $LogTimestamp.Substring(10,2) -Minute $LogTimestamp.Substring(12,2) -Second $LogTimestamp.Substring(14,2);
    $LogTimestamp -ge $FromTimestamp -and $LogTimestamp -le $ToTimestamp
};


$tempFolder = ([System.IO.Path]::GetTempPath()+'~'+([System.IO.Path]::GetRandomFileName())).Split('.')[0];

$dir = New-Item -Path $tempFolder -ItemType Directory;

foreach ($LogFile in $Logs) {
    try {
        $ConvertedLogs = New-Object System.Collections.Generic.List[System.Object];
        $CurrentRecord = Get-Content -Path $LogFile.FullName -ErrorAction Ignore | ConvertFrom-Json;
        for ($i=0; $i -lt $CurrentRecord.records.Count; $i = $i + 1) {
            $Record = $CurrentRecord.records[$i];
            $OldTimestamp = $Record.time;
            $NewTimestamp = "$($OldTimestamp.substring(0,4))-$($OldTimestamp.substring(4,2))-$($OldTimestamp.substring(6,2))T$($OldTimestamp.substring(10,2)):$($OldTimestamp.substring(12,2)):$($OldTimestamp.substring(14,2)).$($OldTimestamp.substring(16))Z";
            $Record.time = $NewTimestamp;
            $ConvertedLogs.Add($Record);
        }

        $Object = New-Object -TypeName psobject
        $Object | Add-Member -MemberType NoteProperty -Name 'records' -Value $ConvertedLogs -ErrorAction SilentlyContinue
        $JSONContent = $Object | ConvertTo-Json -Depth 10;
        $FilePath = $tempFolder + "\$($LogFile.Name)";
        Add-Content $FilePath $JSONContent
    }
    catch {
        # There is no way to handle failure here
    }
}

$ConvertedLogs = Get-ChildItem $tempFolder -File -Filter *.json;

if ($ConvertedLogs.Length -gt 0) {
    return $ConvertedLogs.FullName;
} else {
    return @();
}

}
## [END] Convert-AclLogs ##
function Get-AccessControlListRules {
<#

.SYNOPSIS
Get Access Control List Rules of Access Control List

.DESCRIPTION
This script is used to List all Access Control List Rules of a Access Control List available in the Cluster

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName
)

# Get Access Control List Rules
$accessControlListRules = Get-NetworkControllerAccessControlListRule -ConnectionUri $uri -AccessControlListId $aclName

foreach($accessControlListRule in $accessControlListRules)
{
    #Fetch the Name of Access Control List Rule
    $resourecID = $accessControlListRule.ResourceId

    #Fetch the Priority of the Access Control List Rule
    $priority = $accessControlListRule.Properties.Priority

    #Fetch the Type of the Access Control List Rule
    $type = $accessControlListRule.Properties.Type

    #Fetch the Protocol of the Access Control List Rule
    $protocol = $accessControlListRule.Properties.Protocol

    #Fetch the Source Address Prefix of the Access Control List Rule
    $sourceAddressPrefix = $accessControlListRule.Properties.SourceAddressPrefix

    #Fetch the source tags
    $sourceTags = $accessControlListRule.Properties.SourceSecurityTags

    #Fetch the Source Port Range of the Access Control List Rule
    $sourcePortRange = $accessControlListRule.Properties.SourcePortRange

    #Fetch the Destination Address Prefix of the Access Control List Rule
    $destinationAddressPrefix = $accessControlListRule.Properties.DestinationAddressPrefix

    #Fetch the destination tags
    $destinationTags = $accessControlListRule.Properties.DestinationSecurityTags

    #Fetch the Destination Port Range of the Access Control List Rule
    $destinationPortRange = $accessControlListRule.Properties.DestinationPortRange

    #Fetch the Action of the Access Control List Rule
    $action = $accessControlListRule.Properties.Action

    #Fetch the Logging of the Access Control List Rule
    $logging = $accessControlListRule.Properties.Logging

    #Fetch the Provisioning State of the Access Control List Rule
    $provisioningState = $accessControlListRule.Properties.ProvisioningState

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $resourecID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Priority' -Value $priority -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $protocol -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SourceAddressPrefix' -Value $sourceAddressPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SourceTags' -Value $sourceTags -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SourcePortRange' -Value $sourcePortRange -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationAddressPrefix' -Value $destinationAddressPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationTags' -Value $destinationTags -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationPortRange' -Value $destinationPortRange -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Action' -Value $action -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Logging' -Value $logging -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-AccessControlListRules ##
function Get-AccessControlListSubnets {
<#

.SYNOPSIS
Get Access Control Lists subnets

.DESCRIPTION
This script is used to List all Access Control Lists available in the Cluster

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName
)

# Get Access Control Lists
$accessControlLists = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName
$accessControlListSubnets = $accessControlLists.Properties.Subnets

foreach($accessControlListSubnet in $accessControlListSubnets)
{
    #Fetch the Name of the Subnet
    $subnetName = $accessControlListSubnet.ResourceRef.split('/')[4]

    #Fetch the Name of the Virtual Network
    $virtualNetworkName = $accessControlListSubnet.ResourceRef.split('/')[2]

    #Fetch the Virtual Network details
    $virtualNetwork = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri -ResourceId $virtualNetworkName

    #Fetch the Instance ID of Virtual Network
    $instanceId = $virtualNetwork.InstanceId

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkSubnetName' -Value $subnetName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkName' -Value $virtualNetworkName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceID' -Value $instanceId -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-AccessControlListSubnets ##
function Get-AccessControlLists {
<#

.SYNOPSIS
Get Access Control Lists

.DESCRIPTION
This script is used to List all Access Control Lists available in the Cluster

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string] $resourceId
)

# Get Access Control Lists
if ($resourceId -eq '') {
  $accessControlLists = Get-NetworkControllerAccessControlList -ConnectionUri $uri
} else {
  $accessControlLists = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $resourceId
}

foreach($accessControlList in $accessControlLists)
{
    #Fetch the Name of the Access Control List
    $resourceId = $accessControlList.ResourceId

    #Fetch the resource ref
    $resourceRef = $accessControlList.resourceRef

    #Fetch the Length of the Access Control List Rules
    $aclRules = $accessControlList.Properties.AclRules.length

    #Fetch the Length of the Access Control List Subnets
    $subnets = $accessControlList.Properties.Subnets.length

    #Fetch the Length of the Access Controls List NICs
    $ipConfigurations = $accessControlList.Properties.IpConfigurations.length

    #Fetch the Provisioning State of the Access Control List
    $provisioningState = $accessControlList.Properties.ProvisioningState

    #Fetch the Instance ID of the Access Control List
    $instanceID = $accessControlList.InstanceId

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'ResourceId' -Value $resourceId -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ResourceRef' -Value $resourceRef -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AclRules' -Value $aclRules -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AppliedSubnets' -Value $subnets -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AppliedNICs' -Value $ipConfigurations -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceID -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-AccessControlLists ##
function Get-AclAssociatedVM {
<#

.SYNOPSIS
Get VM

.DESCRIPTION
This script is used to List Applied Virtual Machine Network Adapters in Access Control List

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $vmID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $clusterNode


)

$vmName =(Get-VM -ComputerName $clusterNode) | ? Vmid -Like $vmID

if($vmName -ne $null)
{
    #Fetch the VM Name
    $virtualMachine = $vmName.Name
}
else
{
   $virtualMachine = $null
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'virtualMachine' -Value $virtualMachine -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-AclAssociatedVM ##
function Get-AclLogList {
<#

.SYNOPSIS
Fetches list of ACL Log files for the specified time duration at the specific path

.DESCRIPTION
Fetches list of ACL Log files for the specified time duration at the specific path

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String]
    $FromTime,

    [Parameter(Mandatory = $true)]
    [String]
    $ToTime,

    [Parameter(Mandatory = $true)]
    [String]
    $LogPath
)

$EpochStartTime = Get-Date 01.01.1970;
$FromTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($FromTime));
$ToTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($ToTime));

$Logs = Get-ChildItem $LogPath -File -Filter *.json | Where-Object {
    $LogTimestamp = $_.Name.Split('.')[2];
    $LogTimestamp = Get-Date -Year $LogTimestamp.Substring(0,4) -Month $LogTimestamp.Substring(4,2) -Day $LogTimestamp.Substring(6,2) -Hour $LogTimestamp.Substring(10,2) -Minute $LogTimestamp.Substring(12,2) -Second $LogTimestamp.Substring(14,2);
    $LogTimestamp -ge $FromTimestamp -and $LogTimestamp -le $ToTimestamp
};

if ($Logs.Length -gt 0) {
    return $Logs.FullName;
} else {
    return @();
}

}
## [END] Get-AclLogList ##
function Get-AclLogs {
<#

.SYNOPSIS
Fetches ACL Logs for the specified time duration at the specific path

.DESCRIPTION
Fetches ACL Logs for the specified time duration at the specific path

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String]
    $FromTime,

    [Parameter(Mandatory = $true)]
    [String]
    $ToTime,

    [Parameter(Mandatory = $true)]
    [String]
    $LogPath
)

$EpochStartTime = Get-Date 01.01.1970;
$FromTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($FromTime));
$ToTimestamp = $EpochStartTime + ([System.TimeSpan]::FromMilliseconds($ToTime));

$Logs = Get-ChildItem $LogPath -File -Filter *.json | Where-Object {
    $LogTimestamp = $_.Name.Split('.')[2];
    $LogTimestamp = Get-Date -Year $LogTimestamp.Substring(0,4) -Month $LogTimestamp.Substring(4,2) -Day $LogTimestamp.Substring(6,2) -Hour $LogTimestamp.Substring(10,2) -Minute $LogTimestamp.Substring(12,2) -Second $LogTimestamp.Substring(14,2);
    $LogTimestamp -ge $FromTimestamp -and $LogTimestamp -le $ToTimestamp
};

$ReturnAclLogs = New-Object System.Collections.Generic.List[System.Object];

foreach ($LogFile in $Logs) {
    try {
        $CurrentRecord = Get-Content -Path $LogFile.FullName -ErrorAction Ignore;
        $ReturnAclLogs.Add([string]$CurrentRecord);
    }
    catch {
        # This will fail for the latest file - this is not an error
    }
}

return [string[]]$ReturnAclLogs;

}
## [END] Get-AclLogs ##
function Get-AppliedVirtualMachineNetworkAdapters {
<#

.SYNOPSIS
Get Applied Virtual Machine Network Adapters

.DESCRIPTION
This script is used to List all Applied Virtual Machine Network Adapters in Access Control List

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName
)

# Get Applied Virtual Machine Network Adapters
$accessControlLists = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName
$appliedVirtualMachineNetworkAdapters  = $accessControlLists.Properties.IpConfigurations.ResourceRef
$virtualMachineVMIDs = " "
$virtualMachineVMIDs = @()
foreach($appliedVirtualMachineNetworkAdapter in $appliedVirtualMachineNetworkAdapters)
{
    #Fetch the Name of the Network Interface
    $networkInterfaceName = $appliedVirtualMachineNetworkAdapter.split('/')[2]

    #Fetch the Network Interface details
    $networkInterface = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId $networkInterfaceName

    $virtualMachineVMIDs += $networkInterface.Tags.vmId

}

foreach($virtualMachineVMID in $virtualMachineVMIDs)
{
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'virtualMachineVMID' -Value $virtualMachineVMID -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-AppliedVirtualMachineNetworkAdapters ##
function Get-AuditPath {
<#

.SYNOPSIS
Get SDN ACL audit path

.DESCRIPTION
This script is used to get the SDL ACL audit path

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri
)

$nc = Get-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri
$nc.Properties.OutputDirectory

}
## [END] Get-AuditPath ##
function Get-AuditSpaceState {
<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $path
)

function Get-FreeSpace {
    param ([string]$path);
    $space = (Get-Volume -FilePath $path).SizeRemaining;
    return $space;
}

function Get-UsedSpace {
    param ([string]$path);
    # This isn't perfect, an access denied will result in us undercounting
    return (Get-ChildItem -Recurse $path | Microsoft.PowerShell.Utility\Measure-Object -Sum Length).Sum;
}

# Defaults in case of errors
$freespace = -1
$usedspace = -1

try {
    $freespace = Get-FreeSpace -ErrorAction Ignore $path;
} catch { }

try {
    $usedspace = Get-UsedSpace -ErrorAction Ignore $path;
} catch { }

$response = New-Object -TypeName psobject
$response | Add-Member -MemberType NoteProperty -Name 'FreeSpace' -Value $freespace -ErrorAction SilentlyContinue
$response | Add-Member -MemberType NoteProperty -Name 'UsedSpace' -Value $usedspace -ErrorAction SilentlyContinue

$response

}
## [END] Get-AuditSpaceState ##
function Get-AzureBlobSettings {
<#

.SYNOPSIS
Get SDN ACL audit Azure Blob setting

.DESCRIPTION
This script is used to get the SDL ACL audit Azure Blob settings

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri
)

$nc = Get-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri
if ($nc.Tags) {
    $nc.Tags.BlobContainer
}

}
## [END] Get-AzureBlobSettings ##
function Get-SdnClusterInventory {
<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri
)

$nc = Get-NetworkControllerServer -ConnectionUri $uri;

# Result for getting Clusternodes
foreach($node in $nc)
{
    $resourceID = $node.ResourceId;
    $instanceID = $node.instanceId;
    $nodeName = $node.Properties.Connections[0].ManagementAddresses[0];
    $auditingEnabled = $node.Properties.AuditingEnabled.Contains("Firewall");

    $response = New-Object -TypeName psobject;
    $response | Add-Member -MemberType NoteProperty -Name 'ResourceID' -Value $resourceID -ErrorAction SilentlyContinue;
    $response | Add-Member -MemberType NoteProperty -Name 'InstanceID' -Value $instanceID -ErrorAction SilentlyContinue;
    $response | Add-Member -MemberType NoteProperty -Name 'NodeName' -Value $nodeName -ErrorAction SilentlyContinue;
    $response | Add-Member -MemberType NoteProperty -Name 'AuditingEnabled' -Value $auditingEnabled -ErrorAction SilentlyContinue;

    $response;
}

}
## [END] Get-SdnClusterInventory ##
function Get-SdnClusterNodes {
<#

.SYNOPSIS
Get all the Cluster Nodes.

.DESCRIPTION
Get the cluster nodes information for the cluster.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;
# Get hostnames 
$hostNames=Get-ClusterNode
$domainName=((Get-CIMInstance CIM_ComputerSystem).Domain)
$result = @()
# Result for getting Clusternodes
foreach($hostName in $hostnames)
{
    $result+=($hostName.name +"."+ $domainName).ToLower()
}

$result

}
## [END] Get-SdnClusterNodes ##
function Get-SdnVirtualMachineDetails {
<#

.SYNOPSIS
Get VM Details

.DESCRIPTION
This script is used to get the details of VM's

.ROLE
Readers

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $vmName

)

Import-Module Hyper-V -ErrorAction SilentlyContinue;

foreach($vm in $vmName)
{
    $virtualMachineName = $vm.appliedVirtualMachineNetworkAdapters.ToLower()
    $res = ""
    $res = Get-VM | Where {$_.name -contains $virtualMachineName}

    if($res)
    {
        #Fetch the Name of VM
        $Name = $res.Name

        #Fetch the FQDN of VM
        $hostName = ($res.ComputerName+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()

        #Fetch the VM ID
        $vmId = $res.VMId


        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'VMName' -Value $Name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hostName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VMId' -Value $vmId -ErrorAction SilentlyContinue

        $myResponse
    }
}

}
## [END] Get-SdnVirtualMachineDetails ##
function Get-SecurityTags {
<#

.SYNOPSIS
Gets a Security tag from a given network controller.

.DESCRIPTION
Gets a security tag object from the SDN Network Controller.

.ROLE
Readers

.PARAMETER uri
    The uri used to connect to the SDN Network controller

#>


param (
		[Parameter(Mandatory = $true)]
		[String]
        $uri
)

Import-Module NetworkController;

$tags = @(Get-NetworkControllerSecurityTag -ConnectionUri $uri)
$tags | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-SecurityTags ##
function New-AccessControlList {
<#

.SYNOPSIS
Create Access Control List

.DESCRIPTION
This script is used to Create Access Control List in the Cluster

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName

)
#Import Network Controller Moudule
Import-Module NetworkController -Force

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

#Create a new object for the Access Control List
$acllistproperties = new-object Microsoft.Windows.NetworkController.AccessControlListProperties

try
{
    #Add the New Access Control List
    $result = New-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName -Properties $acllistproperties -Force
}
catch
{
  throw getInnerExceptionMessage
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

}
## [END] New-AccessControlList ##
function New-AccessControlListRule {
<#

.SYNOPSIS
Create Access Control List Rule

.DESCRIPTION
This script is used to Create Access Control List Rule for Access Control List

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $priority,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    # Exactly one of these two (tags or address prefix) needs to be included
    [Parameter(Mandatory = $False)]
    [string] $sourceAddressPrefix,

    [Parameter(Mandatory = $False)]
    [string[]] $sourceTags,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $sourcePortRange,

    # Exactly one of these two (tags or address prefix) needs to be included
    [Parameter(Mandatory = $False)]
    [string] $destinationAddressPrefix,

    [Parameter(Mandatory = $False)]
    [string[]] $destinationTags,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationPortRange,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $action,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logging

)

#Create Access Control List Rule
#Import Network Controller Moudule
Import-Module NetworkController -Force

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

$parent = $null
$existing = $null
# get parent resource
try {
  $parent = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.AclRules | Where-Object {$_.ResourceId -ieq $aclRuleName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

#Create a new object for the Access Control List Rule
$ruleproperties = new-object Microsoft.Windows.NetworkController.AclRuleProperties
$ruleproperties.Priority = $priority
$ruleproperties.Type = $type
$ruleproperties.Protocol = $protocol
$ruleproperties.SourceAddressPrefix = $sourceAddressPrefix
if ($null -ne $sourceTags) {
  $ruleproperties.SourceSecurityTags = @()
  foreach ($tag in $sourceTags) {
    $ruleproperties.SourceSecurityTags += @{"resourceRef" = $tag}
  }
}
$ruleproperties.SourcePortRange = $sourcePortRange
$ruleproperties.DestinationAddressPrefix = $destinationAddressPrefix
if ($null -ne $destinationTags) {
  $ruleproperties.DestinationSecurityTags = @()
  foreach ($tag in $destinationTags) {
    $ruleproperties.DestinationSecurityTags += @{"resourceRef" = $tag}
  }
}
$ruleproperties.DestinationPortRange = $destinationPortRange
$ruleproperties.Action = $action
$ruleproperties.Logging = $logging

try
{
  #Add the New Access Control List Rule for Access Control List
  $result = New-NetworkControllerAccessControlListRule -ConnectionUri $uri -ResourceId $aclRuleName -AccessControlListId $aclName -Properties $ruleproperties -ResourceMetadata $metadata -Force
}
catch
{
  throw getInnerExceptionMessage
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-AccessControlListRule ##
function New-AuditPath {
<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $path
)

New-Item -ItemType Directory -Force -Path $path

}
## [END] New-AuditPath ##
function New-SecurityTag {
<#

.SYNOPSIS
Creates a Security tag from a given network controller.

.DESCRIPTION
Creates a security tag from the SDN Network Controller.

.ROLE
Administrators

.PARAMETER uri
    The uri used to connect to the SDN Network controller

.PARAMETER resourceId
    The name used to refer to the security tag

.PARAMETER type
    The optional type of the security tag

.PARAMETER acl
    The optional resourceRef of the security tag

#>


param (
    [Parameter(Mandatory = $true)]
    [String]
        $uri,

    [Parameter(Mandatory = $true)]
    [String]
        $resourceId,

    [Parameter(Mandatory = $false)]
    [String]
        $type,

    [Parameter(Mandatory = $false)]
    [String]
        $acl
)
Import-Module NetworkController

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

$existing = $null
# get existing resource
try {
  $existing = Get-NetworkControllerSecurityTag -ConnectionUri $uri -ResourceId $resourceId
} catch {
  # resource has not been created yet, do nothing
}
$metadata = $null
$tags = $null
if ($null -ne $existing) {
  throwIfResourceManaged $existing
  $metadata = $existing.ResourceMetadata
  $tags = $existing.Tags
}

$tagProperties = New-Object Microsoft.Windows.NetworkController.SecurityTagProperties
if ('' -ne $type) {
  $tagProperties.Type = $type
}
if ('' -ne $acl) {
  $tagProperties.AccessControlList = @{"resourceRef" = $acl}
}
try {
  New-NetworkControllerSecurityTag -ConnectionUri $uri -ResourceId $resourceId -Properties $tagProperties -ResourceMetadata $metadata -Tags $tags -Force
} catch {
  throw getInnerExceptionMessage
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-SecurityTag ##
function Remove-AccessControlList {
<#

.SYNOPSIS
Delete Access Control List

.DESCRIPTION
This script is used to Delete Access Control List in the Cluster

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName

)

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

$existing = $null
# get existing resource
try {
  $existing = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $existing

try {
  #Delete Access Control List
  Remove-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName -Force
} catch {
  throw getInnerExceptionMessage
}

try {
  #Fetch the Access Control Lists available in the Cluster
  $accessControlLists = Get-NetworkControllerAccessControlList -ConnectionUri $uri
} catch {
  throw getInnerExceptionMessage
}

#Fetch the Access Control List Names
$accessControlListNames = $accessControlLists.ResourceId

if($accessControlListNames -notcontains $aclName)
{
    $result = "Success"
}
else
{
    $result = "Failure"
}

# Preapring Object Response
$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-AccessControlList ##
function Remove-AccessControlListRule {
<#

.SYNOPSIS
Delete Access Control List Rule

.DESCRIPTION
This script is used to Delete Access Control List Rule available in the Access Control List

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $aclRuleName

)

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

$parent = $null
# get parent resource
try {
  $parent = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId $aclName
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $parent

try {
  #Delete Access Control List Rule
  Remove-NetworkControllerAccessControlListRule -ConnectionUri $uri -AccessControlListId $aclName -ResourceId $aclRuleName -Force
} catch {
  throw getInnerExceptionMessage
}

try {
  #Fetch the Access Control Lists Rules available in the Access Control List
  $accessControlListRules = Get-NetworkControllerAccessControlListRule -ConnectionUri $uri -AccessControlListId $aclName
} catch {
  throw getInnerExceptionMessage
}

#Fetch the Access Control List Rule Names
$accessControlListRuleNames = $accessControlListRules.ResourceId

if($accessControlListRuleNames -notcontains $aclRuleName)
{
    $result = "Success"
}
else
{
    $result = "Failure"
}

# Preapring Object Response
$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-AccessControlListRule ##
function Remove-AclLogs {
<#

.SYNOPSIS
Deletes ACL logs from a node on the cluster

.DESCRIPTION
Deletes ACL logs from a node on the cluster

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [String[]]
    $Files
)

foreach ($File in $Files) {
    try {
        Remove-Item -Path $File -Force
    }
    catch {
        # There is no way to handle failure here
    }
}

}
## [END] Remove-AclLogs ##
function Remove-AclLogsAfterUpload {
<#

.SYNOPSIS
Deletes ACL logs from a node on the cluster

.DESCRIPTION
Deletes ACL logs from a node on the cluster

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [String[]]
    $Files,

    [Parameter(Mandatory = $true)]
    [bool]
    $Success
)

if ($Success -eq $true) {
    foreach ($File in $Files) {
        try {
            Remove-Item -Path $File -Force
        }
        catch {
            # There is no way to handle failure here
        }
    }
}

}
## [END] Remove-AclLogsAfterUpload ##
function Remove-NetworkWatcherTempLogs {
<#

.SYNOPSIS
Deletes Azure Network watcher upload temp files.

.DESCRIPTION
Deletes Azure Network watcher upload temp files.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [String[]]
    $Files,

    [Parameter(Mandatory = $true)]
    [bool]
    $Success,

    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [String[]]
    $OriginalFiles,

    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [String[]]
    $DeleteOriginal
)

$dir = Get-Item $Files[0];
Remove-Item -Path $dir.Directory -Force -Recurse;

if ($DeleteOriginal -eq $true -and $Success -eq $true)
{
    foreach ($File in $OriginalFiles) {
        try {
            Remove-Item -Path $File -Force
        }
        catch {
            # There is no way to handle failure here
        }
    }
}

}
## [END] Remove-NetworkWatcherTempLogs ##
function Remove-SecurityTag {
<#

.SYNOPSIS
Removes a Security tag from a given network controller.

.DESCRIPTION
Removes a security tag from the SDN Network Controller.

.ROLE
Administrators

.PARAMETER uri
    The uri used to connect to the SDN Network controller

.PARAMETER resourceId
    The name used to refer to the security tag

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $uri,

    [Parameter(Mandatory = $true)]
    [String]
    $resourceId
)

Import-Module NetworkController

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

$existing = $null
# get existing resource
try {
  $existing = Get-NetworkControllerSecurityTag -ConnectionUri $uri -ResourceId $resourceId
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $existing

try {
  Remove-NetworkControllerSecurityTag -ConnectionUri $uri -ResourceId $resourceId -Force
} catch {
  throw getInnerExceptionMessage
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-SecurityTag ##
function Set-AuditEnabled {
<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $resourceID,

    [Parameter(Mandatory = $True)]
    [bool] $enable
)

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

try {
  $nc = Get-NetworkControllerServer -ConnectionUri $uri
} catch {
  throw getInnerExceptionMessage
}

# Result for getting Clusternodes
foreach ($node in $nc) {
  if ($node.ResourceId -eq $resourceID) {
    $existing = $null
    try {
      $existing = Get-NetworkControllerServer -ConnectionUri $uri -ResourceId $resourceID
    } catch {
      throw getInnerExceptionMessage
    }
    throwIfResourceManaged $existing
    $metadata = $null
    $tags = $null
    if ($null -ne $existing) {
      $metadata = $existing.ResourceMetadata
      $tags = $existing.Tags
    }

    if ($enable) {
        if (-not $node.Properties.AuditingEnabled.Contains("Firewall")) {
            $node.Properties.AuditingEnabled = $node.Properties.AuditingEnabled += "Firewall"
        }
    }
    else {
        if ($node.Properties.AuditingEnabled.Contains("Firewall")) {
            $node.Properties.AuditingEnabled = $node.Properties.AuditingEnabled -ne "Firewall"
        }
    }

    try {
      New-NetworkControllerServer -ConnectionUri $uri -ResourceId $resourceID -Properties $node.Properties -ResourceMetadata $metadata -Tags $tags -Force | Out-Null
    } catch {
      throw getInnerExceptionMessage
    }
    break
  }
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Set-AuditEnabled ##
function Set-AuditPath {
<#

.SYNOPSIS
Set SDN ACL audit path

.DESCRIPTION
This script is used to set the SDL ACL audit path

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $path
)

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

try {
  $nc = Get-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $nc

$nc.Properties.OutputDirectory = $path

try {
  Set-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri -ResourceId $nc.ResourceId -Properties $nc.Properties -ResourceMetadata $nc.ResourceMetadata -Tags $nc.Tags -Force
} catch {
  throw getInnerExceptionMessage
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Set-AuditPath ##
function Set-SdnAclAzureBlobSettings {
<#

.SYNOPSIS
Set SDN ACL audit Azure Blob setting

.DESCRIPTION
This script is used to set the SDL ACL audit Azure Blob settings

.ROLE
Administrators

#>
Param
(

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $uri,

    [Parameter()]
    [string] $blobSubscription,

    [Parameter()]
    [string] $blobStorageAccount,

    [Parameter()]
    [string] $blobContainer
)

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

# get inner exception message of error
function getInnerExceptionMessage() {
  $ex = $_.Exception
  while ($null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  $message = $ex.Message
  try {
    # check if error message is in json format
    $message = ($message | ConvertFrom-Json).error.message
  } catch {
    # do nothing
  }
  $message
}

# check if resource is managed
function throwIfResourceManaged($resource) {
  $metadata = $null
  if ($null -ne $resource) {
    $metadata = $resource.ResourceMetadata
    if ($null -ne $metadata -and $Clients.Contains($metadata.Client)) {
      throw @{client = $metadata.Client; resourceId = $resource.ResourceId} | ConvertTo-Json
    }
  }
}

try {
  $nc = Get-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri
} catch {
  throw getInnerExceptionMessage
}
throwIfResourceManaged $nc

if ($Null -eq $nc.Tags) {
    $nc.Tags = @{}
}

$nc.Tags.BlobContainer = $blobContainer

try {
  Set-NetworkControllerAuditingSettingsConfiguration -ConnectionUri $uri -ResourceId $nc.ResourceId -Properties $nc.Properties -ResourceMetadata $nc.ResourceMetadata -Tags $nc.Tags -Force
} catch {
  throw getInnerExceptionMessage
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Set-SdnAclAzureBlobSettings ##
function Get-CimWin32LogicalDisk {
<#

.SYNOPSIS
Gets Win32_LogicalDisk object.

.DESCRIPTION
Gets Win32_LogicalDisk object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_LogicalDisk

}
## [END] Get-CimWin32LogicalDisk ##
function Get-CimWin32NetworkAdapter {
<#

.SYNOPSIS
Gets Win32_NetworkAdapter object.

.DESCRIPTION
Gets Win32_NetworkAdapter object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_NetworkAdapter

}
## [END] Get-CimWin32NetworkAdapter ##
function Get-CimWin32PhysicalMemory {
<#

.SYNOPSIS
Gets Win32_PhysicalMemory object.

.DESCRIPTION
Gets Win32_PhysicalMemory object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PhysicalMemory

}
## [END] Get-CimWin32PhysicalMemory ##
function Get-CimWin32Processor {
<#

.SYNOPSIS
Gets Win32_Processor object.

.DESCRIPTION
Gets Win32_Processor object.

.ROLE
Readers

#>
##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Processor

}
## [END] Get-CimWin32Processor ##
function Get-ClusterInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a cluster.

.DESCRIPTION
Retrieves the inventory data for a cluster.

.ROLE
Readers

#>

Import-Module CimCmdlets -ErrorAction SilentlyContinue

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
Import-Module FailoverClusters -ErrorAction SilentlyContinue

Import-Module Storage -ErrorAction SilentlyContinue
<#

.SYNOPSIS
Get the name of this computer.

.DESCRIPTION
Get the best available name for this computer.  The FQDN is preferred, but when not avaialble
the NetBIOS name will be used instead.

#>

function getComputerName() {
    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, DNSHostName

    if ($computerSystem) {
        $computerName = $computerSystem.DNSHostName

        if ($null -eq $computerName) {
            $computerName = $computerSystem.Name
        }

        return $computerName
    }

    return $null
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
Get the MSCluster Cluster CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster CIM instance from this server.

#>
function getClusterCimInstance() {
    $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    if ($namespace) {
        return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object fqdn, S2DEnabled
    }

    return $null
}


<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB
is supported or not.

#>
function getClusterPerformanceHistoryPath() {
    $storageSubsystem = Get-StorageSubSystem clus* -ErrorAction SilentlyContinue
    $storageHealthSettings = Get-StorageHealthSetting -InputObject $storageSubsystem -Name "System.PerformanceHistory.Path" -ErrorAction SilentlyContinue

    return $null -ne $storageHealthSettings
}

<#

.SYNOPSIS
Get some basic information about the cluster from the cluster.

.DESCRIPTION
Get the needed cluster properties from the cluster.

#>
function getClusterInfo() {
    $returnValues = @{}

    $returnValues.Fqdn = $null
    $returnValues.isS2DEnabled = $false
    $returnValues.isTsdbEnabled = $false

    $cluster = getClusterCimInstance
    if ($cluster) {
        $returnValues.Fqdn = $cluster.fqdn
        $isS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -eq 1)
        $returnValues.isS2DEnabled = $isS2dEnabled

        if ($isS2DEnabled) {
            $returnValues.isTsdbEnabled = getClusterPerformanceHistoryPath
        } else {
            $returnValues.isTsdbEnabled = $false
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Are the cluster PowerShell Health cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell Health cmdlets installed on this server?

s#>
function getisClusterHealthCmdletAvailable() {
    $cmdlet = Get-Command -Name "Get-HealthFault" -ErrorAction SilentlyContinue

    return !!$cmdlet
}
<#

.SYNOPSIS
Are the Britannica (sddc management resources) available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) available on the cluster?

#>
function getIsBritannicaEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual machine available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual machine available on the cluster?

#>
function getIsBritannicaVirtualMachineEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual switch available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual switch available on the cluster?

#>
function getIsBritannicaVirtualSwitchEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue)
}

###########################################################################
# main()
###########################################################################

$clusterInfo = getClusterInfo

$result = New-Object PSObject

$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $clusterInfo.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2DEnabled' -Value $clusterInfo.isS2DEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInfo.isTsdbEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterHealthCmdletAvailable' -Value (getIsClusterHealthCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value (getIsBritannicaEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualMachineEnabled' -Value (getIsBritannicaVirtualMachineEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualSwitchEnabled' -Value (getIsBritannicaVirtualSwitchEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterCmdletAvailable' -Value (getIsClusterCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'CurrentClusterNode' -Value (getComputerName)

$result

}
## [END] Get-ClusterInventory ##
function Get-ClusterNodes {
<#

.SYNOPSIS
Retrieves the inventory data for cluster nodes in a particular cluster.

.DESCRIPTION
Retrieves the inventory data for cluster nodes in a particular cluster.

.ROLE
Readers

#>

import-module CimCmdlets

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
import-module FailoverClusters -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value $MyInvocation.ScriptName -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed?

.DESCRIPTION
Use the Get-Command cmdlet to quickly test if the cluster PowerShell cmdlets
are installed on this server.

#>

function getClusterPowerShellSupport() {
    $cmdletInfo = Get-Command 'Get-ClusterNode' -ErrorAction SilentlyContinue

    return $cmdletInfo -and $cmdletInfo.Name -eq "Get-ClusterNode"
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster CIM provider.

.DESCRIPTION
When the cluster PowerShell cmdlets are not available fallback to using
the cluster CIM provider to get the needed information.

#>

function getClusterNodeCimInstances() {
    # Change the WMI property NodeDrainStatus to DrainStatus to match the PS cmdlet output.
    return Get-CimInstance -Namespace root/mscluster MSCluster_Node -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object @{Name="DrainStatus"; Expression={$_.NodeDrainStatus}}, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster PowerShell cmdlets.

.DESCRIPTION
When the cluster PowerShell cmdlets are available use this preferred function.

#>

function getClusterNodePsInstances() {
    return Get-ClusterNode -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object DrainStatus, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Use DNS services to get the FQDN of the cluster NetBIOS name.

.DESCRIPTION
Use DNS services to get the FQDN of the cluster NetBIOS name.

.Notes
It is encouraged that the caller add their approprate -ErrorAction when
calling this function.

#>

function getClusterNodeFqdn([string]$clusterNodeName) {
    return ([System.Net.Dns]::GetHostEntry($clusterNodeName)).HostName
}

<#

.SYNOPSIS
Writes message to event log as warning.

.DESCRIPTION
Writes message to event log as warning.

#>

function writeToEventLog([string]$message) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message $message  -ErrorAction SilentlyContinue
}

<#

.SYNOPSIS
Get the cluster nodes.

.DESCRIPTION
When the cluster PowerShell cmdlets are available get the information about the cluster nodes
using PowerShell.  When the cmdlets are not available use the Cluster CIM provider.

#>

function getClusterNodes() {
    $isClusterCmdletAvailable = getClusterPowerShellSupport

    if ($isClusterCmdletAvailable) {
        $clusterNodes = getClusterNodePsInstances
    } else {
        $clusterNodes = getClusterNodeCimInstances
    }

    $clusterNodeMap = @{}

    foreach ($clusterNode in $clusterNodes) {
        $clusterNodeName = $clusterNode.Name.ToLower()
        try 
        {
            $clusterNodeFqdn = getClusterNodeFqdn $clusterNodeName -ErrorAction SilentlyContinue
        }
        catch 
        {
            $clusterNodeFqdn = $clusterNodeName
            writeToEventLog "[$ScriptName]: The fqdn for node '$clusterNodeName' could not be obtained. Defaulting to machine name '$clusterNodeName'"
        }

        $clusterNodeResult = New-Object PSObject

        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FullyQualifiedDomainName' -Value $clusterNodeFqdn
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'Name' -Value $clusterNodeName
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DynamicWeight' -Value $clusterNode.DynamicWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'NodeWeight' -Value $clusterNode.NodeWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FaultDomain' -Value $clusterNode.FaultDomain
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'State' -Value $clusterNode.State
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DrainStatus' -Value $clusterNode.DrainStatus

        $clusterNodeMap.Add($clusterNodeName, $clusterNodeResult)
    }

    return $clusterNodeMap
}

###########################################################################
# main()
###########################################################################

getClusterNodes

}
## [END] Get-ClusterNodes ##
function Get-DecryptedDataFromNode {
<#

.SYNOPSIS
Gets data after decrypting it on a node.

.DESCRIPTION
Decrypts data on node using a cached RSAProvider used during encryption within 3 minutes of encryption and returns the decrypted data.
This script should be imported or copied directly to other scripts, do not send the returned data as an argument to other scripts.

.PARAMETER encryptedData
Encrypted data to be decrypted (String).

.ROLE
Readers

#>
param (
  [Parameter(Mandatory = $true)]
  [String]
  $encryptedData
)

Set-StrictMode -Version 5.0

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  # If you copy this script directly to another, you can get rid of the throw statement and add custom error handling logic such as "Write-Error"
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

}
## [END] Get-DecryptedDataFromNode ##
function Get-EncryptionJWKOnNode {
<#

.SYNOPSIS
Gets encrytion JSON web key from node.

.DESCRIPTION
Gets encrytion JSON web key from node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function Get-RSAProvider
{
    if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue)
    {
        return (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    }

    $Global:RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 4096
    return $RSA
}

function Get-JsonWebKey
{
    $rsaProvider = Get-RSAProvider
    $parameters = $rsaProvider.ExportParameters($false)
    return [PSCustomObject]@{
        kty = 'RSA'
        alg = 'RSA-OAEP'
        e = [Convert]::ToBase64String($parameters.Exponent)
        n = [Convert]::ToBase64String($parameters.Modulus).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
}

$jwk = Get-JsonWebKey
ConvertTo-Json $jwk -Compress

}
## [END] Get-EncryptionJWKOnNode ##
function Get-ServerInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a server.

.DESCRIPTION
Retrieves the inventory data for a server.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets

Import-Module Storage -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Converts an arbitrary version string into just 'Major.Minor'

.DESCRIPTION
To make OS version comparisons we only want to compare the major and
minor version.  Build number and/os CSD are not interesting.

#>

function convertOsVersion([string]$osVersion) {
  [Ref]$parsedVersion = $null
  if (![Version]::TryParse($osVersion, $parsedVersion)) {
    return $null
  }

  $version = [Version]$parsedVersion.Value
  return New-Object Version -ArgumentList $version.Major, $version.Minor
}

<#

.SYNOPSIS
Determines if CredSSP is enabled for the current server or client.

.DESCRIPTION
Check the registry value for the CredSSP enabled state.

#>

function isCredSSPEnabled() {
  Set-Variable credSSPServicePath -Option Constant -Value "WSMan:\localhost\Service\Auth\CredSSP"
  Set-Variable credSSPClientPath -Option Constant -Value "WSMan:\localhost\Client\Auth\CredSSP"

  $credSSPServerEnabled = $false;
  $credSSPClientEnabled = $false;

  $credSSPServerService = Get-Item $credSSPServicePath -ErrorAction SilentlyContinue
  if ($credSSPServerService) {
    $credSSPServerEnabled = [System.Convert]::ToBoolean($credSSPServerService.Value)
  }

  $credSSPClientService = Get-Item $credSSPClientPath -ErrorAction SilentlyContinue
  if ($credSSPClientService) {
    $credSSPClientEnabled = [System.Convert]::ToBoolean($credSSPClientService.Value)
  }

  return ($credSSPServerEnabled -or $credSSPClientEnabled)
}

<#

.SYNOPSIS
Determines if the Hyper-V role is installed for the current server or client.

.DESCRIPTION
The Hyper-V role is installed when the VMMS service is available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>

function isHyperVRoleInstalled() {
  $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue

  return $vmmsService -and $vmmsService.Name -eq "VMMS"
}

<#

.SYNOPSIS
Determines if the Hyper-V PowerShell support module is installed for the current server or client.

.DESCRIPTION
The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>
function isHyperVPowerShellSupportInstalled() {
  # quicker way to find the module existence. it doesn't load the module.
  return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.

.DESCRIPTION
Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
Windows Server 2016.

#>
function isWMF5Installed([string] $operatingSystemVersion) {
  Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
  Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')

  $version = convertOsVersion $operatingSystemVersion
  if (-not $version) {
    # Since the OS version string is not properly formatted we cannot know the true installed state.
    return $false
  }

  if ($version -ge $Server2016) {
    # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
    return $true
  }
  else {
    if ($version -ge $Server2012) {
      # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
      $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
      $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue

      if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
        $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion

        if ($installedWmfVersion -ge [Version]'5.0') {
          return $true
        }
      }
    }
  }

  return $false
}

<#

.SYNOPSIS
Determines if the current usser is a system administrator of the current server or client.

.DESCRIPTION
Determines if the current usser is a system administrator of the current server or client.

#>
function isUserAnAdministrator() {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

<#

.SYNOPSIS
Get some basic information about the Failover Cluster that is running on this server.

.DESCRIPTION
Create a basic inventory of the Failover Cluster that may be running in this server.

#>
function getClusterInformation() {
  $returnValues = @{ }

  $returnValues.IsS2dEnabled = $false
  $returnValues.IsCluster = $false
  $returnValues.ClusterFqdn = $null
  $returnValues.IsBritannicaEnabled = $false

  $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
  if ($namespace) {
    $cluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction SilentlyContinue
    if ($cluster) {
      $returnValues.IsCluster = $true
      $returnValues.ClusterFqdn = $cluster.Fqdn
      $returnValues.IsS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -gt 0)
      $returnValues.IsBritannicaEnabled = $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
    }
  }

  return $returnValues
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

#>
function getComputerFqdnAndAddress($computerName) {
  $hostEntry = [System.Net.Dns]::GetHostEntry($computerName)
  $addressList = @()
  foreach ($item in $hostEntry.AddressList) {
    $address = New-Object PSObject
    $address | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $item.ToString()
    $address | Add-Member -MemberType NoteProperty -Name 'AddressFamily' -Value $item.AddressFamily.ToString()
    $addressList += $address
  }

  $result = New-Object PSObject
  $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $hostEntry.HostName
  $result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $addressList
  return $result
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

#>
function getHostFqdnAndAddress($computerSystem) {
  $computerName = $computerSystem.DNSHostName
  if (!$computerName) {
    $computerName = $computerSystem.Name
  }

  return getComputerFqdnAndAddress $computerName
}

<#

.SYNOPSIS
Are the needed management CIM interfaces available on the current server or client.

.DESCRIPTION
Check for the presence of the required server management CIM interfaces.

#>
function getManagementToolsSupportInformation() {
  $returnValues = @{ }

  $returnValues.ManagementToolsAvailable = $false
  $returnValues.ServerManagerAvailable = $false

  $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue

  if ($namespaces) {
    $returnValues.ManagementToolsAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ManagementTools" })
    $returnValues.ServerManagerAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ServerManager" })
  }

  return $returnValues
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>
function isRemoteAppEnabled() {
  Set-Variable key -Option Constant -Value "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\TSAppAllowList"

  $registryKeyValue = Get-ItemProperty -Path $key -Name fDisabledAllowList -ErrorAction SilentlyContinue

  if (-not $registryKeyValue) {
    return $false
  }
  return $registryKeyValue.fDisabledAllowList -eq 1
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>

<#
c
.SYNOPSIS
Get the Win32_OperatingSystem information as well as current version information from the registry

.DESCRIPTION
Get the Win32_OperatingSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller. Included in the results are current version
information from the registry

#>
function getOperatingSystemInfo() {
  $operatingSystemInfo = Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType, OSType, LastBootUpTime, SerialNumber
  $currentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Microsoft.PowerShell.Utility\Select-Object CurrentBuild, UBR, DisplayVersion, InstallationType

  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name CurrentBuild -Value $currentVersion.CurrentBuild
  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name UpdateBuildRevision -Value $currentVersion.UBR
  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name DisplayVersion -Value $currentVersion.DisplayVersion
  $operatingSystemInfo | Add-Member -MemberType NoteProperty -Name InstallationType -Value $currentVersion.InstallationType

  return $operatingSystemInfo
}

<#

.SYNOPSIS
Get the Win32_ComputerSystem information

.DESCRIPTION
Get the Win32_ComputerSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller.

#>
function getComputerSystemInfo() {
  return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
    Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain, SystemFamily, SystemSKUNumber
}

<#

.SYNOPSIS
Get SMBIOS locally from the passed in machineName


.DESCRIPTION
Get SMBIOS locally from the passed in machine name

#>
function getSmbiosData($computerSystem) {
  <#
    Array of chassis types.
    The following list of ChassisTypes is copied from the latest DMTF SMBIOS specification.
    REF: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf
  #>
  $ChassisTypes =
  @{
    1  = 'Other'
    2  = 'Unknown'
    3  = 'Desktop'
    4  = 'Low Profile Desktop'
    5  = 'Pizza Box'
    6  = 'Mini Tower'
    7  = 'Tower'
    8  = 'Portable'
    9  = 'Laptop'
    10 = 'Notebook'
    11 = 'Hand Held'
    12 = 'Docking Station'
    13 = 'All in One'
    14 = 'Sub Notebook'
    15 = 'Space-Saving'
    16 = 'Lunch Box'
    17 = 'Main System Chassis'
    18 = 'Expansion Chassis'
    19 = 'SubChassis'
    20 = 'Bus Expansion Chassis'
    21 = 'Peripheral Chassis'
    22 = 'Storage Chassis'
    23 = 'Rack Mount Chassis'
    24 = 'Sealed-Case PC'
    25 = 'Multi-system chassis'
    26 = 'Compact PCI'
    27 = 'Advanced TCA'
    28 = 'Blade'
    29 = 'Blade Enclosure'
    30 = 'Tablet'
    31 = 'Convertible'
    32 = 'Detachable'
    33 = 'IoT Gateway'
    34 = 'Embedded PC'
    35 = 'Mini PC'
    36 = 'Stick PC'
  }

  $list = New-Object System.Collections.ArrayList
  $win32_Bios = Get-CimInstance -class Win32_Bios
  $obj = New-Object -Type PSObject | Microsoft.PowerShell.Utility\Select-Object SerialNumber, Manufacturer, UUID, BaseBoardProduct, ChassisTypes, Chassis, SystemFamily, SystemSKUNumber, SMBIOSAssetTag
  $obj.SerialNumber = $win32_Bios.SerialNumber
  $obj.Manufacturer = $win32_Bios.Manufacturer
  $computerSystemProduct = Get-CimInstance Win32_ComputerSystemProduct
  if ($null -ne $computerSystemProduct) {
    $obj.UUID = $computerSystemProduct.UUID
  }
  $baseboard = Get-CimInstance Win32_BaseBoard
  if ($null -ne $baseboard) {
    $obj.BaseBoardProduct = $baseboard.Product
  }
  $systemEnclosure = Get-CimInstance Win32_SystemEnclosure
  if ($null -ne $systemEnclosure) {
    $obj.SMBIOSAssetTag = $systemEnclosure.SMBIOSAssetTag
  }
  $obj.ChassisTypes = Get-CimInstance Win32_SystemEnclosure | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty ChassisTypes
  $obj.Chassis = New-Object -TypeName 'System.Collections.ArrayList'
  $obj.ChassisTypes | ForEach-Object -Process {
    $obj.Chassis.Add($ChassisTypes[[int]$_])
  }
  $obj.SystemFamily = $computerSystem.SystemFamily
  $obj.SystemSKUNumber = $computerSystem.SystemSKUNumber
  $list.Add($obj) | Out-Null

  return $list

}

<#

.SYNOPSIS
Get the azure arc status information

.DESCRIPTION
Get the azure arc status information

#>
function getAzureArcStatus() {

  $LogName = "WindowsAdminCenter"
  $LogSource = "SMEScript"
  $ScriptName = "Get-ServerInventory.ps1 - getAzureArcStatus()"
  $AzcmagentExecutable = "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe"

  Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  $service = Get-Service -Name himds -ErrorVariable Err -ErrorAction SilentlyContinue
  if (!!$Err) {
    $Err = "Failed to retrieve HIMDS service. Details: $Err"

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message "[$ScriptName]: $Err" -ErrorAction SilentlyContinue

    return "NotInstalled"
  } elseif ($service.Status -ne "Running") {
    $Err = "The Azure arc agent is not running. Details: HIMDS service is $($service.Status)"

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message "[$ScriptName]: $Err" -ErrorAction SilentlyContinue

    return "Disconnected"
  }

  $rawStatus = Invoke-Command { & $AzcmagentExecutable show --json --log-stderr } -ErrorVariable Err 2>$null
  if (!!$Err) {
    $Err = "The Azure arc agent failed to communicate. Details: $rawStatus"

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
    -Message "[$ScriptName]: $Err" -ErrorAction SilentlyContinue

    return "Disconnected"
  }

  if (!$rawStatus) {
    $Err = "The Azure arc agent is not connected. Details: $rawStatus"

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
    -Message "[$ScriptName]: $Err" -ErrorAction SilentlyContinue

    return "Disconnected"
  }

  return ($rawStatus | ConvertFrom-Json -ErrorAction Stop).status
}

<#

.SYNOPSIS
Gets an EnforcementMode that describes the system lockdown policy on this computer.

.DESCRIPTION
By checking the system lockdown policy, we can infer if PowerShell is in ConstrainedLanguage mode as a result of an enforced WDAC policy.
Note: $ExecutionContext.SessionState.LanguageMode should not be used within a trusted (by the WDAC policy) script context for this purpose because
the language mode returned would potentially not reflect the system-wide lockdown policy/language mode outside of the execution context.

#>
function getSystemLockdownPolicy() {
  return [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy().ToString()
}

<#

.SYNOPSIS
Determines if the operating system is HCI.

.DESCRIPTION
Using the operating system 'Caption' (which corresponds to the 'ProductName' registry key at HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion) to determine if a server OS is HCI.

#>
function isServerOsHCI([string] $operatingSystemCaption) {
  return $operatingSystemCaption -eq "Microsoft Azure Stack HCI"
}

###########################################################################
# main()
###########################################################################

$operatingSystem = getOperatingSystemInfo
$computerSystem = getComputerSystemInfo
$isAdministrator = isUserAnAdministrator
$fqdnAndAddress = getHostFqdnAndAddress $computerSystem
$hostname = [Environment]::MachineName
$netbios = $env:ComputerName
$managementToolsInformation = getManagementToolsSupportInformation
$isWmfInstalled = isWMF5Installed $operatingSystem.Version
$clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
$isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
$isHyperVRoleInstalled = isHyperVRoleInstalled
$isCredSSPEnabled = isCredSSPEnabled
$isRemoteAppEnabled = isRemoteAppEnabled
$smbiosData = getSmbiosData $computerSystem
$azureArcStatus = getAzureArcStatus
$systemLockdownPolicy = getSystemLockdownPolicy
$isHciServer = isServerOsHCI $operatingSystem.Caption

$result = New-Object PSObject
$result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
$result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
$result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdnAndAddress.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $fqdnAndAddress.AddressList
$result | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $hostname
$result | Add-Member -MemberType NoteProperty -Name 'NetBios' -Value $netbios
$result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
$result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2dEnabled' -Value $clusterInformation.IsS2dEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value $clusterInformation.IsBritannicaEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsRemoteAppEnabled' -Value $isRemoteAppEnabled
$result | Add-Member -MemberType NoteProperty -Name 'SmbiosData' -Value $smbiosData
$result | Add-Member -MemberType NoteProperty -Name 'AzureArcStatus' -Value $azureArcStatus
$result | Add-Member -MemberType NoteProperty -Name 'SystemLockdownPolicy' -Value $systemLockdownPolicy
$result | Add-Member -MemberType NoteProperty -Name 'IsHciServer' -Value $isHciServer

$result

}
## [END] Get-ServerInventory ##

# SIG # Begin signature block
# MIIoOQYJKoZIhvcNAQcCoIIoKjCCKCYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCobKsE36df653a
# H2bJW4YGl7Gr42+J3SZskfH+EsFGYaCCDYUwggYDMIID66ADAgECAhMzAAAEA73V
# lV0POxitAAAAAAQDMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTEzWhcNMjUwOTExMjAxMTEzWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCfdGddwIOnbRYUyg03O3iz19XXZPmuhEmW/5uyEN+8mgxl+HJGeLGBR8YButGV
# LVK38RxcVcPYyFGQXcKcxgih4w4y4zJi3GvawLYHlsNExQwz+v0jgY/aejBS2EJY
# oUhLVE+UzRihV8ooxoftsmKLb2xb7BoFS6UAo3Zz4afnOdqI7FGoi7g4vx/0MIdi
# kwTn5N56TdIv3mwfkZCFmrsKpN0zR8HD8WYsvH3xKkG7u/xdqmhPPqMmnI2jOFw/
# /n2aL8W7i1Pasja8PnRXH/QaVH0M1nanL+LI9TsMb/enWfXOW65Gne5cqMN9Uofv
# ENtdwwEmJ3bZrcI9u4LZAkujAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU6m4qAkpz4641iK2irF8eWsSBcBkw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMjkyNjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AFFo/6E4LX51IqFuoKvUsi80QytGI5ASQ9zsPpBa0z78hutiJd6w154JkcIx/f7r
# EBK4NhD4DIFNfRiVdI7EacEs7OAS6QHF7Nt+eFRNOTtgHb9PExRy4EI/jnMwzQJV
# NokTxu2WgHr/fBsWs6G9AcIgvHjWNN3qRSrhsgEdqHc0bRDUf8UILAdEZOMBvKLC
# rmf+kJPEvPldgK7hFO/L9kmcVe67BnKejDKO73Sa56AJOhM7CkeATrJFxO9GLXos
# oKvrwBvynxAg18W+pagTAkJefzneuWSmniTurPCUE2JnvW7DalvONDOtG01sIVAB
# +ahO2wcUPa2Zm9AiDVBWTMz9XUoKMcvngi2oqbsDLhbK+pYrRUgRpNt0y1sxZsXO
# raGRF8lM2cWvtEkV5UL+TQM1ppv5unDHkW8JS+QnfPbB8dZVRyRmMQ4aY/tx5x5+
# sX6semJ//FbiclSMxSI+zINu1jYerdUwuCi+P6p7SmQmClhDM+6Q+btE2FtpsU0W
# +r6RdYFf/P+nK6j2otl9Nvr3tWLu+WXmz8MGM+18ynJ+lYbSmFWcAj7SYziAfT0s
# IwlQRFkyC71tsIZUhBHtxPliGUu362lIO0Lpe0DOrg8lspnEWOkHnCT5JEnWCbzu
# iVt8RX1IV07uIveNZuOBWLVCzWJjEGa+HhaEtavjy6i7MIIHejCCBWKgAwIBAgIK
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGgowghoGAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAQDvdWVXQ87GK0AAAAA
# BAMwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIK0v
# n7XUCkHBwh2oTVesE/R02OgHcGQS7ady8woBJSYaMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAmW5DtTfmpnL0ovyMp4fegPXvB5k5FKUUSpfJ
# lhLl6ja/Zr1YOujiT33/BsQMn+yLTeic2aYtEnU3hQ1acnQkmT5AFx8De722zCOY
# 3xAj3iMVFqzCtn4eFPdiefoLxP3thyxb4OBPLBslf9URovJlPFWwi7CC1P5gyahx
# ChgKq7PoFedhFuQFlHGlJk3MkJPsNQVm6uxnbkr7NOed2XdLEV++6cr/JFhe8fnP
# bfCWHm7TuSq8bEdLLM7uRprqqHd3Jx//Iw625OPmof/vzwhzhx6AQ97qBLOWyzpX
# JVtAWj47w4TK7YBBt02RBEZOZilIZepl+dH+W12VOazVXt1anqGCF5QwgheQBgor
# BgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCALGdhkIv26T68KPJEWIjUATWYhS0YdaZGe
# vZTch+9NAAIGZz81TL+TGBMyMDI0MTIwNTE5NDY1OS4xNDZaMASAAgH0oIHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046N0YwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgITMwAAAfAqfB1ZO+YfrQAB
# AAAB8DANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDAeFw0yMzEyMDYxODQ1NTFaFw0yNTAzMDUxODQ1NTFaMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0YwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC1Hi1Tozh3O0czE8xfRnry
# mlJNCaGWommPy0eINf+4EJr7rf8tSzlgE8Il4Zj48T5fTTOAh6nITRf2lK7+upcn
# Z/xg0AKoDYpBQOWrL9ObFShylIHfr/DQ4PsRX8GRtInuJsMkwSg63bfB4Q2UikME
# P/CtZHi8xW5XtAKp95cs3mvUCMvIAA83Jr/UyADACJXVU4maYisczUz7J111eD1K
# rG9mQ+ITgnRR/X2xTDMCz+io8ZZFHGwEZg+c3vmPp87m4OqOKWyhcqMUupPveO/g
# QC9Rv4szLNGDaoePeK6IU0JqcGjXqxbcEoS/s1hCgPd7Ux6YWeWrUXaxbb+JosgO
# azUgUGs1aqpnLjz0YKfUqn8i5TbmR1dqElR4QA+OZfeVhpTonrM4sE/MlJ1JLpR2
# FwAIHUeMfotXNQiytYfRBUOJHFeJYEflZgVk0Xx/4kZBdzgFQPOWfVd2NozXlC2e
# pGtUjaluA2osOvQHZzGOoKTvWUPX99MssGObO0xJHd0DygP/JAVp+bRGJqa2u7Aq
# Lm2+tAT26yI5veccDmNZsg3vDh1HcpCJa9QpRW/MD3a+AF2ygV1sRnGVUVG3VODX
# 3BhGT8TMU/GiUy3h7ClXOxmZ+weCuIOzCkTDbK5OlAS8qSPpgp+XGlOLEPaM31Mg
# f6YTppAaeP0ophx345ohtwIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFNCCsqdXRy/M
# mjZGVTAvx7YFWpslMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQA4IvSbnr4jEPgo
# 5W4xj3/+0dCGwsz863QGZ2mB9Z4SwtGGLMvwfsRUs3NIlPD/LsWAxdVYHklAzwLT
# wQ5M+PRdy92DGftyEOGMHfut7Gq8L3RUcvrvr0AL/NNtfEpbAEkCFzseextY5s3h
# zj3rX2wvoBZm2ythwcLeZmMgHQCmjZp/20fHWJgrjPYjse6RDJtUTlvUsjr+878/
# t+vrQEIqlmebCeEi+VQVxc7wF0LuMTw/gCWdcqHoqL52JotxKzY8jZSQ7ccNHhC4
# eHGFRpaKeiSQ0GXtlbGIbP4kW1O3JzlKjfwG62NCSvfmM1iPD90XYiFm7/8mgR16
# AmqefDsfjBCWwf3qheIMfgZzWqeEz8laFmM8DdkXjuOCQE/2L0TxhrjUtdMkATfX
# dZjYRlscBDyr8zGMlprFC7LcxqCXlhxhtd2CM+mpcTc8RB2D3Eor0UdoP36Q9r4X
# WCVV/2Kn0AXtvWxvIfyOFm5aLl0eEzkhfv/XmUlBeOCElS7jdddWpBlQjJuHHUHj
# OVGXlrJT7X4hicF1o23x5U+j7qPKBceryP2/1oxfmHc6uBXlXBKukV/QCZBVAiBM
# YJhnktakWHpo9uIeSnYT6Qx7wf2RauYHIER8SLRmblMzPOs+JHQzrvh7xStx310L
# Op+0DaOXs8xjZvhpn+WuZij5RmZijDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKb
# SZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIy
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXI
# yjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjo
# YH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1y
# aa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v
# 3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pG
# ve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viS
# kR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYr
# bqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlM
# jgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSL
# W6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AF
# emzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIu
# rQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIE
# FgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
# 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
# MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2
# LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv
# 6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZn
# OlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1
# bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4
# rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU
# 6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDF
# NLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/
# HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdU
# CbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKi
# excdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTm
# dHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZq
# ELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJp
# Y2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjdGMDAtMDVF
# MC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMK
# AQEwBwYFKw4DAhoDFQDCKAZKKv5lsdC2yoMGKYiQy79p/6CBgzCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA6vwnvDAi
# GA8yMDI0MTIwNTEzMjMwOFoYDzIwMjQxMjA2MTMyMzA4WjB0MDoGCisGAQQBhFkK
# BAExLDAqMAoCBQDq/Ce8AgEAMAcCAQACAgUJMAcCAQACAhKoMAoCBQDq/Xk8AgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAAWqCV8fLMM+as96Zvxkj4vfJ/Cg
# DPZZCZYDiGdzhjsJTlhEjEYCtByoM8QlWQf8rkYhZFf5ygmzOaz+8nAO67u08Zit
# hXhoX2HkikOGNF+aahCqur7p/iXFHVe6h0H6jabAc41MC/NE+FSJwVEu9XAjrAHK
# XqORffA5BDqPYP5FEVzIEISyozU9b3ODIT5Wjj+JxGyjvDn9PHI5pqkRmJEH5e3I
# UmWqbZ9sOLj9hoD7loWTPd4UpZM95tttmjI5DY6B/++6MUS8txDIqz70NKnT6QCI
# gOXWOkzaYPos9U0HJUWJ2M0ka6Z1cMg6q3K2bMV0xXr/ReVbjLlKLcrpagUxggQN
# MIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfAq
# fB1ZO+YfrQABAAAB8DANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0G
# CyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCUGOWC26YTBmTT6hS+Ju7Y54bC
# N3tfb0JCFxb2KuNbMjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIFwBmqOl
# cv3kU7mAB5sWR74QFAiS6mb+CM6asnFAZUuLMIGYMIGApH4wfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHwKnwdWTvmH60AAQAAAfAwIgQghLCud4ui
# dAddmBPS7k5gWohJySpLGHTaQuh/us5+5F8wDQYJKoZIhvcNAQELBQAEggIAlmUq
# bJH2lnkZg67rPlvTxTao/l0Hqp0OTW1cxyOBgw4ADMG7e2nPOVoOTIRGMcY6tbm6
# SdEMwrN48S8wOXBo2Wkwcu6gRPacLPMMrZte87o/dmDjJ4IalUBpfrE603KCKqvi
# v3Dihcg6ZZCaN4qxWVLdRkw0oGFw1pCYpFuxwhh63zsEf4Bxe0pp+/bFmxsO8Y1Y
# NQGJlr6dTuPbKE1fLZBCrAnJiyUEiLcsVwXw14STlqEJECV9+FOfaEcHeJ/XoBwn
# iNlzVzoCziQ71vnQD08sgUIHIxaGZWeghRkYbB17hfFTXchaVWUrItnzGUnuIXlQ
# ZT41r9gpAB6CFscDa0mE2S080f5XqU5jLl0NG1YdGGk/oaO7lJ1HDXLhZDZty/FF
# sMpm3xkyRr/L8VhzKaBtUVU1XrYPqBFFrnlg/QPzDAD2SOIbJCmanrorajZ+PCYu
# 3qxyUZoybJXVGcHeATwHT7KtSGIBG/dmrmWTqNJ0urSQ1sFzwYYerwcVdn6ihJgu
# W3TIauax40GOrnzYfuYylA4nIbAqNQgvO+vT4522aENbc/AlT+lj0CJmbSKMnj9A
# BJ0Jz8/HepHkercGGLINZncqJfiBZNY57rUu1crxOujxQJoBi8AO80trk45wfIAY
# aJc1/o52cD0AABeUeIMaG7iwS/pf4DgJXJClTkA=
# SIG # End signature block
