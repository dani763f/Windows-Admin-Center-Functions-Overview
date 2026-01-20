function Add-WACSDDCAzStackHCIVMAttestation {
<#

.SYNOPSIS
Calls add-azstackHCI on specified nodes
.DESCRIPTION
Calls add-azstackHCI on specified nodes
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmName
  )

  try {
    $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

    if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
    }
    else
    {
      Import-Module $module -ErrorAction Stop
    }
  }
  catch {
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }


#  if vm name supplied, add just the single vm, else add all vms
$err = $null
$result = $null
try
{
    $result = Add-AzStackHCIVMAttestation -VMName $vmName -Force -ErrorAction Stop # add a single vm on this node

}
catch {
  $err = $_
}

Write-Output @{
  "error" = $err;
  "result" = $result
}

}
## [END] Add-WACSDDCAzStackHCIVMAttestation ##
function Add-WACSDDCAzureStackHciExtension {
<#

.SYNOPSIS
Add the Azure Stack HCI extension

.DESCRIPTION
Add the Azure Stack HCI extension

.ROLE
Administrators

#>
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

# If no account is available will send back null -> will then parse to UI that needs az login
$value = az account show

# Az account is logged in and valid
if ($null -ne $value) {
    az extension add --name azurestackhci --version 0.2.3 --upgrade --only-show-errors
}
}
## [END] Add-WACSDDCAzureStackHciExtension ##
function Add-WACSDDCGalleryImage {
<#

.SYNOPSIS
Add the gallery image

.DESCRIPTION
Add the Azure Stack HCI gallery image

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $galleryImageName,

    [Parameter(Mandatory = $true)]
    [string]
    $galleryImagePath,

    [Parameter(Mandatory = $true)]
    [string]
    $osType,

    [Parameter(Mandatory = $true)]
    [string]
    $location,

    [Parameter(Mandatory = $true)]
    [string]
    $extendedLocation,

    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

return az azurestackhci galleryimage create --subscription $subscriptionID --resource-group $resourceGroup --extended-location name=$extendedLocation type=""CustomLocation"" --location ""$location"" --image-path $galleryImagePath --name $galleryImageName --os-type $osType --only-show-errors

}
## [END] Add-WACSDDCGalleryImage ##
function Add-WACSDDCSDDCResource {
<#
.SYNOPSIS

Adds SDDC Management Cluster Resource
.DESCRIPTION

Adds SDDC Management Cluster Resource

.ROLE
Administrators
#>

Import-Module  Microsoft.PowerShell.Management
Import-Module FailoverClusters

$clusterGroupId = (Get-ItemProperty -Path HKLM:cluster).ClusterGroup
if ($clusterGroupId -eq $null)
{
  Throw 'ClusterGroup property was not found on HKLM:cluster'
}
else
{
  $clusterGroup = FailoverClusters\Get-Cluster | Get-ClusterGroup -Name $ClusterGroupId
  $groupName = $clusterGroup.name
  $sddcResource = Add-ClusterResource -Name 'SDDC Management' -Group $groupName  -ResourceType 'SDDC Management' -SeparateMonitor

  # Add dependency
  $healthRes = Get-ClusterResourceType "Health Service" | Get-ClusterResource;
  if($healthres.Count -eq 1)
  {
    Add-ClusterResourceDependency $healthRes -resource $sddcResource;
  }

  Start-ClusterResource $sddcResource -ErrorAction SilentlyContinue
}

}
## [END] Add-WACSDDCSDDCResource ##
function Add-WACSDDCVMNetworkAdapterExtendedAcl {
<#
.SYNOPSIS

Adds the ACL rule on a cluster VM.
.DESCRIPTION

Adds the ACL rule with the given params on the cluster VM.

.ROLE
Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [string] $action,
    [Parameter(Mandatory = $true)]
    [string] $direction,
    [Parameter(Mandatory = $true)]
    [int] $weight,
    [Parameter(Mandatory = $true)]
    [string] $vmId,
    [Parameter(Mandatory = $false)]
    [string] $localIpAddress,
    [Parameter(Mandatory = $false)]
    [string] $remoteIpAddress,
    [Parameter(Mandatory = $false)]
    [string] $protocol,
    [Parameter(Mandatory = $false)]
    [boolean] $stateful,
    [Parameter(Mandatory = $false)]
    [string] $vmNetworkAdapterName,
    [Parameter(Mandatory = $false)]
    [string] $computerName
)

Import-Module  'Hyper-V'

$parameters = @{
                'Action' = $action;
                'Direction' = $direction;
                'Weight' = $weight;
               }

if ($localIpAddress) {
    $parameters.Add('LocalIPAddress', $localIpAddress)
}
if ($remoteIpAddress) {
    $parameters.Add('RemoteIPAddress', $remoteIpAddress)
}
if ($protocol) {
    $parameters.Add('Protocol', $protocol)
}
if ($stateful) {
    $parameters.Add('Stateful', $stateful)
}
if ($computerName) {
    $parameters.Add('ComputerName', $computerName)
}
if ($vmNetworkAdapterName) {
    $parameters.Add('VMNetworkAdapterName', $vmNetworkAdapterName)
}
Get-VM -Id $vmId | Add-VMNetworkAdapterExtendedAcl @parameters


}
## [END] Add-WACSDDCVMNetworkAdapterExtendedAcl ##
function Add-WACSDDCVirtualNetwork {
<#

.SYNOPSIS
Add a virtual network

.DESCRIPTION
Add a virtual network

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $extensionProvider,

    [Parameter(Mandatory = $true)]
    [string]
    $vnetName,

    [Parameter(Mandatory = $true)]
    [string]
    $vswitchName,

    [Parameter(Mandatory = $true)]
    [string]
    $location,

    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup,

    [Parameter(Mandatory = $true)]
    [int]
    $vlanID
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

Import-Module ArcHci

try{
    New-MocGroup -name "Default_Group" -location "MocLocation"
} catch {
    if (!($_.Exception.Message -like '*[[]Error: rpc error: code = AlreadyExists desc = Group[[]Default_Group[]] Location [[]MocLocation[]]: Already Exists[]]*')) {
        throw
    }
}
$tags = @{}
$tags['VSwitch-Name'] = "$vswitchName"
New-MocVirtualNetwork -name "$vnetName" -group "Default_Group" -tags $tags -vlanID $vlanID
return az azurestackhci virtualnetwork create --subscription $subscriptionID --resource-group $resourceGroup --name $vnetName --network-type ""Transparent"" --location $location --extended-location name=$extensionProvider type="CustomLocation" --vlan $vlanID --only-show-errors
}
## [END] Add-WACSDDCVirtualNetwork ##
function Confirm-WACSDDCCluster {
<#

.SYNOPSIS
Check whether environment is ASZ or HCI. Show tool in HCI only

.DESCRIPTION
Check whether environment is ASZ or HCI. Show tool in HCI only

.ROLE
Readers

#>
$response = @{ State = 'Available'; Message = 'Environment is a cluster';}; 
$clusterObj = $null
try {
    Import-Module FailoverClusters -ErrorAction SilentlyContinue
    $clusterObj = FailoverClusters\Get-Cluster -ErrorAction SilentlyContinue
    if ($clusterObj -eq $null) {
        $response = @{ State = 'NotSupported'; Message = 'Environment is not a cluster';};
    }
} catch {
    # no op
}
return $response

}
## [END] Confirm-WACSDDCCluster ##
function Confirm-WACSDDCEnvironment {
<#

.SYNOPSIS
Check whether environment is ASZ or HCI. Show tool in HCI only

.DESCRIPTION
Check whether environment is ASZ or HCI. Show tool in HCI only

.ROLE
Readers

#>

$response = @{ State = 'Available'; Message = 'Environment is non-ASZ. Tool is supported';}; 
$regKeyPath = 'HKLM:/SOFTWARE/Microsoft/AzureStack'
if (test-path -Path $regKeyPath) {
    $deviceType = Get-ItemPropertyValue -Path $regKeyPath -Name 'DeviceType'; 
    if($deviceType -eq 'AzureEdge') {
        $response.State = 'NotSupported'; 
        $response.Message = 'Environment is ASZ. Tool is not supported on ASZ environments';
    };
}; 

return $response

}
## [END] Confirm-WACSDDCEnvironment ##
function Disable-WACSDDCAccelNetManagement {
<#

.SYNOPSIS
Disables accelerated networking on the cluster
.DESCRIPTION
Disables accelerated networking on the cluster
.ROLE
Administrators

#>

$result = @{
    "failoverClustersNotInstalled" = $false
    "disableAccelNetManagementStatus" = $null
    "errorReturned" = $null
}
try {
    Import-Module FailoverClusters -ErrorAction Stop
    try {
        $result.disableAccelNetManagementStatus = Disable-AccelNetManagement -InformationAction Ignore -ErrorAction Stop
    } catch {
        $result.errorReturned = $_
    }
} catch {
    $result.failoverClustersNotInstalled = $true
}
$result

}
## [END] Disable-WACSDDCAccelNetManagement ##
function Disable-WACSDDCAccelNetOnVirtualMachines {
<#
.SYNOPSIS
Given a list of virtual machines, disable accel net on these VMs

.DESCRIPTION
Given a list of virtual machines, disable accel net on these VMs

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmNames
)

$result = @{
  "succeededVMs" = $null;
  "failedVMs" = $null;
}

Import-Module FailoverClusters -ErrorAction Stop
Import-Module Hyper-V -ErrorAction Stop

###############################################################################
# Constants
###############################################################################
# Script scope variable
$script:virtualMachineSuccesses = New-Object System.Collections.ArrayList
$script:virtualMachineFailures = New-Object System.Collections.ArrayList

function main($vmNames) {

    foreach ($vmName in $vmNames) {
      $vm = Get-VM -VMName $vmName -ErrorVariable getVmError -ErrorAction SilentlyContinue

      if (-not $vm) {
        $errorMessage = $getVmError[0].Exception.Message
        $failedVmObj = New-Object -TypeName PSObject
        $failedVmObj | Add-Member -NotePropertyName VmName -NotePropertyValue $vmName
        $failedVmObj | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $errorMessage
        $script:virtualMachineFailures.Add($failedVmObj) > $null
        return
      }

      $vm | Disable-AccelNetVM -ErrorVariable enableError -ErrorAction SilentlyContinue

      if ($enableError) {
        $errorMessage = $enableError[0].Exception.Message
        $failedVmObj = New-Object -TypeName PSObject
        $failedVmObj | Add-Member -NotePropertyName VmName -NotePropertyValue $vmName
        $failedVmObj | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $errorMessage
        $script:virtualMachineFailures.Add($failedVmObj) > $null
      } else {
        $script:virtualMachineSuccesses.Add($vmName) > $null
      }
    }

    $result = New-Object -TypeName PSObject
    $result | Add-Member -NotePropertyName SucceededVMs -NotePropertyValue $script:virtualMachineSuccesses
    $result | Add-Member -NotePropertyName FailedVMs -NotePropertyValue $script:virtualMachineFailures

    return $result
}

###############################################################################
# Script execution starts here...
###############################################################################
return main $vmNames

}
## [END] Disable-WACSDDCAccelNetOnVirtualMachines ##
function Disable-WACSDDCAzStackHCIAttestation {
<#

.SYNOPSIS
Disables Azure Stack HCI attestation on all nodes in the cluster
.DESCRIPTION
Disables Azure Stack HCI attestation on all nodes in the cluster
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool] $removeVM
)


try {
  $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object  -First 1

  if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
  {
    # insufficient verison - get a new one from PS Gallery
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }
  else
  {
    Import-Module $module -ErrorAction Stop
  }
}
catch {
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
  Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
}

Disable-AzStackHCIAttestation -RemoveVM:$removeVM -Force

}
## [END] Disable-WACSDDCAzStackHCIAttestation ##
function Enable-WACSDDCAccelNetManagement {
<#

.SYNOPSIS
Enables accelerated networking on the cluster
.DESCRIPTION
Enables accelerated networking on the cluster
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $intentName,
    [Parameter(Mandatory = $true)]
    [int]
    $nodeReservePercentage
)

Import-Module FailoverClusters
$result = @{
    "failoverClustersNotInstalled" = $false
    "enableAccelNetManagementStatus" = $null
    "errorReturned" = $null
}

try {
    Import-Module FailoverClusters -ErrorAction Stop
    try {
        # Find out if the selected intent passed the prerequisite check
        $prereq = (Get-AccelNetManagementPreReq -IntentName $intentName) | Where-Object { $_.Passed -eq $False } -InformationAction Ignore -ErrorAction Stop

        if ($null -ne $prereq) {
          # The selected intent does not pass prerequisite validation, fail the script
          throw $prereq.Message
        }

        $result.enableAccelNetManagementStatus = Enable-AccelNetManagement -IntentName $intentName -NodeReservePercentage $nodeReservePercentage -InformationAction Ignore -ErrorAction Stop
    } catch {
        $result.errorReturned = $_
    }
} catch {
    $result.failoverClustersNotInstalled = $true
}
$result


}
## [END] Enable-WACSDDCAccelNetManagement ##
function Enable-WACSDDCAccelNetOnVirtualMachines {
<#
.SYNOPSIS
Given a list of virtual machines, enable accel net on these VMs
If the VM does not have the necessary network adapter, create one with virtual switch set to the
currently enabled network intent

.DESCRIPTION
Given a list of virtual machines, enable accel net on these VMs
If the VM does not have the necessary network adapter, create one with virtual switch set to the
currently enabled network intent

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmNames,
    [Parameter(Mandatory = $true)]
    [String] $performanceLevel
)

$result = @{
  "succeededVMs" = $null;
  "failedVMs" = $null;
}

Import-Module FailoverClusters -ErrorAction Stop
Import-Module Hyper-V -ErrorAction Stop

###############################################################################
# Constants
###############################################################################
# Script scope variable
$script:virtualMachineSuccesses = New-Object System.Collections.ArrayList
$script:virtualMachineFailures = New-Object System.Collections.ArrayList

function main($vmNames, $performanceLevel) {

    foreach ($vmName in $vmNames) {
      try {
        $vm = Get-VM -VMName $vmName -ErrorVariable getVmError -ErrorAction Stop

        $vmAdaptersConnectedToEnabledIntentSwitch = $vm | Get-VMAdaptersConnectedToEnabledIntentSwitch -ErrorAction SilentlyContinue

        if ($null -eq $vmAdaptersConnectedToEnabledIntentSwitch) {
          # No existing VM Adapter connected to the enabled AccelNet Intent, create one for this VM before enablement
          $newAdapter = Add-VMNetworkAdapter -VM $vm -Passthru -ErrorAction Stop
          $intentName = Get-AccelNetManagement -ErrorAction Stop
          $vmSwitch = Get-VMSwitch -Name "*($intentName)" -ErrorAction Stop
          Connect-VMNetworkAdapter -VMNetworkAdapter $newAdapter -VMSwitch $vmSwitch -ErrorAction Stop
        }

        $vm | Enable-AccelNetVM -Performance $performanceLevel -ErrorAction Stop

        $script:virtualMachineSuccesses.Add($vmName) > $null
      }
      catch {
        $failedVmObj = New-Object -TypeName PSObject
        $failedVmObj | Add-Member -NotePropertyName VmName -NotePropertyValue $vmName
        $failedVmObj | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $_
        $script:virtualMachineFailures.Add($failedVmObj) > $null
      }
    }

    $result = New-Object -TypeName PSObject
    $result | Add-Member -NotePropertyName SucceededVMs -NotePropertyValue $script:virtualMachineSuccesses
    $result | Add-Member -NotePropertyName FailedVMs -NotePropertyValue $script:virtualMachineFailures

    return $result
}

###############################################################################
# Script execution starts here...
###############################################################################
return main $vmNames $performanceLevel

}
## [END] Enable-WACSDDCAccelNetOnVirtualMachines ##
function Enable-WACSDDCAzStackHCIAttestation {
<#

.SYNOPSIS
Enables Azure Stack HCI attestation on all nodes in the cluster
.DESCRIPTION
Enables Azure Stack HCI attestation on all nodes in the cluster
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool] $addVM
)

try {
  $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object  -First 1
  # if ($module.version.major -lt 1)
  if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
  {
    # insufficient verison - get a new one from PS Gallery
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }
  else
  {
    Import-Module $module -ErrorAction Stop
  }
}
catch {
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
  Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
}

Enable-AzStackHCIAttestation -AddVM:$addVM -Force

}
## [END] Enable-WACSDDCAzStackHCIAttestation ##
function Enable-WACSDDCVmIntegrationService {
<#
.SYNOPSIS
Calls Enable-VMIntegrationService on list of vms to enable speficic VM integration service
.DESCRIPTION
Calls Enable-VMIntegrationService on list of vms to enable speficic VM integration service
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmNames,

    [Parameter(Mandatory = $true)]
    [string] $serviceToEnable
)

Set-StrictMode -Version 5.0
Import-Module CimCmdlets
Import-Module Hyper-V -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################
# Script scope variable
$script:virtualMachineSuccesses = New-Object System.Collections.ArrayList
$script:virtualMachineFailures = New-Object System.Collections.ArrayList

function main(
  $vmNames,
  $serviceToEnable) {

    foreach ($vmName in $vmNames) {
      $vm = Get-VM -VMName $vmName -ErrorAction SilentlyContinue

      if (-not $vm) {
        return
      }

      $vm | Enable-VMIntegrationService -Name $serviceToEnable -ErrorVariable enableError -ErrorAction SilentlyContinue

      if ($enableError) {
        $errorMessage = $enableError[0].Exception.Message
        $failedVmObj = New-Object -TypeName PSObject
        $failedVmObj | Add-Member -NotePropertyName VmName -NotePropertyValue $vmName
        $failedVmObj | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $errorMessage
        $script:virtualMachineFailures.Add($failedVmObj) > $null
      } else {
        $script:virtualMachineSuccesses.Add($vmName) > $null
      }

      if ($serviceToEnable -eq "Key-Value Pair Exchange") {
        $cimSession = New-CimSession
        # Refresh britannica cache here if the enabling VM integration service  is 'Key-Value Pair Exchange' integration service
        $britannicaVmObj = Get-CimInstance -Namespace  "root/sddc/management" -ClassName "SDDC_VirtualMachine" |  Where-Object { $_.Name -eq $vmName }
        Invoke-CimMethod -CimSession $cimSession -InputObject $britannicaVmObj -MethodName Refresh -Arguments @{ RefreshType = 0 } -ErrorAction SilentlyContinue
      }
    }

    $result = New-Object -TypeName PSObject
    $result | Add-Member -NotePropertyName SucceededVMs -NotePropertyValue $script:virtualMachineSuccesses
    $result | Add-Member -NotePropertyName FailedVMs -NotePropertyValue $script:virtualMachineFailures

    return $result
}

###############################################################################
# Script execution starts here...
###############################################################################
$hyperVModule = Get-Module -Name Hyper-V -ErrorAction SilentlyContinue

if (-not($hyperVModule)) {
    Write-Error "Hyper-V Module cannot be found"

    return $null
}

return main $vmNames $serviceToEnable

}
## [END] Enable-WACSDDCVmIntegrationService ##
function Get-WACSDDCAccelNetManagementPreReq {
<#

.SYNOPSIS
Runs a list of prerequisite checks - required to enable accelerated networking on the cluster
.DESCRIPTION
Runs a list of prerequisite checks - required to enable accelerated networking on the cluster
.ROLE
Readers

#>

$result = @{
    "failoverClustersNotInstalled" = $false
    "error" = $null
    "prereqResults" = $null
}
try {
    Import-Module FailoverClusters -ErrorAction Stop
    try {
        $result.prereqResults = Get-AccelNetManagementPreReq -InformationAction Ignore -ErrorAction Stop
    } catch {
        $result.error = $_
    }
} catch {
    $result.failoverClustersNotInstalled = $true
}
$result
}
## [END] Get-WACSDDCAccelNetManagementPreReq ##
function Get-WACSDDCAccelNetManagementStatus {
<#
.SYNOPSIS
Gets the accelerated networking status on the given cluster
.DESCRIPTION
Gets the accelerated networking status on the given cluster
.ROLE
Readers
#>

$result = @{
    "failoverClustersNotInstalled" = $false
    "clusterName" = $null
    "accelNetManagementStatus" = $false
    "nodeReservePercentage" = $null
    "enabledIntentName" = $null
    "error" = $null
}
try {
    Import-Module FailoverClusters -ErrorAction Stop
    try {
        $clusterObj = Get-Cluster -ErrorAction Stop
        $result.clusterName = $clusterObj.Name
        $result.accelNetManagementStatus = $clusterObj.AcceleratedNetworkingEnabled
        if ($clusterObj.AcceleratedNetworkingEnabled -eq $true) {
            $result.enabledIntentName = Get-AccelNetManagement -ErrorAction Stop
            $result.nodeReservePercentage = $clusterObj.AcceleratedNetworkingNodeReserve
        }
    } catch {
        $result.error = $_
    }
} catch {
    $result.failoverClustersNotInstalled = $true
}
$result

}
## [END] Get-WACSDDCAccelNetManagementStatus ##
function Get-WACSDDCAccelNetVirtualMachines {
<#
.SYNOPSIS
Get a list of VMs on the node along with whether or not the VM has a network adapter
associated with a virtual switch under the currently enabled AccelNet Intent

.DESCRIPTION
Get a list of VMs on the node along with whether or not the VM has a network adapter
associated with a virtual switch under the currently enabled AccelNet Intent

.ROLE
Readers
#>

$result = @{
  "virtualMachines" = @{}
  "error" = $null
}

Import-Module FailoverClusters -ErrorAction Stop
Import-Module Hyper-V -ErrorAction Stop
try {
    $virtualMachines = Get-VM -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object `
      Name, `
      ProcessorCount, `
      Id, `
      ProblemDescription, `
      Status, `
      StatusInfo, `
      NetworkAdapters, `
      ComputerName

    foreach ($vm in $virtualMachines) {
      # Find accelerated network adapter
      $vmAccelNetAdapter = Get-VMAdaptersConnectedToEnabledIntentSwitch -VMName $vm.Name -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object `
        IovWeight, `
        IovQueuePairsRequested, `
        IovInterruptModeration, `
        IovUsage, `
        Connected, `
        SwitchName, `
        Id

      if ($vmAccelNetAdapter) {
        $vm | Add-Member -NotePropertyName AccelNetAdapter -NotePropertyValue $vmAccelNetAdapter
      } else {
        $vm | Add-Member -NotePropertyName AccelNetAdapter -NotePropertyValue $null
      }
    }

    $result.virtualMachines = $virtualMachines
} catch {
    $result.error = $_
}

$result

}
## [END] Get-WACSDDCAccelNetVirtualMachines ##
function Get-WACSDDCAvailableWindowsUpdates {
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
  [int16]$serverSelection
)

$objSession = Microsoft.PowerShell.Utility\New-Object -ComObject "Microsoft.Update.Session"
$objSearcher = $objSession.CreateUpdateSearcher()
$objSearcher.ServerSelection = $serverSelection
try
{
  $objResults = $objSearcher.Search("IsInstalled = 0")
}
catch
{
  $err = $_
  $objResults = $null
}
if (!$objResults -or !$objResults.Updates) {
  return $null
}

foreach ($objResult in $objResults.Updates) {
  $objResult | Microsoft.PowerShell.Utility\Select-Object Title, IsMandatory, RebootRequired, MsrcSeverity, `
		@{Name="UpdateID"; Expression={$_.Identity | Microsoft.PowerShell.Utility\Select-Object UpdateID} } | `
    Microsoft.PowerShell.Utility\Select-Object -Property * -ExcludeProperty UpdateID -ExpandProperty UpdateID
}

}
## [END] Get-WACSDDCAvailableWindowsUpdates ##
function Get-WACSDDCAzStackHCIVMAttestation {
<#

.SYNOPSIS
Gets Azure STack HCI VM attestation data
.DESCRIPTION
Gets Azure STack HCI VM attestation data
.ROLE
Readers

#>

try {
  $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

  if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
  {
    # insufficient verison - get a new one from PS Gallery
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }
  else
  {
    Import-Module $module -ErrorAction Stop
  }
}
catch {
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
  Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
}

$vmAttestationData = Get-AzStackHCIVMAttestation -Local
$attestationCount = ($vmAttestationData | Microsoft.PowerShell.Utility\Measure-Object).Count
$tmpAttestationArray = @();
if ($attestationCount -eq 0 ) {
    $vmAttestationData = $tmpAttestationArray;
}

if ($attestationCount -eq 1) {

    $tmpAttestationArray += $vmAttestationData
    #  ensure we get an array if only one object
    $vmAttestationData = $tmpAttestationArray
}


$result = @{
  "vmAttestationData" = $vmAttestationData;
}



Write-Output $result

}
## [END] Get-WACSDDCAzStackHCIVMAttestation ##
function Get-WACSDDCAzureConnection {
<#
.SYNOPSIS
Gets Azure Stack HCI connection and registration status

.DESCRIPTION
Gets Azure Stack HCI connection and registration status

.ROLE
Readers

#>
Import-Module AzureStackHCI, FailoverClusters

$azureStackHCI = Get-AzureStackHCI
$arcStatsusEnumObj = $null
$arcAgentVersionID = $null

$cluster = FailoverClusters\Get-Cluster


$isHCIV2ClusterFunctionalLevel = $false;

if ($cluster.ClusterFunctionalLevel -ge 12)
{
    $isHCIV2ClusterFunctionalLevel = $true;
}
elseif ($cluster.ClusterFunctionalLevel -eq 11 -and $cluster.ClusterUpgradeVersion -ge 4)
{
    $isHCIV2ClusterFunctionalLevel = $true;
}

# this functional level supports Arc
if ($isHCIV2ClusterFunctionalLevel)
{
    $arcStatsus = Get-AzureStackHCIArcIntegration
    $azureConnectedMachineAgentDefaultPath = Join-Path -Path $env:ProgramFiles -ChildPath 'AzureConnectedMachineAgent\azcmagent.exe'
    $validPath = Test-Path $azureConnectedMachineAgentDefaultPath
    if ($validPath) {
        $arcAgentVersionID = & $azureConnectedMachineAgentDefaultPath "version"
    }
    $nodesArcStatusEnumObj = @()

    $arcStatsus.nodesArcStatus.Keys | ForEach-Object {

        $arcStatusValue = $null;

        if ($arcStatsus.nodesArcStatus[$_] -ne $null) {
            $arcStatusValue = $arcStatsus.nodesArcStatus[$_].value__;
        }

        $nodesArcStatusEnumObj += @{
          "nodeName" = $_;
          "arcStatus" = $arcStatusValue
        }
    }

    $arcStatsusEnumObj = @{
      "clusterArcStatus" = $arcStatsus.clusterArcStatus.value__;
      "nodesArcStatus" = $nodesArcStatusEnumObj;
    }
}

$imdsAttestation = $null
$diagnosticLevel = $null

if ($azureStackHCI.PSobject.properties.name -contains "imdsAttestation") {
    $imdsAttestation = $azureStackHCI.imdsAttestation

    if ($imdsAttestation -ne $null) {
      $imdsAttestation = $azureStackHCI.imdsAttestation.value__
    }
}

if ($azureStackHCI.PSobject.properties.name -contains "diagnosticLevel") {
    $diagnosticLevel = $azureStackHCI.diagnosticLevel

    if ($diagnosticLevel -ne $null) {
      $diagnosticLevel = $azureStackHCI.diagnosticLevel.value__
    }
}

# 0 here means a Registration Status of Registered
if ($azureStackHCI.RegistrationStatus.value__ -eq 0) {
  $ResourceUri = $azureStackHCI.AzureResourceUri;
  $region = $null;
  $nextSync = $null;
  try {
    $region = $azureStackHCI.region;
    $nextSync = $azureStackHCI.nextSync;
  } catch {
    # no action needed
  }
  $result = @{
      "registrationStatus" = $azureStackHCI.RegistrationStatus.value__;
      "connectionStatus" = $azureStackHCI.ConnectionStatus.value__;
      "registrationDate" = $azureStackHCI.RegistrationDate;
      "region" = $region;
      "azureResourceUri" = $ResourceUri;
      "azureResourceName" = $azureStackHCI.AzureResourceName;
      "lastConnected" = $azureStackHCI.LastConnected;
      "nextSync" = $nextSync;
      "subscriptionId" = $ResourceUri.Split('/')[2];
      "arcStatus" = $arcStatsusEnumObj;
      "arcAgentVersionID" = $arcAgentVersionID;
      "imdsAttestation" = $imdsAttestation;
      "diagnosticLevel" = $diagnosticLevel;
      "isHCIV2FuncionalLevel" = $isHCIV2ClusterFunctionalLevel
  }
} else {
    $result = @{
      "registrationStatus" = $azureStackHCI.RegistrationStatus.value__;
      "connectionStatus" = $null
      "registrationDate" = $null;
      "region" = $null;
      "azureResourceUri" = $null;
      "azureResourceName" = $null
      "lastConnected" = $null
      "nextSync" = $null;
      "subscriptionId" = $null
      "arcStatus" = $arcStatsusEnumObj;
      "arcAgentVersionID" = $arcAgentVersionID;
      "imdsAttestation" = $null;
      "diagnosticLevel" = $diagnosticLevel;
      "isHCIV2FuncionalLevel" = $isHCIV2ClusterFunctionalLevel
  }
}

$result

}
## [END] Get-WACSDDCAzureConnection ##
function Get-WACSDDCAzureStackHCIAttestation {
<#

.SYNOPSIS
Gets Azure STack HCI host attestation data
.DESCRIPTION
Gets Azure STack HCI host attestation data
.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [string] $computerName
)

Import-Module AzureStackHCI


try {
    $data = Get-AzureStackHCIAttestation -ErrorAction Stop
    Write-Output @{
        "expiration" = $data.expiration;
        "status" = $data.status.value__;
        "legacyOsSupport" = $data.LegacyOsSupport
        "computerName" = $computerName
        "scriptError" = $null
    }

}
catch {
    $err = $_
    Write-Output @{
      "expiration" = $null
      "status" = $null
      "legacyOsSupport" = $null
      "computerName" = $computerName
      "scriptError" = $err
    }
}


}
## [END] Get-WACSDDCAzureStackHCIAttestation ##
function Get-WACSDDCAzureStackHCIPreviewChannel {
<#

.SYNOPSIS
Gets the state of the Get-PreviewChannel command

.DESCRIPTION
Gets the state of the Get-PreviewChannel command

.ROLE
Readers

#>

Import-Module PreviewOptIn
Get-PreviewChannel

}
## [END] Get-WACSDDCAzureStackHCIPreviewChannel ##
function Get-WACSDDCAzureStackHCISubscriptionStatus {
<#
.SYNOPSIS
Determines if the Diagnostic Level settings should be displayed

.DESCRIPTION
Determines if the Diagnostic Level settings should be displayed

.ROLE
Readers

#>

Import-Module AzureStackHCI

$statuses = Get-AzureStackHCISubscriptionStatus

$subscriptionInfo = $statuses | Where-Object {  $_.subscriptionName -eq "windows server subscription" }

if ($subscriptionInfo -ne $null) {
  Write-Output $subscriptionInfo.status.value__
}
else {
  Write-Output $null
}


}
## [END] Get-WACSDDCAzureStackHCISubscriptionStatus ##
function Get-WACSDDCAzureStackHciExtension {
<#
.SYNOPSIS

Adds SDDC Management Cluster Resource
.DESCRIPTION

Adds SDDC Management Cluster Resource

.ROLE
Administrators
#>
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

# Is the az azurestackhci extension installed
$extensions = az extension list --only-show-errors | ConvertFrom-Json
foreach($extension in $extensions) {
  if ($extension.name -eq 'azurestackhci') {
    return $true
  }
}
return $false
}
## [END] Get-WACSDDCAzureStackHciExtension ##
function Get-WACSDDCBitLockerRecoveryPassword {
<#

.SYNOPSIS
Gets BitLocker recovery key

.DESCRIPTION
Gets BitLocker recovery key

.ROLE
Readers

#>


param (
  [string]
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  $volumePath
)

Import-Module BitLocker -ErrorAction Stop  # stop becasue this is required

$recoveryPassword = $null
$keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

foreach($key in $keys){
  if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
    $recoveryPassword = $key.RecoveryPassword
    break;
  }
}

return $recoveryPassword

}
## [END] Get-WACSDDCBitLockerRecoveryPassword ##
function Get-WACSDDCCPUCores {
<#
.SYNOPSIS
Gets OS SKU number

.DESCRIPTION
Gets OS SKU number

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management
$cores = (get-wmiobject -class "win32_processor").NumberOfCores

$totalCores = ($cores | Microsoft.PowerShell.Utility\Measure-Object -Sum).Sum
$totalCores

}
## [END] Get-WACSDDCCPUCores ##
function Get-WACSDDCCSVOwnerNode {
<#
.SYNOPSIS
Get CSV owner node

.DESCRIPTION
Get CSV owner node

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
		[string]
    $volumeId
)

Import-Module FailoverClusters -ErrorAction Stop


function Get-MatchingCSV {
  param (
    $volumeId
  )
  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk
  foreach ($csvObj in Get-ClusterSharedVolume) {
    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}

$csv = $null
try {
  $csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop
  Write-Output $csv.ownerNode.name
}
catch {
  throw $_
}


}
## [END] Get-WACSDDCCSVOwnerNode ##
function Get-WACSDDCCimInstance {
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
## [END] Get-WACSDDCCimInstance ##
function Get-WACSDDCCluster {
<#
.SYNOPSIS
Gets cluster object

.DESCRIPTION
Gets cluster object

.ROLE
Readers

#>

Import-Module FailoverClusters
FailoverClusters\Get-Cluster

}
## [END] Get-WACSDDCCluster ##
function Get-WACSDDCClusterIPAddress {
<#
.SYNOPSIS
Gets cluster IP address info

.DESCRIPTION
Gets cluster IP address info

Process:
- Get the "Cluster Group", you can reliably (localization safe) find the cluster group by looking for groups with IsCoreGroup flag will be true (there may be several,
but only one should also contain a network name or distributed network name)
- Enumerate the resources in the group. find either the "Network Name" or "Distributed Network Name" (these type values are not localized) which IsCoreResource set to true

if "Network Name" (otherwise skip to 4)
- Retrieve the dependency expression
- retrieve all the Resource Names from that dependency expression
- for each of those resources get their private properties (get-clusterparameter), retrieve the value of Address. Add it to list of IPs
- return list of IPs

if "Distributed Network Name"
- Enumerate the cluster networks (Get-ClusterNetwork), specifically role ClusterAndClient (numeric value 3) networks
- Retrieve the Private Property named "ExcludeNetworks" from the Cluster name (it is a comma separated list of GUIDs)
- Filter the list obtained in step 1 by removing any network that's guid matches a member of the list obtained in step 2
- Retrieve the network (get-clusternetwork -network <name/id>) for the networks still in the list after step 3
- Add the values of the IPv4Addresses and IPv6Addresses (Which are lists) properties of each network to IP list
- return list of IPs

.ROLE
Readers

#>

Import-Module FailoverClusters

$resultNetworkName = @()
$resultDistributedNetworkName = @()


$clusterResourceId = (Get-ItemProperty -Path HKLM:cluster).ClusterNameResource


if ($null -eq $clusterResourceId) {
  throw "ClusterNameResource id not found"
} else {

  $clusterNameResource = Get-ClusterResource $clusterResourceId

  # Find IP addresses of Distributed Network Name, if exists
  if ($clusterNameResource.ResourceType -eq "Distributed Network Name")
  {
    $networkIdToExclude = (Get-ClusterResource $clusterNameResource.Name | Get-ClusterParameter | Where-Object { $_.Name -eq "ExcludeNetworks" }).Value
    $distributedNetworkObject = Get-ClusterNetwork | Where-Object { $networkIdToExclude -notcontains $_.Id }

    foreach ($network in $distributedNetworkObject)  {
      $resultDistributedNetworkName += $network.Ipv4Addresses
      $resultDistributedNetworkName += $network.Ipv6Addresses
    }
  }
  elseif ($clusterNameResource.ResourceType -eq "Network Name")# Find IP addresses of Network Name
  {
    $depends = (Get-ClusterResource $clusterNameResource.Name | Get-ClusterResourceDependency).DependencyExpression
    $networkNames = [Regex]::Matches($depends,'\[([^\[\]]+)\]').Value -replace '\[','' -replace '\]',''
    $resultNetworkName = (Get-ClusterResource $networkNames | Get-ClusterParameter | Where-Object name -eq 'address').Value
  }
  else {
    throw "Unable to get either Network Name or Distributed Network Name cluster resource"
  }
}


return $resultNetworkName + $resultDistributedNetworkName;

}
## [END] Get-WACSDDCClusterIPAddress ##
function Get-WACSDDCClusterQuorum {
<#
.SYNOPSIS
Gets cluster witnes information

.DESCRIPTION
Gets cluster witnes information

.ROLE
Readers

#>

Import-Module FailoverClusters

$quorum = Get-ClusterQuorum
if ($quorum -ne $null -and $quorum.QuorumResource -eq $null)
{
    return $null
}
else
{
    $resource = $quorum.QuorumResource
    $resourceTypeName = $resource.ResourceType.Name
    $cloudEndpoint = $null
    $cloudAccountName = $null
    $diskNames = $null
    $fileSharePath = $null
    $username = $null
    $clusterParameters = $resource | Get-ClusterParameter

    if ($resourceTypeName -eq "Cloud Witness")
    {

      $cloudAccountName = ($clusterParameters | Where-Object Name -eq "AccountName").value
      $cloudEndpoint = ($clusterParameters | Where-Object Name -eq "EndPointInfo").value
    }

    if ($resourceTypeName -eq "File Share Witness")
    {
        $fileSharePath = ($clusterParameters | Where-Object Name -eq "SharePath").value
        $username = ($clusterParameters | Where-Object Name -eq "UserName").value
    }

    if ($resourceTypeName -eq "Physical Disk")
    {

        $diskObjects = Get-ClusterResource | Where-Object ResourceType -Eq "Physical Disk"

        # can only use resources that are in available storage (or could be the same one we already are using)
        $clusGroupTypeCoreCluster = 1 #enum value from clusapi.w
        $clusGroupTypeAvailableStorage = 2; #enum value from clusapi.w

        $diskNames = @();
        foreach ($disk in $diskObjects)
        {
            $groupType = $disk.OwnerGroup.GroupType.value__

            if ($groupType -eq $clusGroupTypeAvailableStorage)
            {
                $diskNames += $disk.Name
            }

            if ($groupType -eq $clusGroupTypeCoreCluster -and $disk.name -eq $resource.Name)
            {
              $diskNames += $disk.Name
            }
        }

    }

  return @{
        "resourceTypeName" = $resourceTypeName; # used for witness type
        "resourceName" =  $resource.Name; # used for file share witness to get the current cluster disk that is witness
        "state" = $resource.State.value__;
        "cloudEndpoint" = $cloudEndpoint;
        "cloudAccountName" = $cloudAccountName;
        "diskNames" = $diskNames;
        "fileSharePath" = $fileSharePath;
        "username" = $username;
    }
}

}
## [END] Get-WACSDDCClusterQuorum ##
function Get-WACSDDCClusterS2DAndStorageHealthSettings {
<#
.SYNOPSIS
Gets information for Storage Spaces and  pools

.DESCRIPTION
Gets information for Storage Spaces and  pools

.ROLE
Readers

#>

Import-Module FailoverClusters
Import-Module Microsoft.PowerShell.Utility
Import-Module Storage

$s2dData = Get-ClusterS2D
$disableWriteCacheValue = $null
$autoPoolValue = $null
$autoRetireValue = $null
$resyncBandwidth = $null

$clusterStorageSubsystem = Get-StorageSubSystem "Cluster*"

$disableWriteCache = $clusterStorageSubsystem | Get-StorageHealthSetting -Name "System.Storage.NestedResiliency.DisableWriteCacheOnNodeDown.Enabled"
if ($disableWriteCache -ne $null)
{
    $disableWriteCacheValue = $disableWriteCache.value
}

$autoPool =  $clusterStorageSubsystem | Get-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoPool.Enabled"
if ($autoPool -ne $null)
{
    $autoPoolValue = $autoPool.value
}

$autoRetire =  $clusterStorageSubsystem  | Get-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoRetire.OnLostCommunication.Enabled"
if ($autoRetire -ne $null)
{
    $autoRetireValue = $autoRetire.value
}


if (($clusterStorageSubsystem | Get-Member -name VirtualDiskRepairQueueDepth) -ne $null) {
    $resyncBandwidth = $clusterStorageSubsystem.VirtualDiskRepairQueueDepth
}


@{
  "s2dData" = $s2dData;
  "autoPool" = $autoPoolValue;
  "autoRetire" = $autoRetireValue;
  "disableWriteCache" = $disableWriteCacheValue;
  "resyncBandwidth" = $resyncBandwidth
}

}
## [END] Get-WACSDDCClusterS2DAndStorageHealthSettings ##
function Get-WACSDDCClusterStatus {
<#

.SYNOPSIS
Script that is run when connecting to the cluster from connections page

.DESCRIPTION
Script that is run when connecting to the cluster from connections page

.ROLE
Readers

#>


Import-Module CimCmdlets

$nodes = Get-CimInstance MSCluster_Node -Namespace root/mscluster | Where-Object { $_.State -eq '0' };
$aliases = $nodes | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Name;
$status = @{label = $null; type = 0; details = $null; }
$result = @{status = $status; aliases = $aliases}
return $result;

}
## [END] Get-WACSDDCClusterStatus ##
function Get-WACSDDCClusterWitnessDiskNames {
<#
.SYNOPSIS
Gets disk names for disk witness

.DESCRIPTION
Gets disk names for disk witness

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $false)]
  [string]
  $currentDiskWitnessName
)

Install-Module FailoverClusters

$diskObjects = Get-ClusterResource | Where-Object ResourceType -Eq "Physical Disk"

# can only use resources that are in available storage (or could be the same one we already are using)
$clusGroupTypeCoreCluster = 1 #enum value from clusapi.w
$clusGroupTypeAvailableStorage = 2 #enum value from clusapi.w

$diskNames = @();
foreach ($disk in $diskObjects)
{
    $groupType = $disk.OwnerGroup.GroupType.value__
    if ($groupType -eq $clusGroupTypeAvailableStorage)
    {
        $diskNames += $disk.Name
    }

    if ($groupType -eq $clusGroupTypeCoreCluster -and $disk.name -eq $currentDiskWitnessName)
    {
        $diskNames += $disk.Name
    }
}

$diskNames

}
## [END] Get-WACSDDCClusterWitnessDiskNames ##
function Get-WACSDDCClusteredScheduledTask {
<#
.SYNOPSIS
Gets cluster scheduled task

.DESCRIPTION
Gets cluster scheduled task

.ROLE
Readers

#>

Import-Module ScheduledTasks
Get-ClusteredScheduledTask

}
## [END] Get-WACSDDCClusteredScheduledTask ##
function Get-WACSDDCEncryptionPolicy {
<#
.SYNOPSIS
Gets BitLocker encryption method policy

.DESCRIPTION
Gets BitLocker encryption method policy

.ROLE
Readers

#>
Import-Module  Microsoft.PowerShell.Management

try {
  $item = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\FVE" -ErrorAction Stop

  if ($item -ne $null) {
    Write-Output $item.EncryptionMethodWithXtsFdv
  }
  else  {
    Write-Output $null
  }

}
catch {
  Write-Output $null
}


}
## [END] Get-WACSDDCEncryptionPolicy ##
function Get-WACSDDCFileSystemChildItem {
<#

.SYNOPSIS
Get all child items for the selected path

.DESCRIPTION
Get all child items for the selected path

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $selectedPath
)

return Get-ChildItem -Path $selectedPath -Force |
    Microsoft.PowerShell.Utility\Select-Object @{Name = "Caption"; Expression = { $_.FullName } },
    @{Name = "CreationDate"; Expression = { $_.CreationTimeUtc } },
    Extension,
    @{Name = "IsHidden"; Expression = { $_.Attributes -match "Hidden" } },
    @{Name = "IsShared"; Expression = { [bool]($folderShares | Where-Object Path -eq $_.FullName) } },
    Name,
    @{Name = "Type"; Expression = { Get-FileSystemEntityType -Attributes $_.Attributes } },
    @{Name = "LastModifiedDate"; Expression = { $_.LastWriteTimeUtc } },
    @{Name = "Size"; Expression = { if ($_.PSIsContainer) { $null } else { $_.Length } } },
    Directory;
}
## [END] Get-WACSDDCFileSystemChildItem ##
function Get-WACSDDCGalleryImage {
<#

.SYNOPSIS
Get the Azure Stack HCI gallery image

.DESCRIPTION
Get the Azure Stack HCI gallery image

.ROLE
Readers

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup,

    [Parameter(Mandatory = $true)]
    [string]
    $customLocationName
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

$galleryImages = az azurestackhci galleryimage list --subscription $subscriptionID --resource-group $resourceGroup --only-show-errors | ConvertFrom-Json

return [array]$galleryImages | Where-Object { $_.extendedLocation -Match $customLocationName}
}
## [END] Get-WACSDDCGalleryImage ##
function Get-WACSDDCHyperVState {
<#

.SYNOPSIS
Get hyper-v installation state

.DESCRIPTION
Get hyper-v installation state

.ROLE
Readers

#>

$hyperV = Get-WindowsFeature -Name Hyper-V

$rsatHyperV = Get-WindowsFeature RSAT-Hyper-V-Tools

if ($hyperV -ne $null -and $rsatHyperV -ne $null) {
    return ($hyperV.installed -and $rsatHyperV.installed)
}

return $false

}
## [END] Get-WACSDDCHyperVState ##
function Get-WACSDDCInstalledDiagnosticInfoModule {
<#

.SYNOPSIS
Gets diagnostic settings info

.DESCRIPTION
Gets diagnostic settings info

.ROLE
Readers

#>

$diagnosticInfoResult = $null
$diagnosticInfoException = $null

Import-Module PackageManagement
Import-Module PowerShellGet

try
{
    $diagnosticInfoResult = Get-InstalledModule "PrivateCloud.DiagnosticInfo" -ErrorAction stop
}
catch
{
    $diagnosticInfoException = $_ # the exception
    # check err code for the case of not finding the module
    if ((($diagnosticInfoException).exception).hresult -eq -2146233088)
    {
      $diagnosticInfoResult = "not installed"
    }
    else
    {
      throw $diagnosticInfoException
    }

}


@{
  "diagnosticInfo" = $diagnosticInfoResult;
}

}
## [END] Get-WACSDDCInstalledDiagnosticInfoModule ##
function Get-WACSDDCLatestDiagnosticInfoModule {
<#

.SYNOPSIS
Gets latest diagnotistic info module

.DESCRIPTION
Gets latest diagnotistic info module

.ROLE
Readers

#>
Import-Module PackageManagement

Install-PackageProvider NuGet -Force | Out-Null

Find-Package "PrivateCloud.DiagnosticInfo"

}
## [END] Get-WACSDDCLatestDiagnosticInfoModule ##
function Get-WACSDDCMetrics {
<#

.SYNOPSIS
Gets metrics data for drawing charts

.DESCRIPTION
Gets metrics data for drawing charts

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [System.Object]
    $identifyingObject,
    [Parameter(Mandatory = $true)]
    [int]
    $timeFrame,
    [Parameter(Mandatory = $true)]
    [string]
    $seriesName,
    [Parameter(Mandatory = $true)]
    [string]
    $className
)

$args = @{}
$args += @{"seriesName" = $seriesName }
$args += @{"timeFrame" = $timeFrame }

Import-Module CimCmdlets

# server and cluster instances are identified by unique name
if ($className -eq "SDDC_Server" -or $className -eq "SDDC_Cluster")
{
    $inputObject = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName $classname | Where-Object { $_.Name -eq $identifyingObject.metricsIdentifier }
}
else
{
    # drive and volume instances are identified by unique id
    $inputObject = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName $classname | Where-Object { $_.Id -eq $identifyingObject.metricsIdentifier }
}

$inputObject | Invoke-CimMethod -MethodName GetMetrics -Arguments $args

}
## [END] Get-WACSDDCMetrics ##
function Get-WACSDDCMonitoringData {
<#
.SYNOPSIS

Gets Monitoring Data log collection intervals
.DESCRIPTION

Gets Monitoring Data log collection intervals

.ROLE
Readers
#>


Import-Module FailoverClusters

Get-ClusterResource | Where-Object { $_.ResourceType -eq "SDDC Management" } | Get-ClusterParameter -Name "CacheDumpIntervalInSeconds"

}
## [END] Get-WACSDDCMonitoringData ##
function Get-WACSDDCNetAdapterRDMA {
<#

.SYNOPSIS
Gets NetAdapterRDMA

.DESCRIPTION
Gets NetAdapterRDMA

.ROLE
Readers

#>

Import-Module NetAdapter
Get-NetAdapterRDMA

}
## [END] Get-WACSDDCNetAdapterRDMA ##
function Get-WACSDDCNetIntents {
<#

.SYNOPSIS
Gets the network atc intents on the cluster
.DESCRIPTION
Gets the network atc intents on the cluster
.ROLE
Readers

#>
$result = @{
    "netatcNotInstalled" = $false
    "error" = $null
    "intents" = $null
}
$intents = @()
try {
    Import-Module NetworkATC -ErrorAction Stop
    try {
        $intents = Get-NetIntent | Microsoft.PowerShell.Utility\Select-Object IntentName, IsComputeIntentSet -ErrorAction Stop
        # making sure the intents is always an array of intents
        if (($intents -ne $null) -and (($intents | Microsoft.PowerShell.Utility\Measure-Object).count -eq 1))
        {
            $result.intents = @( $intents )
        } else {
            $result.intents = $intents
        }
    } catch {
        $result.error = $_
    }
} catch {
    $result.netatcNotInstalled = $true
}
$result

}
## [END] Get-WACSDDCNetIntents ##
function Get-WACSDDCNodeFqdnsAndState {
<#

.SYNOPSIS
Gets FQDN and state of cluster nodes

.DESCRIPTION
Gets FQDN and state of cluster nodes

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [bool]
    $getNodeToSiteMap
)


Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

function Get-NodeToSiteMap {

  Import-Module CimCmdlets

  $nodeMap = @{}

  $nodeFaultDomains = Get-ClusterFaultDomain -Type Node
  $nodesInCluster = @()
  $nodesObserved = 0

  $nodesNotInSite = @()

  $hasSite = $false

  foreach($clusterNode in Get-ClusterNode)
  {
    $nodesInCluster += $clusterNode.nodeName
  }

  foreach($fdNode in $nodeFaultDomains)
  {
      # we are only concerned with node fault domains if it is currently part of the cluster
      if ($nodesinCluster -contains $fdNode.name)
      {

          $parent = ($fdNode | Invoke-CimMethod -MethodName GetParent).parent
          if ($parent -ne $null) {

              while ($parent.type.value__ -ne 1000) # 1000 is site type
              {
                  if ($parent -eq $null)
                  {
                      #  we reached the end of the parent chain but did not find a site fault domain
                      # node name will be used to tell user the node is not in a fault domain
                      $nodesNotInSite += $fdNode.name
                      break
                  }
                  $parent = ($parent | Invoke-CimMethod -MethodName GetParent).parent
              }

              if ($nodeMap[$parent.name] -eq $null)
              {
                  $nodeMap[$parent.name] = @()
              }

              $nodeMap[$parent.name] += $fdNode.name
              $nodesObserved += 1
              $hasSite = $true
          }
          else
          {
              # the node fault domain had no parent at all
              # node name will be used to tell user the node is not in a fault domain
              $nodesNotInSite += $fdNode.name
          }
      }
}

      # we have ignored old nodes that have been removed from cluster but are still in the fault domain list.

  return @{
    "nodeMap" = $nodeMap;
    "nodesNotInSite" = $nodesNotInSite;
    "hasSite" = $hasSite;
  }
}

$nodes = @()

$nodeToSiteMap = $null
if ($getNodeToSiteMap) {
    $nodeToSiteMap =  Get-NodeToSiteMap
}


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

if ($getNodeToSiteMap) {
    Write-Output @{
        "nodes" = $nodes;
        "nodeToSiteMap" = $nodeToSiteMap;
    }
}
else {
  Write-Output $nodes
}

}
## [END] Get-WACSDDCNodeFqdnsAndState ##
function Get-WACSDDCNonS2DDisks {
<#
.SYNOPSIS
Gets MSFT_Disk objects that are RAW and not part of storage spaces

.DESCRIPTION
Gets MSFT_Disk objects that are RAW and not part of storage spaces

.ROLE
Readers

#>

Import-Module storage
Import-Module  Microsoft.PowerShell.Utility

$spacesBusType = 16
$rawPartitionStyle = 0

$perPoolData = @()

$pools = Get-StoragePool -IsPrimordial $false
foreach ($pool in $pools) {
  $clusterStorageSubSystem = Get-StorageSubSystem -StoragePool $pool
  $allNonSpacesDisks = Get-Disk -StorageSubSystem $clusterStorageSubSystem | Where-Object { $_.psBase.CimInstanceProperties["BusType"].value -ne $spacesBusType }
  $rawDisks = $allNonSpacesDisks | Where-Object { $_.psBase.CimInstanceProperties["PartitionStyle"].Value -eq $rawPartitionStyle }

  $rawDiskData = @()
  forEach ($disk in $rawDisks) {
    $rawDiskData += @{
      "size" = $disk.size;
      "diskNumber" = $disk.diskNumber;
      "friendlyName" = $disk.friendlyName;
      "model" = $disk.model;
      "manufacturer" = $disk.manufacturer;
      "location" = $disk.location;
    }
  }
  $hasNonS2DDisks = ($allNonSpacesDisks | Microsoft.PowerShell.Utility\Measure-Object).Count -gt 0

  $perPoolData += @{
    "rawDiskData" = $rawDiskData;
    "hasNonS2DDisks" = $hasNonS2DDisks;
  }

}

Write-Output $perPoolData

}
## [END] Get-WACSDDCNonS2DDisks ##
function Get-WACSDDCNonS2DServerMemory {
<#
.SYNOPSIS
Gets OS SKU number

.DESCRIPTION
Gets OS SKU number

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management
$mem = (get-wmiobject -class "win32_physicalmemory" -namespace "root\CIMV2").Capacity

$mem

}
## [END] Get-WACSDDCNonS2DServerMemory ##
function Get-WACSDDCOSBuild {
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
## [END] Get-WACSDDCOSBuild ##
function Get-WACSDDCOperatingSystemSKU {
<#
.SYNOPSIS
Gets OS SKU number

.DESCRIPTION
Gets OS SKU number

.ROLE
Readers

#>
Import-Module CimCmdlets
(Get-CimInstance Win32_OperatingSystem).OperatingSystemSku

}
## [END] Get-WACSDDCOperatingSystemSKU ##
function Get-WACSDDCPrimordialPoolVersion {
<#

.SYNOPSIS
Gets the primordial storage pool version

.DESCRIPTION
Gets the primordial storage pool version

.ROLE
Readers

#>

Import-Module Storage

(Get-StorageSubSystem | Where-Object { $_.FriendlyName -NotLike "Cluster*" } | Get-StoragePool -IsPrimordial $True).Version

}
## [END] Get-WACSDDCPrimordialPoolVersion ##
function Get-WACSDDCRackToNodeClusterFaultDomainMap {
<#
.SYNOPSIS
Gets rack fault domains

.DESCRIPTION
Gets rack fault domains

.ROLE
Readers

#>

Import-Module FailoverClusters

$racks = Get-ClusterFaultDomain -Type ([Microsoft.PowerShell.Cmdletization.GeneratedTypes.MSCLUSTER.MSCluster_FaultDomain.FaultDomainType]::Rack) -ErrorAction SilentlyContinue

$rackNodeMappings = @()

if ($null -ne $racks) {
    $racks | ForEach-Object {
        $rackNodeMappingObj = @{
            "rack" = $_.Name
            "nodes" = @()
        }
        $rack = $_
        $rackChildren = $rack.children
        if ($null -ne $rackChildren) {
            $rackChildren | ForEach-Object {
                $rackChild = $_
                if ($rackChild.type.value__ -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MSCLUSTER.MSCluster_FaultDomain.FaultDomainType]::Chassis) {
                    $chasisChildren = $rackChild.children
                    if ($null -ne $chasisChildren) {
                        $chasisChildren | ForEach-Object {
                            $chasisChild = $_
                            if ($chasisChild.type.value__ -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MSCLUSTER.MSCluster_FaultDomain.FaultDomainType]::Node) {
                                $rackNodeMappingObj.nodes += $chasisChild.Name
                            }
                        }
                    }
                }
                if ($rackChild.type.value__ -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MSCLUSTER.MSCluster_FaultDomain.FaultDomainType]::Node) {
                    $rackNodeMappingObj.nodes += $rackChild.Name
                }
            }
        }
        $rackNodeMappings += $rackNodeMappingObj
    }
}

$rackNodeMappings

}
## [END] Get-WACSDDCRackToNodeClusterFaultDomainMap ##
function Get-WACSDDCReFSDedupSchedule {
<#

.SYNOPSIS
Gets ReFS deduplication schedule for a volume

.DESCRIPTION
Gets ReFS deduplication schedule for a volume

.ROLE
Readers

#>


param (
		[Parameter(Mandatory = $true)]
		[string]
    $path

)

Import-Module Microsoft.ReFsDedup.Commands

$schedule = Get-ReFSDedupSchedule -Volume $path

Write-Output @{
  "type"  = $schedule.type.value__
  "suspended" = $schedule.suspended;
  "days" = $schedule.days.value__;
  "enabled" = $schedule.enabled;
  "start" = $schedule.start;
  "duration" = $schedule.duration.totalHours;
}


}
## [END] Get-WACSDDCReFSDedupSchedule ##
function Get-WACSDDCSDDCDiagnosticInfo {
<#

.SYNOPSIS
Gets SDDC diagnostic info

.DESCRIPTION
Gets SDDC diagnostic info

.ROLE
Readers

#>

Import-Module  Microsoft.PowerShell.Management

try {
  Import-Module PrivateCloud.DiagnosticInfo -ErrorAction Stop
}
catch {
  Import-Module PowerShellGet
  Import-Module PackageManagement
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module - run on all nodes
  Install-Module PrivateCloud.DiagnosticInfo -Force # this will get the latest verison
}

$path = Join-Path -Path $env:Public -ChildPath "SddcDiagnosticInfo"
$pathExists =  Test-Path $path
$filePrefix =  Join-Path -Path $path -ChildPath "info"

if (-not $pathExists)
{
  New-Item -ItemType Directory -Force -Path $path | Out-Null
}

# this suppresses non-terminal errs but allows exceptions to be thrown and thus only show terminal exceptions in the Notification pane
Get-SDDCDiagnosticInfo -ZipPrefix $filePrefix -ErrorVariable scriptErrors -ErrorAction SilentlyContinue

}
## [END] Get-WACSDDCSDDCDiagnosticInfo ##
function Get-WACSDDCSDDCDiagnosticInfoList {
<#

.SYNOPSIS
Gets SDDC diagnostic info child items

.DESCRIPTION
Gets SDDC diagnostic info child items

.ROLE
Readers

#>
Import-Module Microsoft.PowerShell.Management

$path = Join-Path -Path $env:Public -ChildPath "SddcDiagnosticInfo"
$pathExists =  Test-Path $path

if (-not $pathExists)
{
  New-Item -ItemType Directory -Force -Path $path | Out-Null
}

Get-ChildItem $path

}
## [END] Get-WACSDDCSDDCDiagnosticInfoList ##
function Get-WACSDDCSDDCResource {
<#

.SYNOPSIS
Gets SDDC Management resource

.DESCRIPTION
Gets SDDC Management resource

.ROLE
Readers

#>
Import-Module CimCmdlets

$resourceTypeName = "SDDC Management"
$resourceType = Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_ResourceType | Where-Object { $_.Name -eq $resourceTypeName }

if (($resourceType | Microsoft.PowerShell.Utility\Measure-Object ).Count -lt 1)
{
    # this error does not surface to user - it is used internally
    Throw "Did not find the resourceType: '$resourceTypeName'"
}
else {
    $resource = $resourceType | Get-CimAssociatedInstance -ResultClassName MSCluster_Resource
    if (($resource | Microsoft.PowerShell.Utility\Measure-Object ).Count -gt 0)
    {
        return $resource
    } else
    {
        # this error does not surface to user - it is used internally
        Throw "Could not get the associated resource for the resourceType: '$resourceTypeName'"
    }
}

}
## [END] Get-WACSDDCSDDCResource ##
function Get-WACSDDCSDDCResourceCapabilities {
<#

.SYNOPSIS
Gets SDDC Managment  capability level for the cluster

.DESCRIPTION
Gets SDDC Managment  capability level for the cluster

.ROLE
Readers

#>

Import-Module FailoverClusters

try
{
    Get-ClusterResource | Where-Object { $_.ResourceType -eq "SDDC Management" } | Get-ClusterParameter -Name Capabilities
}
catch
{
    return $null
}

}
## [END] Get-WACSDDCSDDCResourceCapabilities ##
function Get-WACSDDCSDDCResourceType {
<#

.SYNOPSIS
Gets SDDC Managment resource type

.DESCRIPTION
Gets SDDC Managment resource type

.ROLE
Readers

#>
Import-Module CimCmdlets

$resourceTypeName = "SDDC Management"
$resourceType = Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_ResourceType | Where-Object { $_.Name -eq $resourceTypeName }

if (($resourceType | Microsoft.PowerShell.Utility\Measure-Object ).Count -lt 1)
{
    # this error does not surface to user - it is used internally
    Throw "Did not find the resourceType: '$resourceTypeName'"
}

return $resourceType

}
## [END] Get-WACSDDCSDDCResourceType ##
function Get-WACSDDCSRServerFeature {
<#

.SYNOPSIS
Gets Storage Replica feature status

.DESCRIPTION
Gets Storage Replica feature status

.ROLE
Readers

#>

Import-Module ServerManager
Get-WindowsFeature -Name Storage-Replica, RSAT-Storage-Replica

}
## [END] Get-WACSDDCSRServerFeature ##
function Get-WACSDDCSiteDownStatus {
<#

.SYNOPSIS
Determines if all nodes in a site are down

.DESCRIPTION
Determines if all nodes in a site are down

.ROLE
Readers

#>

Import-Module FailoverClusters
Import-Module CimCmdlets
Import-Module Microsoft.PowerShell.Utility


function Get-SiteDownStatusNodeMap {
  $nodeMap = @{}

  $nodeFaultDomains = Get-ClusterFaultDomain -Type Node
  $nodesInCluster = @()

  $clusterNodes = Get-ClusterNode

  foreach($clusterNode in $clusterNodes)
  {
    $nodesInCluster += $clusterNode.nodeName
  }

  foreach($fdNode in $nodeFaultDomains)
  {

      # we are only concerned with node fault domains if it is currently part of the cluster
      if ($nodesinCluster -contains $fdNode.name)
      {

          $parent = ($fdNode | Invoke-CimMethod -MethodName GetParent).parent
          if ($parent -ne $null) { # null here means we would have standalone node with no parent and thus no site

              while ($parent.type.value__ -ne 1000) # 1000 is site type
              {
                  if ($parent -eq $null)
                  {
                      #  we reached the end of the parent chain but did not find a site fault domain
                      break
                  }
                  $parent = ($parent | Invoke-CimMethod -MethodName GetParent).parent
              }

              if ($parent -ne $null) # null parent here means we would have hit a terminal parent that was not a site
              {

                  if ($nodeMap[$parent.name] -eq $null)
                  {
                      $nodeMap[$parent.name] = @()
                  }
                  #  now we find the clusterNode with this name so we can get its up/down status
                  $matchingClusterNode = $clusterNodes | Where-Object { $_.Name -eq $fdNode.name }
                  $downStatus = 1
                  $nodeMap[$parent.name] += @{ "name" = $matchingClusterNode.name; "isDown" = $matchingClusterNode.State.value__ -eq $downStatus}
              }
          }
      }
  }

  # we have ignored old nodes that have been removed from cluster but are still in the fault domain list.

  return $nodeMap
}

$map = Get-SiteDownStatusNodeMap
$downSite = $null
foreach ($site in $map.keys)
{
    # assume all nodes in site are down, then if any one is not down, we end the loop and declare the site is not totally down
    $allNodesDown = $true
    foreach ($nodeItem in $map[$site])
    {
        if (-not $nodeItem.isDown)
        {
            $allNodesDown = $false
            break;
        }
    }
    if ($allNodesDown)
    {
      $downSite = $site
    }
}

# this will give us the string of the name for the down site
return $downSite

}
## [END] Get-WACSDDCSiteDownStatus ##
function Get-WACSDDCStorageHealthReport {
<#

.SYNOPSIS
Gets storage health report data

.DESCRIPTION
Gets storage health report data

.ROLE
Readers

#>

Import-Module Storage
Import-Module Microsoft.PowerShell.Utility

$allData = Get-StorageSubSystem Cluster* | Get-StorageHealthReport

$throughputData = @{}
$iopsData = @{}
$latencyData = @{}
$cpuAverage = @{}
$memoryAvailable = @{}
$memoryTotal = @{}
$storageAvailable = @{}
$storageTotal = @{}

if (($allData | Microsoft.PowerShell.Utility\Measure-Object ).count -gt 0)
{
    $records = $allData[0].itemvalue.records

    foreach ($record in $records)
    {
        if ($record.name -eq "IOLatencyAverage")
        {
          $latencyData = $record.value;
        }

        if ($record.name -eq "IOPSTotal")
        {
          $iopsData = $record.value;
        }

        if ($record.name -eq "IOThroughputTotal")
        {
          $throughputData = $record.value;
        }

        if ($record.name -eq "CPUUsageAverage")
        {
          $cpuAverage = $record.value;
        }

        if ($record.name -eq "MemoryAvailable")
        {
          $memoryAvailable = $record.value;
        }

        if ($record.name -eq "MemoryTotal")
        {
          $memoryTotal = $record.value;
        }

        if ($record.name -eq "CapacityVolumesAvailable")
        {
          $storageAvailable = $record.value;
        }

        if ($record.name -eq "CapacityVolumesTotal")
        {
          $storageTotal = $record.value;
        }

    }

    $memoryUsed = $memoryTotal - $memoryAvailable
    $storageUsed = $storageTotal - $storageAvailable

    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "Iops" $iopsData
    $result | Add-Member -MemberType NoteProperty -Name "Throughput" $throughputData
    $result | Add-Member -MemberType NoteProperty -Name "Latency" $latencyData
    $result | Add-Member -MemberType NoteProperty -Name "CpuAverage" $cpuAverage
    $result | Add-Member -MemberType NoteProperty -Name "MemoryUsed" $memoryUsed
    $result | Add-Member -MemberType NoteProperty -Name "MemoryTotal" $memoryTotal
    $result | Add-Member -MemberType NoteProperty -Name "StorageUsed" $storageUsed
    $result | Add-Member -MemberType NoteProperty -Name "StorageTotal" $storageTotal
    return $result
}

return $null


}
## [END] Get-WACSDDCStorageHealthReport ##
function Get-WACSDDCStorageHistory {
<#

.SYNOPSIS
Gets storage history for the specified drive

.DESCRIPTION
Gets storage history for the specified drive

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $driveId
)

Import-Module Storage


$driveIdWildCard = "*" + $driveId + "*"
$disk = Get-PhysicalDisk | Where-Object ObjectID -like $driveIdWildCard
return $disk | Get-StorageHistory -Disaggregate

}
## [END] Get-WACSDDCStorageHistory ##
function Get-WACSDDCStoragePoolClusterResource {
<#

.SYNOPSIS
Gets a storage pool cluster resource by resource id and returns data about the pool

.DESCRIPTION
Gets a storage pool cluster resource by resource id and returns data about the pool

.ROLE
Readers

#>

param (
		[Parameter(Mandatory = $true)]
		[String]
    $resourceId
)

Import-Module FailoverClusters

$result = Get-ClusterResource  | Where-Object { $_.id -eq $resourceId }

$pool = Get-StoragePool | Where-Object { $_.UniqueId -match $resourceId }

Write-Output @{
  "clusterResourceState" = $result.State.value__;
  "operationalStatus" = $pool.psBase.CimInstanceProperties["OperationalStatus"].Value;
  "healthStatus" = $pool.psBase.CimInstanceProperties["HealthStatus"].Value;
}

}
## [END] Get-WACSDDCStoragePoolClusterResource ##
function Get-WACSDDCStoragePools {
<#

.SYNOPSIS
Gets storage pool information

.DESCRIPTION
Gets storage pool information

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $false)]
  [bool]
  $isStretch,
  [Parameter(Mandatory = $false)]
  [bool]
  $forVolumes,
  [Parameter(Mandatory = $false)]
  [string]
  $volumeId,
  [Parameter(Mandatory = $false)]
  [bool]
  $forSettings
)

Import-Module CimCmdlets
Import-Module Storage
Import-Module FailoverClusters

# this method is only called in the case we need storage pools informatoin for stretch cluster volume creation
# in that case, if we found and loose nodes that are not part of a site, that would be a problem
function Get-NodeToSiteMap {

    $nodeMap = @{}

    $nodeFaultDomains = Get-ClusterFaultDomain -Type Node
    $nodesInCluster = @()
    $nodesObserved = 0

    $nodesNotInSite = @()

    $hasSite = $false

    foreach($clusterNode in Get-ClusterNode)
    {
      $nodesInCluster += $clusterNode.nodeName
    }

    foreach($fdNode in $nodeFaultDomains)
    {
        # we are only concerned with node fault domains if it is currently part of the cluster
        if ($nodesinCluster -contains $fdNode.name)
        {

            $parent = ($fdNode | Invoke-CimMethod -MethodName GetParent).parent
            if ($parent -ne $null) {

                while ($parent.type.value__ -ne 1000) # 1000 is site type
                {
                    if ($parent -eq $null)
                    {
                        #  we reached the end of the parent chain but did not find a site fault domain
                        # node name will be used to tell user the node is not in a fault domain
                        $nodesNotInSite += $fdNode.name
                        break
                    }
                    $parent = ($parent | Invoke-CimMethod -MethodName GetParent).parent
                }

                if ($nodeMap[$parent.name] -eq $null)
                {
                    $nodeMap[$parent.name] = @()
                }

                    $nodeMap[$parent.name] += $fdNode.name
                    $nodesObserved += 1
                    $hasSite = $true
                }
                else
                {
                    # the node fault domain had no parent at all
                    # node name will be used to tell user the node is not in a fault domain
                    $nodesNotInSite += $fdNode.name
                }
            }
        }

        # we have ignored old nodes that have been removed from cluster but are still in the fault domain list.

    return @{
      "nodeMap" = $nodeMap;
      "nodesNotInSite" = $nodesNotInSite;
      "hasSite" = $hasSite #this will not be used in the volumes case because a stretch cluster by definition has sites, but let's add this for parity's sake with getNodeFDNSAndState
    }
}

$pools = Get-StoragePool -IsPrimordial $false -ErrorAction SilentlyContinue
$correlatedData = @()

$result = @{
  "correlatedData" = @();
  "nodesNotInSite" = @();
  "hasVirtualDisk" = $null;
}

if ($pools -ne $null)
{

    if ($forVolumes -and $isStretch)
    {
      $siteMapData = Get-NodeToSiteMap


      # if we have nodes that are not in a site, we  should not proceed - return early with the list of nodes not in site
      if (($siteMapData.nodesNotInSite | Microsoft.PowerShell.Utility\Measure-Object).Count -gt 0) {
          $result.nodesNotInSite = $siteMapData.nodesNotInSite;
          return $result
      }
    }

    foreach ($pool in $pools)
    {
        $disks = $pool | Get-PhysicalDisk
        # all disks will be on the same pool so we can take any of the disks to find the site fault domain
        $faultDomain = $disks[0] | Get-StorageFaultDomain -Type StorageSite

        $poolData = @{
          "friendlyName" = $pool.friendlyName;
          "totalSize" = $pool.size;
          "sizeAvailable" = ($pool.size - $pool.allocatedSize);
          "operationalStatus" = $pool.psBase.CimInstanceProperties["OperationalStatus"].Value;
          "healthStatus" = $pool.psBase.CimInstanceProperties["HealthStatus"].Value;
          "siteName" = $null;
          "numberOfNodes" = $null;
          "storageTiers"  = $null;
          "clusterResourceState" = $null;
          "clusterResourceId" = $null;

          # these 3 are script properties
          "version" = $pool.version;
          "supportedProvisioningTypes" = [array]$pool.supportedProvisioningTypes;
          "provisioningTypeDefault" = $pool.provisioningTypeDefault;
          "thinProvisioningAlertThresholds" = $pool.thinProvisioningAlertThresholds;
        }


        $poolId = $pool.UniqueId.Substring(1,36) # will be the id string wrapped in braces:  {<id>} so we will remove the braces - guid will have fixed number of chars, so we can take stubstring to remove
        $clusterResource = Get-ClusterResource | Where-Object { $_.Id -eq $poolId}
        $clusterResourceState = $clusterResource.State.value__
        $poolData.clusterResourceState = $clusterResourceState

        $clusterResourceId = $clusterResource.Id;
        $poolData.clusterResourceId = $clusterResourceId

        $siteName = $null
        if ($faultDomain -ne $null)
        {
            # add siteName if we have site fault domains
            $siteName = $faultDomain.FriendlyName
            $poolData.siteName = $siteName
        }

        if ($forSettings)
        {
            $correlatedData += $poolData
        }
        else
        {
           if ($forVolumes)
           {
              # get storageTier info for the pool
              $storageTiers = Get-StorageTier -StoragePool $pool  # this only gets the template tiers we want

              try {
                # needed becuase of bug getting supported size if tier is set to Thin
                $storageTiers | Set-StorageTier -ProvisioningType "Fixed";
              }
              catch {
                $err = $_  # ignore the err - this would occur in WS16  that does not take the -ProvisioningType parameterm and it will be fixed provisioning anyway
              }

              $numberOfNodesInPool = $null
              if ($siteName -ne $null -and $isStretch) {
                $numberOfNodesInPool = ($siteMapData.nodeMap[$siteName] | Microsoft.PowerShell.Utility\Measure-Object).Count
              } else {
                 # whether there is a site or not, we count all nodes in the cluster, rather than those on just one matching site
                 $numberOfNodesInPool = (Get-ClusterNode | Microsoft.PowerShell.Utility\Measure-Object).Count
              }

              $poolData.numberOfNodes = $numberOfNodesInPool

              $poolData.storageTiers = @()
              foreach ($tier in $storageTiers)
              {
                $poolData.storageTiers += @{
                  "maxSize" = $null; # will get set later when the tier is selected in the UX
                  "friendlyName" = $tier.friendlyName;
                  "resiliencySettingName" = $tier.resiliencySettingName;
                  "mediaType" = $tier.psBase.CimInstanceProperties["MediaType"].Value;
                }
              }

              #  ignore any pools that are not associated with a site for stretch cases
              if ($isStretch)
              {
                  if ($siteName -ne $null) {
                    $correlatedData += $poolData
                  }
              }
              else
              {
                # non-stretch case doesnt need to care about nodes being in sites - always add to correlatedData
                $correlatedData += $poolData
              }

          }

        }

    }
}
$result.correlatedData = $correlatedData

# check for virtual disk backing a volume to edit so that we know if we need todo non-s2d options in the ux
if ($forVolumes -and $volumeId) {
  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk
  $virtualDisk = $volDisk | Get-VirtualDisk # will be null for non-s2d volume
  $result.hasVirtualDisk = $virtualDisk -ne $null

}
return $result

}
## [END] Get-WACSDDCStoragePools ##
function Get-WACSDDCStorageTierSupportedSize {

<#

.SYNOPSIS
Gets storage tier max supported size information

.DESCRIPTION
Gets storage tier max supported size information

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [object]
  $poolObj,

  [Parameter(Mandatory = $true)]
  [array]
  $tierFriendlyNames
)

Import-Module Storage

$tierInfo = @()

$poolFriendlyName = $poolObj.friendlyName
$numberOfNodesInPool = $poolObj.numberOfNodes

$pool = Get-StoragePool -FriendlyName $poolFriendlyName
$tiers = Get-StorageTier -StoragePool $pool

foreach ($tierFriendlyName in $tierFriendlyNames)
{
    $tier = $tiers  | Where-Object { $_.FriendlyName  -eq $tierFriendlyName }

    $maxSize = $null

    if ($numberOfNodesInPool -gt 2) {
      # _pool_ default settings that will affect the max _tier_ size
      $pool | Set-ResiliencySetting -Name $tier.resiliencySettingName -PhysicalDiskRedundancyDefault 2
      # get max size for 3 way mirror or dual parity
      # resiliencySettingName Unknown is for the virtual disk (space) not the tier - it tells us to ignore the space's resiliency so the calculation only considers the tier
      $maxSize = ($tier | Get-StorageTierSupportedSize -ResiliencySettingName Unknown).TierSizeMax
    }

    if ($numberOfNodesInPool -le 2) {
      # _pool_ default settings that will affect the max _tier_ size
      $pool | Set-ResiliencySetting -Name $tier.resiliencySettingName -PhysicalDiskRedundancyDefault 1
      # get max size for 2 way mirror or single parity
      # resiliencySettingName Unknown is for the virtual disk (space) not the tier - it tells us to ignore the space's resiliency so the calculation only considers the tier
      $maxSize = ($tier | Get-StorageTierSupportedSize -ResiliencySettingName Unknown).TierSizeMax
    }

    $tierInfo += @{
      "maxSize" =  $maxSize;
      "friendlyName" = $tierFriendlyName;
    }

}

Write-Output $tierInfo

}
## [END] Get-WACSDDCStorageTierSupportedSize ##
function Get-WACSDDCVMAutomaticActivation {
<#
.SYNOPSIS
Gets VM automatic activation

.DESCRIPTION
Gets VM automatic activation

.ROLE
Readers
#>

$activationResult = $null
$importError = $null
$getError = $null
$moduleSupportsWSSubscription = $null
try {
  $module = Get-Module -Name ServerAVMAManager -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

  if ($module.version.major -ge 1 -and $module.version.minor -ge 1)
  {
    $moduleSupportsWSSubscription = $true
  }
  else {
    $moduleSupportsWSSubscription = $false
  }
    Import-Module $module -ErrorAction Stop
}
catch {
    #  either the node was down or some other network error so it failed, or the node was up but did not have the module
    $importError = $_  # swallow the error
}

if ($importError -eq $null) {
    try
    {
        $activationResult = Get-VMAutomaticActivation -ErrorAction Stop
    }
    catch
    {
        $getError = $_  # swallow the error

    }
}
return @{
   "result" = $activationResult;
   "getError" = $getError;
   "importError" = $importError;
   "moduleSupportsWSSubscription" = $moduleSupportsWSSubscription;
}

}
## [END] Get-WACSDDCVMAutomaticActivation ##
function Get-WACSDDCVMNetworkAdapterExtendedAcl {
<#
.SYNOPSIS

Gets ACL rule list
.DESCRIPTION

fetches the list of ACL rules for the given VM name on the cluster.

.ROLE
Readers
#>

param (
    [Parameter(Mandatory = $false)]
    [string] $vmName
)

Import-Module  'Hyper-V'
$parameters = @{}
if ($vmName) {
    $parameters.Add('VMName', $vmName)
}

Get-VMNetworkAdapterExtendedAcl @parameters

}
## [END] Get-WACSDDCVMNetworkAdapterExtendedAcl ##
function Get-WACSDDCVirtualNetwork {
<#

.SYNOPSIS
Get the Azure Stack HCI virtual network

.DESCRIPTION
Get the Azure Stack HCI virtual network

.ROLE
Readers

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup,

    [Parameter(Mandatory = $true)]
    [string]
    $customLocationName
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

$virtualNetworks = az azurestackhci virtualnetwork list --subscription $subscriptionID --resource-group $resourceGroup --only-show-errors | ConvertFrom-Json

return [array]$virtualNetworks | Where-Object { $_.extendedLocation -Match $customLocationName}
}
## [END] Get-WACSDDCVirtualNetwork ##
function Get-WACSDDCVmSwitch {
<#

.SYNOPSIS
Get the VM switch

.DESCRIPTION
Get the VM switch

.ROLE
Administrators

#>

return Get-VmSwitch
}
## [END] Get-WACSDDCVmSwitch ##
function Install-WACSDDCDiagnosticInfoTools {
<#

.SYNOPSIS
Installs diagnostic info and networking modules

.DESCRIPTION
Installs diagnostic info and networking modules

.ROLE
Administrators

#>

Import-Module PowerShellGet
Import-Module PackageManagement
Install-PackageProvider NuGet -Force | Out-Null # required to  install the module - run on all nodes
Install-Module PrivateCloud.DiagnosticInfo -Force # this will get the latest verison
return $null

}
## [END] Install-WACSDDCDiagnosticInfoTools ##
function Install-WACSDDCFailoverClustersRSAT {
<#

.SYNOPSIS
Installs RSAT-Clustering feature

.DESCRIPTION
Installs RSAT-Clustering feature

.ROLE
Administrators

#>

Import-Module ServerManager
Install-WindowsFeature -Name 'RSAT-Clustering'

}
## [END] Install-WACSDDCFailoverClustersRSAT ##
function Install-WACSDDCNCRsatFeature {
<#

.SYNOPSIS
Installs RSAT-NetworkController feature

.DESCRIPTION
Installs RSAT-NetworkController feature

.ROLE
Administrators

#>

Import-Module ServerManager
Install-WindowsFeature rsat-networkcontroller -IncludeAllSubFeature -IncludeManagementTools

}
## [END] Install-WACSDDCNCRsatFeature ##
function Invoke-WACSDDCCimMethod {
<#
.SYNOPSIS
Invokes CIM method

.DESCRIPTION
Invokes CIM method

.ROLE
Administrators

#>

param (
		[Parameter(Mandatory = $false)]
		[System.Object]
    $identifyingObject,

    [Parameter(Mandatory = $true)]
		[string]
    $methodName,

    [Parameter(Mandatory = $true)]
		[string]
    $namespace,

    [Parameter(Mandatory = $true)]
		[string]
    $className
)

Import-Module CimCmdlets


if ($identifyingObject -ne $null)
{
    # server instances are identified by unique name
    if ($className -eq "SDDC_Server")
    {
        $inputObject = Get-CimInstance -Namespace $namespace -ClassName $classname | Where-Object { $_.Name -eq $identifyingObject.name }
    }
    else
    {
        # drive and volume instances are identified by unique id
        $inputObject = Get-CimInstance -Namespace $namespace -ClassName $classname | Where-Object { $_.Id -eq $identifyingObject.id }
    }

    Invoke-CimMethod -InputObject $inputObject -MethodName $methodName
}
else
{
    Invoke-CimMethod -Namespace  $namespace -ClassName $className -MethodName $methodName
}



}
## [END] Invoke-WACSDDCCimMethod ##
function Move-WACSDDCClusterSharedVolume {
<#
.SYNOPSIS
Move CSV

.DESCRIPTION
Move CSV

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
		[string]
    $volumeId,

    [Parameter(Mandatory = $true)]
		[string]
    $serverName
)

Import-Module FailoverClusters -ErrorAction Stop


function Get-MatchingCSV {
  param (
    $volumeId
  )


  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk
  foreach ($csvObj in Get-ClusterSharedVolume) {
    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}

$csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop

$csv | Move-ClusterSharedVolume -Node $serverName  -ErrorAction Stop | Out-Null


}
## [END] Move-WACSDDCClusterSharedVolume ##
function New-WACSDDCHCIClusterNonS2DVolume {
<#

.SYNOPSIS
Creates new NonS2D volume

.DESCRIPTION
Creates new NonS2D volume

.ROLE
Administrators

#>

Param(
  [int]
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  $diskNumber,
  [string]
  [Parameter(
      Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  $volumeName
)

Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
Import-Module Storage
Import-Module FailoverClusters
Import-Module BitLocker -ErrorAction SilentlyContinue # this one needs to continue since it is optional and won't be used if not installed

$disk = Get-Disk -number $diskNumber
$disk | Set-Disk -IsOffline $false;
try {
  $disk | initialize-disk -PartitionStyle GPT -ErrorAction Stop | Out-Null # should be raw based on filtering in the UX, but if for any reason it is not raw, we cannot continue
  $disk = Get-Disk -number $diskNumber # need updated reference to the disk

  $partition = $disk | New-Partition -UseMaximumSize
  $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel $volumeName | Out-Null

  $diskclusterresource = $disk |  Add-ClusterDisk

  $diskclusterresource.name = $volumeName

  $diskclusterresource | Add-ClusterSharedVolume   | Out-Null


  #must rename the csv and path to get the path to reflect the volume name
  $csv = Get-ClusterSharedVolume $diskclusterresource.name

  $csv.Name = $VolumeName

  $mountingPath = $csv.SharedVolumeInfo.FriendlyVolumeName

  $newMountingPath = Join-Path $(Split-Path -Path $mountingPath -Parent) $VolumeName


  Rename-Item $mountingPath $newMountingPath -Force
}
catch {
  throw
}



}
## [END] New-WACSDDCHCIClusterNonS2DVolume ##
function New-WACSDDCHCIClusterVolume {
<#

.SYNOPSIS
Creates new no-replicated volume or volume/log volume pair with Storage Replica group for replicated volumes

.DESCRIPTION
Creates new non-replicated volume or volume/log volume pair with Storage Replica group for replicated volumes

.ROLE
Administrators

#>

Param(
  [psobject]
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  $Data,
  [string]
  [Parameter(
      Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  $node
)

Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
Import-Module Storage
Import-Module FailoverClusters
Import-Module BitLocker -ErrorAction SilentlyContinue # this one needs to continue since it is optional and won't be used if not installed

function Handle-ReFSDedupOnCreateVolume {

param (

  [Parameter(Mandatory = $true)]
  [bool]
  $enableDedup,

  [Parameter(Mandatory = $true)]
  [bool]
  $setSchedule,

  [Parameter(Mandatory = $true)]
  [string]
  $path,

  [Parameter(Mandatory = $true)]
  [DateTime]
  $start,

  [Parameter(Mandatory = $true)]
  [int]
  $hours,

  [Parameter(Mandatory = $true)]
  [array] # array of enum values for days
  $days
)

Import-Module Microsoft.ReFsDedup.Commands
Import-Module Microsoft.PowerShell.Utility


if ($enableDedup) {
    $dedupOnly= 1 # UX will only allow for dedupe, but user can specify compression or both comrpression and dedupe on cmd line
    Enable-ReFSDedup -Volume $path -Type $dedupOnly | Out-Null
}

if ($resumeResult) {
  Resume-ReFSDedupSchedule -Volume $path | Out-Null
}


if ($setSchedule) {
$duration = New-Timespan -Hours $hours
Set-ReFSDedupSchedule -Volume $path -Start $start -Days $days -Duration $duration | Out-Null
}


if ($disableDedup) {
Disable-ReFSDedup -Volume $path | Out-Null
}


if ($suspendSchedule) {
Suspend-ReFSDedupSchedule -Volume $path | Out-Null
}


}

function Move-AvailableStorage
{
  param (
      [psobject]
      [Parameter(
          Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      $pool  # this will be a pool from get-storagepool - Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_StoragePool
  )

  $poolId = $pool.UniqueId

  # ensure the uniquieId which is bracketed guid can be matched to resource id, which is not bracketed
  $poolResource = Get-ClusterResource | Where-Object {  $_.resourcetype -eq "storage pool" } | Where-Object { ([GUID]$_.Id).ToString('b') -eq $poolId }

  $poolResourceNode = $poolResource.OwnerGroup.OwnerNode.Name

  $available_storage = Get-ClusterGroup | Where-Object { $_.GroupType -eq 'AvailableStorage' }

  try
  {
      Move-ClusterGroup -InputObject $available_storage -Node $poolResourceNode -ErrorAction Stop | Out-Null
  }
  catch
  {
      $err = $_
      $available_storage | Get-ClusterResource | Stop-ClusterResource | Out-Null
      Move-ClusterGroup -InputObject $available_storage -Node $poolResourceNode -ErrorAction Stop | Out-Null
  }

}


function Get-BitLockerRecoveryPassword {
  param (
    [string]
    [Parameter(
        Mandatory        = $true)]
    [ValidateNotNullOrEmpty()]
    $volumePath
  )

  $recoveryPassword = $null
  $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

  foreach($key in $keys){
    if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
      $recoveryPassword = $key.RecoveryPassword
      break;
    }
  }

  return $recoveryPassword

}

function Get-MatchingCSV {
  param (
    $voldisk
  )

  foreach ($csvObj in Get-ClusterSharedVolume) {

    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}


function Set-IntegrityAndBitlocker {
    param (
      [psobject]
      [Parameter(Mandatory = $false)]
      $inputVdClusterResource,

      [string]
      [Parameter(Mandatory = $false)]
      $inputVolumePath,

      [string]
      [Parameter(Mandatory = $false)]
      $volumeId,

      [bool]
      [Parameter(Mandatory = $true)]
      $useVolumeId,

      [psobject]
      [Parameter(Mandatory = $false)]
      $csvToUse,

      [bool]
      [Parameter(Mandatory = $true)]
      $useCsv,


      [string]
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      $node,

      # params for set integrity streams
      [bool]
      [Parameter(Mandatory = $false)]
      $SetIntegrityStreams,

      #  params for BitLocker
      [bool]
      [Parameter(Mandatory = $false)]
      $EnableBitLocker,

      [bool]
      [Parameter(Mandatory = $false)]
      $backupPasswordToAD,

      [bool]
      [Parameter(Mandatory = $false)]
      $clusterADAccountCanUnlock,

      [bool]
      [Parameter(Mandatory = $true)]
      $externalKey,

      [string]
      [Parameter(Mandatory = $true)]
      $encryptionMethod
    )

    $result = @{
      "bitLockerRecoveryPassword" = $null
      "bitLockerError" = $null;
      "integrityStreamsError" = $null;
      "deduplicationError" = $null;
      "removeBitLockerError" = $null;
      "otherError" = $null;
      "resumeResourceFailed" = $null;
    }

    $vdClusterResource = $null
    $volumePath = $null
    $externalKeyFolder = "c:\windows\cluster"
    $csv = $null
    try {
      if ($useVolumeId) {
        $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
        $voldisk = $volumeobj | Get-Partition | Get-Disk
        $csv = Get-MatchingCSV -voldisk $voldisk -ErrorAction Stop
        $volumePath = $csv.SharedVolumeInfo[0].FriendlyVolumeName  # pased in for replicated volmes, but volume.path will not be the right path for volumes created using new-volume

        # move the csv to THIS node so enabkle-bitlocker stuff will work during "creating"
        $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null #alraedy moved when we create without new-volume
        $virtualDisk = $volDisk | Get-VirtualDisk

        $vdClusterResource  = $virtualdisk | Get-ClusterResource -ErrorAction Stop

      }
      elseif ($useCsv) {
        $vdClusterResource = $inputVdClusterResource
        $csv = $csvToUse
        $volumePath = $inputVolumePath
      }

      # need to put the virtual disk into maintenance before we can enable BitLocker
      $vdClusterResource | Suspend-ClusterResource -Force -ErrorAction Stop | Out-Null


    }
    catch {

      $result.otherError = $_

    }

    # only proceed if we succeeded in suspending the cluster resource
    if ($result.otherError -eq $null) {

      if ($SetIntegrityStreams) {
        try {
            Set-FileIntegrity $volumePath -Enable $True -ErrorAction Stop
        }
        catch {
            $result.integrityStreamsError = $_
        }
      }


      # if any bitlocker error, clean up bitlocker
      if ($EnableBitLocker) {
          $bitLockerEnabled = $null;
          try {
            # use numerical recoverypassword
            Enable-BitLocker $volumePath -EncryptionMethod $encryptionMethod  -RecoveryPasswordProtector -Confirm:$false -ErrorAction Stop | Out-Null
            $bitLockerEnabled = $true
          } catch {
            $result.bitLockerError = $_
            #  no need to clean up bitlocker - it wasnt enabled
            $bitLockerEnabled = $false
          }

          # proceed if we succeeded in enabling bitlocker
          if ($bitLockerEnabled -eq $true) {

            try {
              $result.bitLockerRecoveryPassword = Get-BitLockerRecoveryPassword -volumePath $volumePath -ErrorAction Stop



              if ($clusterADAccountCanUnlock)
              {
                # for backup to AD, we already have set the reg keys on all nodes before calling this script
                # this $truncatedName will be truncated to no more than 15 chars

                $clusterResourceId = (Get-ItemProperty -Path HKLM:cluster).ClusterNameResource

                $truncatedName = Get-ClusterResource $clusterResourceId | Get-ClusterParameter | Where-Object { $_.name -eq "name" }

                $CNO = -Join($truncatedName.value ,"$")
                Add-BitLockerKeyProtector $volumePath -AdAccountOrGroupProtector -AdAccountOrGroup $CNO -Confirm:$false -ErrorAction Stop | Out-Null
              }

              if ($backupPasswordToAD)
              {

                $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

                foreach($key in $keys){
                  if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
                    Backup-BitLockerKeyProtector -MountPoint $volumePath -KeyProtectorId $key.keyProtectorId -Confirm:$false -ErrorAction Stop | Out-Null
                    break;
                  }
                }

              }

              if ($externalKey)
              {
                 Add-BitLockerKeyProtector $volumePath -RecoveryKeyProtector -RecoveryKeyPath  $externalKeyFolder -Confirm:$false -ErrorAction Stop | Out-nUll
              }
            }
            catch {
              $result.bitLockerError = $_
              $result.bitLockerRecoveryPassword = $null
            }
          }

      }
    }


    if ($result.bitLockerError -ne $null -and $bitLockerEnabled -eq $true) {
        # if AD  key protector errs, we cannot resume the cluster resource because this is currently our only optoin to unlock the volume
        # but in all cases we wil just remove bitlocker
        # we to disable bitlocker first
        try {
            Disable-BitLocker $volumePath -ErrorAction Stop | Out-Null
        }
        catch {
            $result.removeBitLockerError = $_
        }
    }



    if ($externalKey) {
      $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector
      $externalKeyTypeEnumValue = 2;
      $keyProtectorExternal = $keys | Where-Object {$_.KeyProtectorType.value__ -eq $externalKeyTypeEnumValue}
      $externalKeyFileName = $keyProtectorExternal.KeyFileName
      $externalKeyFullPath =  [System.String] (Join-Path $externalKeyFolder $externalKeyFileName)

      $resumeResult = $csv | Resume-ClusterPhysicalDiskResource -RecoveryKeyPath $externalKeyFullPath

      if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterResourceState enum value
        $result.resumeResourceFailed = $true
      }


    }
    else {
      # Resume-clusterResource does not seem to throw an err we can catch, but we will identify if it failed and use that instead
      $resumeResult = $vdClusterResource | Resume-ClusterResource -ErrorAction SilentlyContinue
      if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterRsoruceState enum value
        $result.resumeResourceFailed = $true
      }

    }

    return $result
}

function Get-VolumeArguments
{
  param (
      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $singleSiteVolume,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $UseTierNamedCapacity,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $UseTierNamedPerformance,

      [FileSystemType]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $FileSystem,

      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $FriendlyName,

      [ResiliencyType]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $Resiliency,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $CanSetProvisioningType,

      [uint16]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $ProvisioningType,

      [Array]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $TierSizes,  # for MRT the order needs to be parity, mirror

      [NewVolumeMediaTypeFromStorageTiers]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $MediaType,

      [PSObject]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $Pool # this will be a cim instance from get-storagepool

  )

  Begin
  {
      [flagsattribute()]
      Enum FileSystemType
      {
          NTFS       = 14
          ReFS       = 15
          CSVFS_NTFS = 32768
          CSVFS_ReFS = 32769
      }

      [flagsattribute()]
      Enum NewVolumeMediaTypeFromStorageTiers
      {
        Unspecified = 0
        HDD = 3
        SSD = 4
        SCM = 5
      }

      [flagsattribute()]
      Enum ResiliencyType {
          Unknown = 0
          Simple = 1
          SingleParity = 2
          DualParity = 3
          TwoWayMirror = 4
          ThreeWayMirror = 5
          MirrorAcceleratedParity = 6
          NestedParity = 7
          NestedTwoWayMirror = 8
          NestedMirrorAcceleratedParity = 9
      }

  }

  Process
  {
      $newVolumeArgs = @{
        "StoragePoolFriendlyName" = $pool.FriendlyName;
        "FriendlyName" =  $FriendlyName;
        "StorageTierSizes" = $null;  # set this depending on inf stretch cluster or not
        "StorageTiers" = $null #storagesTiers get added on later after setting physical disk redundancy and provisioning type
      }


      if ( $singleSiteVolume -eq $true) {
          $newVolumeArgs["StorageTierSizes"]  = $TierSizes

          # explicitly set this if using New-Volume, but for using new-virtualdisk, we will noot need this field here and will set this when we format the partition on the vdisk
          $newVolumeArgs += @{ "fileSystem" = $FileSystem  }
      } else {
          #  only expand the tier sizes if creating a stretch cluster where we need to control this.
          # Add extra size to the virtual disk tiers so there will be enough room for the full user-specified volume size
          $StorageTierSizes = @()
          foreach ($TierSize in $TierSizes)
          {
              $StorageTierSizes += ([uint64]$TierSize + 1GB)
              $newVolumeArgs["StorageTierSizes"] = $StorageTierSizes
          }
      }


      $PhysicalDiskRedundancy =  $null;
      # set physical disk redundancy for the tiers based on the resiliency - we will not use this for nested tiers
      switch ($Resiliency)
      {
          "TwoWayMirror"
          {
              $PhysicalDiskRedundancy = 1
              break;
          }

          "ThreeWayMirror"
          {
              $PhysicalDiskRedundancy = 2
              break;
          }

          "MirrorAcceleratedParity"
          {
              $PhysicalDiskRedundancy = 2
              break;
          }
      }


      # set tier names based on media type
      $MirrorTierName = $null
      $ParityTierName = $null

      $isNested = $false
      if ($Resiliency -eq "NestedTwoWayMirror" -or $Resiliency -eq  "NestedParity" -or $Resiliency -eq  "NestedMirrorAcceleratedParity")
      {
        $isNested =$true
      }

      if ($isNested -eq $true)
      {
        switch ($MediaType)
        {
            "SCM"
            {
                $MirrorTierName = "NestedMirrorOnSCM"
                $ParityTierName = "NestedParityOnSCM"
                break;
            }

            "SSD"
            {
                $MirrorTierName = "NestedMirrorOnSSD"
                $ParityTierName = "NestedParityOnSSD"
                break;
            }

            "HDD"
            {
                $MirrorTierName = "NestedMirrorOnHDD"
                $ParityTierName = "NestedParityOnHDD"
                break;
            }
        }
      }
      else
      {
        switch ($MediaType)
        {
            "SCM"
            {
                $MirrorTierName = "MirrorOnSCM"
                $ParityTierName = "ParityOnSCM"
                break;
            }

            "SSD"
            {
                $MirrorTierName = "MirrorOnSSD"
                $ParityTierName = "ParityOnSSD"
                break;
            }

            "HDD"
            {
                $MirrorTierName = "MirrorOnHDD"
                $ParityTierName = "ParityOnHDD"
                break;
            }
        }
      }

      if ($UseTierNamedCapacity)
      { # if using the older "Capacity" tier, then we will only allow 2 or 3 way mirror in UX, and we will need to find that tier here instead

        $CapacityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Capacity" }

        if ($CapacityTier -ne $null) {
          $CapacityTier | Set-StorageTier -PhysicalDiskRedundancy $PhysicalDiskRedundancy
          # get refernce to the updated tier
          $CapacityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Capacity" }
          $newVolumeArgs["StorageTiers"] = $CapacityTier
        }
        else {
# todo: throw a code we can catch to show loc strings?
          throw "Capacity tier not found. This is required for mirror volumes."
        }
      }

      elseif ($UseTierNamedPerformance)
      { # if using the older "Performance" tier, we can do MRT in addition to 2 or 3 way mirror, and we will need to find that tier here instead

        $PerformanceTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Performance" }

        if ($PerformanceTier -ne $null) {
          $PerformanceTier | Set-StorageTier -PhysicalDiskRedundancy $PhysicalDiskRedundancy
          # get refernce to the updated tier
          $PerformanceTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Performance" }
          if ($Resiliency -eq "MirrorAcceleratedParity") {
            $CapacityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Capacity" }

            if ($CapacityTier -ne $null) {
              $CapacityTier | Set-StorageTier -PhysicalDiskRedundancy $PhysicalDiskRedundancy
              # get refernce to the updated tier
              $CapacityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq "Capacity" }
              $newVolumeArgs["StorageTiers"] = $CapacityTier
            }
            else {
  # todo: throw a code we can catch to show loc strings?
              throw "Capacity tier not found. This is required for mirror volumes."
            }

            $WS16MRTTiers = $CapacityTier, $PerformanceTier # parity first, mirror second
            $newVolumeArgs["StorageTiers"] = $WS16MRTTiers
          } else {
            $newVolumeArgs["StorageTiers"] = $PerformanceTier
          }
        }
        else {
  # todo: throw a code we can catch to show loc strings?
          throw "Performance tier not found. This is required for mirror volumes."
        }
      }
      else
      { # use newer mirror/parity on hdd/ss/scm tiers
          $MirrorTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq $MirrorTierName }

          # we will create  tiers so that we can set thier properties without editing the default tiers
          if ($MirrorTier -eq $null) {
            # all of our WAC cases will reuire the mirror tier
# todo: throw a code we can catch to show loc strings?
              throw "Mirror tier not found. This is required for mirror volumes."
          }

          # only fetch the parity tier if we are making MRT volume
          if (($Resiliency -eq "MirrorAcceleratedParity") -or ($Resiliency -eq "NestedMirrorAcceleratedParity")) {
            $ParityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq $ParityTierName }


            if ($ParityTier -eq $null) {
# todo: throw a code we can catch to show loc strings?
              throw "Parity tier not found. This is required for mirror accelearated parity volumes."
            }

          }

          if ($isNested -eq $true)
          {

              # set provisioning type if supported - do not touch physical disk redundancy for nested!
              if ($CanSetProvisioningType)
              {
                if ($MirrorTier -ne $null) {
                  $MirrorTier | Set-StorageTier -ProvisioningType $ProvisioningType | Out-Null
                }

                if ($ParityTier -ne $null) {
                  $ParityTier | Set-StorageTier -ProvisioningType $ProvisioningType | Out-Null
                }
              }

          }
          else # set non-nested tiers
          {

            if ($CanSetProvisioningType)
            { # set provisioning type and physical disk redundancy

              if ($MirrorTier -ne $null) {
                $MirrorTier | Set-StorageTier -ProvisioningType $ProvisioningType -PhysicalDiskRedundancy $PhysicalDiskRedundancy | Out-Null

              }

              if ($ParityTier -ne $null) {
                $ParityTier | Set-StorageTier -ProvisioningType $ProvisioningType -PhysicalDiskRedundancy $PhysicalDiskRedundancy | Out-Null

              }

            } else #set just physical disk redundancy - provisioning type not supported
            {
              if ($MirrorTier -ne $null) {
                $MirrorTier | Set-StorageTier -PhysicalDiskRedundancy $PhysicalDiskRedundancy | Out-Null
              }

              if ($ParityTier -ne $null) {
                $ParityTier | Set-StorageTier -PhysicalDiskRedundancy $PhysicalDiskRedundancy | Out-Null
              }

            }

          }


          # tiers are set, now select the correct tiers to supply to new-virtualdisk newVolumeArgs
          $MirrorTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq $MirrorTierName }

          # If no parity tier, and we are not making MRT volume, then the null value here will not matter
          $ParityTier = Get-StorageTier -StoragePool $pool | Where-Object { $_.FriendlyName -eq $ParityTierName }
          $MRTTiers =  $ParityTier, $MirrorTier

          # set tiers to use based on redundancy
          switch ($Resiliency)
          {
            "TwoWayMirror"
            {
                $newVolumeArgs["StorageTiers"] = $MirrorTier
                break;
            }

            "ThreeWayMirror"
            {
                $newVolumeArgs["StorageTiers"] = $MirrorTier
                break;
            }

            "MirrorAcceleratedParity"
            {
                $newVolumeArgs["StorageTiers"] = $MRTTiers
                break;
            }

            "NestedTwoWayMirror"
            {
                $newVolumeArgs["StorageTiers"] = $MirrorTier
                break;
            }

            "NestedMirrorAcceleratedParity"
            {
                $newVolumeArgs["StorageTiers"] = $MRTTiers
                break;
            }

          }
      }
      return $newVolumeArgs
    }
  }

function New-VolumePath
{
  param (
      [psobject]
      [Parameter(
        Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $newVolumeArgs,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $singleSiteVolume,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $isForRawLog,

      [FileSystemType]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $FileSystem,

      [UInt64]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $VolumeSize,

      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $FriendlyName,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $EnableBitlocker,

      [string]
      [Parameter(Mandatory = $true)]
      $encryptionMethod,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $backupPasswordToAD,

      [bool]
      [Parameter(Mandatory = $true)]
      $clusterADAccountCanUnlock,

      [bool]
      [Parameter(
          Mandatory        = $false)]
      $externalKey,

      [bool]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $SetIntegrityStreams,

      [string]
      [Parameter(
          Mandatory        = $true)]
      [ValidateNotNullOrEmpty()]
      $node
  )

  Begin
  {
      [flagsattribute()]
      Enum FileSystemType
      {
          NTFS       = 14
          ReFS       = 15
          CSVFS_NTFS = 32768
          CSVFS_ReFS = 32769
      }

  }

  Process
  {


      # up to this point, nothing needs to be cleaned up if we hit an err
      #  new-volume cleans up if it errs out
      # after this point, we wneed to remove the virutal disk if anything errs

      # after volume is created, we still need to clean up if we err on Bitlocker or integrity streams
      #  or if new-srgroup fails


      $volumePath = $null
      $volumeId = $null
      $csvToUse = $null
      $useVolumeId = $false;
      $useCsv = $false;

        # for non-replicated voluems we will use New-Volume
      if ($singleSiteVolume -eq $true) {

          $volume = New-Volume @newVolumeArgs

          $volumePath = $volume.path
          $volumeId = $volume.uniqueid
          $useVolumeId = $true
      }
      else {  # for replicated volumes, we will use custom method create vDisk , partition, etc.
          $virtualdisk = $null;

          try {

            $virtualdisk = New-VirtualDisk @newVolumeArgs -ErrorAction Stop

            $vdClusterResource = $virtualdisk | Get-ClusterResource -ErrorAction Stop

            #  need to put the virtual disk into maintenance before we can format the volume
            $vdClusterResource | Suspend-ClusterResource -Force -ErrorAction Stop | Out-Null

            $disk = $virtualdisk | Get-Disk -ErrorAction Stop
            $partition = $disk | New-Partition -Size $VolumeSize  -ErrorAction Stop

            if ($isForRawLog) {
              $volumePath = $partition.AccessPaths[0]
            } else {

              $tempFileSystem = $FileSystem

              #  if CSV, make REFS or NTFS first then make the the volume csv afterword
              if ($FileSystem -eq "CSVFS_REFS")
              {
                  $tempFileSystem = "REFS"
              }

              if ($FileSystem -eq "CSVFS_NTFS")
              {
                  $tempFileSystem = "NTFS"
              }

              # attempt to give the volume a label matching the VDisk friendly name, if this is too many chars (gt 32) it will not get set
              $volume = $partition | Format-Volume -FileSystem $tempFileSystem -NewFileSystemLabel $FriendlyName -ErrorAction Stop
              $volumePath = $volume.Path
            }

            # now take virtual disk out of maintenance mode
            $vdClusterResource | Resume-ClusterResource -ErrorAction Stop | Out-Null

            if ($FileSystem -eq "CSVFS_REFS" -or $FileSystem -eq "CSVFS_NTFS")
            {
                $vdClusterResource | Add-ClusterSharedVolume -ErrorAction Stop | Out-Null

                $csv = Get-ClusterSharedVolume -ErrorAction Stop | Where-Object { $_.Id -eq $vdClusterResource.Id }
                $volumePath = $csv.SharedVolumeInfo[0].FriendlyVolumeName
                $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null

                $vdClusterResource  = $virtualdisk | Get-ClusterResource -ErrorAction Stop


                $csvToUse = $csv
                $useCsv = $true;
            }
          }
          catch {
            # if there is an err up to this point remove the virtual disk if it got created and throw the err
            if ($virtualdisk -ne $null) {
              # first ensure the clsuter resource is online so that we can remove the virtual disk
              $vdClusterResource | Resume-ClusterResource  -ErrorAction Stop | Out-Null

              $virtualdisk | Remove-VirtualDisk -Confirm:$false -ErrorAction Stop
            }

            throw
          }

      }


      $volumeResults = @{
        "volumePath" = $volumePath;
        "integrityAndBitLockerResults" = $null;
      }

      # optionally set bitlocker and/or integrity streams
      # if we err here, we will need to inform the user that the volume got created but bitlocker/integrity streams failed
      # we will need to online the volume again as it may have failed there

      if ($EnableBitlocker -or $SetIntegrityStreams) {
        $SetVolumeArgs = @{
          "node" = $node;
          "useVolumeId" = $useVolumeId;
          "useCsv" = $useCsv;
          # for a fast fix, we will add the 2 required properties for the case that integrity sterams is set but bitlcoker is not
          "externalKey" = $false;
          "encryptionMethod" = $encryptionMethod
        }

        if ($useCsv)  {
          $SetVolumeArgs["inputVdClusterResource"] = $vdClusterResource;
          $SetVolumeArgs["csvToUse"] = $csvToUse;
          $SetVolumeArgs["inputVolumePath"] = $volumePath;
        }

        if ($useVolumeId) {
          $SetVolumeArgs["volumeId"] = $volumeId;
        }


        if ($SetIntegrityStreams) {
          #  this will only apply to single-site volumes created by New-Volume as we will already set the parameter to false after format-volume for replicated volumes
          $SetVolumeArgs["SetIntegrityStreams"] = $SetIntegrityStreams
        }


        if ($EnableBitlocker) {
          $SetVolumeArgs["EnableBitLocker"] = $EnableBitLocker
          $SetVolumeArgs["backupPasswordToAD"] = $backupPasswordToAD
          $SetVolumeArgs["clusterADAccountCanUnlock"] = $clusterADAccountCanUnlock
          $SetVolumeArgs["externalKey"] = $externalKey
          $SetVolumeArgs["encryptionMethod"] = $encryptionMethod
        }

        $volumeResults.integrityAndBitLockerResults = Set-IntegrityAndBitlocker @SetVolumeArgs
      }

      return $volumeResults
  }
}


# for a single-site csv volume and non-stretch cluster scenarios, we will just make one volume
function New-VolumeSet
{
    param (
        [psobject]
        [Parameter(
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Data,  #has 6 props: .VolumeData  <array of volumedata ps objects>, .LogVolumeData <volume data ps object>, .RGData <rg data psobject>, .SingleSite <boolean>, .UseTierNamedCapacity<boolean>, UseTierNamedPerformance<boolean>
        [string]
        [Parameter(
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $node
    )

    #  if creating a volume errs, we will err out
    #  but if it succeeds, we will need to care about 3 cases:
      # 1. bitlocker or integrity streams errs on src data volume (not attempted on logs or destination data volume)
      # 2. log volume errs - we will need to tell user that the log volume erred but the data volume succeeded
      # 3. new-srgroup errs - then  we will still have 2 valid volumes that user can delete in  from the UX
    $volumeSetResults = @{
      "integrityAndBitLockerResults" = $null; #this will contain the bitlocker recovery key and any info about where we may have erred while setting this
      "logVolumeError" = $null;
      "srGroupError" = $null;
      "refsDedupError" = $null;
    }

    # used to provide volume paths for New-SRGroup if making replicated volume
    $srGroupVolumePaths = @()
    $volumePaths = @()

    $srGroupLogVolumePath = $null

    $pool = Get-StoragePool -FriendlyName $Data.VolumeData.storagePoolFriendlyName -ErrorAction Stop;

    $dataVolumeFailedToComeOnline = $null

    # move available storage so that the virtual disk is not detached when we create it
    # that way we can do Get-Disk with non-null result
    Move-AvailableStorage -Pool $pool | Out-Null

    Write-Progress -Activity "Create volume(s)"  -PercentComplete 25

    # handle data volume(s) - there is only one as of now
    foreach ($Item in $Data.VolumeData)
    {
        try {
          $newVolumeArgs =  Get-VolumeArguments -FileSystem $Item.FileSystem -singleSiteVolume $Data.SingleSite -UseTierNamedCapacity $Data.UseTierNamedCapacity -UseTierNamedPerformance $Data.UseTierNamedPerformance  -FriendlyName $Item.FriendlyName -Resiliency $Item.Resiliency -CanSetProvisioningType $Item.CanSetProvisioningType -ProvisioningType $Item.ProvisioningType -TierSizes $Item.TierSizes -MediaType $Item.MediaType -Pool $pool

          #  integrity streams and bitlocker should only be set on source data volumes if replicated - the data passed in takes care of this from UX
          $volumePathResults = New-VolumePath -ErrorAction Stop -isForRawLog $false -FriendlyName $Item.FriendlyName -FileSystem $Item.FileSystem -VolumeSize $Item.VolumeSize  -SetIntegrityStreams $Item.SetIntegrityStreams -EnableBitlocker $Item.enableBitlocker -BackupPasswordToAD $Item.BackupPasswordToAD -ClusterADAccountCanUnlock $Item.clusterADAccountCanUnlock -ExternalKey $Item.externalKey -EncryptionMethod $Item.encryptionMethod -node $node -singleSiteVolume $Data.SingleSite -newVolumeArgs $newVolumeArgs

          # used for New-SRGoup if creating replicated volume - does not need to be returned
          $srGroupVolumePaths += $volumePathResults.volumePath
          $volumePaths += $volumePathResults.volumePath

          $volumeSetResults.integrityAndBitLockerResults = $volumePathResults.integrityAndBitLockerResults

          # we do not wnat to proceed  to creating log volume if data volume did not come online
          if ($volumePathResults.integrityAndBitLockerResults -ne $null -and $volumePathResults.integrityAndBitLockerResults.resumeResourceFailed) {
            $dataVolumeFailedToComeOnline = $true
          } else {
            $dataVolumeFailedToComeOnline = $false
          }

        }
        catch {
          throw
        }

    }

    Write-Progress -Activity "Create volume(s)"  -PercentComplete 50

    if ($Data.SingleSite -eq $false -and $dataVolumeFailedToComeOnline -eq $false) {
      # we are creating a replicated volume - first create the log volume, then make SR group form data volume(s) and log volume
      $LogItem = $Data.LogVolumeData

      try {

          $logVolumeArgs =  Get-VolumeArguments -FileSystem $LogItem.FileSystem -singleSiteVolume $Data.SingleSite -UseTierNamedCapacity $Data.UseTierNamedCapacity -UseTierNamedPerformance $Data.UseTierNamedPerformance  -FriendlyName $LogItem.FriendlyName -Resiliency $LogItem.Resiliency -CanSetProvisioningType $LogItem.CanSetProvisioningType -ProvisioningType $LogItem.ProvisioningType -TierSizes $LogItem.TierSizes -MediaType $LogItem.MediaType -Pool $pool


          #  integrity streams and bitlocker should only be set on source data volumes if replicated - the data passed in takes care of this from UX

          $logVolumePathResults = New-VolumePath -ErrorAction Stop -isForRawLog $LogItem.isForRawLog -FriendlyName $LogItem.FriendlyName -FileSystem $LogItem.FileSystem -VolumeSize $LogItem.VolumeSize  -SetIntegrityStreams $LogItem.SetIntegrityStreams -EnableBitlocker $LogItem.enableBitlocker -BackupPasswordToAD $LogItem.BackupPasswordToAD -ClusterADAccountCanUnlock $LogItem.clusterADAccountCanUnlock -ExternalKey $LogItem.externalKey -EncryptionMethod $LogItem.encryptionMethod -node $node -singleSiteVolume $Data.SingleSite -newVolumeArgs $logVolumeArgs

          $srGroupLogVolumePath = $logVolumePathResults.volumePath

      }
      catch {
          $volumeSetResults.logVolumeError = $_
      }

      Write-Progress -Activity "Create volume(s)" -PercentComplete 75

      # proceed only if log volume didn't err out
      if ($volumeSetResults.logVolumeError -eq $null) {
        #  only import StorageReplica if it is needed - it will err if a non-stretch cluster does not have it installed
            try {
              Import-Module StorageReplica -ErrorAction Stop
            }
            catch {
                $volumeSetResults.srGroupError = $_
            }

            if ($volumeSetResults.srGroupError -eq $null) {

              $srErrVar = $null
              if ($LogItem.isForRawLog) {

                if ($Data.RGData.enableCompression) {
                  New-SRGroup -LogType RAW -ComputerName $Data.RGData.ComputerName -Name $Data.RGData.Name -VolumeName $srGroupVolumePaths -LogVolumeName $srGroupLogVolumePath -LogSizeInBytes $Data.RGData.LogSizeInBytes -EnableConsistencyGroups:$Data.RGData.EnableConsistencyGroups -EnableEncryption:$Data.RGData.EnableEncryption -EnableCompression:$Data.RGData.enableCompression  -ErrorAction SilentlyContinue -ErrorVariable srErrVar | Out-Null
                } else {
                  New-SRGroup -LogType RAW -ComputerName $Data.RGData.ComputerName -Name $Data.RGData.Name -VolumeName $srGroupVolumePaths -LogVolumeName $srGroupLogVolumePath -LogSizeInBytes $Data.RGData.LogSizeInBytes -EnableConsistencyGroups:$Data.RGData.EnableConsistencyGroups -EnableEncryption:$Data.RGData.EnableEncryption -ErrorAction SilentlyContinue -ErrorVariable srErrVar | Out-Null
                }

              } else {
                if ($Data.RGData.enableCompression) {
                  New-SRGroup -ComputerName $Data.RGData.ComputerName -Name $Data.RGData.Name -VolumeName $srGroupVolumePaths -LogVolumeName $srGroupLogVolumePath -LogSizeInBytes $Data.RGData.LogSizeInBytes -EnableConsistencyGroups:$Data.RGData.EnableConsistencyGroups -EnableEncryption:$Data.RGData.EnableEncryption -EnableCompression:$Data.RGData.enableCompression  -ErrorAction SilentlyContinue -ErrorVariable srErrVar | Out-Null
                }
                else {
                  New-SRGroup -ComputerName $Data.RGData.ComputerName -Name $Data.RGData.Name -VolumeName $srGroupVolumePaths -LogVolumeName $srGroupLogVolumePath -LogSizeInBytes $Data.RGData.LogSizeInBytes -EnableConsistencyGroups:$Data.RGData.EnableConsistencyGroups -EnableEncryption:$Data.RGData.EnableEncryption -ErrorAction SilentlyContinue -ErrorVariable srErrVar | Out-Null
                }

              }


              $volumeSetResults.srGroupError = $srErrVar
            }
      }
    }

    if ($Data.refsDedupData) {

      $refsDedupData = $Data.refsDedupData

      foreach ($Item in $Data.VolumeData)
      {

        $index = [array]::indexOf($Data.VolumeData, $item)
        $path = $volumePaths[$index]

        # move the csv to THIS node to be sure we are on the right node
        $FriendlyName = $Item.FriendlyName
         # since we just created the virtual disk, it will not have the possiblity of being renamed, so this is sufficient to find the CSV
        $csv = Get-ClusterSharedVolume -ErrorAction Stop | Where-Object { $_.Name -eq "Cluster Virtual Disk ($FriendlyName)" }
        $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null


        try {
          Handle-ReFSDedupOnCreateVolume -enableDedup $refsDedupData.enableDedup -setSchedule  $refsDedupData.schedule.setSchedule  -path $path -start $refsDedupData.schedule.start -hours $refsDedupData.schedule.hours -days $refsDedupData.schedule.days -ErrorAction Stop

        }
        catch {
          $volumeSetResults.refsDedupError = $_
        }
      }

    }

    Write-Progress -Activity "Create volume(s)" -PercentComplete 100

    return $volumeSetResults
}

New-VolumeSet -Data $Data -Node $node


}
## [END] New-WACSDDCHCIClusterVolume ##
function New-WACSDDCSRPartnership {
<#

.SYNOPSIS
Creates Storage Replica partnership

.DESCRIPTION
Creates Storage Replica partnership

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
  [bool]
  $seeded,

  [Parameter(Mandatory = $true)]
  [int]
  $replicationMode,

  [Parameter(Mandatory = $true)]
  [uint32]
  $asyncRPO
)
Import-Module StorageReplica
$customArgs = @{
    "SourceComputerName" =  $sourceComputerName;
    "DestinationComputerName" =  $destinationComputerName;
    "SourceRGName" =  $sourceRGName;
    "DestinationRGName" =  $destinationRGName;
    "ReplicationMode" =  $replicationMode;
}

if ($asyncRPO -gt 0)
{
    $customArgs.AsyncRPO = $asyncRPO
}

New-SRPartnership @customArgs -Seeded:$seeded


}
## [END] New-WACSDDCSRPartnership ##
function Register-WACSDDCAzureStackHCI {
<#

.SYNOPSIS
Registers Azure Stack HCI cluster with Azure
.DESCRIPTION
Registers Azure Stack HCI cluster with Azure
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $subscriptionId,
    [Parameter(Mandatory = $true)]
    [String]
    $armAccessToken,
    [Parameter(Mandatory = $true)]
    [String]
    $accountId,
    [Parameter(Mandatory = $true)]
    [String]
    $azureRegion,
    [Parameter(Mandatory = $true)]
    [String]
    $resourceGroup,
    [Parameter(Mandatory = $true)]
    [String]
    $environmentName
  )

try {
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
  Install-Module Az.Resources -Force | Out-Null
  Import-Module Az.Resources -ErrorAction Stop

  $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

  if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
  {
    # insufficient verison - get a new one from PS Gallery
    Update-Module Az.StackHCI -Force | Out-Null
  }
  else
  {
    Import-Module $module -ErrorAction Stop
  }
}
catch {
  Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
}

try
{
    $DebugPreference = 'Continue'
    Register-AzStackHCI -SubscriptionId $subscriptionId -ArmAccessToken $armAccessToken -AccountId $accountId -Region $azureRegion -ResourceGroupName $resourceGroup -EnvironmentName $environmentName -IsWac:$true -Verbose -Debug -Confirm:$False

    $DebugPreference = 'SilentlyContinue'
}

catch {
    $DebugPreference = 'SilentlyContinue'
    Throw
}

}
## [END] Register-WACSDDCAzureStackHCI ##
function Register-WACSDDCSDDCDiagnosticArchiveJob {
<#

.SYNOPSIS
Registers SDDC diagnostic archive job

.DESCRIPTION
Registers SDDC diagnostic archive job

.ROLE
Administrators

#>

try {
    Import-Module PrivateCloud.DiagnosticInfo -ErrorAction Stop
}
catch {
    Import-Module PowerShellGet
    Import-Module PackageManagement
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module - run on all nodes
    Install-Module PrivateCloud.DiagnosticInfo -Force # this will get the latest verison
}

Register-SDDCDiagnosticArchiveJob

}
## [END] Register-WACSDDCSDDCDiagnosticArchiveJob ##
function Remove-WACSDDCAzStackHCIVMAttestation {
<#

.SYNOPSIS
Calls remove-azstackHCI on specified nodes
.DESCRIPTION
Calls remove-azstackHCI on specified nodes
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmName
  )

  try {
    $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
    {
      # insufficient verison - get a new one from PS Gallery
      Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
      Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
    }
    else
    {
      Import-Module $module -ErrorAction Stop
    }
  }
  catch {
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }


#  if vm name supplied, add just the single vm, else add all vms
$err = $null
$result = $null
try
{
    $result = Remove-AzStackHCIVMAttestation -VMName $vmName -Force -ErrorAction Stop # add a single vm on this node
}
catch {
  $err = $_
}

Write-Output @{
  "error" = $err;
  "result" = $result
}

}
## [END] Remove-WACSDDCAzStackHCIVMAttestation ##
function Remove-WACSDDCGalleryImage {
<#

.SYNOPSIS
Remove the Azure Stack HCI gallery image

.DESCRIPTION
Remove the Azure Stack HCI gallery image

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $galleryImageName,

    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

return az azurestackhci galleryimage delete --subscription $subscriptionID --resource-group $resourceGroup --name $galleryImageName --yes --only-show-errors

}
## [END] Remove-WACSDDCGalleryImage ##
function Remove-WACSDDCVMNetworkAdapterExtendedAcl {
<#
.SYNOPSIS

Remove the ACL rule on a cluster VM.
.DESCRIPTION

Removes the ACL rule with the given params on the cluster VM.

.ROLE
Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [string] $direction,
    [Parameter(Mandatory = $true)]
    [int] $weight,
    [Parameter(Mandatory = $false)]
    [string] $vmNetworkAdapterName,
    [Parameter(Mandatory = $false)]
    [string] $computerName,
    [Parameter(Mandatory = $true)]
    [string] $vmName
)

Import-Module  'Hyper-V'

$parameters = @{
                'Direction' = $direction;
                'Weight' = $weight;
                'VMName' = $vmName;
               }

if ($vmNetworkAdapterName) {
    $parameters.Add('VMNetworkAdapterName', $vmNetworkAdapterName)
}
if ($computerName) {
    $parameters.Add('ComputerName', $computerName)
}

Remove-VMNetworkAdapterExtendedAcl @parameters

}
## [END] Remove-WACSDDCVMNetworkAdapterExtendedAcl ##
function Remove-WACSDDCVirtualNetwork {
<#

.SYNOPSIS
Remove the Azure Stack HCI virtual network

.DESCRIPTION
Remove the Azure Stack HCI virtual network

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $vmSwitchName,

    [Parameter(Mandatory = $true)]
    [string]
    $subscriptionID,

    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup
)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

return az azurestackhci virtualnetwork delete --subscription $subscriptionID --resource-group $resourceGroup --name $vmSwitchName --yes --only-show-errors
}
## [END] Remove-WACSDDCVirtualNetwork ##
function Remove-WACSDDCVolume {
<#

.SYNOPSIS
Deletes a volume using volume id (not possible for offline volumes)

.DESCRIPTION
Deletes a volume using volume id (not possible for offline volumes)

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string] $volumeId
)

Import-Module Storage
Import-module FailoverClusters


function Get-MatchingCSV {
  param (
    $voldisk
  )

  foreach ($csvObj in Get-ClusterSharedVolume) {

    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}

$volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
$voldisk = $volumeobj | Get-Partition | Get-Disk
if ($voldisk -eq $null) {
  # could not find the partition - we are unable to delete the volume
  return @{ "customWACRemoveVolumePSErrorCode" = 1; }
} else {
  $virtualDisk = $volDisk | Get-VirtualDisk # will be null for non-s2d volume

  if ($virtualDisk -ne $null) {
    $virtualDisk | Remove-VirtualDisk -Confirm:$false | Out-Null
  }
  else {

    $csv = Get-MatchingCSV -voldisk $voldisk -ErrorAction Stop
    $physicalDiskResource = $csv | Remove-ClusterSharedVolume -confirm:$false
    $physicalDiskResource | remove-clusterResource -Force | Out-Null

    # - clear the disk so that it will RAW and can be reused
    $disk = Get-Disk -Number  $voldisk.DiskNumber
    $disk | set-disk -IsReadOnly $false
    $disk | Set-Disk -IsOffline $false

    $disk  | Clear-Disk -RemoveData -Confirm:$false
  }
}

return @{ "customWACRemoveVolumePSErrorCode" = $null; }



}
## [END] Remove-WACSDDCVolume ##
function Remove-WACSDDCVolumeUsingClusterResourceId {
<#

.SYNOPSIS
Deletes a volume using cluster resource id (will work for offline volumes)

.DESCRIPTION
Deletes a volume using cluster resource id (will work for offline volumes)

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string] $clusterResourceId
)

Import-Module Storage
Import-module FailoverClusters

$csv = Get-ClusterSharedVolume | Where-Object { $_.id -eq $clusterResourceId}

$virtualDiskClusterParameter = $csv | Get-ClusterParameter | Where-Object { $_.name -eq "virtualDiskId"}

if ($virtualDiskClusterParameter.value -ne "") {
  $virtualDisk = Get-VirtualDisk | Where-Object { $_.objectid.contains($virtualDiskClusterParameter.value)}

  if ($virtualDisk -eq $null) {
    # Virtual disk not found - could not delete the volume
    return @{"customWACRemoveVolumePSErrorCode" = 2}
  }
  $virtualDisk | Remove-VirtualDisk -confirm:$false
} else {
  $diskClusterParameter = $csv | Get-ClusterParameter | Where-Object { $_.name -eq "diskGuid"}

  # for volumes not backed by a virutal disk, first remove the cluster resoruce
  $physicalDiskResource = $csv | Remove-ClusterSharedVolume -confirm:$false

  $physicalDiskResource | Remove-ClusterResource -Force | Out-Null

  # then clear the disk so that it will RAW and can be reused
  $disk = Get-Disk | Where-Object { $_.objectid.contains($diskClusterParameter.value)}
  if ($disk -eq $null) {
    # could not find the disk - we are unable to clear the data
    return @{ "customWACRemoveVolumePSErrorCode" = 3; }
  }

  $disk | Set-Disk -IsReadOnly $false

  $disk | Set-Disk -IsOffline $false

  $disk | Clear-Disk -RemoveData -Confirm:$false
}

return @{ "customWACRemoveVolumePSErrorCode" = $null; }



}
## [END] Remove-WACSDDCVolumeUsingClusterResourceId ##
function Restart-WACSDDCComputer {
<#

.SYNOPSIS
Restarts a machine

.DESCRIPTION
Restarts a machine

.ROLE
Administrators

#>
Import-Module  Microsoft.PowerShell.Management
Restart-Computer

}
## [END] Restart-WACSDDCComputer ##
function Resume-WACSDDCClusternode {
<#

.SYNOPSIS
Resumes suspended cluster node

.DESCRIPTION
Resumes suspended cluster node

.ROLE
Administrators

#>
Import-Module FailoverClusters
Resume-ClusterNode

}
## [END] Resume-WACSDDCClusternode ##
function Set-WACSDDCAccelNetManagement {
<#

.SYNOPSIS
Edits accelerated networking config on the cluster
.DESCRIPTION
Edits accelerated networking config on the cluster
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $intentName,
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [int]
    $nodeReservePercentage
)
$result = @{
    "failoverClustersNotInstalled" = $false
    "setAccelNetManagementStatus" = $null
    "errorReturned" = $null
}
$parameters = @{}
if ($intentName) {
    $parameters.Add('IntentName', $intentName)
}
if ($nodeReservePercentage) {
    $parameters.Add('NodeReservePercentage', $nodeReservePercentage)
}
try {
    Import-Module FailoverClusters -ErrorAction Stop
    try {
      # Find out if the selected intent passed the prerequisite check
      $prereq = (Get-AccelNetManagementPreReq -IntentName $intentName) | Where-Object { $_.Passed -eq $False } -InformationAction Ignore -ErrorAction Stop

      if ($null -ne $prereq) {
        # The selected intent does not pass prerequisite validation, fail the script
        throw $prereq.Message
      }
      $result.setAccelNetManagementStatus = Set-AccelNetManagement @parameters -InformationAction Ignore -ErrorAction Stop
    } catch {
        $result.errorReturned = $_
    }
} catch {
    $result.failoverClustersNotInstalled = $true
}
$result

}
## [END] Set-WACSDDCAccelNetManagement ##
function Set-WACSDDCAccelNetOnVirtualMachines {
<#
.SYNOPSIS
Given a list of virtual machines, set accel net performance level on these VMs

.DESCRIPTION
Given a list of virtual machines, set accel net performance level on these VMs

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]] $vmNames,
    [Parameter(Mandatory = $true)]
    [int] $performanceLevel
)

$result = @{
  "succeededVMs" = $null;
  "failedVMs" = $null;
}

Import-Module FailoverClusters -ErrorAction Stop

###############################################################################
# Constants
###############################################################################
# Script scope variable
$script:virtualMachineSuccesses = New-Object System.Collections.ArrayList
$script:virtualMachineFailures = New-Object System.Collections.ArrayList

function main($vmNames, $performanceLevel) {

    foreach ($vmName in $vmNames) {
      try {
        Set-AccelNetVM -VMName $vmName -Performance $performanceLevel -ErrorAction Stop

        $script:virtualMachineSuccesses.Add($vmName) > $null
      }
      catch {
        $failedVmObj = New-Object -TypeName PSObject
        $failedVmObj | Add-Member -NotePropertyName VmName -NotePropertyValue $vmName
        $failedVmObj | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $_
        $script:virtualMachineFailures.Add($failedVmObj) > $null
      }
    }

    $result = New-Object -TypeName PSObject
    $result | Add-Member -NotePropertyName SucceededVMs -NotePropertyValue $script:virtualMachineSuccesses
    $result | Add-Member -NotePropertyName FailedVMs -NotePropertyValue $script:virtualMachineFailures

    return $result
}

###############################################################################
# Script execution starts here...
###############################################################################
return main $vmNames $performanceLevel

}
## [END] Set-WACSDDCAccelNetOnVirtualMachines ##
function Set-WACSDDCAutoPoolState {

<#

.SYNOPSIS
Set autopool storage health setting

.DESCRIPTION
Set autopool storage health setting

.ROLE
Administrators

#>
param (
		[Parameter(Mandatory = $true)]
		[bool]
    $enabled
)
Import-Module Storage
Get-StorageSubSystem "Cluster*" | Set-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoPool.Enabled" -Value $enabled

}
## [END] Set-WACSDDCAutoPoolState ##
function Set-WACSDDCAutoRetireState {
<#

.SYNOPSIS
Sets auto retire disk setting

.DESCRIPTION
Sets auto retire disk setting

.ROLE
Administrators

#>

param (
		[Parameter(Mandatory = $true)]
		[bool]
    $enabled
)
Import-Module Storage
Get-StorageSubSystem "Cluster*" | Set-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoRetire.OnLostCommunication.Enabled" -Value $enabled

}
## [END] Set-WACSDDCAutoRetireState ##
function Set-WACSDDCAzStackHCI {
<#

.SYNOPSIS
Calls set-azstackHCI
.DESCRIPTION
Calls set-azstackHCI
.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool] $enableWSSubscription,

    [Parameter(Mandatory = $true)]
    [string] $accountId,

    [Parameter(Mandatory = $true)]
    [string] $armAccessToken,

    [Parameter(Mandatory = $true)]
    [string] $environmentName
  )

  try {
    Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
    Install-Module Az.Resources -Force | Out-Null
    Import-Module Az.Resources -ErrorAction Stop
    $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
    {
      # insufficient verison - get a new one from PS Gallery
      Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
    }
    else
    {
      Import-Module $module -ErrorAction Stop
    }
  }
  catch {
    Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
  }

Set-AzStackHCI -EnableWSSubscription $enableWSSubscription -EnvironmentName $environmentName -AccountId $accountId -ArmAccessToken $armAccessToken -Force -Confirm:$false

# # give azure a chance to sync up with on prem
Start-Sleep -Seconds 10


}
## [END] Set-WACSDDCAzStackHCI ##
function Set-WACSDDCAzureStackHCIPreviewChannel {
<#

.SYNOPSIS
Gets the state of the Get-PreviewChannel command

.DESCRIPTION
Gets the state of the Get-PreviewChannel command

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $False)]
    [string]
    $channel,

    [Parameter(Mandatory = $False)]
    [string]
    $ring
)
Import-Module PreviewOptIn
Set-PreviewChannel -Channel $channel -Ring $ring

}
## [END] Set-WACSDDCAzureStackHCIPreviewChannel ##
function Set-WACSDDCBitLockerADBackupRegistryKeys {
<#

.SYNOPSIS
Sets bitlocker settings  for FDVRREcovyr and FDVActiveDirectoryBackup

.DESCRIPTION
Sets bitlocker settings  for FDVRREcovyr and FDVActiveDirectoryBackup

.ROLE
Administrators

#>
Import-Module  Microsoft.PowerShell.Management

$path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

$pathExists = Test-Path $path

if (-not $pathExists)
{
  New-Item $path -Force
}

Set-ItemProperty -Path $path -Name FDVRecovery -Value 1 | Out-Null

Set-ItemProperty -Path $path -Name FDVActiveDirectoryBackup -Value 1 | Out-Null

}
## [END] Set-WACSDDCBitLockerADBackupRegistryKeys ##
function Set-WACSDDCClusterBlockCacheSize {
<#

.SYNOPSIS
Sets cluster block cache size

.DESCRIPTION
Sets cluster block cache size

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $blockCacheSize
)
Import-Module FailoverClusters
$cluster = FailoverClusters\Get-Cluster;

$cluster.BlockCacheSize = $blockCacheSize

}
## [END] Set-WACSDDCClusterBlockCacheSize ##
function Set-WACSDDCClusterName {
<#

.SYNOPSIS
Sets cluster name

.DESCRIPTION
Sets cluster name

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $clusterName
)
Import-Module FailoverClusters
$cluster = FailoverClusters\Get-Cluster

$cluster.Name = $clusterName

}
## [END] Set-WACSDDCClusterName ##
function Set-WACSDDCClusterNodeShutdownBehavior {
<#

.SYNOPSIS
Sets node shutdown drain behavior

.DESCRIPTION
Sets node shutdown drain behavior

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $drainOnShutdown
)
Import-Module FailoverClusters
$cluster = FailoverClusters\Get-Cluster;

$cluster.DrainOnShutdown = $drainOnShutdown

}
## [END] Set-WACSDDCClusterNodeShutdownBehavior ##
function Set-WACSDDCClusterQuorum {
<#

.SYNOPSIS
Sets cluster witness

.DESCRIPTION
Sets cluster witness

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [bool]
  $isCloudWitness,

  [Parameter(Mandatory = $true)]
  [bool]
  $isDiskWitness,

  [Parameter(Mandatory = $true)]
  [bool]
  $isFileShareWitness,

  [Parameter(Mandatory = $false)]
  [string]
  $diskWitnessName,

  [Parameter(Mandatory = $false)]
  [string]
  $fileSharePath,

  [Parameter(Mandatory = $false)]
  [string]
  $username,

  [Parameter(Mandatory = $false)]
  [string]
  $password,

  [Parameter(Mandatory = $false)]
  [string]
  $accountName,

  [Parameter(Mandatory = $false)]
  [string]
  $accessKey,

  [Parameter(Mandatory = $false)]
  [string]
  $endpoint
)

function Get-Cred() {
  Param(
      [Parameter(Mandatory = $true)]
      [string]$password,

      [Parameter(Mandatory = $true)]
      [string]$username
  )
  Import-Module  Microsoft.PowerShell.Security
  Import-Module  Microsoft.PowerShell.Utility
  $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
  return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $username, $securePass
}

Import-Module FailoverClusters

if ($isCloudWitness -eq $false -and $isDiskWitness -eq $false -and $isFileShareWitness -eq $false)
{
    Set-ClusterQuorum -NoWitness
}

if ($isDiskWitness -eq $true)
{
  Set-ClusterQuorum -DiskWitness $diskWitnessName
}

if ($isFileShareWitness -eq $true)
{
    if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password))
    {
        Set-ClusterQuorum -FileShareWitness $fileSharePath
    }
    else {
        $cred = Get-Cred -UserName $username -Password $password;
        Set-ClusterQuorum -FileShareWitness $fileSharePath -Credential $cred
    }
}

if ($isCloudWitness -eq $true)
{
    if ($endpoint -ne $null)
    {
        Set-ClusterQuorum -CloudWitness -AccountName $accountName -AccessKey $accessKey -Endpoint $endpoint

    }
    else {
        Set-ClusterQuorum -CloudWitness -AccountName $accountName -AccessKey $accessKey
    }
}

}
## [END] Set-WACSDDCClusterQuorum ##
function Set-WACSDDCClusterS2D {
<#

.SYNOPSIS
Sets cache states for S2D

.DESCRIPTION
Sets cache states for S2D

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $persistentCache,
  [Parameter(Mandatory = $true)]
  [uint32]
  $cacheModeForHDD,
  [Parameter(Mandatory = $true)]
  [uint32]
  $cacheModeForSSD
)
Import-Module FailoverClusters
Set-ClusterS2D -CacheState $persistentCache -CacheModeHDD $cacheModeForHDD -CacheModeSSD $cacheModeForSSD

}
## [END] Set-WACSDDCClusterS2D ##
function Set-WACSDDCClusterTrafficEncryption {
<#

.SYNOPSIS
Sets cluster traffic encryption

.DESCRIPTION
Sets cluster traffic encryption

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $encryptCoreTraffic,
  [Parameter(Mandatory = $false)]
  [uint32]
  $encryptStorageTraffic
)
Import-Module FailoverClusters
$cluster = FailoverClusters\Get-Cluster;

$cluster.SecurityLevel = $encryptCoreTraffic

if ($encryptStorageTraffic)
{
  $cluster.SecurityLevelForStorage = $encryptStorageTraffic
}

}
## [END] Set-WACSDDCClusterTrafficEncryption ##
function Set-WACSDDCDisableWriteCache {
<#

.SYNOPSIS
Sets write cache enabled state

.DESCRIPTION
Sets write cache enabled state

.ROLE
Administrators

#>

param (
		[Parameter(Mandatory = $true)]
		[bool]
    $enabled
)

Import-Module Storage

Get-StorageSubSystem "Cluster*" | Set-StorageHealthSetting -Name "System.Storage.NestedResiliency.DisableWriteCacheOnNodeDown.Enabled" -Value $enabled

}
## [END] Set-WACSDDCDisableWriteCache ##
function Set-WACSDDCMonitoringData {
<#
.SYNOPSIS

Sets Monitoring Data log collection intervals
.DESCRIPTION

Sets Monitoring Data log collection intervals

.ROLE
Administrators
#>


param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $sddcManagementOperationalLogInterval
)

Import-Module FailoverClusters

Get-ClusterResource | Where-Object { $_.ResourceType -eq "SDDC Management" } | Set-ClusterParameter -Name "CacheDumpIntervalInSeconds" -Value $sddcManagementOperationalLogInterval

}
## [END] Set-WACSDDCMonitoringData ##
function Set-WACSDDCNonS2DVolume {
<#

.SYNOPSIS
Resize volume, change provisioning type

.DESCRIPTION
Resize volume, change provisioning type

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string] $volumeId,

    [bool]
    $enableBitlocker,

    [bool]
    $backupPasswordToAD,

    [bool]
    [Parameter(Mandatory = $true)]
    $externalKey,

    [bool]
    [Parameter(Mandatory = $true)]
    $clusterADAccountCanUnlock,

    [bool]
    $encryptionStatusChanged,

    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $node
)

Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
Import-Module Storage
Import-Module FailoverClusters
Import-Module BitLocker -ErrorAction SilentlyContinue # this one needs to continue since it is optional and won't be used if not installed

function Get-BitLockerRecoveryPassword {
  param (
    [string]
    [Parameter(
        Mandatory        = $true)]
    [ValidateNotNullOrEmpty()]
    $volumePath
  )

  $recoveryPassword = $null
  $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

  foreach($key in $keys){
    if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
      $recoveryPassword = $key.RecoveryPassword
      break;
    }
  }

  return $recoveryPassword

}


function Get-MatchingCSV {
  param (
    $volumeId
  )


  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk
  foreach ($csvObj in Get-ClusterSharedVolume) {

    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}


function Set-BitLocker {
  param (
    #  required params for all
    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $volumeId,
    [bool]
    [Parameter(Mandatory = $false)]
    $EnableBitLocker,


    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $node,

    [bool]
    [Parameter(Mandatory = $false)]
    $backupPasswordToAD,

    [bool]
    [Parameter(Mandatory = $false)]
    $externalKey,

    [bool]
    [Parameter(Mandatory = $false)]
    $clusterADAccountCanUnlock,

    [string]
    [Parameter(Mandatory = $false)]
    $encryptionMethod
  )



  $bitLockerAndDedupeResult = @{
    "bitLockerRecoveryPassword" = $null
    "bitLockerError" = $null;
    "removeBitLockerError" = $null;
    "suspendClusterResourceError" = $null;
    "resumeResourceFailed" = $null;
    "csvNullSharedVolumeInfo" = $false;
    "moveCSVError" = $null;
  }

  $externalKeyFolder = "c:\windows\cluster"

  try {

    $csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop

    if ($csv.SharedVolumeInfo -ne $null) {
      $volumePath = $csv.SharedVolumeInfo[0].FriendlyVolumeName
      # move the csv to THIS node so enable-bitlocker stuff will work
      $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null
    }
    else {
      $bitLockerAndDedupeResult.csvNullSharedVolumeInfo = $true
    }
  }
  catch {
    $bitLockerAndDedupeResult.moveCSVError = $_
  }

  # only proceed if we moved the csv

  if ($bitLockerAndDedupeResult.moveCSVError -eq $null -and  ($bitLockerAndDedupeResult.csvNullSharedVolumeInfo -eq $false)) {


      try {

          Suspend-ClusterResource -Name $csv.name -force | Out-Null
      }
      catch {
        $bitLockerAndDedupeResult.suspendClusterResourceError = $_
      }

      # only proceed if we succeeded in suspending the cluster resource
      if ($bitLockerAndDedupeResult.suspendClusterResourceError -eq $null) {


        # if any bitlocker error, clean up bitlocker
        if ($EnableBitLocker) {
            $bitLockerEnabled = $null;
            try {
              # use numerical recoverypassword
              Enable-BitLocker $volumePath -EncryptionMethod $encryptionMethod -RecoveryPasswordProtector -Confirm:$false -ErrorAction Stop | Out-Null
              $bitLockerEnabled = $true
            } catch {
              $bitLockerAndDedupeResult.bitLockerError = $_
              #  no need to clean up bitlocker - it wasnt enabled
              $bitLockerEnabled = $false
            }

            # proceed if we succeeded in enabling bitlocker
            if ($bitLockerEnabled -eq $true) {

              try {
                $bitLockerAndDedupeResult.bitLockerRecoveryPassword = Get-BitLockerRecoveryPassword -volumePath $volumePath -ErrorAction Stop


                if ($clusterADAccountCanUnlock)
                {
                  # for backup to AD, we already have set the reg keys on all nodes before calling this script
                  # this $truncatedName will be truncated to no more than 15 chars


                  $clusterResourceId = (Get-ItemProperty -Path HKLM:cluster).ClusterNameResource

                  $truncatedName = Get-ClusterResource $clusterResourceId | Get-ClusterParameter | Where-Object { $_.name -eq "name" }

                  $CNO = -Join($truncatedName.value ,"$")
                  Add-BitLockerKeyProtector $volumePath -AdAccountOrGroupProtector -AdAccountOrGroup $CNO -Confirm:$false -ErrorAction Stop | Out-Null
                }


                if ($backupPasswordToAD)
                {

                  $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

                  foreach($key in $keys){
                    if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
                      Backup-BitLockerKeyProtector -MountPoint $volumePath -KeyProtectorId $key.keyProtectorId -Confirm:$false -ErrorAction Stop | Out-Null
                      break;
                    }
                  }

                }

                if ($externalKey)
                {
                  Add-BitLockerKeyProtector $volumePath -RecoveryKeyProtector -RecoveryKeyPath  $externalKeyFolder -Confirm:$false | Out-Null
                }
              }
              catch {
                $bitLockerAndDedupeResult.bitLockerError = $_
                $bitLockerAndDedupeResult.bitLockerRecoveryPassword = $null
              }
            }

        }
        else {
          try {
            Disable-BitLocker $volumePath -ErrorAction Stop | Out-Null
          }
          catch {
              $bitLockerAndDedupeResult.removeBitLockerError = $_
          }
        }
      }

      if ($bitLockerAndDedupeResult.bitLockerError -ne $null -and $bitLockerEnabled -eq $true) {
          # if AD  key protector errs, we cannot resume the cluster resource because this is currently our only optoin to unlock the volume
          # but in all cases we will just remove bitlocker
          # we to disable bitlocker first
          try {
              Disable-BitLocker $volumePath -ErrorAction Stop | Out-Null
          }
          catch {
              $bitLockerAndDedupeResult.removeBitLockerError = $_
          }
      }

      if ($bitLockerAndDedupeResult.suspendClusterResourceError -eq $null) {
        if ($externalKey) {
          $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector
          $externalKeyTypeEnumValue = 2;
          $keyProtectorExternal = $keys | Where-Object {$_.KeyProtectorType.value__ -eq $externalKeyTypeEnumValue}
          $externalKeyFileName = $keyProtectorExternal.KeyFileName
          $externalKeyFullPath =  [System.String] (Join-Path $externalKeyFolder $externalKeyFileName)

          $resumeResult = $csv | Resume-ClusterPhysicalDiskResource -RecoveryKeyPath $externalKeyFullPath

          if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterResourceState enum value
            $bitLockerAndDedupeResult.resumeResourceFailed = $true
          }
        }
        else {
          # Resume-clusterResource does not seem to throw an err we can catch, but we will identify if it failed and use that instead
          $resumeResult = Resume-ClusterResource -name $csv.name -ErrorAction SilentlyContinue

          if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterResourceState enum value
            $bitLockerAndDedupeResult.resumeResourceFailed = $true
          }

        }

      }

  }

  return $bitLockerAndDedupeResult
}



#### start of script
$allResults = @{
  "bitLockerAndDedupeResult"  = $null;
}

if ($encryptionStatusChanged) {
  $SetVolumeArgs = @{
    "volumeId" = $volumeId;
    "node" = $node;
  }

  if ($EnableBitlocker) {
    $SetVolumeArgs["EnableBitLocker"] = $EnableBitLocker
    $SetVolumeArgs["backupPasswordToAD"] = $backupPasswordToAD
    $SetVolumeArgs["clusterADAccountCanUnlock"] = $clusterADAccountCanUnlock
    $SetVolumeArgs["externalKey"] = $externalKey
    $SetVolumeArgs["encryptionMethod"] = $encryptionMethod
  }
  else { #disable bitlocker
    $SetVolumeArgs["EnableBitLocker"] = $false
  }

  #even though no dedup here, we need to have the property name match s2d scenarios
  $allResults.bitLockerAndDedupeResult = Set-BitLocker @SetVolumeArgs
}

Write-Output $allResults




}
## [END] Set-WACSDDCNonS2DVolume ##
function Set-WACSDDCResyncBandwidth {
<#

.SYNOPSIS
Sets resync bandwidth

.DESCRIPTION
Sets resync bandwidth

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [Int32]
  $bandwidth
)
Import-Module Storage
Get-StorageSubSystem "Cluster*" | Set-StorageSubSystem -VirtualDiskRepairQueueDepth $bandwidth

}
## [END] Set-WACSDDCResyncBandwidth ##
function Set-WACSDDCStoragePoolCapacityThresholdAlert {
<#

.SYNOPSIS
Sets storage pool thinProvisioningAlertThresholds
.DESCRIPTION
Sets storage pool thinProvisioningAlertThresholds
.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $friendlyName,
  [Parameter(Mandatory = $true)]
  [int]
  $newCapacityAlertThreshold
)

Import-Module Storage
Get-StoragePool -FriendlyName $friendlyName | Set-StoragePool -ThinProvisioningAlertThresholds $newCapacityAlertThreshold

}
## [END] Set-WACSDDCStoragePoolCapacityThresholdAlert ##
function Set-WACSDDCStoragePoolName {
<#

.SYNOPSIS
Sets storage pool name

.DESCRIPTION
Sets storage pool name

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $friendlyName,
  [Parameter(Mandatory = $true)]
  [string]
  $newFriendlyName
)

Import-Module Storage
Get-StoragePool -FriendlyName $friendlyName | Set-StoragePool -NewFriendlyName $newFriendlyName

}
## [END] Set-WACSDDCStoragePoolName ##
function Set-WACSDDCStoragePoolProvisioningTypeDefault {
<#

.SYNOPSIS
Sets storage pool default provisioning type

.DESCRIPTION
Sets storage pool default provisioning type

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $friendlyName,
  [Parameter(Mandatory = $true)]
  [string]
  $newProvisioningTypeDefault
)

Import-Module Storage
Get-StoragePool -FriendlyName $friendlyName | Set-StoragePool -ProvisioningTypeDefault $newProvisioningTypeDefault

}
## [END] Set-WACSDDCStoragePoolProvisioningTypeDefault ##
function Set-WACSDDCVMAutomaticActivation {
<#
.SYNOPSIS
Sets VM automatic activation

.DESCRIPTION
Sets VM automatic activation

.ROLE
Administrators
#>

param (
  [Parameter(Mandatory = $true)]
  [string] $productKey
)

$result = $null
$importErr = $null
try {
  Import-Module ServerAVMAManager -ErrorAction Stop
} catch {
  $importErr = $true
}

if ($importErr -ne $true) {
  $result = Set-VMAutomaticActivation -ProductKey $productKey
}

return @{
  "result" = $result;
  "error" = $importErr;
}


}
## [END] Set-WACSDDCVMAutomaticActivation ##
function Set-WACSDDCVirtualMachineLoadBalancing {
<#

.SYNOPSIS
Sets auto balancing level

.DESCRIPTION
Sets VM load balancing level

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $autoBalancerMode,
  [Parameter(Mandatory = $false)]
  [uint32]
  $autoBalancerLevel
)

Import-Module FailoverClusters
$cluster = FailoverClusters\Get-Cluster;

$cluster.AutoBalancerMode = $autoBalancerMode

if ($cluster.AutoBalancerMode -gt 0 -and $autoBalancerLevel -ne $null)
{
    $cluster.AutoBalancerLevel = $autoBalancerLevel
}
else
{
    # default to high setting for the next time mode is set to other-than-never
    $cluster.AutoBalancerLevel = 3
}

}
## [END] Set-WACSDDCVirtualMachineLoadBalancing ##
function Set-WACSDDCVolume {
<#

.SYNOPSIS
Resize volume, change provisioning type

.DESCRIPTION
Resize volume, change provisioning type

.ROLE
Administrators

#>

param (

    [Parameter(Mandatory = $true)]
    [string] $volumeid,

    [Parameter(Mandatory = $true)]
    [bool] $isTiered,

    [Parameter(Mandatory = $true)]
    [bool] $setProvisioningTypeToThin,

    [Parameter(Mandatory = $true)]
    [bool] $isSingleNodeCluster,

    [UInt64] $newSize,

    [bool]
    $enableBitlocker,

    [bool]
    $backupPasswordToAD,

    [bool]
    [Parameter(Mandatory = $true)]
    $externalKey,

    [bool]
    [Parameter(Mandatory = $true)]
    $clusterADAccountCanUnlock,

    [bool]
    $encryptionStatusChanged,

    [int]
    $dedupeMode,

    [Parameter(Mandatory = $true)]
    [bool]
    $deduplicationStatusChanged,

    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $node,

    [psobject]
    $refsDedupData,

    [string]
    [Parameter(Mandatory = $true)]
    $encryptionMethod
)

Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
Import-Module Storage
Import-Module FailoverClusters
Import-Module BitLocker -ErrorAction SilentlyContinue # this one needs to continue since it is optional and won't be used if not installed
Import-Module Deduplication -ErrorAction SilentlyContinue # this one needs to continue since it is optional and won't be used if not installed


function Handle-ReFSDedup {

  param (

      [Parameter(Mandatory = $true)]
      [bool]
      $disableDedup,

      [Parameter(Mandatory = $true)]
      [bool]
      $enableDedup,

      [Parameter(Mandatory = $true)]
      [bool]
      $resumeSchedule,


      [Parameter(Mandatory = $true)]
      [bool]
      $suspendSchedule,


      [Parameter(Mandatory = $true)]
      [bool]
      $setSchedule,

      [Parameter(Mandatory = $true)]
      [string]
      $path,

      [Parameter(Mandatory = $true)]
      [DateTime]
      $start,

      [Parameter(Mandatory = $true)]
      [int]
      $hours,

      [Parameter(Mandatory = $true)]
      [array] # array of enum values for days
      $days
  )

  Import-Module Microsoft.ReFsDedup.Commands
  Import-Module Microsoft.PowerShell.Utility

  # must come before set schedule
  if ($enableDedup) {
    $dedupOnly= 1 # UX will only allow for dedupe, but user can specify compression or both comrpression and dedupe on cmd line
    Enable-ReFSDedup -Volume $path -Type $dedupOnly | Out-Null
  }

  # must come before set schedule
  if ($resumeSchedule) {
    Resume-ReFSDedupSchedule -Volume $path | Out-Null
  }

  if ($setSchedule) {
    $duration = New-Timespan -Hours $hours
    Set-ReFSDedupSchedule -Volume $path -Start $start -Days $days -Duration $duration | Out-Null
  }

  if ($disableDedup) {
    Disable-ReFSDedup -Volume $path | Out-Null
  }

  if ($suspendSchedule) {
    Suspend-ReFSDedupSchedule -Volume $path | Out-Null
  }

}

function Get-BitLockerRecoveryPassword {
  param (
    [string]
    [Parameter(
        Mandatory        = $true)]
    [ValidateNotNullOrEmpty()]
    $volumePath
  )

  $recoveryPassword = $null
  $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

  foreach($key in $keys){
    if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
      $recoveryPassword = $key.RecoveryPassword
      break;
    }
  }

  return $recoveryPassword

}
function Get-MatchingCSV {
  param (
    [string] $volumeid
  )


  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk
  foreach ($csvObj in Get-ClusterSharedVolume) {
    if ( ($csvObj | Get-ClusterParameter | Where-Object { $_.name -eq "diskidguid"}).value -eq $voldisk.guid ) {

      return $csvobj
    }
  }
}

function Set-BitlockerAndDeduplication {
  param (
    #  required params for all


    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $volumeId,

    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $node,

    #  params for BitLocker
    [bool]
    [Parameter(Mandatory = $false)]
    $encryptionStatusChanged,

    [bool]
    [Parameter(Mandatory = $false)]
    $EnableBitLocker,

    [bool]
    [Parameter(Mandatory = $false)]
    $backupPasswordToAD,

    [bool]
    [Parameter(Mandatory = $false)]
    $externalKey,

    [bool]
    [Parameter(Mandatory = $false)]
    $clusterADAccountCanUnlock,
    [int]
    [Parameter(Mandatory = $false)]
    $DeduplicationMode,

    [bool]
    [Parameter(Mandatory = $false)]
    $deduplicationStatusChanged,

    [string]
    [Parameter(Mandatory = $false)]
    $encryptionMethod
  )



  $bitLockerAndDedupeResult = @{
    "bitLockerRecoveryPassword" = $null
    "bitLockerError" = $null;
    "deduplicationError" = $null;
    "removeBitLockerError" = $null;
    "suspendClusterResourceError" = $null;
    "resumeResourceFailed" = $null;
    "csvNullSharedVolumeInfo" = $false;
    "moveCSVError" = $null;
  }

  $externalKeyFolder = "c:\windows\cluster"


  try {
    $csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop

    if ($csv.SharedVolumeInfo -ne $null) {
      $volumePath = $csv.SharedVolumeInfo[0].FriendlyVolumeName
      # move the csv to THIS node so enable-bitlocker stuff will work
      $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null
    }
    else {
      $bitLockerAndDedupeResult.csvNullSharedVolumeInfo = $true
    }
  }
  catch {
    $bitLockerAndDedupeResult.moveCSVError = $_
  }

# only proceed if we moved the csv
  if ($bitLockerAndDedupeResult.moveCSVError -eq $null -and  ($bitLockerAndDedupeResult.csvNullSharedVolumeInfo -eq $false)) {

    # fs-datadeduplication
    if ($deduplicationStatusChanged) {

      if ($DeduplicationMode -eq 0) {
        try {
            Disable-DedupVolume -Volume $volumePath -ErrorAction Stop | Out-Null
        }
        catch {
            $bitLockerAndDedupeResult.deduplicationError = $_
        }
      }

      if ($DeduplicationMode -gt 0) {
        try {
            Enable-DedupVolume -Volume $volumePath -UsageType $DeduplicationMode -ErrorAction Stop | Out-Null
        }
        catch {
            $bitLockerAndDedupeResult.deduplicationError = $_
        }
      }
    }

    if ($encryptionStatusChanged) {
      $vdClusterResource = $null
      try {
        $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
        $voldisk = $volumeobj | Get-Partition | Get-Disk

        $virtualDisk = $volDisk | Get-VirtualDisk

        $vdClusterResource  = $virtualdisk | Get-ClusterResource -ErrorAction Stop


        # need to put the virtual disk into maintenance before we can enable BitLocker
        $vdClusterResource | Suspend-ClusterResource -Force -ErrorAction Stop | Out-Null
      }
      catch {
        $bitLockerAndDedupeResult.suspendClusterResourceError = $_
      }

      # only proceed if we succeeded in suspending the cluster resource
      if ($bitLockerAndDedupeResult.suspendClusterResourceError -eq $null) {


        # if any bitlocker error, clean up bitlocker
        if ($EnableBitLocker) {
            $bitLockerEnabled = $null;
            try {
              # use numerical recoverypassword
              Enable-BitLocker $volumePath -EncryptionMethod $encryptionMethod -RecoveryPasswordProtector -Confirm:$false -ErrorAction Stop | Out-Null
              $bitLockerEnabled = $true
            } catch {
              $bitLockerAndDedupeResult.bitLockerError = $_
              #  no need to clean up bitlocker - it wasnt enabled
              $bitLockerEnabled = $false
            }

            # proceed if we succeeded in enabling bitlocker
            if ($bitLockerEnabled -eq $true) {

              try {
                $bitLockerAndDedupeResult.bitLockerRecoveryPassword = Get-BitLockerRecoveryPassword -volumePath $volumePath -ErrorAction Stop

                if ($clusterADAccountCanUnlock)
                {
                  # for backup to AD, we already have set the reg keys on all nodes before calling this script
                  # this $truncatedName will be truncated to no more than 15 chars

                  $clusterResourceId = (Get-ItemProperty -Path HKLM:cluster).ClusterNameResource

                  $truncatedName = Get-ClusterResource $clusterResourceId | Get-ClusterParameter | Where-Object { $_.name -eq "name" }

                  $CNO = -Join($truncatedName.value ,"$")
                  Add-BitLockerKeyProtector $volumePath -AdAccountOrGroupProtector -AdAccountOrGroup $CNO -Confirm:$false -ErrorAction Stop | Out-Null
                }

                if ($backupPasswordToAD)
                {

                  $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector

                  foreach($key in $keys){
                    if ($key.keyProtectorType.value__ -eq 3) { # 3 is RecoveryPassword
                      Backup-BitLockerKeyProtector -MountPoint $volumePath -KeyProtectorId $key.keyProtectorId -Confirm:$false -ErrorAction Stop | Out-Null
                      break;
                    }
                  }

                }

                if ($externalKey)
                {
                  Add-BitLockerKeyProtector $volumePath -RecoveryKeyProtector -RecoveryKeyPath  $externalKeyFolder -Confirm:$false | Out-Null
                }
              }
              catch {
                $bitLockerAndDedupeResult.bitLockerError = $_
                $bitLockerAndDedupeResult.bitLockerRecoveryPassword = $null
              }
            }

        }
        else {
          try {
            Disable-BitLocker $volumePath -ErrorAction Stop | Out-Null
          }
          catch {
              $bitLockerAndDedupeResult.removeBitLockerError = $_
          }
        }
      }

      if ($bitLockerAndDedupeResult.bitLockerError -ne $null -and $bitLockerEnabled -eq $true) {
          # if AD  key protector errs, we cannot resume the cluster resource because this is currently our only optoin to unlock the volume
          # but in all cases we wil just remove bitlocker
          # we to disable bitlocker first
          try {
              Disable-BitLocker $volumePath -ErrorAction Stop | Out-Null
          }
          catch {
              $bitLockerAndDedupeResult.removeBitLockerError = $_
          }
      }

      # only proceed if we succeeded in suspending the cluster resource
      if ($bitLockerAndDedupeResult.suspendClusterResourceError -eq $null) {

        if ($bitLockerAndDedupeResult.suspendClusterResourceError -eq $null) {


          if ($externalKey) {
            $keys = (Get-BitLockerVolume -MountPoint $volumePath).KeyProtector
            $externalKeyTypeEnumValue = 2;
            $keyProtectorExternal = $keys | Where-Object {$_.KeyProtectorType.value__ -eq $externalKeyTypeEnumValue}
            $externalKeyFileName = $keyProtectorExternal.KeyFileName
            $externalKeyFullPath =  [System.String] (Join-Path $externalKeyFolder $externalKeyFileName)

            $resumeResult = $csv | Resume-ClusterPhysicalDiskResource -RecoveryKeyPath $externalKeyFullPath

            if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterResourceState enum value
              $bitLockerAndDedupeResult.resumeResourceFailed = $true
            }
          }
          else {
            # Resume-clusterResource does not seem to throw an err we can catch, but we will identify if it failed and use that instead
            $resumeResult = $vdClusterResource | Resume-ClusterResource -ErrorAction SilentlyContinue
            if ($resumeResult.state -eq 4) {  # 4 is the failed ClusterRsoruceState enum value
              $bitLockerAndDedupeResult.resumeResourceFailed = $true
            }

          }

        }

      }
    }

  }



  return $bitLockerAndDedupeResult
}



Function Start-VolumeReMounting {
  param (
    [Parameter(Mandatory = $true)]
    [bool] $isSingleNodeCluster,

    [Parameter(Mandatory = $true)]
    [string] $volumeid
  )

  $csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop
  $csvName = $csv.name
  $originalNode = $csv.OwnerNode
  $originalNodeName = $originalNode.name
  $remountResult = @{
    "error" = $null;
    "csvRemounted" = $false;
  }
  if ($isSingleNodeCluster) {
    try {
      Stop-ClusterResource $csvName -ErrorAction Stop | Out-Null
      Start-ClusterResource $csvName -ErrorAction Stop  | Out-Null
      $remountResult.csvRemounted = $true
    }
    catch {
      $remountResult.error = $_
    }
  }
  else {
    Import-Module FailoverClusters -ErrorAction SilentlyContinue

    Get-Clusternode | ForEach-Object {
      if ($_.name -ne $originalNodeName -and ($_.State.value__ -eq 0 -or $_.State.value__ -eq 2) -and -not  $csvRemounted -and  ($remountResult.error -eq $null)) {
        # node to move csv to must be up or paused
        try {
          Move-ClusterSharedVolume $csvName -Node $_.name -ErrorAction Stop | Out-Null
          Move-ClusterSharedVolume $csvName -Node $originalNodeName -ErrorAction Stop | Out-Null
          $remountResult.csvRemounted = $true
        }
        catch {
          $remountResult.error = $_
        }
      }

    }

  }
  return $remountResult
}


#### start of script
$allResults = @{
  "remountResult" = $null;
  "bitLockerAndDedupeResult"  = $null;
  "refsDedupError" = $null;
}

if ($refsDedupData) {

    $csv = Get-MatchingCSV -volumeId $volumeId -ErrorAction Stop

    # move the csv to THIS node to be sure we are on the right node
    $csv | Move-ClusterSharedVolume -Node $node  -ErrorAction Stop | Out-Null


  try {
    Handle-ReFSDedup -disableDedup $refsDedupData.disableDedup -enableDedup $refsDedupData.enableDedup -resumeSchedule $refsDedupData.schedule.resumeSchedule -suspendSchedule $refsDedupData.schedule.suspendSchedule -setSchedule  $refsDedupData.schedule.setSchedule  -path $refsDedupData.path  -start $refsDedupData.schedule.start -hours $refsDedupData.schedule.hours -days $refsDedupData.schedule.days -ErrorAction Stop

  }
  catch {
    $allResults.refsDedupError = $_
  }
}

if ($setProvisioningTypeToThin -or ($newSize -ne 0)) {
  $tierObjects = $null

  $volumeobj = Get-Volume | Where-Object {$_.uniqueid -like "*$volumeId*"}
  $voldisk = $volumeobj | Get-Partition | Get-Disk

  $virtualDisk = $volDisk | Get-VirtualDisk

  $partition = $virtualDisk | Get-Disk | Get-Partition | Where-Object { $_.type -eq "Basic" }

  if ($isTiered) {
    $tierObjects =  $virtualDisk | Get-StorageTier
  }

  # change provisioning (if needed) first so that the volume is thin when we expand it - no need to map/unmap space if we are also resizing
  if ($setProvisioningTypeToThin) {
    if ($isTiered){
      foreach ($tier in $tierObjects) {
        $tier | Set-StorageTier -ProvisioningType Thin
      }
    }
    else {
      $virtualDisk | Set-VirtualDisk -ProvisioningType Thin
    }

    $allResults.remountResult = Start-VolumeReMounting -isSingleNodeCluster $isSingleNodeCluster -volumeId $volumeId

    if ($remountData.error) {
      # todo handle this
    }

    if ($remountData.csvRemounted -eq $false) {
      # todo handle this
    }

  }

  if ($newSize -ne 0) {

    if ($isTiered) {

      # first get total size
      $originalSize = 0
      foreach ($tier in $tierObjects) {
        $originalSize += $tier.size
      }

      #then resize each tier based on its percentage of the total
      foreach ($tier in $tierObjects) {

        $fraction = $tier.size / $originalSize
        $fractionalSize = $fraction * $newSize

        $tier | Resize-StorageTier -Size $fractionalSize
      }

    }
    else {
      $virtualDisk | Resize-VirtualDisk -Size $newSize | Out-Null
    }

    $partition | Resize-Partition -Size ($partition | Get-PartitionSupportedSize).SizeMax

  }
}

 # optionally set bitlocker and/or integrity streams
      # if we err here, we will need to inform the user that the volume got created but bitlocker/integrity streams failed
      # we will need to online the volume again as it may have failed there

if ($encryptionStatusChanged -or $deduplicationStatusChanged) {
  $SetVolumeArgs = @{
    "node" = $node;
    "volumeId" = $volumeid;
  }

  if ($encryptionStatusChanged) {
    $SetVolumeArgs["encryptionStatusChanged"] = $encryptionStatusChanged

  if ($EnableBitlocker) {
    $SetVolumeArgs["EnableBitLocker"] = $EnableBitLocker
    $SetVolumeArgs["backupPasswordToAD"] = $backupPasswordToAD
    $SetVolumeArgs["clusterADAccountCanUnlock"] = $clusterADAccountCanUnlock
    $SetVolumeArgs["externalKey"] = $externalKey
    $SetVolumeArgs["encryptionMethod"] = $encryptionMethod
  }
  }
  else { #disable bitlocker
    $SetVolumeArgs["EnableBitLocker"] = $false
  }

  if ($deduplicationStatusChanged)
  {
    $SetVolumeArgs["deduplicationStatusChanged"] = $deduplicationStatusChanged
    $SetVolumeArgs["DeduplicationMode"] = $dedupeMode
  }
  $allResults.bitLockerAndDedupeResult = Set-BitlockerAndDeduplication @SetVolumeArgs
}


Write-Output $allResults




}
## [END] Set-WACSDDCVolume ##
function Start-WACSDDCSDDCResource {
<#

.SYNOPSIS
Starts SDDC Managmenet resource

.DESCRIPTION
Starts SDDC Managmenet resource

.ROLE
Administrators

#>
Import-Module FailoverClusters

$resourceTypeName = "SDDC Management"
$sddcResource = Get-ClusterResource | Where-Object { $_.ResourceType -eq $resourceTypeName}

if (($sddcResource | Microsoft.PowerShell.Utility\Measure-Object ).count -eq 1)
{
    $startedResource = Start-ClusterResource $sddcResource -ErrorAction SilentlyContinue
    # give the same enum that the cim call was giving us before instead of a localized string - instead of the localized string that Start-ClusterResource gives us for state
    return @{ "state" = $startedResource.State.value__ }
}
else {
    throw "No resource found or more than one resource found with type name ${$resourceTypeName}"
}

}
## [END] Start-WACSDDCSDDCResource ##
function Start-WACSDDCStoragePoolClusterResource {
<#

.SYNOPSIS
Starts a storage pool  cluster resource by resource id and returns data about the pool


.DESCRIPTION
Starts a storage pool cluster resource by resource id and returns data about the pool

.ROLE
Administrators

#>

param (
		[Parameter(Mandatory = $true)]
		[String]
    $resourceId
)

Import-Module FailoverClusters

$result = Get-ClusterResource  | Where-Object { $_.id -eq $resourceId } | Start-ClusterResource -Wait 1000

$pool = Get-StoragePool | Where-Object { $_.UniqueId -match $resourceId }

Write-Output @{
  "clusterResourceState" = $result.State.value__;
  "operationalStatus" = $pool.psBase.CimInstanceProperties["OperationalStatus"].Value;
  "healthStatus" = $pool.psBase.CimInstanceProperties["HealthStatus"].Value;
}

}
## [END] Start-WACSDDCStoragePoolClusterResource ##
function Stop-WACSDDCComputer {
<#

.SYNOPSIS
Stops computer

.DESCRIPTION
Stops computer

.ROLE
Administrators

#>
Import-Module Microsoft.PowerShell.Management
Stop-Computer

}
## [END] Stop-WACSDDCComputer ##
function Suspend-WACSDDCClusternode {
<#

.SYNOPSIS
Suspends clusternode

.DESCRIPTION
Suspends clusternode

.ROLE
Administrators

#>
Import-Module FailoverClusters
Suspend-ClusterNode -Drain

}
## [END] Suspend-WACSDDCClusternode ##
function Sync-WACSDDCAzureStackHCI {
<#

.SYNOPSIS
Syncs registered Az Stack HCI cluster with Azure

.DESCRIPTION
Syncs registered Az Stack HCI cluster with Azure

.ROLE
Administrators

#>

Import-Module AzureStackHCI

Sync-AzureStackHCI

}
## [END] Sync-WACSDDCAzureStackHCI ##
function Test-WACSDDCConnection {
<#

.SYNOPSIS
Tests connection

.DESCRIPTION
Tests connection

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
## [END] Test-WACSDDCConnection ##
function Unregister-WACSDDCAzureStackHCI {
<#

.SYNOPSIS
Unregisters Azure Stack HCI cluster from Azure

.DESCRIPTION
Unregisters Azure Stack HCI cluster from Azure

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $armAccessToken,
    [Parameter(Mandatory = $true)]
    [String]
    $accountId,
    [Parameter(Mandatory = $true)]
    [String]
    $environmentName
)
try {
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module
  Install-Module Az.Resources -Force | Out-Null
  Import-Module Az.Resources -ErrorAction Stop

  $module = Get-Module -Name Az.StackHCI -ListAvailable | Sort-Object -Property Version -Descending | Microsoft.PowerShell.Utility\Select-Object -First 1

  if ($module -and (($module.version.major -lt 2) -or ($module.version.major -eq 2 -and $module.version.minor -lt 3)))
  {
    # insufficient verison - get a new one from PS Gallery
    Update-Module Az.StackHCI -Force | Out-Null
  }
  else
  {
    Import-Module $module -ErrorAction Stop
  }
}
catch {
  Install-Module Az.StackHCI -Force -AllowClobber | Out-Null
}

try
{
    $DebugPreference = 'Continue'

    Unregister-AzStackHCI -ArmAccessToken $armAccessToken -AccountId $accountId -EnvironmentName $environmentName -isWAC:$true -Confirm:$false -Verbose -Debug

    $DebugPreference = 'SilentlyContinue'
}

catch {
    $DebugPreference = 'SilentlyContinue'
    Throw
}


}
## [END] Unregister-WACSDDCAzureStackHCI ##
function Unregister-WACSDDCSDDCDiagnosticArchiveJob {
<#

.SYNOPSIS
Unregisteres SDDC diagnostic archive job

.DESCRIPTION
Unregisteres SDDC diagnostic archive job

.ROLE
Administrators

#>
try {
  Import-Module PrivateCloud.DiagnosticInfo -ErrorAction Stop
}
catch {
  Import-Module PowerShellGet
  Import-Module PackageManagement
  Install-PackageProvider NuGet -Force | Out-Null # required to  install the module - run on all nodes
  Install-Module PrivateCloud.DiagnosticInfo -Force # this will get the latest verison
}

Unregister-SDDCDiagnosticArchiveJob

}
## [END] Unregister-WACSDDCSDDCDiagnosticArchiveJob ##
function Update-WACSDDCStoragePool {
<#

.SYNOPSIS
Updates storage pool to the latest version

.DESCRIPTION
Updates storage pool to the latest version

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [string]
  $friendlyName
)
Import-Module Storage
Update-StoragePool -FriendlyName $friendlyName  -Confirm:$false

}
## [END] Update-WACSDDCStoragePool ##
function Add-WACSDDCCauClusterRole {
<#

.SYNOPSIS
Adds the Cluster Aware Updating role to the cluster.

.DESCRIPTION
Adds the Cluster Aware Updating role to the cluster.

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

return Add-CauClusterRole -ClusterName $clusterName -Force -EnableFirewallRules

}
## [END] Add-WACSDDCCauClusterRole ##
function Add-WACSDDCFolderShare {
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
## [END] Add-WACSDDCFolderShare ##
function Add-WACSDDCFolderShareNameUser {
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
## [END] Add-WACSDDCFolderShareNameUser ##
function Add-WACSDDCFolderShareUser {
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
## [END] Add-WACSDDCFolderShareUser ##
function Add-WACSDDCSmeClusterNodes {
<#

.SYNOPSIS
Adds servers to a cluster on this node.

.DESCRIPTION
Adds servers to a cluster on this node.

.ROLE
Administrators

.PARAMETER serverNames
The servers to add to the cluster of which this server is a member.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$serverNames
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Add-SmeClusterNodes" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorRecords
May, or may not, be an array of errors...

#>

function writeErrors($errorRecords) {
    foreach ($errorRecord in @($errorRecords)) {
        $message = "[$ScriptName]: $errorRecord"

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $message  -ErrorAction SilentlyContinue

        Microsoft.PowerShell.Utility\Write-Error $errorRecord
    }
}

<#

.SYNOPSIS
Helper function to write the warnings to warning stream.

.DESCRIPTION
Helper function to write the warnings to warning stream.


.PARAMETER warningRecords
May, or may not, be an array of warnings...

#>

function writeWarnings($warningRecords) {
    foreach ($warningRecord in @($warningRecords)) {
        Microsoft.PowerShell.Utility\Write-Warning $warningRecord
    }
}

<#

.SYNOPSIS
Validate the cluster and the candidate servers.

.DESCRIPTION
Test the cluster with the candindate nodes (servers).

.PARAMETER serverNames
The servers to validae with the cluster.

#>

function validate([string []] $serverNames) {
    Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.AddNodesProgressValidationStart -PercentComplete 0

    Test-Cluster -Node $serverNames -ErrorAction SilentlyContinue -ErrorVariable +errorRecords -WarningVariable +warningRecords -Force

    if ($errorRecords) {
        # Falure means this script is 100% complete.
        Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.AddNodesProgressValidationEnd -PercentComplete 100 -Completed $true

        writeErrors $errorRecords

        return $false
    }

    if ($warningRecords) {
        writeWarnings $warningRecords
    }

    # Success means this script is 50% complete.
    Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.AddNodesProgressValidationEnd -PercentComplete 50 -Completed $false

    return $true
}

<#

.SYNOPSIS
Add the servers to the cluster on this node.

.DESCRIPTION
Add the passed in servers to the cluster on this node.

.PARAMETER serverNames
The servers to add to the cluster.

#>

function addServers([string[]] $serverNames) {
    # Starting second half of the script, progress is now 51% complete

    $clusterName = (Get-Cluster).Name

    Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.AddNodesProgressAdditionStartFormat -f $clusterName) -PercentComplete 51 -Completed $false

    $result = Add-ClusterNode -Name $serverNames -ErrorAction SilentlyContinue -ErrorVariable +errorRecords -WarningVariable +warningRecords

    if ($errorRecords) {
        # Falure means this script is 100% complete.
        Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.AddNodesProgressAdditionEndFormat -f $clusterName) -PercentComplete 100 -Completed $false

        writeErrors $errorRecords

        return $null;
    }

    if ($warningRecords) {
        writeWarnings $warningRecords
    }

    # Now the script is complete.
    Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.AddNodesProgressAdditionEndFormat -f $clusterName) -PercentComplete 100 -Completed $true

    return $result -ne $null
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER serverNames
The servers to add to the cluster.

#>

function main([string[]] $serverNames) {
    if (validate $serverNames) {
        return addServers $serverNames
    }

    return $null
}

###############################################################################
# Script execution starts here...
###############################################################################

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main $serverNames
}

Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

return $null

}
## [END] Add-WACSDDCSmeClusterNodes ##
function Compress-WACSDDCArchiveFileSystemEntity {
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
## [END] Compress-WACSDDCArchiveFileSystemEntity ##
function Disable-WACSDDCCauClusterRole {
<#

.SYNOPSIS
Disable the Cluster Aware Updating role to the cluster.

.DESCRIPTION
Disable the Cluster Aware Updating role to the cluster.

.ROLE
Administrators

#>

Param
(
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

Disable-CauClusterRole -ClusterName $clusterName -Force

}
## [END] Disable-WACSDDCCauClusterRole ##
function Disable-WACSDDCKdcProxy {
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
## [END] Disable-WACSDDCKdcProxy ##
function Disable-WACSDDCSmbOverQuic {
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
## [END] Disable-WACSDDCSmbOverQuic ##
function Disconnect-WACSDDCHybridManagement {
<#

.SYNOPSIS
Disconnects a machine from azure hybrid agent.

.DESCRIPTION
Disconnects a machine from azure hybrid agent and uninstall the hybrid instance service.
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER authToken
    The authentication token for connection

#>

param (
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
    Set-Variable -Name HybridAgentConfigFile -Option ReadOnly -Value "$env:ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" -Scope Script
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
    Remove-Variable -Name HybridAgentConfigFile -Scope Script -Force
    Remove-Variable -Name HybridAgentPackage -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Disconnects a machine from azure hybrid agent.

#>

function main(
    [string]$authToken
) {
    $err = $null
    $args = @{}

   # Disconnect Azure hybrid agent
   if (Test-Path $HybridAgentExecutable) {
        & $HybridAgentExecutable disconnect --access-token $authToken
   }
   else {
        throw "Could not find the Azure hybrid agent executable file."
   }


   # Uninstall Azure hybrid instance metadata service
   Uninstall-Package -Name $HybridAgentPackage -ErrorAction SilentlyContinue -ErrorVariable +err

   if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not uninstall the package. Error: $err"  -ErrorAction SilentlyContinue

        throw $err
   }

   # Remove Azure hybrid agent config file if it exists
   if (Test-Path $HybridAgentConfigFile) {
        Remove-Item -Path $HybridAgentConfigFile -ErrorAction SilentlyContinue -ErrorVariable +err -Force

        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:Could not remove the config file. Error: $err"  -ErrorAction SilentlyContinue

            throw $err
        }
   }
}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $authToken
} finally {
    cleanupScriptEnv
}

}
## [END] Disconnect-WACSDDCHybridManagement ##
function Edit-WACSDDCFolderShareInheritanceFlag {
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
## [END] Edit-WACSDDCFolderShareInheritanceFlag ##
function Edit-WACSDDCFolderShareUser {
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
## [END] Edit-WACSDDCFolderShareUser ##
function Edit-WACSDDCSmbFileShare {
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
## [END] Edit-WACSDDCSmbFileShare ##
function Edit-WACSDDCSmbServerCertificateMapping {
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
## [END] Edit-WACSDDCSmbServerCertificateMapping ##
function Enable-WACSDDCCauClusterRole {
<#

.SYNOPSIS
Enable the Cluster Aware Updating role to the cluster.

.DESCRIPTION
Enable the Cluster Aware Updating role to the cluster.

.ROLE
Administrators

#>

Param
(
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

Enable-CauClusterRole -ClusterName $clusterName -Force

}
## [END] Enable-WACSDDCCauClusterRole ##
function Enable-WACSDDCSmbOverQuic {
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
## [END] Enable-WACSDDCSmbOverQuic ##
function Expand-WACSDDCArchiveFileSystemEntity {
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
## [END] Expand-WACSDDCArchiveFileSystemEntity ##
function Find-WACSDDCClusterUpdateModule {
<#

.SYNOPSIS
Finds ClusterAwareUpdating module is present or not.

.DESCRIPTION
Finds ClusterAwareUpdating module is present or not.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

if (!(Get-Module -ListAvailable -Name ClusterAwareUpdating)) {
    return @{ ResultState = "Failed"; ErrorCode = "ModuleNotFound"; }
}


return @{ ResultState = "Success"; ErrorCode = ""; }

}
## [END] Find-WACSDDCClusterUpdateModule ##
function Find-WACSDDCCommandProperty {
<#

.SYNOPSIS
Finds if a property exists for a specified PS command.

.DESCRIPTION
Finds if a property exists for a specified PS command.

.ROLE
Readers
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $commandName,
    [Parameter(Mandatory = $true)]
    [String] $propertyName
)

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Core -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue

$commandObj = Get-Command $commandName
$propertyExists = $commandObj.ParameterSets[0] | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty parameters | Where-Object -Property Name -eq $propertyName

# Will return true when the property exists
return -not ($null -eq $propertyExists)

}
## [END] Find-WACSDDCCommandProperty ##
function Find-WACSDDCUrpStatus {
<#

.SYNOPSIS
Finds URP service is present or not and additional URP related info.

.DESCRIPTION
Finds URP service is present or not and additional URP related info.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Find-UrpStatus.ps1"

$urpService = $null
$urpService = Get-Service -Name "URP Windows Service" -ErrorAction SilentlyContinue # Do not catch error here to avoid the one thrown if service not found
$os = $null
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue -ErrorVariable +err

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error finding URP status.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

$urpStatus = @{}
$urpStatus.Add("UrpServicePresent", ($urpService -ne $null))
if ($urpService -ne $null -and $urpService.Status -ne $null) {
    $urpStatus.Add("UrpServiceStatus", $urpService.Status)
}
else {
    $urpStatus.Add("UrpServiceStatus", "NotFound")
}

if ($os -ne $null -and $os.OperatingSystemSKU -ne $null) {
    $urpStatus.Add("OperatingSystemSKU", $os.OperatingSystemSKU)
}
else {
    $urpStatus.Add("OperatingSystemSKU", -1)
}
if ($os -ne $null -and $os.BuildNumber -ne $null) {
    $urpStatus.Add("BuildNumber", $os.BuildNumber)
}
else {
    $urpStatus.Add("BuildNumber", -1)
}

$urpStatus

}
## [END] Find-WACSDDCUrpStatus ##
function Get-WACSDDCAntimalwareSoftwareStatus {
<#

.SYNOPSIS
Gets the status of antimalware software on the computer.

.DESCRIPTION
Gets the status of antimalware software on the computer.

.ROLE
Readers

#>

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
{
    return (Get-MpComputerStatus -ErrorAction SilentlyContinue);
}
else{
    return $Null;
}


}
## [END] Get-WACSDDCAntimalwareSoftwareStatus ##
function Get-WACSDDCAvailableClusterUpdates {

<#

.SYNOPSIS
Scan cluster nodes to check if any updates are available.

.DESCRIPTION
Scan cluster nodes to check if any updates are available.

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

# filter out if node is null, this happens when there is no windows update entry.
Invoke-CauScan -ClusterName $clusterName -CauPluginName Microsoft.WindowsUpdatePlugin `
    | Microsoft.PowerShell.Utility\Select-Object @{N = 'node'; E = { $_.NodeName } }, @{N = 'title'; E = { $_.UpdateTitle } } `
    | Where-Object { $_.node -ne $null }


}
## [END] Get-WACSDDCAvailableClusterUpdates ##
function Get-WACSDDCAvailableFeatureUpdates {
<#

.SYNOPSIS
Scan cluster nodes to check if any feature updates are available.

.DESCRIPTION
Scan cluster nodes to check if any feature updates are available.

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)


Set-StrictMode -Version 5.0

Import-Module ClusterAwareUpdating -ErrorAction SilentlyContinue

$results = @();

$pluginAvailable = Get-CauPlugin | Where-Object { $_.Name -eq 'Microsoft.RollingUpgradePlugin' }
if ($null -ne $pluginAvailable) {
    $updates = Invoke-CauScan -ClusterName $clusterName -CauPluginName Microsoft.RollingUpgradePlugin -CauPluginArguments @{'WuConnected' = 'true' }
    $updates | ForEach-Object {
        if ($_ -notlike $null) {
            $installProperties = $_.UpgradeInstallProperties
            if ($null -ne $installProperties) {
                $updatesInfo = $installProperties.WuUpdatesInfo
                if ($null -ne $updatesInfo.NodeName) {
                    $results += @{'Node'=$updatesInfo.NodeName; 'Title'=$updatesInfo.UpdateTitle;}
                }
            }
        }
    }
}

$results

}
## [END] Get-WACSDDCAvailableFeatureUpdates ##
function Get-WACSDDCAzureProtectionStatus {
<#

.SYNOPSIS
Gets the status of Azure Backup on the target.

.DESCRIPTION
Checks whether azure backup is installed on target node, and is the machine protected by azure backup.
Returns the state of azure backup.

.ROLE
Readers

#>

Function Test-RegistryValue($path, $value) {
    if (Test-Path $path) {
        $Key = Get-Item -LiteralPath $path
        if ($Key.GetValue($value, $null) -ne $null) {
            $true
        }
        else {
            $false
        }
    }
    else {
        $false
    }
}

Set-StrictMode -Version 5.0
$path = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
$value = 'PSModulePath'
if ((Test-RegistryValue $path $value) -eq $false) {
    @{ Registered = $false }
} else {
    $env:PSModulePath = (Get-ItemProperty -Path $path -Name PSModulePath).PSModulePath
    $AzureBackupModuleName = 'MSOnlineBackup'
    $DpmModuleName = 'DataProtectionManager'
    $DpmModule = Get-Module -ListAvailable -Name $DpmModuleName
    $AzureBackupModule = Get-Module -ListAvailable -Name $AzureBackupModuleName
    $IsAdmin = $false;

    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (!$IsAdmin) {
        @{ Registered = $false }
    }
    elseif ($DpmModule) {
        @{ Registered = $false }
    } 
    elseif ($AzureBackupModule) {
        try {
            Import-Module $AzureBackupModuleName
            $registrationstatus = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetMachineRegistrationStatus(0)
            if ($registrationstatus -eq $true) {
                @{ Registered = $true }
            }
            else {
                @{ Registered = $false }
            }
        }
        catch {
            @{ Registered = $false }
        }
    }
    else {
        @{ Registered = $false }
    }
}
}
## [END] Get-WACSDDCAzureProtectionStatus ##
function Get-WACSDDCAzureVMStatus {
<#

.SYNOPSIS
Checks whether a VM is from azure or not
.DESCRIPTION
Checks whether a VM is from azure or not
.ROLE
Readers

#>

$ErrorActionPreference="SilentlyContinue"

$uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
$Proxy=New-object System.Net.WebProxy
$WebSession=new-object Microsoft.PowerShell.Commands.WebRequestSession
$WebSession.Proxy=$Proxy
$result = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri $uri -WebSession $WebSession

if ( $null -eq $result){
   return $false
}
 else {
    return $true
}


}
## [END] Get-WACSDDCAzureVMStatus ##
function Get-WACSDDCBestHostNode {
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
## [END] Get-WACSDDCBestHostNode ##
function Get-WACSDDCBmcInfo {
<#

.SYNOPSIS
Gets current information on the baseboard management controller (BMC).

.DESCRIPTION
Gets information such as manufacturer, serial number, last known IP
address, model, and network configuration to show to user.

.ROLE
Readers

#>

Import-Module CimCmdlets
Import-Module PcsvDevice

$error.Clear()

$bmcInfo = Get-PcsvDevice -ErrorAction SilentlyContinue

$bmcAlternateInfo = Get-CimInstance Win32_Bios -ErrorAction SilentlyContinue
$serialNumber = $bmcInfo.SerialNumber

if ($bmcInfo -and $bmcAlternateInfo) {
    $serialNumber = -join($bmcInfo.SerialNumber, " / ", $bmcAlternateInfo.SerialNumber)
}

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "Error" $error.Count

if ($error.Count -EQ 0) {
    $result | Add-Member -MemberType NoteProperty -Name "Ip" $bmcInfo.IPv4Address
    $result | Add-Member -MemberType NoteProperty -Name "Serial" $serialNumber
}

$result

}
## [END] Get-WACSDDCBmcInfo ##
function Get-WACSDDCCPUAvailabilityPreCheck {
<#

.SYNOPSIS
Checks if there is enough CPU to allow shutting down one node without preempting any workloads.

.DESCRIPTION
Checks if there is enough CPU to allow shutting down one node without preempting any workloads.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory=$true)]
    [String[]] $nodeNames
)

Import-Module Updates -ErrorAction SilentlyContinue

$resultObject = New-Object -TypeName PSObject

# Get number of nodes
$nodesCount = $nodeNames.Count

# Check for no nodes
if ($nodesCount -lt 1) {
    $resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Unknown"
    return $resultObject
}

# For successful failover, we are checking that there is enough CPU on all but one node
# in the cluster to handle the average usage on all nodes over recent period of time
$maxCpuUsagePercent = ($nodesCount - 1) * 100 / $nodesCount;

# Average CPU usage on the cluster over the last hour, as a percent
$data = Get-ClusterPerf -ClusterSeriesName "ClusterNode.Cpu.Usage" -TimeFrame "LastHour"
$perf = $data | Microsoft.PowerShell.Utility\Measure-Object -Property Value -Minimum -Maximum -Average
$averageCpuUsagePercent = $perf.Average

# Checks if over the last hour, the cluster was using a greater percent of total CPU than is available on n-1 nodes.
if ($averageCpuUsagePercent -gt $maxCpuUsagePercent ) {
    $maxCpuUsagePercent = [math]::Round($maxCpuUsagePercent, 2)
    $averageCpuUsagePercent = [math]::Round($averageCpuUsagePercent, 2)
    $resultObject | Add-Member -MemberType NoteProperty -Name MaxUsagePercent -Value $maxCpuUsagePercent
    $resultObject | Add-Member -MemberType NoteProperty -Name UsagePercent -Value $averageCpuUsagePercent
    $resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Fail"
    return $resultObject
}

$resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Pass"
return $resultObject

}
## [END] Get-WACSDDCCPUAvailabilityPreCheck ##
function Get-WACSDDCCertificates {
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
## [END] Get-WACSDDCCertificates ##
function Get-WACSDDCCimDiskRegistry {
<#

.SYNOPSIS
Get Disk Registry status by using ManagementTools CIM provider.

.DESCRIPTION
Get Disk Registry status by using ManagementTools CIM provider.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTRegistryKey -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName GetValues

}
## [END] Get-WACSDDCCimDiskRegistry ##
function Get-WACSDDCCimDiskSummary {
<#

.SYNOPSIS
Get Disk summary by using ManagementTools CIM provider.

.DESCRIPTION
Get Disk summary by using ManagementTools CIM provider.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTDisk

}
## [END] Get-WACSDDCCimDiskSummary ##
function Get-WACSDDCCimMemorySummary {
<#

.SYNOPSIS
Get Memory summary by using ManagementTools CIM provider.

.DESCRIPTION
Get Memory summary by using ManagementTools CIM provider.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTMemorySummary

}
## [END] Get-WACSDDCCimMemorySummary ##
function Get-WACSDDCCimNetworkAdapterSummary {
<#

.SYNOPSIS
Get Network Adapter summary by using ManagementTools CIM provider.

.DESCRIPTION
Get Network Adapter summary by using ManagementTools CIM provider.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTNetworkAdapter

}
## [END] Get-WACSDDCCimNetworkAdapterSummary ##
function Get-WACSDDCCimProcessorSummary {
<#

.SYNOPSIS
Get Processor summary by using ManagementTools CIM provider.

.DESCRIPTION
Get Processor summary by using ManagementTools CIM provider.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcessorSummary

}
## [END] Get-WACSDDCCimProcessorSummary ##
function Get-WACSDDCClientConnectionStatus {
<#

.SYNOPSIS
Gets status of the connection to the client computer.

.DESCRIPTION
Gets status of the connection to the client computer.

.ROLE
Readers

#>

import-module CimCmdlets
$OperatingSystem = Get-CimInstance Win32_OperatingSystem
$Caption = $OperatingSystem.Caption
$ProductType = $OperatingSystem.ProductType
$Version = $OperatingSystem.Version
$Status = @{ Label = $null; Type = 0; Details = $null; }
$Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }

if ($Version -and $ProductType -eq 1) {
    $V = [version]$Version
    $V10 = [version]'10.0'
    if ($V -ge $V10) {
        return $Result;
    } 
}

$Status.Label = 'unsupported-label'
$Status.Type = 3
$Status.Details = 'unsupported-details'
return $Result;

}
## [END] Get-WACSDDCClientConnectionStatus ##
function Get-WACSDDCClusterInformation {
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
## [END] Get-WACSDDCClusterInformation ##
function Get-WACSDDCClusterReportList {
<#

.SYNOPSIS
List available Cluster validation report XML, HTM and MHT files.

.DESCRIPTION
List available Cluster validation report XML, HTM and MHT files.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$ReportPath = "${env:windir}\Cluster\Reports"
$XmlReports = @(Get-ChildItem "${ReportPath}\Validation*.xml" |
    Microsoft.PowerShell.Utility\Sort-Object -Descending LastWriteTime |
    Microsoft.PowerShell.Utility\Select-Object -Property @{Name = "Path"; Expression = {$_.FullName}}, @{Name = "Date"; Expression = {$_.LastWriteTime}})
$HtmlReports = @(Get-ChildItem "${ReportPath}\*.htm","${ReportPath}\*.mht" |
    Microsoft.PowerShell.Utility\Sort-Object -Descending LastWriteTime |
    Microsoft.PowerShell.Utility\Select-Object -Property @{Name = "Path"; Expression = {$_.FullName}}, @{Name = "Date"; Expression = {$_.LastWriteTime}})
$Hostname = HOSTNAME.EXE
$Fqdn = [System.Net.Dns]::GetHostEntry($Hostname).HostName
@{
    XmlReports = $XmlReports
    HtmlReports = $HtmlReports
    DownloadHostName = $Fqdn
}
}
## [END] Get-WACSDDCClusterReportList ##
function Get-WACSDDCClusterReportResult {
<#

.SYNOPSIS
Reads the validation report by Test-Cluster cmdlet. Produce PowerShell objects that can be converted to JSON.

.DESCRIPTION
Reads the validation report by Test-Cluster cmdlet. Produce PowerShell objects that can be converted to JSON.

.ROLE
Readers

#>

Param([string]$Path)

Set-StrictMode -Version 5.0

# simple element which just has a string content.
$SimpleElements = @(
    "ChannelName"
    "ReportType"
)

# elements exists in the channel.
$ChannelElements = @{
    StartTime          = "Name", "Value"
    StopTime           = "Name", "Value"
    ValidationResult   = "Name", "Value"
    SummaryChannelItem = "Name", "Value"
    SummaryChannel     = "Name", "Value"
    Result             = "Name", "Value"
    Description        = "Name", "Value"
    Title              = "Name", "Value"
    ResultDescription  = "Name", "Value"
}

# element treated at sequential positioning with section container.
$SectionElements = @{
    IPAddress              = "Name", "Value"
    Quorum                 = "Name", "Value"
    QuorumConfiguration    = "Name", "Value"
    DistributedNetworkName = "Name", "Value"
    Subnet                 = "Name", "Value"
    OU                     = "Name", "Value"
    DynamicQuorum          = "Name", "Value"
    Storage                = "Name", "Value"
    VirtualMachine         = "Name", "Value"
    Resource               = "Name", "Value"
    ResourceGroup          = "Name", "Value"
    ResourceType           = "Name", "Value"
    NetName                = "Name", "Value"
    RoleSpecificNotes      = "Name", "Value"
    Node                   = "Name", "Value", "Status"
    Cluster                = "Name", "Value"
    Source                 = "Name", "Value"
    Network                = "Name", "Value"
    Image                  = "Value"
    ImageData              = "Value"
}

# element with "Name" element empty.
$ValueOnlyElements = @(
    "Result"
    "ResultDescription"
    "Title"
    "SummaryChannel"
    "SummaryChannelItem"
    "Image"
    "ImageData"
    "ValidationResult"
)

<#

.DESCRIPTION
Read element valuses specified by Names list.
If there is only Value propery containing data, just return value of Value.

#>
function ReadValues($TargetName, $Reader, $Names) {
    if ($Reader.Read()) {
        $Items = @{}
        foreach ($Name in $Names) {
            if ($Reader.Name -eq $Name) {
                $Value = $Reader.ReadElementContentAsString($Name, "")
                if ($Value) {
                    $Items[$Name] = $Value
                }
            }
        }

        if ($Items["Value"] -and $Items.Count -eq 1) {
            if (-not $ValueOnlyElements.Contains($TargetName)) {
                # warning at an unexpected format.
                Write-Warning ($TargetName + ":" +  $Items.Value)
            }

            return $Items.Value
        }

        return $Items
    }
}

<#

.DESCRIPTION
Read element as simple string.

#>
function ReadSimple($Reader) {
    if ($Reader.Read()) {
        $Reader.ReadString()
    }
}

<#

.DESCRIPTION
Read complex Table elements.

#>
function ReadTable($Reader) {
    $Table = @{
        Columns = @()
        Rows    = @()
    }

    While ($Reader.Read()) {
        $Name = $Reader.Name
        if (($Name -eq "Table") -or ($Name -eq "AlertTable")) {
            break
        }

        switch ($Name) {
            "Name" {
                $Table.Name = ReadSimple($Reader)
                break
            }
            "Column" {
                $Column = (ReadValues $Name $Reader "Name")
                $Table.Columns += $Column.Name
                break
            }
            "Row" {
                if ($Reader.Read()) {
                    for ($i = 0; $i -lt $Table.Columns.Count; $i++) {
                        $Table.Rows += $Reader.ReadElementContentAsString("Value", "")
                    }
                }

                break
            }
            default {
                # Skip "Width"
                break
            }
        }
    }
    
    return $Table
}

<#

.DESCRIPTION
Get current target channel to store the data.

#>
function GetCurrent($Depth) {
    if ($Depth -eq 2) {
        return $Root
    }

    return $Channel
}


<#

.DESCRIPTION
Move the section to store current section if any data contain.

#>
function MoveSection() {
    if ($Section.Count -gt 0) {
        AddItemToList $Channel "Sections" $Section
    }
}

<#

.DESCRIPTION
Add the item to the list. If there is no list exists, create a list.

#>
function AddItemToList($TargetObject, $ListName, $Item) {
    if (-not $TargetObject[$ListName]) {
        $TargetObject[$ListName] = @()
    }

    $TargetObject[$ListName] += $Item
}

<#

.DESCRIPTION
Read Channels data from XML document.

#>
function ReadChannels($Reader) {
    # Enter to content
    $Reader.MoveToContent() | Out-Null

    # Continue reading until EOF
    While ($Reader.Read()) {
        $Name = $Reader.Name
        $Depth = $Reader.Depth
        if ($Name -eq "Channel" -and $Reader.IsStartElement()) {
            # Channel Element newly starting.
            MoveSection
            $Section = @{}

            if ($Depth -eq 1) {
                $Channel = $Root
            }
            else {
                if ($Channel -and ($Channel -ne $Root)) {
                    AddItemToList $Result $Channel.Type $Channel
                }

                $Channel = @{}
            }

            $Channel.Type = $Reader.GetAttribute("Type")
            $Channel.Id = $Reader.GetAttribute("id")
        }
        elseif ($Name -eq "NewLine") {
            # NewLine is a separator of section.
            MoveSection
            $Section = @{}
            (ReadValues $Name $Reader "Name", "Value") | Out-Null
        }
        elseif ($Name -eq "Message") {
            # Message is sequentially produced in the section.
            $Message = @{}
            $Message.Level = $Reader.GetAttribute("Level")
            $Message.Text = ReadSimple($Reader)
            AddItemToList $Section "MessageList" $Message
        }
        elseif ($Name -eq "Table") {
            # Table always creates a section.
            if ($Section["Table"] -or $Section["AlertTable"]) {
                MoveSection
                $Section = @{}
            }

            $Section["Table"] = ReadTable($Reader)
        }
        elseif ($Name -eq "AlertTable") {
            # AlertTable always creates a sction.
            if ($Section["AlertTable"] -or $Section["Table"]) {
                MoveSection
                $Section = @{}
            }

            $Section["AlertTable"] = ReadTable($Reader)
        }
        elseif ($SimpleElements.Contains($Name)) {
            # Simple channel propery
            $Channel[$Name] = ReadSimple $Reader
        }
        elseif ($ChannelElements[$Name]) {
            # Channel property
            $Pair = ReadValues $Name $Reader $ChannelElements[$Name]
            $Target = (GetCurrent $Depth)
            if ($Name -eq "SummaryChannelItem") {
                $ItemList = $Name + "List"
                AddItemToList $Target $ItemList $Pair
            }
            else {
                $Target[$Name] = $Pair
            }
        }
        elseif ($SectionElements[$Name]) {
            # Section property
            $Pair = ReadValues $Name $Reader $SectionElements[$Name]
            if ($Name -eq "Node") {
                $ItemList = $Name + "List"
                AddItemToList $Section $ItemList $Pair
            }
            else {
                $Section[$Name] = $Pair
            }
        }
    }

    if ($Section.Count -gt 0) {
        MoveSection
        $Section = @{}
    }

    if ($Channel -and ($Channel.Count -gt 0)) {
        AddItemToList $Result $Channel.Type $Channel
        $Channel = $null
    }
}

# Main script to process XML data.
$Root = @{}
$Result = @{
    Root = $Root
}
$Channel = $Root
$Section = @{}

$Settings = new-object System.Xml.XmlReaderSettings
$Settings.IgnoreWhitespace = $true
$Settings.IgnoreComments = $true
$Reader = [System.Xml.XmlReader]::Create($Path, $Settings)
ReadChannels($Reader)

$Result
}
## [END] Get-WACSDDCClusterReportResult ##
function Get-WACSDDCComputerIdentification {
<#

.SYNOPSIS
Gets the local computer domain/workplace information.

.DESCRIPTION
Gets the local computer domain/workplace information.
Returns the computer identification information.

.ROLE
Readers

#>

import-module CimCmdlets

$ComputerSystem = Get-CimInstance -Class Win32_ComputerSystem;
$ComputerName = $ComputerSystem.DNSHostName
if ($ComputerName -eq $null) {
    $ComputerName = $ComputerSystem.Name
}

$fqdn = ([System.Net.Dns]::GetHostByName($ComputerName)).HostName

$ComputerSystem | Microsoft.PowerShell.Utility\Select-Object `
@{ Name = "ComputerName"; Expression = { $ComputerName }},
@{ Name = "Domain"; Expression = { if ($_.PartOfDomain) { $_.Domain } else { $null } }},
@{ Name = "DomainJoined"; Expression = { $_.PartOfDomain }},
@{ Name = "FullComputerName"; Expression = { $fqdn }},
@{ Name = "Workgroup"; Expression = { if ($_.PartOfDomain) { $null } else { $_.Workgroup } }}


}
## [END] Get-WACSDDCComputerIdentification ##
function Get-WACSDDCComputerName {
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
## [END] Get-WACSDDCComputerName ##
function Get-WACSDDCCrashEvents {
<#
.SYNOPSIS
Get crash events

.DESCRIPTION
Gets application error events within the last 14 days, the Get-WinEvent cmdlet can cause powershell exception if the event id not exist.
Will suppress the error and return an empty array if no events are found.

.ROLE
Readers

#>

param (
  [boolean] $fromDialog
)

$eventIDs = @(1000)
$loggedSince = (Get-Date).AddDays(-14)

if ($fromDialog) {
  $filteredLogs = Get-WinEvent -MaxEvents 50 -FilterHashtable @{
    Level = 2
    LogName = "Application"
    ID = $eventIDs
    StartTime = $loggedSince
  } -ErrorAction SilentlyContinue | Select-Object Message, Properties, TimeCreated, LogName, ProviderName, Id, LevelDisplayName
} else {
  $filteredLogs = Get-WinEvent -MaxEvents 5 -FilterHashtable @{
    Level = 2
    LogName = "Application"
    ID = $eventIDs
    StartTime = $loggedSince
  } -ErrorAction SilentlyContinue | Select-Object Message, Properties, TimeCreated, LogName, ProviderName, Id, LevelDisplayName
}

if (-not $filteredLogs) {
    $filteredLogs = @()
}

return $filteredLogs

}
## [END] Get-WACSDDCCrashEvents ##
function Get-WACSDDCDiagnosticDataSetting {
<#
.SYNOPSIS
Gets diagnostic data setting

.DESCRIPTION
Gets diagnostic data setting for telemetry

.ROLE
Readers

#>

$registryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
$propertyName = 'AllowTelemetry'
$allowTelemetry = Get-ItemProperty -Path $registryKey -Name $propertyName -ErrorAction SilentlyContinue
if (!$allowTelemetry) {
  $registryKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
  $propertyName = 'AllowTelemetry'
  $allowTelemetry = Get-ItemProperty -Path $registryKey -Name $propertyName -ErrorAction SilentlyContinue
}
return $allowTelemetry.AllowTelemetry




}
## [END] Get-WACSDDCDiagnosticDataSetting ##
function Get-WACSDDCDiskSpaceOnVolumePreCheck {
<#

.SYNOPSIS
Checks if there is enough disk space on the boot volume of a node

.DESCRIPTION
Checks if there is enough disk space on the boot volume of a node

.ROLE
Readers

#>

$volume = Get-Volume $ENV:SystemDrive[0]

if ($null -ne $volume) {
    $volume.SizeRemaining -gt 5GB
}

}
## [END] Get-WACSDDCDiskSpaceOnVolumePreCheck ##
function Get-WACSDDCDiskSummaryDownlevel {
<#

.SYNOPSIS
Gets disk summary information by performance counter WMI object on downlevel computer.

.DESCRIPTION
Gets disk summary information by performance counter WMI object on downlevel computer.

.ROLE
Readers

#>

param
(
)

import-module CimCmdlets

function ResetDiskData($diskResults) {
    $Global:DiskResults = @{}
    $Global:DiskDelta = 0

    foreach ($item in $diskResults) {
        $diskRead = New-Object System.Collections.ArrayList
        $diskWrite = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 60; $i++) {
            $diskRead.Insert(0, 0)
            $diskWrite.Insert(0, 0)
        }

        $Global:DiskResults.Item($item.name) = @{
            ReadTransferRate  = $diskRead
            WriteTransferRate = $diskWrite
        }
    }
}

function UpdateDiskData($diskResults) {
    $Global:DiskDelta += ($Global:DiskSampleTime - $Global:DiskLastTime).TotalMilliseconds

    foreach ($diskResult in $diskResults) {
        $localDelta = $Global:DiskDelta

        # update data for each disk
        $item = $Global:DiskResults.Item($diskResult.name)

        if ($item -ne $null) {
            while ($localDelta -gt 1000) {
                $localDelta -= 1000
                $item.ReadTransferRate.Insert(0, $diskResult.DiskReadBytesPersec)
                $item.WriteTransferRate.Insert(0, $diskResult.DiskWriteBytesPersec)
            }

            $item.ReadTransferRate = $item.ReadTransferRate.GetRange(0, 60)
            $item.WriteTransferRate = $item.WriteTransferRate.GetRange(0, 60)

            $Global:DiskResults.Item($diskResult.name) = $item
        }
    }

    $Global:DiskDelta = $localDelta
}

$counterValue = Get-CimInstance win32_perfFormattedData_PerfDisk_PhysicalDisk -Filter "name!='_Total'" | Microsoft.PowerShell.Utility\Select-Object name, DiskReadBytesPersec, DiskWriteBytesPersec
$now = get-date

# get sampling time and remember last sample time.
if (-not $Global:DiskSampleTime) {
    $Global:DiskSampleTime = $now
    $Global:DiskLastTime = $Global:DiskSampleTime
    ResetDiskData($counterValue)
}
else {
    $Global:DiskLastTime = $Global:DiskSampleTime
    $Global:DiskSampleTime = $now
    if ($Global:DiskSampleTime - $Global:DiskLastTime -gt [System.TimeSpan]::FromSeconds(30)) {
        ResetDiskData($counterValue)
    }
    else {
        UpdateDiskData($counterValue)
    }
}

$Global:DiskResults
}
## [END] Get-WACSDDCDiskSummaryDownlevel ##
function Get-WACSDDCEnvironmentVariables {
<#

.SYNOPSIS
Gets 'Machine' and 'User' environment variables.

.DESCRIPTION
Gets 'Machine' and 'User' environment variables.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$data = @()

$system = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
$user = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)

foreach ($h in $system.GetEnumerator()) {
    $obj = @{"Name" = $h.Name; "Value" = $h.Value; "Type" = "Machine"}
    $data += $obj
}

foreach ($h in $user.GetEnumerator()) {
    $obj = @{"Name" = $h.Name; "Value" = $h.Value; "Type" = "User"}
    $data += $obj
}

$data
}
## [END] Get-WACSDDCEnvironmentVariables ##
function Get-WACSDDCFileNamesInPath {
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
## [END] Get-WACSDDCFileNamesInPath ##
function Get-WACSDDCFileSystemEntities {
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
## [END] Get-WACSDDCFileSystemEntities ##
function Get-WACSDDCFileSystemRoot {
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
## [END] Get-WACSDDCFileSystemRoot ##
function Get-WACSDDCFolderItemCount {
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
## [END] Get-WACSDDCFolderItemCount ##
function Get-WACSDDCFolderOwner {
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
## [END] Get-WACSDDCFolderOwner ##
function Get-WACSDDCFolderShareNames {
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
## [END] Get-WACSDDCFolderShareNames ##
function Get-WACSDDCFolderSharePath {
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
## [END] Get-WACSDDCFolderSharePath ##
function Get-WACSDDCFolderShareStatus {
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
## [END] Get-WACSDDCFolderShareStatus ##
function Get-WACSDDCFolderShareUsers {
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
## [END] Get-WACSDDCFolderShareUsers ##
function Get-WACSDDCHybridManagementConfiguration {
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
    $config = & $HybridAgentExecutable -j show

    if ($config) {
        $configObj = $config | ConvertFrom-Json
        @{
            machine = $configObj.resourceName;
            resourceGroup = $configObj.resourceGroup;
            subscriptionId = $configObj.subscriptionId;
            tenantId = $configObj.tenantId;
            vmId = $configObj.vmId;
            azureRegion = $configObj.location;
            agentVersion = $configObj.agentVersion;
            agentStatus = $configObj.status;
            agentLastHeartbeat = $configObj.lastHeartbeat;
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }
}

function getValue([string]$keyValue) {
    $splitArray = $keyValue -split ":"
    $value = $splitArray[1].trim()
    return $value
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
## [END] Get-WACSDDCHybridManagementConfiguration ##
function Get-WACSDDCHybridManagementStatus {
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
## [END] Get-WACSDDCHybridManagementStatus ##
function Get-WACSDDCHyperVEnhancedSessionModeSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host Enhanced Session Mode settings.

.DESCRIPTION
Gets a computer's Hyper-V Host Enhnaced Session Mode settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    EnableEnhancedSessionMode

}
## [END] Get-WACSDDCHyperVEnhancedSessionModeSettings ##
function Get-WACSDDCHyperVGeneralSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host General settings.

.DESCRIPTION
Gets a computer's Hyper-V Host General settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    VirtualHardDiskPath, `
    VirtualMachinePath

}
## [END] Get-WACSDDCHyperVGeneralSettings ##
function Get-WACSDDCHyperVHostPhysicalGpuSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host Physical GPU settings.

.DESCRIPTION
Gets a computer's Hyper-V Host Physical GPU settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdlets

Get-CimInstance -Namespace "root\virtualization\v2" -Class "Msvm_Physical3dGraphicsProcessor" | `
    Microsoft.PowerShell.Utility\Select-Object EnabledForVirtualization, `
    Name, `
    DriverDate, `
    DriverInstalled, `
    DriverModelVersion, `
    DriverProvider, `
    DriverVersion, `
    DirectXVersion, `
    PixelShaderVersion, `
    DedicatedVideoMemory, `
    DedicatedSystemMemory, `
    SharedSystemMemory, `
    TotalVideoMemory

}
## [END] Get-WACSDDCHyperVHostPhysicalGpuSettings ##
function Get-WACSDDCHyperVLiveMigrationSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host Live Migration settings.

.DESCRIPTION
Gets a computer's Hyper-V Host Live Migration settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    maximumVirtualMachineMigrations, `
    VirtualMachineMigrationAuthenticationType, `
    VirtualMachineMigrationEnabled, `
    VirtualMachineMigrationPerformanceOption

}
## [END] Get-WACSDDCHyperVLiveMigrationSettings ##
function Get-WACSDDCHyperVMigrationSupport {
<#

.SYNOPSIS
Gets a computer's Hyper-V migration support.

.DESCRIPTION
Gets a computer's Hyper-V  migration support.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$migrationSettingsDatas=Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Query "associators of {Msvm_VirtualSystemMigrationCapabilities.InstanceID=""Microsoft:MigrationCapabilities""} where resultclass = Msvm_VirtualSystemMigrationSettingData"

$live = $false;
$storage = $false;

foreach ($migrationSettingsData in $migrationSettingsDatas) {
    if ($migrationSettingsData.MigrationType -eq 32768) {
        $live = $true;
    }

    if ($migrationSettingsData.MigrationType -eq 32769) {
        $storage = $true;
    }
}

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "liveMigrationSupported" $live;
$result | Add-Member -MemberType NoteProperty -Name "storageMigrationSupported" $storage;
$result
}
## [END] Get-WACSDDCHyperVMigrationSupport ##
function Get-WACSDDCHyperVNumaSpanningSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host settings.

.DESCRIPTION
Gets a computer's Hyper-V Host settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    NumaSpanningEnabled

}
## [END] Get-WACSDDCHyperVNumaSpanningSettings ##
function Get-WACSDDCHyperVRoleInstalled {
<#

.SYNOPSIS
Gets a computer's Hyper-V role installation state.

.DESCRIPTION
Gets a computer's Hyper-V role installation state.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
 
$service = Microsoft.PowerShell.Management\get-service -Name "VMMS" -ErrorAction SilentlyContinue;

return ($service -and $service.Name -eq "VMMS");

}
## [END] Get-WACSDDCHyperVRoleInstalled ##
function Get-WACSDDCHyperVStorageMigrationSettings {
<#

.SYNOPSIS
Gets a computer's Hyper-V Host settings.

.DESCRIPTION
Gets a computer's Hyper-V Host settings.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    MaximumStorageMigrations

}
## [END] Get-WACSDDCHyperVStorageMigrationSettings ##
function Get-WACSDDCIsAzureTurbineServer {
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
## [END] Get-WACSDDCIsAzureTurbineServer ##
function Get-WACSDDCIsDellApexCp {
<#

.SYNOPSIS
Gets if a cluster is a DELL DellApexCp cluster.

.DESCRIPTION
Existence of cluster parameters signifies that it is a DELL DellApexCp cluster.

.ROLE
Readers

#>

Get-ClusterResource -Name "Cluster IP Address" | Get-ClusterParameter -Name @("ACP_ManagerIP", "ACP_ManagerVersion", "ACP_ManagerCertThumbprint") -ErrorAction SilentlyContinue -ErrorVariable +err
$isDellApexCp = $true
if ($err) {
  $isDellApexCp = $false
}

$isDellApexCp

}
## [END] Get-WACSDDCIsDellApexCp ##
function Get-WACSDDCItemProperties {
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
## [END] Get-WACSDDCItemProperties ##
function Get-WACSDDCItemType {
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
## [END] Get-WACSDDCItemType ##
function Get-WACSDDCKsrClusterProperty {
<#

.SYNOPSIS
Checks if the cluster property for KSR is set to true.

.DESCRIPTION
Checks if the cluster property for KSR is set to true.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

$result = Get-Cluster | Get-ClusterParameter -Name "CauEnableSoftReboot" -ErrorAction SilentlyContinue -ErrorVariable +err

if ($err) {
    return @{ ksrEnabled = $false }
}

# Value will be 1 if soft reboot is enabled
return @{ ksrEnabled = $result.value }

}
## [END] Get-WACSDDCKsrClusterProperty ##
function Get-WACSDDCLastCauReport {
<#

.SYNOPSIS
Gets the last CAU run details.

.DESCRIPTION
Gets the last CAU run details.

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

function Get-LastCauRunDetails {
    $report = Get-CauReport -ClusterName $clusterName -Last -Detailed

    $cauReport = @{}
    # This is the 0 Day scenario where there is no previous report. So we need to get all nodes names.
    if ($report -eq $null) {
        $clusterNodes = Get-ClusterNode | Microsoft.PowerShell.Utility\Select-object Cluster,
            @{Name = "Node"; Expression = {$_.Name}},
            @{Name = "Status"; Expression = {4}}
        $clusterName = $clusterNodes[0].Cluster
        $status = $clusterNodes[0].Status
        $nodeResults = $clusterNodes
        $cauReport.Add("ClusterName", $clusterName)
        $cauReport.Add("Status", $status)
        $cauReport.Add("NodeResults", $nodeResults)
    }
    else
    {

        $cauReport.Add("ClusterName", $report.ClusterResult.Name)
        $cauReport.Add("StartTimestamp", $report.ClusterResult.StartTimestamp)
        # If we build a PS object instead of an array we may be able to get Status back with it's enum value instead of a string like "Succeeded"
        # More info/example in Get-RunDetails script.
        $cauReport.Add("Status", $report.ClusterResult.Status)
        $cauReport.Add("RunId", $report.ClusterResult.RunId)
        $cauReport.Add("NodeResults", $report.ClusterResult.NodeResults)
        $cauReport.Add("RunDuration", $report.ClusterResult.RunDuration)
        $cauReport.Add("ErrorRecordData", $report.ClusterResult.ErrorRecordData)
        $cauReport.Add("OrchestratorMachine", $report.OrchestratorMachine)
        $cauReport.Add("OrchestratorUser", $report.OrchestratorUser)
        $cauReport.Add("OrchestratorUpdateAccount", $report.OrchestratorUpdateAccount)
        $cauReport.Add("Plugin",  $report.Plugin)
    }

    $cauReport
}

########
# Main
########
Get-LastCauRunDetails

}
## [END] Get-WACSDDCLastCauReport ##
function Get-WACSDDCLicenseStatusChecks {
<#

.SYNOPSIS
Does the license checks for a server

.DESCRIPTION
Does the license checks for a server

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $applicationId
)

Import-Module CimCmdlets

function Get-LicenseStatus() {
  # LicenseStatus check
  $cim = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.ProductKeyID  -and  $_.ApplicationID -eq $applicationId }
  try {
    $licenseStatus = $cim.LicenseStatus;
  }
  catch {
    $LicenseStatus = $null;
  }

  return $LicenseStatus;
}

function Get-SoftwareLicensingService() {
  $cim = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction SilentlyContinue

  # Without the trycf it fails with the error:
  # The property 'AzureMetadataResponse' cannot be found on this object. Verify that the property exists.
  try {
    $azureMetadataResponse = $cim.AzureMetadataResponse
  }
  catch {
    $azureMetadataResponse = $null
  }

  return $azureMetadataResponse;
}


$result = New-Object PSObject
$result | Add-Member -MemberType NoteProperty -Name "LicenseStatus" -Value (Get-LicenseStatus)
$result | Add-Member -MemberType NoteProperty -Name "AzureMetadataResponse" -Value (Get-SoftwareLicensingService)

$result

}
## [END] Get-WACSDDCLicenseStatusChecks ##
function Get-WACSDDCLocalGroups {
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
## [END] Get-WACSDDCLocalGroups ##
function Get-WACSDDCLocalUsers {
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
## [END] Get-WACSDDCLocalUsers ##
function Get-WACSDDCMSCluster_Cluster {
<#

.SYNOPSIS
Gets MSCluster_Cluster object.

.DESCRIPTION
Gets MSCluster_Cluster object.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/mscluster -ClassName MSCluster_Cluster

}
## [END] Get-WACSDDCMSCluster_Cluster ##
function Get-WACSDDCMSCluster_Node {
<#

.SYNOPSIS
Gets MSCluster_Node objects.

.DESCRIPTION
Gets MSCluster_Node objects.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/mscluster -ClassName MSCluster_Node

}
## [END] Get-WACSDDCMSCluster_Node ##
function Get-WACSDDCMemoryAvailabilityPreCheck {
<#

.SYNOPSIS
Checks if there is enough memory to allow shutting down one node without preempting any workloads.

.DESCRIPTION
Checks if there is enough memory to allow shutting down one node without preempting any workloads.

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory=$true)]
    [String[]] $nodeNames
)

Import-Module Updates -ErrorAction SilentlyContinue

$resultObject = New-Object -TypeName PSObject

# Get number of nodes
$nodesCount = $nodeNames.Count

# Check for no nodes
if ($nodesCount -lt 1) {
    $resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Unknown"
    return $resultObject
}

# For successful failover, we are checking that there is enough memory on all but one node
# in the cluster to handle the average usage on all nodes over recent period of time
$maxMemoryUsageFraction = ($nodesCount - 1) / $nodesCount;

# Average memory usage on the cluster over the last hour, as a value
$data = Get-ClusterPerf -ClusterSeriesName "ClusterNode.Memory.Usage" -TimeFrame "LastHour"
$perf = $data | Microsoft.PowerShell.Utility\Measure-Object -Property Value -Minimum -Maximum -Average
$averageMemoryUsageValue = $perf.Average

# Average total available memory on the cluster over the last hour, as a value
$Data = Get-ClusterPerf -ClusterSeriesName "ClusterNode.Memory.Total" -TimeFrame "LastHour"
$perf = $Data | Microsoft.PowerShell.Utility\Measure-Object -Property Value -Minimum -Maximum -Average
$averageMemoryTotalValue = $perf.Average

$averageMemoryUsageFraction = $averageMemoryUsageValue / $averageMemoryTotalValue

# Checks if over the last hour, the cluster was using a greater fraction of total memory
# than is available on n-1 nodes.
if ($averageMemoryUsageFraction -gt $maxMemoryUsageFraction ) {
    $maxMemoryUsagePercent = [math]::Round($maxMemoryUsageFraction*100, 2)
    $averageMemoryUsagePercent = [math]::Round($averageMemoryUsageFraction*100, 2)
    $resultObject | Add-Member -MemberType NoteProperty -Name MaxUsagePercent -Value $maxMemoryUsagePercent
    $resultObject | Add-Member -MemberType NoteProperty -Name UsagePercent -Value $averageMemoryUsagePercent
    $resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Fail"
    return $resultObject
}

$resultObject | Add-Member -MemberType NoteProperty -Name Status -Value "Pass"
return $resultObject

}
## [END] Get-WACSDDCMemoryAvailabilityPreCheck ##
function Get-WACSDDCMemorySummaryDownLevel {
<#

.SYNOPSIS
Gets memory summary information by performance counter WMI object on downlevel computer.

.DESCRIPTION
Gets memory summary information by performance counter WMI object on downlevel computer.

.ROLE
Readers

#>

import-module CimCmdlets

# reset counter reading only first one.
function Reset($counter) {
    $Global:Utilization = [System.Collections.ArrayList]@()
    for ($i = 0; $i -lt 59; $i++) {
        $Global:Utilization.Insert(0, 0)
    }

    $Global:Utilization.Insert(0, $counter)
    $Global:Delta = 0
}

$memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$now = get-date
$system = Get-CimInstance Win32_ComputerSystem
$percent = 100 * ($system.TotalPhysicalMemory - $memory.AvailableBytes) / $system.TotalPhysicalMemory
$cached = $memory.StandbyCacheCoreBytes + $memory.StandbyCacheNormalPriorityBytes + $memory.StandbyCacheReserveBytes + $memory.ModifiedPageListBytes

# get sampling time and remember last sample time.
if (-not $Global:SampleTime) {
    $Global:SampleTime = $now
    $Global:LastTime = $Global:SampleTime
    Reset($percent)
}
else {
    $Global:LastTime = $Global:SampleTime
    $Global:SampleTime = $now
    if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
        Reset($percent)
    }
    else {
        $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
        while ($Global:Delta -gt 1000) {
            $Global:Delta -= 1000
            $Global:Utilization.Insert(0, $percent)
        }

        $Global:Utilization = $Global:Utilization.GetRange(0, 60)
    }
}

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "Available" $memory.AvailableBytes
$result | Add-Member -MemberType NoteProperty -Name "Cached" $cached
$result | Add-Member -MemberType NoteProperty -Name "Total" $system.TotalPhysicalMemory
$result | Add-Member -MemberType NoteProperty -Name "InUse" ($system.TotalPhysicalMemory - $memory.AvailableBytes)
$result | Add-Member -MemberType NoteProperty -Name "Committed" $memory.CommittedBytes
$result | Add-Member -MemberType NoteProperty -Name "PagedPool" $memory.PoolPagedBytes
$result | Add-Member -MemberType NoteProperty -Name "NonPagedPool" $memory.PoolNonpagedBytes
$result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
$result
}
## [END] Get-WACSDDCMemorySummaryDownLevel ##
function Get-WACSDDCMmaStatus {
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
$ServiceMapAgentStatus = Get-Service -Name MicrosoftDependencyAgent -ErrorAction SilentlyContinue
$IsServiceMapAgentInstalled = $null -ne $ServiceMapAgentStatus -and $ServiceMapAgentStatus.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

$AgentConfig = New-Object -ComObject 'AgentConfigManager.mgmtsvccfg'
$WorkSpaces = @($AgentConfig.GetCloudWorkspaces() | Microsoft.PowerShell.Utility\Select-Object -Property WorkspaceId, AgentId)

return @{
  Installed                     = $true;
  Running                       = $IsAgentRunning;
  IsServiceMapAgentInstalled    = $IsServiceMapAgentInstalled
  WorkSpaces                    = $WorkSpaces
}

}
## [END] Get-WACSDDCMmaStatus ##
function Get-WACSDDCNetworkSummaryDownlevel {
<#

.SYNOPSIS
Gets network adapter summary information by performance counter WMI object on downlevel computer.

.DESCRIPTION
Gets network adapter summary information by performance counter WMI object on downlevel computer.

.ROLE
Readers

#>

import-module CimCmdlets
function ResetData($adapterResults) {
    $Global:NetworkResults = @{}
    $Global:PrevAdapterData = @{}
    $Global:Delta = 0

    foreach ($key in $adapterResults.Keys) {
        $adapterResult = $adapterResults.Item($key)
        $sentBytes = New-Object System.Collections.ArrayList
        $receivedBytes = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 60; $i++) {
            $sentBytes.Insert(0, 0)
            $receivedBytes.Insert(0, 0)
        }

        $networkResult = @{
            SentBytes = $sentBytes
            ReceivedBytes = $receivedBytes
        }
        $Global:NetworkResults.Item($key) = $networkResult
    }
}

function UpdateData($adapterResults) {
    $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds

    foreach ($key in $adapterResults.Keys) {
        $localDelta = $Global:Delta

        # update data for each adapter
        $adapterResult = $adapterResults.Item($key)
        $item = $Global:NetworkResults.Item($key)
        if ($item -ne $null) {
            while ($localDelta -gt 1000) {
                $localDelta -= 1000
                $item.SentBytes.Insert(0, $adapterResult.SentBytes)
                $item.ReceivedBytes.Insert(0, $adapterResult.ReceivedBytes)
            }

            $item.SentBytes = $item.SentBytes.GetRange(0, 60)
            $item.ReceivedBytes = $item.ReceivedBytes.GetRange(0, 60)

            $Global:NetworkResults.Item($key) = $item
        }
    }

    $Global:Delta = $localDelta
}

$adapters = Get-CimInstance -Namespace root/standardCimV2 MSFT_NetAdapter | Where-Object MediaConnectState -eq 1 | Microsoft.PowerShell.Utility\Select-Object Name, InterfaceIndex, InterfaceDescription
$activeAddresses = get-CimInstance -Namespace root/standardCimV2 MSFT_NetIPAddress | Microsoft.PowerShell.Utility\Select-Object interfaceIndex

$adapterResults = @{}
foreach ($adapter in $adapters) {
    foreach ($activeAddress in $activeAddresses) {
        # Find a match between the 2
        if ($adapter.InterfaceIndex -eq $activeAddress.interfaceIndex) {
            $description = $adapter | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty interfaceDescription

            if ($Global:UsePerfData -EQ $NULL) {
                $adapterData = Get-CimInstance -Namespace root/StandardCimv2 MSFT_NetAdapterStatisticsSettingData -Filter "Description='$description'" | Microsoft.PowerShell.Utility\Select-Object ReceivedBytes, SentBytes

                if ($adapterData -EQ $null) {
                    # If above doesnt return data use slower perf data below
                    $Global:UsePerfData = $true
                }
            }

            if ($Global:UsePerfData -EQ $true) {
                # Need to replace the '#' to ascii since we parse anything after # as a comment
                $sanitizedDescription = $description -replace [char]35, "_"
                $adapterData = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkAdapter | Where-Object name -EQ $sanitizedDescription | Microsoft.PowerShell.Utility\Select-Object BytesSentPersec, BytesReceivedPersec

                $sentBytes = $adapterData.BytesSentPersec
                $receivedBytes = $adapterData.BytesReceivedPersec
            }
            else {
                # set to 0 because we dont have a baseline to subtract from
                $sentBytes = 0
                $receivedBytes = 0

                if ($Global:PrevAdapterData -ne $null) {
                    $prevData = $Global:PrevAdapterData.Item($description)
                    if ($prevData -ne $null) {
                        $sentBytes = $adapterData.SentBytes - $prevData.SentBytes
                        $receivedBytes = $adapterData.ReceivedBytes - $prevData.ReceivedBytes
                    }
                }
                else {
                    $Global:PrevAdapterData = @{}
                }

                # Now that we have data, set current data as previous data as baseline
                $Global:PrevAdapterData.Item($description) = $adapterData
            }

            $adapterResult = @{
                SentBytes = $sentBytes
                ReceivedBytes = $receivedBytes
            }
            $adapterResults.Item($description) = $adapterResult
            break;
        }
    }
}

$now = get-date

if (-not $Global:SampleTime) {
    $Global:SampleTime = $now
    $Global:LastTime = $Global:SampleTime
    ResetData($adapterResults)
}
else {
    $Global:LastTime = $Global:SampleTime
    $Global:SampleTime = $now
    if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
        ResetData($adapterResults)
    }
    else {
        UpdateData($adapterResults)
    }
}

$Global:NetworkResults
}
## [END] Get-WACSDDCNetworkSummaryDownlevel ##
function Get-WACSDDCNumberOfLoggedOnUsers {
<#

.SYNOPSIS
Gets the number of logged on users.

.DESCRIPTION
Gets the number of logged on users including active and disconnected users.
Returns a count of users.

.ROLE
Readers

#>

$error.Clear()

# Use Process class to hide exe prompt when executing
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = "quser.exe"
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true 
$process.StartInfo.RedirectStandardError = $true
$process.Start() | Out-Null 
$process.WaitForExit()

$result = @()
while ($line = $process.StandardOutput.ReadLine()) {
    $result += $line 
}

if ($process.StandardError.EndOfStream) {
    # quser does not return a valid ps object and includes the header.
    # subtract 1 to get actual count.
    $count = $result.count - 1
} else {
    # there is an error to get result. Set to 0 instead of -1 currently
    $count = 0
}

$process.Dispose()

@{ Count = $count }
}
## [END] Get-WACSDDCNumberOfLoggedOnUsers ##
function Get-WACSDDCOSBuildnumber {
<#

.SYNOPSIS
Gets the OS build number.

.DESCRIPTION
Gets the OS build number.

.ROLE
Administrators

.PARAMETER groupName
Gets the OS build number.

#>

return [System.Environment]::OSVersion.Version.Build

}
## [END] Get-WACSDDCOSBuildnumber ##
function Get-WACSDDCOSDetails {
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
## [END] Get-WACSDDCOSDetails ##
function Get-WACSDDCPowerConfigurationPlan {
<#

.SYNOPSIS
Gets the power plans on the machine.

.DESCRIPTION
Gets the power plans on the machine.

.ROLE
Readers

#>

$GuidLength = 36
$plans = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan

if ($plans) {
  $result = New-Object 'System.Collections.Generic.List[System.Object]'

  foreach ($plan in $plans) {
    $currentPlan = New-Object -TypeName PSObject

    $currentPlan | Add-Member -MemberType NoteProperty -Name 'Name' -Value $plan.ElementName
    $currentPlan | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $plan.ElementName
    $currentPlan | Add-Member -MemberType NoteProperty -Name 'IsActive' -Value $plan.IsActive
    $startBrace = $plan.InstanceID.IndexOf("{")
    $currentPlan | Add-Member -MemberType NoteProperty -Name 'Guid' -Value $plan.InstanceID.SubString($startBrace + 1, $GuidLength)

    $result.Add($currentPlan)
  }

  return $result.ToArray()
}

return $null

}
## [END] Get-WACSDDCPowerConfigurationPlan ##
function Get-WACSDDCProcessorSummaryDownlevel {
<#

.SYNOPSIS
Gets processor summary information by performance counter WMI object on downlevel computer.

.DESCRIPTION
Gets processor summary information by performance counter WMI object on downlevel computer.

.ROLE
Readers

#>

import-module CimCmdlets

# reset counter reading only first one.
function Reset($counter) {
    $Global:Utilization = [System.Collections.ArrayList]@()
    for ($i = 0; $i -lt 59; $i++) {
        $Global:Utilization.Insert(0, 0)
    }

    $Global:Utilization.Insert(0, $counter)
    $Global:Delta = 0
}

$processorCounter = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "name='_Total'"
$now = get-date
$processor = Get-CimInstance Win32_Processor
$os = Get-CimInstance Win32_OperatingSystem
$processes = Get-CimInstance Win32_Process
$percent = $processorCounter.PercentProcessorTime
$handles = 0
$threads = 0
$processes | ForEach-Object { $handles += $_.HandleCount; $threads += $_.ThreadCount }
$uptime = ($now - $os.LastBootUpTime).TotalMilliseconds * 10000

# get sampling time and remember last sample time.
if (-not $Global:SampleTime) {
    $Global:SampleTime = $now
    $Global:LastTime = $Global:SampleTime
    Reset($percent)
}
else {
    $Global:LastTime = $Global:SampleTime
    $Global:SampleTime = $now
    if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
        Reset($percent)
    }
    else {
        $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
        while ($Global:Delta -gt 1000) {
            $Global:Delta -= 1000
            $Global:Utilization.Insert(0, $percent)
        }

        $Global:Utilization = $Global:Utilization.GetRange(0, 60)
    }
}

$result = New-Object -TypeName PSObject
$result | Add-Member -MemberType NoteProperty -Name "Name" $processor[0].Name
$result | Add-Member -MemberType NoteProperty -Name "AverageSpeed" ($processor[0].CurrentClockSpeed / 1000)
$result | Add-Member -MemberType NoteProperty -Name "Processes" $processes.Length
$result | Add-Member -MemberType NoteProperty -Name "Uptime" $uptime
$result | Add-Member -MemberType NoteProperty -Name "Handles" $handles
$result | Add-Member -MemberType NoteProperty -Name "Threads" $threads
$result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
$result
}
## [END] Get-WACSDDCProcessorSummaryDownlevel ##
function Get-WACSDDCRbacEnabled {
<#

.SYNOPSIS
Gets the state of the Get-PSSessionConfiguration command

.DESCRIPTION
Gets the state of the Get-PSSessionConfiguration command

.ROLE
Readers

#>

if ($null -ne (Get-Command Get-PSSessionConfiguration -ErrorAction SilentlyContinue)) {
  @{ State = 'Available' }
} else {
  @{ State = 'NotSupported' }
}

}
## [END] Get-WACSDDCRbacEnabled ##
function Get-WACSDDCRbacSessionConfiguration {
<#

.SYNOPSIS
Gets a Microsoft.Sme.PowerShell endpoint configuration.

.DESCRIPTION
Gets a Microsoft.Sme.PowerShell endpoint configuration.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $false)]
    [String]
    $configurationName = "Microsoft.Sme.PowerShell"
)

## check if it's full administrators
if ((Get-Command Get-PSSessionConfiguration -ErrorAction SilentlyContinue) -ne $null) {
    @{
        Administrators = $true
        Configured = (Get-PSSessionConfiguration $configurationName -ErrorAction SilentlyContinue) -ne $null
    }
} else {
    @{
        Administrators = $false
        Configured = $false
    }
}
}
## [END] Get-WACSDDCRbacSessionConfiguration ##
function Get-WACSDDCRebootPendingStatus {
<#

.SYNOPSIS
Gets information about the server pending reboot.

.DESCRIPTION
Gets information about the server pending reboot.

.ROLE
Readers

#>

import-module CimCmdlets

function Get-ComputerNameChangeStatus {
    $currentComputerName = (Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
    $activeComputerName = (Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName").ComputerName
    return $currentComputerName -ne $activeComputerName
}

function Get-ItemPropertyValueSafe {
    param (
        [String] $Path,
        [String] $Name
    )
    # See https://github.com/PowerShell/PowerShell/issues/5906
    $value = Get-ItemProperty -Path $Path | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
    if ([String]::IsNullOrWhiteSpace($value)) {
        return $null;
    }
    return $value
}

function Get-SystemNameChangeStatus {
    $nvName = Get-ItemPropertyValueSafe -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "NV Hostname"
    $name = Get-ItemPropertyValueSafe -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "Hostname"
    $nvDomain = Get-ItemPropertyValueSafe -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "NV Domain"
    $domain = Get-ItemPropertyValueSafe -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "Domain"
    return ($nvName -ne $name) -or ($nvDomain -ne $domain)
}
function Test-PendingReboot {
    $value = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    if ($null -ne $value) { 
        return @{
            RebootRequired        = $true
            AdditionalInformation = 'Component Based Servicing\RebootPending'
        }
    } 
    $value = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if ($null -ne $value) { 
        return @{
            RebootRequired        = $true
            AdditionalInformation = 'WindowsUpdate\Auto Update\RebootRequired'
        } 
    }
    if (Get-ComputerNameChangeStatus) { 
        return @{
            RebootRequired        = $true
            AdditionalInformation = 'ComputerName\ActiveComputerName'
        }
    }
    if (Get-SystemNameChangeStatus) {
        return @{
            RebootRequired        = $true
            AdditionalInformation = 'Services\Tcpip\Parameters'
        }
    }
    $status = Invoke-CimMethod -Namespace root/ccm/clientsdk -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Ignore
    if (($null -ne $status) -and $status.RebootPending) {
        return @{
            RebootRequired        = $true
            AdditionalInformation = 'CCM_ClientUtilities'
        }
    }
    return @{
        RebootRequired        = $false
        AdditionalInformation = $null
    }
}
return Test-PendingReboot

}
## [END] Get-WACSDDCRebootPendingStatus ##
function Get-WACSDDCReleaseChannelPreCheck {
<#

.SYNOPSIS
Gets the release channel of a node

.DESCRIPTION
Gets the release channel of a node

.ROLE
Readers

#>

Get-PreviewChannel

}
## [END] Get-WACSDDCReleaseChannelPreCheck ##
function Get-WACSDDCRemoteDesktop {
<#
.SYNOPSIS
Gets the Remote Desktop settings of the system.

.DESCRIPTION
Gets the Remote Desktop settings of the system.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
Import-Module NetSecurity -ErrorAction SilentlyContinue
Import-Module ServerManager -ErrorAction SilentlyContinue

Set-Variable -Option Constant -Name OSRegistryKey -Value "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name OSTypePropertyName -Value "InstallationType" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name OSVersion -Value [Environment]::OSVersion.Version -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpSystemRegistryKey -Value "HKLM:\\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpGroupPolicyProperty -Value "fDenyTSConnections" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpNlaGroupPolicyProperty -Value "UserAuthentication" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpGroupPolicyRegistryKey -Value "HKLM:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpListenerRegistryKey -Value "$RdpSystemRegistryKey\WinStations" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpProtocolTypeUM -Value "{5828227c-20cf-4408-b73f-73ab70b8849f}" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpProtocolTypeKM -Value "{18b726bb-6fe6-4fb9-9276-ed57ce7c7cb2}" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpWdfSubDesktop -Value 0x00008000 -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RdpFirewallGroup -Value "@FirewallAPI.dll,-28752" -ErrorAction SilentlyContinue
Set-Variable -Option Constant -Name RemoteAppRegistryKey -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList" -ErrorAction SilentlyContinue

<#
.SYNOPSIS
Gets the Remote Desktop Network Level Authentication settings of the current machine.

.DESCRIPTION
Gets the Remote Desktop Network Level Authentication settings of the system.

.ROLE
Readers
#>
function Get-RdpNlaGroupPolicySettings {
    $nlaGroupPolicySettings = @{}
    $nlaGroupPolicySettings.GroupPolicyIsSet = $false
    $nlaGroupPolicySettings.GroupPolicyIsEnabled = $false
    $registryKey = Get-ItemProperty -Path $RdpGroupPolicyRegistryKey -ErrorAction SilentlyContinue
    if (!!$registryKey) {
        if ((Get-Member -InputObject $registryKey -name $RdpNlaGroupPolicyProperty -MemberType Properties) -and ($null -ne $registryKey.$RdpNlaGroupPolicyProperty)) {
            $nlaGroupPolicySettings.GroupPolicyIsSet = $true
            $nlaGroupPolicySettings.GroupPolicyIsEnabled = $registryKey.$RdpNlaGroupPolicyProperty -eq 1
        }
    }

    return $nlaGroupPolicySettings
}

<#
.SYNOPSIS
Gets the Remote Desktop settings of the system related to Group Policy.

.DESCRIPTION
Gets the Remote Desktop settings of the system related to Group Policy.

.ROLE
Readers
#>
function Get-RdpGroupPolicySettings {
    $rdpGroupPolicySettings = @{}
    $rdpGroupPolicySettings.GroupPolicyIsSet = $false
    $rdpGroupPolicySettings.GroupPolicyIsEnabled = $false
    $registryKey = Get-ItemProperty -Path $RdpGroupPolicyRegistryKey -ErrorAction SilentlyContinue
    if (!!$registryKey) {
        if ((Get-Member -InputObject $registryKey -name $RdpGroupPolicyProperty -MemberType Properties) -and ($null -ne $registryKey.$RdpGroupPolicyProperty)) {
            $rdpGroupPolicySettings.groupPolicyIsSet = $true
            $rdpGroupPolicySettings.groupPolicyIsEnabled = $registryKey.$RdpGroupPolicyProperty -eq 0
        }
    }

    return $rdpGroupPolicySettings
}

<#
.SYNOPSIS
Gets all of the valid Remote Desktop Protocol listeners.

.DESCRIPTION
Gets all of the valid Remote Desktop Protocol listeners.

.ROLE
Readers
#>
function Get-RdpListener {
    $listeners = @()
    Get-ChildItem -Name $RdpListenerRegistryKey | Where-Object { $_.PSChildName.ToLower() -ne "console" } | ForEach-Object {
        $registryKeyValues = Get-ItemProperty -Path "$RdpListenerRegistryKey\$_" -ErrorAction SilentlyContinue
        if ($null -ne $registryKeyValues) {
            $protocol = $registryKeyValues.LoadableProtocol_Object
            $isProtocolRDP = ($null -ne $protocol) -and ($protocol -eq $RdpProtocolTypeUM -or $protocol -eq $RdpProtocolTypeKM)

            $wdFlag = $registryKeyValues.WdFlag
            $isSubDesktop = ($null -ne $wdFlag) -and ($wdFlag -band $RdpWdfSubDesktop)

            $isRDPListener = $isProtocolRDP -and !$isSubDesktop
            if ($isRDPListener) {
                $listeners += $registryKeyValues
            }
        }
    }

    return ,$listeners
}

<#
.SYNOPSIS
Gets the number of the ports that the Remote Desktop Protocol is operating over.

.DESCRIPTION
Gets the number of the ports that the Remote Desktop Protocol is operating over.

.ROLE
Readers
#>
function Get-RdpPortNumber {
    $portNumbers = @()
    Get-RdpListener | Where-Object { $null -ne $_.PortNumber } | ForEach-Object { $portNumbers += $_.PortNumber }
    return ,$portNumbers
}

<#
.SYNOPSIS
Gets the Remote Desktop settings of the system.

.DESCRIPTION
Gets the Remote Desktop settings of the system.

.ROLE
Readers
#>
function Get-RdpSettings {
    $remoteDesktopSettings = New-Object -TypeName PSObject
    $rdpEnabledSource = $null
    $rdpIsEnabled = Test-RdpEnabled
    $rdpRequiresNla = Test-RdpUserAuthentication
    $remoteAppAllowed = Test-RemoteApp
    $rdpPortNumbers = Get-RdpPortNumber
    if ($rdpIsEnabled) {
        $rdpGroupPolicySettings = Get-RdpGroupPolicySettings
        if ($rdpGroupPolicySettings.groupPolicyIsEnabled) {
            $rdpEnabledSource = "GroupPolicy"
        } else {
            $rdpEnabledSource = "System"
        }
    }
    $operatingSystemType = Get-OperatingSystemType
    $desktopFeatureAvailable = Test-DesktopFeature($operatingSystemType)
    $versionIsSupported = Test-OSVersion($operatingSystemType)

    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "IsEnabled" -Value $rdpIsEnabled
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "RequiresNLA" -Value $rdpRequiresNla
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "Ports" -Value $rdpPortNumbers
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "EnabledSource" -Value $rdpEnabledSource
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "RemoteAppAllowed" -Value $remoteAppAllowed
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "DesktopFeatureAvailable" -Value $desktopFeatureAvailable
    $remoteDesktopSettings | Add-Member -MemberType NoteProperty -Name "VersionIsSupported" -Value $versionIsSupported

    return $remoteDesktopSettings
}

<#
.SYNOPSIS
Tests whether Remote Desktop Protocol is enabled.

.DESCRIPTION
Tests whether Remote Desktop Protocol is enabled.

.ROLE
Readers
#>
function Test-RdpEnabled {
    $rdpEnabledWithGP = $false
    $rdpEnabledLocally = $false
    $rdpGroupPolicySettings = Get-RdpGroupPolicySettings
    $rdpEnabledWithGP = $rdpGroupPolicySettings.GroupPolicyIsSet -and $rdpGroupPolicySettings.GroupPolicyIsEnabled
    $rdpEnabledLocally = !($rdpGroupPolicySettings.GroupPolicyIsSet) -and (Test-RdpSystem)

    return (Test-RdpListener) -and (Test-RdpFirewall) -and ($rdpEnabledWithGP -or $rdpEnabledLocally)
}

<#
.SYNOPSIS
Tests whether the Remote Desktop Firewall rules are enabled.

.DESCRIPTION
Tests whether the Remote Desktop Firewall rules are enabled.

.ROLE
Readers
#>
function Test-RdpFirewall {
    $firewallRulesEnabled = $true
    Get-NetFirewallRule -Group $RdpFirewallGroup | Where-Object { $_.Profile -match "Domain" } | ForEach-Object {
        if ($_.Enabled -eq "False") {
            $firewallRulesEnabled = $false
        }
    }

    return $firewallRulesEnabled
}

<#
.SYNOPSIS
Tests whether or not a Remote Desktop Protocol listener exists.

.DESCRIPTION
Tests whether or not a Remote Desktop Protocol listener exists.

.ROLE
Readers
#>
function Test-RdpListener {
    $listeners = Get-RdpListener
    return ($listeners | Microsoft.PowerShell.Utility\Measure-Object).Count -gt 0
}

<#
.SYNOPSIS
Tests whether Remote Desktop Protocol is enabled via local system settings.

.DESCRIPTION
Tests whether Remote Desktop Protocol is enabled via local system settings.

.ROLE
Readers
#>
function Test-RdpSystem {
    $registryKey = Get-ItemProperty -Path $RdpSystemRegistryKey -ErrorAction SilentlyContinue

    if ($registryKey) {
        return $registryKey.fDenyTSConnections -eq 0
    } else {
        return $false
    }
}

<#
.SYNOPSIS
Tests whether Remote Desktop connections require Network Level Authentication while enabled via local system settings.

.DESCRIPTION
Tests whether Remote Desktop connections require Network Level Authentication while enabled via local system settings.

.ROLE
Readers
#>
function Test-RdpSystemUserAuthentication {
    $listener = Get-RdpListener | Where-Object { $null -ne $_.UserAuthentication } | Microsoft.PowerShell.Utility\Select-Object -First 1

    if ($listener) {
        return $listener.UserAuthentication -eq 1
    } else {
        return $false
    }
}

<#
.SYNOPSIS
Tests whether Remote Desktop connections require Network Level Authentication.

.DESCRIPTION
Tests whether Remote Desktop connections require Network Level Authentication.

.ROLE
Readers
#>
function Test-RdpUserAuthentication {
    $nlaEnabledWithGP = $false
    $nlaEnabledLocally = $false
    $nlaGroupPolicySettings = Get-RdpNlaGroupPolicySettings
    $nlaEnabledWithGP = $nlaGroupPolicySettings.GroupPolicyIsSet -and $nlaGroupPolicySettings.GroupPolicyIsEnabled
    $nlaEnabledLocally = !($nlaGroupPolicySettings.GroupPolicyIsSet) -and (Test-RdpSystemUserAuthentication)

    return $nlaEnabledWithGP -or $nlaEnabledLocally
}

<#
.SYNOPSIS
Tests whether Remote App connections are allowed.

.DESCRIPTION
Tests whether Remote App connections are allowed.

.ROLE
Readers
#>
function Test-RemoteApp {
  $registryKey = Get-ItemProperty -Path $RemoteAppRegistryKey -Name fDisabledAllowList -ErrorAction SilentlyContinue
  if ($registryKey)
  {
      $remoteAppEnabled = $registryKey.fDisabledAllowList
      return $remoteAppEnabled -eq 1
  } else {
      return $false;
  }
}

<#
.SYNOPSIS
Gets the Windows OS installation type.

.DESCRIPTION
Gets the Windows OS installation type.

.ROLE
Readers
#>
function Get-OperatingSystemType {
    $osResult = Get-ItemProperty -Path $OSRegistryKey -Name $OSTypePropertyName -ErrorAction SilentlyContinue

    if ($osResult -and $osResult.$OSTypePropertyName) {
        return $osResult.$OSTypePropertyName
    } else {
        return $null
    }
}

<#
.SYNOPSIS
Tests the availability of desktop features based on the system's OS type.

.DESCRIPTION
Tests the availability of desktop features based on the system's OS type.

.ROLE
Readers
#>
function Test-DesktopFeature ([string] $osType) {
    $featureAvailable = $false

    switch ($osType) {
        'Client' {
            $featureAvailable = $true
        }
        'Server' {
            $DesktopFeature = Get-DesktopFeature
            if ($DesktopFeature) {
                $featureAvailable = $DesktopFeature.Installed
            }
        }
    }

    return $featureAvailable
}

<#
.SYNOPSIS
Checks for feature cmdlet availability and returns the installation state of the Desktop Experience feature.

.DESCRIPTION
Checks for feature cmdlet availability and returns the installation state of the Desktop Experience feature.

.ROLE
Readers
#>
function Get-DesktopFeature {
    $moduleAvailable = Get-Module -ListAvailable -Name ServerManager -ErrorAction SilentlyContinue
    if ($moduleAvailable) {
        return Get-WindowsFeature -Name Desktop-Experience -ErrorAction SilentlyContinue
    } else {
        return $null
    }
}

<#
.SYNOPSIS
Tests whether the current OS type/version is supported for Remote App.

.DESCRIPTION
Tests whether the current OS type/version is supported for Remote App.

.ROLE
Readers
#>
function Test-OSVersion ([string] $osType) {
    switch ($osType) {
        'Client' {
            return (Get-OSVersion) -ge (new-object 'Version' 6,2)
        }
        'Server' {
            return (Get-OSVersion) -ge (new-object 'Version' 6,3)
        }
        default {
            return $false
        }
    }
}

<#
.SYNOPSIS
Retrieves the system version information from the system's environment variables.

.DESCRIPTION
Retrieves the system version information from the system's environment variables.

.ROLE
Readers
#>
function Get-OSVersion {
    return [Environment]::OSVersion.Version
}

#########
# Main
#########

$module = Get-Module -Name NetSecurity -ErrorAction SilentlyContinue

if ($module) {
    Get-RdpSettings
}
}
## [END] Get-WACSDDCRemoteDesktop ##
function Get-WACSDDCRunDetails {
<#

.SYNOPSIS
Gets currently running cluster update details.

.DESCRIPTION
Gets currently running cluster update details.

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-RunDetails.ps1"

$run = @(Get-CauRun -ClusterName $clusterName -ErrorAction SilentlyContinue -ErrorVariable err)

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting the Cluster Aware Updates Run details.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}
else {
    $runState = $run[0]
    $runDetails = @{}
    $runDetails.Add("RunState", $runState)

    if ($run.length -gt 1) {
        $runDetails.Add("CancelPending", $run[1].CancelPending)
        $runDetails.Add("RunId", $run[1].RunId)
        $runDetails.Add("RunStartTime", $run[1].RunStartTime)
        $runDetails.Add("CurrentOrchestrator", $run[1].CurrentOrchestrator)
        $runDetails.Add("NodeResults", $run[1].NodeResults)

        # TODO: determine if we need this ConvertTo-Json | ConvertFrom-Json part frm legacy code
        $statusNotifications = $run[1].NodeStatusNotifications | ConvertTo-Json | ConvertFrom-Json
        $statusNotifications = @($statusNotifications)
        $nodeStatus = @()

        for ($notificationCount = 0; $notificationCount -lt $statusNotifications.length; $notificationCount++) {
            $statusNotification = $statusNotifications[$notificationCount];
            if ($statusNotification) {
                $statusObject = New-Object -TypeName PSObject
                $statusObject | Add-Member -MemberType NoteProperty -Name Node -Value $statusNotification.Node.NodeName
                # If we do not specifically parse this status data into a PSObject it is returned as a string
                # Most likely, -Value calls .getValue() on the data but returning the object directly returns the enum name like "Scanning"
                $statusObject | Add-Member -MemberType NoteProperty -Name Status -Value $statusNotification.Status
                $statusObject | Add-Member -MemberType NoteProperty -Name Timestamp -Value $statusNotification.Timestamp

                $nodeStatus += $statusObject
            }
        }

        $runDetails.Add("NodeStatusNotifications", $nodeStatus)

    }

    $runDetails
}

}
## [END] Get-WACSDDCRunDetails ##
function Get-WACSDDCSQLServerEndOfSupportVersion {
<#

.SYNOPSIS
Gets information about SQL Server installation on the server.

.DESCRIPTION
Gets information about SQL Server installation on the server.

.ROLE
Readers

#>

import-module CimCmdlets

$V2008 = [version]'10.0.0.0'
$V2008R2 = [version]'10.50.0.0'

Set-Variable -Name SQLRegistryRoot64Bit -Option ReadOnly -Value "HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server" -ErrorAction SilentlyContinue
Set-Variable -Name SQLRegistryRoot32Bit -Option ReadOnly -Value "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Microsoft SQL Server" -ErrorAction SilentlyContinue
Set-Variable -Name InstanceNamesSubKey -Option ReadOnly -Value "Instance Names"-ErrorAction SilentlyContinue
Set-Variable -Name SQLSubKey -Option ReadOnly -Value "SQL" -ErrorAction SilentlyContinue
Set-Variable -Name CurrentVersionSubKey -Option ReadOnly -Value "CurrentVersion" -ErrorAction SilentlyContinue
Set-Variable -Name Running -Option ReadOnly -Value "Running" -ErrorAction SilentlyContinue

function Get-KeyPropertiesAndValues($path) {
  Get-Item $path -ErrorAction SilentlyContinue |
  Microsoft.PowerShell.Utility\Select-Object -ExpandProperty property |
  ForEach-Object {
    New-Object psobject -Property @{"Property"=$_; "Value" = (Get-ItemProperty -Path $path -Name $_ -ErrorAction SilentlyContinue).$_}
  }
}

function IsEndofSupportVersion($SQLRegistryPath) {
  $result = $false
  if (Test-Path -Path $SQLRegistryPath) {
    # construct reg key path to lead up to instances.
    $InstanceNamesKeyPath = Join-Path $SQLRegistryPath -ChildPath $InstanceNamesSubKey | Join-Path -ChildPath $SQLSubKey

    if (Test-Path -Path $InstanceNamesKeyPath) {
      # get properties and their values
      $InstanceCollection = Get-KeyPropertiesAndValues($InstanceNamesKeyPath)
      if ($InstanceCollection) {
        foreach ($Instance in $InstanceCollection) {
          if (Get-Service | Where-Object { $_.Status -eq $Running } | Where-Object { $_.Name -eq $Instance.Property }) {
            $VersionPath = Join-Path $SQLRegistryPath -ChildPath $Instance.Value | Join-Path -ChildPath $Instance.Property | Join-Path -ChildPath $CurrentVersionSubKey
            if (Test-Path -Path $VersionPath) {
              $CurrentVersion = [version] (Get-ItemPropertyValue $VersionPath $CurrentVersionSubKey -ErrorAction SilentlyContinue)
              if ($CurrentVersion -ge $V2008 -and $CurrentVersion -le $V2008R2) {
                $result = $true
                break
              }
            }
          }
        }
      }
    }
  }

  return $result
}

$Result64Bit = IsEndofSupportVersion($SQLRegistryRoot64Bit)
$Result32Bit = IsEndofSupportVersion($SQLRegistryRoot32Bit)

return $Result64Bit -OR $Result32Bit

}
## [END] Get-WACSDDCSQLServerEndOfSupportVersion ##
function Get-WACSDDCServerConnectionStatus {
<#

.SYNOPSIS
Gets status of the connection to the server.

.DESCRIPTION
Gets status of the connection to the server.

.ROLE
Readers

#>

import-module CimCmdlets

$OperatingSystem = Get-CimInstance Win32_OperatingSystem
$Caption = $OperatingSystem.Caption
$ProductType = $OperatingSystem.ProductType
$Version = $OperatingSystem.Version
$Status = @{ Label = $null; Type = 0; Details = $null; }
$Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }
if ($Version -and ($ProductType -eq 2 -or $ProductType -eq 3)) {
    $V = [version]$Version
    $V2016 = [version]'10.0'
    $V2012 = [version]'6.2'
    $V2008r2 = [version]'6.1'

    if ($V -ge $V2016) {
        return $Result;
    }

    if ($V -ge $V2008r2) {
        $Key = 'HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine'
        $WmfStatus = $false;
        $Exists = Get-ItemProperty -Path $Key -Name PowerShellVersion -ErrorAction SilentlyContinue
        if (![String]::IsNullOrEmpty($Exists)) {
            $WmfVersionInstalled = $exists.PowerShellVersion
            if ($WmfVersionInstalled.StartsWith('5.')) {
                $WmfStatus = $true;
            }
        }

        if (!$WmfStatus) {
            $status.Label = 'wmfMissing-label'
            $status.Type = 3
            $status.Details = 'wmfMissing-details'
        }

        return $result;
    }
}

$status.Label = 'unsupported-label'
$status.Type = 3
$status.Details = 'unsupported-details'
return $result;

}
## [END] Get-WACSDDCServerConnectionStatus ##
function Get-WACSDDCShareEntities {
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
## [END] Get-WACSDDCShareEntities ##
function Get-WACSDDCSmb1InstallationStatus {
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
## [END] Get-WACSDDCSmb1InstallationStatus ##
function Get-WACSDDCSmbFileShareDetails {
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
## [END] Get-WACSDDCSmbFileShareDetails ##
function Get-WACSDDCSmbFileShareDetailsFC {
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

$shares = Get-SmbShare -includehidden | Where-Object {-not ($_.Name -eq "IPC$")} | Microsoft.PowerShell.Utility\Select-Object Name, Path, CachingMode, EncryptData, CurrentUsers, Special, LeasingMode, FolderEnumerationMode

$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($null -ne $computerSystem) {
    $uncPath = $computerSystem.DNSHostName + "." + $computerSystem.Domain
}

return @{
    shareNames = $shares.name;
    uncPath = $uncPath
}

}
## [END] Get-WACSDDCSmbFileShareDetailsFC ##
function Get-WACSDDCSmbOverQuicSettings {
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
## [END] Get-WACSDDCSmbOverQuicSettings ##
function Get-WACSDDCSmbServerCertificateHealth {
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
## [END] Get-WACSDDCSmbServerCertificateHealth ##
function Get-WACSDDCSmbServerCertificateMapping {
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
## [END] Get-WACSDDCSmbServerCertificateMapping ##
function Get-WACSDDCSmbServerCertificateValues {
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
## [END] Get-WACSDDCSmbServerCertificateValues ##
function Get-WACSDDCSmbServerSettings {

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
## [END] Get-WACSDDCSmbServerSettings ##
function Get-WACSDDCSmbShareAccess {
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
## [END] Get-WACSDDCSmbShareAccess ##
function Get-WACSDDCSmeClientAccessPointIsAvailable {
<#

.SYNOPSIS
Gets whether a proposed client access point is available.

.DESCRIPTION
Gets whether a proposed client access point is available.

.ROLE
Readers

.PARAMETER ClientAccessPoint
The client access point.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$ClientAccessPoint
)

Set-StrictMode -Version 5.0

Import-Module -Name DnsClient -ErrorAction SilentlyContinue

function Get-DnsEntryExists
{
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$ClientAccessPoint
    )

    $dnsEntry = Resolve-DnsName $ClientAccessPoint -ErrorAction SilentlyContinue
    if ($dnsEntry.Name) {
        $true
    } else {
        $false
    }
}

# Check for a DNS entry
$dnsEntryExists = Get-DnsEntryExists -ClientAccessPoint $ClientAccessPoint

# Evaluate against all criteria
$clientAccessPointIsAvailable = -not $dnsEntryExists

$clientAccessPointIsAvailable

}
## [END] Get-WACSDDCSmeClientAccessPointIsAvailable ##
function Get-WACSDDCSmeClusterDisk {
<#

.SYNOPSIS
Gets the disks of a failover cluster.

.DESCRIPTION
Gets the disks of a failover cluster.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name Storage -ErrorAction SilentlyContinue

$clusterDisks= @()
$clusterDiskResources = FailoverClusters\Get-ClusterResource | Where-Object { $_.IsStorageClassResource }

# Get the cluster resource disks first
foreach ($disk in $clusterDiskResources) {
    $diskIdGuid = ($disk | FailoverClusters\Get-ClusterParameter | Where-Object { $_.Name -eq "DiskIdGuid" }).Value
    $diskSignature = ($disk | FailoverClusters\Get-ClusterParameter | Where-Object { $_.Name -eq "DiskSignature" }).Value
    $diskSignature = if ($diskSignature -match '^0x[0-9A-Fa-f]+$') { [Convert]::ToUInt32($diskSignature, 16) } else { $diskSignature }

    Add-Member -InputObject $disk -MemberType NoteProperty -Name "DiskIdGuid" -Value $diskIdGuid
    Add-Member -InputObject $disk -MemberType NoteProperty -Name "DiskSignature" -Value $diskSignature -Force
    Add-Member -InputObject $disk -MemberType NoteProperty -Name "IsClusterSharedVolume" -Value $false

    $clusterDisks += $disk | Microsoft.PowerShell.Utility\Select-Object Name,
                                                                        State,
                                                                        OwnerGroup,
                                                                        OwnerNode,
                                                                        DiskNumber,
                                                                        PartitionStyle,
                                                                        Capacity,
                                                                        DiskIdGuid,
                                                                        DiskSignature,
                                                                        IsClusterSharedVolume,
                                                                        @{Name="ResourceId"; Expression={$_.Id}},
                                                                        UniqueId
}

# Get the cluster shared volumes and the properties from the registry
$sharedVolumes = FailoverClusters\Get-ClusterSharedVolume
foreach ($disk in $sharedVolumes) {
    $regPath = "HKLM:\Cluster\Resources\$($disk.Id)"
    $sharedVolumeProperties = Get-ChildItem -Path $regPath | Get-ItemProperty
    $diskSignature = if ($sharedVolumeProperties.DiskSignature -match '^0x[0-9A-Fa-f]+$') { [Convert]::ToUInt32($sharedVolumeProperties.DiskSignature, 16) } else { $sharedVolumeProperties.DiskSignature }

    Add-Member -InputObject $disk -MemberType NoteProperty -Name "DiskIdGuid" -Value $sharedVolumeProperties.DiskIdGuid
    Add-Member -InputObject $disk -MemberType NoteProperty -Name "DiskSignature" -Value $diskSignature -Force
    Add-Member -InputObject $disk -MemberType NoteProperty -Name "IsClusterSharedVolume" -Value $true

    $clusterDisks += $disk | Microsoft.PowerShell.Utility\Select-Object Name,
                                                                        State,
                                                                        OwnerGroup,
                                                                        OwnerNode,
                                                                        DiskNumber,
                                                                        PartitionStyle,
                                                                        Capacity,
                                                                        DiskIdGuid,
                                                                        DiskSignature,
                                                                        IsClusterSharedVolume,
                                                                        @{Name="ResourceId"; Expression={$_.Id}},
                                                                        UniqueId
}

# Remove-Module Storage -ErrorAction Ignore
$localDisks = Get-Disk

foreach ($clusterDisk in $clusterDisks) {
    foreach ($localDisk in $localDisks) {
        if ($null -eq $clusterDisk.DiskIdGuid -or $clusterDisk.DiskIdGuid -eq '') {
            if ($clusterDisk.DiskSignature -eq $localDisk.Signature) {
                $clusterDisk.Capacity = $localDisk.Size
                $clusterDisk.DiskNumber = $localDisk.Number
                $clusterDisk.PartitionStyle = $localDisk.psBase.CimInstanceProperties["PartitionStyle"].Value
                $clusterDisk.UniqueId = $localDisk.uniqueId

                break
            }
        } else {
            if ($clusterDisk.DiskIdGuid -eq $localDisk.Guid) {
                $clusterDisk.Capacity = $localDisk.Size
                $clusterDisk.DiskNumber = $localDisk.Number
                $clusterDisk.PartitionStyle = $localDisk.psBase.CimInstanceProperties["PartitionStyle"].Value
                $clusterDisk.UniqueId = $localDisk.uniqueId

                break
            }
        }
    }
}

$clusterDisks

}
## [END] Get-WACSDDCSmeClusterDisk ##
function Get-WACSDDCSmeClusterDiskVolume {
<#

.SYNOPSIS
Gets the volumes of a failover cluster disk.

.DESCRIPTION
Gets the volumes of a failover cluster disk.

.ROLE
Readers

.PARAMETER UniqueId
The unique identifier of the cluster disk to get the volumes of.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$UniqueId
)

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module -Name Storage -ErrorAction SilentlyContinue

    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-SmeClusterDiskVolume" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
}
PROCESS {

    # NOTE: This script should only be temporary in the Failover Cluster project.
    #       The long term goal is to have the Failover Cluster project consume a cluster-aware
    #       component from the Storage project.

    function Get-VolumeName {
        param(
            [Parameter(Mandatory = $true)]
            $Volume
        )

        if (-not($null -eq $Volume.FileSystemLabel) -and -not($null -eq $Volume.DriveLetter -or $Volume.DriveLetter.ToString() -eq '')) {
            $Volume.FileSystemLabel + "(" + $Volume.DriveLetter + ")"
        } elseif (-not($null -eq $Volume.FileSystemLabel) -and ($null -eq $Volume.DriveLetter -or $Volume.DriveLetter.ToString() -eq '')) {
            $Volume.FileSystemLabel
        } elseif (($null -eq $Volume.FileSystemLabel) -and -not($null -eq $Volume.DriveLetter -or $Volume.DriveLetter.ToString() -eq '')) {
            "(" + $Volume.DriveLetter + ")"
        } else {
            $Volume.Path
        }
    }

    function main {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.String]$UniqueId
        )

        $disk = Get-Disk -UniqueId $UniqueId -ErrorAction SilentlyContinue -ErrorVariable +err
        if (!!$err) {
            $message = @($err)[0]

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: There was an error getting the disk with uniqueId $uniqueId. Error: $message" -ErrorAction SilentlyContinue

            Write-Error $message -ErrorAction Stop

            return
        }

        if (!!$disk) {
            $partitions = $disk | Get-Partition -ErrorAction SilentlyContinue -ErrorVariable +err
            if (!!$err) {
                $message = @($err)[0]

                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]: There was an error getting the disk partition for disk with uniqueId $uniqueId. Error: $message" -ErrorAction SilentlyContinue

                Write-Error $message -ErrorAction Stop

                return
            }

            if (!!$partitions) {
               $diskVolumes = $partitions | Get-Volume -ErrorAction SilentlyContinue -ErrorVariable +err
                if (!!$err) {
                    $message = @($err)[0]

                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: There was an error getting the volumes for disk with uniqueId $uniqueId. Error: $message" -ErrorAction SilentlyContinue

                    Write-Error $message -ErrorAction Stop

                    return
                }

                if (!!$diskVolumes) {
                    $volumes = $diskVolumes | Microsoft.PowerShell.Utility\Select-Object `
                    @{Name = "Name"; Expression = { Get-VolumeName -Volume $_ }},
                    @{Name = "OperationalStatus"; Expression = { $_.psBase.CimInstanceProperties["OperationalStatus"].Value }},
                    @{Name = "HealthStatus"; Expression = { $_.psBase.CimInstanceProperties["HealthStatus"].Value }},
                    @{Name = "DriveType"; Expression = { $_.psBase.CimInstanceProperties["DriveType"].Value }},
                    @{Name = "FileSystemType"; Expression = { $_.psBase.CimInstanceProperties["FileSystemType"].Value }},
                    @{Name = "DedupMode"; Expression = { $_.psBase.CimInstanceProperties["DedupMode"].Value}},
                    UniqueId,
                    AllocationUnitSize,
                    DriveLetter,
                    FileSystem,
                    FileSystemLabel,
                    Path,
                    Size,
                    SizeRemaining
                }

                $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10
                if ($isDownlevel) {
                    $healthStatusMap = @{
                        0 = 0
                        1 = 1
                        2 = 2
                        3 = 2
                    }

                    $volumes | ForEach-Object { $_.HealthStatus = $healthStatusMap[[int32]$_.HealthStatus] }
                }

                $volumes
            }
        }
    }

    ###########################################################################
    # Script execution starts here
    ###########################################################################

    main $UniqueId
}
END {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
}
}
## [END] Get-WACSDDCSmeClusterDiskVolume ##
function Get-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Gets the group(s) of a failover cluster.

.DESCRIPTION
Gets the group(s) of a failover cluster.

.ROLE
Readers

.PARAMETER GroupId
The unique identifier of the request cluster group, or empty (null) to request all groups.

#>
param (
    [Parameter(Mandatory = $false)]
    [string]$groupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
ClusterGroupType

.DESCRIPTION
This enum is the cluster group type as defined in cluapi.h.

#>

enum ClusterGroupType {
    ClusterGroup = 1
    AvailableStorage = 2
    ClusterStoragePool = 5
    FileServer = 100
    PrintServer = 101
    DHCPServer = 102
    DTC = 103
    MessageQueuing = 104
    WINSServer = 105
    DFSNamespaceServer = 106
    GenericApplication = 107
    GenericService = 108
    GenericScript = 109
    ISnsClusterResource = 110
    VirtualMachine = 111
    TSSessionBroker = 112
    IScsiTargetServer = 113
    ScaleOutFileServer = 114
    HyperVReplicaBroker = 115
    TaskScheduler = 116
    Unknown = 9999
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-SmeClusterGroup" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name VmIdPropertyName -Option ReadOnly -Value "VmId" -Scope Script
    Set-Variable -Name OwnerNodePropertyName -Option ReadOnly -Value "OwnerNode" -Scope Script
    Set-Variable -Name OwnerNodeFqdnPropertyName -Option ReadOnly -Value "OwnerNodeFqdn" -Scope Script
    Set-Variable -Name VirtualMachineResourceTypeName -Option ReadOnly -Value "Virtual Machine" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name VmIdPropertyName -Scope Script -Force
    Remove-Variable -Name OwnerNodePropertyName -Scope Script -Force
    Remove-Variable -Name OwnerNodeFqdnPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachineResourceTypeName -Scope Script -Force
}

<#

.SYNOPSIS
Get te VmId of the first virtual machine in the group.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER clusterGroup
The group

#>

function getVmId($clusterGroup) {
    if ($clusterGroup.GroupType -eq [ClusterGroupType]::VirtualMachine) {
        $resource = $clusterGroup | Get-ClusterResource -ErrorAction SilentlyContinue | Where-Object { $_.ResourceType.Name -eq $VirtualMachineResourceTypeName }

        if ($resource) {
            $vmId = $resource | Get-ClusterParameter | Where-Object { $_.Name -eq $VmIdPropertyName }

            if ($vmId) {
                return $vmId.Value
            } else {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                -Message "[$ScriptName]: Could not find the vmId of the Virtual Machine resoure is clustered virtul macnine role $ClusterGroup.Name"  -ErrorAction SilentlyContinue
            }
        } else {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not find a Virtual Machine resource in the clustered virtual machine role $clusterGroup.Name"  -ErrorAction SilentlyContinue
        }
    }

    return $null;
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER groupId
The group Id of the requested cluster group, or empty to request all groups.

#>

function main([string] $groupId) {
    $err = $null

    if ($groupId) {
        $result = Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err
    } else {
        $result = Get-ClusterGroup -ErrorAction SilentlyContinue -ErrorVariable +err  | `
        Where-Object { $_.GroupType -ne [ClusterGroupType]::ClusterStoragePool -and $_.GroupType -ne [ClusterGroupType]::AvailableStorage}
    }

    if (-not ($err)) {
        return @($result | Microsoft.PowerShell.Utility\Select-Object `
            Name, `
            Id, `
            State, `
            GroupType, `
            $OwnerNodePropertyName, `
            @{ Name = $OwnerNodeFqdnPropertyName; Expression = { [System.Net.Dns]::GetHostEntry($_.$OwnerNodePropertyName).HostName } }, `
            Priority, `
            @{ Name = $VmIdPropertyName; Expression = { getVmId $_ } })
        }

    $e = @($err)[0]

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
    -Message "[$ScriptName]: Failed to get cluster groups. The error is: $e." -ErrorAction SilentlyContinue

    Write-Error $e

    return @()
}

###############################################################################
# Script execution starts here...
###############################################################################

setupScriptEnv

if (-not ($env:pester)) {
    $retValue = @()

    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        $retValue = main $groupId
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue
    }

    cleanupScriptEnv

    return $retValue
}
}
## [END] Get-WACSDDCSmeClusterGroup ##
function Get-WACSDDCSmeClusterGroupFailoverSettings {
<#

.SYNOPSIS
Gets the failover settings of a group in a failover cluster.

.DESCRIPTION
Gets the failover settings of a group in a failover cluster.

.ROLE
Readers

.PARAMETER GroupId
The unique identifier of the cluster group.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$GroupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

$group = FailoverClusters\Get-ClusterGroup -Name $GroupId

$settings = New-Object psobject
Add-Member -InputObject $settings -MemberType NoteProperty -Name Id -Value $group.Id
Add-Member -InputObject $settings -MemberType NoteProperty -Name FailoverPeriod -Value $group.FailoverPeriod
Add-Member -InputObject $settings -MemberType NoteProperty -Name AutoFailbackType -Value $group.AutoFailbackType
Add-Member -InputObject $settings -MemberType NoteProperty -Name FailoverThreshold -Value $group.FailoverThreshold
Add-Member -InputObject $settings -MemberType NoteProperty -Name FailbackWindowEnd -Value $group.FailbackWindowEnd
Add-Member -InputObject $settings -MemberType NoteProperty -Name FailbackWindowStart -Value $group.FailbackWindowStart

$settings

}
## [END] Get-WACSDDCSmeClusterGroupFailoverSettings ##
function Get-WACSDDCSmeClusterGroupGeneralSettings {
<#

.SYNOPSIS
Gets the general settings of a group in a failover cluster.

.DESCRIPTION
Gets the general settings of a group in a failover cluster.

.ROLE
Readers

.PARAMETER GroupId
The unique identifier of the cluster group.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$GroupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

$group = FailoverClusters\Get-ClusterGroup $GroupId
$ownerNodeList = $group | FailoverClusters\Get-ClusterOwnerNode
$ownerNodes = $ownerNodeList.OwnerNodes

$settings = New-Object psobject
Add-Member -InputObject $settings -MemberType NoteProperty -Name Id -Value $group.Id
Add-Member -InputObject $settings -MemberType NoteProperty -Name Name -Value $group.Name
Add-Member -InputObject $settings -MemberType NoteProperty -Name PreferredOwners -Value $ownerNodes
Add-Member -InputObject $settings -MemberType NoteProperty -Name Priority -Value $group.Priority

# Excluding these attributes for the time being
# They aren't used in the general settings page, they're only labels
# Pending discussion we can bring them back
#
# Add-Member -InputObject $settings -MemberType NoteProperty -Name State -Value $group.State;
# Add-Member -InputObject $settings -MemberType NoteProperty -Name OwnerNode -Value $group.OwnerNode;

$settings

}
## [END] Get-WACSDDCSmeClusterGroupGeneralSettings ##
function Get-WACSDDCSmeClusterNetwork {
<#

.SYNOPSIS
Gets the networks in a failover cluster.

.DESCRIPTION
Gets the networks in a failover cluster.

.ROLE
Readers

.PARAMETER networkId
The unique identifier of the request cluster network, or empty (null) to request all networks.

#>
param (
    [Parameter(Mandatory = $false)]
    [string]$networkId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value $MyInvocation.ScriptName -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER networkId
The unique identifier of the request cluster network, or empty (null) to request all networks.

#>

function main([string]$networkId) {
    if ($networkId) {
        $result = FailoverClusters\Get-ClusterNetwork -Name $networkId
    } else {
        $result = FailoverClusters\Get-ClusterNetwork
    }

    return @($result | Microsoft.PowerShell.Utility\Select-Object Name, State, Role, Id)
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        return main $networkId
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

    return @()
}

}
## [END] Get-WACSDDCSmeClusterNetwork ##
function Get-WACSDDCSmeClusterNetworkInterface {
<#

.SYNOPSIS
Gets the network interfaces of a cluster network.

.DESCRIPTION
Gets the network interfaces of a cluster network.

.ROLE
Readers

.PARAMETER networkId
The Id of the cluster network to get the interfaces of.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$networkId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value $MyInvocation.ScriptName -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER networkId
The unique identifier of the request cluster network, or empty (null) to request all networks.

#>

function main([string]$networkId) {
    $result = Get-ClusterNetwork -Name $networkId | Get-ClusterNetworkInterface

    return @($result | Microsoft.PowerShell.Utility\Select-Object `
        Adapter, `
        AdapterId, `
        Address, `
        Description, `
        DhcpEnabled, `
        Id, `
        Ipv4Addresses, `
        Ipv6Addresses, `
        Name, `
        Network, `
        Node, `
        State
    )
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        return main $networkId
    }

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

    return @()
}

}
## [END] Get-WACSDDCSmeClusterNetworkInterface ##
function Get-WACSDDCSmeClusterNode {
<#

.SYNOPSIS
Gets the nodes of a cluster.

.DESCRIPTION
Gets the nodes of a cluster.

.ROLE
Readers

.PARAMETER NodeName
The name of the node.

#>
Param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [System.String]$NodeName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

if ($NodeName) {
    $result = FailoverClusters\Get-ClusterNode -Name $NodeName
} else {
    $result = FailoverClusters\Get-ClusterNode
}

$isDownlevel = [Environment]::OSVersion.Version.Major -lt 10
$result | ForEach-Object {
    $_ | Microsoft.PowerShell.Utility\Select-Object BuildNumber,
    Cluster,
    CSDVersion,
    Description,
    @{Name = "DrainStatus"; Expression = { $_.DrainStatus.value__ }},
    DrainTarget,
    DynamicWeight,
    Id,
    MajorVersion,
    MinorVersion,
    Name,
    NeedsPreventQuorum,
    NodeHighestVersion,
    NodeInstanceId,
    NodeLowestVersion,
    NodeName,
    NodeWeight,
    @{Name = "FaultDomain"; Expression = { if (-Not $isDownlevel) { $_.FaultDomain } else { $null }}},
    Model,
    Manufacturer,
    SerialNumber,
    @{Name = "State"; Expression = { $_.State.value__ }},
    @{Name = "StatusInformation"; Expression = { if (-Not $isDownlevel) { $_.StatusInformation.value__ } else { -2147483648 }}},
    @{Name = "FQDN"; Expression = { [System.Net.Dns]::GetHostEntry($_.Name).HostName }}
}

}
## [END] Get-WACSDDCSmeClusterNode ##
function Get-WACSDDCSmeClusterNodeFQDN {
<#

.SYNOPSIS
Get the fully qualified DNS name of a failover cluster node.

.DESCRIPTION
Get the fully qualified DNS name of a failover cluster node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName

}
## [END] Get-WACSDDCSmeClusterNodeFQDN ##
function Get-WACSDDCSmeClusterProperties {
<#

.SYNOPSIS
Gets the cluster properties.

.DESCRIPTION
Gets the cluster properties.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
ClusterGroupType

.DESCRIPTION
This enum is the cluster group type as defined in cluapi.h.

#>

enum ClusterGroupType {
    ClusterGroup = 1
    AvailableStorage = 2
    ClusterStoragePool = 5
    FileServer = 100
    PrintServer = 101
    DHCPServer = 102
    DTC = 103
    MessageQueuing = 104
    WINSServer = 105
    DFSNamespaceServer = 106
    GenericApplication = 107
    GenericService = 108
    GenericScript = 109
    ISnsClusterResource = 110
    VirtualMachine = 111
    TSSessionBroker = 112
    IScsiTargetServer = 113
    ScaleOutFileServer = 114
    HyperVReplicaBroker = 115
    TaskScheduler = 116
    Unknown = 9999
}

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-SmeClusterProperties" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name OwnerNodePropertyName -Option ReadOnly -Value "OwnerNode" -Scope Script
    Set-Variable -Name FqdnPropertyName -Option ReadOnly -Value "Fqdn" -Scope Script
    Set-Variable -Name NamePropertyName -Option ReadOnly -Value "Name" -Scope Script
    Set-Variable -Name CurrentHostServerPropertyName -Option ReadOnly -Value "CurrentHostServer" -Scope Script
    Set-Variable -Name NodeCountPropertyName -Option ReadOnly -Value "NodeCount" -Scope Script
    Set-Variable -Name RoleCountPropertyName -Option ReadOnly -Value "RoleCount" -Scope Script
    Set-Variable -Name NetworkCountPropertyName -Option ReadOnly -Value "NetworkCount" -Scope Script
    Set-Variable -Name DiskCountPropertyName -Option ReadOnly -Value "DiskCount" -Scope Script
    Set-Variable -Name WitnessPropertyName -Option ReadOnly -Value "Witness" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name OwnerNodePropertyName -Scope Script -Force
    Remove-Variable -Name FqdnPropertyName -Scope Script -Force
    Remove-Variable -Name NamePropertyName -Scope Script -Force
    Remove-Variable -Name CurrentHostServerPropertyName -Scope Script -Force
    Remove-Variable -Name NodeCountPropertyName -Scope Script -Force
    Remove-Variable -Name RoleCountPropertyName -Scope Script -Force
    Remove-Variable -Name NetworkCountPropertyName -Scope Script -Force
    Remove-Variable -Name DiskCountPropertyName -Scope Script -Force
    Remove-Variable -Name WitnessPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
Get the FQDN of the passed in NetBIOS name.

.DESCRIPTION
Get the FQDN of the passed in NetBIOS name.

#>

function getFqdn([string] $netBIOSName) {
    try {
        return [System.Net.Dns]::GetHostEntry($netBIOSName).HostName
    } catch {
        $errMessage = $_.Exception.Message

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was as error getting the DNS host entry for $netBIOSName. Error: $errMessage"  -ErrorAction SilentlyContinue

        return $null
    }
}

<#

.SYNOPSIS
Get the owner node of the core cluster group.

.DESCRIPTION
Get the owner node of the core cluster group.

#>

function getCoreClusterGroupOwner() {
    $clusterGroup = Get-ClusterGroup -ErrorAction SilentlyContinue -ErrorVariable +err | Where-Object { $_.GroupType -eq [ClusterGroupType]::ClusterGroup }

    if (-not ($clusterGroup)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: Could not find the core cluster group. Error: $err"  -ErrorAction SilentlyContinue
    }

    return getFqdn $clusterGroup.$OwnerNodePropertyName.Name
}

<#

.SYNOPSIS
Get the role count.

.DESCRIPTION
Get the role count.  Filter out the core cluster group, the available storage group and all
storage pool groups.

#>

function getRoleCount() {
    $groups = @(Get-ClusterGroup -ErrorAction SilentlyContinue -ErrorVariable +err | `
        Where-Object { $_.GroupType -ne [ClusterGroupType]::ClusterGroup -and `
                       $_.GroupType -ne [ClusterGroupType]::AvailableStorage -and `
                       $_.GroupType -ne [ClusterGroupType]::ClusterStoragePool })

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: There was as error getting the cluster groups. Error: $err"  -ErrorAction SilentlyContinue
    }

    return $groups.Length
}

<#

.SYNOPSIS
Get the count of disks (storage class) resources.

.DESCRIPTION
Get the count of disks (storage class) resources.

#>

function getDiskCount() {
    $storageClassResources = @(Get-ClusterResource -ErrorAction SilentlyContinue -ErrorVariable +err | Where-Object { $_.IsStorageClassResource -eq $true })

    if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: There was as error getting the storage class resources. Error: $err"  -ErrorAction SilentlyContinue
    }

    return $storageClassResources.Length
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

    if (-not ($cluster) -and $err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was as error getting the cluster object. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]

        return @{}
    }

    $name = $cluster.Name
    $fqdn = getFqdn($name)

    $witness = $null

    $quorum = Get-ClusterQuorum -ErrorAction SilentlyContinue -ErrorVariable +err
    if (-not ($quorum) -and $err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: There was as error getting the cluster quorum object. Error: $err"  -ErrorAction SilentlyContinue
    }

    if ($quorum.QuorumResource -and $quorum.QuorumResource.Name) {
        $witness = $Quorum.QuorumResource.Name
    }

    $clusterProperties = New-Object PSObject -Property @{
        $NamePropertyName = $name;
        $fqdnPropertyName = $fqdn;
        $CurrentHostServerPropertyName = getCoreClusterGroupOwner;
        $NodeCountPropertyName = @(Get-ClusterNode).Length;
        $RoleCountPropertyName = getRoleCount;
        $NetworkCountPropertyName = @(Get-ClusterNetwork).Length;
        $DiskCountPropertyName = getDiskCount;
        $WitnessPropertyName = $witness;
    }

    return $clusterProperties
}

###############################################################################
# Script exevution starts here...
###############################################################################

setupScriptEnv

if (-not ($env:pester)) {
    $retValue = @{}

    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        $retValue = main
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue
    }

    cleanupScriptEnv

    return $retValue
}


}
## [END] Get-WACSDDCSmeClusterProperties ##
function Get-WACSDDCSmeClusterRequiredFeatures {
<#

.SYNOPSIS
Retrieves the install state information about the required features to perform Failover Cluster operations.

.DESCRIPTION
Retrieves the install state information about the required features to perform Failover Cluster operations.

.ROLE
Readers

#>

# If further features are required for Failover Cluster, do the following:
#   - Add a function called 'Get-{FeatureName}IsInstalled and have it return a boolean
#   - Follow the existing pattern at the bottom of the file of defining a variable to hold the result and add it
#     to the existing $requiredFeatures object

Set-StrictMode -Version 5.0

Import-Module -Name CimCmdlets -ErrorAction SilentlyContinue
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

function Get-WindowsManagementFrameworkIsInstalled {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $operatingSystemVersion = $OperatingSystem.Version
    $windows2016Version = [Version]'10.0'
    $windows2012Version = [Version]'6.2'

    if ($operatingSystemVersion -ge $windows2016Version) {
        # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
        $true
    } elseif ($operatingSystemVersion -ge $windows2012Version) {
        # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
        $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
        $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue
        if ($registryKeyValue -and ($registryKeyValue.Length -ne 0)) {
            $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion
            if ($installedWmfVersion -ge [Version]'5.0') {
                $true
            }
        }
    } else {
        # Unsupported version of Windows
        $false
    }
}

function Get-ClusterPowerShellFeatureIsInstalled {
    $clusterPowerShellFeature = Microsoft.PowerShell.Core\Get-Command -Name "Get-Cluster" -ErrorAction SilentlyContinue

    if ($clusterPowerShellFeature) {
        $true
    } else {
        $false
    }
}

$clusterPowerShellIsInstalled = Get-ClusterPowerShellFeatureIsInstalled
$windowsManagementFrameworkIsInstalled = Get-WindowsManagementFrameworkIsInstalled
$requiredFeatures = New-Object -TypeName System.Object
Add-Member -InputObject $requiredFeatures -MemberType NoteProperty -Name "ClusterPowerShell" -Value @{ IsInstalled = $clusterPowerShellIsInstalled }
Add-Member -InputObject $requiredFeatures -MemberType NoteProperty -Name "WindowsManagementFramework" -Value @{ IsInstalled = $windowsManagementFrameworkIsInstalled }

$requiredFeatures

}
## [END] Get-WACSDDCSmeClusterRequiredFeatures ##
function Get-WACSDDCSmeClusterResource {
<#

.SYNOPSIS
Gets the resources of a cluster group.

.DESCRIPTION
Gets the resources of a cluster group.

.ROLE
Readers

.PARAMETER groupId
The unique identifier of the cluster group.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-SmeClusterResource" -Scope Script
    Set-Variable -Name DependencyRegEx -Option ReadOnly -Value "\[([^]]+)\]" -Scope Script
    Set-Variable -Name DisplayNamePropertyName -Option ReadOnly -Value "DisplayName" -Scope Script
    Set-Variable -Name SettingsPropertyName -Option ReadOnly -Value "Settings" -Scope Script
    Set-Variable -Name SettingNamePropertyName -Option ReadOnly -Value "Name" -Scope Script
    Set-Variable -Name SettingValuePropertyName -Option ReadOnly -Value "Value" -Scope Script
    Set-Variable -Name ResourceTypeIPv6Address -Option ReadOnly -Value "IPv6 Address" -Scope Script
    Set-Variable -Name ResourceTypeIPAddress -Option ReadOnly -Value "IP Address" -Scope Script
    Set-Variable -Name ResourceTypePhysicalDisk -Option ReadOnly -Value "Physical Disk" -Scope Script
    Set-Variable -Name ResourceTypePropertyName -Option ReadOnly -Value "ResourceType" -Scope Script
    Set-Variable -Name ResourceTypeNetworkName -Option ReadOnly -Value "Network Name" -Scope Script
    Set-Variable -Name AddressPropertyName -Option ReadOnly -Value "Address" -Scope Script
    Set-Variable -Name DnsNamePropertyName -Option ReadOnly -Value "DnsName" -Scope Script
    Set-Variable -Name NetworkPropertyName -Option ReadOnly -Value "Network" -Scope Script
    Set-Variable -Name ResourceStateOnline -Option ReadOnly -Value "Online" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name DependencyRegEx -Scope Script -Force
    Remove-Variable -Name DisplayNamePropertyName -Scope Script -Force
    Remove-Variable -Name SettingsPropertyName -Scope Script -Force
    Remove-Variable -Name SettingNamePropertyName -Scope Script -Force
    Remove-Variable -Name SettingValuePropertyName -Scope Script -Force
    Remove-Variable -Name ResourceTypeIPv6Address -Scope Script -Force
    Remove-Variable -Name ResourceTypeIPAddress -Scope Script -Force
    Remove-Variable -Name ResourceTypePhysicalDisk -Scope Script -Force
    Remove-Variable -Name ResourceTypePropertyName -Scope Script -Force
    Remove-Variable -Name ResourceTypeNetworkName -Scope Script -Force
    Remove-Variable -Name AddressPropertyName -Scope Script -Force
    Remove-Variable -Name DnsNamePropertyName -Scope Script -Force
    Remove-Variable -Name NetworkPropertyName -Scope Script -Force
    Remove-Variable -Name ResourceStateOnline -Scope Script -Force
}

<#

.SYNOPSIS
Compute the best display name for v4 and v6 addresses

.DESCRIPTION
Compute the best display name for v4 and v6 addresses

.PARAMETER resource
The cluster resource PowerShell object.

.PARAMETER params
The settings (private properties) of the cluster resource.

#>

function computeIpAddressDisplayName($resource, $params) {
    $name = $null
    $value = $null

    if ($resource.State -eq $ResourceStateOnline) {
        $value = ($params | Where-Object { $_.Name -eq $AddressPropertyName }).Value
        $name = $strings.IPAddressDisplayNameFormat -f $value
    } else {
        $value = ($params | Where-Object { $_.Name -eq $NetworkPropertyName }).Value
        $name = $strings.NetworkNameOfflineDisplayNameFormat -f $value
    }

    return $name
}

<#

.SYNOPSIS
Compute the most appropriate display name for the passed in resource.

.DESCRIPTION
Each well-known type of cluster resource has its own display name.

.PARAMETER resource
The cluster resource PowerShell object.

#>

function computeDisplayName($resource) {
    $name = $null
    $params = $resource | Get-ClusterParameter

    switch ($resource.$ResourceTypePropertyName) {
        $ResourceTypeIPv6Address {
            $name = computeIpAddressDisplayName $resource $params
        }

        $ResourceTypeIPAddress {
            $name = computeIpAddressDisplayName $resource $params
        }

        $ResourceTypeNetworkName {
            $value = ($params | Where-Object { $_.Name -eq $DnsNamePropertyName }).Value
            $name = $strings.NetworkNameDisplayNameFormat -f $value
        }

        default {
            $name = $resource.Name
        }
    }

    return $name
}

<#

.SYNOPSIS
Get the settings (private properties)(ClusterParameters)

.DESCRIPTION
Get the settings for the passed in resource.

.PARAMETER resource
The cluster resource PowerShell object.

#>

function getSettings($resource) {
    $settings = @()

    $params = $resource | Get-ClusterParameter

    ForEach($param in $params) {
        $setting = New-Object PSObject

        Add-Member -InputObject $setting -MemberType NoteProperty -Name $SettingNamePropertyName -Value $param.Name
        Add-Member -InputObject $setting -MemberType NoteProperty -Name $SettingValuePropertyName -Value $param.Value

        $settings += $setting
    }

    return $settings
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

.PARAMETER groupId
The Id of the cluster group whose cluster resources are being requested.

#>

function main([string]$groupId) {
    $err = $null

    $resources = FailoverClusters\Get-ClusterGroup -Name $groupId | FailoverClusters\Get-ClusterResource -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($resources) {
        $dependencies = $resources | FailoverClusters\Get-ClusterResourceDependency  -ErrorAction SilentlyContinue -ErrorVariable +err
        if ($dependencies) {
            $dependencies | ForEach-Object {
                if ($_.DependencyExpression) {
                    # DependencyExpression has the form: [Cluster IP Address] or [Cluster IP Address 2001:4898:9:100d::]
                    # Match and extract the items between square brackets
                    $deps = $_.DependencyExpression.split($DependencyRegEx, [System.StringSplitOptions]::RemoveEmptyEntries)
                    $deps = $deps | Where-Object { $_ -notmatch " or " -and $_ -notmatch " and "}

                    $name = $_.Resource
                    $resources | Where-Object { $_.Name -eq $name} | Add-Member -MemberType NoteProperty -Name 'Dependencies' -Value @($deps)
                }
            }

            $resources | ForEach-Object {
                if ($_.ResourceType -eq 'Virtual Machine Configuration') {
                    $dependsOnSharedVols = $_ | FailoverClusters\Get-ClusterParameter | Where-Object { $_.Name -eq 'DependsOnSharedVolumes' }

                    if ($dependsOnSharedVols) {
                        $volIds = ($_ | FailoverClusters\Get-ClusterParameter -Name 'DependsOnSharedVolumes').Value

                        $volIds | ForEach-Object {
                            $volume = FailoverClusters\Get-ClusterSharedVolume $_
                            Add-Member -InputObject $volume -MemberType NoteProperty -Name $ResourceTypePropertyName -Value $ResourceTypePhysicalDisk
                            Add-Member -InputObject $volume -MemberType NoteProperty -Name "IsStorageClassResource" -Value $true
                            $resources += $volume
                        }
                    }
                }
            }

            return $resources | Microsoft.PowerShell.Utility\Select-Object `
            Characteristics, `
            @{Name=$DisplayNamePropertyName;Expression={computeDisplayName $_}}, `
            Name, `
            ResourceType, `
            State, `
            Dependencies, `
            Id, `
            IsCoreResource, `
            IsStorageClassResource, `
            IsNetworkClassResource, `
            OwnerGroup, `
            OwnerNode, `
            @{Name=$SettingsPropertyName;Expression={getSettings $_}}
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to get the cluster resources of cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @()
}

###############################################################################
# Script execution starts here...
###############################################################################

setupScriptEnv

$returnVal = @()

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Get-WACSDDCSmeClusterResource ##
function Get-WACSDDCSmeClusterStatus {
<#

.SYNOPSIS
Gets the status of the cluster.

.DESCRIPTION
Gets the status of the cluster.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

try {
    $Nodes = Get-ClusterNode | Microsoft.PowerShell.Core\Where-Object { $_.State -eq [Microsoft.FailoverClusters.PowerShell.ClusterNodeState]::Up }
    $Aliases = @($Nodes | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Name)

    ## Output success.
    @{
        Status = @{
            # Online: 0
            Type    = 0
            Label   = $null
            Details = $null
        }
        Aliases = $Aliases
    }
}
catch {
    ## Output error
    @{
        Status = @{
            # Error: 3
            Type    = 3
            Label   = 'cmdletModuleError'
            Details = $_.Exception.Message
        }
    }
}


}
## [END] Get-WACSDDCSmeClusterStatus ##
function Get-WACSDDCSmeNodeCurrentVersion {
<#
.SYNOPSIS
    Retreives OS version from registry.
.DESCRIPTION
    Retreives OS version from registry.
.ROLE
    Administrators
#>

$versionInformation = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Microsoft.PowerShell.Utility\Select-Object CurrentBuild, UBR
$versionInformation

}
## [END] Get-WACSDDCSmeNodeCurrentVersion ##
function Get-WACSDDCSolutionUpdate {
<#

.SYNOPSIS
Gets list of solution updates.

.DESCRIPTION
Gets list of solution updates.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdate.ps1"

Get-SolutionUpdate -ErrorAction SilentlyContinue -ErrorVariable +err | ConvertTo-Json -Depth 4 | ConvertFrom-Json

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting solution update.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdate ##
function Get-WACSDDCSolutionUpdateEnvironment {
<#

.SYNOPSIS
Gets solution update environment.

.DESCRIPTION
Gets solution update environment.

.ROLE
Readers
#>

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdateEnvironment.ps1"

Get-SolutionUpdateEnvironment -ErrorAction SilentlyContinue -ErrorVariable +err

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting solution update environment.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdateEnvironment ##
function Get-WACSDDCSolutionUpdateRun {
<#

.SYNOPSIS
Gets a solution update run for an update.

.DESCRIPTION
Gets a solution update run for an update.

.ROLE
Readers
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $updateRunId
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdateRun.ps1"

Get-SolutionUpdateRun -Id $updateRunId -MaxDepth 3 -ErrorAction SilentlyContinue -ErrorVariable +err | ConvertTo-Json -Depth 20 | ConvertFrom-Json

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting solution update run.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdateRun ##
function Get-WACSDDCSolutionUpdateRunAll {
<#

.SYNOPSIS
Gets list of solution update runs for an update.

.DESCRIPTION
Gets list of solution update runs for an update.

.ROLE
Readers
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $updateId
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdateRunAll.ps1"

Get-SolutionUpdate -Id $updateId -ErrorAction SilentlyContinue -ErrorVariable +err | Get-SolutionUpdateRun -MaxDepth 3 -ErrorAction SilentlyContinue -ErrorVariable +err | ConvertTo-Json -Depth 20 | ConvertFrom-Json

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting all solution update runs.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdateRunAll ##
function Get-WACSDDCSolutionUpdateRunAllXml {
<#

.SYNOPSIS
Gets list of XML output of solution update runs for an update.

.DESCRIPTION
Gets list of XML output of solution update runs for an update.

.ROLE
Readers
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $updateId
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdateRunAllXml.ps1"

Get-SolutionUpdate -Id $updateId -ErrorAction SilentlyContinue -ErrorVariable +err | Get-SolutionUpdateRun -ErrorAction SilentlyContinue -ErrorVariable +err | ConvertTo-Xml -Depth 50 -As String -NoTypeInformation

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting all solution update runs as xml.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdateRunAllXml ##
function Get-WACSDDCSolutionUpdateRunXml {
<#

.SYNOPSIS
Gets XML output of a solution update run for an update.

.DESCRIPTION
Gets XML output of a solution update run for an update.

.ROLE
Readers
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $updateRunId
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Get-SolutionUpdateRunXml.ps1"

Get-SolutionUpdateRun -Id $updateRunId -ErrorAction SilentlyContinue -ErrorVariable +err | ConvertTo-Xml -Depth 50 -As String -NoTypeInformation

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error getting the solution update run as xml.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Get-WACSDDCSolutionUpdateRunXml ##
function Get-WACSDDCStorageFileShare {
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
## [END] Get-WACSDDCStorageFileShare ##
function Get-WACSDDCTempFolderPath {
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
## [END] Get-WACSDDCTempFolderPath ##
function Get-WACSDDCUpdatesHistory {
<#

.SYNOPSIS
Gets history of install results.

.DESCRIPTION
Gets history of install results.

.ROLE
Readers

#>
Param
(    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue
<#

.SYNOPSIS
Helper function that gets history of install results.

.DESCRIPTION
Helper function that gets history of install results.

#>
function Get-UpdatesHistory {
    Param
    (
        [Parameter(Mandatory = $true)]
        [System.Array] $nodeResults,
        [string] $timestamp,
        [string] $plugin
    )

    $result = @()
    # UpgradeOS is defining the type of update.
    # False represents Quality update and True represents Feature Update. 
    if (([bool]$nodeResults[0].PSObject.Properties["UpgradingOs"] -eq $false) -or ($nodeResults.UpgradingOs -eq $false)) {
        $nodeResults | ForEach-Object {
            $nodeResult = $_
            $isInstallResultsExist = [bool]$nodeResult.InstallResults
            if ($isInstallResultsExist -ne $false -and $nodeResult.InstallResults.Count -gt 0) {
                $installResults = $nodeResult.InstallResults
                $installResults | ForEach-Object {
                    $installResult = $_
                    $result += Get-ResultObject -node $installResult.NodeName -updateStartingTimestamp $timestamp -updateTimestamp $installResult.UpdateTimestamp `
                            -updateResultCode $installResult.UpdateResultCode -errorCode $installResult.ErrorCode -plugin $installResult.SourcePlugin `
                            -updateTitle $installResult.UpdateTitle -updateDescription $installResult.UpdateDescription -updateID $installResult.UpdateId
                }
            }
            else {
                $result += Get-ResultObject -node $nodeResult.Node -updateStartingTimestamp $timestamp -updateResultCode $nodeResult.Status `
                    -plugin $plugin
            }
        }
    } else {
        $upgradeResults = $nodeResults.UpgradeResult
        $upgradeResults | ForEach-Object {
            $upgradeResult = $_
            if ($upgradeResult) {
                if ($upgradeResult.UpgradeInstallProperties -and $upgradeResult.UpgradeInstallProperties.WuConnected -eq $true) {
                    $wuUpdatesInfo = $upgradeResult.UpgradeInstallProperties.WuUpdatesInfo
                    $wuUpdatesInfo | ForEach-Object {
                        $wuUpdateInfo = $_
                        $result += Get-ResultObject -node $wuUpdateInfo.NodeName -updateStartingTimestamp $timestamp -updateTimestamp $upgradeResult.UpgradeTimestamp `
                            -updateResultCode $upgradeResult.UpgradeInstallResultCode -errorCode $upgradeResult.SetupExitCode -plugin $upgradeResult.SourcePlugin `
                            -updateTitle $wuUpdateInfo.UpdateTitle -updateDescription $wuUpdateInfo.UpdateDescription -updateID $wuUpdateInfo.UpdateId
                    }
                } else {
                    $result += Get-ResultObject -node $upgradeResult.NodeName -updateStartingTimestamp $timestamp -updateTimestamp $upgradeResult.UpgradeTimestamp `
                        -updateResultCode $upgradeResult.UpgradeInstallResultCode -errorCode $upgradeResult.SetupExitCode -plugin $upgradeResult.SourcePlugin
                }
            }
        }
    }
    return $result
}

<#

.SYNOPSIS
Processes single cau report results

.DESCRIPTION
Processes single cau report results

#>
function Get-ResultObject() {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $updateStartingTimestamp,
        [string] $updateResultCode,
        [string] $errorCode,
        [string] $plugin,
        [AllowEmptyString()]
        [string] $node,
        [string] $updateTimestamp,
        [string] $updateTitle,
        [string] $updateDescription,
        [string] $updateID,
        [string] $errorRecordData
    )

    $resultObject = New-Object -TypeName PSObject
    $resultObject | Add-Member -MemberType NoteProperty -Name Status -Value $updateResultCode
    $resultObject | Add-Member -MemberType NoteProperty -Name UpdateStartingTimestamp -Value $updateStartingTimestamp
    if($node){
        $resultObject | Add-Member -MemberType NoteProperty -Name Node -Value $node
    }
    if ($errorCode) {
        $resultObject | Add-Member -MemberType NoteProperty -Name ErrorCode -Value $errorCode
    }
    if ($updateTimestamp) {
        $resultObject | Add-Member -MemberType NoteProperty -Name UpdateTimestamp -Value $updateTimestamp
    }
    if ($plugin) {
        $resultObject | Add-Member -MemberType NoteProperty -Name Plugin -Value $plugin
    }
    if ($updateTitle) {
        $resultObject | Add-Member -MemberType NoteProperty -Name UpdateTitle -Value $updateTitle
    }
    if ($updateDescription) {
        $resultObject | Add-Member -MemberType NoteProperty -Name UpdateDescription -Value $updateDescription
    }
    if ($updateID) {
        $resultObject | Add-Member -MemberType NoteProperty -Name UpdateID -Value $updateID
    }
    if ($errorRecordData) {
        $resultObject | Add-Member -MemberType NoteProperty -Name ErrorRecordData -Value $errorRecordData
    }
    return $resultObject
}

<#

.SYNOPSIS
Processes single cau report results

.DESCRIPTION
Processes single cau report results

#>
function Get-ReportInstallResults() {
    Param
    (
        [Parameter(Mandatory = $true)]
        $report
    )

    if ($report.ClusterResult.NodeResults.Count -ne 0) {
        $nodeResults = $report.ClusterResult.NodeResults
        $timestamp = $report.ClusterResult.StartTimestamp
        $plugin = $report.Plugin
        $result = Get-UpdatesHistory -nodeResults $nodeResults -timestamp $timestamp -plugin $plugin
    } else {
        $result += Get-ResultObject -updateStartingTimestamp $report.ClusterResult.StartTimestamp `
        -updateResultCode $report.ClusterResult.Status -plugin $report.Plugin -errorRecordData $report.ClusterResult.ErrorRecordData
    }
    $result
}

#########################################
## Main Script
#########################################
$reports = Get-CauReport -ClusterName $clusterName -Detailed
$result = @()
if ($reports) {
    $reports | ForEach-Object {
        $reportResult = Get-ReportInstallResults $_
        if ($null -ne $reportResult) {
            $result += $reportResult
        }
    }
}

$result

}
## [END] Get-WACSDDCUpdatesHistory ##
function Get-WACSDDCVirtualDiskPreCheck {
<#

.SYNOPSIS
Runs Get-VirutalDisk on the cluster to check all virtual disk health.

.DESCRIPTION
Runs Get-VirutalDisk on the cluster to check all virtual disk health.

.ROLE
Readers

#>

Get-VirtualDisk

}
## [END] Get-WACSDDCVirtualDiskPreCheck ##
function Install-WACSDDCMonitoringDependencies {
<#

.SYNOPSIS
Script that returns if Microsoft Monitoring Agent is running or not.

.DESCRIPTION
Download and install MMAAgent & Microsoft Dependency agent

.PARAMETER WorkspaceId
  is the workspace id of the Log Analytics workspace

.PARAMETER WorkspacePrimaryKey
  is the primary key of the Log Analytics workspace

.PARAMETER IsHciCluster
 flag to indicate if the node is part of a HCI cluster

.PARAMETER AzureCloudType
  is the Azure cloud type of the Log Analytics workspace

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
  $IsHciCluster,
  [Parameter()]
  [int]
  $AzureCloudType
)

$ErrorActionPreference = "Stop"

$LogName = "WindowsAdminCenter"
$LogSource = "SMEScript"
$ScriptName = "Install-MonitoringDependencies.ps1"

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Utility function to invoke a Windows command.
    (This command is Microsoft internal use only.)

.DESCRIPTION
    Invokes a Windows command and generates an exception if the command returns an error. Note: only for application commands.

.PARAMETER Command
    The name of the command we want to invoke.

.PARAMETER Parameters
    The parameters we want to pass to the command.
.EXAMPLE
    Invoke-WACWinCommand "netsh" "http delete sslcert ipport=0.0.0.0:9999"
#>
function Invoke-WACWinCommand {
  Param(
    [string]$Command,
    [string[]]$Parameters
  )

  try {
    Write-Verbose "$command $([System.String]::Join(" ", $Parameters))"
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Command
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.UseShellExecute = $false
    $startInfo.Arguments = [System.String]::Join(" ", $Parameters)
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
  }
  catch {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: $_"  -ErrorAction SilentlyContinue
    Write-Error $_
  }

  try {
    $process.Start() | Out-Null
  }
  catch {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: $_"  -ErrorAction SilentlyContinue
    Write-Error $_
  }

  try {
    $process.WaitForExit() | Out-Null
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $output = $stdout + "`r`n" + $stderr
  }
  catch {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: $_"  -ErrorAction SilentlyContinue
    Write-Error $_
  }

  if ($process.ExitCode -ne 0) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message "[$ScriptName]: $_"  -ErrorAction SilentlyContinue
    Write-Error $_
  }

  # output all messages
  return $output
}

$MMAAgentStatus = Get-Service -Name HealthService -ErrorAction SilentlyContinue
$IsMmaRunning = $null -ne $MMAAgentStatus -and $MMAAgentStatus.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

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
  for ($i = 0; $i -lt 10; $i++) {
    if (-Not(Test-Path $SetupExePath)) {
      Start-Sleep -Seconds 6
    }
  }


  Invoke-WACWinCommand -Command $SetupExePath -Parameters "/qn", "NOAPM=1", "ADD_OPINSIGHTS_WORKSPACE=1", "OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=$AzureCloudType", "OPINSIGHTS_WORKSPACE_ID=$WorkspaceId", "OPINSIGHTS_WORKSPACE_KEY=$WorkspacePrimaryKey", "AcceptEndUserLicenseAgreement=1"
}

$ServiceMapAgentStatus = Get-Service -Name MicrosoftDependencyAgent -ErrorAction SilentlyContinue
$IsServiceMapRunning = $null -ne $ServiceMapAgentStatus -and $ServiceMapAgentStatus.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running

if (-not $IsServiceMapRunning) {
  # Install service map/ dependency agent
  $ServiceMapExe = Join-Path -Path $env:temp -ChildPath 'InstallDependencyAgent-Windows.exe'

  if (Test-Path $ServiceMapExe) {
    Remove-Item $ServiceMapExe
  }
  Invoke-WebRequest -Uri https://aka.ms/dependencyagentwindows -OutFile $ServiceMapExe

  Invoke-WACWinCommand -Command $ServiceMapExe -Parameters "/S", "AcceptEndUserLicenseAgreement=1"
}

# Wait for agents to completely install
for ($i = 0; $i -lt 10; $i++) {
  if ($null -eq (Get-Service -Name HealthService -ErrorAction SilentlyContinue) -or $null -eq (Get-Service -Name MicrosoftDependencyAgent -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 6
  }
}

<#
 # .DESCRIPTION
 # Enable health settings on HCI cluster node to log faults into Microsoft-Windows-Health/Operational
 #>
if ($IsHciCluster) {
  $subsystem = Get-StorageSubsystem clus*
  $subsystem | Set-StorageHealthSetting -Name "Platform.ETW.MasTypes" -Value "Microsoft.Health.EntityType.Subsystem,Microsoft.Health.EntityType.Server,Microsoft.Health.EntityType.PhysicalDisk,Microsoft.Health.EntityType.StoragePool,Microsoft.Health.EntityType.Volume,Microsoft.Health.EntityType.Cluster"
}

}
## [END] Install-WACSDDCMonitoringDependencies ##
function Install-WACSDDCRsatFailoverClusterFoD {
<#

.SYNOPSIS
Installs the Remote Server Administration Tools (RSAT) Feature-on-Demand required for CAU.

.DESCRIPTION
Installs the Remote Server Administration Tools (RSAT) Feature-on-Demand required for CAU.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Set-Variable -Name RsatFailoverClusterTool -Option Constant -Value "Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0" -ErrorAction SilentlyContinue

$result = Add-WindowsCapability -Name $RsatFailoverClusterTool -Online

return @{
    isSuccess = $result.Online
}

}
## [END] Install-WACSDDCRsatFailoverClusterFoD ##
function Install-WACSDDCSmeClusterCmdlets {
<#

.SYNOPSIS
Installs the Failover Cluster PowerShell Cmdlets on the target node.

.DESCRIPTION
Installs the Failover Cluster PowerShell Cmdlets on the target node.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Import-Module -Name ServerManager -ErrorAction SilentlyContinue

Install-WindowsFeature -Name "RSAT-Clustering-PowerShell"

}
## [END] Install-WACSDDCSmeClusterCmdlets ##
function Move-WACSDDCFile {
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
## [END] Move-WACSDDCFile ##
function Move-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Moves a group in a failover cluster.

.DESCRIPTION
Moves a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the cluster group.

.PARAMETER destinationName
The name of the cluster node to move the group to.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $groupId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $destinationNodeName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Move-SmeClusterGroup" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>
function main([string] $groupId, [string] $destinationName) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err
    if ($group) {
        $isVm = $group.GroupType -eq [Microsoft.FailoverClusters.PowerShell.GroupType]::VirtualMachine

        if ($isVm) {
            $isRunning = $group.State -eq [Microsoft.FailoverClusters.PowerShell.ClusterGroupState]::Online

            if ($isRunning) {
                $group | FailoverClusters\Move-ClusterVirtualMachineRole -Node $destinationNodeName -MigrationType Live -ErrorAction SilentlyContinue -ErrorVariable +err
            } else {
                $group | FailoverClusters\Move-ClusterVirtualMachineRole -Node $destinationNodeName -MigrationType Quick -ErrorAction SilentlyContinue -ErrorVariable +err
            }
        } else {
            $group | FailoverClusters\Move-ClusterGroup -Node $destinationNodeName -ErrorAction SilentlyContinue -ErrorVariable +err
        }

        if (-not ($err)) {
            $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully moved cluster group $group." -ErrorAction SilentlyContinue

            return FailoverClusters\Get-ClusterGroup -Name $groupId | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to move cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId $destinationNodeName
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Move-WACSDDCSmeClusterGroup ##
function New-WACSDDCEnvironmentVariable {
<#

.SYNOPSIS
Creates a new environment variable specified by name, type and data.

.DESCRIPTION
Creates a new environment variable specified by name, type and data.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [String]
    $name,

    [Parameter(Mandatory = $True)]
    [String]
    $value,

    [Parameter(Mandatory = $True)]
    [String]
    $type
)

Set-StrictMode -Version 5.0
Import-LocalizedData -BindingVariable strings -FileName strings.psd1

If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
    return [Environment]::SetEnvironmentVariable($name, $value, $type)
}
Else {
    Write-Error $strings.EnvironmentErrorAlreadyExists
}
}
## [END] New-WACSDDCEnvironmentVariable ##
function New-WACSDDCFile {
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
## [END] New-WACSDDCFile ##
function New-WACSDDCFolder {
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
## [END] New-WACSDDCFolder ##
function New-WACSDDCSmbFileShare {
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
## [END] New-WACSDDCSmbFileShare ##
function New-WACSDDCSmeCluster {
<#

.SYNOPSIS
Creates a new cluster on the target node.

.DESCRIPTION
Creates a new cluster on the target node.

.ROLE
Administrators

.PARAMETER ClusterName
The name of the cluster.

.PARAMETER serverNames
The servers to use to create the cluster.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$clusterName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$serverNames
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "New-SmeCluster" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorRecords
May, or may not, be an array of errors...

#>

function writeErrors($errorRecords) {
    foreach ($errorRecord in @($errorRecords)) {
        Microsoft.PowerShell.Utility\Write-Error $errorRecord
    }
}

<#

.SYNOPSIS
Helper function to write the warnings to warning stream.

.DESCRIPTION
Helper function to write the warnings to warning stream.


.PARAMETER warningRecords
May, or may not, be an array of warnings...

#>

function writeWarnings($warningRecords) {
    foreach ($warningRecord in @($warningRecords)) {
        Microsoft.PowerShell.Utility\Write-Warning $warningRecord
    }
}

<#

.SYNOPSIS
Validate the servers.

.DESCRIPTION
validate that the servers provided are suitable to be a cluster.

.PARAMETER serverNames
The servers to use to create the cluster.

.RETURN bool
True when validatation passed or was skipped.  False if it failed.

#>

function validate([string []] $serverNames) {
    # Doesn't make sense to validate a one node cluster.
    if ($serverNames.Count -gt 1) {
        Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.CreateClusterProgressValidationStart -PercentComplete 0

        Test-Cluster -Node $serverNames -ErrorAction SilentlyContinue -ErrorVariable +errorRecords -WarningVariable +warningRecords -Force

        if ($errorRecords) {
            # Falure means this script is 100% complete.
            Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.CreateClusterProgressValidationEnd -PercentComplete 100 -Completed $true

            writeErrors $errorRecords

            return $false
        }

        if ($warningRecords) {
           writeWarnings $warningRecords
        }
    }

    # Success means this script is 50% complete.
    Microsoft.PowerShell.Utility\Write-Progress -Activity $strings.CreateClusterProgressValidationEnd -PercentComplete 50 -Completed $false

    return $true
}

<#

.SYNOPSIS
Create a cluster.

.DESCRIPTION
Create a cluster from the passed in servers.

.PARAMETER ClusterName
The name of the cluster.

.PARAMETER serverNames
The servers to use to create the cluster.

.RETURN Cluster
A JSON object that matches the UX Cluster model.

#>


function createCluster([string] $clusterName, [string []] $serverNames) {
    # Starting second half of the script, progress is now 51% complete
    Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.CreateClusterProgressCreationStartFormat -f $clusterName) -PercentComplete 51 -Completed $false

    $clusterObject = New-Cluster -Name $clusterName -Node $serverNames -Force -ErrorAction SilentlyContinue -ErrorVariable +errorRecords -WarningVariable +warningRecords

    if ($errorRecords) {
        # Falure means this script is 100% complete.
        Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.CreateClusterProgressCreationEndFormat -f $clusterName) -PercentComplete 100 -Completed $false

        writeErrors $errorRecords

        return $null
    }

    if ($warningRecords) {
        writeWarnings $warningRecords
    }

    # Now the script is complete.
    Microsoft.PowerShell.Utility\Write-Progress -Activity ($strings.CreateClusterProgressCreationEndFormat -f $clusterName) -PercentComplete 100 -Completed $true

    return $clusterObject | Microsoft.PowerShell.Utility\Select-Object Name, Domain
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER ClusterName
The name of the cluster.

.PARAMETER serverNames
The servers to use to create the cluster.

.RETURN Cluster
A JSON object that matches the UX Cluster model.

#>

function main([string] $clusterName, [string []] $serverNames) {
    if (validate @($serverNames)) {
        Start-Sleep 1

        return createCluster $clusterName @($serverNames)
    }

    return $null
}

###############################################################################
# Script execution starts here...
###############################################################################

$module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main $clusterName $serverNames
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

return $null

}
## [END] New-WACSDDCSmeCluster ##
function New-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Creates an empty group in a failover cluster.

.DESCRIPTION
Creates an empty group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupName
The name of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "New-SmeClusterGroup" -Scope Script
    Set-Variable -Name RetryMax -Option ReadOnly -Value 4 -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name RetryMax -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>
function main([string] $groupName) {
    $name = $groupName
    $err = $null

    for ($i = 0; $i -le $RetryMax; $i++) {
        $group = FailoverClusters\Add-ClusterGroup -Name $name -ErrorAction SilentlyContinue -ErrorVariable +err

        if ($group) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully created cluster group $group." -ErrorAction SilentlyContinue

            return $group | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        } else {
            $tryNumber = $i + 1
            $name = $groupName + ' (' + $tryNumber + ')'
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to create cluster group $groupName. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupName
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal


}
## [END] New-WACSDDCSmeClusterGroup ##
function Remove-WACSDDCAllShareNames {
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
## [END] Remove-WACSDDCAllShareNames ##
function Remove-WACSDDCEnvironmentVariable {
<#

.SYNOPSIS
Removes an environment variable specified by name and type.

.DESCRIPTION
Removes an environment variable specified by name and type.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [String]
    $name,

    [Parameter(Mandatory = $True)]
    [String]
    $type
)

Set-StrictMode -Version 5.0
Import-LocalizedData -BindingVariable strings -FileName strings.psd1

If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
    Write-Error $strings.EnvironmentErrorDoesNotExists
}
Else {
    [Environment]::SetEnvironmentVariable($name, $null, $type)
}
}
## [END] Remove-WACSDDCEnvironmentVariable ##
function Remove-WACSDDCFileSystemEntity {
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
## [END] Remove-WACSDDCFileSystemEntity ##
function Remove-WACSDDCFolderShareUser {
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
## [END] Remove-WACSDDCFolderShareUser ##
function Remove-WACSDDCSmbServerCertificateMapping {
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
## [END] Remove-WACSDDCSmbServerCertificateMapping ##
function Remove-WACSDDCSmbShare {
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
## [END] Remove-WACSDDCSmbShare ##
function Remove-WACSDDCSmeCluster {
<#

.SYNOPSIS
Remove (Destroy) the cluster on the target node.

.DESCRIPTION
Permanently destroys the cluster on the target node.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Remove-SmeCluster" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script  -Force
    Remove-Variable -Name LogSource -Scope Script -Force
}

<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorRecords
May, or may not, be an array of errors...

#>

function writeErrors($errorRecords) {
    foreach ($errorRecord in @($errorRecords)) {
        Microsoft.PowerShell.Utility\Write-Error $errorRecord
    }
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

#>

function main() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

    if (-not ($cluster) -and $err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Could not find the cluster. Error: $err"  -ErrorAction SilentlyContinue

        writeErrors $err
    } else {
        $cluster | Remove-Cluster -Force -ErrorAction SilentlyContinue -ErrorVariable +err
        if ($err) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Could not remove the cluster. Error: $err"  -ErrorAction SilentlyContinue

            writeErrors $err
        }
    }
}

###############################################################################
# Script execution starts here...
###############################################################################

setupScriptEnv

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    main
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue
}

cleanupScriptEnv
}
## [END] Remove-WACSDDCSmeCluster ##
function Remove-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Removes a group in a failover cluster.

.DESCRIPTION
Removes a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Remove-SmeClusterGroup" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {
        $group | FailoverClusters\Remove-ClusterGroup -Force -RemoveResources -ErrorAction SilentlyContinue -ErrorVariable +err

        if (-not ($err)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully removed cluster group $group." -ErrorAction SilentlyContinue
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to remove cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    main $groupId
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

}
## [END] Remove-WACSDDCSmeClusterGroup ##
function Remove-WACSDDCSmeClusterNode {
<#

.SYNOPSIS
Removes (evicts) a failover cluster node from the cluster.

.DESCRIPTION
Removes a failover cluster node.

.ROLE
Administrators

.PARAMETER NodeName
The name of the node.

.PARAMETER cleanupDisks
Should the -CleanupDisks paramater be added?

#>
Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$nodeName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.Boolean]$cleanupDisks
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option Constant -Value "Remove-SmeClusterNode" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorRecords
May, or may not, be an array of errors...

#>

function writeErrors($errorRecords) {
    foreach ($errorRecord in @($errorRecords)) {
        Microsoft.PowerShell.Utility\Write-Error $errorRecord
    }
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER nodeName
The name of the cluster node to remove from the cluster.

#>

function main([string]$nodeName) {
    $node = Get-ClusterNode -Name $nodeName -ErrorAction SilentlyContinue -ErrorVariable +errorRecords

    if ($errorRecords) {
        writeErrors $errorRecord

        return
    }

    if ($node) {
        $args = @{ Force = $null; }

        if ($cleanupDisks) {
            $args += @{ CleanupDisks = $null; }
        }

        $node | Remove-ClusterNode @args
    }
}

###############################################################################
# Script execution starts here...
###############################################################################

$module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    return main $nodeName
}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue

return

}
## [END] Remove-WACSDDCSmeClusterNode ##
function Remove-WACSDDCSmeClusterResource {
<#

.SYNOPSIS
Removes a resource in a failover cluster.

.DESCRIPTION
Removes a resource in a failover cluster.

.ROLE
Administrators

.PARAMETER ResourceId
The unique identifier of the resource.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$ResourceId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

FailoverClusters\Remove-ClusterResource -Name $resourceId -Force

}
## [END] Remove-WACSDDCSmeClusterResource ##
function Rename-WACSDDCFileSystemEntity {
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
## [END] Rename-WACSDDCFileSystemEntity ##
function Rename-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Renames a group in a failover cluster.

.DESCRIPTION
Renames a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

.PARAMETER newName
The new name of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$newName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Rename-SmeClusterGroup" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId, [string] $newName) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {
        $oldName = $group.Name

        try {
            $group.Name = $newName
        } catch {
            $err = $_.Exception.Message
        }

        if (-not ($err)) {
            $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully renamed cluster group from $oldName to $group." -ErrorAction SilentlyContinue

            return FailoverClusters\Get-ClusterGroup -Name $groupId | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to rename cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId $newName
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Rename-WACSDDCSmeClusterGroup ##
function Restart-WACSDDCOperatingSystem {
<#

.SYNOPSIS
Reboot Windows Operating System by using Win32_OperatingSystem provider.

.DESCRIPTION
Reboot Windows Operating System by using Win32_OperatingSystem provider.

.ROLE
Administrators

#>
##SkipCheck=true##

Param(
)

import-module CimCmdlets

$instance = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem

$instance | Invoke-CimMethod -MethodName Reboot

}
## [END] Restart-WACSDDCOperatingSystem ##
function Restore-WACSDDCConfigureSmbServerCertificateMapping {
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
## [END] Restore-WACSDDCConfigureSmbServerCertificateMapping ##
function Resume-WACSDDCSmeClusterNode {
<#

.SYNOPSIS
Resumes a failover cluster node.

.DESCRIPTION
Resumes a failover cluster node.

.ROLE
Administrators

.PARAMETER NodeName
The name of the node.

.PARAMETER FailbackRoles
Whether to failback the node roles.

#>
Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$NodeName,

    [Parameter(Mandatory = $false)]
    [Switch]$FailbackRoles
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

$node = FailoverClusters\Get-ClusterNode -Name $NodeName

if ($FailbackRoles) {
    $node | FailoverClusters\Resume-ClusterNode -Failback Immediate
} else {
    $node | FailoverClusters\Resume-ClusterNode -Failback NoFailback
}

}
## [END] Resume-WACSDDCSmeClusterNode ##
function Set-WACSDDCComputerIdentification {
<#

.SYNOPSIS
Sets a computer and/or its domain/workgroup information.

.DESCRIPTION
Sets a computer and/or its domain/workgroup information.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $False)]
    [string]
    $ComputerName = '',

    [Parameter(Mandatory = $False)]
    [string]
    $NewComputerName = '',

    [Parameter(Mandatory = $False)]
    [string]
    $Domain = '',

    [Parameter(Mandatory = $False)]
    [string]
    $NewDomain = '',

    [Parameter(Mandatory = $False)]
    [string]
    $Workgroup = '',

    [Parameter(Mandatory = $False)]
    [string]
    $UserName = '',

    [Parameter(Mandatory = $False)]
    [string]
    $Password = '',

    [Parameter(Mandatory = $False)]
    [string]
    $UserNameNew = '',

    [Parameter(Mandatory = $False)]
    [string]
    $PasswordNew = '',

    [Parameter(Mandatory = $False)]
    [switch]
    $Restart)

function CreateDomainCred($username, $password) {
    $secureString = ConvertTo-SecureString $password -AsPlainText -Force
    $domainCreds = New-Object System.Management.Automation.PSCredential($username, $secureString)

    return $domainCreds
}

function UnjoinDomain($domain) {
    If ($domain) {
        $unjoinCreds = CreateDomainCred $UserName $Password
        Remove-Computer -UnjoinDomainCredential $unjoinCreds -PassThru -Force
    }
}

If ($NewDomain) {
    $newDomainCreds = $null
    If ($Domain) {
        UnjoinDomain $Domain
        $newDomainCreds = CreateDomainCred $UserNameNew $PasswordNew
    }
    else {
        $newDomainCreds = CreateDomainCred $UserName $Password
    }

    If ($NewComputerName) {
        Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -NewName $NewComputerName -Restart:$Restart
    }
    Else {
        Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -Restart:$Restart
    }
}
ElseIf ($Workgroup) {
    UnjoinDomain $Domain

    If ($NewComputerName) {
        Add-Computer -WorkGroupName $Workgroup -Force -PassThru -NewName $NewComputerName -Restart:$Restart
    }
    Else {
        Add-Computer -WorkGroupName $Workgroup -Force -PassThru -Restart:$Restart
    }
}
ElseIf ($NewComputerName) {
    If ($Domain) {
        $domainCreds = CreateDomainCred $UserName $Password
        Rename-Computer -NewName $NewComputerName -DomainCredential $domainCreds -Force -PassThru -Restart:$Restart
    }
    Else {
        Rename-Computer -NewName $NewComputerName -Force -PassThru -Restart:$Restart
    }
}
}
## [END] Set-WACSDDCComputerIdentification ##
function Set-WACSDDCDiagnosticDataSetting {
<#
.SYNOPSIS
Sets diagnostic data setting

.DESCRIPTION
Sets diagnostic data setting for telemetry

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [boolean]
    $IncludeOptionalDiagnosticData
  )

$registryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'

$propertyName = 'AllowTelemetry'
if($IncludeOptionalDiagnosticData)  {
  Set-ItemProperty -Path $registryKey -Name $propertyName -Value 3
} else {
  Set-ItemProperty -Path $registryKey -Name $propertyName -Value 1
}


}
## [END] Set-WACSDDCDiagnosticDataSetting ##
function Set-WACSDDCEnvironmentVariable {
<#

.SYNOPSIS
Updates or renames an environment variable specified by name, type, data and previous data.

.DESCRIPTION
Updates or Renames an environment variable specified by name, type, data and previrous data.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [String]
    $oldName,

    [Parameter(Mandatory = $True)]
    [String]
    $newName,

    [Parameter(Mandatory = $True)]
    [String]
    $value,

    [Parameter(Mandatory = $True)]
    [String]
    $type
)

Set-StrictMode -Version 5.0

$nameChange = $false
if ($newName -ne $oldName) {
    $nameChange = $true
}

If (-not [Environment]::GetEnvironmentVariable($oldName, $type)) {
    @{ Status = "currentMissing" }
    return
}

If ($nameChange -and [Environment]::GetEnvironmentVariable($newName, $type)) {
    @{ Status = "targetConflict" }
    return
}

If ($nameChange) {
    [Environment]::SetEnvironmentVariable($oldName, $null, $type)
    [Environment]::SetEnvironmentVariable($newName, $value, $type)
    @{ Status = "success" }
}
Else {
    [Environment]::SetEnvironmentVariable($newName, $value, $type)
    @{ Status = "success" }
}


}
## [END] Set-WACSDDCEnvironmentVariable ##
function Set-WACSDDCHybridManagement {
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
    The correlation ID for the connection (default value is the correlation ID for WAC)

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
    [Parameter(Mandatory = $false)]
    [string]
    $correlationId = '88079879-ba3a-4bf7-8f43-5bc912c8cd04'
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
    $ErrorActionPreference = "Stop"
    & $HybridAgentExecutable connect --resource-group $resourceGroup --tenant-id $tenantId --location $azureRegion `
        --subscription-id $subscriptionId --access-token $authToken --correlation-id $correlationId
    $ErrorActionPreference = "Continue"

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
## [END] Set-WACSDDCHybridManagement ##
function Set-WACSDDCHyperVEnhancedSessionModeSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Enhanced Session Mode settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Enhanced Session Mode settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $enableEnhancedSessionMode
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'EnableEnhancedSessionMode' = $enableEnhancedSessionMode};

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    EnableEnhancedSessionMode

}
## [END] Set-WACSDDCHyperVEnhancedSessionModeSettings ##
function Set-WACSDDCHyperVHostGeneralSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host General settings.

.DESCRIPTION
Sets a computer's Hyper-V Host General settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $virtualHardDiskPath,
    [Parameter(Mandatory = $true)]
    [String]
    $virtualMachinePath
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'VirtualHardDiskPath' = $virtualHardDiskPath};
$args += @{'VirtualMachinePath' = $virtualMachinePath};

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    VirtualHardDiskPath, `
    VirtualMachinePath

}
## [END] Set-WACSDDCHyperVHostGeneralSettings ##
function Set-WACSDDCHyperVHostLiveMigrationSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Live Migration settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Live Migration settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $virtualMachineMigrationEnabled,
    [Parameter(Mandatory = $true)]
    [int]
    $maximumVirtualMachineMigrations,
    [Parameter(Mandatory = $true)]
    [int]
    $virtualMachineMigrationPerformanceOption,
    [Parameter(Mandatory = $true)]
    [int]
    $virtualMachineMigrationAuthenticationType
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

if ($virtualMachineMigrationEnabled) {
    $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2;
    
    Enable-VMMigration;

    # Create arguments
    $args = @{'MaximumVirtualMachineMigrations' = $maximumVirtualMachineMigrations};
    $args += @{'VirtualMachineMigrationAuthenticationType' = $virtualMachineMigrationAuthenticationType; };

    if (!$isServer2012) {
        $args += @{'VirtualMachineMigrationPerformanceOption' = $virtualMachineMigrationPerformanceOption; };
    }

    Set-VMHost @args;
} else {
    Disable-VMMigration;
}

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    maximumVirtualMachineMigrations, `
    VirtualMachineMigrationAuthenticationType, `
    VirtualMachineMigrationEnabled, `
    VirtualMachineMigrationPerformanceOption

}
## [END] Set-WACSDDCHyperVHostLiveMigrationSettings ##
function Set-WACSDDCHyperVHostNumaSpanningSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host settings.

.DESCRIPTION
Sets a computer's Hyper-V Host settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $numaSpanningEnabled
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'NumaSpanningEnabled' = $numaSpanningEnabled};

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    NumaSpanningEnabled

}
## [END] Set-WACSDDCHyperVHostNumaSpanningSettings ##
function Set-WACSDDCHyperVHostStorageMigrationSettings {
<#

.SYNOPSIS
Sets a computer's Hyper-V Host Storage Migration settings.

.DESCRIPTION
Sets a computer's Hyper-V Host Storage Migrtion settings.

.ROLE
Hyper-V-Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [int]
    $maximumStorageMigrations
    )

Set-StrictMode -Version 5.0
Import-Module Hyper-V

# Create arguments
$args = @{'MaximumStorageMigrations' = $maximumStorageMigrations; };

Set-VMHost @args

Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
    MaximumStorageMigrations

}
## [END] Set-WACSDDCHyperVHostStorageMigrationSettings ##
function Set-WACSDDCPowerConfigurationPlan {
<#

.SYNOPSIS
Sets the new power plan

.DESCRIPTION
Sets the new power plan using powercfg when changes are saved by user

.ROLE
Administrators

#>

param(
	[Parameter(Mandatory = $true)]
	[String]
	$PlanGuid
)

$Error.clear()
$message = ""

# If executing an external command, then the following steps need to be done to produce correctly formatted errors:
# Use 2>&1 to store the error to the variable. FD 2 is stderr. FD 1 is stdout.
# Watch $Error.Count to determine the execution result.
# Concatenate the error message to a single string and print it out with Write-Error.
$result = & 'powercfg' /S $PlanGuid 2>&1

# $LASTEXITCODE here does not return error code, so we have to use $Error
if ($Error.Count -ne 0) {
	foreach($item in $result) {
		if ($item.Exception.Message.Length -gt 0) {
			$message += $item.Exception.Message
		}
	}
	$Error.Clear()
	Write-Error $message
}

}
## [END] Set-WACSDDCPowerConfigurationPlan ##
function Set-WACSDDCRemoteDesktop {
<#

.SYNOPSIS
Sets a computer's remote desktop settings.

.DESCRIPTION
Sets a computer's remote desktop settings.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $False)]
    [boolean]
    $AllowRemoteDesktop,

    [Parameter(Mandatory = $False)]
    [boolean]
    $AllowRemoteDesktopWithNLA,

    [Parameter(Mandatory=$False)]
    [boolean]
    $EnableRemoteApp)

    Import-Module NetSecurity
    Import-Module Microsoft.PowerShell.Management

function Set-DenyTSConnectionsValue {
    Set-Variable RegistryKey -Option Constant -Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-Variable RegistryKeyProperty -Option Constant -Value 'fDenyTSConnections'

    $KeyPropertyValue = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })

    if (!(Test-Path $RegistryKey)) {
        New-Item -Path $RegistryKey -Force | Out-Null
    }

    New-ItemProperty -Path $RegistryKey -Name $RegistryKeyProperty -Value $KeyPropertyValue -PropertyType DWORD -Force | Out-Null
}

function Set-UserAuthenticationValue {
    Set-Variable RegistryKey -Option Constant -Value 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Set-Variable RegistryKeyProperty -Option Constant -Value 'UserAuthentication'

    $KeyPropertyValue = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })

    if (!(Test-Path $RegistryKey)) {
        New-Item -Path $RegistryKey -Force | Out-Null
    }

    New-ItemProperty -Path $RegistryKey -Name $RegistryKeyProperty -Value $KeyPropertyValue -PropertyType DWORD -Force | Out-Null
}

function Set-RemoteAppSetting {
    Set-Variable RegistryKey -Option Constant -Value 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList'
    Set-Variable RegistryKeyProperty -Option Constant -Value 'fDisabledAllowList'

    $KeyPropertyValue = $(if ($EnableRemoteApp -eq $True) { 1 } else { 0 })

    if (!(Test-Path $RegistryKey)) {
        New-Item -Path $RegistryKey -Force | Out-Null
    }

    New-ItemProperty -Path $RegistryKey -Name $RegistryKeyProperty -Value $KeyPropertyValue -PropertyType DWORD -Force | Out-Null
}

Set-DenyTSConnectionsValue
Set-UserAuthenticationValue
Set-RemoteAppSetting

Enable-NetFirewallRule -Group "@FirewallAPI.dll,-28752" -ErrorAction SilentlyContinue

}
## [END] Set-WACSDDCRemoteDesktop ##
function Set-WACSDDCSmbOverQuicServerSettings {
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
## [END] Set-WACSDDCSmbOverQuicServerSettings ##
function Set-WACSDDCSmbServerCertificateMapping {
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
## [END] Set-WACSDDCSmbServerCertificateMapping ##
function Set-WACSDDCSmbServerSettings {
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
## [END] Set-WACSDDCSmbServerSettings ##
function Set-WACSDDCSmeClusterGroupFailoverSettings {
<#

.SYNOPSIS
Sets the failover settings of a group in a failover cluster.

.DESCRIPTION
Sets the failover settings of a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

.PARAMETER failoverPeriod
The failover period of the group.

.PARAMETER autoFailbackType
The auto failback type of the group.

.PARAMETER failoverThreshold
The failover threshold of the group.

.PARAMETER failbackWindowStart
The failback window start of the group.

.PARAMETER failbackWindowEnd
The failback window end of the group.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$failoverPeriod,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$autoFailbackType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$failoverThreshold,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$failbackWindowStart,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$failbackWindowEnd
)
BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
    Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-SmeClusterGroupFailoverSettings" -Scope Script
}
PROCESS {
    <#

    .SYNOPSIS
    The main function.

    .DESCRIPTION
    The main function.

    #>

    function main([string]$groupId, [System.UInt32]$failoverPeriod, [System.UInt32]$autoFailbackType, [System.UInt32]$failoverThreshold, [System.UInt32]$failbackWindowStart, [System.UInt32]$failbackWindowEnd) {
        $err = $null

        $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err
        if ($group) {

            try {
                $group.failoverPeriod = $failoverPeriod
                $group.autoFailbackType = $autoFailbackType
                $group.failoverThreshold = $failoverThreshold
                $group.failbackWindowEnd = $failbackWindowEnd
                $group.failbackWindowStart = $failbackWindowStart
            } catch {
                $err = $_.Exception.Message
            }

            if (-not ($err)) {
                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
                    -Message "[$ScriptName]: Successfully changed the failover settings of cluster group $group." -ErrorAction SilentlyContinue

                return FailoverClusters\Get-ClusterGroup -Name $groupId |
                Microsoft.PowerShell.Utility\Select-Object `
                autoFailbackType, `
                FailoverPeriod, `
                FailoverThreshold, `
                FailbackWindowEnd, `
                FailbackWindowStart, `
                Id
            }
        }

        if ($err) {
            $e = @($err)[0]

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
                -Message "[$ScriptName]: Failed to change the failover settings of cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

            Write-Error $e
        }

        return @{}
    }

    ###############################################################################
    # Script execution starts here.
    ###############################################################################

    $returnVal = @{}

    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        $returnVal = main $groupId $failoverPeriod $autoFailbackType $failoverThreshold $failbackWindowStart $failbackWindowEnd
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
    }

return $returnVal
}
END {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

}
## [END] Set-WACSDDCSmeClusterGroupFailoverSettings ##
function Set-WACSDDCSmeClusterGroupGeneralSettings {
<#

.SYNOPSIS
Sets the general settings of a group in a failover cluster.

.DESCRIPTION
Sets the general settings of a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

.PARAMETER groupName
The name of the group.

.PARAMETER preferredOwners
The preferred owners of the group.

.PARAMETER priority
The priority of the group.

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupName,

    [Parameter(Mandatory = $true)]
    $preferredOwners,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.UInt32]$priority
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-SmeClusterGroupGeneralSettings" -Scope Script
    Set-Variable -Name PreferredOwnersPropertyName -Option ReadOnly -Value "PreferredOwners" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name PreferredOwnersPropertyName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId, [string] $groupName, [System.UInt32] $priority, $preferredOwners) {
    $err = $null

    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {

        try {
            $group.Name = $groupName
            $group.priority = $priority
        } catch {
            $err = $_.Exception.Message
        }

        if (-not ($err)) {
            if ("" -eq $preferredOwners) {
                $group | FailoverClusters\Set-ClusterOwnerNode "" -ErrorAction SilentlyContinue -ErrorVariable +err
            } else {
                $nodes = @()

                foreach ($owner in $preferredOwners) {
                    $nodes += $owner
                }

                $args = @{ Owners = $nodes }
                $group | FailoverClusters\Set-ClusterOwnerNode @args -ErrorAction SilentlyContinue -ErrorVariable +err
            }

            if (-not ($err)) {
                $ownerNodeList = $group | FailoverClusters\Get-ClusterOwnerNode
                $ownerNodes = $ownerNodeList.OwnerNodes

                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
                -Message "[$ScriptName]: Successfully changed the general settings of cluster group $group." -ErrorAction SilentlyContinue

                return FailoverClusters\Get-ClusterGroup -Name $groupId |
                Microsoft.PowerShell.Utility\Select-Object `
                Name, `
                Id, `
                Priority, `
                @{Name=$PreferredOwnersPropertyName; Expression={ $ownerNodes }}
            }
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to change the general settings of cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId $groupName $priority $preferredOwners
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Set-WACSDDCSmeClusterGroupGeneralSettings ##
function Set-WACSDDCSmeClusterGroupStartupPriority {
<#

.SYNOPSIS
Sets the startup priority of a group in a failover cluster.

.DESCRIPTION
Sets the startup priority of a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

.PARAMETER priority
The startup priority of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [System.String]$groupId,

    [Parameter(Mandatory = $true)]
    [System.UInt32]$priority
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Set-SmeClusterGroupPriority" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId, [System.UInt32] $priority) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {
        $oldName = $group.Name

        try {
            $group.Priority = $priority
        } catch {
            $err = $_.Exception.Message
        }

        if (-not ($err)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully changed the priority of cluster group $group." -ErrorAction SilentlyContinue

            return FailoverClusters\Get-ClusterGroup -Name $groupId | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to change the priority of cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId $priority
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Set-WACSDDCSmeClusterGroupStartupPriority ##
function Set-WACSDDCVcoAdmin {
<#

.SYNOPSIS
Check each node to ensure that the VCO (virtual computer object) for the cluster resource is in the local admin group

.DESCRIPTION
Scan cluster nodes to check if any updates are available.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0

Import-Module -Name CimCmdlets -ErrorAction SilentlyContinue
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

enum ExitCode {
    Success = 0
    AddAdministratorFailure = 1
    UnknownFailure = 2
    FailedToGetVCOUsername = 3
    RequiredModuleNotFound = 4
}

function getVCOUserName() {
    # Get the CAU group in the *most* robust way possible
    $cauGroup = (Get-ClusterResource -ErrorAction Stop | Where-Object {$_.ResourceType -eq "ClusterAwareUpdatingResource"}).OwnerGroup

    # Get the DNN cluster resource from the CAU group
    $cauDnn = $cauGroup | Get-ClusterResource -ErrorAction Stop | Where-Object {$_.ResourceType -eq "Distributed Network Name" }

    # Get the DnsName parameter of the DNN cluster resource, which acts as the username for the VCO
    $cauPublishedDnsName = (($cauDnn | Get-ClusterParameter -ErrorAction Stop) | Where-Object {$_.Name -eq "DnsName"}).ClusterObject.Name
    return $cauPublishedDnsName
}

function addVCOAdmin() {
    $cauPublishedDnsName = getVCOUserName
    if ($null -eq $cauPublishedDnsName) {
        return [ExitCode]::FailedToGetVCOUsername
    }

    $domains = Get-CimInstance Win32_NTDomain -ErrorAction Stop
    foreach ($domain in $domains) {
        # creating format of domain\cauPublishedDnsName$
        $name = $domain.DomainName + '\' + $cauPublishedDnsName + '$'

        # Check if this 'user'/VCO is already an admin on the node. If it is not, try to add it.
        $existingAdmin = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -eq $name }
        if ($null -ne $existingAdmin) {
            return [ExitCode]::Success
        }

        Add-LocalGroupMember -Group "Administrators" -Member $name -ErrorAction SilentlyContinue -ErrorVariable +err
        if ($null -eq $err) {
            return [ExitCode]::Success
        }
    }

    return [ExitCode]::AddAdministratorFailure
}

function main() {
    <#
        There are 2 scenarios for domains w/ CAU:
        1. Domain joined cluster (Use VCO for authentication in self-updating mode)
        2. Domain-less cluster (User has to set up custom configuration for auth.)
        We are handling case #1 here. The VCO has to be in the local administrator group on each node, or the update will not kick off.
    #>

    # If the administrative access point is ActiveDirectoryAndDns, we can assume that we are in case #1 (domain joined)
    $adminAccessPoint = (Get-Cluster).AdministrativeAccessPoint

    if ($adminAccessPoint -eq "ActiveDirectoryAndDns") {
        return addVCOAdmin
    }

    return [ExitCode]::Success
}

########
# Main
########
if (-not ($env:pester)) {
    $module = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    if ($module) {
        return main
    }
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
    -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue
    return [ExitCode]::RequiredModuleNotFound
}




}
## [END] Set-WACSDDCVcoAdmin ##
function Start-WACSDDCClusterUpdateRun {

<#

.SYNOPSIS
Starts cluster update.

.DESCRIPTION
Starts cluster update.

.ROLE
Administrators

#>
Param
(
    [Object] $cauRunDetails
)
Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

function getArguments([Object] $cauRunDetails) {
    $arguments = @{}

    $arguments.Add('ClusterName', $cauRunDetails.clusterName)

    if ($cauRunDetails.preUpdateScript) {
        $arguments.Add('PreUpdateScript', $cauRunDetails.preUpdateScript)
    }
    if ($cauRunDetails.postUpdateScript) {
        $arguments.Add('PostUpdateScript', $cauRunDetails.postUpdateScript)
    }
    if ($cauRunDetails.disableKernelSoftReboot) {
        $arguments.Add('RebootMode', 'FullReboot')
    }

    # Storing the optional parmeters in dictionary to pass it to Set-CauClusterRole.
    foreach($parameter in $cauRunDetails.optionalParameters){
        $key,$value = $parameter.Split(' ')
        $arguments.Add($key, $value)
    }

    # Gets the plugin names list and the plugin arguments list
    $allPluginNames = @()
    $allPluginArguments = @()
    foreach ($plugin in $cauRunDetails.pluginList) {
        $allPluginNames += $plugin.name

        $pluginArguments = @{}
        foreach ($argument in $plugin.arguments ) {
            $pluginArguments.Add($argument.key, $argument.value)
        }
        $allPluginArguments += $pluginArguments
    }
    $arguments.Add('CauPluginName', $allPluginNames)
    $arguments.Add('CauPluginArguments', $allPluginArguments)

    $arguments.Add('Force', $null)
    $arguments.Add('UseDefault', $null)
    $arguments.Add('EnableFirewallRules', $null)

    return $arguments
}

function main([Object] $cauRunDetails) {

    $arguments = getArguments $cauRunDetails

    # TODO: Must use Set-CauClusterRole when the orchestrator is one of the cluster nodes (not external).
    # Eventually, it should be replaced with Invoke-CauRun once that functionality is implemented from the CAU team.
    # Right now, the -clusterName parameter in the first call of Set-CauClusterRole has to be non-FQDN or the run will not kick off. This needs to be fixed by the CAU team.
    Set-CauClusterRole @arguments;

    Start-Sleep -seconds 10;

    Set-CauClusterRole -clusterName $cauRunDetails.clusterName -UpdateNow -Force;
}

########
# Main
########
if (-not ($env:pester)) {
    $failoverClusterModule = Get-Module FailoverClusters -ErrorAction SilentlyContinue
    $powershellManagementModule = Get-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
    $clusterAwareUpdatingModule = Get-Module ClusterAwareUpdating -ErrorAction SilentlyContinue

    if ($failoverClusterModule -and $powershellManagementModule -and $clusterAwareUpdatingModule) {
        return main $cauRunDetails
    }

    if (-not $failoverClusterModule) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found."  -ErrorAction SilentlyContinue
    }

    if (-not $powershellManagementModule) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (Microsoft.PowerShell.Management) was not found."  -ErrorAction SilentlyContinue
    }

    if (-not $clusterAwareUpdatingModule) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Warning `
        -Message "[$ScriptName]: The required PowerShell module (ClusterAwareUpdating) was not found."  -ErrorAction SilentlyContinue
    }
}

}
## [END] Start-WACSDDCClusterUpdateRun ##
function Start-WACSDDCDiskPerf {
<#

.SYNOPSIS
Start Disk Performance monitoring.

.DESCRIPTION
Start Disk Performance monitoring.

.ROLE
Administrators

#>

# Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
#   EnableCounterForIoctl = DWORD 3
& diskperf -Y

}
## [END] Start-WACSDDCDiskPerf ##
function Start-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Starts a group in a failover cluster.

.DESCRIPTION
Starts a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Start-SmeClusterGroup" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {
        $group | FailoverClusters\Start-ClusterGroup -Wait 0 -ErrorAction SilentlyContinue -ErrorVariable +err

        if (-not ($err)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully started cluster group $group." -ErrorAction SilentlyContinue

            return FailoverClusters\Get-ClusterGroup -Name $groupId | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to start cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Start-WACSDDCSmeClusterGroup ##
function Start-WACSDDCSmeClusterResource {
<#

.SYNOPSIS
Starts a resource in a failover cluster.

.DESCRIPTION
Starts a resource in a failover cluster.

.ROLE
Administrators

.PARAMETER ResourceId
The unique identifier of the resource.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$ResourceId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Start-ClusterResource -Name $ResourceId -Wait 0

}
## [END] Start-WACSDDCSmeClusterResource ##
function Start-WACSDDCSmeClusterService {
<#

.SYNOPSIS
Starts the failover cluster service.

.DESCRIPTION
Starts the failover cluster service.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Start-Service -Name "ClusSvc"

}
## [END] Start-WACSDDCSmeClusterService ##
function Start-WACSDDCSolutionUpdate {
<#

.SYNOPSIS
Starts a solution update.

.DESCRIPTION
Starts a solution update.

.ROLE
Administrators
#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $updateId
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.AzureStack.Lcm.PowerShell -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Start-SolutionUpdate.ps1"

Start-SolutionUpdate -Id $updateId -ErrorAction SilentlyContinue -ErrorVariable +err

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error starting the solution update.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Start-WACSDDCSolutionUpdate ##
function Stop-WACSDDCCimOperatingSystem {
<#

.SYNOPSIS
Shutdown Windows Operating System by using Win32_OperatingSystem provider.

.DESCRIPTION
Shutdown Windows Operating System by using Win32_OperatingSystem provider.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[boolean]$primary
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem -Key @('primary') -Property @{primary=$primary;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName Shutdown

}
## [END] Stop-WACSDDCCimOperatingSystem ##
function Stop-WACSDDCClusterUpdateRun {

<#

.SYNOPSIS
Stops currently running cluster update.

.DESCRIPTION
Stops currently running cluster update.

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

Stop-CauRun -ClusterName $clusterName -Force

}
## [END] Stop-WACSDDCClusterUpdateRun ##
function Stop-WACSDDCDiskPerf {
<#

.SYNOPSIS
Stop Disk Performance monitoring.

.DESCRIPTION
Stop Disk Performance monitoring.

.ROLE
Administrators

#>

# Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
#   EnableCounterForIoctl = DWORD 1
& diskperf -N


}
## [END] Stop-WACSDDCDiskPerf ##
function Stop-WACSDDCSmeClusterGroup {
<#

.SYNOPSIS
Stops a group in a failover cluster.

.DESCRIPTION
Stops a group in a failover cluster.

.ROLE
Administrators

.PARAMETER groupId
The unique identifier of the group.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$groupId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Stop-SmeClusterGroup" -Scope Script
}

<#

.SYNOPSIS
Clean up the script environment.

.DESCRIPTION
Clean up the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
The main function.

#>

function main([string] $groupId) {
    $group = FailoverClusters\Get-ClusterGroup -Name $groupId -ErrorAction SilentlyContinue -ErrorVariable +err

    if ($group) {
        $group | FailoverClusters\Stop-ClusterGroup -Wait 0 -ErrorAction SilentlyContinue -ErrorVariable +err

        if (-not ($err)) {
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType SuccessAudit `
            -Message "[$ScriptName]: Successfully stopped cluster group $group." -ErrorAction SilentlyContinue

            return FailoverClusters\Get-ClusterGroup -Name $groupId | Microsoft.PowerShell.Utility\Select-Object Name, Id, State, GroupType, OwnerNode, Priority
        }
    }

    if ($err) {
        $e = @($err)[0]

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType FailureAudit `
        -Message "[$ScriptName]: Failed to stop cluster group $groupId. The error is: $e." -ErrorAction SilentlyContinue

        Write-Error $e
    }

    return @{}
}

###############################################################################
# Script execution starts here.
###############################################################################

setupScriptEnv

$returnVal = @{}

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

$module = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if ($module) {
    $returnVal = main $groupId
} else {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: Cannot continue because required Failover Clusters PowerShell module was not found." -ErrorAction SilentlyContinue
}

cleanupScriptEnv

return $returnVal

}
## [END] Stop-WACSDDCSmeClusterGroup ##
function Stop-WACSDDCSmeClusterResource {
<#

.SYNOPSIS
Stops a resource in a failover cluster.

.DESCRIPTION
Stops a resource in a failover cluster.

.ROLE
Administrators

.PARAMETER ResourceId
The unique identifier of the resouce.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$ResourceId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Stop-ClusterResource -Name $ResourceId -Wait 0
}
## [END] Stop-WACSDDCSmeClusterResource ##
function Stop-WACSDDCSmeClusterService {
<#

.SYNOPSIS
Stops the failover cluster service.

.DESCRIPTION
Stops the failover cluster service.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Stop-Service -Name "ClusSvc" -Force

}
## [END] Stop-WACSDDCSmeClusterService ##
function Suspend-WACSDDCSmeClusterNode {
<#

.SYNOPSIS
Pauses a failover cluster node.

.DESCRIPTION
Pauses a failover cluster node.

.ROLE
Administrators

.PARAMETER NodeName
The name of the node.

.PARAMETER DrainRoles
Whether to drain the node roles.

#>
Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$NodeName,

    [Parameter(Mandatory = $false)]
    [Switch]$DrainRoles
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

$node = FailoverClusters\Get-ClusterNode -Name $NodeName

if ($DrainRoles) {
    $node | FailoverClusters\Suspend-ClusterNode -Drain -ForceDrain
} else {
    $node | FailoverClusters\Suspend-ClusterNode
}

}
## [END] Suspend-WACSDDCSmeClusterNode ##
function Test-WACSDDCClusterAwareUpdatingRole {
<#

.SYNOPSIS
Tests whether the cluster aware updating role is present.

.DESCRIPTION
Tests whether the cluster aware updating role is present.

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

function Test-ClusterAwareUpdatingRole {
    $role = Get-CauClusterRole -ClusterName $clusterName -ErrorAction SilentlyContinue
    return $null -ne $role;
}

########
# Main
########
Test-ClusterAwareUpdatingRole

}
## [END] Test-WACSDDCClusterAwareUpdatingRole ##
function Test-WACSDDCClusterUpdateReadiness {
<#

.SYNOPSIS
Tests whether the cluster is prepared to use cluster aware updating.

.DESCRIPTION
Tests whether the cluster is prepared to use cluster aware updating.

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [String] $clusterName
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-Module -Name ClusterAwareUpdating -ErrorAction SilentlyContinue

function Test-ClusterUpdateReadiness {
    Test-CauSetup -ClusterName $clusterName -WarningAction SilentlyContinue | Where-Object { (Get-Member -InputObject $_ -Name "RuleId" -MemberType Properties) -and ($null -ne $_.RuleId) } | Microsoft.PowerShell.Utility\Select-Object FailedMachines,
    PercentComplete,
    RuleId,
    @{Name = "Severity"; Expression = {$_.Severity.value__}},
    @{Name = "State"; Expression = {$_.State.value__}},
    Title
}

########
# Main
########

Test-ClusterUpdateReadiness

}
## [END] Test-WACSDDCClusterUpdateReadiness ##
function Test-WACSDDCFileSystemEntity {
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
## [END] Test-WACSDDCFileSystemEntity ##
function Test-WACSDDCSmeCluster {
<#

.SYNOPSIS
Runs cluster validation on the current cluster.

.DESCRIPTION
Runs cluster validation on the current cluster.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

FailoverClusters\Test-Cluster

}
## [END] Test-WACSDDCSmeCluster ##
function Test-WACSDDCSmeClusterResourceFailure {
<#

.SYNOPSIS
Simulates resource failure in a failover cluster.

.DESCRIPTION
Simulates resource failure in a failover cluster.

.ROLE
Administrators

.PARAMETER ResourceId
The unique identifier of the resource.

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [System.String]$ResourceId
)

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

FailoverClusters\Test-ClusterResourceFailure -Name $ResourceId
FailoverClusters\Get-ClusterResource -Name $ResourceId

}
## [END] Test-WACSDDCSmeClusterResourceFailure ##
function Uninstall-WACSDDCSmb1 {
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
## [END] Uninstall-WACSDDCSmb1 ##
function Update-WACSDDCClusterFunctionalLevel {
<#
.SYNOPSIS
    Updates the cluster functional level.
.DESCRIPTION
    Updates the cluster functional level.
.ROLE
    Administrators
#>

Set-StrictMode -Version 5.0

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

$err = $null
$LogName = "WindowsAdminCenter"
$LogSource = "msft.sme.failover-cluster"
$ScriptName = "Update-ClusterFunctionalLevel.ps1"

Update-ClusterFunctionalLevel -Force -ErrorAction SilentlyContinue -ErrorVariable +err

if (!!$err) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]: There was an error updating the cluster functional level.  Error: $err" -ErrorAction SilentlyContinue

    Write-Error @($err)[0]
}

}
## [END] Update-WACSDDCClusterFunctionalLevel ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZM1AbdWaMS2Fd
# XakRkxAw0zW0ui0I/ay0aDRZIUjYgKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJgVxcJQeSlwN4zu+ay3svb+
# WyDPU3FHLIPzXDivtapqMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAi4IeKZD1/izv3ovJC2heZuTCJKz0O5f+U4HX9fpH8xq7IfyVIV5O+Bam
# 4CUCF+lwrFL/jiWYDLcqb5Hs67Pz6mgDwjTiDFGfNuXyBKVazEUEQ9vXAjczFNOR
# WwtPHu9VfNPEXdEXplAPp5djNKKLA4jxGGMqaSdpobynGYViflRMbfSywvifWYJM
# r8LdXKQe8f3ma6bPg8jYvJ7xXsrzDh/4Gc59sij5v9//4Z2g3oFjpRaAHX0bIQ0s
# KWDzqnb7WlaBHtAbVoRWpXbj7Op9zlOreooDRPYz2x64GQGUUTdoUgaxxsmKOm0T
# ZNwS6aj+O9W9hn3kgebch4y3qyLwH6GCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDa0euZbYJDc8+d/cQCAn9NP5lriwjl8dc4ZywG6F2inwIGaPC4AINP
# GBMyMDI1MTExMDE3MTcxOC41MDFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAg9XmkcUQOZG5gABAAACDzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQz
# MDRaFw0yNjA0MjIxOTQzMDRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCl6DTurxf66o73G0A2yKo1/nYvITBQsd50F52SQzo2
# cSrt+EDEFCDlSxZzWJD7ujQ1Z1dMbMT6YhK7JUvwxQ+LkQXv2k/3v3xw8xJ2mhXu
# wbT+s1WOL0+9g9AOEAAM6WGjCzI/LZq3/tzHr56in/Z++o/2soGhyGhKMDwWl4J4
# L1Fn8ndtoM1SBibPdqmwmPXpB9QtaP+TCOC1vAaGQOdsqXQ8AdlK6Vuk9yW9ty7S
# 0kRP1nXkFseM33NzBu//ubaoJHb1ceYPZ4U4EOXBHi/2g09WRL9QWItHjPGJYjuJ
# 0ckyrOG1ksfAZWP+Bu8PXAq4s1Ba/h/nXhXAwuxThpvaFb4T0bOjYO/h2LPRbdDM
# cMfS9Zbhq10hXP6ZFHR0RRJ+rr5A8ID9l0UgoUu/gNvCqHCMowz97udo7eWODA7L
# aVv81FHHYw3X5DSTUqJ6pwP+/0lxatxajbSGsm267zqVNsuzUoF2FzPM+YUIwiOp
# gQvvjYIBkB+KUwZf2vRIPWmhAEzWZAGTox/0vj4eHgxwER9fpThcsbZGSxx0nL54
# Hz+L36KJyEVio+oJVvUxm75YEESaTh1RnL0Dls91sBw6mvKrO2O+NCbUtfx+cQXY
# S0JcWZef810BW9Bn/eIvow3Kcx0dVuqDfIWfW7imeTLAK9QAEk+oZCJzUUTvhh2h
# YQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFJnUMQ2OtyAhLR/MD2qtJ9lKRP9ZMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBTowbo1bUE7fXTy+uW9m58qGEXRBGVMEQi
# FEfSui1fhN7jS+kSiN0SR5Kl3AuV49xOxgHo9+GIne5Mpg5n4NS5PW8nWIWGj/8j
# kE3pdJZSvAZarXD4l43iMNxDhdBZqVCkAYcdFVZnxdy+25MRY6RfaGwkinjnYNFA
# 6DYL/1cxw6Ya4sXyV7FgPdMmxVpffnPEDFv4mcVx3jvPZod7gqiDcUHbyV1gaND3
# PejyJ1MGfBYbAQxsynLX1FUsWLwKsNPRJjynwlzBT/OQbxnzkjLibi4h4dOwcN+H
# 4myDtUSnYq9Xf4YvFlZ+mJs5Ytx4U9JVCyW/WERtIEieTvTRgvAYj/4Mh1F2Elf8
# cdILgzi9ezqYefxdsBD8Vix35yMC5LTnDUoyVVulUeeDAJY8+6YBbtXIty4phIki
# hiIHsyWVxW2YGG6A6UWenuwY6z9oBONvMHlqtD37ZyLn0h1kCkkp5kcIIhMtpzEc
# PkfqlkbDVogMoWy80xulxt64P4+1YIzkRht3zTO+jLONu1pmBt+8EUh7DVct/33t
# uW5NOSx56jXQ1TdOdFBpgcW8HvJii8smQ1TQP42HNIKIJY5aiMkK9M2HoxYrQy2M
# oHNOPySsOzr3le/4SDdX67uobGkUNerlJKzKpTR5ZU0SeNAu5oCyDb6gdtTiaN50
# lCC6m44sXjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQ
# MIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjMzMDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBe
# tIzj2C/MkdiI03EyNsCtSOMdWqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwoxTAiGA8yMDI1MTExMDA5MDMw
# MVoYDzIwMjUxMTExMDkwMzAxWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvCjF
# AgEAMAoCAQACAhyzAgH/MAcCAQACAhLrMAoCBQDsvXpFAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAGPxkuwiqVjmFwHtyH7vaBk6eSwEkK9NLuckWmhhwjWV
# DdmQJ7s2wepvoTY+vNfMlw4juJqYiafX/JCrXxVDsjnSzdY/g5K2GTCJORI25PQR
# ZjV6C/sO6xg/vLp8u/792rgIC5z3awDGDRIL6uriV644HGlHXS3S7HLAcVmHewHg
# mRN1/7hYvFEoLHDiJYSnvIoUoTkQtJbGS6Zwnd4Vy0VFHPN7bthlgyLSo/T2HIdZ
# mPDzoaUCipnYmUAbAyShCMF/7U2GjdW02ZYTWANVkAHqYiOJVNK++jvbdvbKLpHG
# vnQZnyk/t5iwixLHvgP6i1HyJZ5UugQBWu71HwwxDTAxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAg9XmkcUQOZG5gABAAAC
# DzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCFg4SdJbUovjE6wGNfQE4rbdWQbU0o+hKHbVqwF6Vc
# 6zCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIN1Hd5UmKnm7FW7xP3niGsfH
# Jt4xR8Xu+MxgXXc0iqn4MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIPV5pHFEDmRuYAAQAAAg8wIgQgrWNCvaOBX7TMdMxI2uEPazgw
# U1Z8Q8qGTlBvTOzmiKIwDQYJKoZIhvcNAQELBQAEggIAmVmQPepOEBfshdoFGzjJ
# PzBpaGp5C5tVScjXuhbWBw7VvyS7VvAG5N4I7PtCwgdvUE+3e9Tml/BG35oZ92LT
# ZtBw9rFzhZWsorcLZn7mAzKzmAZTe3g/zmQMre9r2twU5xU9yVgUFMPxwkdHqVe5
# XVNZl4Yuyjxb4w7tqWvI09wQkg0AsqdNWhZqCQ2FiluEz4+U6NLEF0dLFKT04a4W
# 6NJRa04CNieUV9deA8xyILONdLV5pVDAnyQoa46uxWW7tta9Dtdax4ttsSFcMDip
# BgE0kA/rQpT+pi19A7KWAYVbmwWwgw4+SW/o5wE3b/BxFShtiCB/hy0HrNZfuy8A
# sYp0OoWUPQ42Y7aKAS85mgVtxPSvbcMEs4YgRpTvaU1lYoDAXpNEc6yucVAWxdAm
# Bv8mdJw9d6tkRr246YbKhldmCOyIF+BRXzioYa7O9Kwed3/SsYzDJSV0Xa6e4tXj
# m/5/Bs1OSrarntvkl8QGC3Qyq9fJxIqHsKj3welc1DCF2eQS8uwydO0lP/pta0XJ
# ip14ebYLf/Sj3+XeSE2AgAVnt2bK0UzGMAGEj8Hv13qd9Gov1y+PSsloBc9LBRus
# hZRya585LnIU7q6xZBId54wOrlPVFPTg+9zEb1Sj5N65fwLb0HjGBtGjbWaAdvW5
# 3ydHhLIlRODXB/ipViU4wzM=
# SIG # End signature block
