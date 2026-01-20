function Get-DefaultNetworkPolicySupport {
<#

.SYNOPSIS
Get whether a "disable DNP" key is present on the cluster node

.DESCRIPTION
Get whether a "disable DNP" key is present on the cluster node

.ROLE
Readers

#>

Try {
  $disableDNPkeys = (
      (Get-ItemProperty -Path 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -ErrorAction Stop).PP1 |
      Where-Object { $_ -eq "DisableDefaultNetworkPolicies" });

  $null -ne $disableDNPkeys.length -and $disableDNPkeys.length -gt 0
}
Catch [System.Management.Automation.ItemNotFoundException] {
  # Key doesn't exist so keep hasKey as it was
  $false
}

}
## [END] Get-DefaultNetworkPolicySupport ##
function Get-IpPools {
<#

.SYNOPSIS
Get IpPool properties in this cluster

.DESCRIPTION
This script is used to List all IpPools available in the Subnet, Logical network or cluster.
When the subnetName and logicalNetworkName are provided, the IP Pools for that particular subnet are returned.
When the logicalNetworkName is provided without a subnet name, the IP pools for that entire network are returned.
When logicalNetworkName is missing, all IP pools for the cluster are returned.

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $False)]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Version 5.0

$subnet = $null
if ((-not [string]::IsNullOrEmpty($subnetName)) -and (-not [string]::IsNullOrEmpty($logicalNetworkName))) {
  $subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash
} elseif (-not [string]::IsNullOrEmpty($logicalNetworkName)) {
  $subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName @paramsHash
} else {
  $networks = (Get-NetworkControllerLogicalNetwork @paramsHash)
  if ($null -ne $networks) {
    $subnet = $networks.properties.subnets
  }
}

#Fetch the IPPools list
$ipPools = $subnet.Properties.IpPools

foreach($ipPool in $ipPools)
{
  if ($null -eq $ipPool) {
    continue;
  }
  $ipPoolName = $ipPool.ResourceRef.split('/')[6]
  $startIpAddress = $ipPool.Properties.StartIpAddress
  $endIpAddress = $ipPool.Properties.EndIpAddress
  $usage = $ipPool.Properties.Usage
  $provisioningState = $ipPool.Properties.ProvisioningState
  if ($null -ne $ipPool.Properties.LoadBalancerManager) {
    $loadBalancerManager = $ipPool.Properties.LoadBalancerManager.ResourceRef
  } else {
    $loadBalancerManager = $null
  }

  # Preparing Object Response
  $myResponse = New-Object -TypeName psobject
  $myResponse | Add-Member -MemberType NoteProperty -Name 'IpPoolName' -Value $ipPoolName -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'StartIpAddress' -Value $startIpAddress -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'EndIpAddress' -Value $endIpAddress -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'Usage' -Value $usage -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'LoadBalancerManager' -Value $loadBalancerManager -ErrorAction SilentlyContinue
  $myResponse
}

}
## [END] Get-IpPools ##
function Get-L3VirtualGatewayConnections {
<#

.SYNOPSIS
Get L3 Virtual Gatewaty Connection of Logical Network

.DESCRIPTION
This script is used to Get L3 Virtual Gatewaty Connection of Logical Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
$l3VirtualGatewayConnections = $logicalNetworkNames.Properties.Subnets.Properties.NetworkConnections
if($l3VirtualGatewayConnections.length -gt 0)
{
    $l3VirtualGatewayConnectionsIDs = $l3VirtualGatewayConnections.ResourceRef

    $l3vgcNames = ""
    $l3vgcNames = @()
    foreach($l3VirtualGatewayConnectionsID in $l3VirtualGatewayConnectionsIDs)
    {
        $l3vgcName = $l3VirtualGatewayConnectionsID.split('/')[4]
        $l3vgcNames += $l3vgcName

    }
}
else
{
   $l3vgcNames = @()
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'L3VirtualGatewayConnection' -Value $l3vgcNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-L3VirtualGatewayConnections ##
function Get-LogicalNetworkDetails {
<#

.SYNOPSIS
Get Selected Logical Networks

.DESCRIPTION
This script is used to get Selected Logical Networks details

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $selectedLogicalNetwork,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetwork = Get-NetworkControllerLogicalNetwork -ResourceId $selectedLogicalNetwork @paramsHash


foreach($logicalNetworkName in $logicalNetwork)
{

    $resourecID = $logicalNetworkName.ResourceId
    $subnetCount = $logicalNetworkName.Properties.Subnets.Count
    $networkVirutalization = $logicalNetworkName.Properties.NetworkVirtualizationEnabled
    $provisioningState = $logicalNetworkName.Properties.ProvisioningState
    if($provisioningState -eq 'Succeeded')
    {
        $state = "Healthy"
    }
    else
    {
        $state = "Unhealthy"
    }
    $virutualNetworkCount = $logicalNetworkName.Properties.VirtualNetworks.Count
    $instanceID = $logicalNetworkName.InstanceId

    # Preparing Object Response

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $resourecID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnetCount' -Value $subnetCount -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkVisualizationState' -Value $networkVirutalization -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'State' -Value $state -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'virtualNetworksdependencyCount' -Value $virutualNetworkCount -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceID -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-LogicalNetworkDetails ##
function Get-LogicalNetworks {
<#

.SYNOPSIS
Get Logical Networks

.DESCRIPTION
This script is used to List all Logical Networks available in the Cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetwork = Get-NetworkControllerLogicalNetwork @paramsHash

foreach($logicalNetworkName in $logicalNetwork)
{
    $resourecID = $logicalNetworkName.ResourceId
    $subnetCount = $logicalNetworkName.Properties.Subnets.Count
    $networkVirutalization = $logicalNetworkName.Properties.NetworkVirtualizationEnabled
    $provisioningState = $logicalNetworkName.Properties.ProvisioningState
    if($provisioningState -eq 'Succeeded')
    {
        $state = "Healthy"
    }
    else
    {
        $state = "Unhealthy"
    }
    $virutualNetworkCount = $logicalNetworkName.Properties.VirtualNetworks.Count
    $instanceID = $logicalNetworkName.InstanceId

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $resourecID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnetCount' -Value $subnetCount -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkVisualizationState' -Value $networkVirutalization -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'State' -Value $state -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'virtualNetworksdependencyCount' -Value $virutualNetworkCount -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceID -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-LogicalNetworks ##
function Get-LogicalSubnets {
<#

.SYNOPSIS
Get Subnets in logical network

.DESCRIPTION
This script is used to List all Subnets available in the Logical Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
$subnets = $logicalNetworkNames.Properties.Subnets
foreach($subnet in $subnets)
{
    $subnetID = $subnet.ResourceId
    $vLanID = $subnet.Properties.VlanID
    $addressPrefix = $subnet.Properties.AddressPrefix
    $dnsServers = $subnet.Properties.DnsServers
    $defaultGateways = $subnet.Properties.DefaultGateways
    $isPublic = $subnet.Properties.IsPublic
    $provisioningState = $subnet.Properties.ProvisioningState
    $numberofIPAddressesAllocated = $subnet.Properties.Usage.NumberofIPAddressesAllocated
    $numberOfIPAddressesInTransition = $subnet.Properties.Usage.NumberOfIPAddressesInTransition
    $numberOfIPAddresses = $subnet.Properties.Usage.NumberOfIPAddresses
    $gatewayPools = $subnet.Properties.GatewayPools
    if($gatewayPools.length -gt 0)
    {
        $gatewayPoolIDs = $gatewayPools.ResourceRef
        $gatewayPoolNames = " "
        $gatewayPoolNames = @()
        foreach($gatewayPoolID in $gatewayPoolIDs)
        {
            $gatewayPoolName = $gatewayPoolID.split('/')[2]
            $gatewayPoolNames += $gatewayPoolName
        }

    }
    else
    {
        $gatewayPoolNames = @()
    }

    if ($null -ne $subnet.Properties.IpReservationss)
    {
      $numberOfIpReservations = $subnet.Properties.IpReservations.Count
    }
    else
    {
      $numberOfIpReservations  = 0
    }

    $ipPools = $subnet.Properties.IpPools.Count
    $aclListName = $subnet.Properties.AccessControlList

    #Prepare Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SubnetName' -Value $subnetID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VlanID' -Value $vLanID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AddressSpace' -Value $addressPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DnsServers' -Value $dnsServers -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DefaultGateways' -Value $defaultGateways -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IsPublic' -Value $isPublic -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'State' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIPAddressesAllocated' -Value $numberofIPAddressesAllocated -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfIPAddressesInTransition' -Value $numberOfIPAddressesInTransition -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIPAddresses' -Value $numberofIPAddresses -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPools' -Value $gatewayPoolNames -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfIpReservations' -Value $numberOfIpReservations -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIpPools' -Value $ipPools -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkName' -Value $logicalNetworkName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NsgGroupName' -Value $aclListName -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-LogicalSubnets ##
function Get-NetworkSecurityGroupsAll {
<#

.SYNOPSIS
Gets a Security group(ACL) from a given network controller.

.DESCRIPTION
Gets a security group (ACL) object from the SDN Network Controller.

.ROLE
Readers

.PARAMETER restParams
The REST parameters used to connect to the SDN Network controller
#>
param (
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Version 5.0

$acls = Get-NetworkControllerAccessControlList @paramsHash
foreach($acl in $acls) {
  $acl
}

}
## [END] Get-NetworkSecurityGroupsAll ##
function Get-SDNGatewayVirtualMachineConnectionInstanceID {
<#

.SYNOPSIS
Get InstanceID of SDN Gateway Virtual Machine Connection

.DESCRIPTION
This script is used to get InstanceID of SDN Gateway Virtual Machine Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $SDNGatewayVirtualMachineConnectionName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$instance = Get-NetworkControllerNetworkInterface  -resourceid $SDNGatewayVirtualMachineConnectionName @paramsHash
$instanceId = $instance.InstanceId

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceId -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SDNGatewayVirtualMachineConnectionInstanceID ##
function Get-SDNGatewayVirtualMachineConnections {
<#

.SYNOPSIS
Get VM Names of IpConfigurations in Logical network for SDN Gateway Virtual Machine Connection

.DESCRIPTION
This script is used to List all VM Names of IpConfigurations available in the Logical Network for SDN Gateway Virtual Machine Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get VM Names of IpConfigurations in Logical network for SDN Gateway Virtual Machine Connection

#Fetch the Logical Network
$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash

#Fetch the IP Configuration Names
$ipConfigurations = $logicalNetworkNames.Properties.Subnets.Properties.IpConfigurations

if($ipConfigurations.length -gt 0)
{
    $ipConfigurationNames = $ipConfigurations.ResourceRef
    $ipcgNames = " "
    $ipcgNames = @()
    foreach($ipConfigurationName in $ipConfigurationNames)
    {
        if($ipConfigurationName.split('/')[1] -eq "networkInterfaces")
        {
            $ipcName = $ipConfigurationName.split('/')[2]
            $ipcgNames += $ipcName
        }
    }
    $vmNames = ""
    $vmNames = @()
    foreach($ipcgName in $ipcgNames)
    {
        #Fetch the VM Names
        $networkInterfaces = Get-NetworkControllerNetworkInterface -ResourceId $ipcgName @paramsHash
        $gateway = $networkInterfaces.Properties.Gateway
        if($gateway -ne $null)
        {
            $vmName = $gateway.ResourceRef.split('/')[2]
            $vmNames += $vmName
        }
    }
}
else
{
    $vmNames = @()
}

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'SDNGatewayVirtualMachineConnection' -Value $vmNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SDNGatewayVirtualMachineConnections ##
function Get-SecurityTags {
<#

.SYNOPSIS
Gets a Security tag from a given network controller.

.DESCRIPTION
Gets a security tag object from the SDN Network Controller.

.ROLE
Readers

.PARAMETER restParams
The REST parameters used to connect to the SDN Network controller
#>
param (
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Version 5.0

# We're only doing this to see if it throws an error, so return type as-is
Get-NetworkControllerSecurityTag @paramsHash

}
## [END] Get-SecurityTags ##
function Get-SelectedLogicalSubnetDetails {
<#

.SYNOPSIS
Get selected Subnets in logical network

.DESCRIPTION
This script is used to get selected Subnets available in the Logical Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkSubnetName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
$subnets = $logicalNetworkNames.Properties.Subnets
$subnet = $null
$subnet = $subnets | Where { $_.ResourceId -ieq $logicalNetworkSubnetName }
if($null -ne $subnet){
    $subnetID = $subnet.ResourceId
    $vLanID = $subnet.Properties.VlanID
    $addressPrefix = $subnet.Properties.AddressPrefix
    $dnsServers = $subnet.Properties.DnsServers
    $defaultGateways = $subnet.Properties.DefaultGateways
    $isPublic = $subnet.Properties.IsPublic
    $provisioningState = $subnet.Properties.ProvisioningState
    $numberofIPAddressesAllocated = $subnet.Properties.Usage.NumberofIPAddressesAllocated
    $numberOfIPAddressesInTransition = $subnet.Properties.Usage.NumberOfIPAddressesInTransition
    $numberOfIPAddresses = $subnet.Properties.Usage.NumberOfIPAddresses
    $gatewayPools = $subnet.Properties.GatewayPools
    if($gatewayPools.length -gt 0)
    {
        $gatewayPoolIDs = $gatewayPools.ResourceRef
        $gatewayPoolNames = " "
        $gatewayPoolNames = @()
        foreach($gatewayPoolID in $gatewayPoolIDs)
        {
            $gatewayPoolName = $gatewayPoolID.split('/')[2]
            $gatewayPoolNames += $gatewayPoolName
        }
    }
    else
    {
        $gatewayPoolNames = @()
    }


    if ($null -ne $subnet.Properties.IpReservations) {
      $numberOfIpReservations = $subnet.Properties.IpReservations.Count
    }
    else {
      $numberOfIpReservations = 0
    }

    if($null -ne $subnet.Properties.IpPools)
    {
      $ipPools = $subnet.Properties.IpPools.Count
    }
    else
    {
      $ipPools = 0
    }

    #Prepare Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SubnetName' -Value $subnetID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VlanID' -Value $vLanID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AddressSpace' -Value $addressPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DnsServers' -Value $dnsServers -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DefaultGateways' -Value $defaultGateways -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IsPublic' -Value $isPublic -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'State' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIPAddressesAllocated' -Value $numberofIPAddressesAllocated -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfIPAddressesInTransition' -Value $numberOfIPAddressesInTransition -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIPAddresses' -Value $numberofIPAddresses -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPools' -Value $gatewayPoolNames -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfIpReservations' -Value $numberOfIpReservations -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberofIpPools' -Value $ipPools -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkName' -Value $logicalNetworkName -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-SelectedLogicalSubnetDetails ##
function Get-ServerConnectionInstanceID {
<#

.SYNOPSIS
Get InstanceID of Server Connection

.DESCRIPTION
This script is used to get InstanceID of Server Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $serverConnection,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$instance = Get-NetworkControllerServer -resourceid $serverConnection @paramsHash
$instanceId = $instance.InstanceId

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceId -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-ServerConnectionInstanceID ##
function Get-ServerConnections {
<#

.SYNOPSIS
Get Server Names of Network Interfaces in Logical network for Server Connection

.DESCRIPTION
This script is used to List all Server Names of Network Interfaces available in the Logical Network for Server Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Server Names of Network Interfaces in Logical network for Server Connection

#Fetch the Logical Networks
$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash

#Fetch the Network Interface Names
$networkInterface = $logicalNetworkNames.Properties.Subnets.Properties.NetworkInterfaces
if($networkInterface.length -gt 0)
{
    $networkInterfaceNames = $networkInterface.ResourceRef
    $nwifNames = ""
    $nwifNames = @()
    foreach($networkInterfaceName in $networkInterfaceNames)
    {
        $nifName = $networkInterfaceName.split('/')[2]
        $nwifNames += $nifName
    }
    $serverNames = ""
    $serverNames = @()
    foreach($nwifName in $nwifNames)
    {
        #Fetch the Server Names
        $serverConnections = Get-NetworkControllerServer -ResourceId "$nwifName" @paramsHash
        $serverName = $serverConnections.Properties.Connections.ManagementAddresses.split('.')[0]
        $serverNames += $serverName

    }
}
else
{
    $serverNames = @()
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'ServerConnection' -Value $serverNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-ServerConnections ##
function Get-SubnetL3VirtualGatewayConnection {
<#

.SYNOPSIS
Get L3 Virtual Gatewaty Connection of Subnet

.DESCRIPTION
This script is used to Get L3 Virtual Gatewaty Connection of Subnet

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$Subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash
$l3VirtualGatewayConnections = $Subnets.Properties.NetworkConnections
if($l3VirtualGatewayConnections.length -gt 0)
{
    $l3VirtualGatewayConnectionsIDs = $l3VirtualGatewayConnections.ResourceRef

    $l3vgcNames = ""
    $l3vgcNames = @()
    foreach($l3VirtualGatewayConnectionsID in $l3VirtualGatewayConnectionsIDs)
    {
        $l3vgcName = $l3VirtualGatewayConnectionsID.split('/')[4]
        $l3vgcNames += $l3vgcName
    }
}
else
{
   $l3vgcNames = @()
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'L3VirtualGatewayConnection' -Value $l3vgcNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SubnetL3VirtualGatewayConnection ##
function Get-SubnetSDNGatewayVirtualMachineConnections {
<#

.SYNOPSIS
Get VM Names of IpConfigurations in Subnet for SDN Gateway Virtual Machine Connection

.DESCRIPTION
This script is used to List all  VM Names of IpConfigurations available in the Subnet for SDN Gateway Virtual Machine Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get VM Names of IpConfigurations in Subnet for SDN Gateway Virtual Machine Connection

#Fetch the Subnet
$subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash

#Fetch the IP Configuration Names
$ipConfigurations = $subnets.Properties.IpConfigurations
$vmNames = @()
if($ipConfigurations.length -gt 0)
{
    $ipConfigurationNames = $ipConfigurations.ResourceRef
    $ipcgNames = " "
    $ipcgNames = @()
    foreach($ipConfigurationName in $ipConfigurationNames)
    {
        $ipcName = $ipConfigurationName.split('/')[2]
        $ipcgNames += $ipcName
    }
    foreach($ipcgName in $ipcgNames)
    {
        #Fetch the VM Names
        $networkInterfaces = Get-NetworkControllerNetworkInterface -ResourceId $ipcgName @paramsHash
        $vmName = $networkInterfaces.Properties.Gateway.ResourceRef.split('/')[2]
        $vmNames += $vmName
    }
}

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'SDNGatewayVirtualMachineConnection' -Value $vmNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SubnetSDNGatewayVirtualMachineConnections ##
function Get-SubnetServerConnection {
<#

.SYNOPSIS
Get Server Names of Network Interfaces in Subnet for Server Connection

.DESCRIPTION
This script is used to List all Server Names of Network Interfaces available in the Subnet for Server Connection

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

# Get Server Names of Network Interfaces in Subnet for Server Connection

#Fetch the Logical Subnet
$subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash

#Fetch the Network Interface Names
$networkInterface = $subnets.Properties.NetworkInterfaces
$serverNames = @()
if($networkInterface.length -gt 0)
{
    $networkInterfaceNames = $networkInterface.ResourceRef
    $nwifNames = @()
    foreach($networkInterfaceName in $networkInterfaceNames)
    {
        $nifName = $networkInterfaceName.split('/')[2]
        $nwifNames += $nifName
    }
    foreach($nwifName in $nwifNames)
    {
        #Fetch the Server Names
        $serverConnections = Get-NetworkControllerServer -ResourceId "$nwifName" @paramsHash
        $serverName = $serverConnections.Properties.Connections.ManagementAddresses.split('.')[0]
        $serverNames += $serverName
    }
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'ServerConnection' -Value $serverNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SubnetServerConnection ##
function Get-VirtualNetworkInstanceID {
<#

.SYNOPSIS
Get InstanceID of Virtual Network

.DESCRIPTION
This script is used to get InstanceID of Virtual Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$instance = Get-NetworkControllerVirtualNetwork -resourceid $virtualNetworkName @paramsHash
$instanceId = $instance.InstanceId

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceId -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-VirtualNetworkInstanceID ##
function Get-VirtualNetworks {
<#

.SYNOPSIS
Get Virtual Network in logical network

.DESCRIPTION
This script is used to List all Virtual Networks available in the Logical Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$logicalNetworkNames = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
$vNetNames = @()
$virtualNetworks = $logicalNetworkNames.Properties.VirtualNetworks
if($virtualNetworks.length -gt 0)
{
    $virtualNetworkNames = $VirtualNetworks.ResourceRef
    foreach($virtualNetworkName in $virtualNetworkNames)
    {
        $vNetName = $virtualNetworkName.split('/')[2]
        $vNetNames += $vNetName
    }
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $vNetNames -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-VirtualNetworks ##
function New-IpPool {
<#

.SYNOPSIS
Create IpPool for the Logical Subnet

.DESCRIPTION
This script is used to Create a IpPool for the Logical Subnet

.ROLE
Administrators

#>
Param
(
[Parameter(Mandatory = $True)]
[ValidateNotNullOrEmpty()]
[string] $logicalNetworkName,

[Parameter(Mandatory = $True)]
[ValidateNotNullOrEmpty()]
[string] $ipPoolList,

[Parameter(Mandatory = $True)]
[object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
$restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

$props = $ipPoolList | ConvertFrom-Json

#create IP Pool for Logical Subnet
$result = @()

for($i=0; $i -lt $props.length; $i++)
{
  for($j=0; $j -lt $props[$i].ipPoolName.length; $j++)
  {
    #Create a new object for IpPool
    $poolProperties = New-Object Microsoft.Windows.NetworkController.IpPoolProperties

    #Update the properties of the IpPool
    $poolProperties.startIPAddress = $props[$i].startIpAddress[$j].startIpAddress
    $poolProperties.endIPAddress = $props[$i].endIpAddress[$j].endIpAddress

    #Add the new IpPool for the Logical Subnet
    $resultvalue = New-NetworkControllerIpPool -ResourceId $props[$i].ipPoolName[$j].ipPoolName -NetworkId $logicalNetworkName -SubnetId $props[$i].subnet -Properties $poolProperties @paramsHash -Force
    if($props[$i].addLoadbalancerVipPool[$j].addLoadbalancerVipPool -eq $True)
    {
      $getIpPool = Get-NetworkControllerIpPool -ResourceId $props[$i].ipPoolName[$j].ipPoolName -NetworkId $logicalNetworkName -SubnetId $props[$i].subnet @paramsHash
      $lbConfig = Get-NetworkControllerLoadBalancerConfiguration @paramsHash
      $lbConfigProperties = $lbConfig.Properties
      $lbConfigProperties.VipIpPools += $getIpPool

      $lbConfiguration = New-NetworkControllerLoadBalancerConfiguration -ResourceId $lbConfig.ResourceId -Properties $lbConfigProperties -ResourceMetadata $lbConfig.ResourceMetadata -Tags $lbConfig.Tags @paramsHash -Force
    }
    $result += $resultvalue
  }
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-IpPool ##
function New-LogicalNetwork {
<#

.SYNOPSIS
Create a logical network

.DESCRIPTION
This script is used to Create Logical Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string] $networkVirtualizationEnabled,

    [Parameter(Mandatory = $True)]
    [object] $restParams
  )

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module Networkcontroller -force

#Create a new object for Logical Network
$NetworkProperties = New-Object Microsoft.Windows.NetworkController.LogicalNetworkProperties
#Update the properties of the Logical Network
$NetworkProperties.NetworkVirtualizationEnabled = $networkVirtualizationEnabled

New-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName -Properties $NetworkProperties @paramsHash -Force

}
## [END] New-LogicalNetwork ##
function New-LogicalSubnet {
<#

.SYNOPSIS
Create a Logical Subnet for the Logical Network

.DESCRIPTION
This script is used to Create a Logical Subnet for the Logical Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $subnetName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [array] $addressPrefix,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [array] $defaultGateways,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [array] $dnsServers,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $vlanId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $isPublic,

    [Parameter(Mandatory = $False)]
    [array] $nsgGroupName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
  )

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module Networkcontroller -Force
Set-StrictMode -Version 5.0

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

#Create a Logical Subnet for the Logical Network

$result = @()
$shouldAddToServers = $parent.Properties.NetworkVirtualizationEnabled -eq "True"
$servers = Get-NetworkControllerServer @paramsHash
for($i=0; $i -lt $subnetName.length; $i++)
{
  #Create a new object for Logical Subnet
  $SubnetProperties = New-Object Microsoft.Windows.NetworkController.LogicalSubnetProperties

  #Update the properties of the Logical Network
  if (-not [string]::IsNullOrEmpty($addressPrefix[$i].addressPrefix)) {
      $SubnetProperties.AddressPrefix = $addressPrefix[$i].addressPrefix
  }
  if (-not [string]::IsNullOrEmpty($defaultGateways[$i].defaultGateway)) {
      $SubnetProperties.DefaultGateways = $defaultGateways[$i].defaultGateway
  }
  if (-not [string]::IsNullOrEmpty($vlanId[$i].vlanId)) {
    $SubnetProperties.VlanId = $vlanId[$i].vlanId
  }
  if (-not [string]::IsNullOrEmpty($nsgGroupName[$i])) {
    $t = $nsgGroupName[$i].split("/")

    $acl = Get-NetworkControllerAccessControlList -ResourceId $t[$t.Count-1] @paramsHash
    $SubnetProperties.AccessControlList = $acl
  }

  $SubnetProperties.DnsServers =@()
  $dns = $dnsServers[$i].dns
  if(-not [string]::IsNullOrEmpty($dns))
  {
    $dnsServersList = $dnsServers[$i].dns.split(',')
    for($j = 0; $j -lt $dnsServersList.length; $j++)
    {
      $SubnetProperties.DnsServers += $dnsServersList[$j]
    }
  }

  $SubnetProperties.IsPublic = ($isPublic[$i].isPublic -eq "true")

  #Add the New Logical Subnet
  $resultvalue = New-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName[$i].subnetName -Properties $SubnetProperties @paramsHash -Force
  if ($shouldAddToServers) {
    foreach ($server in $servers)
    {
      $server.Properties.NetworkInterfaces[0].Properties.LogicalSubnets += $resultvalue
      New-networkcontrollerserver -ResourceId $server.ResourceId -Properties $server.Properties -ResourceMetadata $server.ResourceMetadata -Tags $server.Tags @paramsHash -Force | Out-Null
    }
  }
  $result += $resultvalue
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-LogicalSubnet ##
function Remove-IpPool {
<#

.SYNOPSIS
Delete logical IpPools of a Logical Subnet

.DESCRIPTION
This script is used to Delete a Particular Logical IpPool of the Logical Subnet

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $ipPoolName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
  )

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

#Delete Logical IpPool of the Logical Subnet
Remove-NetworkControllerIpPool -NetworkId $logicalNetworkName -SubnetId $subnetName -ResourceId $ipPoolName @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-IpPool ##
function Remove-LogicalNetwork {
<#

.SYNOPSIS
Delete logical network

.DESCRIPTION
This script is used to Delete Logical Network

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory = $True)]
  [ValidateNotNullOrEmpty()]
  [string] $logicalNetworkName,

  [Parameter(Mandatory = $False)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$existing = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $existing

$subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName @paramsHash
if ($subnets.length -gt 0) {
  $subnetRefs = $subnets.ResourceRef
  $servers = Get-NetworkControllerServer @paramsHash
  foreach ($server in $servers) {
    #Replace the subnets list with an identical list, leaving out subnets in this logical network
    $lns = $server.Properties.NetworkInterfaces[0].Properties.LogicalSubnets
    $newSubnets = @()

    foreach ($ls in $lns) {
      if ($subnetRefs -notcontains $ls.ResourceRef) {
        $splitSubnet = $ls.ResourceRef.split('/')
        $subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $splitSubnet[2] -ResourceId $splitSubnet[4] @paramsHash
        $newSubnets += $subnet
      }
    }

    $server.Properties.NetworkInterfaces[0].Properties.LogicalSubnets = $newSubnets
    New-networkcontrollerserver -ResourceId $server.ResourceId -Properties $server.Properties -ResourceMetadata $server.ResourceMetadata -Tags $server.Tags @paramsHash -Force | Out-Null
  }
}

Remove-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-LogicalNetwork ##
function Remove-LogicalSubnet {
<#

.SYNOPSIS
Delete logical Subnet of a Logical Network

.DESCRIPTION
This script is used to Delete a Particular Logical Subnet of the Logical Network

.ROLE
Administrators

#>
Param
(
  [Parameter(Mandatory = $True)]
  [ValidateNotNullOrEmpty()]
  [string] $logicalNetworkName,

  [Parameter(Mandatory = $True)]
  [ValidateNotNullOrEmpty()]
  [string] $subnetName,

  [Parameter(Mandatory = $False)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

$removeSubnet = $parent.Properties.Subnets | Where-Object {$_.ResourceId -eq $subnetName}
$servers = Get-NetworkControllerServer @paramsHash
foreach ($server in $servers) {
  #Replace the subnets list with an identical list, leaving out subnets in this logical network
  $lns = $server.Properties.NetworkInterfaces[0].Properties.LogicalSubnets
  $newSubnets = @()

  foreach ($ls in $lns) {
    if ($ls.ResourceRef -ne $removeSubnet.ResourceRef) {
      $splitSubnet = $ls.ResourceRef.split('/')
      $subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $splitSubnet[2] -ResourceId $splitSubnet[4] @paramsHash
      $newSubnets += $subnet
    }
  }
  $server.Properties.NetworkInterfaces[0].Properties.LogicalSubnets = $newSubnets
  New-networkcontrollerserver -ResourceId $server.ResourceId -Properties $server.Properties -ResourceMetadata $server.ResourceMetadata -Tags $server.Tags @paramsHash -Force | Out-Null
}

Remove-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-LogicalSubnet ##
function Update-IpPool {
<#

.SYNOPSIS
Update IpPool for the Logical Subnet

.DESCRIPTION
This script is used to Update a IpPool for the Logical Subnet

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $ipPoolName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $startIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $endIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $addLoadbalancerVipPool,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#update IP Pool for Logical Subnet

#Import the Network Controller Module
Import-Module NetworkController -Force

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

$ipPool = ($parent.Properties.Subnets | Where-Object {$_.ResourceId -eq $subnetName}).Properties.IpPools | Where-Object {$_.ResourceId -eq $ipPoolName}
$metadata = $null
if ($null -ne $ipPool) {
  $metadata = $ipPool.ResourceMetadata
}
$loadBalancerManager = $ipPool.Properties.LoadBalancerManager

$isAvailable = ($null -ne $loadBalancerManager)

#Create a new object for IpPool
$poolProperties = New-Object Microsoft.Windows.NetworkController.IpPoolProperties

#Update the properties of the IpPool
$poolProperties.startIPAddress = $startIPAddress
$poolProperties.endIPAddress = $endIPAddress

$result = New-NetworkControllerIpPool -ResourceId $ipPoolName -NetworkId $logicalNetworkName -SubnetId $subnetName -Properties $poolProperties -ResourceMetadata $metadata @paramsHash -Force

if($addLoadbalancerVipPool -ne $isAvailable)
{
  $lbConfig = Get-NetworkControllerLoadBalancerConfiguration @paramsHash
  $lbConfigProperties = $lbConfig.Properties
  if($addLoadbalancerVipPool -eq $True)
  {
    $getIpPool = Get-NetworkControllerIpPool -ResourceId $ipPoolName -NetworkId $logicalNetworkName -SubnetId $subnetName @paramsHash
    $lbConfigProperties.VipIpPools += $getIpPool
    $lbConfiguration = New-NetworkControllerLoadBalancerConfiguration -ResourceId $lbConfig.ResourceId -Properties $lbConfigProperties -ResourceMetadata $lbConfig.ResourceMetadata -Tags $lbConfig.Tags @paramsHash -Force
  }
  else
  {
    [System.Collections.ArrayList]$vipIpPools = $lbConfigProperties.VipIpPools
    foreach($vipIpPool in $vipIpPools)
    {
      $lnet = $vipIpPool.ResourceRef.split('/')[2]
      $snet = $vipIpPool.ResourceRef.split('/')[4]
      $PoolName = $vipIpPool.ResourceRef.split('/')[6]

      if($lnet -eq $logicalNetworkName  -and $snet -eq $subnetName -and $PoolName -eq $ipPoolName)
      {
        $VipIpPools.Remove($vipIpPool)
        break
      }

    }
    $lbConfigProperties.VipIpPools = $vipIpPools
    $lbConfiguration = New-NetworkControllerLoadBalancerConfiguration -ResourceId $lbConfig.ResourceId -Properties $lbConfigProperties -ResourceMetadata $lbConfig.ResourceMetadata -Tags $lbConfig.Tags @paramsHash -Force
  }
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-IpPool ##
function Update-LogicalNetwork {
<#

.SYNOPSIS
Update the logical network

.DESCRIPTION
This script is used to update the Logical Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string] $networkVirtualizationEnabled,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$existing = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $existing
$metadata = $existing.ResourceMetadata
$tags = $existing.Tags

#Create a new object for Logical Network
$NetworkProperties = New-Object Microsoft.Windows.NetworkController.LogicalNetworkProperties

#Update the properties of the Logical Network
$NetworkProperties.NetworkVirtualizationEnabled = $networkVirtualizationEnabled
$NetworkProperties.Subnets = @()

#Fetch the Logical Subnets of the Logical Network
$subnets = $exisiting.Properties.Subnets

#Add the Logical Subnets to the Logical Network
$NetworkProperties.Subnets = $subnets

#Add the properties of the Logical Network
$result = New-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName -Properties $NetworkProperties -ResourceMetadata $metadata -Tags $tags @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-LogicalNetwork ##
function Update-LogicalSubnet {
<#

.SYNOPSIS
Update Logical Subnet for the Logical Network

.DESCRIPTION
This script is used to Update a Logical Subnet for the Logical Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $addressPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $defaultGateways,

    [Parameter(Mandatory = $False)]
    [string[]] $dnsServers,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $vlanId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $isPublic,

    [Parameter(Mandatory = $False)]
    [string] $aclList,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Update a Logical Subnet for the Logical Network

Import-Module NetworkController -Force

Set-Variable -Name Clients -Option ReadOnly -Value @('AksHci', 'MOC') -Scope Script -ErrorAction SilentlyContinue

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
$parent = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
throwIfResourceManaged $parent

#Fetch the Subnet details
$subnet = $parent.Properties.Subnets | Where-Object {$_.ResourceId -eq $subnetName}
$metadata = $subnet.ResourceMetadata

#Create a new object for Logical Subnet
$SubnetProperties = New-Object Microsoft.Windows.NetworkController.LogicalSubnetProperties
#Update the properties of the Logical Network
$SubnetProperties.AddressPrefix = $addressPrefix
$SubnetProperties.DefaultGateways = $defaultGateways
$SubnetProperties.VlanId = $vlanId

#dns servers
if($null -ne $dnsServers -and $dnsServers.count -gt 0) {
  $SubnetProperties.DnsServers = @()
  foreach($dnsServer in $dnsServers) {
    if([string]::IsNullOrEmpty($dnsServer) -eq $false)
    {
      $SubnetProperties.DnsServers += $dnsServer
    }
  }
}

$SubnetProperties.IsPublic = ($isPublic -eq "true")

#Fetch the IpPools of the Logical Subnet
$ipPools = $subnet.Properties.IpPools
#Add the IpPools to the Logical Subnet
$SubnetProperties.IpPools = $ipPools

#Fetch the acl list
if([string]::IsNullOrEmpty($aclList) -eq $false)
{
  $t = $aclList.Split("/");
  $aclListResource = Get-NetworkControllerAccessControlList -ResourceId $t[$t.Count-1] @paramsHash
  $SubnetProperties.AccessControlList = $aclListResource
}
#Add the new Logical Subnet
$result = New-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName -Properties $SubnetProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-LogicalSubnet ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCDtIDKyNMJhEQv
# GjV4aN8w8vTYR/C1OmUZhlUj0WrveKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEg1nLmxRj/p1ng2TjX1wTsf
# /85DiGwSlwle3f4IvwgmMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEATHRt/RaQ1QRB04HNqGmtgY5wgzTVvpIthHrlvv23e1bBWDdK/FDer8C5
# zHgXTg+j5QiugUP13aOgZ9Pv7Oajf9mkFmcdAqemou2Su6pOFbNrL3M5+CCq4Ndk
# JZhBTOxSmpAw+fKGVbOdcTAXKZqUdTvMQPOCyPEHK3B2MzoywhMp8ocMgrQ9CfZv
# hyTf0OYb3cbXXaBJh0Bvh/6U99KO4icp0Em4ip0cRkradZuB089gFCwra5jSVyiX
# aDpNI0b6Uvls83ElEdMxQxRCwdvfip2GahSM3aM+LDa6EqPFFK/RW0SWJ3GLVYQ5
# wrIitMk+eblUXZrdfe7ZqQQ5Sz/eh6GCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCA+Vsp441M7A4hZG7sU5UkYiICOyvS0L/dOG+1pvbvSPwIGaO/YTsf6
# GBMyMDI1MTExMDE3MTYxMS40MjFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgJ5UHQhFH24oQABAAACAjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NDRaFw0yNjA0MjIxOTQyNDRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC3eSp6cucUGOkcPg4vKWKJfEQeshK2ZBsYU1tDWvQu
# 6L9lp+dnqrajIdNeH1HN3oz3iiGoJWuN2HVNZkcOt38aWGebM0gUUOtPjuLhuO5d
# 67YpQsHBJAWhcve/MVdoQPj1njiAjSiOrL8xFarFLI46RH8NeDhAPXcJpWn7AIzC
# yIjZOaJ2DWA+6QwNzwqjBgIpf1hWFwqHvPEedy0notXbtWfT9vCSL9sdDK6K/HH9
# HsaY5wLmUUB7SfuLGo1OWEm6MJyG2jixqi9NyRoypdF8dRyjWxKRl2JxwvbetlDT
# io66XliTOckq2RgM+ZocZEb6EoOdtd0XKh3Lzx29AhHxlk+6eIwavlHYuOLZDKod
# POVN6j1IJ9brolY6mZboQ51Oqe5nEM5h/WJX28GLZioEkJN8qOe5P5P2Yx9HoOqL
# ugX00qCzxq4BDm8xH85HKxvKCO5KikopaRGGtQlXjDyusMWlrHcySt56DhL4dcVn
# n7dFvL50zvQlFZMhVoehWSQkkWuUlCCqIOrTe7RbmnbdJosH+7lC+n53gnKy4OoZ
# zuUeqzCnSB1JNXPKnJojP3De5xwspi5tUvQFNflfGTsjZgQAgDBdg/DO0TGgLRDK
# vZQCZ5qIuXpQRyg37yc51e95z8U2mysU0XnSpWeigHqkyOAtDfcIpq5Gv7HV+da2
# RwIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFNoGubUPjP2f8ifkIKvwy1rlSHTZMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCD83aFQUxN37HkOoJDM1maHFZVUGcqTQcP
# nOD6UoYRMmDKv0GabHlE82AYgLPuVlukn7HtJPF2z0jnTgAfRMn26JFLPG7O/XbK
# K25hrBPJ30lBuwjATVt58UA1BWo7lsmnyrur/6h8AFzrXyrXtlvzQYqaRYY9k0UF
# Y5GM+n9YaEEK2D268e+a+HDmWe+tYL2H+9O4Q1MQLag+ciNwLkj/+QlxpXiWou9K
# vAP0tIk+fH8F3ww5VOTi9aZ9+qPjszw31H4ndtivBZaH5s5boJmH2JbtMuf2y7hS
# dJdE0UW2B0FEZPLImemlKhslJNVqEO7RPgl7c81QuVSO58ffpmbwtSxhYrES3VsP
# glXn9ODF7DqmPMG/GysB4o/QkpNUq+wS7bORTNzqHMtH+ord2YSma+1byWBr/izI
# KggOCdEzaZDfym12GM6a4S+Iy6AUIp7/KIpAmfWfXrcMK7V7EBzxoezkLREEWI4X
# tPwpEBntOa1oDH3Z/+dRxsxL0vgya7jNfrO7oizTAln/2ZBYB9ioUeobj5AGL45m
# 2mcKSk7HE5zUReVkILpYKBQ5+X/8jFO1/pZyqzQeI1/oJ/RLoic1SieLXfET9EWZ
# IBjZMZ846mDbp1ynK9UbNiCjSwmTF509Yn9M47VQsxsv1olQu51rVVHkSNm+rTrL
# wK1tvhv0mTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE0MDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBJ
# iUhpCWA/3X/jZyIy0ye6RJwLzqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LyafDAiGA8yMDI1MTExMDE3MDgx
# MloYDzIwMjUxMTExMTcwODEyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvJp8
# AgEAMAoCAQACAilUAgH/MAcCAQACAhILMAoCBQDsvev8AgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBABgL1hPn6i4MmzS20dVO2WIBdQBH36K7HI553xc5olAg
# xC3Rnd3r3770aNxXcsPokvQhImfyGSu3/A97gTjgCA05P3SxgHyI/n21NWeBAzio
# mhfRTAxwlzidr2nizwqoNMGHxGpVnOk4sR1emvLeu+wX2LtXgdzhOlI07WZymDiJ
# HF6IaIVWe+FqN+BK5wF9Dqg/gFWQmCv+KRYA8TntgKEcy5aMmp5DD6/tJugO5HzP
# EjBOLOLHY5ZWi0uWz5XriExrN5f0QLLqWyIYXhGk4LM/W+4+oH/WlEsH6qp7zCRx
# skDr5YKdZPnDCYNtk2ttclG5GNyqRwa4b99KRJm5g+QxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgJ5UHQhFH24oQABAAAC
# AjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCq1z+SMYxhhfesXiFNGQP18oF8ZP87IYiiU0Qo15FC
# LTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPON6gEYB5bLzXLWuUmL8Zd8
# xXAsqXksedFyolfMlF/sMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAICeVB0IRR9uKEAAQAAAgIwIgQgla+KcZeP3OgOwPzMHQvgcHA0
# cYXa3F0K4iFZ1wTSMqwwDQYJKoZIhvcNAQELBQAEggIACoba9Z+Ga5tiJIEHojzf
# 7ySneQK/CY679fwYxpKTyIJ9hx9f5s8Sh4MJF7ql0tecZolbx+nTc9Zq1tk4QR7k
# r1g2GHDwIYJHoQIGa/X3BTTipEv1O5KyXrKNo6Sk3e1LAJFqINFtJmQj2hg7v7YP
# dI053UEgmoOrRyC2Y5DKew6mJvpYRutGKAylHjXRShlHqja1jqAB8Tb1Enq3IKHx
# lUyEQ7DEUhpIqOw18nUhRp0BCtgVimb4sUUay2IgXD+wi2kc1y7MO0aQmaWgssc1
# iLn6hk0UieK/3Vr/mSUUMm6dYNEQ+UE2czi/oTi7FMyA058b794fLHon6jchZCfn
# 1cuvdbo9nTz2FolqGBk6lDMuR/+uEV2aRyKD3YDngjFZgU0K40qI8eJGHT5FeVQJ
# lQghUd0NY4SflMfMDOtGnfuwCVg44AubxxNVPRR9E7zVabhs6s0B03KoBQekD93k
# jhBQ7UHGsDt61e3eI3ZxGVmA3lhowdTUYgEwUfvLi7fBLP2yL8LO1rsm+oxKOc1g
# 3SomxCu1vYeMY9UmF7pB+z8xGkZYmOjPRzVDsU4Y7Ukt7lme/Tni8hEKgOi3ljp6
# gsebPBrm0DU6HWflG7xH1duF+4JPtZf69ecF3kQtmhRRDpEzXPT31fjch+OB1Ea2
# PO5C0bBnPC+vnpRMfBRaPUg=
# SIG # End signature block
