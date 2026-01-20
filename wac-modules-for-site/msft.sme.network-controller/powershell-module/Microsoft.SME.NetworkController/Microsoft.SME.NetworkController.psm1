function Edit-VirtualSubnet {
<#

.SYNOPSIS
Edits a virtual subnet.

.DESCRIPTION
Edits a virtual subnet.

.ROLE
Administrators

.PARAMETER restParams
    An object containing SDN specific REST parameters

.PARAMETER virtualNetworkResourceId
    The resource id of the parent virtual network.

.PARAMETER virtualSubnetResourceId
    The resource id of the virtual subnet to edit.

.PARAMETER properties
    A json corresponding to the properties of the edited virtual subnet.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $virtualNetworkResourceId,

    [Parameter(Mandatory = $true)]
    [String]
    $virtualSubnetResourceId,

    [Parameter(Mandatory = $false)]
    [String]
    $properties,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

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

$props = $properties | ConvertFrom-Json
# get the virtual network
$vnet = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkResourceId @paramsHash
throwIfResourceManaged $vnet

# set the properties to the new properties
$vnetProps = $vnet.Properties
($vnetProps.Subnets | Where-Object {$_.ResourceId -eq $virtualSubnetResourceId}).Properties = $props

# do the update
New-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkResourceId -Properties $vnetProps -ResourceMetadata $vnet.ResourceMetadata -Tags $vnet.Tags @paramsHash -Force

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Edit-VirtualSubnet ##
function Find-VirtualGateway {
<#

.SYNOPSIS
Check Virtual Gateways

.DESCRIPTION
This script is used to check Whether Virtual Network has Virutal Gateway or Not

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

#Fetch the Virtual Network Name
foreach($virtualNetwork in $virtualNetworks)
{
  $instanceId = $virtualNetwork.InstanceId
  if($instanceId -eq $virtualNetworkInstanceId)
  {
    $virtualNetworkName = $virtualNetwork.ResourceId
    break
  }
}

#Fetch Virtual Gateways
$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

#Check Whether Virtual Gateway is available or not for the Virtual Network
# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $virtualGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $virtualNetworkName}

if($null -ne $myGw)
{
  $result = "Available"
}
else
{
  $result = "Unavilable"
}

$myResponse = New-Object -TypeName PsObject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

}
## [END] Find-VirtualGateway ##
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
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

# Get Access Control Lists
$accessControlLists = Get-NetworkControllerAccessControlList @paramsHash

foreach($accessControlList in $accessControlLists)
{
    #Fetch the Name of the Access Control List
    $resourecID = $accessControlList.ResourceId

    #Fetch the Length of the Access Control List Rules
    $aclRules = $accessControlList.Properties.AclRules.length

    #Fetch the Length of the Access Control List Subnets
    $subnets = $accessControlList.Properties.Subnets.length

    #Fetch the Lenght of the Access Controls List NICs
    $ipConfigurations = $accessControlList.Properties.IpConfigurations.length

    #Fetch the Provisioning State of the Access Control List
    $provisioningState = $accessControlList.Properties.ProvisioningState

    #Fetch the Instance ID of the Access Control List
    $instanceID = $accessControlList.InstanceId

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $resourecID -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AclRules' -Value $aclRules -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AppliedSubnets' -Value $subnets -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AppliedNICs' -Value $ipConfigurations -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceID -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-AccessControlLists ##
function Get-BGPPeers {
<#

.SYNOPSIS
Get BGP Peers of BGP Router in Virtual Network

.DESCRIPTION
This script is used to List all BGP Peers in a BGP Router available in the Virtual Network

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

$bgpPeerIPAddress = $null
$bgRouterASN = $null
$connectionState = $null
$myResponse = $null
if($null -ne $myGw)
{
  #Fetching BGP Routers in Virtual Network
  $bgpRouters = $myGw.Properties.BgpRouters

  $bgpRouter = $bgpRouters | Where-Object {$_.Properties.IsGenerated -eq $False}

  if($null -ne $bgpRouter)
  {
    #Fetching BGP Peers of BGP Router in Virtual Network
    $bgpPeers = $bgpRouter.Properties.BgpPeers

    if($bgpPeers.Count -eq 0)
    {
      #Preparing Object Response
      $myResponse = New-Object -TypeName psobject

      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouter.ResourceId -ErrorAction SilentlyContinue
      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $null -ErrorAction SilentlyContinue
      $myResponse
    }
    foreach($bgpPeer in $bgpPeers)
    {
      $bgpPeerName = $bgpPeer.ResourceId
      $bgpPeerIPAddress = $bgpPeer.Properties.PeerIpAddress
      $bgRouterASN = $bgpPeer.Properties.AsNumber
      $connectionState = $bgpPeer.Properties.ConnectionState

      $myResponse = New-Object -TypeName psobject
      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouter.ResourceId -ErrorAction SilentlyContinue
      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIPAddress' -Value $bgpPeerIPAddress -ErrorAction SilentlyContinue
      $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgRouterASN -ErrorAction SilentlyContinue
      $myResponse | Add-Member -MemberType NoteProperty -Name 'ConnectionState' -Value $connectionState -ErrorAction SilentlyContinue

      $myResponse
    }
  }
}
if ($null -eq $myResponse)
{
  $myResponse = New-Object -TypeName psobject
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIPAddress' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'ConnectionState' -Value $null -ErrorAction SilentlyContinue
  $myResponse
}

}
## [END] Get-BGPPeers ##
function Get-BGPRouters {
<#

.SYNOPSIS
Get BGP Routers in Virtual Network

.DESCRIPTION
This script is used to List all BGP Routers available in the Virtual Network When IsGenerated is False

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

$myResponse = $null
if($null -ne $myGw) {

  #Fetching BGP Routers in Virtual Network
  $bgpRouters = $myGw.Properties.BgpRouters

  foreach($bgpRouter in $bgpRouters)
  {
    $bgpRouterName = $null
    $bgpRouterASN = $null
    $bgpRouterIP = $null

    $isGenerated = $bgpRouter.Properties.IsGenerated

    if($isGenerated -eq $False)
    {
      $bgpRouterName = $bgpRouter.ResourceId
      $bgpRouterASN = $bgpRouter.Properties.ExtAsNumber.Split('.')[1]
      $bgpRouterIP =  $bgpRouter.Properties.RouterIP[0]
    }

    #Preparing Object Response for BGP Router
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgpRouterASN -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
    $myResponse
  }
}

if ($null -eq $myResponse) {
  $myResponse = New-Object -TypeName psobject
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $null -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $null -ErrorAction SilentlyContinue
  $myResponse
}

}
## [END] Get-BGPRouters ##
function Get-HypervNetworkAdapters {
<#

.SYNOPSIS
Gets all hyper-v network adapters.

.DESCRIPTION
Gets all hyper-v network adapters.

.ROLE
Readers

#>

Import-Module Hyper-V
Import-Module Microsoft.PowerShell.Utility

@(Get-VMNetworkAdapter -All | Microsoft.PowerShell.Utility\Select-Object VmId, MacAddress)

}
## [END] Get-HypervNetworkAdapters ##
function Get-LogicalNetworks {
<#

.SYNOPSIS
Gets all logical networks.

.DESCRIPTION
Gets all logical networks.

.ROLE
Readers

.PARAMETER restParams
    An object containing SDN specific REST parameters

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
Import-Module Microsoft.PowerShell.Management

$lnets = @(Get-NetworkControllerLogicalNetwork @paramsHash)
$lnets | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-LogicalNetworks ##
function Get-NetworkInterfaces {
<#

.SYNOPSIS
Gets all network interfaces.

.DESCRIPTION
Gets all network interfaces.

.ROLE
Readers

.PARAMETER restParams
    An object containing SDN specific REST parameters

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
Import-Module Microsoft.PowerShell.Management

$nics = @(Get-NetworkControllerNetworkInterface @paramsHash)
$nics | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-NetworkInterfaces ##
function Get-VirtualNetworkPeerings {
<#

.SYNOPSIS
Get Virtual Network Peerings

.DESCRIPTION
This script is used to List all Virtual Network Peerings associated to particular Virtual Network in the Cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Fetch the Virtual Network Name

$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash
foreach($virtualNetwork in $virtualNetworks)
{
    $instanceId = $virtualNetwork.InstanceId
    if($instanceId -eq $virtualNetworkInstanceId)
    {
        $virtualNetworkName = $virtualNetwork.ResourceId
        break
    }
}

#Fetch the Virtual Network Peerings of the Selected virtual Network
$virtualNetworkPeerings = Get-NetworkControllerVirtualNetworkPeering -VirtualNetworkId $virtualNetworkName @paramsHash

foreach($virtualNetworkPeering in $virtualNetworkPeerings)
{
    #Fetch the Peer Name
    $peerName = $virtualNetworkPeering.ResourceId

    #Fetch the Peering Status
    $peeringStatus = $virtualNetworkPeering.Properties.PeeringState

    #Fetch the Peer Virtual Network
    $peerVirtualNetwork = $virtualNetworkPeering.Properties.RemoteVirtualNetwork.ResourceRef.split('/')[2]

    #Fetch Gateway Transit
    $allowGatewayTransit = $virtualNetworkPeering.Properties.AllowGatewayTransit
    if($allowGatewayTransit -eq $false)
    {
        $gatewayTransit = "Disabled"
    }
    else
    {
        $gatewayTransit = "Enabled"
    }

    #Fetch GatewayTraffic
    $allowForwardTraffic = $virtualNetworkPeering.Properties.AllowForwardedTraffic
    if($allowForwardTraffic -eq $false)
    {
        $forwardTraffic = "Disabled"
    }
    else
    {
        $forwardTraffic = "Enabled"
    }

    #Fetch Vnet Access
    $allowVirtualNetworkAccess = $virtualNetworkPeering.Properties.AllowVirtualNetworkAccess
    if($allowVirtualNetworkAccess -eq $false)
    {
        $virtualNetworkAccess = "Disabled"
    }
    else
    {
        $virtualNetworkAccess = "Enabled"
    }

     #Fetch UseRemoteGateways
    $useRemoteGateways = $virtualNetworkPeering.Properties.UseRemoteGateways
    if($useRemoteGateways -eq $false)
    {
        $remoteGateways = "Disabled"
    }
    else
    {
        $remoteGateways = "Enabled"
    }

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'PeerName' -Value $peerName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PeeringStatus' -Value $peeringStatus -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PeerVirtualNetwork' -Value $peerVirtualNetwork -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayTransit' -Value $gatewayTransit -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ForwardTraffic' -Value $forwardTraffic -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkAccess' -Value $virtualNetworkAccess -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RemoteGateways' -Value $remoteGateways -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-VirtualNetworkPeerings ##
function Get-VirtualNetworks {
<#

.SYNOPSIS
Gets all virtual networks.

.DESCRIPTION
Gets all virtual networks.

.ROLE
Readers

.PARAMETER restParams
    An object containing SDN specific REST parameters

#>

param (
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module -Name NetworkController -DisableNameChecking -Global
Import-Module Microsoft.PowerShell.Management

$vnets = @(Get-NetworkControllerVirtualNetwork @paramsHash)
$vnets | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-VirtualNetworks ##
function Get-Vms {
<#

.SYNOPSIS
Gets all hyper-v virtual machines.

.DESCRIPTION
Gets all hyper-v virtual machines.

.ROLE
Readers

#>

Import-Module Hyper-V
Import-Module Microsoft.PowerShell.Utility

$domain = (Get-CIMInstance CIM_ComputerSystem).Domain
@(Get-Vm | Microsoft.PowerShell.Utility\Select-Object name, id, @{Label="State"; Expression={$_.State.ToString()}}, @{Label="Server"; Expression={$_.ComputerName.ToString() + '.' + $domain.ToString()}})

}
## [END] Get-Vms ##
function New-BGPPeer {
<#

.SYNOPSIS
Create a new BGP Peer of a BGP Router in Virtual Network

.DESCRIPTION
This script is used to create a BGP Peer of a BGP Router in the Virtual Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $bgpPeerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $bgpPeerIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $bgpRouterASNNumber,

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

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

if($null -ne $myGw)
{
  throwIfResourceManaged $myGw

  #Fetching BGP Routers in Virtual Network
  $bgpRouters = $myGw.Properties.BgpRouters

  $bgpRouter = $bgpRouters | Where-Object {$_.Properties.IsGenerated -eq $False}

  if($null -ne $bgpRouter)
  {
    for($i=0; $i -lt $bgpPeerName.length; $i++)
    {
      # Create a new object for tenant BGP peer
      $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

      # Update the BGP peer properties
      $bgpPeerProperties.PeerIpAddress = $bgpPeerIPAddress[$i].bgpPeerIPAddress
      $bgpPeerProperties.ExtAsNumber = "0."+$bgpRouterASNNumber[$i].bgpRouterASNNumber

      # Add the new BGP peer for tenant
      New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $myGw.ResourceId -BgpRouterName $bgpRouter.ResourceId -ResourceId $bgpPeerName[$i].bgpPeerName -Properties $bgpPeerProperties @paramsHash -Force
    }
  }
} else {
  throw "Virtual Gateway Name of the selected Virtual Network not found"
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-BGPPeer ##
function New-BGPRouter {
<#

.SYNOPSIS
Create a new BGP Router in Virtual Network

.DESCRIPTION
This script is used to create a BGP Router in the Virtual Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $asnNumber,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterName,

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

#Fetch Virtual Networks available in the Cluster
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

# Fetch the Virtual Network Name of the selected Virtual Network Instance ID
foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

if($null -ne $myGw)
{
  throwIfResourceManaged $myGw

  # Create a new object for the Tenant BGP router
  $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

  # Update the BGP router properties
  $bgpRouterproperties.ExtAsNumber = "0.$asnNumber"

   # Add the new BGP router for the tenant
  New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId $myGw.ResourceId -ResourceId $bgpRouterName -Properties $bgpRouterProperties @paramsHash -Force
}
else
{
  # Create a new object for tenant virtual gateway
  $VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties

  # Specify the Virtual Subnet to use for routing between the gateway and virtual network
  $gatewaysubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $vNetName @paramsHash
  $VirtualGWProperties.GatewaySubnets = @()
  $VirtualGWProperties.GatewaySubnets += $gatewaysubnet

  # Update gateway pool reference
  $gwPool = Get-NetworkControllerGatewayPool @paramsHash

  $VirtualGWProperties.GatewayPools = @()
  $VirtualGWProperties.GatewayPools += $gwPool

  $VirtualGWProperties.RoutingType = "Dynamic"
  $VirtualGWProperties.NetworkConnections = @()
  $VirtualGWProperties.BgpRouters = @()

  # Update the rest of the virtual gateway object properties
  $resNew = New-NetworkControllerVirtualGateway -ResourceId "GW-$vNetName" -Properties $VirtualGWProperties @paramsHash -Force

  # Create a new object for the Tenant BGP router
  $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

  # Update the BGP router properties
  $bgpRouterproperties.ExtAsNumber = "0.$asnNumber"

  # Add the new BGP router for the tenant
  New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId "GW-$vNetName" -ResourceId $bgpRouterName -Properties $bgpRouterProperties @paramsHash -Force
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-BGPRouter ##
function New-VirtualNetwork {
<#

.SYNOPSIS
Creates a virtual network.

.DESCRIPTION
Creates a virtual network.

.ROLE
Administrators

.PARAMETER restParams
    An object containing SDN specific REST parameters

.PARAMETER resourceId
    The resource id of the virtual network to create.

.PARAMETER properties
    A json corresponding to the properties of the new virtual network.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $resourceId,

    [Parameter(Mandatory = $false)]
    [String]
    $properties,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

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

$props = $properties | ConvertFrom-Json

$existing = $null
$metadata = $null
$tags = $null
# get existing resource
try {
  $existing = Get-NetworkControllerVirtualNetwork -ResourceId $resourceId @paramsHash
} catch {
  # resource has not been created yet, do nothing
}
if ($null -ne $existing) {
  throwIfResourceManaged $existing
  $metadata = $existing.ResourceMetadata
  $tags = $existing.Tags
}

New-NetworkControllerVirtualNetwork -ResourceId $resourceId -Properties $props -ResourceMetadata $metadata -Tags $tags @paramsHash -Force

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-VirtualNetwork ##
function New-VirtualNetworkPeering {
<#

.SYNOPSIS
Create Virtual Network Peering

.DESCRIPTION
This script is used to create  Virtual Network Peering with another Virtual Network in the Cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $peeringVirtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $peeringName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowVirtualnetworkAccess,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowForwardedTraffic,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowGatewayTransit,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $useRemoteGateways,

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

#Fetch the Virtual Network Name
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash
$vnetPeer = $null

foreach ($virtualNetwork in $virtualNetworks) {
    $instanceId = $virtualNetwork.InstanceId
    if ($instanceId -eq $virtualNetworkInstanceId) {
      throwIfResourceManaged $virtualNetwork
      $virtualNetworkName = $virtualNetwork.ResourceId
    }
    if ($instanceId -eq $peeringVirtualNetworkInstanceId) {
      throwIfResourceManaged $virtualNetwork
      $vnetPeer = $virtualNetwork
    }
    if (($null -ne $virtualNetworkName) -and ($null -ne $vnetPeer)) {
      break
    }
}

#create a new object for Virtual Network Peering
$peeringProperties = New-Object Microsoft.Windows.NetworkController.VirtualNetworkPeeringProperties

#Fetch the Virtual Network Details
$peeringProperties.remoteVirtualNetwork = $vnetPeer

# Indicates whether communication between the two virtual networks is allowed
$peeringProperties.allowVirtualnetworkAccess = [System.Convert]::ToBoolean($allowVirtualnetworkAccess)

# Indicates whether forwarded traffic will be allowed across the vnets
$peeringProperties.allowForwardedTraffic = [System.Convert]::ToBoolean($allowForwardedTraffic)

# Indicates whether the peer virtual network can access this virtual networks gateway
$peeringProperties.allowGatewayTransit = [System.Convert]::ToBoolean($allowGatewayTransit)

# Indicates whether this virtual network will use peer virtual networks gateway
$peeringProperties.useRemoteGateways = [System.Convert]::ToBoolean($useRemoteGateways)

$result = New-NetworkControllerVirtualNetworkPeering -VirtualNetworkId $virtualNetworkName -ResourceId $peeringName -Properties $peeringProperties @paramsHash -Force

# Preapring Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-VirtualNetworkPeering ##
function New-VirtualSubnet {
<#

.SYNOPSIS
Creates a virtual subnet.

.DESCRIPTION
Creates a virtual subnet.

.ROLE
Administrators

.PARAMETER restParams
    An object containing SDN specific REST parameters

.PARAMETER virtualNetworkResourceId
    The resource id of the parent virtual network.

.PARAMETER virtualSubnetResourceId
    The resource id of the virtual subnet to create.

.PARAMETER properties
    A json corresponding to the properties of the new virtual subnet.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $virtualNetworkResourceId,

    [Parameter(Mandatory = $true)]
    [String]
    $virtualSubnetResourceId,

    [Parameter(Mandatory = $false)]
    [String]
    $properties,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

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

$props = $properties | ConvertFrom-Json

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkResourceId @paramsHash
throwIfResourceManaged $parent

New-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkResourceId -ResourceId $virtualSubnetResourceId -Properties $props @paramsHash -Force

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-VirtualSubnet ##
function Remove-BGPPeer {
<#

.SYNOPSIS
Remove BGP Peer of a BGP Router in Virtual Network

.DESCRIPTION
This script is used to Remove BGP Peer of a BGP Router in the Virtual Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerName,

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

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

if($null -ne $myGw)
{
  throwIfResourceManaged $myGw

  #Fetching BGP Routers in Virtual Network
  $bgpRouters = $myGw.Properties.BgpRouters

  $bgpRouter = $bgpRouters | Where-Object {$_.Properties.IsGenerated -eq $False}

  if($null -ne $bgpRouter)
  {
    # Remove the BGP peer for tenant
    Remove-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $myGw.ResourceId -BgpRouterName $bgpRouter.ResourceId -ResourceId $bgpPeerName @paramsHash -Force

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
    $myResponse
  }
} else {
  throw "The Network Controller resource was not found"
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-BGPPeer ##
function Remove-VirtualNetwork {
<#

.SYNOPSIS
Deletes a virtual network.

.DESCRIPTION
Deletes a virtual network.

.ROLE
Administrators

.PARAMETER restParams
    An object containing SDN specific REST parameters

.PARAMETER resourceId
    The resource id of the virtual network to delete.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $resourceId,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

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
$existing = Get-NetworkControllerVirtualNetwork -ResourceId $resourceId @paramsHash
throwIfResourceManaged $existing

Remove-NetworkControllerVirtualNetwork -ResourceId $resourceId @paramsHash -Force

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-VirtualNetwork ##
function Remove-VirtualNetworkPeering {
<#

.SYNOPSIS
Delete Virtual Network Peering

.DESCRIPTION
This script is used to Delete Virtual Network Peering associated to particular Virtual Network in the Cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $peeringName,

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

#Fetch the Virtual Network Name
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  $instanceId = $virtualNetwork.InstanceId
  if($instanceId -eq $virtualNetworkInstanceId)
  {
    throwIfResourceManaged $virtualNetwork

    $virtualNetworkName = $virtualNetwork.ResourceId
    break
  }
}

Remove-NetworkControllerVirtualNetworkPeering -VirtualNetworkId $virtualNetworkName -ResourceId $peeringName @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-VirtualNetworkPeering ##
function Remove-VirtualSubnet {
<#

.SYNOPSIS
Deletes a virtual subnet of a virtual network.

.DESCRIPTION
Deletes a virtual subnet of a virtual network.

.ROLE
Administrators

.PARAMETER restParams
    An object containing SDN specific REST parameters

.PARAMETER virtualNetworkResourceId
    The resource id of the parent virtual network.

.PARAMETER virtualSubnetResourceId
    The resource id of the virtual subnet to delete.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $virtualNetworkResourceId,

    [Parameter(Mandatory = $true)]
    [String]
    $virtualSubnetResourceId,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

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
$parent = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkResourceId @paramsHash
throwIfResourceManaged $parent

Remove-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkResourceId -ResourceId $virtualSubnetResourceId @paramsHash -Force

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-VirtualSubnet ##
function Update-BGPPeer {
<#

.SYNOPSIS
Update the existing BGP Peer of a BGP Router in Virtual Network

.DESCRIPTION
This script is used to Update the existing BGP Peer of a BGP Router in the Virtual Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterASNNumber,

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

#Fetch Virtual Networks
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

if($null -ne $myGw)
{
  throwIfResourceManaged $myGw

  #Fetching BGP Routers in Virtual Network
  $bgpRouters = $myGw.Properties.BgpRouters

  $bgpRouter = $bgpRouters | Where-Object {$_.Properties.IsGenerated -eq $False}

  if($null -ne $bgpRouter)
  {
    $existing = $bgpRouter.Properties.BgpPeers | Where-Object {$_.ResourceId -eq $bgpPeerName}
    $metadata = $null
    if ($null -ne $existing) {
      $metadata = $existing.ResourceMetadata
    }

    # Create a new object for tenant BGP peer
    $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

    # Update the BGP peer properties
    $bgpPeerProperties.PeerIpAddress = $bgpPeerIPAddress
    $bgpPeerProperties.ExtAsNumber = "0.$bgpRouterASNNumber"

    
    New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $myGw.ResourceId -BgpRouterName $bgpRouter.ResourceId -ResourceId $bgpPeerName -Properties $bgpPeerProperties -ResourceMetadata $metadata @paramsHash -Force
  }
} else {
  throw "The Network Controller resource was not found"
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-BGPPeer ##
function Update-BGPRouter {
<#

.SYNOPSIS
Create a new BGP Router in Virtual Network

.DESCRIPTION
This script is used to create a BGP Router in the Virtual Network

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $asnNumber,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterName,

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

#Fetch Virtual Networks available in the Cluster
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

# Fetch the Virtual Network Name of the selected Virtual Network Instance ID
foreach($virtualNetwork in $virtualNetworks)
{
  #Fetch Virtual Network Instance Id
  $virtualNetworkInstanceID = $virtualNetwork.InstanceId
  if($virtualNetworkInstanceID -eq $virtualNetworkID)
  {
    # Fetch Virtual Network Name
    $vNetName = $virtualNetwork.ResourceRef.split('/')[2]
    break
  }
}

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$myGw = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2] -ieq $vNetName}

if($null -ne $myGw)
{
  throwIfResourceManaged $myGw

  $existing = $myGw.Properties.BgpRouters | Where-Object {$_.ResourceId -eq $bgpRouterName}
  $metadata = $null
  if ($null -ne $existing) {
    $metadata = $existing.ResourceMetadata
  }

  # Create a new object for the Tenant BGP router
  $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

  # Update the BGP router properties
  $bgpRouterproperties.ExtAsNumber = "0.$asnNumber"

  #Fetch the BGP Peers of the BGP Router
  $bgpPeers = $existing.Properties.BgpPeers
  $bgpRouterproperties.BgpPeers = @()
  if ($null -ne $bgpPeers) {
    $bgpRouterproperties.BgpPeers += $bgpPeers
  }

  # Add the new BGP router for the tenant
  New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId $myGw.ResourceId -ResourceId $bgpRouterName -Properties $bgpRouterProperties -ResourceMetadata $metadata @paramsHash -Force

} else {
  throw "The Network Controller resource was not found"
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-BGPRouter ##
function Update-VirtualNetworkPeering {
<#

.SYNOPSIS
Update Virtual Network Peering

.DESCRIPTION
This script is used to Update Virtual Network Peering with another Virtual Network in the Cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetworkInstanceId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $peeringVirtualNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $peeringName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowVirtualnetworkAccess,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowForwardedTraffic,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $allowGatewayTransit,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $useRemoteGateways,

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

#Fetch the Virtual Network Name
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

foreach ($virtualNetwork in $virtualNetworks) {
  $instanceId = $virtualNetwork.InstanceId
  if ($instanceId -eq $virtualNetworkInstanceId) {
    throwIfResourceManaged $virtualNetwork
    $virtualNetworkName = $virtualNetwork.ResourceId
    break
  }
}

$existing = $null
$metadata = $null
$existing = Get-NetworkControllerVirtualNetworkPeering -VirtualNetworkId $virtualNetworkName -ResourceId $peeringName @paramsHash
$metadata = $existing.ResourceMetadata

#create a new object for Virtual Network Peering
$peeringProperties = New-Object Microsoft.Windows.NetworkController.VirtualNetworkPeeringProperties

#Fetch the Virtual Network Details
$virtualNetwork = Get-NetworkControllerVirtualNetwork -ResourceId $peeringVirtualNetworkName @paramsHash
$peeringProperties.remoteVirtualNetwork = $virtualNetwork

# Indicates whether communication between the two virtual networks is allowed
$peeringProperties.allowVirtualnetworkAccess = [System.Convert]::ToBoolean($allowVirtualnetworkAccess)

# Indicates whether forwarded traffic will be allowed across the vnets
$peeringProperties.allowForwardedTraffic = [System.Convert]::ToBoolean($allowForwardedTraffic)

# Indicates whether the peer virtual network can access this virtual networks gateway
$peeringProperties.allowGatewayTransit = [System.Convert]::ToBoolean($allowGatewayTransit)

# Indicates whether this virtual network will use peer virtual networks gateway
$peeringProperties.useRemoteGateways = [System.Convert]::ToBoolean($useRemoteGateways)

$result = New-NetworkControllerVirtualNetworkPeering -VirtualNetworkId $virtualNetworkName -ResourceId $peeringName -Properties $peeringProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-VirtualNetworkPeering ##
function Update-VirtualSubnetwithAccessControlList {
<#

.SYNOPSIS
Add Access Control Lists to the Subnet of a Virtual Network

.DESCRIPTION
This script is used to add Access Control Lists to the Subnet of a Virtual Network to update the properties
of a Subnet

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $False)]
    [string] $aclName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $addressPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $subnetName,

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

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.Subnets | Where-Object {$_.ResourceId -ieq $subnetName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

#Create New object for the Virtual Subnet Properties
$virtualSubnetProperties = New-Object Microsoft.Windows.NetworkController.VirtualSubnetProperties
if ($null -ne $existing) {
  $virtualSubnetProperties = $existing.Properties
}

#Fetch the Access Control List
if (-not [string]::IsNullOrWhiteSpace($aclName) -and $aclName -ne "None")
{
  $acl = Get-NetworkControllerAccessControlList -ResourceId $aclName @paramsHash

  #Add the ACL to the Subnet Properties
  $virtualSubnetProperties.AccessControlList = $acl
}

$virtualSubnetProperties.AddressPrefix = $addressPrefix

#Update the properties of the subnet
$result = New-NetworkControllerVirtualSubnet -ResourceId $subnetName -VirtualNetworkId $virtualNetworkName -Properties $virtualSubnetProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-VirtualSubnetwithAccessControlList ##

# SIG # Begin signature block
# MIIoUgYJKoZIhvcNAQcCoIIoQzCCKD8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDCg64xfSwkH1Hk
# KqW/+QTBG6H0kBqTViwvcxGbTeYzZqCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMfj
# Z+BcdM5ldZvit8LLWnOFx/ChIaHR1BZStFuf+TvsMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAs0WSGmBvCLyPPinKDh63kyYSevDQBJ2NiDoJ
# LwDmkoIpfzZmrAZVystodR3q47bimb89F/r1abAUjJ2nUK/43yJ6cRzkZl3Mx130
# C7PVomnC5kfyxd7dylhqMmyfPE+1SR2z1hdAHfc1forQTUWQ/QIKNxswAx6MBGJW
# hUMXJgoWxVQdRtZ6HBDUTwqe4o3zAm29Rpd/YpX7zJY+5ojPvFsBvxSHNiiKVKIT
# SKREQ3dhDYRqRjTRdRGLbiqT2ils8wpc/kQp1t939Of9rT3jN3/oAj3re0b4Yu1C
# tXjYpa6CDKYK3iz6q+8sh9HMAzj0xgPa4Vy8tYRPLBkOunbGq6GCF60wghepBgor
# BgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCCF4YwgheCAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCFhNWd4FFBDNEXaKuHF3Mo07aPBPusmqNB
# rTuTen4UpwIGaQIxAReTGBMyMDI1MTExMDE3MTczMy4zOTJaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjoyRDFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggcoMIIFEKADAgECAhMzAAACEtEI
# BjzKGE+qAAEAAAISMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgxNVoXDTI2MTExMzE4NDgxNVowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjJEMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# r0zToDkpWQtsZekS0cV0quDdKSTGkovvBaZH0OAIEi0O3CcO77JiX8c4Epq9uibH
# VZZ1W/LoufE172vkRXO+QYNtWWorECJ2AcZQ10bpAltkhZNiXlVJ8L3QzhKgrXrm
# Mkm2J+/g81U23JPcO4wXHEftonT3wpd//936rjmwxMm7NkbsygbJf+4AVBMNr4aM
# PQhBd76od0KMB6WrvyEGOOU0893OFufS5EDey4n44WgaxJE0Vnv3/OOvuOw5Kp1K
# PqjjYJ+L9ywLuBMtcDfLpNQO/h1eFEoMrbiEM67TOfNlXfxbDz4MlsYvLioxgd2X
# zey1QxrV1+i+JyVDJMiSe9gKOuzpiQQFE19DUPgsidyjLTzXEhSVLBlRor0eCVf7
# gC6Rfk8NY3rO2sggOL79vU5FuDKTh/sIOtcUHeHC42jBGB+tfdKC1KOBR+UlN9aO
# zg8mpUNI2FgqQvirVP9ppbeMUfvp2wA9voyTiRWvDgzCxo8xlJ1nscYTHIQrmkF9
# j/Ca0IDmt8fvOn64nnlJOGUYZYHMC1l0xtgkYTE1ESUqqkawKk7iqbxdnLyycS+d
# R+zaxPudMDLrQFz8lgfy9obk0D8HC2dzhWpYNn5hdkoPEzgCqQUOp8v3Qj/sd4an
# yupe5KoCkjABOP3yhSQ4W9Z+DrJnhM/rbsXC7oTv26cCAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBRSBblSxb5cYKYOwvd/VfoXOfu33jAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAXnSAkmX79Rc7lxS1wOozXJ7V0ou5DntVcOJplIkDjvEN8BIQph4U+gSO
# LZuVReP/z9YdUiUkcPwL1PM245/kEX1EegpxNc8HDA6hKCHg0ALNEcuxnGOlgKLo
# kXfUer1D5hiW8PABM9R+neiteTgPaaRlJFvGTYvotc0uqGiES5hMQhL8RNFhpS9R
# cIWHtnQGEnrdOUvCAhs4FeViawcmLTKv+1870c/MeTHi0QDdeR+7/Wg4qhkJ2k1i
# EHJdmYf8rIV0NRBZcdRTTdHee35SXP5neNCfAkjDIuZycRud6jzPLCNLiNYzGXBs
# wzJygj4EeSORT7wMvaFuKeRAXoXC3wwYvgIsI1zn3DGY625Y+yZSi8UNSNHuri36
# Zv9a+Q4vJwDpYK36S0TB2pf7xLiiH32nk7YK73Rg98W6fZ2INuzYzZ7Ghgvfffkj
# 4EUXg1E0EffY1pEqkbpDTP7h/DBqtzoPXsyw2MUh+7yvWcq2BGZSuca6CY6X4ioM
# uc5PWpsmvOOli7ARNA7Ab8kKdCc2gNDLacglsweZEc9/VQB6hls/b6Kk32nkwuHE
# xKlaeoSVrKB5U9xlp1+c8J/7GJj4Rw7AiQ8tcp+WmfyD8KxX2QlKbDi4SUjnglv4
# 617R8+a/cDWJyaMt8279Wn7f2yMedN7kfGIQ5SZj66RdhdlZOq8wggdxMIIFWaAD
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
# Hm5TaGllbGQgVFNTIEVTTjoyRDFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA5VHBr4h00EN7
# jUdQ33SE+qbk/8CggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy8gKowIhgPMjAyNTExMTAxNTE4MDJaGA8yMDI1
# MTExMTE1MTgwMlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7LyAqgIBADAHAgEA
# AgI3KzAHAgEAAgISwTAKAgUA7L3SKgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQBTGbSliEM/gL81RHBqcHihkcsXf6r1Ebd92OfjRkugMuqwnWPSvX7JGCYA
# s0wDjpQKIvMmY4aiBIGNJIa0VzLaaujFazIAvD/E0BhSORr8qanVYJAchSbpTRkk
# ui+OWRwtZXZQJoW/3FUKzL9cXu7sWXCeJb9tAIeHRRuHRQ6rHP09mLbW5c2N/qKM
# ilOHkZIuSwUzxOYOCfzDhuNLdIgz388W3kr0eYETcfKuZBAcxpLT0N4pr50jsuWW
# RrlcOVlYdF9lehNAmWSRxNZ2uIigmxYOaU3DxwZy076XtyXcxRinWUjB86V0yC6h
# f5kDsZoPecwXaH25+Ts5uuucwbWrMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAIS0QgGPMoYT6oAAQAAAhIwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgwNOHgk1QP9LHfPTRqBwEmaKCTu9p0FCvgBdf6vxRElYwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCBz+X5GvO7WngknH4BZeYU+BzBL1Jy5oJ8wVlTN
# IxfYgzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAC
# EtEIBjzKGE+qAAEAAAISMCIEIANCrcO3hii2I1Xr+8QrZ6VPi2dSnusj6tOMjLxW
# SuZcMA0GCSqGSIb3DQEBCwUABIICAAFPPRlqdqeI8q7LrtdtofmysrlLzQtD5pQq
# CxbmfDmF5tjXTXjPSOI1tYSY0tirOeINkhICtGplKPhHAGAw9yVkFGfphViTwvVn
# Kkw3+rF0GQBhfnn6tAeC5cVokfbxsF1eamgQ+gS0A5+UR8vtjMFXauZ2ipniOsdV
# wIY9so+uugh8M6SJ7CFf1ICzKSfP3dtkTlVwzxyj/aue6FL6KiwSxPaqnGSc1Bvl
# zpROn+gz16L4oTorHedwExh8j0QfLD2Uwfz5M6Y79patGA7sENA9c/j1zVnKxvKo
# zm5d4uu29lAizh84YReuxdk3PDcMBUtFGWstL+dhA8hriZWinQvs12kjNvqXLIDj
# 2n2gZiTcsXLu8UqVPdSV6jiJnb2A6bVs9QmvLhFLHSdoyuD6G16yNmI9YN1GvTmw
# iHR1SiY70jqJaxRmaoxj5NKGiPspgXXGwqjbOfiRDIhtcVK9csuIg/fk5jJcWtbq
# FAybOo+lJEBPUmRCj+YpSWVB0pGtXeyk91rr4elYJTJ2KUTcprIfMlYV5WyHeQsI
# edtjoc4nJ3WDbQXmsl+cPh2bbseREigZuxMoUrEYaDGDzwF3jU6lbG8Dr8rSqBcS
# sAoeAjPPjS3wrQkoQtKPH3GUvPq9Y0O9/28gX8YkxVaibC6dPhiRdzsfxSC8ftV2
# fFQHZFWl
# SIG # End signature block
