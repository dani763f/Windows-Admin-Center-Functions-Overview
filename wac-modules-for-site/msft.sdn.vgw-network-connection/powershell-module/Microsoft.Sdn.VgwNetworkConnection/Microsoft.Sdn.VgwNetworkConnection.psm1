function Compare-IpAddressRangeValidation {
<#

.SYNOPSIS
Validate if IP Address is in the range of subnet

.DESCRIPTION
This script is used to validate if IP Address is in the range of subnet

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $SubnetRange,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $IpToValidate

)
$matchCount = 0

$startIp = $SubnetRange.split('/')[0]
$range = [Int]$SubnetRange.split('/')[1]

$decimalValueRange = $startIp.split('.')
$decimalValueIpToValidate = $IpToValidate.split('.')
for($i = 0 ; $i -lt 4 ; $i++)
{
   if($i -eq 0)
   {
        if ([Int]$decimalValueIpToValidate[$i] -eq [Int]$decimalValueRange[$i])
        {
            $matchCount++
        }
   }
   else
   {
        if ([Int]$decimalValueIpToValidate[$i] -le [Int]$range)
        {
            $matchCount++
        }
   }
}
$result = $false

if($matchCount -eq 4)
{
    $result = $true
}

$result

}
## [END] Compare-IpAddressRangeValidation ##
function Get-BGPRoutersAvailableorNot {
<#

.SYNOPSIS
Get BGP Routers from the Virtual Network

.DESCRIPTION
This script is used to Get BGP Routers from the Virtual Network

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

# Get BGP Routers from the Virtual Network

$vNetGatewayName=""

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
Foreach($myGw in $allGateways)
{
    # Fetch Virtual Network Name
    $virtualNetworkName =  $myGw.Properties.GatewaySubnets.ResourceRef
    if($virtualNetworkName.split('/')[2].ToLower() -eq $virtualNetwork.ToLower())
    {
        # Getting Virtual Gateway Name
        $vNetGatewayName = $myGw.ResourceId

        break
    }
}

if($vNetGatewayName -ne "")
{
    $vnetgateway = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash

    $bgpRoutersIsGenerated= $vnetgateway.Properties.BgpRouters.Properties.IsGenerated

    if($bgpRoutersIsGenerated -eq $false)
    {
        $bgpRouters = "Available"
    }
    else
    {
        $bgpRouters = "Not Available"
    }
    # Preparing Object Response of Get BGP Routers from the Virtual Network

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouters' -Value $bgpRouters -ErrorAction SilentlyContinue

    $myResponse

}
else
{
    $bgpRouters = "Not Available"

    # Preparing Object Response of Get BGP Routers from the Virtual Network

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouters' -Value $bgpRouters -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-BGPRoutersAvailableorNot ##
function Get-GatewayConnectionDetails {

<#

.SYNOPSIS
Get details of Gateway connection

.DESCRIPTION
This script is used to Get deatils of particular Gateway Connection in Gateway connections available in the cluster

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

#Fetch the Gateway connection details
$gatewayConnection = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName @paramsHash

#Fetch Connection Type of Gateway Connection
$connectionType = $gatewayConnection.Properties.ConnectionType

if($connectionType -eq "IPSec")
{
    #Fetch Name
    $name = $gatewayConnection.ResourceId

    #Fetch Destination IP
    $destinationIP = $gatewayConnection.Properties.DestinationIPAddress

    #Fetch Maximum Allowed Inbound Bandwidth
    $maximumAllowedInboundBandwidth = $gatewayConnection.Properties.InboundKiloBitsPerSecond

    #Fetch Maximum Allowed Outbound Bandwidth
    $maximumAllowedOutboundBandwidth = $gatewayConnection.Properties.OutboundKiloBitsPerSecond

    #Fetch Destination IP Prefix
    $destinationIpPrefix = 0
    $destinationIpPrefix =@()
    $destinationIpPrefix += $gatewayConnection.Properties.Routes.DestinationPrefix

    #Fetch Route Metric
    $routeMetric = 0
    $routeMetric =@()
    $routeMetric += $gatewayConnection.Properties.Routes.Metric

    #Fetch Diffie Hellman Group in MainMode of IpSec Configuration
    $diffieHellmanGroup = $gatewayConnection.Properties.IpSecConfiguration.MainMode.DiffieHellmanGroup

    #Fetch Encryption Algorithm in MainMode of IpSec Configuration
    $encryptionAlgorithm = $gatewayConnection.Properties.IpSecConfiguration.MainMode.EncryptionAlgorithm

    #Fetch Integrity Algorithm in MainMode of IpSec Configuration
    $integrityAlgorithm = $gatewayConnection.Properties.IpSecConfiguration.MainMode.IntegrityAlgorithm

    #Fetch SA Life Time Seconds in MainMode of IpSec Configuration
    $mainModeSALifeTimeSeconds = $gatewayConnection.Properties.IpSecConfiguration.MainMode.SALifeTimeSeconds

    #Fetch SA Life Time KiloBytes in MainMode of IpSec Configuration
    $mainModeSALifeTimeKiloBytes = $gatewayConnection.Properties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes

    #Fetch Perfect Forward Secrecy in QuickMode of IpSec Configuration
    $perfectForwardSecrecy = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy

    #Fetch Cipher Transformation Constant in QuickMode of IpSec Configuration
    $cipherTransformationConstant = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.CipherTransformationConstant

    #Fetch Authentication Transformation Constant in QuickMode of IpSec Configuration
    $authenticationTransformationConstant = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant

    #Fetch Idle Disconnect Seconds in QuickMode of IpSec Configuration
    $idleDisconnectSeconds = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds

    #Fetch SA Life Time Seconds in QuickMode of IpSec Configuration
    $quickModeSALifeTimeSeconds = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.SALifeTimeSeconds

    #Fetch SA Life Time KiloBytes in QuickMode of IpSec Configuration
    $quickModeSALifeTimeKiloBytes = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIP' -Value $destinationIP -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedInboundBandwidth' -Value $maximumAllowedInboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedOutboundBandwidth' -Value $maximumAllowedOutboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIpPrefix' -Value $destinationIpPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RouteMetric' -Value $routeMetric -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DiffieHellmanGroup' -Value $diffieHellmanGroup -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EncryptionAlgorithm' -Value $encryptionAlgorithm -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IntegrityAlgorithm' -Value $integrityAlgorithm -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MainModeSALifeTimeSeconds' -Value $mainModeSALifeTimeSeconds -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MainModeSALifeTimeKiloBytes' -Value $mainModeSALifeTimeKiloBytes -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PerfectForwardSecrecy' -Value $PerfectForwardSecrecy -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'CipherTransformationConstant' -Value $cipherTransformationConstant -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AuthenticationTransformationConstant' -Value $authenticationTransformationConstant -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleDisconnectSeconds' -Value $idleDisconnectSeconds -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'QuickModeSALifeTimeSeconds' -Value $quickModeSALifeTimeSeconds -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'QuickModeSALifeTimeKiloBytes' -Value $quickModeSALifeTimeKiloBytes -ErrorAction SilentlyContinue
    $myResponse
}

if($connectionType -eq "GRE")
{
    #Fetch Name
    $name = $gatewayConnection.ResourceId

    #Fetch Destination IP
    $destinationIP = $gatewayConnection.Properties.DestinationIPAddress

    #Fetch Maximum Allowed Inbound Bandwidth
    $maximumAllowedInboundBandwidth = $gatewayConnection.Properties.InboundKiloBitsPerSecond

    #Fetch Maximum Allowed Outbound Bandwidth
    $maximumAllowedOutboundBandwidth = $gatewayConnection.Properties.OutboundKiloBitsPerSecond

    #Fetch Destination IP Prefix
    $destinationIpPrefix = 0
    $destinationIpPrefix =@()
    $destinationIpPrefix += $gatewayConnection.Properties.Routes.DestinationPrefix

    #Fetch Route Metric
    $routeMetric = 0
    $routeMetric =@()
    $routeMetric += $gatewayConnection.Properties.Routes.Metric

    #Fetch GRE key
    $greKey = $gatewayConnection.Properties.GreConfiguration.GreKey

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIP' -Value $destinationIP -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedInboundBandwidth' -Value $maximumAllowedInboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedOutboundBandwidth' -Value $maximumAllowedOutboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIpPrefix' -Value $destinationIpPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RouteMetric' -Value $routeMetric -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'GreKey' -Value $greKey -ErrorAction SilentlyContinue
    $myResponse
}

if($connectionType -eq "L3")
{
    #Fetch Name
    $name = $gatewayConnection.ResourceId

    #Fetch Maximum Allowed Inbound Bandwidth
    $maximumAllowedInboundBandwidth = $gatewayConnection.Properties.InboundKiloBitsPerSecond

    #Fetch Maximum Allowed Outbound Bandwidth
    $maximumAllowedOutboundBandwidth = $gatewayConnection.Properties.OutboundKiloBitsPerSecond

    #Fetch Destination IP Prefix
    $destinationIpPrefix = 0
    $destinationIpPrefix =@()
    $destinationIpPrefix += $gatewayConnection.Properties.Routes.DestinationPrefix

    #Fetch Route Metric
    $routeMetric = 0
    $routeMetric =@()
    $routeMetric += $gatewayConnection.Properties.Routes.Metric

    #Fetch Logical Network of L3 Configuration
    $logicalNetwork = $gatewayConnection.Properties.l3Configuration.vlanSubnet.resourceRef.split('/')[2]

    #Fetch Logical Subnet of L3 Configuration
    $logicalSubnetName = $gatewayConnection.Properties.l3Configuration.vlanSubnet.resourceRef.split('/')[4]

    $lSubnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetwork -ResourceId $logicalSubnetName @paramsHash

    #Fetch the Address Prefix of Subnet
    $addressPrefix = $lSubnet.Properties.AddressPrefix

    $logicalSubnet=  $logicalSubnetName +" "+"-"+" "+ $addressPrefix

    #Fetch Ip Address of L3 Configuration
    $ipAddress = $gatewayConnection.Properties.ipAddresses.ipAddress

    #Fetch Prefix Prefix Lenght of L3 Configuration
    $prefixLength = $gatewayConnection.Properties.ipAddresses.prefixLength

    $l3IPSubnetMask = $ipAddress +"/"+ $prefixLength

    #Fetch Peer Ip Address of L3 Configuration
    $peerIPAddresses = $gatewayConnection.Properties.peerIPAddresses

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedInboundBandwidth' -Value $maximumAllowedInboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedOutboundBandwidth' -Value $maximumAllowedOutboundBandwidth -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIpPrefix' -Value $destinationIpPrefix -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RouteMetric' -Value $routeMetric -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetwork' -Value $logicalNetwork -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnet' -Value $logicalSubnet -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'L3SubnetMask' -Value $l3IPSubnetMask -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PeerIPAddresses' -Value $peerIPAddresses -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-GatewayConnectionDetails ##
function Get-GatewayConnections {
<#

.SYNOPSIS
Get Gateway connections in the cluster

.DESCRIPTION
This script is used to List all Gateway connections available in the cluster

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

Import-Module NetworkController -Force

$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

foreach($virtualGateway in $virtualGateways)
{
    #Fetch VirtualNetwork
    $virtualNetworkName =  $virtualGateway.Properties.GatewaySubnets.ResourceRef.split('/')[2]

    #Fetch Virtual Network Instance Id
    $virtualNetworks = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkName @paramsHash
    $virtualNetworkInstanceId = $virtualNetworks.InstanceId

    #Fetch Address Prefix
    $virtualNetworkAddressPrefix = $virtualNetworks.Properties.AddressSpace.AddressPrefixes

    #Fetch Gateway ID
    $gatewayID = $virtualGateway.ResourceRef.split('/')[2]

    #Fetch Gateway Pool
    $gatewayPool = $virtualGateway.Properties.GatewayPools.ResourceRef.split('/')[2]

    #Fetch Tags for the Gateway
    $gatewayTags = $virtualGateway.Tags

    #Fetch BGP Status
    $bgpStatus = ""
    if($virtualGateway.Properties.BgpRouters.length -gt 0 -and $virtualGateway.Properties.BgpRouters.Properties.IsGenerated -eq $false)
    {
        $bgpStatus="Enabled"
        $bgpRouterName = $virtualGateway.Properties.BgpRouters.ResourceId
        $bgpRouterAsNumber = $virtualGateway.Properties.BgpRouters.Properties.ExtAsNumber.split('.')[1]
        $bgpRouterIP = $virtualGateway.Properties.BgpRouters.Properties.RouterIP
        $bgpPeers = $virtualGateway.Properties.BgpRouters.Properties.BgpPeers
        $bgpPeerName = $bgpPeers.ResourceId
        $bgpIPAddress = $bgpPeers.Properties.PeerIpAddress
        $bgpAsNumber = $bgpPeers.Properties.AsNumber
    }
    else
    {
        $bgpStatus="Disabled"
        $bgpRouterName = $null
        $bgpRouterAsNumber = $null
        $bgpRouterIP = $null
        $bgpPeerName = $null
        $bgpIPAddress = $null
        $bgpAsNumber = $null
    }

    $gatewayConnections = $virtualGateway.Properties.NetworkConnections

    foreach($gatewayConnection in $gatewayConnections)
    {
        #Fetch Name
        $name = $gatewayConnection.ResourceId

        #Fetch type
        $type = $gatewayConnection.Properties.ConnectionType

        #Fetch Configuration State
        $configurationState = $gatewayConnection.Properties.ConfigurationState.Status
        if($null -eq $configurationState)
        {
            $configurationState = "Unknown"
            $configurationStateDetailedInfo = "Check Gateway Status in the SDN-Monitoring page for more information"
        }
        else
        {
            #Fetch Configuration State Detailed Info
            $configurationStateDetailedInfo = $gatewayConnection.Properties.ConfigurationState.DetailedInfo.Message
        }

        #Fetch Source IpAddress
        $sourceIpAddress = $gatewayConnection.Properties.SourceIPAddress

        #Fetch Destination IP
        $destinationIP = $gatewayConnection.Properties.DestinationIPAddress

        #Fetch Connection Status
        $connectionStatus = $gatewayConnection.Properties.ConnectionStatus

        #Fetch Connection State
        $connectionState = $gatewayConnection.Properties.ConnectionState

        #Fetch Maximum Allowed Inbound Bandwidth
        $maximumAllowedInboundBandwidth = [String] $gatewayConnection.Properties.InboundKiloBitsPerSecond + ' KBPS'

        #Fetch Maximum Allowed Outbound Bandwidth
        $maximumAllowedOutboundBandwidth = [String] $gatewayConnection.Properties.OutboundKiloBitsPerSecond + ' KBPS'

        #Fetch Gateway VM and InstanceId
        $gatewayVM = $gatewayConnection.Properties.Gateway
        if($gatewayVM.Length -gt 0)
        {
            $gatewayVMName = $gatewayVM.ResourceRef.split('/')[2]
        }
        else
        {
            $gatewayVMName = $gatewayVM
        }

        #Fetch Destiation IP Prefix
        $destinationIpPrefix = ""
        foreach($route in $gatewayConnection.Properties.Routes)
        {
            $newRoutePair=[string]$route.Metric+" " + "|"+" " + $route.DestinationPrefix
            $destinationIpPrefix += $newRoutePair +", "
        }
        if($destinationIpPrefix -ne "" -and $destinationIpPrefix.length -gt 0)
        {
            $destinationIpPrefix =  $destinationIpPrefix.substring(0,$destinationIpPrefix.length - 1)
        }


        #Fetch Authentication Method
        $authMethod = $gatewayConnection.Properties.IpSecConfiguration.AuthenticationMethod

        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationStateDetailedInfo' -Value $configurationStateDetailedInfo -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetworkName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkAddressPrefix' -Value $virtualNetworkAddressPrefix -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'SourceIpAddress' -Value $sourceIpAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIP' -Value $destinationIP -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConnectionStatus' -Value $connectionStatus -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConnectionState' -Value $connectionState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedInboundBandwidth' -Value $maximumAllowedInboundBandwidth -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'MaximumAllowedOutboundBandwidth' -Value $maximumAllowedOutboundBandwidth -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayVM' -Value $gatewayVMName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Routes' -Value $destinationIpPrefix -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'AuthenticationMethod' -Value $authMethod -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayID' -Value $gatewayID -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPStatus' -Value $bgpStatus -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterAsNumber' -Value $bgpRouterAsNumber -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerAsNumber' -Value $bgpAsNumber -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIP' -Value $bgpIPAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $gatewayPool -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Tags' -Value $gatewayTags -ErrorAction SilentlyContinue
        $myResponse
    }
}

}
## [END] Get-GatewayConnections ##
function Get-GatewayList {
<#

.SYNOPSIS
Get Gateways in the cluster

.DESCRIPTION
This script is used to check whether gateways available or Unavailable in the cluster

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

Import-Module NetworkController -Force

$gateways = Get-NetworkControllerGateway @paramsHash

return ($null -ne $gateways) -and ($gateways.length -gt 0)

}
## [END] Get-GatewayList ##
function Get-GatewayPools {
<#

.SYNOPSIS
Get Gateway Pools

.DESCRIPTION
This script is used to Get Gateway Pools

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

$allGateways = Get-NetworkControllerVirtualGateway @paramsHash
$gatewayPoolObject =  Get-NetworkControllerGatewayPool @paramsHash
$ipPoolsToList = @()
$myPoolTypeArray = @()
$vNetGatewayName = ""

Foreach($myGw in $allGateways)
{
    #Fetch Virtual Network Name
    $virtualNetworkName =  $myGw.Properties.GatewaySubnets.ResourceRef
    if($virtualNetworkName.split('/')[2].ToLower() -eq $virtualNetwork.ToLower())
    {
        #Getting Virtual Gateway Name
        $vNetGatewayName = $myGw.ResourceId
        #Getting associated gatewaypools
        $allAssociatedPools = $myGw.Properties.GatewayPools
        foreach($myPoolObject in $allAssociatedPools)
        {
        #Fetch GatewayPool Name
        $myPoolName = $myPoolObject.ResourceRef.split('/')[2]

        #Getting GatewayPool Type by Name
        $myPoolTypeArray += ($gatewayPoolObject | Where-Object {$_.ResourceId -Match $myPoolName}).Properties.Type
        }
        break
    }
}
#Getting display name of the selected type
$ipPoolDisplayName = ($gatewayPoolObject | Where-Object {$_.Properties.Type -Match $connectionType}).ResourceId
$ipPoolDisplayTypes = $gatewayPoolObject.Properties.Type
if($vNetGatewayName -ne "")
{
    if ($null -ne $myPoolTypeArray)
    {
        if($myPoolTypeArray -contains $connectionType)
        {
            $ipPoolsToList += $ipPoolDisplayName
        }
        else
        {
            if($myPoolTypeArray.ToLower() -contains "all")
            {
                $ipPoolsToList += ($gatewayPoolObject | Where-Object {$_.Properties.Type -Match "All"}).ResourceId
            }
            else
            {
                $ipPoolsToList += $ipPoolDisplayName
            }
        }
    }
    else
    {
        if($ipPoolDisplayTypes -contains $connectionType)
        {
            $ipPoolsToList += $ipPoolDisplayName
        }
        $ipPoolsToList += ($gatewayPoolObject | Where-Object {$_.Properties.Type -Match "All"}).ResourceId
    }
}
else
{
    if($ipPoolDisplayTypes -contains $connectionType)
    {
        $ipPoolsToList += $ipPoolDisplayName
    }
    $ipPoolsToList += ($gatewayPoolObject | Where-Object {$_.Properties.Type -Match "All"}).ResourceId
}

#Preparing Object Response of Virtual Networks
$myResponse = @()
foreach($ipPoolSingle in $ipPoolsToList)
{
    $myResponse += New-Object -TypeName psobject -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpPool' -Value $ipPoolSingle -ErrorAction SilentlyContinue
}
$myResponse

}
## [END] Get-GatewayPools ##
function Get-GatewayVMId {
<#

.SYNOPSIS
Get VM id

.DESCRIPTION
Get VM id based on name from CIM

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory = $True)]
  [ValidateNotNullOrEmpty()]
  [object[]] $gateways
)

foreach ($gateway in $gateways) {
  $vm = $null
  $vmId = $null
  if ($null -ne $gateway.GatewayVM) {
    try {
      $vm = Get-CimInstance -Namespace "root\SDDC\Management" -ClassName SDDC_VirtualMachine -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object name , @{N = 'id'; E = { $_.Id.ToLower() } } | Where-Object { $_.name -match $gateway.GatewayVM }
      $vmId = $vm.id
    } catch {}
  }
  $gateway | Add-Member -MemberType NoteProperty -Name 'GatewayVMInstanceId' -Value $vmId -ErrorAction SilentlyContinue
  $gateway
}

}
## [END] Get-GatewayVMId ##
function Get-GreKey {
<#

.SYNOPSIS
Get Gre Key and Destination IPAddress Values

.DESCRIPTION
This script is used to Get Gre Key and Destination IPAddress Values

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

$vNetGatewayName=""

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
Foreach($myGw in $allGateways)
{
    # Fetch Virtual Network Name
    $virtualNetworkName =  $myGw.Properties.GatewaySubnets.ResourceRef
    if($virtualNetworkName.split('/')[2].ToLower() -eq $virtualNetwork.ToLower())
    {
        # Getting Virtual Gateway Name
        $vNetGatewayName = $myGw.ResourceId
        break
    }
}

if($vNetGatewayName -ne "")
{
    $vnetgateway = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash
    $networkConnections = $vnetgateway.Properties.NetworkConnections
    foreach($networkConnection in $networkConnections)
    {
        $connectionType = $networkConnection.Properties.ConnectionType
        if($connectionType -eq "GRE")
        {
            $connectionName = $networkConnection.ResourceId
            $gatewayConnection = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $vNetGatewayName -ResourceId $connectionName @paramsHash

            $destinationIP = $gatewayConnection.Properties.DestinationIPAddress
            $greKey = $gatewayConnection.Properties.GreConfiguration.GreKey

            # Preparing Object Response of Get Gre Key and Destination IPAddress Values
            $myResponse = New-Object -TypeName psobject
            $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIPAddress' -Value $destinationIP -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'GreKey' -Value $greKey -ErrorAction SilentlyContinue
            $myResponse
        }
    }
}
else
{
    $destinationIP = " "
    $greKey = " "

    # Preparing Object Response of Get Gre Key and Destination IPAddress Values
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationIPAddress' -Value $destinationIP -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'GreKey' -Value $greKey -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-GreKey ##
function Get-IpSecConfiguration {
<#

.SYNOPSIS
Get IPSEC Configuration in Gateway connections

.DESCRIPTION
This script is used to Get IPSEC Configuration in Gateway connections available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

#Get IPSEC Configuration in Gateway connections
$gatewayConnection = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayId -ResourceId $gatewayConnectionName @paramsHash

#Fetch Diffie Hellman Group in MainMode of IpSec Configuration
$diffieHellmanGroup = $gatewayConnection.Properties.IpSecConfiguration.MainMode.DiffieHellmanGroup

#Fetch Encryption Algorithm in MainMode of IpSec Configuration
$encryptionAlgorithm = $gatewayConnection.Properties.IpSecConfiguration.MainMode.EncryptionAlgorithm

#Fetch Integrity Algorithm in MainMode of IpSec Configuration
$integrityAlgorithm = $gatewayConnection.Properties.IpSecConfiguration.MainMode.IntegrityAlgorithm

#Fetch SA Life Time Seconds in MainMode of IpSec Configuration
$mainModeSALifeTimeSeconds = $gatewayConnection.Properties.IpSecConfiguration.MainMode.SALifeTimeSeconds

#Fetch SA Life Time KiloBytes in MainMode of IpSec Configuration
$mainModeSALifeTimeKiloBytes = $gatewayConnection.Properties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes

#Fetch Perfect Forward Secrecy in QuickMode of IpSec Configuration
$perfectForwardSecrecy = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy

#Fetch Cipher Transformation Constant in QuickMode of IpSec Configuration
$cipherTransformationConstant = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.CipherTransformationConstant

#Fetch Authentication Transformation Constant in QuickMode of IpSec Configuration
$authenticationTransformationConstant = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant

#Fetch Idle Disconnect Seconds in QuickMode of IpSec Configuration
$idleDisconnectSeconds = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds

#Fetch SA Life Time Seconds in QuickMode of IpSec Configuration
$quickModeSALifeTimeSeconds = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.SALifeTimeSeconds

#Fetch SA Life Time KiloBytes in QuickMode of IpSec Configuration
$quickModeSALifeTimeKiloBytes = $gatewayConnection.Properties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes


#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'DiffieHellmanGroup' -Value $diffieHellmanGroup -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'EncryptionAlgorithm' -Value $encryptionAlgorithm -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'IntegrityAlgorithm' -Value $integrityAlgorithm -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'MainModeSALifeTimeSeconds' -Value $mainModeSALifeTimeSeconds -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'MainModeSALifeTimeKiloBytes' -Value $mainModeSALifeTimeKiloBytes -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'PerfectForwardSecrecy' -Value $PerfectForwardSecrecy -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'CipherTransformationConstant' -Value $cipherTransformationConstant -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'AuthenticationTransformationConstant' -Value $authenticationTransformationConstant -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'IdleDisconnectSeconds' -Value $idleDisconnectSeconds -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'QuickModeSALifeTimeSeconds' -Value $quickModeSALifeTimeSeconds -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'QuickModeSALifeTimeKiloBytes' -Value $quickModeSALifeTimeKiloBytes -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-IpSecConfiguration ##
function Get-L3Configuration {
<#

.SYNOPSIS
Get L3 Configuration in Gateway connections

.DESCRIPTION
This script is used to Get L3 Configuration in Gateway connections available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

#Get L3 Configuration in Gateway connections
$gatewayConnection = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayId -ResourceId $gatewayConnectionName @paramsHash

#Fetch Logical Network of L3 Configuration
$logicalNetwork = $gatewayConnection.Properties.l3Configuration.vlanSubnet.resourceRef.split('/')[2]

#Fetch Logical Subnet of L3 Configuration
$logicalSubnet = $gatewayConnection.Properties.l3Configuration.vlanSubnet.resourceRef.split('/')[4]

#Fetch Ip Address of L3 Configuration
$ipAddress = $gatewayConnection.Properties.ipAddresses.ipAddress

#Fetch Prefix Prefix Lenght of L3 Configuration
$prefixLength = $gatewayConnection.Properties.ipAddresses.prefixLength

#Fetch Peer Ip Address of L3 Configuration
$peerIPAddresses = $gatewayConnection.Properties.peerIPAddresses

$subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetwork -ResourceId $logicalSubnet @paramsHash

#Fetch the VLAN ID of the Subnet

$vLanId = $subnet.Properties.VlanID

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetwork' -Value $logicalNetwork -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnet' -Value $logicalSubnet -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'PrefixLength' -Value $prefixLength -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'PeerIPAddresses' -Value $peerIPAddresses -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'VLanId' -Value $vLanId -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-L3Configuration ##
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

Import-Module NetworkController -Force

#Fetch Logical Networks
$logicalNetworks = Get-NetworkControllerLogicalNetwork @paramsHash

foreach($logicalNetwork in $logicalNetworks)
{
    $logicalNetworkName = $logicalNetwork.ResourceId

    # Three requirements for showing a network for L3
    $isVirtualizationDisabled = ($logicalNetwork.Properties.NetworkVirtualizationEnabled -ne "True")

    $hasSubnetWithVlan = (($logicalNetwork.Properties.Subnets) | Where-Object {$null -ne $_.Properties.VlanID -and 0 -ne $_.Properties.VlanID}).Length -gt 0

    $doesNotHaveVirtualNetworks = $logicalNetwork.Properties.VirtualNetworks.Length -eq 0

    $lNetName = $null
    if($isVirtualizationDisabled -and $hasSubnetWithVlan -and $doesNotHaveVirtualNetworks) {
        $lNetName = $logicalNetworkName
    }

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkName' -Value $lNetName -ErrorAction SilentlyContinue
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

Import-Module NetworkController -Force

#Fetching Subnet of the Logical Network
$subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName @paramsHash
foreach($subnet in $subnets)
{
    #Fetch the Name of the Subnet
    $subnetName = $subnet.ResourceId

    #Fetch the VlanID of the Subnet
    $vlanID = $subnet.Properties.VlanID

    #Fetch the Network Interfaces of the Subnet
    $networkInterfaces = $subnet.Properties.NetworkInterfaces

    #Fetch the Gateway Pools of the Subnet
    $gatewayPools = $subnet.Properties.GatewayPools

    #Fetch the Network Connections of the Subnet
    $networkConnections = $subnet.Properties.NetworkConnections

    #Fetch Address prefix of the Subnet
    $addressPrefix = $subnet.Properties.AddressPrefix

    $sNetName = $null
    If(($vlanID -ne 0) -and ($null -ne $vlanId) -and ($gatewayPools.Length -eq 0) -and ($networkConnections.Length -eq 0))
    {
        $sNetName = $subnetName + " - " + $addressPrefix
    }

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SubnetName' -Value $sNetName -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-LogicalSubnets ##
function Get-StatisticsOfGatewayConnections {
<#

.SYNOPSIS
Get Statistics in Gateway connections

.DESCRIPTION
This script is used to Get Statistics in Gateway connections available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayId,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

$gatewayConnection = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayId -ResourceId $gatewayConnectionName @paramsHash

#Fetch Outbound Bytes
$outBoundBytes = $gatewayConnection.Properties.Statistics.OutBoundBytes

#Fetch Inbound Bytes
$inboundBytes = $gatewayConnection.Properties.Statistics.InboundBytes

#Fetch Rx Total Packets Dropped
$rxTotalPacketsDropped = $gatewayConnection.Properties.Statistics.RxTotalPacketsDropped

#Fetch Tx Total Packets Dropped
$txTotalPacketsDropped = $gatewayConnection.Properties.Statistics.TxTotalPacketsDropped

#Fetch Tx Rate Kbps
$txRateKbps = $gatewayConnection.Properties.Statistics.TxRateKbps

#Fetch R xRate Kbps
$rxRateKbps = $gatewayConnection.Properties.Statistics.RxRateKbps

#Fetch TxRate Limited Packets Dropped
$txRateLimitedPacketsDropped = $gatewayConnection.Properties.Statistics.TxRateLimitedPacketsDropped

#Fetch R xRateLimited Packets Dropped
$rxRateLimitedPacketsDropped = $gatewayConnection.Properties.Statistics.RxRateLimitedPacketsDropped

#Fetch Last Updated
$lastUpdated = $gatewayConnection.Properties.Statistics.LastUpdated
$lastUpdated = [Datetime] $lastUpdated


#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'OutBoundBytes' -Value $outBoundBytes -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'InboundBytes' -Value $inboundBytes -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'RxTotalPacketsDropped' -Value $rxTotalPacketsDropped -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'TxTotalPacketsDropped' -Value $txTotalPacketsDropped -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'TxRateKbps' -Value $txRateKbps -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'RxRateKbps' -Value $rxRateKbps -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'TxRateLimitedPacketsDropped' -Value $txRateLimitedPacketsDropped -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'RxRateLimitedPacketsDropped' -Value $rxRateLimitedPacketsDropped -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'LastUpdated' -Value $lastUpdated -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-StatisticsOfGatewayConnections ##
function Get-VirtualGateways {
<#

.SYNOPSIS
Get Virtual Gateway of the Virtual Network

.DESCRIPTION
This script is used to List Virtual Gateway of the Virtual Network available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

$vNetGatewayName=""

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
Foreach($myGw in $allGateways)
{
    # Fetch Virtual Network Name
    $virtualNetworkName =  $myGw.Properties.GatewaySubnets.ResourceRef
    if($virtualNetworkName.split('/')[2].ToLower() -eq $virtualNetwork.ToLower())
    {
        # Getting Virtual Gateway Name
        $vNetGatewayName = $myGw.ResourceId

        break
    }
}
if($vNetGatewayName -ne "")
{
    $virtualGateway = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash

    #Fetch Gateway ID
    $gatewayID = $virtualGateway.ResourceRef.split('/')[2]

    #Fetch the Provisioning State
    $provisioningState = $virtualGateway.Properties.ProvisioningState

    #Fetch the Configuration State
    $configurationState = $virtualGateway.Properties.ConfigurationState.Status

    #Fetch Network Connections
    $networkConnections = $virtualGateway.Properties.NetworkConnections.ResourceId

    #Fetch Gateway Pool
    $gatewayPool = $virtualGateway.Properties.GatewayPools.ResourceRef.split('/')[2]

    #Fetch VirtualNetwork
    $virtualNetworkName =  $virtualGateway.Properties.GatewaySubnets.ResourceRef.split('/')[2]

    #Fetch Virtual Network Instance Id
    $virtualNetworks = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkName @paramsHash
    $virtualNetworkInstanceId = $virtualNetworks.InstanceId

    #Fetch Gateway Subnet
    $subnetName =  $virtualGateway.Properties.GatewaySubnets.ResourceRef.split('/')[4]

    #Fetch Gateway Tags
    $gatewayTags = $virtualGateway.Tags

    #Fetch BGP Routers
    $bgpRouters = $virtualGateway.Properties.BgpRouters
    if($bgpRouters.Length -gt 0)
    {
        foreach($bgpRouter in $bgpRouters)
        {
            $isGenerated = $bgpRouter.Properties.IsGenerated

            if($isGenerated -eq $False)
            {
                #Fetch BGP Router Name
                $bgpRouterName = $bgpRouter.ResourceId

                #Fetch BGP Router ASN
                $bgpRouterASN = $bgpRouter.Properties.ExtAsNumber.split('.')[1]

                #Fetch BGP Router IP
                $bgpRouterIP =  $bgpRouter.Properties.RouterIP[0]

                #Fetch BGP Peers
                $bgpPeers = $bgpRouter.Properties.BgpPeers
                if($bgpPeers.Length -gt 0)
                {

                    #Fetch BGP Peer Name
                    $bgpPeerName = $bgpPeers.ResourceId

                    #Fetch BGP Peer ASN
                    $bgpPeerASNNumbers = $bgpPeers.Properties.ExtAsNumber

                    $bgpPeerASN = @()
                    foreach($bgpPeerASNNumber in $bgpPeerASNNumbers)
                    {
                        $bgpPeerASN += $bgpPeerASNNumber.split('.')[1]
                    }

                    #Fetch BGP Peer Connection State
                    $bgpPeerConnectionState = $bgpPeers.Properties.ConnectionState

                    #Fetch BGP Peer IP Address
                    $bgpPeerIpAddress = $bgpPeers.Properties.PeerIpAddress

                    #Fetch BGP Peer Provisioning State
                    $bgpPeerProvisioningState = $bgpPeers.Properties.ProvisioningState

                    #Preparing Object Response
                    $myResponse = New-Object -TypeName psobject

                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayID' -Value $gatewayID -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkConnections' -Value $networkConnections -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $gatewayPool -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetworkName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewaySubnet' -Value $subnetName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgpRouterASN -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerASN' -Value $bgpPeerASN -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerConnectionState' -Value $bgpPeerConnectionState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIpAddress' -Value $bgpPeerIpAddress -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerProvisioningState' -Value $bgpPeerProvisioningState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayTags' -Value $gatewayTags -ErrorAction SilentlyContinue

                    $myResponse

                }
                else
                {
                    $bgpPeerName = $null
                    $bgpPeerASN = $null
                    $bgpPeerConnectionState = $null
                    $bgpPeerIpAddress = $null
                    $bgpPeerProvisioningState = $null

                    #Preparing Object Response
                    $myResponse = New-Object -TypeName psobject

                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayID' -Value $gatewayID -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkConnections' -Value $networkConnections -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $gatewayPool -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetworkName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewaySubnet' -Value $subnetName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgpRouterASN -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerASN' -Value $bgpPeerASN -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerConnectionState' -Value $bgpPeerConnectionState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIpAddress' -Value $bgpPeerIpAddress -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerProvisioningState' -Value $bgpPeerProvisioningState -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayTags' -Value $gatewayTags -ErrorAction SilentlyContinue

                    $myResponse
                }
            }
            else
            {
                $bgpRouterName = $null
                $bgpRouterASN = $null
                $bgpRouterIP =  $null
                $bgpPeerName = $null
                $bgpPeerASN = $null
                $bgpPeerConnectionState = $null
                $bgpPeerIpAddress = $null
                $bgpPeerProvisioningState = $null

                #Preparing Object Response
                $myResponse = New-Object -TypeName psobject

                $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayID' -Value $gatewayID -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkConnections' -Value $networkConnections -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $gatewayPool -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetworkName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewaySubnet' -Value $subnetName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgpRouterASN -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerASN' -Value $bgpPeerASN -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerConnectionState' -Value $bgpPeerConnectionState -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIpAddress' -Value $bgpPeerIpAddress -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerProvisioningState' -Value $bgpPeerProvisioningState -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayTags' -Value $gatewayTags -ErrorAction SilentlyContinue

                $myResponse
            }
        }
    }
    else
    {
        $bgpRouterName = $null
        $bgpRouterASN = $null
        $bgpRouterIP =  $null
        $bgpPeerName = $null
        $bgpPeerASN = $null
        $bgpPeerConnectionState = $null
        $bgpPeerIpAddress = $null
        $bgpPeerProvisioningState = $null

        #Preparing Object Response
        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayID' -Value $gatewayID -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkConnections' -Value $networkConnections -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $gatewayPool -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetworkName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewaySubnet' -Value $subnetName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $configurationState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterName' -Value $bgpRouterName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterASN' -Value $bgpRouterASN -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPRouterIP' -Value $bgpRouterIP -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerName' -Value $bgpPeerName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerASN' -Value $bgpPeerASN -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerConnectionState' -Value $bgpPeerConnectionState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerIpAddress' -Value $bgpPeerIpAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BGPPeerProvisioningState' -Value $bgpPeerProvisioningState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayTags' -Value $gatewayTags -ErrorAction SilentlyContinue

        $myResponse
    }
}

}
## [END] Get-VirtualGateways ##
function Get-VirtualNetworks {
<#

.SYNOPSIS
Get Virtual Network connections in the cluster

.DESCRIPTION
This script is used to List all Virtual Network connections available in the cluster

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

Import-Module NetworkController -Force

$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash

# Fetch Virtual Network
$virtualNetworkNames = $virtualNetworks.ResourceRef

# Preparing Object Response
foreach($virtualNetworkName in $virtualNetworkNames)
{
    $vNetName = $virtualNetworkName.split('/')[2]

    #Fetch Virtual Network Instance Id
    $virtualNetworks = Get-NetworkControllerVirtualNetwork -ResourceId $vNetName @paramsHash
    $virtualNetworkInstanceId = $virtualNetworks.InstanceId

    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $vNetName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkInstanceId' -Value $virtualNetworkInstanceId -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-VirtualNetworks ##
function Get-VirtualSubnetsOfGateway {
<#

.SYNOPSIS
Get Subnets in Virtual Network of the Gateway

.DESCRIPTION
This script is used to List all Subnets available in the Virtual Network of the Gateway

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

#Get Virtual Gateways
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash
$vNetGatewayName = ""

Foreach($myGw in $allGateways)
{
    #Fetch Virtual Network Name
    $virtualNetworkName =  $myGw.Properties.GatewaySubnets.ResourceRef
    if($virtualNetworkName.split('/')[2].ToLower() -eq $virtualNetwork.ToLower())
    {
        #Getting Virtual Gateway Name
        $vNetGatewayName = $myGw.ResourceId
        break
    }
}

if(-not [string]::IsNullOrWhiteSpace($vNetGatewayName))
{
   #Fetch Virtual Subnet of the Gateway
   $subnetNames = $virtualNetworkName
}
else
{
    #Fetch the Virtual Subnets of the Virtual Network
    $virtualSubnets = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetwork @paramsHash

    #Fetch the Subnet Names of the virtual Network
    $subnetNames = $virtualSubnets.ResourceRef
}

#Preparing Object Response of Virtual Networks
$myResponse = @()
foreach($subnetName in $subnetNames)
{
    $myResponse += New-Object -TypeName psobject -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SubnetName' -Value $subnetName.split('/')[4].ToLower() -ErrorAction SilentlyContinue
}
$myResponse

}
## [END] Get-VirtualSubnetsOfGateway ##
function New-AndUpdateVirtualGateway {
<#

.SYNOPSIS
Create/Update Virtual Gateway

.DESCRIPTION
This script is used to create/update Virtual Gateway

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualNetwork,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayPool,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $selectedGatewaySubnet,

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

# Fetch Gateways available in the Cluster
$allGateways = Get-NetworkControllerVirtualGateway @paramsHash

# Fetch the Virtual Gateway Name of the selected Virtual Network
$vnetgateway = $allGateways | Where-Object {$_.Properties.GatewaySubnets.ResourceRef.split('/')[2].ToLower() -eq $virtualNetwork.ToLower()}

# Check whether the Virtual Gateway is existed or not and update the virtual Gateway object properties
if($null -ne $vnetgateway)
{
  throwIfResourceManaged $vnetgateway

  # Set the properties to the new properties
  $vnetgatewayProps = $vnetgateway.Properties

  # Update gateway pool reference
  $gwpool = Get-NetworkControllerGatewayPool -ResourceId $gatewayPool @paramsHash

  if($vnetgatewayProps.GatewayPools.Length -ge 0)
  {
    foreach($GatewayPoolName in $vnetgatewayProps.GatewayPools)
    {
      if($GatewayPoolName.ResourceRef.split('/')[2].ToLower() -ne $gwpool.ResourceId.ToLower())
      {
        $vnetgatewayProps.GatewayPools = $vnetgatewayProps.GatewayPools
        $vnetgatewayProps.GatewayPools += $gwPool
      }
    }
  }
  else
  {
    $vnetgatewayProps.GatewayPools = @()
    $vnetgatewayProps.GatewayPools += $gwPool
  }

  # Update the rest of the virtual gateway object properties
  $resNew = New-NetworkControllerVirtualGateway -ResourceId $vNetGateway.ResourceId -Properties $vnetgatewayProps -ResourceMetadata $vnetgateway.ResourceMetadata -Tags $vnetgateway.Tags @paramsHash -Force
}
else
{
  # Create a new virtual gateway

  # Create a new object for tenant virtual gateway
  $VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties

  # Specify the Virtual Subnet to use for routing between the gateway and virtual network
  $gatewaysubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetwork -ResourceId $selectedGatewaySubnet @paramsHash
  $VirtualGWProperties.GatewaySubnets = @()
  $VirtualGWProperties.GatewaySubnets += $gatewaysubnet

  # Update gateway pool reference
  $gwpool = Get-NetworkControllerGatewayPool -ResourceId $gatewayPool @paramsHash
  $VirtualGWProperties.GatewayPools = @()
  $VirtualGWProperties.GatewayPools += $gwPool

  $VirtualGWProperties.RoutingType = "Dynamic"
  $VirtualGWProperties.NetworkConnections = @()
  $VirtualGWProperties.BgpRouters = @()

  $resNew = New-NetworkControllerVirtualGateway -ResourceId "GW-$gatewayConnectionName" -Properties $VirtualGWProperties @paramsHash -Force
}

#Fetch the Gateway Resource ID

$virutalGatewayID = $resNew.ResourceId

# Preparing Object Response of Virtual Gateway
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'VirutalGatewayID' -Value $virutalGatewayID -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-AndUpdateVirtualGateway ##
function New-GREGatewayNetworkConnection {
<#

.SYNOPSIS
Create GRE Gateway Connection

.DESCRIPTION
This script is used to create a new GRE Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $greKey,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent

# Create a new object for the tenant network connection

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# Update specific properties depending on the connection type

$nwConnectionProperties.GreConfiguration = New-Object Microsoft.Windows.NetworkController.GreConfiguration
$nwConnectionProperties.GreConfiguration.GreKey = $greKey

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Tunnel destination (remote endpoint) address

$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

# L3 specific configuration (leave blank for GRE)

$nwConnectionProperties.L3Configuration = New-Object Microsoft.Windows.NetworkController.L3Configuration
$nwConnectionProperties.IPAddresses = @()
$nwConnectionProperties.PeerIPAddresses = @()

# Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-GREGatewayNetworkConnection ##
function New-IPSECGatewayNetworkConnection {
<#

.SYNOPSIS
Create IPSEC Gateway Connection

.DESCRIPTION
This script is used to create a new IPSEC Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $sharedSecret,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $perfectForwardSecrecy,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $authenticationTransformationConstant,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $cipherTransformationConstant,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $quickModeSALifeTimeSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $idleDisconnectSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $quickModeSALifeTimeKiloBytes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $diffieHellmanGroup,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $integrityAlgorithm,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $encryptionAlgorithm,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $mainModeSALifeTimeSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $mainModeSALifeTimeKiloBytes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationIPAddress,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent

# Create a new object for tenant network connection

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# Update specific properties depending on the connection type

$nwConnectionProperties.IpSecConfiguration = New-Object Microsoft.Windows.NetworkController.IpSecConfiguration
$nwConnectionProperties.IpSecConfiguration.AuthenticationMethod = "PSK"
$nwConnectionProperties.IpSecConfiguration.SharedSecret = $sharedSecret

$nwConnectionProperties.IpSecConfiguration.QuickMode = New-Object Microsoft.Windows.NetworkController.QuickMode
$nwConnectionProperties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy = $perfectForwardSecrecy
$nwConnectionProperties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant = $authenticationTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.CipherTransformationConstant = $cipherTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeSeconds = $quickModeSALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds = $idleDisconnectSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes = $quickModeSALifeTimeKiloBytes

$nwConnectionProperties.IpSecConfiguration.MainMode = New-Object Microsoft.Windows.NetworkController.MainMode
$nwConnectionProperties.IpSecConfiguration.MainMode.DiffieHellmanGroup = $diffieHellmanGroup
$nwConnectionProperties.IpSecConfiguration.MainMode.IntegrityAlgorithm = $integrityAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.EncryptionAlgorithm = $encryptionAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeSeconds = $mainModeSALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes = $mainModeSALifeTimeKiloBytes

# L3 specific configuration (leave blank for IPSec)

$nwConnectionProperties.IPAddresses = @()
$nwConnectionProperties.PeerIPAddresses = @()

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Tunnel destination (remote endpoint) address

$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

# Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-IPSECGatewayNetworkConnection ##
function New-L3GatewayConnection {
<#

.SYNOPSIS
Create L3 Gateway Connection

.DESCRIPTION
This script is used to create a new L3 Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetwork,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalSubnetName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $SelectedlocalIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $localPeerIP,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# GRE-specific configuration (leave blank for L3)

$nwConnectionProperties.GreConfiguration = New-Object Microsoft.Windows.NetworkController.GreConfiguration

# Update specific properties depending on the connection type

$logicalsubnet =  Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetwork -ResourceId $logicalSubnetName @paramsHash
$nwConnectionProperties.L3Configuration = New-Object Microsoft.Windows.NetworkController.L3Configuration
$nwConnectionProperties.L3Configuration.VlanSubnet = $logicalsubnet

$nwConnectionProperties.IPAddresses = @()
$localIPAddress = New-Object Microsoft.Windows.NetworkController.CidrIPAddress
$localIPAddress.IPAddress = $SelectedlocalIPAddress.split('/')[0]
$localIPAddress.PrefixLength = $SelectedlocalIPAddress.split('/')[1]
$nwConnectionProperties.IPAddresses += $localIPAddress
$nwConnectionProperties.PeerIPAddresses = @($localPeerIP)

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-L3GatewayConnection ##
function New-VirtualGateway {
<#

.SYNOPSIS
Create a new Virtual Gateway with BGP Router and BGP Peer

.DESCRIPTION
This script is used to Create a new Virtual Gateway with BGP Router and BGP Peer

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtulaNetworkName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterASNNumber,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerASNNumber,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $selectedGatewaySubnet,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayPool,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network controller Module
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

# Create a new object for tenant virtual gateway
$VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties

# Specify the Virtual Subnet to use for routing between the gateway and virtual network
$gatewaysubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtulaNetworkName -ResourceId $selectedGatewaySubnet @paramsHash
$VirtualGWProperties.GatewaySubnets = @()
$VirtualGWProperties.GatewaySubnets += $gatewaysubnet

# Update gateway pool reference
$gwpool = Get-NetworkControllerGatewayPool -ResourceId $gatewayPool @paramsHash
$VirtualGWProperties.GatewayPools = @()
$VirtualGWProperties.GatewayPools += $gwPool

$VirtualGWProperties.RoutingType = "Dynamic"
$VirtualGWProperties.NetworkConnections = @()
$VirtualGWProperties.BgpRouters = @()
# Update the rest of the virtual gateway object properties
$resNew = New-NetworkControllerVirtualGateway -ResourceId $virtualGatewayName -Properties $VirtualGWProperties @paramsHash -Force

# Create a new object for the Tenant BGP router
$bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

# Update the BGP router properties
$bgpRouterproperties.ExtAsNumber = "0.$bgpRouterASNNumber"

# Add the new BGP router for the tenant
$bgprouter = New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId $virtualGatewayName -ResourceId $bgpRouterName -Properties $bgpRouterProperties @paramsHash -Force

# Create a new object for tenant BGP peer
$bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

# Update the BGP peer properties
$bgpPeerProperties.PeerIpAddress = $bgpPeerIPAddress
$bgpPeerProperties.ExtAsNumber = "0."+$bgpPeerASNNumber

# Add the new BGP peer for tenant
$bgpPeer = New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $virtualGatewayName -BgpRouterName $bgpRouterName -ResourceId $bgpPeerName -Properties $bgpPeerProperties @paramsHash -Force

$result = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayName @paramsHash

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-VirtualGateway ##
function New-VirtualGatewayNetworkConnection {
<#

.SYNOPSIS
Create New Virtual Gateway Network Connection

.DESCRIPTION
This script is used to Create New Virtual Gateway Network Connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $sharedSecret,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $routeMetric,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationIPAddress,

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
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent

# Create a new object for tenant network connection
$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

#Update the common object properties
$nwConnectionProperties.ConnectionType = "IPSec"
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

#Update specific properties depending on the connection type
$nwConnectionProperties.IpSecConfiguration = New-Object Microsoft.Windows.NetworkController.IpSecConfiguration
$nwConnectionProperties.IpSecConfiguration.AuthenticationMethod = "PSK"
$nwConnectionProperties.IpSecConfiguration.SharedSecret = $sharedSecret

$nwConnectionProperties.IpSecConfiguration.QuickMode = New-Object Microsoft.Windows.NetworkController.QuickMode
$nwConnectionProperties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy = "PFS2048"
$nwConnectionProperties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant = "MD596"
$nwConnectionProperties.IpSecConfiguration.QuickMode.CipherTransformationConstant = "DES3"
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeSeconds = 1200
$nwConnectionProperties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds = 500
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes = 1048576

$nwConnectionProperties.IpSecConfiguration.MainMode = New-Object Microsoft.Windows.NetworkController.MainMode
$nwConnectionProperties.IpSecConfiguration.MainMode.DiffieHellmanGroup = "Group2"
$nwConnectionProperties.IpSecConfiguration.MainMode.IntegrityAlgorithm = "SHA256"
$nwConnectionProperties.IpSecConfiguration.MainMode.EncryptionAlgorithm = "AES256"
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeSeconds = 1200
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes = 1048576

# L3 specific configuration (leave blank for IPSec)

$nwConnectionProperties.IPAddresses = @()
$nwConnectionProperties.PeerIPAddresses = @()

#Update the IPv4 routes that are reachable over the site-to-site VPN tunnel
$nwConnectionProperties.Routes = @()

$ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
$ipv4Route.metric = $routeMetric
$ipv4Route.DestinationPrefix = $destinationPrefix
$nwConnectionProperties.Routes += $ipv4Route

#Tunnel destination (remote endpoint) address
$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

#Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties @paramsHash -Force

while ([string]::IsNullOrWhiteSpace($sourceIPAddress)) {
  $gwconn = Get-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName @paramsHash
  $sourceIPAddress = $gwconn.Properties.SourceIPAddress
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'SourceIPAddress' -Value $sourceIPAddress -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-VirtualGatewayNetworkConnection ##
function Remove-GatewayNetworkConnection {
<#

.SYNOPSIS
Remove the Network Controller Virtual Gateway Network Connection

.DESCRIPTION
This script is used to Remove the Network Controller Virtual Gateway Network Connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent

# Remove the Network Controller Virtual Gateway Network Connection
Remove-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName @paramsHash -Force

# Get Gateway connections in the cluster
$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash
$gatewayConnections = $virtualGateways.Properties.NetworkConnections

if ($null -eq $gatewayConnections -or $gatewayConnections.Count -eq 0) {
  # Remove the Virtual Gateway if all Network Connections are removed
  Remove-NetworkControllerVirtualGateway -ConnectionUri $uri -ResourceId $virtualGatewayID -Force
}

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-GatewayNetworkConnection ##
function Update-GreGatewayNetworkConnection {
<#

.SYNOPSIS
Update GRE Gateway Connection

.DESCRIPTION
This script is used to Update existing GRE Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $greKey,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent
$existing = $parent.Properties.NetworkConnections | Where-Object {$_.ResourceId -eq $gatewayConnectionName}
$metadata = $existing.ResourceMetadata

# Create a new object for the tenant network connection

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# Update specific properties depending on the connection type

$nwConnectionProperties.GreConfiguration = New-Object Microsoft.Windows.NetworkController.GreConfiguration
$nwConnectionProperties.GreConfiguration.GreKey = $greKey

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Tunnel destination (remote endpoint) address

$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

# Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-GreGatewayNetworkConnection ##
function Update-IPSecGatewayNetworkConnection {
<#

.SYNOPSIS
Update IPSEC Gateway Connection

.DESCRIPTION
This script is used to Update existing IPSEC Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $sharedSecret,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $perfectForwardSecrecy,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $authenticationTransformationConstant,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $cipherTransformationConstant,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $quickModeSALifeTimeSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $idleDisconnectSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $quickModeSALifeTimeKiloBytes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $diffieHellmanGroup,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $integrityAlgorithm,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $encryptionAlgorithm,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $mainModeSALifeTimeSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $mainModeSALifeTimeKiloBytes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $destinationIPAddress,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent
$existing = $parent.Properties.NetworkConnections | Where-Object {$_.ResourceId -eq $gatewayConnectionName}
$metadata = $existing.ResourceMetadata

# Create a new object for tenant network connection

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# Update specific properties depending on the connection type

$nwConnectionProperties.IpSecConfiguration = New-Object Microsoft.Windows.NetworkController.IpSecConfiguration
if($sharedSecret -ne "null")
{
  $nwConnectionProperties.IpSecConfiguration.SharedSecret = $sharedSecret
}

$nwConnectionProperties.IpSecConfiguration.QuickMode = New-Object Microsoft.Windows.NetworkController.QuickMode
$nwConnectionProperties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy = $perfectForwardSecrecy
$nwConnectionProperties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant = $authenticationTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.CipherTransformationConstant = $cipherTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeSeconds = $quickModeSALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds = $idleDisconnectSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes = $quickModeSALifeTimeKiloBytes

$nwConnectionProperties.IpSecConfiguration.MainMode = New-Object Microsoft.Windows.NetworkController.MainMode
$nwConnectionProperties.IpSecConfiguration.MainMode.DiffieHellmanGroup = $diffieHellmanGroup
$nwConnectionProperties.IpSecConfiguration.MainMode.IntegrityAlgorithm = $integrityAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.EncryptionAlgorithm = $encryptionAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeSeconds = $mainModeSALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes = $mainModeSALifeTimeKiloBytes

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Tunnel destination (remote endpoint) address

$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

# Update the Gateway network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-IPSecGatewayNetworkConnection ##
function Update-L3GatewayConnection {
<#

.SYNOPSIS
Update L3 Gateway Connection

.DESCRIPTION
This script is used to Update the exisiting L3 Gateway connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalNetwork,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $logicalSubnetName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $connectionType,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $SelectedlocalIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $localPeerIP,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $destinationPrefix,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [array] $routeMetric,

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

$parent = $null
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent
$existing = $parent.Properties.NetworkConnections | Where-Object {$_.ResourceId -eq $gatewayConnectionName}
$metadata = $existing.ResourceMetadata

$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

# Update the common object properties

$nwConnectionProperties.ConnectionType = $connectionType
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

# Update specific properties depending on the connection type

$logicalsubnet =  Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetwork -ResourceId $logicalSubnetName @paramsHash
$nwConnectionProperties.L3Configuration = New-Object Microsoft.Windows.NetworkController.L3Configuration
$nwConnectionProperties.L3Configuration.VlanSubnet = $logicalsubnet

$nwConnectionProperties.IPAddresses = @()
$localIPAddress = New-Object Microsoft.Windows.NetworkController.CidrIPAddress
$localIPAddress.IPAddress = $SelectedlocalIPAddress.split('/')[0]
$localIPAddress.PrefixLength = $SelectedlocalIPAddress.split('/')[1]
$nwConnectionProperties.IPAddresses += $localIPAddress
$nwConnectionProperties.PeerIPAddresses = @($localPeerIP)

# Update the IPv4 routes that are reachable over the site-to-site VPN tunnel

$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i].routemetric
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i].addressprefix
  $nwConnectionProperties.Routes += $ipv4Route
}

# Add the new network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-L3GatewayConnection ##
function Update-VirtualGatewayNetworkConnection {
<#

.SYNOPSIS
Update Virtual Gateway Network Connection

.DESCRIPTION
This script is used to Update Virtual Gateway Network Connection

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $gatewayConnectionName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $virtualGatewayID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedInboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $maximumAllowedOutboundBandwidth,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $sharedSecret,

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
# get parent resource
$parent = Get-NetworkControllerVirtualGateway -ResourceId $virtualGatewayID @paramsHash
throwIfResourceManaged $parent
$gwc = $parent.Properties.NetworkConnections | Where-Object {$_.ResourceId -eq $gatewayConnectionName}
$metadata = $gwc.ResourceMetadata

# Create a new object for tenant network connection
$nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties

#Update the common object properties
$nwConnectionProperties.ConnectionType = "IPSec"
$nwConnectionProperties.OutboundKiloBitsPerSecond = $maximumAllowedOutboundBandwidth
$nwConnectionProperties.InboundKiloBitsPerSecond = $maximumAllowedInboundBandwidth

#Update specific properties depending on the connection type
$nwConnectionProperties.IpSecConfiguration = New-Object Microsoft.Windows.NetworkController.IpSecConfiguration
$nwConnectionProperties.IpSecConfiguration.AuthenticationMethod = "PSK"
if($sharedSecret -ne "null")
{
  $nwConnectionProperties.IpSecConfiguration.SharedSecret = $sharedSecret
}

$quickMode = $gwc.Properties.IpSecConfiguration.QuickMode
$mainMode = $gwc.Properties.IpSecConfiguration.MainMode
$routeMetric = $gwc.Properties.Routes.Metric
$destinationPrefix = $gwc.Properties.Routes.DestinationPrefix
$destinationIPAddress  = $gwc.Properties.DestinationIPAddress

#Update specific properties of Quick Mode Configuration
$nwConnectionProperties.IpSecConfiguration.QuickMode = New-Object Microsoft.Windows.NetworkController.QuickMode
$nwConnectionProperties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy = $quickMode.PerfectForwardSecrecy
$nwConnectionProperties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant = $quickMode.AuthenticationTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.CipherTransformationConstant = $quickMode.CipherTransformationConstant
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeSeconds = $quickMode.SALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds = $quickMode.IdleDisconnectSeconds
$nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes = $quickMode.SALifeTimeKiloBytes

#Update specific properties of Main Mode Configuration
$nwConnectionProperties.IpSecConfiguration.MainMode = New-Object Microsoft.Windows.NetworkController.MainMode
$nwConnectionProperties.IpSecConfiguration.MainMode.DiffieHellmanGroup = $mainMode.DiffieHellmanGroup
$nwConnectionProperties.IpSecConfiguration.MainMode.EncryptionAlgorithm = $mainMode.EncryptionAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.IntegrityAlgorithm = $mainMode.IntegrityAlgorithm
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeSeconds = $mainMode.SALifeTimeSeconds
$nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes = $mainMode.SALifeTimeKiloBytes

# L3 specific configuration (leave blank for IPSec)
$nwConnectionProperties.IPAddresses = @()
$nwConnectionProperties.PeerIPAddresses = @()

#Update the IPv4 routes that are reachable over the site-to-site VPN tunnel
$nwConnectionProperties.Routes = @()
for($i=0; $i -lt $routeMetric.length; $i++)
{
  $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo
  $ipv4Route.metric = $routeMetric[$i]
  $ipv4Route.DestinationPrefix = $destinationPrefix[$i]
  $nwConnectionProperties.Routes += $ipv4Route
}

#Tunnel destination (remote endpoint) address
$nwConnectionProperties.DestinationIPAddress = $destinationIPAddress

#Update Network connection for the tenant
$result = New-NetworkControllerVirtualGatewayNetworkConnection -VirtualGatewayId $virtualGatewayID -ResourceId $gatewayConnectionName -Properties $nwConnectionProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-VirtualGatewayNetworkConnection ##
function Update-VirtualGatewaywithBGPRouter {
<#

.SYNOPSIS
Update Virtual Gateway with BGP Router and BGP Peer

.DESCRIPTION
This script is used to Update Virtual Gateway with BGP Router and BGP Peer

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $vNetGatewayName,

    [Parameter(Mandatory = $False)]
    [string] $bgpRouterASNNumber,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpRouterName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerIPAddress,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $bgpPeerASNNumber,

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

#Import Network Controller Moduler
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
$existing = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash
throwIfResourceManaged $existing

#Update Virtual Gateway with BGP Router

$router = $existing.Properties.BgpRouters | Where-Object {$_.ResourceId -eq $bgpRouterName}

if($null -ne $router)
{
  if($bgpRouterASNNumber -ne "")
  {
    # Create a new object for the Tenant BGP router and BGP Peer
    $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

    # Update the BGP router properties
    $bgpRouterproperties.ExtAsNumber = "0."+$bgpRouterASNNumber
    $bgpPeers = $router.Properties.BgpPeers
    $bgpRouterproperties.BgpPeers = @()
    $bgpRouterproperties.BgpPeers += $bgpPeers

    $bgprouter = New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId $vNetGatewayName -ResourceId $bgpRouterName -Properties $bgpRouterProperties -ResourceMetadata $router.ResourceMetadata @paramsHash -Force
  }
  $peers = $bgprouter.Properties.BgpPeers
  if($peers.Length -gt 0)
  {
    $peerNames = @()
    $peerNames += $peers.ResourceId
    $peerNames += $bgpPeerName

    $peerIPAddress = @()
    $peerIPAddress += $peers.Properties.PeerIpAddress
    $peerIPAddress += $bgpPeerIPAddress

    $peerASNNumbers = @()
    $peerASNNumbers += $peers.Properties.AsNumber
    $peerASNNumbers += $bgpPeerASNNumber

    $peerMetadata = @()
    $peerMetadata += $peers.ResourceMetadata
    $peerMetadata += $null

    for($i = 0; $i -lt $peerNames.Length; $i++)
    {
      # Create a new object for tenant BGP peer
      $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

      # Update the BGP peer properties
      $bgpPeerProperties.PeerIpAddress = $peerIPAddress[$i]
      $bgpPeerProperties.ExtAsNumber = "0."+$peerASNNumbers[$i]

      $bgpPeer = New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $vNetGatewayName -BgpRouterName $bgpRouterName -ResourceId $peerNames[$i] -Properties $bgpPeerProperties -ResourceMetadata $peerMetadata[$i] @paramsHash -Force
    }
  }
  else
  {
    # Create a new object for tenant BGP peer
    $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

    # Update the BGP peer properties
    $bgpPeerProperties.PeerIpAddress = $bgpPeerIPAddress
    $bgpPeerProperties.ExtAsNumber = "0."+$bgpPeerASNNumber

    $bgpPeer = New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $vNetGatewayName -BgpRouterName $bgpRouterName -ResourceId $bgpPeerName -Properties $bgpPeerProperties @paramsHash -Force
  }
}
else
{
  # Create a new object for the Tenant BGP router and BGP Peer
  $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties

  # Update the BGP router properties
  $bgpRouterproperties.ExtAsNumber = "0.$bgpRouterASNNumber"

  $bgprouter = New-NetworkControllerVirtualGatewayBgpRouter -VirtualGatewayId $vNetGatewayName -ResourceId $bgpRouterName -Properties $bgpRouterProperties @paramsHash -Force

  # Create a new object for tenant BGP peer
  $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties

  # Update the BGP peer properties
  $bgpPeerProperties.PeerIpAddress = $bgpPeerIPAddress
  $bgpPeerProperties.ExtAsNumber = "0."+$bgpPeerASNNumber

  $bgpPeer = New-NetworkControllerVirtualGatewayBgpPeer -VirtualGatewayId $vNetGatewayName -BgpRouterName $bgpRouterName -ResourceId $bgpPeerName -Properties $bgpPeerProperties @paramsHash -Force
}

$result = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-VirtualGatewaywithBGPRouter ##
function Update-VirtualGatewaywithTags {

<#

.SYNOPSIS
Update Virtual Gateway with BGP Router

.DESCRIPTION
This script is used to Update Virtual Gateway with BGP Router

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $vNetGatewayName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $VirtualGatewayNetworkConnectionResourceID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $AzureConnectionID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $AzureSubscriptionID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroups,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Moduler
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

# get existing resource
$gateway = Get-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName @paramsHash
throwIfResourceManaged $gateway
$metadata = $gateway.ResourceMetadata
$tag = $gateway.Tags

$VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties
$VirtualGWProperties= $gateway.Properties
$Value=$AzureConnectionID+'.'+$AzureSubscriptionID+'.'+$ResourceGroups

if($null -ne $tag)
{
  $tagNames = $tag.PSObject.Properties.Name

  if($tagNames -contains $VirtualGatewayNetworkConnectionResourceID)
  {
    $tag.$VirtualGatewayNetworkConnectionResourceID = $Value
  }
  else
  {
    $tag | Add-Member -MemberType NoteProperty -Name  $VirtualGatewayNetworkConnectionResourceID -Value $Value
  }
}
else{
  $tag = New-Object -TypeName psobject -Property @{$VirtualGatewayNetworkConnectionResourceID = $Value}
}

# Add the new BGP router for the tenant
$result = New-NetworkControllerVirtualGateway -ResourceId $vNetGatewayName -Properties $VirtualGWProperties -ResourceMetadata $metadata -Tags $tag @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-VirtualGatewaywithTags ##

# SIG # Begin signature block
# MIIoKgYJKoZIhvcNAQcCoIIoGzCCKBcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBydiaRmPChXmXl
# YTrkHgwic5oO5MeatYMNy3Mn4wXRC6CCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMkRO3XBi2CyeRjBxx9Q7Dw0
# NgVxVWm0ZNBfWlusMTeWMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAboeoA+xpSdFgUftiQwS1pBUvETEqwNWrtBMAVwQMzI9obcQY95QP8Dt2
# G06qN07Swe3YHAanDj9mRQe5n0DVOQsQ/0ULvO4C7Jfr9YFpIKv9aDaqtUslAmaN
# OEtJKsA+6VMMSslS5On+m61GK5lY7oqTSozYuyXTyPg5e7PNMiDoTQ50e9OaTBK+
# QcrsQlFEhrNqSqoVXeA8ki/sP2/oP3YpimkWzL2rXp37eZy0/8mcCiMhiMlXjRTz
# 0Mf83siwZBnM81VuBCucOsRjzYQLh1eEHqH3U7FcNqqVrK6uoO7JTMKfu7TSir5G
# 69lJawvtrfs3WqIYBiT7mHZ7qsCusqGCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCC
# F3wGCSqGSIb3DQEHAqCCF20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCI8lqNRCP9kLJ8u9fMCXxea5ZNaJE3yqYbf4UcIr4NSQIGaPCeYko7
# GBMyMDI1MTExMDE3MTYxNi40MzdaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RjAwMi0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHqMIIHIDCCBQigAwIBAgITMwAAAgU8dWyCRIfN/gABAAACBTANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NDlaFw0yNjA0MjIxOTQyNDlaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCSkvLfd7gF1r2wGdy85CFYXHUC8ywEyD4LRLv0WYEX
# eeZ0u5YuK7p2cXVzQmZPOHTN8TWqG2SPlUb+7PldzFDDAlR3vU8piOjmhu9rHW43
# M2dbor9jl9gluhzwUd2SciVGa7f9t67tM3KFKRSMXFtHKF3KwBB7aVo+b1qy5p9D
# Wlo2N5FGrBqHMEVlNyzreHYoDLL+m8fSsqMu/iYUqxzK5F4S7IY5NemAB8B+A3Qg
# wVIi64KJIfeKZUeiWKCTf4odUgP3AQilxh48P6z7AT4IA0dMEtKhYLFs4W/KNDMs
# Yr7KpQPKVCcC5E8uDHdKewubyzenkTxy4ff1N3g8yho5Pi9BfjR0VytrkmpDfep8
# JPwcb4BNOIXOo1pfdHZ8EvnR7JFZFQiqpMZFlO5CAuTYH8ujc5PUHlaMAJ8NEa9T
# FJTOSBrB7PRgeh/6NJ2xu9yxPh/kVN9BGss93MC6UjpoxeM4x70bwbwiK8SNHIO8
# D8cql7VSevUYbjN4NogFFwhBClhodE/zeGPq6y6ixD4z65IHY3zwFQbBVX/w+L/V
# HNn/BMGs2PGHnlRjO/Kk8NIpN4shkFQqA1fM08frrDSNEY9VKDtpsUpAF51Y1oQ6
# tJhWM1d3neCXh6b/6N+XeHORCwnY83K+pFMMhg8isXQb6KRl65kg8XYBd4JwkbKo
# VQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFHR6Wrs27b6+yJ3bEZ9o5NdL1bLwMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAOuxk47b1i75V81Tx6xo10xNIr4zZxYVfk
# F5TFq2kndPHgzVyLnssw/HKkEZRCgZVpkKEJ6Y4jvG5tugMi+Wjt7hUMSipk+RpB
# 5gFQvh1xmAEL2flegzTWEsnj0wrESplI5Z3vgf2eGXAr/RcqGjSpouHbD2HY9Y3F
# 0Ol6FRDCV/HEGKRHzn2M5rQpFGSjacT4DkqVYmem/ArOfSvVojnKEIW914UxGtuh
# JSr9jOo5RqTX7GIqbtvN7zhWld+i3XxdhdNcflQz9YhoFqQexBenoIRgAPAtwH68
# xczr9LMC3l9ALEpnsvO0RiKPXF4l22/OfcFffaphnl/TDwkiJfxOyAMfUF3xI9+3
# izT1WX2CFs2RaOAq3dcohyJw+xRG0E8wkCHqkV57BbUBEzLX8L9lGJ1DoxYNpoDX
# 7iQzJ9Qdkypi5fv773E3Ch8A+toxeFp6FifQZyCc8IcIBlHyak6MbT6YTVQNgQ/h
# 8FF+S5OqP7CECFvIH2Kt2P0GlOu9C0BfashnTjodmtZFZsptUvirk/2HOLLjBiMj
# DwJsQAFAzJuz4ZtTyorrvER10Gl/mbmViHqhvNACfTzPiLfjDgyvp9s7/bHu/Cal
# KmeiJULGjh/lwAj5319pggsGJqbhJ4FbFc+oU5zffbm/rKjVZ8kxND3im10Qp41n
# 2t/qpyP6ETCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkYwMDItMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDV
# sH9p1tJn+krwCMvqOhVvXrbetKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwPIzAiGA8yMDI1MTExMDA3MTMz
# OVoYDzIwMjUxMTExMDcxMzM5WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDsvA8j
# AgEAMAcCAQACAgY9MAcCAQACAhNOMAoCBQDsvWCjAgEAMDYGCisGAQQBhFkKBAIx
# KDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZI
# hvcNAQELBQADggEBABTkKZEN5bkOmAhgyZSYt+lF8lbbKqJj+VrKsVJn3mfRSqGj
# JfxvNGF0AtX+eDH4R2PIjat0snhBjX9Ep7zAaQUkZUI1te6k6H11at7N+VGBfNqW
# 5YoDwKFe62KZoDaSa2Q6m1IFhDghVUTvs6iiI4MyXctVeoiMq8TKDukHSAHjNmm5
# aS8k2B2iZNr8qjP5L2BIBnCM2unGA2Qrq/7kfFcePYWQB5c4+AAOmOX1hVDa8kBl
# s98/17JbhZam0kpPRgmGtfSvo2DFWQ/DLov3PTtrdgBRugwxj6GIQyTOsaNX5Dhs
# F3OEDesA0DZNxdZ3dUJlHGXiMkJ7UljnfssMD98xggQNMIIECQIBATCBkzB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgU8dWyCRIfN/gABAAACBTAN
# BglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8G
# CSqGSIb3DQEJBDEiBCA+1jfjB8sdGxWRdqFmPyB3E99de3T8O9GW62BCGTbV3jCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIIANAz3ceY0umhdWLR2sJpq0OPqt
# JDTAYRmjHVkwEW9IMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAIFPHVsgkSHzf4AAQAAAgUwIgQgRBDlQb+gopepisYbPRj7HblfQnY1
# Ki7YZJ0/XEIg230wDQYJKoZIhvcNAQELBQAEggIAclscaBWR/+5APeMAbF7H+2K+
# HIG6GjJ8Z5n40jtDWkUOD5RABu7DK7QS3OtlnKvWRiYC/RNscFxA7rwL3Z50Y4BM
# syvCFIrNYuRZtO9VjMjZ4Gqj8hR6pCxlxnF4+bixLjmeit675qJr1/bZDix4zvGI
# puxdtGj6/RNNhJOwdA5URK6WhEKIJP8Pjx1W4xGCJViHjE0vVHwcK4vNX64JkLAZ
# WvwDopb6lZVNhh+33vpuDCKfIrLSgTu1RVyu3QXF9nkcK81jFi8iz27GYr6bWqgX
# kheT73l1WtG+gQKezoj+XdPytQl0tmRDU8wy/khmZV3UdZ4jpB7nLrsn+bhU9ppE
# Jmg88Vc3aBtrNSx55fs8bddLGILWTfizu05RZvGwccX/JyxJqfAfsYT3rdw4RzJd
# AIsVoYPSC7pOEEueAROcMT4btkhULTT1lkYmkPVqAxec788VWqFFFuCyEMOrpymd
# /BXccT3D29y2ZEcUkCUOPfegNoCxPEg9jWY+UNs60CpDEWCiPBxqLvsqrCVDloEZ
# +Y6+aghVUGz6KsAc9AyzkN5RBybY6rACNsfW9CXnQFQPdPIXz9iZ2oit6v8gI/OW
# kxoPET9kA53vETQIxpH9G03ru+ewxypn8svYePZmedij+V72xdFUY8B3E9+kMJMr
# fBTrIaKbPlycekk2kPQ=
# SIG # End signature block
