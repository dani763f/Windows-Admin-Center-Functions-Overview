function Get-BackendIpConfigurations {
<#

.SYNOPSIS
Get Backend Ip Configuration

.DESCRIPTION
This script is used to get Backend Ip configuration of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backendAddressPoolName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController

$backendAddressPool = Get-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadbalancerName -ResourceId $backendAddressPoolName @paramsHash

#Get Backend Ip Configuration
$backendIPConfigurations = $backendAddressPool.Properties.BackendIPConfigurations

if($backendIPConfigurations.count -gt 0)
{
  foreach($backendIPConfiguration in $backendIPConfigurations)
  {
    #Fetch Associates Network Interface Name
    $associatedNetworkInterface = $backendIPConfiguration.ResourceRef.split('/')[2]

    #Fetch IP Configuration Name
    $ipConfigurationName = $backendIPConfiguration.ResourceRef.split('/')[4]

    $ipConfig = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $associatedNetworkInterface -ResourceId $ipConfigurationName @paramsHash

    #Fetch Private IP Address
    $privateIPAddress = $ipConfig.Properties.PrivateIPAddress

    $ipConfiguration = $ipConfigurationName +" - "+"($privateIPAddress)"

    $nw = $ipConfig.Properties.Subnet.ResourceRef.Split('/')[1]
    if($nw -ieq "virtualnetworks")
    {
      $network = "Virtual Network"
    }
    else
    {
      $network = "Logical Network"
    }
    $networkName = $ipConfig.Properties.Subnet.ResourceRef.Split('/')[2]

    #Preparing Object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterface' -Value $associatedNetworkInterface -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfiguration' -Value $ipConfiguration -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Network' -Value $network -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkName' -Value $networkName -ErrorAction SilentlyContinue

    $myResponse
  }
}
else
{
  #Preparing Object Response
  $myResponse = New-Object -TypeName psobject

  $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterface' -Value "" -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfiguration' -Value "" -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'Network' -Value "" -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkName' -Value "" -ErrorAction SilentlyContinue

  $myResponse
}

}
## [END] Get-BackendIpConfigurations ##
function Get-BackendPools {
<#

.SYNOPSIS
Get Backend Ip Configuration

.DESCRIPTION
This script is used to get Backend Ip configuration of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController

$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash

$backendAddressPools = $loadBalancer.Properties.BackendAddressPools
foreach($backendAddressPool in $backendAddressPools)
{
  #Fetch Name
  $name = $backendAddressPool.ResourceId
  #Get Backend Ip Configuration
  $backendIPConfigurationsCount = $backendAddressPool.Properties.BackendIPConfigurations.Count

  $myResponse = New-Object -TypeName psobject

  $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendIPConfigurationsCount' -Value $backendIPConfigurationsCount -ErrorAction SilentlyContinue

  $myResponse
}

}
## [END] Get-BackendPools ##
function Get-BackendPoolsdependonType {
<#

.SYNOPSIS
Get Backend Pools

.DESCRIPTION
This script is used to List all Backend Pools depending on the FrontIpConfiguration available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontendIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$backendPools = Get-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadbalancerName @paramsHash
foreach($backendPool in $backendPools)
{
  $backendPoolName = ""
  if($type -ieq "internal")
  {
    $frontendIPConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadbalancerName -ResourceId $frontendIPConfigurationName @paramsHash
    $virtualNetworkName = $frontendIPConfiguration.Properties.Subnet.ResourceRef.Split('/')[2]
    $backendIPConfigurations = $backendPool.Properties.BackendIPConfigurations
    if($backendIPConfigurations.Count -gt 0)
    {
      $networkInterfaceName = $backendIPConfigurations[0].ResourceRef.Split('/')[2]
      $ipConfigurationName = $backendIPConfigurations[0].ResourceRef.Split('/')[4]
      $ipConfiguration = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $networkInterfaceName -ResourceId $ipConfigurationName @paramsHash
      $network = $ipConfiguration.Properties.Subnet.ResourceRef.Split('/')[1]
      $networkName = $ipConfiguration.Properties.Subnet.ResourceRef.Split('/')[2]
      if($network -ieq "virtualnetworks")
      {
        if($networkName -ieq $virtualNetworkName)
        {
          $backendPoolName = $backendPool.ResourceId
        }
      }
    }
  }
  else
  {
    $backendPoolName = $backendPool.ResourceId
  }

  $myResponse = New-Object -TypeName psobject
  $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPoolName' -Value $backendPoolName -ErrorAction SilentlyContinue
  $myResponse | Where 'BackendPoolName' -NotLike ""

}

}
## [END] Get-BackendPoolsdependonType ##
function Get-FrontendIPConfiguration {
<#

.SYNOPSIS
Get Frontend Ip Configuration

.DESCRIPTION
This script is used to get Frontend Ip configuration of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController -Force

#Get Frontend Ip Configuration
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$frontendIPConfigurations = $loadBalancer.Properties.FrontendIPConfigurations
if($frontendIPConfigurations.count -gt 0)
{
    foreach($frontendIPConfiguration in $frontendIPConfigurations)
    {
        #Fetch Name
        $name = $frontendIPConfiguration.ResourceId

        #Fetch Rules Count
        [int]$loadBalancingRules = $frontendIPConfiguration.Properties.LoadBalancingRules.Count
        [int]$inboundNatRules = $frontendIPConfiguration.Properties.InboundNatRules.Count
        [int]$outboundNatRules = $frontendIPConfiguration.Properties.OutboundNatRules.Count

        $rulescount = $loadBalancingRules+$inboundNatRules+$outboundNatRules

        $publicIpAddressCount = $frontendIPConfiguration.Properties.PublicIPAddress.count
        $subnetCount = $frontendIPConfiguration.Properties.Subnet.count
        if($publicIpAddressCount -gt 0)
        {
            $ipAddressName = $frontEndIpConfiguration.Properties.PublicIPAddress.ResourceRef.split('/')[2]
            $publicIPAddress = Get-NetworkControllerPublicIpAddress -ResourceId $ipAddressName @paramsHash | ConvertTo-Json | ConvertFrom-Json
            $pipAddress = $publicIpAddress.Properties.IpAddress
            $ipAddress = $pipAddress+"($ipAddressName)"
            $frontEndIpConfigurationName = $name+"($pipAddress)"
            $public = $True
            $type = "Public Ip"
            $virtualNetworkName = $null
            $virtualSubnet = $null
            $logicalNetworkName = $null
            $logicalSubnet = $null
            $pool =$null

        }
        elseif($subnetCount -gt 0)
        {
            $networkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[1]
            if($networkName -eq "virtualNetworks")
            {
                $ipAddress = $frontEndIpConfiguration.Properties.PrivateIPAddress
                $public = $false
                $publicIPAddress = $null
                $virtualNetworkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[2]
                $subnetName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[4]
                $subnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkName -ResourceId $subnetName @paramsHash
                $addressPrefix = $subnet.Properties.AddressPrefix
                $virtualSubnet = $subnetName +" "+"-"+" "+ "($addressPrefix)"
                $frontEndIpConfigurationName = $name+"($ipAddress)"
                $type = "Internal"
                $logicalNetworkName = $null
                $logicalSubnet = $null
                $pipAddress = $null
                $pool = $null
            }
            else
            {
                $ipAddress = $frontEndIpConfiguration.Properties.PrivateIPAddress
                $public = $false
                $publicIPAddress = $null
                $logicalNetworkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[2]
                $subnetName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[4]
                $subnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $subnetName @paramsHash
                $addressPrefix = $subnet.Properties.AddressPrefix
                $logicalSubnet = $subnetName + " - " + "($addressPrefix)"
                $frontEndIpConfigurationName = $name + "($ipAddress)"
                $type = "Ip Address"
                $isPublic = $subnet.Properties.IsPublic
                if($isPublic -eq $True)
                {
                    $pool = "Public Pool"
                }
                else
                {
                    $pool = "Private Pool"
                }
                $publicIpAddress = $null
                $virtualNetworkName = $null
                $virtualSubnet = $null
                $pipAddress = $null
            }
        }

        # Preparing Object Response

        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddressWithName' -Value $ipAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'RulesCount' -Value $rulescount -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Public' -Value $public -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'PublicIpAddress' -Value $publicIpAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkName' -Value $virtualNetworkName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualSubnet' -Value $virtualSubnet -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkName' -Value $logicalNetworkName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnet' -Value $logicalSubnet -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $pipAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfigurationName' -Value $frontEndIpConfigurationName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Pool' -Value $pool -ErrorAction SilentlyContinue

        $myResponse
    }
}
else
{
    # Preparing Object Response

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddressWithName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RulesCount' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Public' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PublicIpAddress' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualSubnet' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalSubnet' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfigurationName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Pool' -Value $null -ErrorAction SilentlyContinue

    $myResponse
}


}
## [END] Get-FrontendIPConfiguration ##
function Get-Healthprobes {
<#

.SYNOPSIS
Get Health Probes

.DESCRIPTION
This script is used to get Health Probes of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Health Probes
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$probes = $loadBalancer.Properties.Probes
if($probes.Count -gt 0)
{
    foreach($probe in $probes)
    {
        #Fetch Name
        $name = $probe.ResourceId
        #Fetch protocol
        $protocol = $probe.Properties.Protocol
        #Fetch Port
        $port = $probe.Properties.Port
        #Fetch Request Path
        $requestPath = $probe.Properties.RequestPath
        #Fetch Interval In Seconds
        $intervalInSeconds = $probe.Properties.IntervalInSeconds
        #Fetch No of Probes
        $numberOfProbes = $probe.Properties.NumberOfProbes

        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $protocol -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Port' -Value $port -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'RequestPath' -Value $requestPath -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IntervalInSeconds' -Value $intervalInSeconds -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfProbes' -Value $numberOfProbes -ErrorAction SilentlyContinue
        $myResponse
    }
}
else
{
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Port' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'RequestPath' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IntervalInSeconds' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NumberOfProbes' -Value $null -ErrorAction SilentlyContinue
    $myResponse
}
}
## [END] Get-Healthprobes ##
function Get-InboundNatRules {
<#

.SYNOPSIS
Get Inbound Nat Rules

.DESCRIPTION
This script is used to get Inbound Nat Rules of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Inbound Nat Rules
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$inboundNatRules = $loadBalancer.Properties.InboundNatRules
if($inboundNatRules.Count -gt 0)
{
    foreach($inboundNatRule in $inboundNatRules)
    {
        #Fetch Name
        $name = $inboundNatRule.ResourceId
        #Fetch protocol
        $protocol = $inboundNatRule.Properties.Protocol
        #Fetch Frontend port
        $frontendPort = $inboundNatRule.Properties.FrontendPort
        #Fetch Backend Port
        $backendPort = $inboundNatRule.Properties.BackendPort
        #Fetch Idle Timeout In Minutes
        $idleTimeoutInMinutes = $inboundNatRule.Properties.IdleTimeoutInMinutes
        #Fetch Enable Floating IP
        $enableFloatingIP = $inboundNatRule.Properties.EnableFloatingIP
        #Fetch Public Ip Address
        $FrontendIPConfigurations = $inboundNatRule.Properties.FrontendIPConfigurations
        if($FrontendIPConfigurations.Count -ne 0)
        {
            $frontendIPName = $FrontendIPConfigurations.ResourceRef.Split('/')[4]
            $frontendIP = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadbalancerName -ResourceId $frontendIPName @paramsHash
            $publicIpAddress = $frontendIP.Properties.PublicIPAddress.count
            if($publicIpAddress -gt 0)
            {
                $ipAddressName = $frontendIP.Properties.PublicIPAddress.ResourceRef.split('/')[2]
                $publicIp = Get-NetworkControllerPublicIpAddress -ResourceId $ipAddressName @paramsHash
                $pIpAddress = $publicIp.Properties.IpAddress
                $ipAddress = $pIpAddress+"($ipAddressName)"
                $frontEndIpConfiguration = $frontendIPName+"($pIpAddress)"
            }
            else
            {
                $ipAddress = $frontendIP.Properties.PrivateIPAddress
                $frontEndIpConfiguration = $frontendIPName+"($ipAddress)"
            }
        }
        else
        {
            $ipAddress = $null
            $frontEndIpConfiguration = $null
        }
        $backendIPConfigurations = $inboundNatRule.Properties.BackendIPConfiguration
        if($backendIPConfigurations.Count -ne 0)
        {
            $networkInterfaceName = $backendIPConfigurations.ResourceRef.split('/')[2]
            $ipConfigName = $backendIPConfigurations.ResourceRef.split('/')[4]
            $ipConfiguration = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $networkInterfaceName -ResourceId $ipConfigName @paramsHash
            #Feth Private Ip Address
            $privateIPAddress = $ipConfiguration.Properties.PrivateIPAddress
            $ipConfigurationName = $ipConfigName +"($privateIPAddress)"
        }
        else
        {
            $networkInterfaceName = $null
            $ipConfigurationName = $null
        }

        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $protocol -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendPort' -Value $frontendPort -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPort' -Value $backendPort -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfiguration' -Value $frontEndIpConfiguration -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $idleTimeoutInMinutes -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'EnableFloatingIP' -Value $enableFloatingIP -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfigurationName' -Value $ipConfigurationName -ErrorAction SilentlyContinue
        $myResponse
    }
}
else
{
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendPort' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPort' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfiguration' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EnableFloatingIP' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfigurationName' -Value $null -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-InboundNatRules ##
function Get-IpConfigurationsDependonType {
<#

.SYNOPSIS
Get Target Ip Configurations

.DESCRIPTION
This script is used to List all Target Ip Configurations depending on the FrontIpConfiguration available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontendIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $networkInterfaceName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$ipConfigurations = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $networkInterfaceName @paramsHash
if($ipConfigurations.Count -gt 0)
{
    foreach($ipConfiguration in $ipConfigurations)
    {
        $ipConfigurationName = ""
        if($type -ieq "internal")
        {
            $frontendIPConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadbalancerName -ResourceId $frontendIPConfigurationName @paramsHash
            $virtualNetworkName = $frontendIPConfiguration.Properties.Subnet.ResourceRef.Split('/')[2]
            $network = $ipConfiguration.Properties.Subnet.ResourceRef.Split('/')[1]
            $networkName = $ipConfiguration.Properties.Subnet.ResourceRef.Split('/')[2]
            if($network -ieq "virtualnetworks")
            {
                if($networkName -ieq $virtualNetworkName)
                {
                        $name = $ipConfiguration.ResourceRef.Split('/')[4]
                        $privateIPAddress = $ipConfiguration.Properties.PrivateIPAddress
                        $ipConfigurationName = $name +"($privateIPAddress)"

                }
            }
        }
        else
        {
            $name = $ipConfiguration.ResourceRef.Split('/')[4]
            $privateIPAddress = $ipConfiguration.Properties.PrivateIPAddress
            $ipConfigurationName = $name + " ($privateIPAddress)"
        }

        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfigurationName' -Value $ipConfigurationName -ErrorAction SilentlyContinue
        $myResponse | Where 'IpConfigurationName' -NotLike ""
    }
}
else
{
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfigurationName' -Value "" -ErrorAction SilentlyContinue
    $myResponse | Where 'IpConfigurationName' -NotLike ""
}

}
## [END] Get-IpConfigurationsDependonType ##
function Get-LoadBalancerConfiguration {
<#

.SYNOPSIS
Get Load Balancer Configuration

.DESCRIPTION
This script is used to get Load Balancer configuration

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadbalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Load Balancer Configuration
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$loadBalancer | ConvertTo-Json -Depth 30 | ConvertFrom-Json

}
## [END] Get-LoadBalancerConfiguration ##
function Get-LoadBalancerList {
<#

.SYNOPSIS
Get Load Balancers in the cluster

.DESCRIPTION
This script is used to List all Load Balancers available in the cluster

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

#Get Load Balancers in the cluster
$loadBalancers = Get-NetworkControllerLoadBalancer @paramsHash
foreach($loadBalancer in $loadBalancers)
{
    #Fetch Name
    $name = $loadBalancer.ResourceId
    #Fetch Type and IP Address of Load Balancer
    $frontEndIpConfigurations = $loadBalancer.Properties.FrontendIPConfigurations

    $type = $null
    $ipAddress = $null
    if($frontEndIpConfigurations.count -gt 0)
    {
        $typeValue= @()
        $ipAddress = @()
        foreach($frontEndIpConfiguration in $frontEndIpConfigurations)
        {
            $publicIpAddress = $frontEndIpConfiguration.Properties.PublicIPAddress.count
            $subnetCount = $frontEndIpConfiguration.Properties.Subnet.count
            if($publicIpAddress -gt 0)
            {
                $typeValue += "Public Ip"
                $ipAddress += " " + $frontEndIpConfiguration.Properties.PublicIPAddress.ResourceRef.split('/')[2]
            }
            elseif($subnetCount -gt 0)
            {
                $networkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[1]
                if($networkName -ieq "virtualNetworks")
                {
                    $typeValue += "Internal"
                    $ipAddress += " " + $frontEndIpConfiguration.Properties.PrivateIPAddress
                }
                else
                {
                    $typeValue += "IP Address"
                    $ipAddress += " " + $frontEndIpConfiguration.Properties.PrivateIPAddress
                }
            }
            else
            {
                $typeValue += $null
                $ipAddress += $null
            }
        }
        if($typeValue.count -gt 1)
        {
            $type = "Mixed"
        }
        else
        {
            $type = $typeValue
        }
    }

    #Fetch Backend Pool Name
    $backendpools = $loadBalancer.Properties.BackendAddressPools.ResourceId
    if($backendpools.count -gt 1)
    {
        $backendpool = $backendpools.count
    }
    else
    {
        $backendpool = $backendpools
    }
    #Fetch Inbound Nat Rules Count
    $inboundNatRules = $loadBalancer.Properties.InboundNatRules.count
    #Fetch Outbound Nat Rules Count
    $outboundNatRules = $loadBalancer.Properties.OutboundNatRules.count
    #Fetch Loadbalancing Rules Count
    $loadbalancingRules = $loadBalancer.Properties.LoadBalancingRules.count
    #Fetch Health Probes Count
    $healthProbes = $loadBalancer.Properties.Probes.count
    #Fetch Provisioning state
    $provisioningState = $loadBalancer.Properties.ProvisioningState

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BackEndPool' -Value $backEndPool -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InboundNatRules' -Value $inboundNatRules -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'OutboundNatRules' -Value $outboundNatRules -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LoadbalancingRules' -Value $loadbalancingRules -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'HealthProbes' -Value $healthProbes -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-LoadBalancerList ##
function Get-LoadBalancerMuxAvailability {
<#

.SYNOPSIS
Get Load Balancer Muxes in the cluster

.DESCRIPTION
This script is used to check whether Load Balancer Muxes available or Unavailable in the cluster

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

# Get Muxes in the cluster
$loadBalancerMuxes = Get-NetworkControllerLoadBalancerMux @paramsHash
return ($null -ne $loadBalancerMuxes) -and ($loadBalancerMuxes.length -gt 0)

}
## [END] Get-LoadBalancerMuxAvailability ##
function Get-LoadBalancingRules {
<#

.SYNOPSIS
Get Load Balancing Rules

.DESCRIPTION
This script is used to get Load Balancing Rules of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Load Balancing Rules
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$loadBalancingRules = $loadBalancer.Properties.LoadBalancingRules
if($loadBalancingRules.Count -gt 0)
{
    foreach($loadBalancingRule in $loadBalancingRules)
    {
        #Fetch Name
        $name = $loadBalancingRule.ResourceId
        #Fetch protocol
        $protocol = $loadBalancingRule.Properties.Protocol
        #Fetch Frontend Port
        $frontendPort = $loadBalancingRule.Properties.FrontendPort
        #Fetch BackendPort
        $backendPort = $loadBalancingRule.Properties.BackendPort
        $lbrule = $name+"($protocol/$frontendPort/$backendPort)"
        #Fetch Enable Floating IP
        $floatingIP = $loadBalancingRule.Properties.EnableFloatingIP
        #Fetch Load Distribution
        $loadDistribution = $loadBalancingRule.Properties.LoadDistribution
        #Fetch Idle Timeout In Minutes
        $idleTimeoutInMinutes = $loadBalancingRule.Properties.IdleTimeoutInMinutes
        #Fetch Backend Address Pool
        $backendAddressPool = $loadBalancingRule.Properties.BackendAddressPool
        if($backendAddressPool.count -ne 0)
        {
            $backendAddressPoolName = $backendAddressPool.ResourceRef.split('/')[4]
        }
        else
        {
            $backendAddressPoolName = $null
        }
        #Fetch Frontend IP Configurations
        $frontendIPConfigurations = $loadBalancingRule.Properties.FrontendIPConfigurations
        $frontendIPConfigurationsName = $null
        if($FrontendIPConfigurations.Count -ne 0)
        {
            $frontendIPConfiguration = $frontendIPConfigurations.ResourceRef.split('/')[4]
            $frontendIP = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadbalancerName -ResourceId $frontendIPConfiguration @paramsHash
            $publicIpAddress = $frontendIP.Properties.PublicIPAddress.count
            if($publicIpAddress -gt 0)
            {
                $ipAddressName = $frontendIP.Properties.PublicIPAddress.ResourceRef.split('/')[2]
                $publicIp = Get-NetworkControllerPublicIpAddress -ResourceId $ipAddressName @paramsHash
                $pIpAddress = $publicIp.Properties.IpAddress
                $ipAddress = $pIpAddress+"($ipAddressName)"
                $frontEndIpConfigurationName = $frontendIPConfiguration+"($pIpAddress)"
            }
            else
            {
                $ipAddress = $frontendIP.Properties.PrivateIPAddress
                $frontEndIpConfigurationName = $frontendIPConfiguration+"($ipAddress)"
            }

        }
        $helathProbe = $loadBalancingRule.Properties.Probe
        $probeName = $null
        if($helathProbe.Count -gt 0)
        {
            $helathProbeName = $helathProbe.ResourceRef.split('/')[4]
            $probe = Get-NetworkControllerLoadBalancerProbe -LoadBalancerId $loadbalancerName -ResourceId $helathProbeName @paramsHash
            #Fetch protocol
            $Probeprotocol = $probe.Properties.Protocol
            #Fetch Port
            $port = $probe.Properties.Port
            $probeName = $helathProbeName+"("+$Probeprotocol+":"+"$port)"
        }

        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Loadbalancingrule' -Value $lbrule -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendAddressPoolName' -Value $backendAddressPoolName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIPConfigurationName' -Value $frontendIPConfigurationName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfiguration' -Value $frontEndIpConfiguration -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $protocol -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendPort' -Value $frontendPort -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPort' -Value $backendPort -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ProbeName' -Value $probeName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $idleTimeoutInMinutes -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'EnableFloatingIP' -Value $floatingIP -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'LoadDistribution' -Value $loadDistribution -ErrorAction SilentlyContinue
        $myResponse
    }
}
else
{
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Loadbalancingrule' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendAddressPoolName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIPConfigurationName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfiguration' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendPort' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPort' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProbeName' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EnableFloatingIP' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'LoadDistribution' -Value $null -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-LoadBalancingRules ##
function Get-LogicalNetworks {
<#

.SYNOPSIS
Get Logical Networks in the cluster

.DESCRIPTION
This script is used to List all Logical Networks available in the cluster

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

$logicalNetworks = (Get-NetworkControllerLoadBalancerConfiguration @paramsHash).Properties.VipIpPools

foreach($logicalNetwork in $logicalNetworks)
{
    #Fetch Logical Network Name
    $logicalNetworkName = $logicalNetwork.ResourceRef.Split('/')[2]

    #Preparing object Response
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'logicalNetworkName' -Value $logicalNetworkName -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-LogicalNetworks ##
function Get-NetworkInterfaces {
<#

.SYNOPSIS
Get Network Interfaces in the cluster

.DESCRIPTION
This script is used to List all Network Interfaces available in the cluster

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

# Get Network Interfaces in the cluster
$networkInterfaces = Get-NetworkControllerNetworkInterface @paramsHash
foreach($networkInterface in $networkInterfaces)
{
    #Fetch Name
    $networkInterfaceName = $networkInterface.ResourceId

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceName -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-NetworkInterfaces ##
function Get-OutboundNatRules {
<#

.SYNOPSIS
Get Outbound Nat Rules

.DESCRIPTION
This script is used to get Outbound Nat Rules of a Load Balander available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Get Outbound Nat Rules
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadbalancerName @paramsHash
$outboundNatRulesList = $loadBalancer.Properties.OutboundNatRules
if($outboundNatRulesList.Count -gt 0)
{
    foreach($outboundNatRules in $outboundNatRulesList)
    {
        #Fetch Name
        $name = $outboundNatRules.ResourceId
        #Fetch protocol
        $protocol = $outboundNatRules.Properties.Protocol
        #Fetch Provisoning State
        $provisioningState = $outboundNatRules.Properties.ProvisioningState
        #Fetch Backend Address Pool
        $backendAddressPool = $outboundNatRules.Properties.BackendAddressPool
        $backendAddressPoolName = $null
        if($backendAddressPool.Count -ne 0)
        {
            $backendAddressPoolName =  $backendAddressPool.ResourceRef.split('/')[4]
        }
        #Fetch Public Ip Address
        $FrontendIPConfigurations = $outboundNatRules.Properties.FrontendIPConfigurations
        $frontendIPName = $null
        $ipAddress = $null
        if($FrontendIPConfigurations.Count -gt 0)
        {
            $frontendIPName = $FrontendIPConfigurations.ResourceRef.Split('/')[4]
            $frontendIP = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadbalancerName -ResourceId $frontendIPName @paramsHash
            $publicIpAddress = $frontendIP.Properties.PublicIPAddress.count
            if($publicIpAddress -gt 0)
            {
                $ipAddressName = $frontendIP.Properties.PublicIPAddress.ResourceRef.split('/')[2]
                $publicIp = Get-NetworkControllerPublicIpAddress -ResourceId $ipAddressName @paramsHash
                $pIpAddress = $publicIp.Properties.IpAddress
                $ipAddress = $pIpAddress+"($ipAddressName)"
                $frontEndIpConfigurationName = $frontendIPName+"($pIpAddress)"
            }
            else
            {
                $ipAddress = $frontendIP.Properties.PrivateIPAddress
                $frontEndIpConfigurationName = $frontendIPName+"($ipAddress)"
            }
        }

        # Preparing Object Response
        $myResponse = New-Object -TypeName psobject
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'protocol' -Value $protocol -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendAddressPool' -Value $backendAddressPoolName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendIPConfigurations' -Value $frontendIPName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfigurationName' -Value $frontEndIpConfigurationName -ErrorAction SilentlyContinue
        $myResponse
    }
}
else
{
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'protocol' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'BackendAddressPool' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendIPConfigurations' -Value $null -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontEndIpConfigurationName' -Value $null -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-OutboundNatRules ##
function Get-PublicIPAddresses {
<#

.SYNOPSIS
Get Public IP Address in the cluster

.DESCRIPTION
This script is used to List all Public IP Addresses available in the cluster

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

# Get Public IP Address in the cluster
Get-NetworkControllerPublicIpAddress @paramsHash | ConvertTo-Json | ConvertFrom-Json | Where-Object { $_.properties.provisioningState -eq "Succeeded" }

}
## [END] Get-PublicIPAddresses ##
function Get-SelectedLoadBalancer {
<#

.SYNOPSIS
Get Selected Loadbalancer in the Cluster

.DESCRIPTION
This script is used to get Selected Loadbalancer in the Cluster

.ROLE
Readers

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Fetch the logical Subnet IpPools
$loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $LoadBalancerName @paramsHash
$name = $loadBalancer.ResourceId

#Fetch Type and IP Address of Load Balancer
$frontEndIpConfigurations = $loadBalancer.Properties.FrontendIPConfigurations
$type = $null
$ipAddress = $null
if($frontEndIpConfigurations.count -gt 0)
{
    $type= @()
    $ipAddress = @()
    foreach($frontEndIpConfiguration in $frontEndIpConfigurations)
    {
        $publicIpAddress = $frontEndIpConfiguration.Properties.PublicIPAddress.count
        $subnetCount = $frontEndIpConfiguration.Properties.Subnet.count
        if($publicIpAddress -gt 0)
        {
            $type += "Public"
            $ipAddress += $frontEndIpConfiguration.Properties.PublicIPAddress.ResourceRef.split('/')[2]
        }
        elseif($subnetCount -gt 0)
        {
            $networkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[1]
            if($networkName -eq "virtualNetworks")
            {
                $type += "Internal"
                $ipAddress += $frontEndIpConfiguration.Properties.PrivateIPAddress
            }
            else
            {
                $type += "VIP"
                $ipAddress += $frontEndIpConfiguration.Properties.PrivateIPAddress
            }
        }
        else
        {
            $type += $null
            $ipAddress += $null
        }
    }
}
$backendpool = $loadBalancer.Properties.BackendAddressPools.ResourceId
$inboundNatRule = $loadBalancer.Properties.InboundNatRules.count
$outboundNatRule = $loadBalancer.Properties.OutboundNatRules.count
$loadBalancing = $loadBalancer.Properties.LoadBalancingRules.count
$healthprobe = $loadBalancer.Properties.Probes.count
$ProvisioningState=$loadBalancer.Properties.ProvisioningState

$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'BackendPool' -Value $backendpool -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'InboundNatRules' -Value $inboundNatRule -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'OutboundNatRules' -Value $outboundNatRule -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'LoadBalancing' -Value $loadBalancing -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'HealthProbe' -Value $healthprobe -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipaddress -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $ProvisioningState -ErrorAction SilentlyContinue
$myResponse

}
## [END] Get-SelectedLoadBalancer ##
function Get-SubnetsofLogicalNetwork {
<#

.SYNOPSIS
Get Subnets of a Logical Network in the cluster

.DESCRIPTION
This script is used to List all Subnets Associated to Logical Network available in the cluster

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

# Get Subnet of a Logical Network in the cluster
$logicalNetwork = Get-NetworkControllerLogicalNetwork -ResourceId $logicalNetworkName @paramsHash
#Fetch Subnets
$subnets = $logicalNetwork.Properties.Subnets
foreach($subnet in $subnets)
{
    #Fetch Name
    $subnetName = $subnet.ResourceId
    #Fetch Address Prefix
    $addressPrefix = $subnet.Properties.AddressPrefix
    #Fetch IsPublic
    $isPublic = $subnet.Properties.IsPublic
    $subnetValue = $subnetName + " - " + "($addressPrefix)"

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Subnet' -Value $subnetValue -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IsPublic' -Value $isPublic -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-SubnetsofLogicalNetwork ##
function Get-SubnetsofVirtualNetwork {
<#

.SYNOPSIS
Get Subnet of a Virtual Network in the cluster

.DESCRIPTION
This script is used to List all Subnets Associated to Virtual Network available in the cluster

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

# Get Subnet of a Virtual Network in the cluster
$virtualNetwork = Get-NetworkControllerVirtualNetwork -ResourceId $virtualNetworkName @paramsHash
#Fetch Subnets
$subnets = $virtualNetwork.Properties.Subnets
foreach($subnet in $subnets)
{
    #Fetch Name
    $subnetName = $subnet.ResourceId
    #Fetch Address Prefix
    $addressPrefix = $subnet.Properties.AddressPrefix
    $subnetValue = $subnetName +" "+"-"+" "+ "($addressPrefix)"

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Subnet' -Value $subnetValue -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-SubnetsofVirtualNetwork ##
function Get-TargetNetworkIpConfiguration {
<#

.SYNOPSIS
Get Network Ip Configuration

.DESCRIPTION
This script is used to List all Network Ip Configuration associated to Network Interfaces available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $networkInterfaceName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

# Get Network Interfaces in the cluster
$networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash
#Fetch Ip Configurations
$ipConfigurations = $networkInterface.Properties.IpConfigurations
foreach($ipConfiguration in $ipConfigurations)
{
    #Fetch Name
    $ipConfigurationName = $ipConfiguration.ResourceId
    #Fetch Private Ip Address
    $privateIPAddress = $ipConfiguration.Properties.PrivateIPAddress
    $targetNetworkIpConfiguration = $ipConfigurationName + " - " + "($privateIPAddress)"

    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'TargetNetworkIpConfiguration' -Value $targetNetworkIpConfiguration -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-TargetNetworkIpConfiguration ##
function Get-VirtualNetworks {
<#

.SYNOPSIS
Get Virtual Networks in the cluster

.DESCRIPTION
This script is used to List all Virtual Networks available in the cluster

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

# Get Virtual Networks in the cluster
$virtualNetworks = Get-NetworkControllerVirtualNetwork @paramsHash
foreach($virtualNetwork in $virtualNetworks)
{
    # fetch name
    $virtualNetworkName = $virtualNetwork.ResourceId
    # fetch instanceId
    $instanceId = $virtualNetwork.InstanceId
    
    # Preparing Object Response
    $myResponse = New-Object -TypeName psobject
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetworkName' -Value $virtualNetworkName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'InstanceId' -Value $instanceId -ErrorAction SilentlyContinue
    $myResponse
}

}
## [END] Get-VirtualNetworks ##
function New-BackEndIPConfiguration {
<#

.SYNOPSIS
Create a Backend Ip Configuration

.DESCRIPTION
This script is used to Create a New Back End IP configuration for a Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    # custom object: {networkInterfaceName, targetNetworkIpConfiguration}
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [object[]] $ipConfigs,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

# create new backend address pool
$backendAddressPoolProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerBackendAddressPoolProperties
$backEndAddressPool = New-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadBalancerName -ResourceId $backEndAddressPoolName -Properties $backendAddressPoolProperties @paramsHash -Force

# update nics
foreach ($ipConfig in $ipConfigs)
{
  $networkInterfaceName = $ipConfig.networkInterfaceName
  $targetNetworkIPConfiguration = $ipConfig.targetNetworkIpConfiguration.split('(')[0].trim().TrimEnd(' -')
  $networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash
  $ipC = $networkInterface.Properties.IpConfigurations | Where-Object {$_.ResourceId -ieq $targetNetworkIPConfiguration}
  if ($null -eq $ipC.Properties.LoadBalancerBackendAddressPools) {
    $ipC.Properties.LoadBalancerBackendAddressPools = $backEndAddressPool
  } else {
    $ipC.Properties.LoadBalancerBackendAddressPools += $backEndAddressPool
  }
  New-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName -Properties $networkInterface.Properties -ResourceMetadata $networkInterface.ResourceMetadata -Tags $networkInterface.Tags @paramsHash -Force
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-BackEndIPConfiguration ##
function New-FrontendIPConfiguration {
<#

.SYNOPSIS
Create a New Front End IP Configuration

.DESCRIPTION
This script is used to Create a New Front End IP configuration for a Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $publicIPAddressName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $privateIPAddress,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $iPAddress,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

# Create a New Front End IP Configuration
$frontEndIPConfig = New-Object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfigurationProperties

if ($type -ieq "public ip")
{
  $publicIP = Get-NetworkControllerPublicIpAddress -ResourceId $publicIPAddressName @paramsHash
  $frontEndIPConfig.PublicIPAddress = $publicIP
}
elseif ($type -ieq "internal")
{
  $frontEndIPConfig.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
  $virtualSubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkName -ResourceId $virtualSubnetName @paramsHash
  $frontEndIPConfig.Subnet.ResourceRef = $virtualSubnet.resourceref
  $frontEndIPConfig.PrivateIPAllocationMethod = "Static"
  $frontEndIPConfig.PrivateIPAddress = $privateIPAddress
}
else
{
  $frontEndIPConfig.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
  $logicalSubnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $logicalSubnetName @paramsHash
  $frontEndIPConfig.Subnet.ResourceRef = $logicalSubnet.resourceref
  $frontEndIPConfig.PrivateIPAllocationMethod = "Static"
  $frontEndIPConfig.PrivateIPAddress = $iPAddress
}

$result = New-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName -Properties $frontEndIPConfig @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-FrontendIPConfiguration ##
function New-HealthProbe {
<#

.SYNOPSIS
Create a Health Probe

.DESCRIPTION
This script is used to Create a Health Probe for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $healthProbeName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $intervalInSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $unhealthyThreshold,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $port,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $requestPath,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

$healthProbeProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerProbeProperties
$healthProbeProperties.IntervalInSeconds = $intervalInSeconds
$healthProbeProperties.NumberOfProbes = $unhealthyThreshold
$healthProbeProperties.Port = $port
$healthProbeProperties.Protocol = $protocol
if ($protocol -ieq "http")
{
  $healthProbeProperties.RequestPath = $requestPath
}

$result = New-NetworkControllerLoadBalancerProbe -LoadBalancerId $loadBalancerName -ResourceId $healthProbeName -Properties $healthProbeProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-HealthProbe ##
function New-InboundNatRule {
<#

.SYNOPSIS
Create a Inbound NAT Rule

.DESCRIPTION
This script is used to Create a Inbound NAT Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $inboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $networkInterfaceName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $targetNetworkIPConfig,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $idleTimeout,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $frontendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $backendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $floatingIP,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

$networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash

$frontEndIPConfiguration = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}

# create new inbound nat rule
$inboundNatRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerInboundNatRuleProperties
$inboundNatRuleProperties.FrontendIPConfigurations = $frontEndIPConfiguration
$inboundNatRuleProperties.Protocol = $protocol
$inboundNatRuleProperties.FrontendPort = $frontendPort
$inboundNatRuleProperties.BackendPort = $backendPort
$inboundNatRuleProperties.IdleTimeoutInMinutes = $idleTimeout
if ($floatingIP -ieq "false") {
  $inboundNatRuleProperties.EnableFloatingIP = $false
} else {
  $inboundNatRuleProperties.EnableFloatingIP = $True
}

$inboundNatRule = New-NetworkControllerLoadBalancerInboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $inboundNatRuleName -Properties $inboundNatRuleProperties @paramsHash -Force

# update nic
$ipConfig = $networkInterface.Properties.IpConfigurations | Where-Object { $_.ResourceId -ieq $targetNetworkIPConfig }
if ($null -eq $ipConfig) {
  throw "Target Network IP Configuration not found"
}
if ($null -eq $ipConfig.Properties.LoadBalancerInboundNatRules) {
  $ipConfig.Properties.LoadBalancerInboundNatRules = $inboundNatRule
} else {
  $ipConfig.Properties.LoadBalancerInboundNatRules += $inboundNatRule
}

$result = New-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName -Properties $networkInterface.Properties -ResourceMetadata $networkInterface.ResourceMetadata -Tags $networkInterface.Tags @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-InboundNatRule ##
function New-LoadBalancer {
<#

.SYNOPSIS
Create a Load Balancer with Front End IP Configuration

.DESCRIPTION
This script is used to Create a New Load Balancer with Front End IP configuration in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $publicIPAddressName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $privateIPAddress,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $IPAddress,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
Import-Module NetworkController

# Create a Load Balancer
$loadBalancerProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerProperties
$loadBalancerProperties.BackendAddressPools = @()
$frontEndIPConfig = New-Object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfiguration
$frontEndIPConfig.ResourceId = $frontEndIPConfigurationName
$frontEndIPConfig.properties = New-Object microsoft.windows.networkcontroller.loadbalancerfrontendipconfigurationproperties
if ($type -ieq "public ip")
{
  $publicIP = Get-NetworkControllerPublicIpAddress -ResourceId $publicIPAddressName @paramsHash
  $frontEndIPConfig.Properties.PublicIPAddress = $publicIP
}
elseif ($type -ieq "internal")
{
  $frontEndIPConfig.properties.subnet = New-Object microsoft.windows.networkcontroller.subnet
  $virtualSubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkName -ResourceId $virtualSubnetName @paramsHash
  $frontEndIPConfig.properties.subnet.resourceref = $virtualSubnet.resourceref
  $frontEndIPConfig.properties.privateipallocationmethod = "Static"
  $frontEndIPConfig.Properties.PrivateIPAddress = $privateIPAddress
}
else
{
  $frontEndIPConfig.properties.subnet = New-Object microsoft.windows.networkcontroller.subnet
  $logicalSubnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $logicalSubnetName @paramsHash
  $frontEndIPConfig.properties.subnet.resourceref = $logicalSubnet.resourceref
  $frontEndIPConfig.properties.privateipallocationmethod = "Static"
  $frontEndIPConfig.Properties.PrivateIPAddress = $IPAddress
}
$loadBalancerProperties.FrontendIPConfigurations += $frontEndIPConfig
$loadBalancerProperties.InboundNatRules = @()
$loadBalancerProperties.OutboundNatRules = @()
$loadBalancerProperties.Probes = @()

$result = New-NetworkControllerLoadBalancer -ResourceId $loadBalancerName -Properties $loadBalancerProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

}
## [END] New-LoadBalancer ##
function New-LoadBalancingRule {
<#

.SYNOPSIS
Create a Load Balancing Rule

.DESCRIPTION
This script is used to Create a Load Balancing Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancingRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    [Parameter(Mandatory = $False)]
    [string] $healthprobeName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $idleTimeoutInMinutes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $floatingIP,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadDistribution,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Create a Load Balancing Rule

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

$backendAddressPool = $parent.Properties.BackendAddressPools | Where-Object {$_.ResourceId -ieq $backEndAddressPoolName}
$frontEndIPConfiguration = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}
$healthprobe = $parent.Properties.Probes | Where-Object {$_.ResourceId -ieq $healthprobeName}

# create new load balancing rule
$loadBalancingRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancingRuleProperties
$loadBalancingRuleProperties.Protocol = $protocol
$loadBalancingRuleProperties.BackendAddressPool = $backendAddressPool
$loadBalancingRuleProperties.FrontendIPConfigurations = $frontendIPConfiguration
$loadBalancingRuleProperties.Probe = $healthprobe
$loadBalancingRuleProperties.IdleTimeoutInMinutes = $idleTimeoutInMinutes
$loadBalancingRuleProperties.FrontendPort = $frontendPort
$loadBalancingRuleProperties.BackendPort = $backendPort
$loadBalancingRuleProperties.LoadDistribution = $loadDistribution
$loadBalancingRuleProperties.EnableFloatingIP = $True
if ($floatingIP -ieq "false")
{
  $loadBalancingRuleProperties.EnableFloatingIP = $false
}

$result = New-NetworkControllerLoadBalancingRule -LoadBalancerId $loadBalancerName -ResourceId $loadBalancingRuleName -Properties $loadBalancingRuleProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-LoadBalancingRule ##
function New-OutboundNATRule {
<#

.SYNOPSIS
Create a Outbound NAT Rule

.DESCRIPTION
This script is used to Create a Outbound NAT Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $outboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Create a Outbound NAT Rule

#Import Network Controller Module
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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

$backendAddressPool = $parent.Properties.BackendAddressPools | Where-Object {$_.ResourceId -ieq $backEndAddressPoolName}
$frontEndIPConfiguration = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}

$outboundNatRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerOutboundNatRuleProperties
$outboundNatRuleProperties.Protocol = $protocol
$outboundNatRuleProperties.BackendAddressPool += $backendAddressPool
$outboundNatRuleProperties.FrontendIPConfigurations += $frontendIPConfiguration

$result = New-NetworkControllerLoadBalancerOutboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $outboundNatRuleName -Properties $outboundNatRuleProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] New-OutboundNATRule ##
function Remove-BackendIPConfiguration {
<#

.SYNOPSIS
Delete Back End IP Configuration

.DESCRIPTION
This script is used to Delete Back End IP Configuration

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $backendAddressPoolName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Back End IP Configuration
Remove-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadBalancerName -ResourceId $backendAddressPoolName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-BackendIPConfiguration ##
function Remove-FrontendIPConfiguration {
<#

.SYNOPSIS
Delete Front End IP Configuration

.DESCRIPTION
This script is used to Delete Front End IP Configuration

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Front End IP Configuration
Remove-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-FrontendIPConfiguration ##
function Remove-HealthProbe {
<#

.SYNOPSIS
Delete Health Probe

.DESCRIPTION
This script is used to Delete Health Probe

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $healthProbeName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Health Probe
Remove-NetworkControllerLoadBalancerProbe -LoadBalancerId $loadBalancerName -ResourceId $healthProbeName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-HealthProbe ##
function Remove-InboundNatRule {
<#

.SYNOPSIS
Delete Inbound Nat Rule

.DESCRIPTION
This script is used to Delete Inbound Nat Rule

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $inboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Inbound Nat Rule
Remove-NetworkControllerLoadBalancerInboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $inboundNatRuleName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-InboundNatRule ##
function Remove-LoadBalancer {
<#

.SYNOPSIS
Delete Load Balancer

.DESCRIPTION
This script is used to Delete Load Balancer

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$existing = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $existing

#Delete Load Balancer
Remove-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-LoadBalancer ##
function Remove-LoadBalancingRule {
<#

.SYNOPSIS
Delete Outbound Nat Rule

.DESCRIPTION
This script is used to Delete Outbound Nat Rule

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancingRuleName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Load Balancing Rule
Remove-NetworkControllerLoadBalancingRule -LoadBalancerId $loadBalancerName -ResourceId $loadBalancingRuleName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-LoadBalancingRule ##
function Remove-OutboundNatRule {
<#

.SYNOPSIS
Delete Outbound Nat Rule

.DESCRIPTION
This script is used to Delete Outbound Nat Rule

.ROLE
Administrators

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $outboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

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
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent

#Delete Outbound Nat Rule
Remove-NetworkControllerLoadBalancerOutboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $outboundNatRuleName @paramsHash -Force

#Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-OutboundNatRule ##
function Update-BackendPool {
<#

.SYNOPSIS
Update a Backend Pool

.DESCRIPTION
This script is used to Update Backend Pool for a Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    # custom object: {networkInterfaceName, targetNetworkIpConfiguration}
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [object[]] $ipConfigs,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.BackendAddressPools | Where-Object {$_.ResourceId -ieq $backEndAddressPoolName}
$ipConfigurations = $existing.Properties.BackendIPConfigurations
# remove existing backend pool from associated ip configurations
if ($ipConfigurations)
{
  foreach($ipConfiguration in $ipConfigurations)
  {
    $nicName = $ipConfiguration.ResourceRef.split('/')[2]
    $ipcName = $ipConfiguration.ResourceRef.split('/')[4]
    $nInterface = Get-NetworkControllerNetworkInterface -ResourceId $nicName @paramsHash
    $ipC = $nInterface.Properties.IpConfigurations | Where-Object {$_.ResourceId -ieq $ipcName}
    $ipC.Properties.LoadBalancerBackendAddressPools = $ipC.Properties.LoadBalancerBackendAddressPools | Where-Object {$_.ResourceRef -ne $existing.ResourceRef}
    if ($null -eq $ipC.Properties.LoadBalancerBackendAddressPools) {
      $ipC.Properties.LoadBalancerBackendAddressPools = @()
    }
    New-NetworkControllerNetworkInterface -ResourceId $nicName -Properties $nInterface.properties -ResourceMetadata $nInterface.ResourceMetadata -Tags $nInterface.Tags @paramsHash -Force
  }
}

foreach($ipConfig in $ipConfigs)
{
  $networkInterfaceName = $ipConfig.networkInterfaceName
  $targetNetworkIPConfiguration = $ipConfig.targetNetworkIpConfiguration.split('(')[0].trim().TrimEnd(' -')
  $networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash
  $ipC = $networkInterface.Properties.IpConfigurations | Where-Object {$_.ResourceId -ieq $targetNetworkIPConfiguration}
  if ($null -eq $ipC.Properties.LoadBalancerBackendAddressPools) {
    $ipC.Properties.LoadBalancerBackendAddressPools = $existing
  } else {
    $ipC.Properties.LoadBalancerBackendAddressPools += $existing
  }
  New-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName -Properties $networkInterface.properties -ResourceMetadata $networkInterface.ResourceMetadata -Tags $networkInterface.Tags @paramsHash -Force
}

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-BackendPool ##
function Update-FrontEndIPConfiguration {
<#

.SYNOPSIS
Update Front End IP Configuration

.DESCRIPTION
This script is used to UPdate Front End IP configuration for a Load Balancer in the cluster

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $type,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $publicIPAddressName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $virtualSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $privateIPAddress,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalNetworkName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $logicalSubnetName,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $IPAddress,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

$frontEndIPConfig = New-Object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfigurationProperties
if ($typ -ieq "public ip")
{
  $publicIP = Get-NetworkControllerPublicIpAddress -ResourceId $publicIPAddressName @paramsHash
  $frontEndIPConfig.PublicIPAddress = $publicIP
}
elseif ($type -ieq "internal")
{
  $frontEndIPConfig.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
  $virtualSubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $virtualNetworkName -ResourceId $virtualSubnetName @paramsHash
  $frontEndIPConfig.Subnet.ResourceRef = $virtualSubnet.resourceref
  $frontEndIPConfig.PrivateIPAllocationMethod = "Static"
  $frontEndIPConfig.PrivateIPAddress = $privateIPAddress
}
else
{
  $frontEndIPConfig.Subnet = New-Object Microsoft.Windows.NetworkController.Subnet
  $logicalSubnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $logicalSubnetName @paramsHash
  $frontEndIPConfig.Subnet.ResourceRef = $logicalSubnet.resourceref
  $frontEndIPConfig.PrivateIPAllocationMethod = "Static"
  $frontEndIPConfig.PrivateIPAddress = $iPAddress
}

$result = New-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName -Properties $frontEndIPConfig -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-FrontEndIPConfiguration ##
function Update-HealthProbe {
<#

.SYNOPSIS
Update Health Probe

.DESCRIPTION
This script is used to Update Health Probe for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $healthProbeName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $intervalInSeconds,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $unhealthyThreshold,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $port,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $False)]
    [AllowNull()]
    [string] $requestPath,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Update a Inbound NAT Rule

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.Probes | Where-Object {$_.ResourceId -ieq $healthProbeName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

$healthProbeProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerProbeProperties
$healthProbeProperties.IntervalInSeconds = $intervalInSeconds
$healthProbeProperties.NumberOfProbes = $unhealthyThreshold
$healthProbeProperties.Port = $port
$healthProbeProperties.Protocol = $protocol
if ($protocol -ieq "http")
{
  $healthProbeProperties.RequestPath = $requestPath
}

$result = New-NetworkControllerLoadBalancerProbe -LoadBalancerId $loadBalancerName -ResourceId $healthProbeName -Properties $healthProbeProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-HealthProbe ##
function Update-InboundNatRule {
<#

.SYNOPSIS
Update Inbound NAT Rule

.DESCRIPTION
This script is used to Update Inbound NAT Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $inboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $networkInterfaceName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $targetNetworkIPConfig,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $idleTimeout,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $frontendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [int] $backendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $floatingIP,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.InboundNatRules | Where-Object {$_.ResourceId -ieq $inboundNatRuleName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

$networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash

$inboundNatRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerInboundNatRuleProperties
$frontEndIPConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName @paramsHash
$inboundNatRuleProperties.FrontendIPConfigurations = $frontEndIPConfiguration
$inboundNatRuleProperties.Protocol = $protocol
$inboundNatRuleProperties.FrontendPort = $frontendPort
$inboundNatRuleProperties.BackendPort = $backendPort
$inboundNatRuleProperties.IdleTimeoutInMinutes = $idleTimeout
$inboundNatRuleProperties.EnableFloatingIP = ($floatingIP -ieq "true")

try {
  $inboundNatRule = New-NetworkControllerLoadBalancerInboundNatRule -ConnectionUri $uri -LoadBalancerId $loadBalancerName -ResourceId $inboundNatRuleName -Properties $inboundNatRuleProperties -ResourceMetadata $metadata @paramsHash -Force
} catch {
  throw getInnerExceptionMessage
}
# update nic
$ipConfig = $networkInterface.Properties.IpConfigurations | Where-Object { $_.ResourceId -ieq $targetNetworkIPConfig }
if ($null -eq $ipConfig) {
  throw "Target Network IP Configuration not found"
}
if ($null -eq $ipConfig.Properties.LoadBalancerInboundNatRules) {
  $ipConfig.Properties.LoadBalancerInboundNatRules = $inboundNatRule
} else {
  $ipConfig.Properties.LoadBalancerInboundNatRules += $inboundNatRule
}

$result = New-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName -Properties $networkInterface.Properties -ResourceMetadata $networkInterface.ResourceMetadata -Tags $networkInterface.Tags @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-InboundNatRule ##
function Update-LoadBalancingRule {
<#

.SYNOPSIS
Update Load Balancing Rule

.DESCRIPTION
This script is used to Update Load Balancing Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancingRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    [Parameter(Mandatory = $False)]
    [string] $healthprobeName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $idleTimeoutInMinutes,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backendPort,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $floatingIP,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadDistribution,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Update Load Balancing Rule

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.LoadBalancingRules | Where-Object {$_.ResourceId -ieq $loadBalancingRuleName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

$backendAddressPool = $parent.Properties.BackendAddressPools | Where-Object {$_.ResourceId -ieq $backEndAddressPoolName}
$frontEndIPConfiguration = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}
$healthprobe = $parent.Properties.Probes | Where-Object {$_.ResourceId -ieq $healthprobeName}

$loadBalancingRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancingRuleProperties
$loadBalancingRuleProperties.Protocol = $protocol
$loadBalancingRuleProperties.BackendAddressPool = $backendAddressPool
$loadBalancingRuleProperties.FrontendIPConfigurations = $frontendIPConfiguration
$loadBalancingRuleProperties.Probe = $healthprobe
$loadBalancingRuleProperties.IdleTimeoutInMinutes = $idleTimeoutInMinutes
$loadBalancingRuleProperties.FrontendPort = $frontendPort
$loadBalancingRuleProperties.BackendPort = $backendPort
$loadBalancingRuleProperties.LoadDistribution = $loadDistribution
$loadBalancingRuleProperties.EnableFloatingIP = ($floatingIP -ieq "true")

$result = New-NetworkControllerLoadBalancingRule -LoadBalancerId $loadBalancerName -ResourceId $loadBalancingRuleName -Properties $loadBalancingRuleProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-LoadBalancingRule ##
function Update-OutboundNatRule {
<#

.SYNOPSIS
Update Outbound NAT Rule

.DESCRIPTION
This script is used to Update Outbound NAT Rule for the Load Balancer in the cluster

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $outboundNatRuleName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $frontEndIPConfigurationName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $backEndAddressPoolName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Update a Outbound NAT Rule

#Import Network Controller Module
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
$existing = $null
# get parent resource
$parent = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash
throwIfResourceManaged $parent
# get existing resource
$existing = $parent.Properties.OutboundNatRules | Where-Object {$_.ResourceId -ieq $outboundNatRuleName}
$metadata = $null
if ($null -ne $existing) {
  $metadata = $existing.ResourceMetadata
}

$backendAddressPool = $parent.Properties.BackendAddressPools | Where-Object {$_.ResourceId -ieq $backEndAddressPoolName}
$frontEndIPConfiguration = $parent.Properties.FrontendIPConfigurations | Where-Object {$_.ResourceId -ieq $frontEndIPConfigurationName}

$outboundNatRuleProperties = New-Object Microsoft.Windows.NetworkController.LoadBalancerOutboundNatRuleProperties
$outboundNatRuleProperties.Protocol = $protocol
$outboundNatRuleProperties.BackendAddressPool += $backendAddressPool
$outboundNatRuleProperties.FrontendIPConfigurations += $frontendIPConfiguration

$result = New-NetworkControllerLoadBalancerOutboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $outboundNatRuleName -Properties $outboundNatRuleProperties -ResourceMetadata $metadata @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-OutboundNatRule ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpkHoHAB+wkU7o
# t7MacMXG3KCIpUC8SYUcSRu8VreXb6CCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBeGC0y6YjAlK8tT3eLOZE8I
# czi+CBkejg08PlMmXodUMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdhbgaoqXKgwG7nKVUilOzI363fdq9Rz5Bmh+8RsVhTRKMfdputtTNbVX
# 6O45lYDEsrIYCiuipy9NiYVhT6J2+hiUwQzQLANIFrDeLCkyiHwAl5sqwi5Fe8Oc
# CA9LDyCrJZu6bMsdvGdu7K2apzRmXw4b7mPGLIm0F7oE6p45+iPFSTJsbEzXa/4h
# PpCBoscZ4Vo6j6GNTWjw96kMCDYB5ktGgYixz+u5RVNMdmGjIEOpopv53D4KBLx+
# Ay6novPrpomoVUXXH3/wvW5t9sNHMGOBQRaMzTtxxhaprMzVqrLckWnU5H+L2sLh
# v+7lx+UnuikfuKji6alnleCNuLmwcKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCe0LIgQybf7Ej/xo7fnLio+AEzZ08PyUIQMDGO/+n7iAIGaPCDIpRR
# GBMyMDI1MTExMDE3MTYzMC40MDlaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgpHshTZ7rKzDwABAAACCjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTdaFw0yNjA0MjIxOTQyNTdaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCy7NzwEpb7BpwAk9LJ00Xq30TcTjcwNZ80TxAtAbhS
# aJ2kwnJA1Au/Do9/fEBjAHv6Mmtt3fmPDeIJnQ7VBeIq8RcfjcjrbPIg3wA5v5MQ
# flPNSBNOvcXRP+fZnAy0ELDzfnJHnCkZNsQUZ7GF7LxULTKOYY2YJw4TrmcHohkY
# 6DjCZyxhqmGQwwdbjoPWRbYu/ozFem/yfJPyjVBql1068bcVh58A8c5CD6TWN/L3
# u+Ny+7O8+Dver6qBT44Ey7pfPZMZ1Hi7yvCLv5LGzSB6o2OD5GIZy7z4kh8UYHdz
# jn9Wx+QZ2233SJQKtZhpI7uHf3oMTg0zanQfz7mgudefmGBrQEg1ox3n+3Tizh0D
# 9zVmNQP9sFjsPQtNGZ9ID9H8A+kFInx4mrSxA2SyGMOQcxlGM30ktIKM3iqCuFEU
# 9CHVMpN94/1fl4T6PonJ+/oWJqFlatYuMKv2Z8uiprnFcAxCpOsDIVBO9K1vHeAM
# iQQUlcE9CD536I1YLnmO2qHagPPmXhdOGrHUnCUtop21elukHh75q/5zH+OnNekp
# 5udpjQNZCviYAZdHsLnkU0NfUAr6r1UqDcSq1yf5RiwimB8SjsdmHll4gPjmqVi0
# /rmnM1oAEQm3PyWcTQQibYLiuKN7Y4io5bJTVwm+vRRbpJ5UL/D33C//7qnHbeoW
# BQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFAKvF0EEj4AyPfY8W/qrsAvftZwkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCwk3PW0CyjOaqXCMOusTde7ep2CwP/xV1J
# 3o9KAiKSdq8a2UR5RCHYhnJseemweMUH2kNefpnAh2Bn8H2opDztDJkj8OYRd/KQ
# ysE12NwaY3KOwAW8Rg8OdXv5fUZIsOWgprkCQM0VoFHdXYExkJN3EzBbUCUw3yb4
# gAFPK56T+6cPpI8MJLJCQXHNMgti2QZhX9KkfRAffFYMFcpsbI+oziC5Brrk3361
# cJFHhgEJR0J42nqZTGSgUpDGHSZARGqNcAV5h+OQDLeF2p3URx/P6McUg1nJ2gMP
# YBsD+bwd9B0c/XIZ9Mt3ujlELPpkijjCdSZxhzu2M3SZWJr57uY+FC+LspvIOH1O
# pofanh3JGDosNcAEu9yUMWKsEBMngD6VWQSQYZ6X9F80zCoeZwTq0i9AujnYzzx5
# W2fEgZejRu6K1GCASmztNlYJlACjqafWRofTqkJhV/J2v97X3ruDvfpuOuQoUtVA
# wXrDsG2NOBuvVso5KdW54hBSsz/4+ORB4qLnq4/GNtajUHorKRKHGOgFo8DKaXG+
# UNANwhGNxHbILSa59PxExMgCjBRP3828yGKsquSEzzLNWnz5af9ZmeH4809fwItt
# I41JkuiY9X6hmMmLYv8OY34vvOK+zyxkS+9BULVAP6gt+yaHaBlrln8Gi4/dBr2y
# 6Srr/56g0DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjM3MDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDR
# AMVJlA6bKq93Vnu3UkJgm5HlYaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7Lvz3TAiGA8yMDI1MTExMDA1MTcx
# N1oYDzIwMjUxMTExMDUxNzE3WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsu/Pd
# AgEAMAoCAQACAkSWAgH/MAcCAQACAhINMAoCBQDsvUVdAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAJXajAutAHA9mPQ6smdRG/3VuwTOcpL2IrCu8urQlgrY
# FVOvJDfCeJ1QM6cdtYWUaDSkKaVtb4jYS4FCpmQ7G9mdlOMOuA9hZA4q6BgWeFL3
# oDbowt845w1fggf2VO/LlNBxHDtgm15cYYad0E6ne0s6dIwLjZx42LWyXZ9K3Xfr
# aakiUPLeehFCFXLe/7d2/IosTAwQS9WfP5VQp5qJ/JKpzX6uggO8DOLX5EGKhEBt
# MB9J5NwiQixx9O4rT4zbXRhc2s3bOclQrcDJANAdNyDMaKiievyzHRPx7N3wt3YI
# yB+P/QcH0EYn0JP3spx0/yRocM3WqDxTCUyrJmrApdcxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgpHshTZ7rKzDwABAAAC
# CjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCDw2Z7/bfM5dvThOIWxAi0l4dJctN5+sQTIeMOT9yYG
# ZTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIE2ay/y0epK/X3Z03KTcloqE
# 8u9IXRtdO7Mex0hw9+SaMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIKR7IU2e6ysw8AAQAAAgowIgQgl7M7lF6SJNEDfsIAyNIJMwba
# dk3UE3kNzaUgIEBT6kkwDQYJKoZIhvcNAQELBQAEggIABtkApJ4TPKYN1MwT9JTo
# Mn4HET+nEVyJy1Ubx56xQHxr+mPFvJTqy3CxyUqpJVwMDVZOgmYkZy6y3DLXwl8S
# HNmF3eVjk3322xrSgChpYt/zvRgancJ/YDUJLa4ywHBoKRKR2ckP4/BS0A6SIDJ/
# rrOnH2cVFDDq288FLiU9X75NAIWbQSeLQ7i49CVyGOuAhqyx9zvmNSXIVK9d+UBQ
# F9SJLrK49oScmDtffGre97aM/HMzB1OjTMN06x+M/vKZlYQQAjvSvbbhUcHez0KC
# A8UkohId+G2QHK1NO3quYrfXD8+f2WMZS8Mp926I9RE36JDJolGsDIv+Py8FgLNr
# VsaW30dgODWtqcinlzd6+WzOW8rrSnyn9PFTaj0WM4xKXJTv616M0u2C2rz9+IVc
# bVGAeqJ5SIRJfyfPWSBhDVP3q5alImvruNxfe/msTcT8CuSdi7AmJHOlKsXwkLou
# YIqImKxVDUzZYoOHPiN4G4C44n+CtPp6fBhAqGRK9X3jDnzvJnMN3dYnXxdihS8k
# Y+/vSO+OSiDlKOfItf5re/XUQZP5qSXqnH2iUqNWed5oJy8CRLKkTx5Hu2nIGA5T
# GGAF3TqazwXr2s6YNYMSbiRN+f1Vlr97CjLZUvoBkeXreGx27HZZHoNbxI9IpLNI
# 9AHGQw6QzpJlyBf5FnI9Kus=
# SIG # End signature block
