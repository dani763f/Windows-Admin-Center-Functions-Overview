function Copy-CertWithinMachine {
<#

.SYNOPSIS
Copies a certificate

.DESCRIPTION
Copies a certificate within a machine

.ROLE
Readers

#>

Param (
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [string] $certThumbprint,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [string] $certLocation,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [string] $importLocation
)

function ExportCertificateAsBytes {
  param(
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert
  )
  $TempFile = New-TemporaryFile
  Remove-Item $TempFile.FullName -Force | out-null
  Export-Certificate -Type CERT -FilePath $TempFile.FullName -cert $cert | out-null
  $CertData = Get-Content $TempFile.FullName -Encoding Byte
  Remove-Item $TempFile.FullName -Force | out-null
  $CertData
}

function ImportCertificateFromBytes {
  param(
      [byte[]] $CertData,
      [string] $location
    )
    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $CertData | set-content $TempFile.FullName -Encoding Byte
    import-certificate -filepath $TempFile.FullName -certstorelocation $location | out-null
    Remove-Item $TempFile.FullName -Force
}

$cert = Get-ChildItem -Path $certLocation | Where-Object {$_.Thumbprint -eq $certThumbprint}
$certData = ExportCertificateAsBytes $cert
ImportCertificateFromBytes $certData $importLocation

}
## [END] Copy-CertWithinMachine ##
function Find-PacketMonCounters {
<#

.SYNOPSIS
check PacketMon Counters

.DESCRIPTION
This Script is used to check whether packet counters are available or not

.ROLE
Readers

#>
$pktmonConters = pktmon counters

if($pktmonConters -eq "All counters are zero.")
{
    $result = "Not Avilable"
}
else
{
    $result = "Available"
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

}
## [END] Find-PacketMonCounters ##
function Find-VMwithVMGuid {
<#

.SYNOPSIS
Get the clusterNode Virtual Machines

.DESCRIPTION
This script is used to Fetch the Names of virtual machines associated to Cluster Node

.ROLE
Readers

#>

param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vmGuid
)

$vmNames = Get-VM

foreach($vmName in $vmNames)
{
    $vmID = $vmName.VMId

    if($vmID -eq $vmGuid)
    {
        $result = "Available"

        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

        $myResponse
    }
}

}
## [END] Find-VMwithVMGuid ##
function Get-AvailableClusterNetworkVlans {
<#

.SYNOPSIS
Gets the Cluster and Client networks

.DESCRIPTION
Gets the Cluster and Client networks and the associated VLAN

.ROLE
Readers

#>

$hostName = hostname
$clusterNetworkInterface = Get-ClusterNetworkInterface | Where-Object {$_.Adapter -like "Hyper-V*" -and $_.Node -eq $hostName -and $_.Network.Role -eq "ClusterAndClient"}
$adapterIsolations = Get-VMNetworkAdapterIsolation -ManagementOS | Where-Object {$_.ComputerName -eq $hostName -and $_.IsDeleted -eq $false}
$adapterIdHash = @{}
$clusterNetworkInterface | ForEach-Object {
    $id = $_.AdapterId
    $vlanId = ($adapterIsolations | Where-Object { [guid]::Parse($_.ParentAdapter.DeviceId).Guid -eq $id }).DefaultIsolationID
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "VlanId" -Value $vlanId
    $obj | Add-Member -MemberType NoteProperty -Name "ClusterNetwork" -Value $_.Network
    $adapterIdHash[$id] = $obj
}

$adapterIdHash.Values

}
## [END] Get-AvailableClusterNetworkVlans ##
function Get-BgpInfoFromMuxs {
<#

.SYNOPSIS
Gets BGP info from Muxes

.DESCRIPTION
This script gets BGP info from the muxes for gateway deployment

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

$sdnAsn = ''
$router1Info = @{
    'ipAddress' = ''
    'asn' = ''
}
$router2Info = @{
    'ipAddress' = ''
    'asn' = ''
}
$muxs = Get-NetworkControllerLoadBalancerMux @paramsHash

if ($muxs.Count -gt 0) {
    $routerConfiguration = $muxs[0].Properties.RouterConfiguration
    $sdnAsn = $routerConfiguration.LocalASN
    $router1Info.ipAddress = $routerConfiguration.PeerRouterConfigurations[0].RouterIPAddress
    $router1Info.asn = $routerConfiguration.PeerRouterConfigurations[0].PeerASN

    if ($routerConfiguration.PeerRouterConfigurations.Count -gt 1) {
        $router2Info.ipAddress = $routerConfiguration.PeerRouterConfigurations[1].RouterIPAddress
        $router2Info.asn = $routerConfiguration.PeerRouterConfigurations[1].PeerASN
    }
}

$bgpInfo = @{
    'sdnAsn'  = $sdnAsn
    'router1' = $router1Info
    'router2' = $router2Info
}

$bgpInfo

}
## [END] Get-BgpInfoFromMuxs ##
function Get-BuildNumber {
<#

.SYNOPSIS
Get build Number

.DESCRIPTION
This Script is used to get the build Number of the OS

.ROLE
Readers

#>

$version = Get-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
$buildValue = $version.GetValue("BuildLabEx").split('.')[0]
if($buildValue -gt '17763')
{
    $result = "Display"
}
else
{
    $result = "Not Display"
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-BuildNumber ##
function Get-BuildValue {
<#

.SYNOPSIS
Get build Number

.DESCRIPTION
This Script is used to get the build Number of the OS

.ROLE
Readers

#>

$version = Get-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
$buildValue = $version.GetValue("BuildLabEx").split('.')[0]

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'BuildValue' -Value $buildValue -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-BuildValue ##
function Get-Capture {
<#

.SYNOPSIS
get pktmon capture results

.DESCRIPTION
get pktmon capture results
if pathToLog is passed in just open and parse the file, otherwise stop capture and use the new log file

.ROLE
Readers

#>
Param(
[Parameter(Mandatory = $true)]
[ValidateNotNullOrEmpty()]
[string] $pathToLog
)

$contents = Get-Content $pathToLog -Raw | ConvertFrom-Json

foreach($content in $contents)
{
    $layers = $content.Layers._source.layers

    foreach($layer in $layers.PSObject.Properties)
    {
        if($layer.Name -match "Transmission Control Protocol")
        {
            $destinationPort = $layers."$($layer.Name)"."Destination Port"
            $sourcePort = $layers."$($layer.Name)"."Source Port"
        }
    }
    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'EventTime' -Value $content."Event Time" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Source' -Value $content.Source -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Destination' -Value $content.Destination -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'SourcePort' -Value $sourcePort -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DestinationPort' -Value $destinationPort -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $content.Protocol -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Message' -Value $content.Message -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ComponentID' -Value $content."Component Id" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ComponentDescription' -Value $content."Component Description" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DropReason' -Value $content."Event Properties".'Drop Reason' -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EventType' -Value $content."Event Type" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EventInfo' -Value $content."Event Info" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'EventPropertiesList' -Value $content."Event Properties" -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Layers' -Value $content.Layers -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-Capture ##
function Get-CertInfo {
<#

.SYNOPSIS
Get the certificate

.DESCRIPTION
Get the certificate from the path provided

.ROLE
Readers

#>

Param(
  [Parameter(Mandatory = $true)]
  [string] $certPath
)

Set-StrictMode -Version 5.0

if (Test-Path $certPath) {
  Get-ChildItem $certPath | ConvertTo-Json | ConvertFrom-Json
}

}
## [END] Get-CertInfo ##
function Get-ClusterIpsDns {
<#

.SYNOPSIS
Checks what IPs are being used by the cluster

.DESCRIPTION
Checks what IPs are being used by the cluster by resolving the DNS names of the cluster and cluster nodes

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$clusterIps = @()
$clusterNodeIps = @()
$clusterIps = (Get-Cluster | Resolve-DnsName -ErrorAction SilentlyContinue | Select-Object -Property IPAddress).IPAddress
$clusterNodeIps = (Get-ClusterNode | Resolve-DnsName -ErrorAction SilentlyContinue | Select-Object -Property IPAddress).IPAddress
$clusterIps + $clusterNodeIps

}
## [END] Get-ClusterIpsDns ##
function Get-ClusterNodeVMs {
<#

.SYNOPSIS
Get the clusterNode Virtual Machines

.DESCRIPTION
This script is used to Fetch the Names of virtual machines associated to Cluster Node

.ROLE
Readers

#>

$vmNames = Get-VM

foreach($vmName in $vmNames)
{
    $name = $vmName.Name
    $domainName = (Get-CIMInstance CIM_ComputerSystem).Domain
    $virtualMachineName = $name+"."+$domainName

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualMachineName' -Value $virtualMachineName.ToLower() -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-ClusterNodeVMs ##
function Get-ClusterNodesSdn {
<#

.SYNOPSIS
Get all the Cluster Nodes.

.DESCRIPTION
Get the cluster nodes information for the cluster.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
  [Parameter(Mandatory = $false)]
  [string] $clusterName
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

# Get hostnames
if ([string]::IsNullOrEmpty($clusterName)) {
  $hostNames = Get-ClusterNode
} else {
  $hostNames = Get-ClusterNode -Cluster $clusterName
}

$domainName=((Get-CIMInstance CIM_ComputerSystem).Domain)
$result = @()
# Result for getting Clusternodes
foreach($hostName in $hostnames)
{
    $result+=($hostName.name +"."+ $domainName).ToLower()
}

$result

}
## [END] Get-ClusterNodesSdn ##
function Get-FCNCReplica {
<#

.SYNOPSIS
Gets the Network controller replica status information.

.DESCRIPTION
Gets the replica status of the Network controller.

.ROLE
Readers

#>

Get-NetworkControllerOnFailoverClusterReplica | ConvertTo-Json | ConvertFrom-Json

}
## [END] Get-FCNCReplica ##
function Get-FrontEndIPConfigurationIPAddress {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the IPAddress of Front End Ip Configuration of all Load Balancers.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$loadBalancers = Get-NetworkControllerLoadBalancer @paramsHash
foreach($loadBalancer in $loadBalancers)
{
    $outboundNatRules = $loadBalancer.Properties.OutboundNatRules
    if($null -ne $outboundNatRules)
    {
        $loadBalancerName = $loadBalancer.ResourceId
        $frontendIpConfigurations = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName @paramsHash
        foreach($frontendIpConfiguration in $frontendIpConfigurations)
        {
            $outboundNatRule = $frontendIpConfiguration.Properties.OutboundNatRules.count
            if($outboundNatRule -gt 0)
            {
                $frontendIpConfigurationName = $frontendIpConfiguration.ResourceId
                $privateIPAddress = $frontendIpConfiguration.Properties.PrivateIPAddress

                $myResponse = New-Object -TypeName psobject

                $myResponse | Add-Member -MemberType NoteProperty -Name 'LoadBalancerName' -Value $loadBalancerName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'FrontendIpConfigurationName' -Value $frontendIpConfigurationName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'PrivateIPAddress' -Value $privateIPAddress -ErrorAction SilentlyContinue

                $myResponse
            }
        }
    }
}

}
## [END] Get-FrontEndIPConfigurationIPAddress ##
function Get-FrontEndPrivateIPAddress {
<#

.SYNOPSIS
Get the Private IP Address

.DESCRIPTION
This script is used to Fetch the Private IP Address of Network Interface

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $netWorkInterfaceId,

  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$networkInterfaceIpConfiguration = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $netWorkInterfaceId @paramsHash
$privateIpAddress= $networkInterfaceIpConfiguration.Properties.PrivateIPAddress

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'PrivateIpAddress' -Value $privateIpAddress -ErrorAction SilentlyContinue

$myResponse


}
## [END] Get-FrontEndPrivateIPAddress ##
function Get-FrontEndPublicIPAddress {
<#

.SYNOPSIS
Get the public IP Address

.DESCRIPTION
This script is used to Fetch the public IP Addresses

.ROLE
Readers

#>


param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$publicIpAddresses = Get-NetworkControllerPublicIpAddress @paramsHash

foreach($publicIpAddress in $publicIpAddresses)
{
    $resourceId = $publicIpAddress.ResourceId
    $publicIPConfiguration = $publicIpAddress.Properties.IpConfiguration
    if($null -ne $publicIPConfiguration)
    {
    $networkIntfaceId=$publicIpAddress.Properties.IpConfiguration.ResourceRef.split('/')[2]
    $networkInterfaceVm = Get-NetworkControllerNetworkInterface -ResourceId $networkIntfaceId @paramsHash
    $tenantipAddress = $networkInterfaceVm.Properties.IpConfigurations.Properties.PrivateIPAddress

    $ipAddress = $publicIpAddress.Properties.IpAddress+ '/' + $tenantipAddress

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'ResourceName' -Value $resourceId -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress  -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceId' -Value $networkIntfaceId -ErrorAction SilentlyContinue

    $myResponse
    }
}



}
## [END] Get-FrontEndPublicIPAddress ##
function Get-GWThroughputHistoryTimeSeries {
<#

.SYNOPSIS
Gets the time series data of the gateway throughput.

.DESCRIPTION
Gets the hour and day time series data for the gateway throughput.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [object] $Gateways,
    [Parameter(Mandatory = $true)]
    [String] $HistoryOf,
    [Parameter(Mandatory = $true)]
    [String] $NodeName

)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;
Import-Module CimCmdlets;
Import-Module FailoverClusters -ErrorAction SilentlyContinue;
Import-Module Microsoft.PowerShell.Management;

function CreateGraphData($rawData, $conversion) {
    $graphData = New-Object System.Collections.ArrayList
    if ($rawData -eq $null){
        return $graphData
    }
    # Group Data
    $groupData = $rawData.Group


    for ($i=$groupData.Count -1; $i -ge 0; $i--) {
        $recordsData = $groupData[$i].Records

        if ($recordsData -and $recordsData.Count -gt 0) {
            $cimProperties = $recordsData[0].CimInstanceProperties;

            if ($cimProperties.Count -gt 0) {
                $pointData = New-Object PSObject

                $value = $cimProperties.Value[1]
                if ($conversion -ne $null) {
                    $value = [math]::Round($value / $conversion, 2)
                }

                $pointData | Add-Member -MemberType NoteProperty -Name 'Value' $value

                $graphData.Add($pointData) > $null
            }
        }
    }

    return $graphData
}

$Gw=$Gateways.Properties.VirtualServer
$gwnames=$gw.ResourceRef

foreach($gwname in $gwnames){
    Try
    {
        $gwarr=$gwname.split("/")[2]
        $vm=get-vm -ComputerName $NodeName | Where {$_.name -contains $gwarr}
        if($vm)
        {
            $vmid=$vm.Id;
            $vm = Get-VM -id $vmId -ComputerName $NodeName

            # Get raw Health Metrics data
            if($HistoryOf -eq "HOUR")
            {
                $NetworkRawInBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.inbound -TimeFrame LastHour
                $NetworkRawOutBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.outbound -TimeFrame LastHour
            }
            elseif($HistoryOf -eq "DAY")
            {
                $NetworkRawInBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.inbound -TimeFrame LastDay
                $NetworkRawOutBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.outbound -TimeFrame LastDay
            }
            # Create data needed for graph


            $kBConversion = 1024
            $MBConversion = 1024 * 1024

            $NetworkInbound = CreateGraphData $NetworkRawInBound $MBConversion
            $NetworkOutBound = CreateGraphData $NetworkRawOutBound $MBConversion

            # Get result for Gateway Throughput History

            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'Name' $gwarr
            $result | Add-Member -MemberType NoteProperty -Name 'Received' -Value $NetworkInbound.value
            $result | Add-Member -MemberType NoteProperty -Name 'Sent' -Value $NetworkOutBound.value

            $result

        }
    }
    Catch{}
}

}
## [END] Get-GWThroughputHistoryTimeSeries ##
function Get-GatewayCPULive {
<#

.SYNOPSIS
Gets Gateway CPU Live Data.

.DESCRIPTION
Gets the live information for the Gateway CPU.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module Hyper-V -ErrorAction SilentlyContinue
Set-StrictMode -Version 5.0
Import-Module CimCmdlets
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management
Import-Module Hyper-V

$Gateway=Get-NetworkControllerGateway @paramsHash
$Gw=$Gateway.Properties.VirtualServer
$gwnames=$gw.ResourceRef
foreach($gwname in $gwnames){
Try
{
    $gwarr=$gwname.split("/")[2]
    $vm=get-vm | Where {$_.name -contains $gwarr}
    if($vm){
        $vmid=$vm.Id

        $now = Get-Date
        $myvm = Get-VM -id $vmid.Guid
    # Get result for Gateway CPULive
        if ($myvm) {
            $cpuUsage = $myvm.CPUUsage
            $result = New-Object PSObject
            $vmFQDN=($gwarr+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
            $result | Add-Member -MemberType NoteProperty -Name 'Name' $vmFQDN
            $result | Add-Member -MemberType NoteProperty -Name 'Cpu' $cpuUsage
            $result
        }
    }
 }
 Catch{}
}

}
## [END] Get-GatewayCPULive ##
function Get-GatewayConnections {
<#

.SYNOPSIS
Get gateways in the cluster

.DESCRIPTION
This script gets all the gateways in the cluster

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

$gateways = Get-NetworkControllerGateway @paramsHash

$gateways

}
## [END] Get-GatewayConnections ##
function Get-GatewayManagerServerName {
<#

.SYNOPSIS
Get Network Controller Server Name

.DESCRIPTION
This script is used to fetch GatewayManager Network Controller Server Name

.ROLE
Readers

#>

Connect-ServiceFabricCluster | Out-Null

$gatewayManagerName = "fabric:/NetworkController/GatewayManager"
$gatewayManagerPartitionId = (Get-ServiceFabricPartition -ServiceName $gatewayManagerName).PartitionId
$gatewayManagerNCNodeName = (Get-ServiceFabricReplica -PartitionId $gatewayManagerPartitionId | where { $_.ReplicaRole -like "*Primary*" }).NodeName

$ncNodes = Get-NetworkControllerNode
# ADD FCNC SUPPORT!

foreach($node in $ncNodes)
{
    if($node.Name -eq $gatewayManagerNCNodeName)
    {
        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'NodeName' -Value  $node.Name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ServerName' -Value  $node.Server -ErrorAction SilentlyContinue

        $myResponse
        break
    }
}

}
## [END] Get-GatewayManagerServerName ##
function Get-GatewayPools {
<#

.SYNOPSIS
Gets Gateway pools Data.

.DESCRIPTION
Gets the information for the Gateway pools.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

# Get Network Controller Gateway Pool
$NCGatewayPool=Get-NetworkControllerGatewayPool @paramsHash
Foreach ($myPool in $NCGatewayPool)
{
    #Name column
    $Name=$myPool.ResourceId
    #Type column
    $PoolType=$myPool.Properties.Type

    #Active, Passive and Redundant column
    $Active=0
    $Passive=0
    $Redundant=0
    Foreach ($myGw in $myPool.Properties.Gateways)
    {
        $gwVM=$myGw.ResourceRef.split("/")[2]
        $myGwResult=get-NetworkControllerGateway -ResourceId $gwVM @paramsHash
        if($myGwResult.Properties.State -eq "Active")
        {
            $Active++
        }
        elseif($myGwResult.Properties.State -eq "Passive")
        {
            $Passive++
        }
        elseif($myGwResult.Properties.State -eq "Redundant")
        {
            $Redundant++
        }
    }

    #Status column
    $IsHealthy=0
    if($myPool.Properties.VirtualGateways.count -gt 0)
    {
        Foreach ($myVirtualGw in $myPool.Properties.VirtualGateways)
        {
            if([bool]($myVirtualGw.PSobject.Properties.name -match "ConfigurationState"))
            {
                if($myVirtualGw.ConfigurationState.count -gt 0)
                {
                        $IsHealthy++
                }
             }
        }
    }

    if($IsHealthy -gt 0)
    {
        $PoolStatus="UnHealthy"
    }
    else
    {
        $totalVG=($Active+$Passive+$Redundant)
        if(($Redundant -lt $myPool.Properties.RedundantGatewayCount ) -or ($Redundant -ge $totalVG))
        {
            $PoolStatus="At Risk"
        }
        else
        {
            $PoolStatus="Healthy"
        }
    }

    #GRE VIP Usage column
    $NumberOfIPAddresses=0;
    $NumberofIPAddressesAllocated=0;
    $isGreVipSubnetsAvailable=0;
    Foreach ($myGreps in $myPool.Properties.IpConfiguration.GreVipSubnets)
    {
        $isGreVipSubnetsAvailable=1
        $logicalnetworkID=$myGreps.ResourceRef.split("/")[2]
        $subnetsID=$myGreps.ResourceRef.split("/")[4]

        $myLogicalSubnet= Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalnetworkID -ResourceId $subnetsID @paramsHash

        $NumberOfIPAddresses+=$myLogicalSubnet.Properties.Usage.NumberOfIPAddresses

        $NumberofIPAddressesAllocated+=$myLogicalSubnet.Properties.Usage.NumberofIPAddressesAllocated

    }
    if($NumberofIPAddressesAllocated -gt 0)
    {
        $GREVIPUsage=(($NumberofIPAddressesAllocated/$NumberOfIPAddresses)*100)#done
    }
    else
    {
       if($isGreVipSubnetsAvailable -eq 0)
       {
            $GREVIPUsage=-1
       }
       else
       {
            $GREVIPUsage=0
       }
    }

    #Public IP Address
    $IpAddresses=""
    Foreach ($myPublicIps in $myPool.Properties.IpConfiguration.PublicIPAddresses)
    {
        $publicIpID=$myPublicIps.ResourceRef.split("/")[2]

        $publicIPResult=Get-NetworkControllerPublicIpAddress -ResourceId $publicIpID @paramsHash

        $IpAddresses=$IpAddresses+$publicIPResult.Properties.IpAddress+","
    }

    if($IpAddresses.length -gt 0)
    {
        $IpAddresses=$IpAddresses.Substring(0,$IpAddresses.length-1)
    }
    $PublicIPAddress=$IpAddresses

# Get Result for GatewayPools

    $Result = New-Object -TypeName psobject
    $Result | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Name -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $PoolStatus -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'Type' -Value $PoolType -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'Active' -Value $Active -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'Passive' -Value $Passive -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'Redundant' -Value $Redundant -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'GREVIPUsage' -Value $GREVIPUsage -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'GREVIPUsed' -Value $NumberofIPAddressesAllocated -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'GREVIPTotal' -Value $NumberOfIPAddresses -ErrorAction SilentlyContinue
    $Result | Add-Member -MemberType NoteProperty -Name 'PublicIPAddress' -Value $PublicIPAddress -ErrorAction SilentlyContinue
    $Result
}

}
## [END] Get-GatewayPools ##
function Get-GatewayPools2 {
<#

.SYNOPSIS
Get Gateway Pools in the cluster

.DESCRIPTION
This script is used to list all GatewayPools available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $publicIpAddressName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

try
{
    # Get Gateway Pools in the cluster

    $gatewayPools = Get-NetworkControllerGatewayPool @paramsHash
    if($gatewayPools)
    {
        foreach($gatewayPool in $gatewayPools)
        {
            $publicIp = $gatewayPool.Properties.IpConfiguration.PublicIPAddresses

            if($publicIp)
            {
                if($publicIp.ResourceRef.Split('/')[2] -eq $publicIpAddressName)
                {
                    #Fetch Name
                    $name = $gatewayPool.ResourceId

                    #Fetch Type
                    $type = $gatewayPool.Properties.Type

                    # Preparing Object Response

                    $myResponse = New-Object -TypeName psobject

                    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue
                    $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type -ErrorAction SilentlyContinue

                    $myResponse
                }
            }
        }
    }
}
catch
{
    $myResponse = $error[0].Exception.InnerException
    $myResponse
}

}
## [END] Get-GatewayPools2 ##
function Get-GatewayPoolsHealthInfo {
<#

.SYNOPSIS
Gets Gateway Pools Health Info.

.DESCRIPTION
Gets the information for the Gateway Pools Health.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>
param(
[Parameter(Mandatory = $True)]
[object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

$NCGatewayPool = Get-NetworkControllerGatewayPool @paramsHash
if ($null -ne $NCGatewayPool)
{
    Foreach ($myPool in $NCGatewayPool)
    {
        $Gateways=@()
        if ($null -ne $myPool.Properties.Gateways)
        {
            Foreach ($myGw in $myPool.Properties.Gateways)
            {
                $gwVM=$myGw.ResourceRef.split("/")[2]
                $myGwResult = Get-NetworkControllerGateway -ResourceId $gwVM @paramsHash | ConvertTo-Json | ConvertFrom-Json
                $Gateways += $myGwResult
            }
        }
        $Result=@()
        $Result += New-Object -TypeName psobject
        $Result | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $NCGatewayPool
        $Result | Add-Member -MemberType NoteProperty -Name 'Gateways' -Value $Gateways
        $Result
    }

}

}
## [END] Get-GatewayPoolsHealthInfo ##
function Get-GatewayPoolsInfo {
<#

.SYNOPSIS
Gets the Gateway pools Information.

.DESCRIPTION
Gets the detailed analytical information for the Gateway pools.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [object] $gatewaysRestResources
)

Import-Module Hyper-V -ErrorAction SilentlyContinue;
Start-Transcript -Path "ms-sdn-wac.log" -ErrorAction SilentlyContinue -Append |Out-Null

Foreach ($gatewayRESTResource in $gatewaysRestResources)
{
    $vmName = ($gatewayRESTResource.ResourceId.split('.')[0])
    Write-Host "Looking for VM $vmName"
    $gatewayVm = Get-VM -Name $vmName -ErrorAction SilentlyContinue -Verbose
    if($null -eq $gatewayVm) {
      Write-Host "Unable to find $($gatewayRESTResource.ResourceId)"
      continue
    }
    Write-Host "Found VM $vmName"

    $NCName=($gatewayVm.Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
    $CPU=$gatewayVm.CPUUsage
    $MemoryDemand=$gatewayVm.MemoryDemand
    $MemoryAssigned=$gatewayVm.MemoryAssigned

    if($MemoryAssigned -gt 0) {
      $Memory=[math]::Round((($MemoryDemand/$MemoryAssigned)*100))
    } else {
      $Memory = 0
    }

    $Storage = 0
    $vhdPaths = (Get-VHD -VMId $gatewayVm.Id).Path
    $fileSize = 0
    $totalSize = 0
    foreach ($vhdPath in $vhdPaths) {
        $VHDAttached=Get-VHD -Path $vhdPath
        $fileSize+=$VHDAttached.FileSize
        $totalSize+=$VHDAttached.Size
    }
    if($fileSize -gt 0)
    {
        $Storage=[math]::Round((($fileSize/$totalSize)*100))
    }

    [String]$NetworkStatus=$gatewayVm.NetworkAdapters[0].Status
    $NetworkStatus = $NetworkStatus.ToUpper()

    [String]$Uptime = $gatewayVm.Uptime
    if($Uptime.split('.').count -gt 2)
    {
        [String]$NewUptime=(($Uptime.split(".")[0])+" days, "+($Uptime.split(".")[1].split(":")[0])+" hours, "+($Uptime.split(".")[1].split(":")[1])+" minutes, "+($Uptime.split(".")[1].split(":")[2])+" seconds")
    }
    else
    {
        [String]$NewUptime=(("0 day, "+($Uptime.split(":")[0])+" hours, "+($Uptime.split(":")[1])+" minutes, "+($Uptime.split(":")[2].split(".")[0])+" seconds"))
    }

    $HostName=((Get-CIMInstance CIM_ComputerSystem).Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
    [String]$VMStatus=$gatewayVm.State
    [String]$Heartbeat=$gatewayVm.Heartbeat

    #Preparing Additional property
    $GatewayStatus = $gatewayRESTResource.Properties.State
    $ConfigurationState=$gatewayRESTResource.Properties.ConfigurationState.Status
    $ConfigurationStateDetails=""
    Foreach($detailedInfo in $gatewayRESTResource.Properties.ConfigurationState.DetailedInfo)
    {
        if($detailedInfo.Message)
        {
            $ConfigurationStateDetails += $detailedInfo.Code + " : " + $detailedInfo.Message+"; "
        }
    }

    $AvailableCapacity=($gatewayRESTResource.Properties.AvailableCapacity.ToString() +" / "+ $gatewayRESTResource.Properties.TotalCapacity.ToString())
    $GatewayConnections=$gatewayRESTResource.Properties.Connections.count
    $GatewayPool=$gatewaysRestResources.Properties.Pool.ResourceRef.split("/")[2]

    #-------------------------------
    # Get Result for GatewayPools Info
    $gatewayPoolInfoResponse = New-Object -TypeName psobject
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $NCName -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'CPU' -Value $CPU -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $Memory -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Storage' -Value $Storage -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'NetworkStatus' -Value $NetworkStatus -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Uptime' -Value $NewUptime -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Host' -Value $HostName -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'VMStatus' -Value $VMStatus -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'Heartbeat' -Value $Heartbeat -ErrorAction SilentlyContinue

    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'GatewayPool' -Value $GatewayPool -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'GatewayStatus' -Value $GatewayStatus -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationState' -Value $ConfigurationState -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'ConfigurationStateDetails' -Value $ConfigurationStateDetails -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'AvailableCapacity' -Value $AvailableCapacity -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'GatewayConnections' -Value $GatewayConnections -ErrorAction SilentlyContinue
    $gatewayPoolInfoResponse | Add-Member -MemberType NoteProperty -Name 'VMId' -Value $gatewayVm.Id -ErrorAction SilentlyContinue

    Write-Host "Returning VM information for VM $vmName "
    $gatewayPoolInfoResponse
}
Stop-Transcript | out-null

}
## [END] Get-GatewayPoolsInfo ##
function Get-GatewayThroughputLive {
<#

.SYNOPSIS
Gets the Gateway throughput Information.

.DESCRIPTION
Gets the live throughput information for the Gateway.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module Hyper-V -ErrorAction SilentlyContinue
Set-StrictMode -Version 5.0
Import-Module CimCmdlets
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management

$Gateway=Get-NetworkControllerGateway @paramsHash
$Gw=$Gateway.Properties.VirtualServer
$gwnames=$gw.ResourceRef

foreach($gwname in $gwnames){
    Try
    {
        $virtualNetworkAdapterInbound=0
        $virtualNetworkAdapterOutbound=0
        $arr=$gwname.split("/")[2]
        $vm=get-vm | Where {$_.name -contains $arr}
        if ($vm) {

            #Virtual Network Adapter
            $networkAdapters = $vm.NetworkAdapters
            $adepterInbound = 0
            $adepterOutbound = 0
            foreach ($networkAdapter in $networkAdapters) {
                $adapterId = $networkAdapter.AdapterId
                if ($null -eq $adapterId) {
                    $idSplit = $networkAdapter.id.Split('\')
                    $adapterId = $idSplit[$idSplit.Count - 1]
                }
            # hyper-V VirtualNetworkAdapter
                $hyperVVirtualNetworkAdapter = Get-CimInstance -ClassName Win32_PerfFormattedData_NvspNicStats_HyperVVirtualNetworkAdapter | Where-Object { $_.Name -and $_.Name.Contains($adapterId)}
                if ($hyperVVirtualNetworkAdapter) {
                    $adepterInbound += $hyperVVirtualNetworkAdapter.BytesReceivedPersec
                    $adepterOutbound += $hyperVVirtualNetworkAdapter.BytesSentPersec

                }
            }

            $virtualNetworkAdapterInbound+= [math]::Round($adepterInbound / 1024 / 1024, 2)
            $virtualNetworkAdapterOutbound+= [math]::Round($adepterOutbound / 1024 / 1024, 2)
            # Get Result for Gateway Throughput Live
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'Name' $arr
            $result | Add-Member -MemberType NoteProperty -Name 'Received' $virtualNetworkAdapterInbound
            $result | Add-Member -MemberType NoteProperty -Name 'Sent' $virtualNetworkAdapterOutbound

            $result
        }
    }
    Catch{}
}

}
## [END] Get-GatewayThroughputLive ##
function Get-HostName {
<#

.SYNOPSIS
Get HostName

.DESCRIPTION
This Script is used to get the Hosting Virtual machine Name

.ROLE
Readers

#>

$vmParameters = Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction SilentlyContinue
if($null -ne $vmParameters)
{
    $hostName = $vmParameters.GetValue("HostName").ToLower()
}
else
{
    $hostName = $null
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hostName -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-HostName ##
function Get-IPAddressesofServer {
<#

.SYNOPSIS
Get the IP Addresses

.DESCRIPTION
This script is used to Fetch the IpAddresses of the server

.ROLE
Readers

#>

param(

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [array] $ipAddresses

)

$data = ovsdb-client dump tcp:127.0.0.1:6641 ms_vtep

foreach($ipAddress in $ipAddresses)
{
    for($i=0; $i -lt $data.Length; $i++)
    {
        if($data[$i] -match $ipAddress )
        {
            $valuesList = $data[$i].split()
            for($j=0; $j -lt $valuesList.Length; $j++)
            {
                if($valuesList[$j] -like '"*.*.*.*"')
                {
                    for($k = $j+1; $k -lt $valuesList.Length; $k++)
                    {
                        if($valuesList[$k] -ne "")
                        {
                            $value = $valuesList[$k]
                            break
                        }
                    }
                    break
                }
            }

            for($l=0; $l -lt $data.Length; $l++)
            {
                if($data[$l] -match $value)
                {
                    $splittedData = $data[$l].split()
                    for($m=0; $m -lt $splittedData.Length; $m++)
                    {
                        if($splittedData[$m] -like '"*.*.*.*"')
                        {
                            $ip = $splittedData[$m].Trim('"')

                            $myResponse = New-Object -TypeName psobject

                            $myResponse | Add-Member -MemberType NoteProperty -Name 'IP' -Value $ip -ErrorAction SilentlyContinue

                            $myResponse

                            break
                        }
                    }
                    break
                }
            }
            break
        }
    }
}

}
## [END] Get-IPAddressesofServer ##
function Get-IPSecGatewayRemoteExternalipAddress {

<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the IPAddress of Network Controller virtual Gateway of type IPSec & GRE

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $connectionTypeName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

foreach($virtualGateway in $virtualGateways)
{
    $networkConnections = $virtualGateway.Properties.NetworkConnections
    foreach($networkConnection in $networkConnections)
    {
        $connectionType = $networkConnection.Properties.ConnectionType
        if($connectionType  -eq $connectionTypeName)
        {
            $IPAddress = $networkConnection.Properties.DestinationIPAddress

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $IPAddress -ErrorAction SilentlyContinue

            $myResponse
        }
    }
}

}
## [END] Get-IPSecGatewayRemoteExternalipAddress ##
function Get-IPSecGatewaySourceIpAddress {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the source IPAddress and Gateway Name of Network Controller virtual Gateway of type IPSec & GRE

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $ipAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $connectionTypeName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

foreach($virtualGateway in $virtualGateways)
{
    $networkConnections = $virtualGateway.Properties.NetworkConnections
    foreach($networkConnection in $networkConnections)
    {
        $connectionType = $networkConnection.Properties.ConnectionType
        if($connectionType -eq $connectionTypeName)
        {

            $ip = $networkConnection.Properties.DestinationIPAddress
            if($ip -eq $ipAddress)
            {
                $sourceIPAddress = $networkConnection.Properties.SourceIPAddress
                $gateway = $networkConnection.Properties.Gateway.ResourceRef.Split('/')[2]

                $myResponse = New-Object -TypeName psobject

                $myResponse | Add-Member -MemberType NoteProperty -Name 'sourceIPAddress' -Value $sourceIPAddress -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'Gateway' -Value $gateway -ErrorAction SilentlyContinue

                $myResponse
                break
            }
        }

    }
}

}
## [END] Get-IPSecGatewaySourceIpAddress ##
function Get-IPV4AddressesofVM {
<#

.SYNOPSIS
Get the Ip Address of Virtual Machine

.DESCRIPTION
This script is used to Fetch the IPV4 and IPV6 addresses of virtual machine associated to Cluster Node

.ROLE
Readers

#>

$ipConfig = IPconfig
$ipAddress = @()

for($i=0; $i -lt $ipConfig.Length; $i++)
{
    if($ipConfig[$i] -match "IPV4")
    {
        $ipAddress += $ipConfig[$i].split(":")[1].trim()
    }
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue

$myResponse





}
## [END] Get-IPV4AddressesofVM ##
function Get-IPV4AddresswithDefaultGateway {
<#

.SYNOPSIS
Get the Ip Address of Virtual Machine

.DESCRIPTION
This script is used to Fetch the IPV4 addresses having a Default Gateway of virtual machine associated to Cluster Node

.ROLE
Readers
#>


$ipconfig = ipconfig

for($i=0;$i -lt $ipconfig.Length; $i++)
{
    if($ipconfig[$i] -match "Default Gateway")
    {
        $defaultGateway = $ipconfig[$i].split(':')[1].Trim()
        if($defaultGateway -like "*.*.*.*")
        {
            $i = $i-2
            $ipv4Address = $ipconfig[$i].split(':')[1].Trim()
            break
        }
    }
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipv4Address -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-IPV4AddresswithDefaultGateway ##
function Get-IPV4andIPV6AddressesofVM {
<#

.SYNOPSIS
Get the Ip Address of Virtual Machine

.DESCRIPTION
This script is used to Fetch the IPV4 and IPV6 addresses of virtual machine associated to Cluster Node

.ROLE
Readers

#>

param(
[Parameter(Mandatory = $true)]
[ValidateNotNullorEmpty()]
[string] $vm
)

$vmName = $vm.split('.')[0]

$vmNetworkAdapter = Get-VMNetworkAdapter -VMName $vmName

$ipAddresses = $vmNetworkAdapter.IPAddresses

if($null -ne $ipAddresses)
{
    $ipAddress = $ipAddresses
}
else
{
    $ipAddress = $null
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-IPV4andIPV6AddressesofVM ##
function Get-InboundFrontEndIPConfigurationIPAddress {
<#

.SYNOPSIS
Get the Network Controller LoadBalancer

.DESCRIPTION
This script is used to Fetch the Names of Network Controller Load Balancer

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$loadBalancers = Get-NetworkControllerLoadBalancer @paramsHash

foreach($loadBalancer in $loadBalancers)
{
    $inboundNatRules = $loadBalancer.Properties.InboundNatRules

    if($null -ne $inboundNatRules)
    {
        foreach($inboundNatRule in $inboundNatRules)
        {

            $loadBalancerName = $loadBalancer.ResourceId
            $frontEndIPConfigurationName = $inboundNatRule.Properties.FrontendIPConfigurations.ResourceRef.split('/')[4]
            $networkInterfaceName = $inboundNatRule.Properties.BackendIPConfiguration.ResourceRef.split('/')[2]
            $frontEndPort = $inboundNatRule.Properties.FrontendPort
            $backEndPort = $inboundNatRule.Properties.BackendPort

            $frontEndIpConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName @paramsHash

            $ipAddress = $frontEndIpConfiguration.Properties.PrivateIPAddress + ':' + $frontEndPort

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceName -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'BackEndPort' -Value $backEndPort -ErrorAction SilentlyContinue

            $myResponse
        }
    }
}


}
## [END] Get-InboundFrontEndIPConfigurationIPAddress ##
function Get-InboundNetworkInterfaceServerName {
<#

.SYNOPSIS
Get the Network Controller Network Interface servers

.DESCRIPTION
This script is used to Fetch the Names of Network ControllerNetwork Interface servers

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $networkInterfaceName,

  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $networkInterfaceName @paramsHash

$privateIPAddress = $networkInterface.Properties.IpConfigurations.Properties.PrivateIPAddress

$serverName = $networkInterface.Properties.Server.ResourceRef.Split('/')[2]

$networkControllerServer = Get-NetworkControllerServer -ResourceId $serverName @paramsHash

$server = $networkControllerServer.Properties.Connections.ManagementAddresses.ToLower()

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'PrivateIPAddress' -Value $privateIPAddress -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'Server' -Value $server -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-InboundNetworkInterfaceServerName ##
function Get-InternalLoadbalancingRuleFrontIPAddress {
<#

.SYNOPSIS
Get the Network Controller LoadBalancer

.DESCRIPTION
This script is used to Fetch the Names of Network Controller Load Balancer

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$loadBalancers = Get-NetworkControllerLoadBalancer @paramsHash
$networkInterfaceNames = @()

foreach($loadBalancer in $loadBalancers)
{
    $loadBalancingRules = $loadBalancer.Properties.LoadBalancingRules
    if($null -ne $loadBalancingRules)
    {
        $loadBalancerName = $loadBalancer.ResourceId
        $frontEndIPConfigurationName = $loadBalancer.Properties.LoadBalancingRules.Properties.FrontendIPConfigurations.ResourceRef.split('/')[4]
        $frontEndIpConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName @paramsHash
        $subnetType = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.Split('/')[1]
        if($subnetType -eq "virtualnetworks")
        {
            $backendAddressPoolName = $loadBalancer.Properties.LoadBalancingRules.Properties.BackendAddressPool.ResourceRef.split('/')[4]
            $backendAddressPool = Get-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadBalancerName -ResourceId $backendAddressPoolName @paramsHash
            $backendIPConfigurations = $backendAddressPool.Properties.BackendIPConfigurations
            foreach($backendIPConfiguration in $backendIPConfigurations)
            {
                $networkInterfaceNames += $backendIPConfiguration.ResourceRef.split('/')[2]
            }
            $frontEndPort = $loadBalancer.Properties.LoadBalancingRules.Properties.FrontendPort
            $backEndPort = $loadBalancer.Properties.LoadBalancingRules.Properties.BackendPort
            $ipAddress = $frontEndIpConfiguration.Properties.PrivateIPAddress + ':' + $frontEndPort

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceNames -ErrorAction SilentlyContinue

            $myResponse
        }

    }
}

}
## [END] Get-InternalLoadbalancingRuleFrontIPAddress ##
function Get-IsClusterS2D {
<#

.SYNOPSIS
Checks whether the cluster has S2D

.DESCRIPTION
Checks whether the cluster has S2D

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

$s2d = $null
try {
  $s2d = Get-ClusterS2D
} catch {

}
$null -ne $s2d

}
## [END] Get-IsClusterS2D ##
function Get-IsEceEnvironment {
<#

.SYNOPSIS
Checks whether the current environment is an ECE environment.

.DESCRIPTION
Checks for ECE cluster group in the current environment. If the group is found, the environment is considered to be an ECE environment. Otherwise, it is not.

.ROLE
Readers

#>

$eceFailOverClusterName = "Azure Stack HCI Orchestrator Service Cluster Group"
$oldEceFailOverClusterName = "ECE Windows Service Cluster Group"
try { 
    Import-Module FailoverClusters
    $eceClusterGroup = Get-ClusterGroup | Where-Object Name -in $eceFailOverClusterName, $oldEceFailOverClusterName
    $null -ne $eceClusterGroup
}
catch {
    $false
}
}
## [END] Get-IsEceEnvironment ##
function Get-IsFCNC {
<#

.SYNOPSIS
Gets whether the Network Controller is deployed on the failover cluster

.DESCRIPTION
Gets whether the Network Controller is deployed on the failover cluster

.ROLE
Readers

#>

$fcnc = Get-Item -Path hklm:\cluster\NetworkController -ErrorAction SilentlyContinue
$null -ne $fcnc -and $null -ne $fcnc.Property -and $fcnc.Property.Count -gt 0

}
## [END] Get-IsFCNC ##
function Get-IsNCReady {
<#
.SYNOPSIS
Gets the curl response

.DESCRIPTION
Gets the curl response

.ROLE
Readers
#>
param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $ncUri,

  [Parameter(Mandatory = $False)]
  [int] $retries = 3,

  [Parameter(Mandatory = $False)]
  [string] $certificateThumbprint

)

$paramsHash = @{}
if (-not [string]::IsNullOrEmpty($certificateThumbprint)) {
  $paramsHash.Add("CertificateThumbprint", $certificateThumbprint)
}

[string] $serversResourceUri = "networking/v1/servers"
$queryUri = "$ncUri/$serversResourceUri"

$count = 0
while ($count -lt $retries) {
  try {
    $curlResponse = curl -Uri $queryUri -UseBasicParsing -UseDefaultCredentials @paramsHash
    break
  } catch {
    $count++
    Start-Sleep -Seconds 5
  }
}

$null -ne $curlResponse -and $curlResponse.StatusCode -eq 200

}
## [END] Get-IsNCReady ##
function Get-L3ScenarioGateway {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the source IPAddress and Gateway Name of Network Controller virtual Gateway of type IPSec

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $resourceRef,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

foreach($virtualGateway in $virtualGateways)
{
    $networkConnections = $virtualGateway.Properties.NetworkConnections
    foreach($networkConnection in $networkConnections)
    {
        $connectionType = $networkConnection.Properties.ConnectionType
        if($connectionType -eq "L3")
        {
            $logicalNetworkResourceRef = $networkConnection.Properties.l3Configuration.vlanSubnet.resourceRef

            if($logicalNetworkResourceRef -eq $resourceRef)
            {
                $gateway = $networkConnection.Properties.Gateway.ResourceRef.Split('/')[2]

                $myResponse = New-Object -TypeName psobject

                $myResponse | Add-Member -MemberType NoteProperty -Name 'Gateway' -Value $gateway -ErrorAction SilentlyContinue

                $myResponse

                break
            }

        }
    }
}

}
## [END] Get-L3ScenarioGateway ##
function Get-L3TenantVLanSubnet {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the IPAddress of Network Controller virtual Gateway of type L3

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualGateways = Get-NetworkControllerVirtualGateway @paramsHash

foreach($virtualGateway in $virtualGateways)
{
    $networkConnections = $virtualGateway.Properties.NetworkConnections
    foreach($networkConnection in $networkConnections)
    {
        $connectionType = $networkConnection.Properties.ConnectionType

        if($connectionType -eq "L3")
        {
            $logicalNetworkResourceRef = $networkConnection.Properties.l3Configuration.vlanSubnet.resourceRef
            $logicalNetworkName = $logicalNetworkResourceRef.split('/')[2]
            $logicalSubnetName = $logicalNetworkResourceRef.split('/')[4]

            $logicalSubnet = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName -ResourceId $logicalSubnetName @paramsHash

            $addressPrefix = $logicalSubnet.properties.AddressPrefix
            $vlanID = $logicalSubnet.properties.VlanID

            $IPAddress = $addressPrefix +"(VLanID:$vlanID)"

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $IPAddress -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'LogicalNetworkResourceRef' -Value $logicalNetworkResourceRef -ErrorAction SilentlyContinue

            $myResponse
        }

    }
}


}
## [END] Get-L3TenantVLanSubnet ##
function Get-LoadBalancer {
<#

.SYNOPSIS
Get Load balancer details

.DESCRIPTION
This script is used to Get the details of Load balancer associated to Public IP Addresses available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $publicIpAddressName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

try
{
    # Get Public IP Address in the cluster
    $publicIpAddress = Get-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName @paramsHash

    $ipConfiguration = $publicIpAddress.Properties.IpConfiguration
    if($ipConfiguration)
    {
        $ipConfigType = $ipConfiguration.ResourceRef.split('/')[1]
        if($ipConfigType.ToLower() -eq "loadBalancers")
        {
            $loadBalancerName = $ipConfiguration.ResourceRef.split('/')[2]

            $loadBalancer = Get-NetworkControllerLoadBalancer -ResourceId $loadBalancerName @paramsHash

            #Fetch Type and IP Address of Load Balancer
            $frontEndIpConfigurations = $loadBalancer.Properties.FrontendIPConfigurations
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
                        $ipAddress += $frontEndIpConfiguration.Properties.PublicIPAddress.ResourceRef.split('/')[2]
                    }
                    elseif($subnetCount -gt 0)
                    {
                        $networkName = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.split('/')[1]
                        if($networkName -eq "virtualNetworks")
                        {
                            $typeValue += "Internal"
                            $ipAddress += $frontEndIpConfiguration.Properties.PrivateIPAddress
                        }
                        else
                        {
                            $typeValue += "IP Address"
                            $ipAddress += $frontEndIpConfiguration.Properties.PrivateIPAddress
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
            else
            {
                $type = $null
                $ipAddress = $null
            }
            $backendpool = $loadBalancer.Properties.BackendAddressPools.ResourceId
            $inboundNatRule = $loadBalancer.Properties.InboundNatRules.count
            $outboundNatRule = $loadBalancer.Properties.OutboundNatRules.count
            $loadBalancing = $loadBalancer.Properties.LoadBalancingRules.count
            $healthprobe = $loadBalancer.Properties.Probes.count
            $ProvisioningState=$loadBalancer.Properties.ProvisioningState

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $loadBalancerName -ErrorAction SilentlyContinue
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
    }

}
catch
{
    $myResponse = $error[0].Exception.InnerException
    $myResponse
}

}
## [END] Get-LoadBalancer ##
function Get-LoadBalancerMuxes {
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

 # Get Virtual Networks in the cluster

$loadBalancerMuxes = Get-NetworkControllerLoadBalancerMux @paramsHash

if(($loadBalancerMuxes.length -gt 0) -and ($null -ne $loadBalancerMuxes))
{
    $result = "Available"
}
else
{
    $result = "Unavailable"
}
$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse



}
## [END] Get-LoadBalancerMuxes ##
function Get-LoadBalancingRuleFrontendIPConfigurations {
<#

.SYNOPSIS
Get the Network Controller LoadBalancer

.DESCRIPTION
This script is used to Fetch the Names of Network Controller Load Balancer

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$loadBalancers = Get-NetworkControllerLoadBalancer @paramsHash
$networkInterfaceNames = @()

foreach($loadBalancer in $loadBalancers)
{
    $loadBalancingRules = $loadBalancer.Properties.LoadBalancingRules
    if($null -ne $loadBalancingRules)
    {
        $loadBalancerName = $loadBalancer.ResourceId
        $frontEndIPConfigurationName = $loadBalancer.Properties.LoadBalancingRules.Properties.FrontendIPConfigurations.ResourceRef.split('/')[4]
        $frontEndIpConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIPConfigurationName @paramsHash
        $subnetType = $frontEndIpConfiguration.Properties.Subnet.ResourceRef.Split('/')[1]
        if($subnetType -eq "logicalnetworks")
        {
            $backendAddressPoolName = $loadBalancer.Properties.LoadBalancingRules.Properties.BackendAddressPool.ResourceRef.split('/')[4]
            $backendAddressPool = Get-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadBalancerName -ResourceId $backendAddressPoolName @paramsHash
            $backendIPConfigurations = $backendAddressPool.Properties.BackendIPConfigurations
            foreach($backendIPConfiguration in $backendIPConfigurations)
            {
                $networkInterfaceNames += $backendIPConfiguration.ResourceRef.split('/')[2]
            }
            $frontEndPort = $loadBalancer.Properties.LoadBalancingRules.Properties.FrontendPort
            $backEndPort = $loadBalancer.Properties.LoadBalancingRules.Properties.BackendPort
            $ipAddress = $frontEndIpConfiguration.Properties.PrivateIPAddress + ':' + $frontEndPort

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceNames -ErrorAction SilentlyContinue

            $myResponse
        }
    }
}


}
## [END] Get-LoadBalancingRuleFrontendIPConfigurations ##
function Get-LogicalNetworks {
<#

.SYNOPSIS
Gets the Logical Networks.

.DESCRIPTION
Gets the Logical Networks objects from the SDN Network Controller.

.ROLE
Readers

.PARAMETER restParams
    The NC REST parameters used to connect to the SDN Network controller

#>

param
(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0
Import-Module NetworkController
Import-Module Microsoft.PowerShell.Management

$logicalNetworks = @(Get-NetworkControllerLogicalNetwork @paramsHash | Where-Object {$_.ResourceId -eq "HNVPA" -And $_.Properties.NetworkVirtualizationEnabled -eq $true -And $_.Properties.Subnets -ne $null -And $_.Properties.Subnets.Properties.IpPools -ne $null})
$logicalNetworks | ConvertTo-Json -depth 100 | ConvertFrom-Json # This expands the Properties so that we can get the objects

}
## [END] Get-LogicalNetworks ##
function Get-LogicalSubnets {
<#

.SYNOPSIS
Get all the Logical Subnets in the Cluster

.DESCRIPTION
This script is used to Fetch all the Logical Subnets in which IsPublic Property
is set to true in the Cluster

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
 $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

try
{
    #Fetch all the Logical Networks
    $logicalNetworks = Get-NetworkControllerLogicalNetwork @paramsHash

    #Fetch Logical Networks ResourceID
    $logicalNetworkNames = $logicalNetworks.ResourceId

    foreach($logicalNetworkName in $logicalNetworkNames)
    {
        #Fetch all the Logical Subnets of a Logical Network
        $subnets = Get-NetworkControllerLogicalSubnet -LogicalNetworkId $logicalNetworkName @paramsHash

        foreach($subnet in $subnets)
        {
            $isPublic = $subnet.Properties.IsPublic
            $numberOfIPAddresses = $subnet.Properties.Usage.NumberOfIPAddresses
            $numberofIPAddressesAllocated = $subnet.Properties.Usage.NumberofIPAddressesAllocated
            if(($isPublic -eq $true) -and ($numberofIPAddressesAllocated -lt $numberOfIPAddresses))
            {
                $subnet | convertto-json -depth 5 | convertfrom-json
            }
        }
    }
}
catch
{
    $myResponse = $error[0].Exception.InnerException.Message
    $myResponse
}

}
## [END] Get-LogicalSubnets ##
function Get-MUXThroughputHistoryTimeSeries {
<#

.SYNOPSIS
Gets the Mux throughput history information.

.DESCRIPTION
Gets the detailed hour and day throughput information for the Multiplexers.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String]$HistoryOf,
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module CimCmdlets
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management

function CreateGraphData($rawData, $conversion) {
    $graphData = New-Object System.Collections.ArrayList
    if ($null -eq $rawData){
        return $graphData
    }
    $groupData = $rawData.Group
    for ($i=$groupData.Count -1; $i -ge 0; $i--) {
        $recordsData = $groupData[$i].Records
        if ($recordsData -and $recordsData.Count -gt 0) {
            $cimProperties = $recordsData[0].CimInstanceProperties;
            if ($cimProperties.Count -gt 0) {
                $pointData = New-Object PSObject

                $value = $cimProperties.Value[1]
                if ($null -ne $conversion) {
                    $value = [math]::Round($value / $conversion, 2)
                }
                $pointData | Add-Member -MemberType NoteProperty -Name 'Value' $value
                $graphData.Add($pointData) > $null
            }
        }
    }

    return $graphData
}
$muxname=Get-NetworkControllerLoadBalancerMux @paramsHash
$muxRRefs=$muxname.Properties.VirtualServer
$muxnames=$muxRRefs.resourceref


foreach($vmname in $muxnames){
    Try
    {
        $arr=$vmname.split("/")[2]
        $vm=get-vm | Where {$_.name -contains $arr}
        if($vm)
        {
            $vmid=$vm.Id;
            $vm = Get-VM -id $vmId

            # Get raw Health Metrics data
            if($HistoryOf -eq "HOUR")
            {
                $NetworkRawInBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.inbound -TimeFrame LastHour
                $NetworkRawOutBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.outbound -TimeFrame LastHour
            }
            elseif($HistoryOf -eq "DAY")
            {
                $NetworkRawInBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.inbound -TimeFrame LastDay
                $NetworkRawOutBound = $vm | Get-ClusterPerformanceHistory -VirtualMachineSeriesName VirtualNetworkAdapter.Bytes.outbound -TimeFrame LastDay
            }
            # Create data needed for graph
            $kBConversion = 1024
            $MBConversion = 1024 * 1024

            $NetworkInbound = CreateGraphData $NetworkRawInBound $MBConversion
            $NetworkOutBound = CreateGraphData $NetworkRawOutBound $MBConversion
            # Get result for MUX Throughput History Time Series
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'Name' $arr
            $result | Add-Member -MemberType NoteProperty -Name 'Received' -Value $NetworkInbound.value
            $result | Add-Member -MemberType NoteProperty -Name 'Sent' -Value $NetworkOutBound.value

            #$result | fl *
            $result
            }
    }
    Catch{}
}


}
## [END] Get-MUXThroughputHistoryTimeSeries ##
function Get-MUXThroughputLive {
<#

.SYNOPSIS
Gets the Mux throughput information.

.DESCRIPTION
Gets the detailed live throughput information for the Multiplexers.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue
Import-Module CimCmdlets
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management

$muxname=Get-NetworkControllerLoadBalancerMux @paramsHash
$muxRRefs=$muxname.Properties.VirtualServer
$muxnames=$muxRRefs.resourceref

foreach($vmname in $muxnames){
Try{
    $arr=$vmname.split("/")[2]
    $vm=get-vm | Where {$_.name -contains $arr}
    $virtualNetworkAdapterInbound=0
    $virtualNetworkAdapterOutbound=0
    if ($vm) {

        #Virtual Network Adapter
        $networkAdapters = $vm.NetworkAdapters
        $adepterInbound = 0
        $adepterOutbound = 0
        foreach ($networkAdapter in $networkAdapters) {
            $adapterId = $networkAdapter.AdapterId
            if ($null -eq $adapterId) {
                $idSplit = $networkAdapter.id.Split('\')
                $adapterId = $idSplit[$idSplit.Count - 1]
            }
        # hyperV virtual network adapter
            $hyperVVirtualNetworkAdapter = Get-CimInstance -ClassName Win32_PerfFormattedData_NvspNicStats_HyperVVirtualNetworkAdapter | Where-Object { $_.Name -and $_.Name.Contains($adapterId)}
            if ($hyperVVirtualNetworkAdapter) {
                $adepterInbound += $hyperVVirtualNetworkAdapter.BytesReceivedPersec
                $adepterOutbound += $hyperVVirtualNetworkAdapter.BytesSentPersec

            }
        }

        $virtualNetworkAdapterInbound+= [math]::Round($adepterInbound / 1024 / 1024, 2)
        $virtualNetworkAdapterOutbound+= [math]::Round($adepterOutbound / 1024 / 1024, 2)
        # Get Result for MUX Throughput Live
        $result = New-Object PSObject
        $result | Add-Member -MemberType NoteProperty -Name 'Name' $arr
        $result | Add-Member -MemberType NoteProperty -Name 'Received' $virtualNetworkAdapterInbound
        $result | Add-Member -MemberType NoteProperty -Name 'Sent' $virtualNetworkAdapterOutbound
        $result
    }
  }
  Catch{}
}

}
## [END] Get-MUXThroughputLive ##
function Get-MultiSiteNetworkControllerSiteInformation {
<#

.SYNOPSIS
Get all the NCs in a multisite configuration

.DESCRIPTION
Get the multisite information for a specific cluster. Names are local to this cluster

.ROLE
Readers

#>
param
(
    [Parameter(Mandatory = $true)]
    [String] $localClusterName,
    [Parameter(Mandatory = $false)]
    [String] $localNcVmName,
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController

$result = @()

try {
  $multisiteConfig = Get-NetworkControllerMultisiteConfiguration @paramsHash
} catch {
  $multisiteConfig = $null
}

if ($null -ne $multisiteConfig) {
  $foundPrimary = $false

  foreach ($site in $multisiteConfig.Properties.sites) {
    $name = $null
    if ($null -ne $site.ResourceMetadata) {
      $name = $site.ResourceMetadata.ResourceName
    }

    $clusterName = $null
    $ncVmName = $null
    if ($null -ne $multisiteConfig.Tags) {
      $clusterName = $multisiteConfig.Tags.RemoteClusterName
      $ncVmName = $multisiteConfig.Tags.RemoteNcVmName
    }

    $newObject = [PSCustomObject]@{
      IsPrimary = $site.Properties.IsPrimary
      ResourceId = $site.ResourceId
      Name = $name
      ClusterName = $clusterName
      NcVmName = $ncVmName
      Uri = ("https://" + $site.Properties.RestIPAddress)
      State = $site.Properties.State
      ProvisioningState = $site.Properties.ProvisioningState
    }

    $result += $newObject

    if ($site.Properties.IsPrimary -eq $true) {
      $foundPrimary = $true
    }
  }

  $name = $null
  if ($null -ne $multisiteConfig.ResourceMetadata) {
    $name = $multisiteConfig.ResourceMetadata.ResourceName
  }

  $localNcVmName = $null
  if ($null -ne $multisiteConfig.Tags) {
    $localNcVmName = $multisiteConfig.Tags.LocalNcVmName
  }

  # Add the local site at the end
  $result += [PSCustomObject]@{
      IsPrimary = -not $foundPrimary
      ResourceId = $multisiteConfig.ResourceId
      Name = $name
      ClusterName = $localClusterName
      NcVmName = $localNcVmName
      Uri = $paramsHash.ConnectionUri
      State = "Local"
      ProvisioningState = $multisiteConfig.Properties.ProvisioningState
  }
}
else {
  $result += [PSCustomObject]@{
      IsPrimary = $true
      ResourceId = $null
      Name = "NetworkController1"
      ClusterName = $localClusterName
      NcVmName = $localNcVmName
      Uri = $paramsHash.ConnectionUri
      State = "Local"
      ProvisioningState = $null
  }
}

$result

}
## [END] Get-MultiSiteNetworkControllerSiteInformation ##
function Get-MuxsVMInfo {
<#

.SYNOPSIS
Gets the Mux VM information.

.DESCRIPTION
Gets the detailed information for the Multiplexer.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

$muxes = Get-NetworkControllerLoadBalancerMux @paramsHash

foreach( $mux in $muxes) {
  $mux | ConvertTo-Json -Depth 10 | ConvertFrom-Json
}

}
## [END] Get-MuxsVMInfo ##
function Get-NCEssentialInfo {
<#

.SYNOPSIS
Gets the Network controller essential information.

.DESCRIPTION
Gets the detailed essential information for the Network controller.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Get-NetworkController | ConvertTo-Json | ConvertFrom-Json

}
## [END] Get-NCEssentialInfo ##
function Get-NCNodeInfo {
<#

.SYNOPSIS
Gets the Network controller node information.

.DESCRIPTION
Gets the detailed node information about the Network controller.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String[]]
    $NCVmName,
    [Parameter(Mandatory = $true)]
    [String[]]
    $NCVmStatus
)

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue


$count=0
Foreach ($myNC in $NCVmName)
{
    $res = Get-Vm | Where-Object {$_.name -contains $myNC.split(".")[0].ToLower()}

    # vms in a bad state should be processed in tabs but their counters should not be evaluated
    [bool] $isUnavailable = $false
    if($null -ne $res -and $res.State -ne 'Running') {
      $isUnavailable = $true
    }

    if($res) {

        $Result = New-Object -TypeName psobject
        $NCName=($res.Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()

        $CPU=0
        $MemoryDemand=0
        $MemoryAssigned=$res.MemoryAssigned
        $CPU=$res.CPUUsage

        $Storage=0
        $fileSize=0
        $totalSize=0
        $fileSize=0
        $totalSize=0
        $Storage = 0
        $Memory = 0
        [String]$NetworkStatus = $res.NetworkAdapters[0].Status
        if(-not $isUnavailable) {

          $CPU=$res.CPUUsage
          $MemoryDemand=$res.MemoryDemand
          $MemoryAssigned=$res.MemoryAssigned
          $Memory=[math]::Round((($MemoryDemand/$MemoryAssigned)*100))

          $Storage=0
          $vhdPaths = (Get-VHD -VMId $res.Id).Path
          $fileSize=0
          $totalSize=0

          foreach ($vhdPath in $vhdPaths) {
              $VHDAttached=Get-VHD -Path $vhdPath
              $fileSize+=$VHDAttached.FileSize
              $totalSize+=$VHDAttached.Size
          }
          if($fileSize -gt 0)
          {
              $Storage=[math]::Round((($fileSize/$totalSize)*100))
          }

        }

        [String]$Uptime=$res.Uptime

        if($Uptime.split('.').count -gt 2)
        {
           [String]$NewUptime=(($Uptime.split(".")[0])+" days, "+($Uptime.split(".")[1].split(":")[0])+" hours, "+($Uptime.split(".")[1].split(":")[1])+" minutes, "+($Uptime.split(".")[1].split(":")[2])+" seconds")
        }
        else
        {
           [String]$NewUptime=(("0 day, "+($Uptime.split(":")[0])+" hours, "+($Uptime.split(":")[1])+" minutes, "+($Uptime.split(":")[2].split(".")[0])+" seconds"))
        }
        $HostName=((Get-CIMInstance CIM_ComputerSystem).Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
        [String]$VMStatus=$res.State
        $NCNodeStatus=$NCVmStatus[$count]
        [String]$Heartbeat=$res.Heartbeat

        #Get result for NC Node Info
        $Result | Add-Member -MemberType NoteProperty -Name 'Name' -Value $NCName -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'CPU' -Value $CPU -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $Memory -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Storage' -Value $Storage -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'NetworkStatus' -Value $NetworkStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Uptime' -Value $NewUptime -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Host' -Value $HostName -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'VMStatus' -Value $VMStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'NCNodeStatus' -Value $NCNodeStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Heartbeat' -Value $Heartbeat -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'VMId' -Value $res.Id -ErrorAction SilentlyContinue
        $Result
    }
    $count++
  }

}
## [END] Get-NCNodeInfo ##
function Get-NCNodeNames {
<#

.SYNOPSIS
Get the NC Node names from the cluster node

.DESCRIPTION
Get the NC Node names from the cluster node

.ROLE
Readers

#>

$nodeNames = $null;

Try {
    $nodeNames = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\' -ErrorAction Stop).NetworkControllerNodeNames
    # turn comma separated string into array of strings
    if ($null -ne $nodeNames -and (($nodeNames -is [System.Collections.IEnumerable] -and $nodeNames.length -ne 0) -or ($nodeNames -is [string] -and $nodeNames -ne "")))
    {
        $nodeNames = $nodeNames.Split(",")
    }
    else
    {
        $nodeNames = @()
    }
}
Catch [System.Management.Automation.ItemNotFoundException] {
    # Key doesn't exist so return empty array
    $nodeNames = @()
}

$nodeNames

}
## [END] Get-NCNodeNames ##
function Get-NCReplicaStatus {
<#

.SYNOPSIS
Gets the Network controller replica status information.

.DESCRIPTION
Gets the replica status of the Network controller.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

$nwReplicas=Get-NetworkControllerReplica
$count=$nwreplicas.count
$j=3
$NwReplicastatus=0
$NwReplicastatus=@()

for($i=1;$i -lt $count;$i++)
{

if($i -eq 1){
#$replica=$nwreplicas[$i]
#$replica
#$servicename=$replica.split(":")[1]
$NwReplicastatus += $nwreplicas[$i]
$k=$j+$i
}

if($k -lt $count){
$PrimaryNode=$nwreplicas[$k].formatEntryInfo.listViewFieldList[1].formatPropertyField.propertyValue
$NwReplicastatus += $PrimaryNode
$ReplicaStatus=$nwreplicas[$k].formatEntryInfo.listViewFieldList[2].formatPropertyField.propertyValue
$NwReplicastatus += $ReplicaStatus
$k=$k+$j
#$nwreplicas[$k]
#$replica=$nwreplicas[$k]
#$servicename=$replica.split(":")[1]
$NwReplicastatus += $nwreplicas[$k]
$u=$k+1
if($nwReplicas[$u].shapeInfo.ClassId2e4f51ef21dd47e99d3c952918aff9cd){ 
$k=$k+$j
}else{
$k=$k+1
#$replica=$nwreplicas[$k]
#$servicename=$replica.split(":")[1]
$NwReplicastatus += $nwreplicas[$k]
#$nwreplicas[$k]
$k=$k+$j
}
}
}
#$format=$NwReplicastatus | convertto-json -depth 10

# Get Result for NC Replica Status
$result = new-object psobject
$result | Add-Member -MemberType NoteProperty -Name 'status' -Value $NwReplicastatus
$result
<#
foreach($replicastatus in $NwReplicastatus){

$result = New-object psobject
$result | Add-Member -MemberType NoteProperty -Name 'ServiceName' -Value $replicastatus
$result | Add-Member -MemberType NoteProperty -Name 'PrimaryNode' -Value $replicastatus
$result | Add-Member -MemberType NoteProperty -Name 'ReplicaStatus' -Value $replicastatus
$result
}
#>

}
## [END] Get-NCReplicaStatus ##
function Get-NCUri {
<#

.SYNOPSIS
Get the NCURIs from the cluster node

.DESCRIPTION
Get the NCURIs from the cluster node

.ROLE
Readers

#>

$connections = $null;

Try {
    $connections = (
    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\' -ErrorAction Stop).Connections | 
        Where-Object { $_ -like "ssl:*" } | # We want all connections that start with "ssl", with each connection having the format "ssl:test.domain.com:5555"
        ForEach-Object -Process { $_.Split(':')[1] }); # The uri is in the middle so filter for that string
}
Catch [System.Management.Automation.ItemNotFoundException] {
    # Key doesn't exist so return empty array
    $connections = @();
}


$connections
}
## [END] Get-NCUri ##
function Get-NCVMMStatus {
<#

.SYNOPSIS
Gets NCVMM status

.DESCRIPTION
Gets NCVMM status

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Management

$result = @{}
try {
    Get-Process vmmagent -ErrorAction Stop
    $result['vmmRunning'] = $true
} catch {
    $result['vmmRunning'] = $false
}

return $result

}
## [END] Get-NCVMMStatus ##
function Get-NConFC {
<#

.SYNOPSIS
Gets the Network Controller information

.DESCRIPTION
Gets the detailed essential information for the Network controller.

.ROLE
Readers

#>

Get-NetworkControllerOnFailoverCluster

}
## [END] Get-NConFC ##
function Get-NetworkAdapters {
<#

.SYNOPSIS
Get Network Adapter in the cluster

.DESCRIPTION
This script is used to List all Network Adapter available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $publicIpAddressName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

try
{
    # Get Gateway Pools in the cluster

    $networkInterfaces = Get-NetworkControllerNetworkInterface @paramsHash
    if($networkInterfaces)
    {
        foreach($networkInterface in $networkInterfaces)
        {
            $ipConfigurations = $networkInterface.Properties.IpConfigurations

            if($ipConfigurations)
            {
                foreach($ipConfiguration in $ipConfigurations)
                {
                    $publicIp = $ipConfiguration.Properties.PublicIPAddress
                    if($publicIp)
                    {
                        if($publicIp.ResourceRef.Split('/')[2] -eq $publicIpAddressName)
                        {
                            #Fetch Name
                            $name = $networkInterface.ResourceId

                            # Preparing Object Response

                            $myResponse = New-Object -TypeName psobject

                            $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name -ErrorAction SilentlyContinue

                            $myResponse
                        }
                    }
                }
            }
        }
    }
}
catch
{
    $myResponse = $error[0].Exception.InnerException
    $myResponse
}

}
## [END] Get-NetworkAdapters ##
function Get-NetworkControllerCertificate {
<#
.SYNOPSIS
Gets the networkcontroller rest certificate

.DESCRIPTION
Gets the networkcontroller rest certificate

Returns certificateImportResult with the details of the operation

.ROLE
Readers
#>
param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $ncUri,

  [Parameter(Mandatory = $false)]
  [String] $certificatePath,

  [Parameter(Mandatory = $False)]
  [string] $certificateThumbprint
)

$paramsHash = @{}
if (-not [string]::IsNullOrEmpty($certificateThumbprint)) {
  $paramsHash.Add("CertificateThumbprint", $certificateThumbprint)
}

[string] $certificateTrustFailure      = "CertificateTrustFailure"
[string] $certAccessDeniedError = "CertAccessDeniedError"
[string] $certificateErrorUnknown      = "CertificateUnknownError"

[string] $serversResourceUri = "networking/v1/servers"
[bool] $attemptCertificateImport = $false
[bool] $isSelfSignedCertificate = $false

$certificateImportResult = @{
  result = "";
  isCertificateNearExpiry = $false;
  isSuccess = $false;
  isCertificateImportRequired = $false
  exceptionDetails = "";
}

Start-Transcript -Path "sdn-wac-validation-cert.log" -Append -IncludeInvocationHeader -Confirm:$false -Force | Out-Null

if([string]::IsNullOrEmpty($certificatePath) -eq $true) {
  $certificatePath = "$Env:Temp\NetworkControllerCertificate.cer"
}

Import-Module NetworkController
$nodeNames = $null;

try {

  Write-Host "attempting to query sdn networkController"
  $queryUri = "$ncUri/$serversResourceUri"

  # bug in NC cmdlets causes transcript abort, thus avoiding it and using curl instead
  # Get-NetworkControllerServer -ConnectionUri $ncUri
  $curlResponse = curl -Uri $queryUri -UseBasicParsing -UseDefaultCredentials @paramsHash
  Write-Debug "sdn validation completed!"

  $certificateImportResult.result = "";
  $certificateImportResult.isCertificateNearExpiry = $false
  $certificateImportResult.isSuccess = $true
  $certificateImportResult.exceptionDetails = ""
  $certificateImportResult
  exit

} catch {

    Write-Host "exception thrown from curl"
    Write-Host "exception details  : "
    Write-Host $_.Exception.ToString()

  if( ($null -ne $_.Exception.Status -and $_.Exception.Status -eq 'TrustFailure') -or
      ($_.Exception -and
      $_.Exception.InnerException -and
      $_.Exception.InnerException.ErrorRecord -and
      $_.Exception.InnerException.ErrorRecord.Exception -and
      $_.Exception.InnerException.ErrorRecord.Exception.Status -eq 'TrustFailure')) {

        Write-Host "Gateway unable to validate NetworkController REST certificate"
        $attemptCertificateImport = $true
        Write-Host ""
        Write-Host $_.Exception.ToString()

  } else {

    Write-Host "Unknown exception. Failed to contact networkcontroller to exchange certificate information. Error Details:"
    Write-Host $_.Exception.ToString()

    Stop-Transcript | Out-Null

    $certificateImportResult.result = $certificateErrorUnknown
    $certificateImportResult.isCertificateNearExpiry = $false
    $certificateImportResult.isSuccess = $false
    $certificateImportResult.exceptionDetails = $_.Exception.ToString()
    $certificateImportResult
    exit
  }
}

if($attemptCertificateImport -eq $true) {

  Write-Host "Creating a request to $($ncUri)..."

  [byte[]] $certData = $null
  # trigger REST query
  try {
    $request = [System.Net.WebRequest]::Create($ncUri)
    $request.GetResponse();
  } catch {

    if($null -ne $request.ServicePoint.Certificate) {
      $certData = $request.ServicePoint.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    } else  {
      Write-Host "No certificate data found, nothing to import"
    }
  }

  # ignore and move on if no certificate data was found
  if($null -eq $certData) {
    Write-Host "Certificate not found in the request, exiting."

    $certificateImportResult.result = $certificateErrorUnknown
    $certificateImportResult.isCertificateNearExpiry = $false
    $certificateImportResult.isSuccess = $false
    $certificateImportResult.exceptionDetails = "No certificate data available"
    $certificateImportResult
    exit
  }
  #convert x509 cert into x509cert2
  $x509Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certData)
  # check expiration
  $certificateImportResult.isCertificateNearExpiry = (($x509Cert2.NotAfter - [datetime]::Now).Days -lt 30)
  #check if certificate is self vs CA signed, only self signed certificates will be automatically be added to trusted root
  foreach($dnsNameItem in $x509Cert2.DnsNameList) {
    $dnsName = $dnsNameItem.Punycode
    $issuerName = $x509Cert2.Issuer.ToString()
    $issuerName = $issuerName.SubString(3)
    Write-Host "Certificate compare: Issuer:$issuerName  DnsName: $dnsName"

    if( $issuerName -ieq $dnsName) {
        $isSelfSignedCertificate = $true
        break
    }
  }
  Write-Host "Certificate returned from networkcontroller $($x509Cert2.Subject) $($x509Cert2.Thumbprint) isselfsigned $isSelfSignedCertificate isnearingexpiry $($certificateImportResult.isCertificateNearExpiry)"
  Write-Host "IsCertificateSelfSigned $isSelfSignedCertificate"
  if($isSelfSignedCertificate -eq $true) {

    Write-Host "Self signed certificate detected, checking if import is required"
    $existingCerts = (gci Cert:\LocalMachine\Root | ?{$_.Thumbprint -eq $x509Cert2.Thumbprint})

    if ( $null -ne $existingCerts -and $existingCerts.Count -ge 1) {

      # the certificate was available but the original call failed, due to Trust failure, this is fatal and needs further investigation
      # thus we throw an exception here
      Write-Host "Certificate found with thumbprint $($x509Cert2.Thumbprint), skipping import."

      Stop-Transcript | Out-Null

      $certificateImportResult.result = $certificateErrorUnknown
      $certificateImportResult.isSuccess = $false
      $certificateImportResult.exceptionDetails = $_.Exception.ToString()
      $certificateImportResult.isCertificateImportRequired = $false
      $certificateImportResult
      exit
    }

    try {
      $filePathWithoutQuotes = $certificatePath.Replace("""","")
      Write-Host "--------"
      Write-Host $certificatePath
      Write-Host $filePathWithoutQuotes
      $filePath = Export-Certificate -Type CERT -FilePath $certificatePath -Cert $x509Cert2
    } catch {
      Write-Host "Certificate export failed. $($_.Exception.ToString())";

      $certificateImportResult.isCertificateImportRequired = $false
      $certificateImportResult.result = "Failed"
      $certificateImportResult.isSuccess = $false
      $certificateImportResult.exceptionDetails = "$($_.Exception.ToString())"
      $certificateImportResult
      exit
    }

    Write-Host "Certificate with thumbprint $($x509Cert2.Thumbprint)...exported"
    # this will cause wac to import certificate, import only if we need it & its not in the current store
    $certificateImportResult.isCertificateImportRequired = $true
    $certificateImportResult.result = ""
    $certificateImportResult.isSuccess = $true
    $certificateImportResult.exceptionDetails = ""
    $certificateImportResult
    exit

  } else {
      Write-Host "Certificate import skipped"
  }
} else {
    Write-host "Certificate import not required"
}
Write-Host "Sdn certificate validation/export completed"

Stop-Transcript | Out-Null

$certificateImportResult.result = ""
$certificateImportResult.isCertificateImportRequired = $false
$certificateImportResult.isSuccess = $true
$certificateImportResult.exceptionDetails = ""
$certificateImportResult

}
## [END] Get-NetworkControllerCertificate ##
function Get-NetworkControllerCluster {
<#

.SYNOPSIS
Gets the Network controller cluster information.

.DESCRIPTION
Gets the information for the Network controller cluster.

.ROLE
Readers

#>
Get-NetworkControllerCluster | ConvertTo-Json | ConvertFrom-Json
}
## [END] Get-NetworkControllerCluster ##
function Get-NetworkControllerGatewayExternalIPAddress {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the External IPAddress of Network Controller Gateway

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $gatewayName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualGateway = Get-NetworkControllerGateway -ResourceId $gatewayName @paramsHash

$externalIPAddress = $virtualGateway.Properties.ExternalIpAddress.IPAddress
$serverName = $virtualGateway.Properties.VirtualServer.ResourceRef.Split('/')[2]
$virtualServer = Get-NetworkControllerVirtualServer -ResourceId $serverName @paramsHash
$server = $virtualServer.Properties.Connections.ManagementAddresses.ToLower()

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'ExternalIPAddress' -Value $externalIPAddress -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'Server' -Value $server -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-NetworkControllerGatewayExternalIPAddress ##
function Get-NetworkControllerGatewayNames {
<#

.SYNOPSIS
Get the Network Controller Gateways

.DESCRIPTION
This script is used to Fetch the Names of Network Controller Gateways

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$gateways = Get-NetworkControllerGateway @paramsHash

foreach($gateway in $gateways)
{
    $name = $gateway.Properties.VirtualServer.ResourceRef.split('/')[2]
    $virtualServer = Get-NetworkControllerVirtualServer -ResourceId $name @paramsHash
    $gatewayName = $virtualServer.Properties.Connections.ManagementAddresses

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'GatewayName' -Value $gatewayName -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-NetworkControllerGatewayNames ##
function Get-NetworkControllerGatewayResources {
<#

.SYNOPSIS
Get the Network Controller Gateways

.DESCRIPTION
This script is used to Fetch the Network Controller Gateways

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
$restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$gateways = Get-NetworkControllerGateway @paramsHash

foreach($gateway in $gateways) {
  $gateway | ConvertTo-Json -Depth 10 | ConvertFrom-Json
}

}
## [END] Get-NetworkControllerGatewayResources ##
function Get-NetworkControllerHealthInfo {
<#

.SYNOPSIS
Gets the Network controllers health information.

.DESCRIPTION
Gets the health information of the network controller.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

# Get Network Controller Health Info
$ncnodes = Get-NetworkControllerNode
foreach($ncNode in $ncNodes) {
  $ncNode | ConvertTo-Json | ConvertFrom-Json
}


}
## [END] Get-NetworkControllerHealthInfo ##
function Get-NetworkControllerLoadBalancerMux {
<#

.SYNOPSIS
Get the Network Controller Load Balancer Muxes

.DESCRIPTION
This script is used to Fetch the Names of Network Controller Load Balancer Muxes

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$muxes = Get-NetworkControllerLoadBalancerMux @paramsHash

foreach($mux in $muxes)
{
    $name = $mux.Properties.VirtualServer.ResourceRef.split('/')[2]
    $virtualServer = Get-NetworkControllerVirtualServer -ResourceId $name @paramsHash
    $muxName = $virtualServer.Properties.Connections.ManagementAddresses
    $ipAddress = $mux.Properties.RouterConfiguration.PeerRouterConfigurations[0].LocalIPAddress

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'MuxName' -Value $muxName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-NetworkControllerLoadBalancerMux ##
function Get-NetworkControllerNcUriServers {
<#

.SYNOPSIS
Gets NetworkController Servers

.DESCRIPTION
Gets NetworkController Servers

.ROLE
Readers

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
Import-Module Microsoft.PowerShell.Utility

$servers = @(Get-NetworkControllerServer @paramsHash)
$servers | ConvertTo-Json -depth 100 | ConvertFrom-Json

}
## [END] Get-NetworkControllerNcUriServers ##
function Get-NetworkControllerServerCertificates {
<#

.SYNOPSIS
Gets the certificates for the Network Controller Servers & virtual Servers

.DESCRIPTION
Gets the certificates for the Network Controller Servers & virtual Servers

.ROLE
Administrators

#>

param(
  [String] $ncNodeName,
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Server Type
enum ServerTypeEnum {
    Mux = 0
    Host = 1
    NC_REST = 2
    NC_Node = 3
}

#Error Type
enum ErrorTypeEnum {
    NoError = 0
    MoreThanOneCertFound = 1
    NoCertFound = 2
}

function CreateReturnObject {
    param(
        [string] $serverName,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $certificate,
        [ServerTypeEnum] $serverType,
        [ErrorTypeEnum] $errorType
    )

    $returnedObject = New-Object -TypeName PSObject -Property @{
        CertificateSubject = $certificate.Subject
        CertificateSubjectName = $certificate.SubjectName.Name
        NotAfter = $certificate.NotAfter
        ServerName = $serverName
        ServerType = $serverType
        ErrorType = $errorType
    }
    $returnedObject
}

function FindNameManagementAddressFromList {
    param([array] $managementAddresses)

    foreach($managementAddress in $managementAddresses) {

        [ipaddress] $ip = $null
        if([ipaddress]::TryParse($managementAddress, [ref] [ipaddress] $ip) -eq $true) {
            continue;
        }
        $managementAddress
        break;
    }
}

function BuildCertificateInfoList {
  param(
    [string] $serverName,
    [ServerTypeEnum] $serverType,
    [Object[]] $outputResults,
    $certificates)


    if($null -eq $certificates) {

      # no certificate found
      $serverCertInfo = CreateReturnObject -serverName $serverName -certificate $null -serverType $serverType -errorType ([ErrorTypeEnum]::NoCertFound)

    }
    elseif( $certificates.Count -gt 1) {

        # more than 1 certificate found
        $serverCertInfo = CreateReturnObject -serverName $serverName -certificate $certificates[0] -serverType $serverType -errorType ([ErrorTypeEnum]::MoreThanOneCertFound)

    } else {

        # 1 certificate found
        $serverCertInfo = CreateReturnObject -serverName $serverName -certificate $certificates -serverType $serverType -errorType ([ErrorTypeEnum]::NoError)

    }
    $outputResults += $serverCertInfo
    $outputResults
}

Import-Module NetworkController

$servers = Get-NetworkControllerServer @paramsHash
$returnedResults = @()

if(-not [string]::IsNullOrEmpty($ncNodeName)) {
  $ncClusterTask = {
    Get-NetworkController -ComputerName $using:ncNodeName
    # ADD FCNC SUPPORT!
  }
  $ncNodesTask = {
    Get-NetworkControllerNode -ComputerName $using:ncNodeName
    # ADD FCNC SUPPORT!
  }
  $getNcClusterTask = Start-Job -ScriptBlock $ncClusterTask
  $getNcNodesTask = Start-Job -ScriptBlock $ncNodesTask
}


# PROCESS ALL V-SERVERS
try {
  $muxes = Get-NetworkControllerLoadBalancerMux @paramsHash
  foreach($mux in $muxes) {
      $tokens = $mux.Properties.VirtualServer.ResourceRef.Split("/")
      $muxServer = Get-NetworkControllerVirtualServer -ResourceId $tokens[2] @paramsHash
      $serverName = FindNameManagementAddressFromList -managementAddresses $muxServer.Properties.Connections.ManagementAddresses
      $certificates = icm -ComputerName $serverName -ScriptBlock {

          $muxCertificateName = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux'  -Name 'MuxCert'
          $muxCertificate = dir Cert:\LocalMachine\My | ?{ $_.Subject -like "*$muxCertificateName*"}
          $muxCertificate
      }
      $returnedResults = BuildCertificateInfoList -serverName $serverName -serverType ([ServerTypeEnum]::Mux) -outputResults $returnedResults -certificates $certificates
  }
}
catch {
    #supress any errors
    write-host $_
}

try {
  # PROCESS ALL SERVERS
  $hostservers = Get-NetworkControllerServer @paramsHash
  foreach($hostserver in $hostservers) {

      $serverName = FindNameManagementAddressFromList -managementAddresses $hostserver.Properties.Connections.ManagementAddresses
      $certificates = icm -ComputerName $serverName -ScriptBlock {

          $serverCertificateName = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\' -Name "HostAgentCertificateCName"
          $serverCertificate = dir Cert:\LocalMachine\My | ?{ $_.Subject -like "*$serverCertificateName*"} | where-object {$_.Issuer -ne "CN=AzureStackCertificationAuthority"}
          $serverCertificate
      }
      $returnedResults = BuildCertificateInfoList -serverName $serverName -serverType  ([ServerTypeEnum]::Host) -outputResults $returnedResults -certificates $certificates
  }
}
catch {
    #supress any errors
}

$returnedResults

if(-not [string]::IsNullOrEmpty($ncNodeName)) {

  # Check for tasks to complete
  while (-not $getNcClusterTask.HasMoreData) {
    Start-Sleep -Milliseconds 500
  }
  while (-not $getNcNodesTask.HasMoreData) {
    Start-Sleep -Milliseconds 500
  }
  # Retrieve the results
  $ncCluster = Receive-Job -Job $getNcClusterTask
  $ncNodes = Receive-Job -Job $getNcNodesTask

  if($null -ne $ncCluster -and $null -ne $ncCluster.ServerCertificate) {

    if([string]::IsNullorEmpty($ncCluster.RestName)) {
      $returnedResults = BuildCertificateInfoList -serverName $ncCluster.RestIPAddress `
                                                  -serverType ([ServerTypeEnum]::NC_REST)  `
                                                  -returnedResults $returnedResults `
                                                  -certificates $ncCluster.ServerCertificate
    } else {
      $returnedResults = BuildCertificateInfoList -serverName $ncCluster.RestName `
                                                  -serverType ([ServerTypeEnum]::NC_REST) `
                                                  -outputResults $returnedResults `
                                                  -certificates $ncCluster.ServerCertificate
    }
  }

  foreach($node in $ncNodes) {
    if($null -ne $node.NodeCertificate) {

      $returnedResults = BuildCertificateInfoList -serverName $node.Server `
                                                -serverType ([ServerTypeEnum]::NC_Node) `
                                                -outputResults $returnedResults `
                                                -certificates $certificates
    }
  }
}

$returnedResults

}
## [END] Get-NetworkControllerServerCertificates ##
function Get-NetworkControllerServerName {
<#

.SYNOPSIS
Get Network Controller Server Name

.DESCRIPTION
This script is used to fetch slb Manager Service Network Controller Server Name

.ROLE
Readers

#>




Connect-ServiceFabricCluster | Out-Null


$slbManagerServiceName = "fabric:/NetworkController/SlbManagerService"
$slbManagerServicePartitionId = (get-servicefabricpartition -ServiceName $slbManagerServiceName).PartitionId

$slbManagerServiceNCNodeName = (Get-ServiceFabricReplica -PartitionId $slbManagerServicePartitionId | where { $_.ReplicaRole -like "*Primary*" }).NodeName

$ncNodes = Get-NetworkControllerNode | convertto-json | ConvertFrom-Json


foreach($node in $ncNodes)
{
 if($node.Name -eq $slbManagerServiceNCNodeName)
 {

        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'NodeName' -Value  $node.Name -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ServerName' -Value  $node.Server.ToLower() -ErrorAction SilentlyContinue

        $myResponse
 }
}




}
## [END] Get-NetworkControllerServerName ##
function Get-NetworkControllerServers {
<#

.SYNOPSIS
Get NetworkController Servers

.DESCRIPTION
This Script is used to get the Network Controller Server Names where API Service, Firewall service, VSwitchService are running.

.ROLE
Readers

#>

Connect-ServiceFabricCluster | Out-Null
$nodeNames = @()

$apiServiceName = "fabric:/NetworkController/ApiService "
$apiServicePartitionId = (Get-ServiceFabricPartition -ServiceName $apiServiceName).PartitionId
$apiServiceNCNodeName = (Get-ServiceFabricReplica -PartitionId $apiServicePartitionId | where { $_.ReplicaRole -like "*Primary*" }).NodeName
$nodeNames += $apiServiceNCNodeName

$firewallServiceName = "fabric:/NetworkController/FirewallService"
$firewallServicePartitionId = (get-servicefabricpartition -ServiceName $firewallServiceName).PartitionId
$firewallServiceNCNodeName = (Get-ServiceFabricReplica -PartitionId $firewallServicePartitionId | where { $_.ReplicaRole -like "*Primary*" }).NodeName
$nodeNames += $firewallServiceNCNodeName

$vswitchServiceName = "fabric:/NetworkController/VSwitchService"
$vswitchServicePartitionId = (get-servicefabricpartition -ServiceName $vswitchServiceName).PartitionId
$vswitchServiceNCNodeName = (Get-ServiceFabricReplica -PartitionId $vswitchServicePartitionId | where { $_.ReplicaRole -like "*Primary*" }).NodeName
$nodeNames += $vswitchServiceNCNodeName

$nodeNames = $nodeNames | Microsoft.PowerShell.Utility\Select-Object -Unique

$ncNodes = Get-NetworkControllerNode | convertto-json | ConvertFrom-Json

foreach($nodeName in $nodeNames)
{
    foreach($ncNode in $ncNodes)
    {
        if($ncNode.Name -eq $nodeName)
        {
            $server = $ncNode.Server.ToLower()

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'Server' -Value $server -ErrorAction SilentlyContinue

            $myResponse
        }
    }
}

}
## [END] Get-NetworkControllerServers ##
function Get-NetworkInterfaceHostName {
<#

.SYNOPSIS
Get Network Interface HostName

.DESCRIPTION
This script is used to Get the HostName associated to the Network Interface

.ROLE
Readers

#>

param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $NetworkInterfaceName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddress,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$networkInterface = Get-NetworkControllerNetworkInterface -ResourceId $NetworkInterfaceName @paramsHash
if($null -ne $networkInterface.Properties.Server)
{
    $serverID = $networkInterface.Properties.Server.ResourceRef.Split('/')[2]
    $server = Get-NetworkControllerServer -ResourceId $serverID @paramsHash
    $hostName = $server.Properties.Connections.ManagementAddresses.ToLower()
}
else
{
    $hostName=''
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hostName -ErrorAction SilentlyContinue
$myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-NetworkInterfaceHostName ##
function Get-NetworkInterfacePrivateIPAddress {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the IPAddress of Network Interface which is associated to OutBound NAT Rules

.ROLE
Readers

#>


param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $loadBalancerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $frontEndIpConfigName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$frontendIpConfiguration = Get-NetworkControllerLoadBalancerFrontendIpConfiguration -LoadBalancerId $loadBalancerName -ResourceId $frontEndIpConfigName @paramsHash

$outboundNatRules = $frontendIpConfiguration.Properties.OutboundNatRules

foreach($outboundNatRule in $outboundNatRules)
{
    $outboundNatRuleName = $outboundNatRule.ResourceRef.Split('/')[4]

    $outboundNatRule = Get-NetworkControllerLoadBalancerOutboundNatRule -LoadBalancerId $loadBalancerName -ResourceId $outBoundNatRuleName @paramsHash
    $backendAddressPoolName = $outboundNatRule.Properties.BackendAddressPool.ResourceRef.Split('/')[4]

    $backendAddressPool = Get-NetworkControllerLoadBalancerBackendAddressPool -LoadBalancerId $loadBalancerName -ResourceId $backendAddressPoolName @paramsHash

    $backendIPConfigurations = $backendAddressPool.Properties.BackendIPConfigurations
    if($null -ne $backendIPConfigurations)
    {
        foreach($backendIPConfiguration in $backendIPConfigurations)
        {
            $networkInterfaceName = $backendIPConfiguration.ResourceRef.split('/')[2]
            $ipConfigurationName = $backendIPConfiguration.ResourceRef.Split('/')[4]

            $networkInterfaceIpConfiguration = Get-NetworkControllerNetworkInterfaceIpConfiguration -NetworkInterfaceId $networkInterfaceName -ResourceId $ipConfigurationName @paramsHash
            $ipAddress = $networkInterfaceIpConfiguration.Properties.PrivateIPAddress

            $myResponse = New-Object -TypeName psobject

            $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceName -ErrorAction SilentlyContinue
            $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue

            $myResponse
        }
    }
    else
    {
        $networkInterfaceName = ""
        $ipAddress = ""

        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'NetworkInterfaceName' -Value $networkInterfaceName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddress' -Value $ipAddress -ErrorAction SilentlyContinue

        $myResponse

    }
}



}
## [END] Get-NetworkInterfacePrivateIPAddress ##
function Get-OsInfo {
<#

.SYNOPSIS
Gets the OS Sku and Version

.DESCRIPTION
Gets the OS Sku and Version

.ROLE
Readers

#>

$UBR = 1 #Update Build revision, RTM version is 1 for 23H2 (ZN)
$UBRKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"
$cim = Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object OperatingSystemSKU, Version
$UBR = Get-ItemPropertyValue -Path $UBRKeyPath -Name UBR -ErrorAction SilentlyContinue
$windowsUpdatedVersion = New-Object System.Version ("{0}.{1}" -f $cim.Version, $UBR)

$result = New-Object -TypeName psobject
$result | Add-Member -MemberType NoteProperty -Name 'OperatingSystemSKU' -Value $cim.OperatingSystemSKU -ErrorAction SilentlyContinue
$result | Add-Member -MemberType NoteProperty -Name 'Version' -Value $windowsUpdatedVersion -ErrorAction SilentlyContinue
$result

}
## [END] Get-OsInfo ##
function Get-PacketDetails {
<#

.SYNOPSIS
get pktmon cature results

.DESCRIPTION
get pktmon cature results
if pathToLog is passed in just open and parse the file, otherwise stop capture and use the new log file

.ROLE
Readers

#>
Param(
    [Parameter(Mandatory = $true)]
    [string] $pktGroupId,
    [Parameter(Mandatory = $true)]
    [string] $pktNumber,
    [Parameter()]
    [string] $pathToLog
)
[xml]$logcontents = (Get-Content $pathToLog)
if (-not $pathToLog) {
    $pathToLog = [System.Environment]::SystemDirectory + "\Pktmon.xml"
}

$result = @{ }
$includeFields = @('IPSrc', 'PortSrc', 'IPDest', 'PortDest',
    'MACSrc', 'MACDest', 'Protocol', 'TCPFlags', 'EtherType', 'Filter',
    'PktGroupId', 'PktNumber', 'PktCount', 'DropReason', 'DropLocation',
    'Appearance', 'Component', 'Direction', 'Edge', 'OriginalSize', 'LoggedSize')
$specialFormatFields = @('DropReason', 'TCPFlags')
$currentRawPackets = New-Object System.Collections.ArrayList
$currentPacketId = $null

$pktGroupString = "PktGroupId " + $pktGroupId + ","

foreach($event in $logcontents.Events.Event)
{
    if($event.System.Provider.Name -eq "Microsoft-Windows-PktMon")
    {
        $msg = $event.RenderingInfo.Message
        if($msg -match $pktGroupString)
        {
            $events = $msg.split(',')
            $timestamp = $event.System.TimeCreated.SystemTime.split('.')[0]
            $properties = @{ }

            if ($events[0].Contains('Component')) {
                break;
            }

            if ($timestamp -and -not $properties.Timestamp) {
                $properties += @{'TimeStamp' = $timestamp }
            }

            $dropString = 'Drop:'
            $isDropped = $events[0].Contains($dropString)
            if ($isDropped) {
                $events[0] = $events[0] -replace $dropString
            }
            $properties += @{'Dropped' = $isDropped }

            foreach ($data in $events) {
                $trimmedData = $data.Trim()
                $splitData = $trimmedData.Split(' ')
                $label = ''
                $text = ''

                $firstWord = $splitData[0]
                if ($specialFormatFields.Contains($firstWord)) {
                    $label = $firstWord
                    if ($firstWord -eq 'DropReason') {
                        $text = $trimmedData -replace $firstWord + ' '
                    }
                    else {
                        for ( $j = 1; $j -lt $splitData.Length; $j++) {
                            $text += $splitData[$j]
                        }
                    }
                }
                else {
                    $text = $splitData[-1].Trim()
                    for ( $j = 0; $j -lt $splitData.Length - 1; $j++) {
                        $label += $splitData[$j]
                    }
                }

                if ($includeFields.Contains($label) -and $properties[$label] -eq $null -and $text -ne 0 -and $text -ne '0x0' -and $text -ne '0.0.0.0') {
                    $properties += @{$label = $text }
                }
            }

            $currentPacketId = $null
            $groupId = $properties.PktGroupId
            $packetNumber = $properties.PktNumber
            if (-not $packetNumber) {
                $packetNumber = $properties.PktCount
            }
            $appearance = $properties.Appearance
            $packetId = $groupId + '+' + $packetNumber + '+' + $appearance
            if ($packetNumber -eq $pktNumber) {
                $currentPacketId = $packetId
                if (!$result[$packetId]) {
                    $result += @{ $packetId = $properties }
                }
                else {
                    $properties.Keys | ForEach-Object {
                        if (-not $result[$packetId].ContainsKey($_)) {
                            $result[$packetId] += @{ $_ = $properties[$_] }
                        }
                    }
                }
            }
            else {
                $currentPacketId = $null
            }
            $currentRawPackets.Clear()
            if($event.EventData.Data.PSobject.Properties.value.Name -contains "Payload")
            {
                 $payload = $event.EventData.Data.GetEnumerator().Where({$_.Name -contains "Payload"})."`#text"
                 $currentRawPackets.Add($payload.Trim()) > $null


            }
            if ($currentRawPackets -and $currentRawPackets.Count -gt 0) {
                if ($currentPacketId -and -not $result[$currentPacketId].RawPacket) {
                    # process raw packet
                    $packetString = $currentRawPackets -join ' '
                    $result[$currentPacketId] += @{'RawPacket' = $packetString }
                    $currentPacketId = $null
                }
            }

        }
    }
}


$result.Keys | ForEach-Object {
    $eventObj = New-Object PSObject -Property $result[$_]
    $eventObj
}
}
## [END] Get-PacketDetails ##
function Get-PublicIpAddress {
<#

.SYNOPSIS
Get Public IP Address in the cluster

.DESCRIPTION
This script is used to Get the details of selected Public IP Addresses available in the cluster

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $publicIpAddressName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

try
{
    # Get Public IP Address in the cluster
    $publicIpAddress = Get-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName @paramsHash

    #Fetch Name
    $publicIPAddressName = $publicIpAddress.ResourceId

    #Fetch IP Address
    $ipAddress = $publicIpAddress.Properties.IpAddress

    #Fetch IP Address Type
    $ipAddressType = $publicIpAddress.Properties.PublicIPAddressVersion

    #Fetch IP Address Allocation Method
    $allocationMethod = $publicIpAddress.Properties.PublicIPAllocationMethod

    #Fetch the Provisioning State
    $provisioningState = $publicIpAddress.Properties.ProvisioningState

    #Fetch Idle Timeout In Minutes
    $idleTimeoutInMinutes = $publicIpAddress.Properties.IdleTimeoutInMinutes

    #Fetch the DNS Settings
    $dns = $publicIpAddress.Properties.DnsSettings
    if($null -eq $dns)
    {
        $dnsSettings = "None"
    }
    else
    {
        $dnsSettings = $dns
    }

    #Fetch the Ip Configuration
    $ipConfig = $publicIpAddress.Properties.IpConfiguration
    if($null -eq $ipConfig)
    {
        $ipConfiguration = "None"
    }
    else
    {
        $ipConfiguration = $ipConfig.ResourceRef.split('/')[4]
    }

    #Fetch the Previous IP Configuration
    $previousIpConfig = $publicIpAddress.Properties.PreviousIpConfiguration
    if($null -eq $previousIpConfig)
    {
        $previousIpConfiguration = "None"
    }
    else
    {
        $previousIpConfiguration = $previousIpConfig
    }

    # Preparing Object Response

    $myResponse = New-Object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $publicIPAddressName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddressType' -Value $ipAddressType -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'AllocationMethod' -Value $allocationMethod -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $idleTimeoutInMinutes -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'DnsSettings' -Value $dnsSettings -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfiguration' -Value $ipConfiguration -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'PreviousIpConfiguration' -Value $previousIpConfiguration -ErrorAction SilentlyContinue

    $myResponse
}
catch
{
    $myResponse = $error[0].Exception.InnerException.Message
    $myResponse
}

}
## [END] Get-PublicIpAddress ##
function Get-PublicIpAddresses {
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

try
{
    # Get Public IP Address in the cluster

    $publicIpAddresses = Get-NetworkControllerPublicIpAddress @paramsHash

    foreach($publicIpAddress in $publicIpAddresses)
    {
        #Fetch Name
        $publicIPAddressName = $publicIpAddress.ResourceId

        #Fetch IP Address
        $ipAddress = $publicIpAddress.Properties.IpAddress

        #Fetch IP Address Type
        $ipAddressType = $publicIpAddress.Properties.PublicIPAddressVersion

        #Fetch IP Address Allocation Method
        $allocationMethod = $publicIpAddress.Properties.PublicIPAllocationMethod

        #Fetch the Provisioning State
        $provisioningState = $publicIpAddress.Properties.ProvisioningState

        #Fetch Idle Timeout In Minutes
        $idleTimeoutInMinutes = $publicIpAddress.Properties.IdleTimeoutInMinutes

        #Fetch the DNS Settings
        $dns = $publicIpAddress.Properties.DnsSettings
        if($null -eq $dns)
        {
            $dnsSettings = "None"
        }
        else
        {
            $dnsSettings = $dns
        }

        #Fetch the Ip Configuration
        $ipConfig = $publicIpAddress.Properties.IpConfiguration
        if($null -eq $ipConfig)
        {
            $ipConfiguration = "None"
        }
        else
        {
            $ipConfiguration = $ipConfig
        }

        #Fetch the Previous IP Configuration
        $previousIpConfig = $publicIpAddress.Properties.PreviousIpConfiguration
        if($null -eq $previousIpConfig)
        {
            $previousIpConfiguration = "None"
        }
        else
        {
            $previousIpConfiguration = $previousIpConfig
        }

        # Preparing Object Response

        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $publicIPAddressName -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IPAddressType' -Value $ipAddressType -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'AllocationMethod' -Value $allocationMethod -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IdleTimeoutInMinutes' -Value $idleTimeoutInMinutes -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'DnsSettings' -Value $dnsSettings -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'IpConfiguration' -Value $ipConfiguration -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'PreviousIpConfiguration' -Value $previousIpConfiguration -ErrorAction SilentlyContinue

        $myResponse
    }
}
catch
{
    $myResponse = $error[0].Exception.InnerException.Message
    $myResponse
}

}
## [END] Get-PublicIpAddresses ##
function Get-ResolvedDnsName {
<#

.SYNOPSIS
Checks if the given REST name can be resolved.

.DESCRIPTION
Checks if the given REST name can be resolved to an IP address and checks that the IP address is not a cluster IP address.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string]$Name
)

Set-StrictMode -Version 5.0

$resolved = $null
$resolved = Resolve-DnsName -Name $Name -ErrorAction SilentlyContinue
if ($null -ne $resolved) {
  ($resolved | Select-Object -Property IPAddress).IPAddress
} else {
  $resolved
}

}
## [END] Get-ResolvedDnsName ##
function Get-SDNConfigurationEvents {
<#

.SYNOPSIS
Get events for SDN configuration on this server.

.DESCRIPTION
Get SDN events from the following logs on this server:
    'WindowsAdminCenter'
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$operationId
)
Set-StrictMode -Version 5.0

Microsoft.PowerShell.Diagnostics\get-winevent -FilterHashtable @{ LogName= `
    'WindowsAdminCenter';`
    StartTime=((Get-Date).AddDays(-1))} `
     -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object Id, TimeCreated, LogName, Level, Message, MachineName, ProviderName | `
        Where-Object {$_.Message -match $operationId -and $_.ProviderName -eq 'SmeHciScripts-SDN'}


}
## [END] Get-SDNConfigurationEvents ##
function Get-SLBEssentialInfo {
<#

.SYNOPSIS
Gets the software load balancer health and essential information.

.DESCRIPTION
Gets the essential information of the software load balancer.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

try {
  Get-NetworkControllerLoadBalancerConfiguration @paramsHash | ConvertTo-Json -Depth 5 | ConvertFrom-Json
}
catch {
  #SLB is not configured
  New-Object PSObject
}

}
## [END] Get-SLBEssentialInfo ##
function Get-SLBHostAgentState {
<#

.SYNOPSIS
Gets the host agent status state for the software load balancer.

.DESCRIPTION
Gets the host agent status state for the software load balancer.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

# Get SLB Host Agent State Info
$servers = (Get-NetworkControllerServer @paramsHash | convertto-json -depth 10 | ConvertFrom-Json)
foreach($server in $servers) {
  $server
}

}
## [END] Get-SLBHostAgentState ##
function Get-SLBMultiplexer {
<#

.SYNOPSIS
Gets the software load balancer multiplexer information.

.DESCRIPTION
Gets the information for the software load balancer multiplexer.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String[]]
    $MUXName
)

Set-StrictMode -Version 5.0;
Import-Module Hyper-V -ErrorAction SilentlyContinue;

Foreach ($myMux in $MUXName)
{
    $res=get-vm | Where {$_.name -contains $myMux.ToLower()}
    
    if($res)
    {
        $Result = New-Object -TypeName psobject

        $NCName=($res.Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
        $CPU=$res.CPUUsage
        $MemoryDemand=$res.MemoryDemand
        $MemoryAssigned=$res.MemoryAssigned
        $Memory=[math]::Round((($MemoryDemand/$MemoryAssigned)*100))
       
        $Storage=0
        $vhdPaths = (Get-VHD -VMId $res.Id).Path
        $fileSize=0
        $totalSize=0
        foreach ($vhdPath in $vhdPaths) {
           $VHDAttached=Get-VHD -Path $vhdPath
           $fileSize+=$VHDAttached.FileSize
           $totalSize+=$VHDAttached.Size
        }
        if($fileSize -gt 0)
        {
            $Storage=[math]::Round((($fileSize/$totalSize)*100))
        }

        [String]$NetworkStatus=$res.NetworkAdapters[0].Status
        $NetworkStatus=$NetworkStatus.ToUpper()
        [String]$Uptime=$res.Uptime
        if($Uptime.split('.').count -gt 2)
        {
           [String]$NewUptime=(($Uptime.split(".")[0])+" days, "+($Uptime.split(".")[1].split(":")[0])+" hours, "+($Uptime.split(".")[1].split(":")[1])+" minutes, "+($Uptime.split(".")[1].split(":")[2])+" seconds")
        }
        else
        {
           [String]$NewUptime=(("0 day, "+($Uptime.split(":")[0])+" hours, "+($Uptime.split(":")[1])+" minutes, "+($Uptime.split(":")[2].split(".")[0])+" seconds"))
        }
        $HostName=((Get-CIMInstance CIM_ComputerSystem).Name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain).ToLower()
        [String]$VMStatus=$res.State
        $NCNodeStatus=$NetworkStatus
        [String]$Heartbeat=$res.Heartbeat
        # Result for  Getting SLB Multiplexer
        $Result | Add-Member -MemberType NoteProperty -Name 'Name' -Value $NCName -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'CPU' -Value $CPU -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $Memory -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Storage' -Value $Storage -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'NetworkStatus' -Value $NetworkStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Uptime' -Value $NewUptime -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Host' -Value $HostName -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'VMStatus' -Value $VMStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'NCNodeStatus' -Value $NCNodeStatus -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Heartbeat' -Value $Heartbeat -ErrorAction SilentlyContinue
          $Result | Add-Member -MemberType NoteProperty -Name 'VMId' -Value $res.Id -ErrorAction SilentlyContinue
        $Result
    }
    
}

}
## [END] Get-SLBMultiplexer ##
function Get-SLBPublicPrivateNetworks {
<#

.SYNOPSIS
Gets the software load balancer public and private networks.

.DESCRIPTION
Gets the public and private networks for the software load balancer.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

try {
  $nwlbconfiguration = Get-NetworkControllerLoadBalancerConfiguration @paramsHash
  $vippools = $nwlbconfiguration.Properties.VipIpPools.ResourceRef
}
catch {
  # SLB is not configured
  $vippools = @()
}

$hs = New-Object 'System.Collections.Generic.HashSet[string]'
$Result = @()

foreach ($resourceid in $vippools)
{
    $logicalnw = $resourceid.split("/")[2]
    $bools = $hs.add($logicalnw)
}
foreach ($logicalnw in $hs)
{
    $nclogicalnws = get-networkcontrollerlogicalnetwork -ResourceId $logicalnw @paramsHash
    foreach ($subnet in $nclogicalnws.Properties.Subnets) {
        $Result += new-object -TypeName psobject
        $Result | Add-Member -MemberType NoteProperty -Name 'Name' -Value $subnet.ResourceRef -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'IsPublic' -Value $subnet.Properties.IsPublic -ErrorAction SilentlyContinue
        $Result | Add-Member -MemberType NoteProperty -Name 'Usage' -Value $subnet.Properties.Usage -ErrorAction SilentlyContinue
    }
}
# Result to get SLB Public Private Network
$Result


}
## [END] Get-SLBPublicPrivateNetworks ##
function Get-ServerInfo {
<#

.SYNOPSIS
Gets the health information for the host.

.DESCRIPTION
Gets the health information for the host.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0
Import-Module Hyper-V -ErrorAction SilentlyContinue

$servers = Get-NetworkControllerServer @paramsHash
foreach($server in $servers) {
  $server | ConvertTo-Json -Depth 5 | ConvertFrom-Json
}

}
## [END] Get-ServerInfo ##
function Get-SourceVMServerName {
<#

.SYNOPSIS
Get the HostName

.DESCRIPTION
This script is used to Fetch the HostName of Source VM

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddress,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$networkInterfaces = Get-NetworkControllerNetworkInterface @paramsHash

foreach($networkInterface in $networkInterfaces)
{
    $privateIPAddress = $networkInterface.Properties.ipConfigurations.Properties.privateIPAddress

    if($privateIPAddress -eq $ipAddress)
    {
        $serverName = $networkInterface.Properties.Server
        if($null -ne $serverName)
        {
            $serverID = $serverName.ResourceRef.Split('/')[2]
            $networkControllerServer = Get-NetworkControllerServer -ResourceId $serverID @paramsHash
            $server = $networkControllerServer.Properties.Connections.ManagementAddresses.ToLower()
        }
        else {
            $server = ""
        }
        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'Server' -Value $server -ErrorAction SilentlyContinue

        $myResponse
        break;
    }
}

}
## [END] Get-SourceVMServerName ##
function Get-VMGuid {
<#

.SYNOPSIS
Get IP Address

.DESCRIPTION
This script is used to Get the VMGuid of the VM

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vmName,

    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$virtualServer = Get-NetworkControllerVirtualServer -ResourceId $vmName @paramsHash
$vmGuid = $virtualServer.Properties.VMGuid

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'VMGuid' -Value $vmGuid -ErrorAction SilentlyContinue

$myResponse

}
## [END] Get-VMGuid ##
function Get-VMNames {
<#

.SYNOPSIS
Get Virtual Machine Names

.DESCRIPTION
This Script is used to get the Virtual machines Names

.ROLE
Readers

#>

param(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

$servers = @()
$ipAddress = @()
$ips = @()
$type = @()

$loadbalancermuxs = Get-NetworkControllerLoadBalancerMux @paramsHash
foreach($loadbalancermux in $loadbalancermuxs)
{
    $ipAddress += $loadbalancermux.Properties.RouterConfiguration.PeerRouterConfigurations.LocalIPAddress
    $ips += $loadbalancermux.Properties.RouterConfiguration.PeerRouterConfigurations.RouterIPAddress
    $servers +=  $loadbalancermux.ResourceRef.Split('/')[2]
    $type += "Mux VM"
}

$gateways = Get-NetworkControllerGateway @paramsHash
foreach($gateway in $gateways)
{
    $status = $gateway.Properties.ConfigurationState.Status
    if($status -eq "Success")
    {
        $ipAddress += $gateway.Properties.ExternalIPAddress.IPAddress
        $ips += $gateway.Properties.BgpConfig.BgpPeer.PeerIP
        $servers += $gateway.Properties.VirtualServer.ResourceRef.Split('/')[2]
        $type += "Gateway VM"

        break
    }
}

for($i=0; $i -lt $ipAddress.length; $i++)
{
    $virtualserver = Get-NetworkControllerVirtualServer -ResourceId $servers[$i] @paramsHash
    $vmName= $virtualserver.Properties.Connections.ManagementAddresses

    $myResponse = new-object -TypeName psobject

    $myResponse | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $ipAddress[$i] -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'IP' -Value $ips[$i] -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'VMName' -Value $vmName -ErrorAction SilentlyContinue
    $myResponse | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type[$i] -ErrorAction SilentlyContinue

    $myResponse
}

}
## [END] Get-VMNames ##
function Get-VMSwitches {
<#

.SYNOPSIS
Get Virtual Machine Switches

.DESCRIPTION
This Script is used to get the available virtual machine switches

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$result = @()

try {
    $result = Get-VMSwitch | Microsoft.PowerShell.Utility\Select-Object Name
    if ($null -eq $result) {
        # Make empty array to ensure we return something valid
        $result = @()
    }
}
catch {
    # No VMSwitches were found
}

$result

}
## [END] Get-VMSwitches ##
function Get-VirtualIPPoolHealthInfo {
<#

.SYNOPSIS
Gets the virtual IP pool health information.

.DESCRIPTION
Gets the virtual IP pool health information.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Set-StrictMode -Version 5.0

$Result=@()
try {
  $resConfig = Get-NetworkControllerLoadBalancerConfiguration @paramsHash
} catch {
  # SLB is not configured
  $resConfig = $null
}
if ($null -ne $resConfig -and $null -ne $resConfig.Properties.VipIpPools)
{
    foreach($vipIpPool in $resConfig.Properties.VipIpPools)
    {
        $logicalNetworkId= $vipIpPool.ResourceRef.split("/")[2]
        $subnetId = $vipIpPool.ResourceRef.split("/")[4]
        $res= Get-NetworkControllerIpPool -NetworkId $logicalNetworkId -SubnetId $subnetId @paramsHash
        if ($null -ne $res)
        {
            $resourceId = $res.ResourceId
            $provisioningState = $res.Properties.ProvisioningState

            # Result to get Virtual Pool
            $Result += New-Object -TypeName psobject
            $Result | Add-Member -MemberType NoteProperty -Name 'ProvisioningState' -Value $provisioningState -ErrorAction SilentlyContinue
            $Result | Add-Member -MemberType NoteProperty -Name 'ResourceId' -Value $resourceId -ErrorAction SilentlyContinue
        }
    }
}

$Result

}
## [END] Get-VirtualIPPoolHealthInfo ##
function Import-NetworkControllerCertificate {
<#
.SYNOPSIS
Imports SDN rest certificate on the gateway node

.DESCRIPTION
Import certificates on the gateway node, and deletes the certificate if completed successfully.
throws exception if failed

.ROLE
Readers
#>
param
(
    [Parameter(Mandatory = $false)]
    [String] $certificatePath
)

[string] $CERTIFICATE_NOT_FOUND = "CertificateNotFoundException"
[string] $CERTIFICATE_IMPORT_FAILED = "CertificateImportFailedException"

$certificateImportResult = @{
  result = ""
  isCertificateNearExpiry = $false
  isSuccess = $false
  exceptionDetails = ""
  isCertificateImportRequired = $false
}

Start-Transcript -Path "sdn-wac-validation-cert.log" -Append -IncludeInvocationHeader -Confirm:$false -Force | Out-Null

if([string]::IsNullOrEmpty($certificatePath) -eq $true) {
  $certificatePath = "$Env:Temp\NetworkControllerCertificate.cer"
}

Write-Host "begin import of SDN rest certificate from path $certificatePath"

try {

  if( (Test-Path -Path $certificatePath ) -eq $false) {
    Write-Host "Unable to find certificate"

    $certificateImportResult.isSuccess = $false
    $certificateImportResult.result = $CERTIFICATE_NOT_FOUND
    $certificateImportResult.isSuccess = $false
    $certificateImportResult
    exit
  }

  Write-Host "Reading certificate information"
  $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
  $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
  $base64Thumbprint = [System.Convert]::ToBase64String($cert.GetCertHash())
  Write-Host "Certificate thumbrint $base64Thumbprint"

  if( ($cert.NotAfter - [datetime]::Now).Days -lt 30 ) {
    Write-Host "certificate nearing expiry"
    $certificateImportResult.isCertificateNearExpiry = $true
  }

  $certificate = Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\Root\"
  Write-Host "certificate imported"
  $certificateImportResult.isSuccess = $true
  $certificateImportResult.result = ""
  $certificateImportResult.isCertificateImportRequired = $false

  Write-Host "removing certificate"
  Remove-Item -Path $certificatePath
  Write-Host "removing certificate successful"

} catch {

  Write-Host "Failed to import certificate"
  $certificateImportResult.isSuccess = $false
  $certificateImportResult.exceptionDetails = $_.Exception.ToString()
  $certificateImportResult.result = $CERTIFICATE_IMPORT_FAILED
}

Stop-Transcript | Out-Null
$certificateImportResult

}
## [END] Import-NetworkControllerCertificate ##
function Import-NetworkControllerRestCertificate {
<#

.SYNOPSIS
Import networkcontroller REST certificate

.DESCRIPTION
Imports networkcontroller REST certificate on the WAC gateway

.ROLE
Readers

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $ncUri
)
#Import Network Controller Module
Import-Module NetworkController -Force

Try
{

  [byte[]] $certData
  # trigger REST query
  try {
    $request = [System.Net.WebRequest]::Create($ncUri)
    $request.GetResponse();
    Write-Host "Creating a request to $($ncUri)..."
  } catch {
    $certData = $request.ServicePoint.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  }

  if($null -eq $certData) {
    # ignore and move on if no certificate data was found
    Write-Host "Certificate not found in the request, exiting."
    return
  }

  #convert x509 cert into x509cert2
  $x509Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certData)
  $existingCerts = (gci Cert:\LocalMachine\Root | ?{$_.Thumbprint -eq $x509Cert2.Thumbprint})
  if ( $null -ne $existingCerts -and $existingCerts.Count -ge 1) {
    #a cert was found, bail out
    Write-Host "Certificate found with thumbprint $($x509Cert2.Thumbprint), skipping import."
    return
  }

  Write-Host "Importing certificate with thumbprint $($x509Cert2.Thumbprint)..."
  # check if this certificate is valid or not
  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
  $store.Add($x509Cert2)
  $store.Close();
  $store.Dispose();

  Write-Host "Certificate with thumbprint $($x509Cert2.Thumbprint)...included"
  #import completed successfully
}
Catch
{
  Write-Host $_
  Write-Host $_.Exception
  throw $_
}

}
## [END] Import-NetworkControllerRestCertificate ##
function Install-WindowsFeatures {
<#

.SYNOPSIS
Installs the required features provided

.DESCRIPTION
Installs the Windows features provided and returns the feature result

.PARAMETER features
The windows features to install

.ROLE
Readers

#>
param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String[]] $features
)

Set-StrictMode -Version 5.0

Install-WindowsFeature -Name $features -IncludeManagementTools -IncludeAllSubFeature

}
## [END] Install-WindowsFeatures ##
function New-PublicIpAddress {
<#

.SYNOPSIS
Create a New Public IP Address in the cluster

.DESCRIPTION
This script is used to Create New Public IP Addresses in the cluster

.ROLE
Administrators

#>

param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIpAddressName,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIpAddressVersion,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIPAllocationMethod,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $idleTimeoutInMinutes,

  [Parameter(Mandatory = $false)]
  [String] $ipAddress,

  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

#Import Network Controller Module
Import-Module NetworkController -Force

# Create a New object for Public Ip Address Properties
$publicIPProperties = New-Object Microsoft.Windows.NetworkController.PublicIpAddressProperties

$publicIPProperties.PublicIPAddressVersion = $publicIpAddressVersion
$publicIPProperties.PublicIPAllocationMethod = $publicIPAllocationMethod
$publicIPProperties.IdleTimeoutInMinutes = $idleTimeoutInMinutes

if ($publicIPAllocationMethod.ToLower() -eq "static") {
  $publicIPProperties.IPAddress = $ipAddress
}

# Create a New Public IP Address
$result = New-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName -Properties $publicIPProperties @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName Psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

}
## [END] New-PublicIpAddress ##
function New-SDNExpressLite {
<#

.SYNOPSIS
Set up SDN

.DESCRIPTION
Set up SDN

.ROLE
Administrators

.PARAMETER OperationType
The type of operation to perform

.PARAMETER OperationID
The operation ID for this SDN deployment used for logging

.PARAMETER UseFCNC
Whether to deploy FC NC or SF NC

.PARAMETER FCNCDBs
The path to the FC NC database files

.PARAMETER NCUsername
The network controller username (domain\user format)

.PARAMETER NCPassword
The network controller password

.PARAMETER LocalAdminPassword
The local administrator password

.PARAMETER VMLocation
The path to the VMs folder

.PARAMETER VHDSrcPath
The path to the VHD folder

.PARAMETER VHDName
The file name of the VHD

.PARAMETER isDHCP
True if DHCP configuration, false if static configuration

.PARAMETER ManagementSubnet
The management subnet in format 10.10.10.0\24

.PARAMETER ManagementGateway
The gateway IP for management

.PARAMETER ManagementVLANID
The VLAN ID for management

.PARAMETER ManagementDNS
Array of DNS IPs to use for management

.PARAMETER JoinDomain
The domain to join

.PARAMETER RestName
The cluster name

.PARAMETER RestIPAddress
The cluster rest IP address

.PARAMETER MacPoolStart
The MAC pool starting address (XX-XX-XX-XX-XX-XX format)

.PARAMETER MacPoolEnd
The MAC pool ending address (XX-XX-XX-XX-XX-XX format)

.PARAMETER SwitchName
The name of the compute or converges switch to use

.PARAMETER ProductKey
The product key for the type of deployment to use for VHD config

.PARAMETER OUPath
The OU Path of the VMs

.PARAMETER HyperVHosts
The list of server names used as hyper-v hosts

.PARAMETER NCs
The list of network controller objects in the format:
    $ComputerName = "Host01" #Assigned round-robin from HyperVHosts list
    $VMName       = "NC01"
    $MacAddress    = "00-11-22-00-00-01" #Can use mac address from mac pool, but adjust mac pool to not include this address
    $IPAddress     = "10.0.0.20"

.PARAMETER CertificateThumbprint
Optional client certificate thumbprint necessary for deploying MUX or Gateways if client authentication is enabled

#>

param (
    [Parameter(Mandatory = $true)]
    [int]$OperationType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OperationID,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$NCUsername,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$NCPassword,
    [Parameter(Mandatory = $false)]
    [bool]$isDHCP,
    [Parameter(Mandatory = $true)]
    [string]$SwitchName,
    [Parameter(Mandatory = $false)]
    [string]$RestName,
    [Parameter(Mandatory = $false)]
    [int]$ManagementVLANID,
    [Parameter(Mandatory = $false)]
    [string]$ManagementSubnet,
    [Parameter(Mandatory = $false)]
    [string]$ManagementGateway,
    [Parameter(Mandatory = $false)]
    [string[]]$ManagementDNS,
    [Parameter(Mandatory = $false)]
    [string]$VMLocation,
    [Parameter(Mandatory = $false)]
    [string]$VHDSrcPath,
    [Parameter(Mandatory = $false)]
    [string]$VHDName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$JoinDomain,
    [Parameter(Mandatory = $true)]
    [AllowNull()]
    [PSObject[]]$NCs,
    [Parameter(Mandatory = $true)]
    [AllowNull()]
    [PSObject[]]$Muxes,
    [Parameter(Mandatory = $true)]
    [AllowNull()]
    [PSOBject[]]$Gateways,
    [Parameter(Mandatory = $false)]
    [string]$ProductKey,
    [Parameter(Mandatory = $false)]
    [string]$OUPath,
    [Parameter(Mandatory = $false)]
    [String]$LocalAdminPassword,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$HyperVHosts,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [bool]$UseFCNC,
    [Parameter(Mandatory = $false)]
    [string]$FCNCDBs,
    [Parameter(Mandatory = $false)]
    [string]$RestIPAddress,
    [Parameter(Mandatory = $false)]
    [string]$ClusterNetworkName,
    [Parameter(Mandatory = $false)]
    [string]$MacPoolStart,
    [Parameter(Mandatory = $false)]
    [string]$MacPoolEnd,
    [Parameter(Mandatory = $false)]
    [string]$PAVLANID,
    [Parameter(Mandatory = $false)]
    [string]$PASubnet,
    [Parameter(Mandatory = $false)]
    [string]$PAGateway,
    [Parameter(Mandatory = $false)]
    [string]$PublicVIPSubnet,
    [Parameter(Mandatory = $false)]
    [string]$PrivateVIPSubnet,
    [Parameter(Mandatory = $true)]
    [AllowNull()]
    [PSObject[]]$Routers,
    [Parameter(Mandatory = $false)]
    [string]$SDNASN,
    [Parameter(Mandatory = $false)]
    [int]$RedundantCount,
    [Parameter(Mandatory = $false)]
    [string]$GreSubnet,
    [Parameter(Mandatory = $false)]
    [int]$GatewayCapacity,
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

function Write-LogProgress {
  param([String] $OperationId, [String] $Source, [String] $Context, [Int] $Percent)
  $message = "$OperationId;PROGRESS;$Source;$Context;$Percent;"
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information -Message $message -ErrorAction SilentlyContinue
}
function Write-LogInfo {
  param([String] $OperationId, [String] $Message)
  $message = "$OperationId;INFO;$message;"
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $InfoLogSource -EventId 0 -Category 0 -EntryType Information -Message $message -ErrorAction SilentlyContinue
  Write-Host $message
}

function Write-LogStageComplete($stageCode, $logMessage) {
  $infoLog = "$operationId;COMPLETE;$stageCode;$logMessage;"
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
      -Message $infoLog  -ErrorAction SilentlyContinue
}

function Write-LogStageStarted($stageCode, $logMessage) {
  $infoLog = "$operationId;STARTED;$stageCode;$logMessage;"
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
      -Message $infoLog  -ErrorAction SilentlyContinue
}
function Write-LogUncaughtError($StageCode, $ErrorMessage) {
  $infoLog = "$operationId;UNCAUGHTERROR;$StageCode;$ErrorMessage;"
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
      -Message $infoLog  -ErrorAction SilentlyContinue
}

function Install-RequiredModulesAndFeatures {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [bool]$UseFCNC,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$HyperVHosts,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PsCredential]$Credential
  )

    Install-PackageProvider -Name NuGet -MinimumVersion "2.8.5.201" -Force
    Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck

    Write-Host "Checking SDN express"
    $module = $null
    $props = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\SdnInstall\ -ErrorAction SilentlyContinue -Verbose
    if ($null -ne $props -and $null -ne $props.SdnExpressPath) {
      $modulePath = Join-Path ($props.SdnExpressPath) -ChildPath "SdnExpress.psm1" -Verbose
      Write-Host "Custom SDN express located at $($modulePath)"
      Import-Module -Name $modulePath
      Write-Host "Module loaded"
    } else {
      Install-Module -Name SdnExpress -Confirm:$false -Force -Verbose
      Import-Module -Name SdnExpress
      $module = Get-Module -Name SdnExpress -ErrorAction SilentlyContinue
      Import-Module "$($module.ModuleBase)\Sdnexpress.psm1" -Force
    }
    Install-SdnWindowsFeatures -hyperVHosts $HyperVHosts -credential $Credential -isFCNC $UseFCNC
    # load the file directly so that we can use the functions in the script
    Import-Module NetworkController
    Import-Module NetworkControllerFc
}

function Deploy-NetworkController {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OperationID,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PsCredential]$Credential,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$HyperVHosts,
    [Parameter(Mandatory = $true)]
    [string]$SwitchName,
    [Parameter(Mandatory = $true)]
    [string]$MacPoolStart,
    [Parameter(Mandatory = $true)]
    [string]$MacPoolEnd,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [bool]$UseFCNC,
    [Parameter(Mandatory = $true, ParameterSetName = "FC")]
    [ValidateNotNullOrEmpty()]
    [string]$FCNCDBs,
    [Parameter(Mandatory = $false, ParameterSetName = "FC")]
    [string]$ClusterNetworkName,
    [Parameter(Mandatory = $true, ParameterSetName = "FC")]
    [string]$RestIPAddress,
    [Parameter(Mandatory = $false, ParameterSetName = "FC")]
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [string]$RestName,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [bool]$isDHCP,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [int]$ManagementVLANID,
    [Parameter(Mandatory = $false, ParameterSetName = "SF")]
    [Parameter(Mandatory = $false, ParameterSetName = "Static")]
    [string]$VMLocation,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [string]$VHDSrcPath,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [string]$VHDName,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$JoinDomain,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [PSObject[]]$NCs,
    [Parameter(Mandatory = $false, ParameterSetName = "SF")]
    [Parameter(Mandatory = $false, ParameterSetName = "Static")]
    [string]$ProductKey,
    [Parameter(Mandatory = $false, ParameterSetName = "SF")]
    [Parameter(Mandatory = $false, ParameterSetName = "Static")]
    [string]$OUPath,
    [Parameter(Mandatory = $true, ParameterSetName = "SF")]
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [SecureString]$LocalAdminSecurePassword,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementSubnet,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementGateway,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string[]]$ManagementDNS,
    [string]$hciDeploymentUser
  )

    $Global:Stage = 1
    $CredentialParam = @{ Credential = $Credential }

    # todo: hook up to the UI later on , for now just move to using subject name
    $useCertBySubject = $false

    if ($UseFCNC -eq $false) {
      Write-LogStageStarted 1 "Creating VMs"
      if ($isDHCP -eq $false) {
          $ManagementSubnetBits = $ManagementSubnet.Split("/")[1]
      }

      # disable vfp on all switches on all hosts, otherwise deployment will fail
      invoke-command -ComputerName $HyperVHosts @CredentialParam {
          $switches = Get-VMSwitch
          if ($null -ne $switches) {
              $switchNames = (Get-VMSwitch).Name
              Disable-VMSwitchExtension -VMSwitchName $switchNames -Name "Microsoft Azure VFP Switch Extension" | out-null
          }
      }
      write-sdnexpresslog "Disabled VFP on all switches."
      $params = @{
          'ComputerName'       = '';
          'VMLocation'         = $VMLocation;
          'VMName'             = '';
          'VHDSrcPath'         = $VHDSrcPath;
          'VHDName'            = $VHDName;
          'VMMemory'           = 8GB;
          'VMProcessorCount'   = 8;
          'Nics'               = @();
          'Credential'         = $Credential;
          'JoinDomain'         = $JoinDomain;
          'LocalAdminPassword' = $LocalAdminSecurePassword;
          'SwitchName'         = $SwitchName;
          'OperationID'        = $OperationID;
      }

      if (-not [String]::IsNullOrWhiteSpace($ProductKey)) {
          $params.ProductKey = $ProductKey
      }
      if (-not [String]::IsNullOrWhiteSpace($OUPath)) {
          $params.OUPath = $OUPath
      }

      if (-not [String]::IsNullOrEmpty($hciDeploymentUser)) {
          $params.DomainAdminsToAdd = @("$JoinDomain\$hciDeploymentUser")
      }

      $NCNodes = @()
      $NCNodesFQDN = @()

      foreach ($NC in $NCs) {
          $params.ComputerName = $NC.ComputerName;
          $params.VMName = $NC.VMName;
          Write-LogInfo $OperationID "VM: $($NC.VMName)"
          if ($isDHCP -eq $true) {
              $params.Nics = @(
                  @{Name = "Management"; MacAddress = $NC.MacAddress; VLANID = $ManagementVLANID }
              );
              Write-LogInfo $OperationID "DHCP Nic Mac:  $($NC.MacAddress)"
              Write-LogInfo $OperationID "DHCP Nic VLAN: $($ManagementVLANID)"
          }
          else {
              $params.Nics = @(
                  @{Name = "Management"; MacAddress = $NC.MacAddress; IPAddress = "$($NC.IPAddress)/$ManagementSubnetBits"; Gateway = $ManagementGateway; DNS = $ManagementDNS; VLANID = $ManagementVLANID }
              );
              Write-LogInfo $OperationID "Static Nic MacAddress: $($NC.MacAddress)"
              Write-LogInfo $OperationID "Static Nic IpAddress: $($NC.IPAddress)/$ManagementSubnetBits"
              Write-LogInfo $OperationID "Static Nic Gateway: $($ManagementGateway)"
              Write-LogInfo $OperationID "Static Nic DNS: $($ManagementDNS)"
              Write-LogInfo $OperationID "Static Nic VLAN: $($ManagementVLANID)"
          }
          $params.Roles = @("NetworkController", "NetworkControllerTools")

          $params.EnablePreDeploymentNetworkConnectionCheck = $true
          $params.DisableIPv6DHCP = $true
          $params.EnableProcessorCompatibilityForLiveMigration = $true

          New-SDNExpressVM @params

          $NCNodesFQDN += "$($NC.VMName).$JoinDomain"
          $NCNodes += $NC.VMName
      }
      WaitforComputerToBeReady -ComputerName $NCNodesFQDN -CheckPendingReboot $false @CredentialParam
      Write-LogStageComplete 1 "Successfully created NC VMs"
    } else {
      Write-LogStageComplete 1 "Skipping VM creation for FC NC"
    }

    Write-LogStageStarted 2 "Configuring Network Controller"
    $Global:Stage = 2

    if ($UseFCNC -eq $true) {
      $NCNodes = $HyperVHosts
      if ([string]::IsNullOrEmpty($RestName)) {
        $RestName = $RestIPAddress.Split("/")[0]
      }
    }
    $params = @{
      'Credential'    = $Credential
      'RestName'      = $RestName
      'ComputerNames' = $NCNodes
      'OperationID'   = $OperationID
      'CertificatePassword' = $Credential.Password
    }
    if (-not [string]::IsNullOrEmpty($RestIPAddress)) {
      $params += @{
        'RestIpAddress' = $RestIPAddress
      }
    }
    Write-LogInfo $OperationID "ComputerNames: $NCNodes"
    Write-LogInfo $OperationID "RestName: $RestName"
    Write-LogInfo $OperationID "RestIpAddress: $RestIPAddress"
    if ($UseFCNC -eq $true) {
      $params += @{
        'FCNCBins' = "C:\Windows\NetworkController"
        'FCNCDBs' = $FCNCDBs
        'UseCertBySubject' = $useCertBySubject
      }
      if (-not [string]::IsNullOrEmpty($ClusterNetworkName)) {
        $params += @{
          'ClusterNetworkName' = $ClusterNetworkName
        }
      }
      Write-LogInfo $OperationID "FCNCBins: C:\Windows\NetworkController"
      Write-LogInfo $OperationID "FCNCDBs: $FCNCDBs"
      Write-LogInfo $OperationID "UseCertBySubject: $useCertBySubject"
      Write-LogInfo $OperationID "ClusterNetworkName: $ClusterNetworkName"
    }

    try {
      if ($UseFCNC -eq $true) {
        New-FCNCNetworkController @params
      } else {
        New-SDNExpressNetworkController @params
      }
    }
    catch {
        Write-LogUncaughtError -StageCode $Global:Stage -ErrorMessage $_.Exception.Message
        throw $_.Exception.Message
    }

    $NCHostCertThumb = Invoke-Command -ComputerName $NCNodes[0] @CredentialParam {
      param(
        $RESTName
      )
      return (Get-ChildItem "cert:\localmachine\my" | Where-Object { $_.Subject -eq "CN=$RestName" }).Thumbprint
    } -ArgumentList $RestName

    $NCHostCert = Get-ChildItem "cert:\localmachine\my\$NCHostCertThumb"

    $params = @{
        'RestName'            = $RestName;
        'MacAddressPoolStart' = $MacPoolStart;
        'MacAddressPoolEnd'   = $MacPoolEnd;
        'NCHostCert'          = $NCHostCert;
        'NCUsername'          = $Credential.UserName;
        'NCPassword'          = $Credential.Password;
        'UseCertBySubject'    = $useCertBySubject;
    }
    New-SDNExpressVirtualNetworkManagerConfiguration @Params @CredentialParam

    Write-LogStageComplete 2 "Successfully configured Network Controller"
    Write-LogStageStarted 3 "Configuring host"
    $Global:Stage = 3
    foreach ($h in $HyperVHosts) {
        Add-SDNExpressHost -ComputerName $h `
            -RestName $RestName `
            -NCHostCert $NCHostCert `
            -Credential $Credential `
            -VirtualSwitchName $SwitchName `
            -NCNodes $NCNodes `
            -CertificatePassword $Credential.Password
    }
    Write-LogStageComplete 3 "Successfully configured host"
}

function Deploy-SoftwareLoadBalancer {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OperationID,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PsCredential]$Credential,
    [Parameter(Mandatory = $true)]
    [bool]$isDHCP,
    [Parameter(Mandatory = $true)]
    [string]$SwitchName,
    [Parameter(Mandatory = $true)]
    [string]$RestName,
    [Parameter(Mandatory = $true)]
    [int]$ManagementVLANID,
    [Parameter(Mandatory = $false)]
    [string]$VMLocation,
    [Parameter(Mandatory = $true)]
    [string]$VHDSrcPath,
    [Parameter(Mandatory = $true)]
    [string]$VHDName,
    [Parameter(Mandatory = $true)]
    [string]$JoinDomain,
    [Parameter(Mandatory = $false)]
    [string]$ProductKey,
    [Parameter(Mandatory = $false)]
    [string]$OUPath,
    [Parameter(Mandatory = $true)]
    [SecureString]$LocalAdminSecurePassword,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementSubnet,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementGateway,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string[]]$ManagementDNS,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$HyperVHosts,
    [Parameter(Mandatory = $true)]
    [string]$PASubnet,
    [Parameter(Mandatory = $false)]
    [string]$PAVLANID,
    [Parameter(Mandatory = $false)]
    [string]$PAGateway,
    [Parameter(Mandatory = $true)]
    [PSObject[]]$Muxes,
    [Parameter(Mandatory = $false)]
    [string]$PublicVIPSubnet,
    [Parameter(Mandatory = $false)]
    [string]$PrivateVIPSubnet,
    [Parameter(Mandatory = $true)]
    [PSObject[]]$Routers,
    [Parameter(Mandatory = $true)]
    [string]$SDNASN,
    [hashtable]$AddRestParams = @{},
    [string]$hciDeploymentUser
  )

    Import-Module NetworkController

    Write-LogStageStarted 1 "Creating SLB VMs"
    if ($isDHCP -eq $false) {
        $ManagementSubnetBits = $ManagementSubnet.Split("/")[1]
    }
    $PASubnetBits = $PASubnet.Split("/")[1]

    $params = @{
        'ComputerName'       = '';
        'VMLocation'         = $VMLocation;
        'VMName'             = '';
        'VHDSrcPath'         = $VHDSrcPath;
        'VHDName'            = $VHDName;
        'VMMemory'           = 8GB;
        'VMProcessorCount'   = 8;
        'Nics'               = @();
        'Credential'         = $Credential;
        'JoinDomain'         = $JoinDomain;
        'LocalAdminPassword' = $LocalAdminSecurePassword;
        'SwitchName'         = $SwitchName;
        'OperationID'        = $OperationID;
    }

    if (-not [String]::IsNullOrWhiteSpace($ProductKey)) {
        $params.ProductKey = $ProductKey
    }
    if (-not [String]::IsNullOrWhiteSpace($OUPath)) {
        $params.OUPath = $OUPath
    }

    if (-not [String]::IsNullOrEmpty($hciDeploymentUser)) {
      $params.DomainAdminsToAdd = @("$JoinDomain\$hciDeploymentUser")
    }

    $MuxNodesFQDN = @()

    foreach ($Mux in $Muxes) {
        $params.ComputerName = $Mux.ComputerName
        $params.VMName = $Mux.VMName
        Write-LogInfo $OperationID "VM: $($Mux.VMName)"
        if ($isDHCP -eq $true) {
            $params.Nics = @(
                @{Name = "Management"; VLANID = $ManagementVLANID },
                @{Name = "HNVPA"; IPAddress = "$($Mux.PAIPAddress)/$PASubnetBits"; VLANID = $PAVLANID; IsMuxPA = $true }
            )
            Write-LogInfo $OperationID "Management VLANID: $($ManagementVLANID)"
            Write-LogInfo $OperationID "HNVPA IPAddress: $($Mux.PAIPAddress)/$PASubnetBits"
            Write-LogInfo $OperationID "HNVPA VLANDID: $($PAVLANID)"
        }
        else {
            $params.Nics = @(
                @{Name = "Management"; IPAddress = "$($Mux.ManagementIP)/$ManagementSubnetBits"; Gateway = $ManagementGateway; DNS = $ManagementDNS; VLANID = $ManagementVLANID },
                @{Name = "HNVPA"; IPAddress = "$($Mux.PAIPAddress)/$PASubnetBits"; VLANID = $PAVLANID; IsMuxPA = $true }
            )
            Write-LogInfo $OperationID "Management IPAddress: $($Mux.ManagementIP)/$ManagementSubnetBits"
            Write-LogInfo $OperationID "Management Gateway: $($ManagementGateway)"
            Write-LogInfo $OperationID "Management DNS: $($ManagementDNS)"
            Write-LogInfo $OperationID "Management VLANID: $($ManagementVLANID)"
            Write-LogInfo $OperationID "HNVPA IPAddress: $($Mux.PAIPAddress)/$PASubnetBits"
            Write-LogInfo $OperationID "HNVPA VLANID: $($PAVLANID)"
        }

        $params.Roles = @("SoftwareLoadBalancer");

        $MuxNodesFQDN += "$($Mux.VMName).$JoinDomain"

        New-SDNExpressVM @params
    }

    WaitforComputerToBeReady -ComputerName $MuxNodesFQDN -Credential $Credential
    Import-SdnExpressCARootIntoVms -InfraVms $MuxNodesFQDN -Hosts $HyperVHosts -Credential $Credential

    Write-LogStageComplete 1 "Successfully created SLB vms"
    Write-LogStageStarted 5 "Deploying Software Load Balancer"
    $Global:Stage = 5
    # Get NC Certificate (generally this should succeed if run on a Hyper-v host already configured for SDN.)

    $fullRestUri = "https://$($RestName)"
    $req = [Net.HttpWebRequest]::Create($fullRestUri)
    try {
        # This will fail with 404 but that is ok as long as we get the cert back
        $req.GetResponse()
    }
    catch {
        if ($null -eq $req.ServicePoint.Certificate) {
            $ErrorText = "Could not get certificate from endpoint $($fullRestUri)"
            Write-SdnExpressLog $ErrorText
            throw $ErrorText
        }
    }

    $thumbprint = $req.ServicePoint.Certificate.GetCertHashString()
    $NCHostCert = get-childitem "cert:\localmachine\my\$($thumbprint)"

    # Apply SLB configuration to the network controller

    $params = @{
        'RestName' = $RestName;
        'PrivateVIPPrefix' = $PrivateVIPSubnet;
        'PublicVIPPrefix' = $PublicVIPSubnet;
        'Credential' = $Credential;
        'AddRestParams' = $AddRestParams;
    }

    New-SDNExpressLoadBalancerManagerConfiguration @params

    $params = @{
      'PAGateway' = $PAGateway;
      'MuxASN' = $SDNASN;
      'Routers' = $Routers;
      'RestName' = $RestName;
      'NCHostCert' = $NCHostCert;
      'Credential' = $Credential;
      'AddRestParams' = $AddRestParams;
    }
    foreach ($Mux in $muxes) {
        $params.ComputerName = $Mux.VMName
        $params.LocalPeerIP = $Mux.PAIPAddress
        Add-SDNExpressMux @params
    }

    Write-LogStageComplete 5 "Successfully deployed SLB"
    Write-LogStageStarted 3 "Starting host configuration"
    $Global:Stage = 3
    # Update host configuration
    $params = @{
        'HostPASubnetPRefix' = $PASubnet;
        'RestName' = $RestName;
        'NCHostCert' = $NCHostCert;
        'Credential' = $Credential;
        'VirtualSwitchName' = $SwitchName;
        'CertificatePassword' = $Credential.Password;
        'AddRestParams' = $AddRestParams;
    }
    foreach ($h in $hypervhosts) {
        $params.ComputerName = $h
        Add-SDNExpressHost @params
    }

    Write-LogStageComplete 3 "Successfully completed host configuration"
}

function Deploy-Gateways {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OperationID,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$HyperVHosts,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PsCredential]$Credential,
    [Parameter(Mandatory = $true)]
    [bool]$isDHCP,
    [Parameter(Mandatory = $true)]
    [string]$SwitchName,
    [Parameter(Mandatory = $true)]
    [string]$RestName,
    [Parameter(Mandatory = $true)]
    [int]$ManagementVLANID,
    [Parameter(Mandatory = $false)]
    [string]$VMLocation,
    [Parameter(Mandatory = $true)]
    [string]$VHDSrcPath,
    [Parameter(Mandatory = $true)]
    [string]$VHDName,
    [Parameter(Mandatory = $true)]
    [string]$JoinDomain,
    [Parameter(Mandatory = $false)]
    [string]$ProductKey,
    [Parameter(Mandatory = $false)]
    [string]$OUPath,
    [Parameter(Mandatory = $true)]
    [SecureString]$LocalAdminSecurePassword,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementSubnet,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementGateway,
    [Parameter(Mandatory = $true, ParameterSetName = "Static")]
    [ValidateNotNullOrEmpty()]
    [string[]]$ManagementDNS,
    [Parameter(Mandatory = $true)]
    [string]$PASubnet,
    [Parameter(Mandatory = $false)]
    [string]$PAVLANID,
    [Parameter(Mandatory = $true)]
    [PSObject[]]$Routers,
    [Parameter(Mandatory = $true)]
    [string]$SDNASN,
    [Parameter(Mandatory = $true)]
    [PSObject[]]$Gateways,
    [Parameter(Mandatory = $true)]
    [int]$GatewayCapacity,
    [Parameter(Mandatory = $false)]
    [int]$RedundantCount,
    [Parameter(Mandatory = $true)]
    [string]$GreSubnet,
    [hashtable] $AddRestParams = @{},
    [string]$hciDeploymentUser
  )

    Import-Module NetworkController

    Write-LogStageStarted 1 "Creating Gateway VMs"
    if ($isDHCP -eq $false) {
        $ManagementSubnetBits = $ManagementSubnet.Split("/")[1]
    }
    $PASubnetBits = $PASubnet.Split("/")[1]

    $params = @{
        'ComputerName'       = '';
        'VMLocation'         = $VMLocation;
        'VMName'             = '';
        'VHDSrcPath'         = $VHDSrcPath;
        'VHDName'            = $VHDName;
        'VMMemory'           = 8GB;
        'VMProcessorCount'   = 8;
        'Nics'               = @();
        'Credential'         = $Credential;
        'JoinDomain'         = $JoinDomain;
        'LocalAdminPassword' = $LocalAdminSecurePassword;
        'SwitchName'         = $SwitchName;
        'OperationID'        = $OperationID;
    }

    if (-not [String]::IsNullOrWhiteSpace($ProductKey)) {
        $params.ProductKey = $ProductKey
    }
    if (-not [String]::IsNullOrWhiteSpace($OUPath)) {
        $params.OUPath = $OUPath
    }

    if (-not [String]::IsNullOrEmpty($hciDeploymentUser)) {
      $params.DomainAdminsToAdd = @("$JoinDomain\$hciDeploymentUser")
    }

    $GatewayFQDN = @()

    $gwParams = @{
      'RestName' = $RestName;
      'JoinDomain' = $JoinDomain;
      'FrontEndLogicalNetworkName' = "HNVPA";
      'FrontEndAddressPrefix' = $PASubnet;
      'Credential' = $Credential;
      'AddRestParams' = $AddRestParams
    }
    foreach ($Gateway in $Gateways) {
      $gwParams.ComputerName = $Gateway.VMName
      $gwParams.HostName = $Gateway.ComputerName

        $GatewayData = Initialize-SDNExpressGateway @gwParams
        $Gateway.FrontEndMac = $GatewayData.FrontEndMac;
        $Gateway.FrontEndIp = $GatewayData.FrontEndIp;
        $Gateway.BackEndMac = $GatewayData.BackEndMac;

        $params.ComputerName = $Gateway.ComputerName;
        $params.VMName = $Gateway.VMName;
        if ($isDHCP -eq $true) {
            $params.Nics = @(
                @{Name = "Management"; VLANID = $ManagementVLANID }
                @{Name = "FrontEnd"; MacAddress = $GatewayData.FrontEndMac; IPAddress = "$($GatewayData.FrontEndIp)/$PASubnetBits"; VLANID = $PAVLANID },
                @{Name = "BackEnd"; MacAddress = $GatewayData.BackEndMac; VLANID = $PAVLANID }
            );

            Write-LogInfo $OperationID "Management VLANID: $($ManagementVLANID)"
            Write-LogInfo $OperationID "FrontEnd MacAddress: $($GatewayData.FrontEndMac)"
            Write-LogInfo $OperationID "FrontEnd IPAddress: $($GatewayData.FrontEndIp)/$PASubnetBits";
            Write-LogInfo $OperationID "FrontEnd VLANID: $($PAVLANID)"
            Write-LogInfo $OperationID "BackEnd MacAddress: $($GatewayData.BackEndMac)"
            Write-LogInfo $OperationID "BackEnd VLANID: $($PAVLANID)"
        }
        else {
            $params.Nics = @(
                @{Name = "Management"; IPAddress = "$($Gateway.ManagementIP)/$ManagementSubnetBits"; Gateway = $ManagementGateway; DNS = $ManagementDNS; VLANID = $ManagementVLANID }
                @{Name = "FrontEnd"; MacAddress = $GatewayData.FrontEndMac; IPAddress = "$($GatewayData.FrontEndIp)/$PASubnetBits"; VLANID = $PAVLANID },
                @{Name = "BackEnd"; MacAddress = $GatewayData.BackEndMac; VLANID = $PAVLANID }
            );

            Write-LogInfo $OperationID "Management IPAddress: $($Gateway.ManagementIP)/$ManagementSubnetBits"
            Write-LogInfo $OperationID "Management Gateway: $($ManagementGateway)"
            Write-LogInfo $OperationID "Management DNS: $($ManagementDNS)"
            Write-LogInfo $OperationID "Management VLANID: $($ManagementVLANID)"
            Write-LogInfo $OperationID "FrontEnd MacAddress: $($GatewayData.FrontEndMac)"
            Write-LogInfo $OperationID "FrontEnd IPAddress: $($GatewayData.FrontEndIp)/$PASubnetBits";
            Write-LogInfo $OperationID "FrontEnd VLANID: $($PAVLANID)"
            Write-LogInfo $OperationID "BackEnd MacAddress: $($GatewayData.BackEndMac)"
            Write-LogInfo $OperationID "BackEnd VLANID: $($PAVLANID)"

        }
        $params.Roles = @("RemoteAccess", "RemoteAccessServer", "RemoteAccessMgmtTools", "RemoteAccessPowerShell", "RasRoutingProtocols", "Web-Application-Proxy")

        $GatewayFQDN += "$($Gateway.VMName).$JoinDomain"
        New-SDNExpressVM @params
    }
    WaitforComputerToBeReady -ComputerName $GatewayFQDN -Credential $Credential
    Import-SdnExpressCARootIntoVms -InfraVms $GatewayFQDN -Hosts $HyperVHosts -Credential $Credential

    Write-LogStageComplete 1 "Successfully deployed Gateway VMs"
    Write-LogStageStarted 6 "Starting Gateway deployment"
    $Global:Stage = 6

    # Get NC Certificate (generally this should succeed if run on a Hyper-v host already configured for SDN.)

    $fullRestUri = "https://$($RestName)"
    $req = [Net.HttpWebRequest]::Create($fullRestUri)
    try {
        # This will fail with 404 but that is ok as long as we get the cert back
        $req.GetResponse()
    }
    catch {
        if ($null -eq $req.ServicePoint.Certificate) {
            $ErrorText = "Could not get certificate from endpoint $($fullRestUri)"
            Write-SdnExpressLog $ErrorText
            throw $ErrorText
        }
    }

    $thumbprint = $req.ServicePoint.Certificate.GetCertHashString()
    $NCHostCert = get-childitem "cert:\localmachine\my\$($thumbprint)"

    $gwParams = @{
      'PoolName' = "DefaultAll";
      'Capacity' = $GatewayCapacity;
      'RestName' = $RestName;
      'Credential' = $Credential;
      'RedundantCount' = $RedundantCount;
      'GreSubnetAddressPrefix' = $GreSubnet
      'AddRestParams' = $AddRestParams
    }
    New-SDNExpressGatewayPool -IsTypeAll @gwParams

    foreach ($Gateway in $Gateways) {
        $params = @{
            'RestName'                   = $RestName
            'ComputerName'               = $Gateway.VMName
            'HostName'                   = $Gateway.ComputerName
            'NCHostCert'                 = $NCHostCert
            'PoolName'                   = 'DefaultAll'
            'FrontEndIp'                 = $Gateway.FrontEndIp
            'FrontEndLogicalNetworkName' = 'HNVPA'
            'FrontEndAddressPrefix'      = $PASubnet
            'FrontEndMac'                = $Gateway.FrontEndMac
            'BackEndMac'                 = $Gateway.BackEndMac
            'Routers'                    = $Routers
            'LocalASN'                   = $SDNASN
            'AddRestParams'              = $AddRestParams
        }
        New-SDNExpressGateway @params -Credential $Credential
    }
    Write-LogStageComplete 6 "Successfully deployed Gateway"
}

Set-StrictMode -Version 5.0
$VerbosePreference = 'Continue'

$SdnLogName = "SDNExpress-$(get-date -Format 'yyyyMMdd-HHmmss').log"
Start-Transcript -Append -IncludeInvocationHeader
Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-SDN" -ErrorAction SilentlyContinue
Set-Variable -Name InfoLogSource -Option Constant -Value "SmeHciScripts-SDN-Info" -ErrorAction SilentlyContinue


try {
    if (-not ($env:pester)) {
      $Global:Stage = 1

      Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
      Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $InfoLogSource -ErrorAction SilentlyContinue

      # set up deployment variables
      $NCSecurePassword = $NCPassword | ConvertTo-SecureString -AsPlainText -Force
      $Credential = New-Object System.Management.Automation.PsCredential($NCUsername, $NCSecurePassword)
      if (-not [string]::IsNullOrEmpty($LocalAdminPassword)) {
        $LocalAdminSecurePassword = $LocalAdminPassword | ConvertTo-SecureString -AsPlainText -Force
      }
      $vmSwitchName = $SwitchName
      $managementSwitch = Get-VMSwitch | Where-Object { $_.name -eq 'Management Virtual Switch' }
      if ($null -ne $managementSwitch) {
        $vmSwitchName = 'Management Virtual Switch'
      }

      Install-RequiredModulesAndFeatures -UseFCNC $UseFCNC -HyperVHosts $HyperVHosts -Credential $Credential

      $credssp = Get-WSManCredSSP
      Write-LogInfo $OperationID "creddssp: $credssp"

      $AddRestParams = @{}
      if (-not [String]::IsNullOrEmpty($CertificateThumbprint)) {
          $AddRestParams += @{
              'CertificateThumbprint' = $CertificateThumbprint
          }
      }

      # fill in deployment parameters
      $params = @{
        "OperationID" = $OperationID;
        "Credential" = $Credential;
        "SwitchName" = $vmSwitchName;
        "HyperVHosts" = $HyperVHosts;
      }

      # deploy nc vms, mux vms, or gateway vms
      if (($OperationType -eq 0 -and $UseFCNC -eq $false) -or $OperationType -eq 1 -or $OperationType -eq 2) {
        $params += @{
          "isDHCP" = $isDHCP;
          "RestName" = $RestName;
          "ManagementVLANID" = $ManagementVLANID;
          "LocalAdminSecurePassword" = $LocalAdminSecurePassword;
          "VMLocation" = $VMLocation;
          "VHDSrcPath" = $VHDSrcPath;
          "VHDName" = $VHDName;
          "JoinDomain" = $JoinDomain;
          # optional variables
          "ProductKey" = $ProductKey;
          "OUPath" = $OUPath;
        }
        # static variables
        if ($isDHCP -eq $false) {
          $params += @{
            "ManagementSubnet" = $ManagementSubnet;
            "ManagementGateway" = $ManagementGateway;
            "ManagementDNS" = $ManagementDNS;
          }
        }
        if (Get-IsEceEnvironment -ComputerName $HyperVHosts[0] -Credential $Credential) {
          $hciDeploymentUser = Get-HciXmlUser -ComputerName $HyperVHosts[0] -Credential $Credential
          $params += @{
            "hciDeploymentUser" = $hciDeploymentUser;
          }
        }
      }
      # deploy mux vms or gateway vms
      if ($OperationType -eq 1 -or $OperationType -eq 2) {
        $params += @{
          "PASubnet" = $PASubnet;
          "PAVLANID" = $PAVLANID;
          "Routers" = $Routers;
          "SDNASN" = $SDNASN;
        }
      }

      ## NETWORK CONTROLLER DEPLOYMENT ##
      if ($OperationType -eq 0) {
        $params += @{
          "UseFCNC" = $UseFCNC;
          # used for new-sdnexpressvirtualmanagerconfiguration
          "MacPoolStart" = $MacPoolStart;
          "MacPoolEnd" = $MacPoolEnd;
        }
        if ($UseFCNC -eq $false) {
          # sf parameters
          $params += @{
            "NCs" = $NCs;
          }
        } else {
          # fc parameters
          $params += @{
            "RestIPAddress" = $RestIPAddress;
            "FCNCDBs" = $FCNCDBs;
            "ClusterNetworkName" = $ClusterNetworkName;
          }
          if (-not [String]::IsNullOrEmpty($RestName)) {
            $params += @{ "RestName" = $RestName; }
          }
        }
        return Deploy-NetworkController @params
      }
      ## MUX DEPLOYMENT ##
      elseif ($OperationType -eq 1) {
        $params += @{
          "Muxes" = $Muxes;
          "PAGateway" = $PAGateway;
          # used in new-sdnexpressloadbalancermanagerconfiguration
          "PublicVIPSubnet" = $PublicVIPSubnet;
          "PrivateVIPSubnet" = $PrivateVIPSubnet;
          "AddRestParams" = $AddRestParams
        }
        return Deploy-SoftwareLoadBalancer @params
      }
      ## GATEWAY DEPLOYMENT ##
      elseif ($OperationType -eq 2) {
        $params += @{
          "Gateways" = $Gateways;
          "GatewayCapacity" = $GatewayCapacity;
          "RedundantCount" = $RedundantCount;
          "GreSubnet" = $GreSubnet;
          "AddRestParams" = $AddRestParams;
        }
        return Deploy-Gateways @params
      }
      else {
        throw "Unknown OperationType $OperationType"
      }
    }
}
catch {
    Write-Host $_
    if($null -ne $_.Exception) {
        Write-Host $_.Exception
    }
    write-LogUncaughtError -StageCode $Global:Stage -ErrorMessage $_.Exception.Message
}

}
## [END] New-SDNExpressLite ##
function Ping-VMwithRouterIP {
<#

.SYNOPSIS
Ping

.DESCRIPTION
This Script is used to Ping in the Virtual Machine with Router IP

.ROLE
Readers

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $routerIP
)

$ping = ping $routerIP -n 1

if($ping -match "Reply from")
{
    $result = "Success"
}
else
{
    $result = "Failed"
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue

$myResponse

}
## [END] Ping-VMwithRouterIP ##
function Remove-MultisiteConfiguration {
<#

.SYNOPSIS
Remove multisite configurations from the cluster

.DESCRIPTION
Remove the multisite configuration for both sites for a 2-site Multisite Configuration

.ROLE
Administrators

#>
param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $uriRemote,
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Off

$local = Get-NetworkControllerMultisiteConfiguration @paramsHash
$localMeta = $local.ResourceMetadata
$localTags = $local.Tags
if ($null -ne $localTags -and $null -ne $localTags.RemoteClusterName) {
  $localTags.RemoteClusterName = ""
}
if ($null -ne $localTags -and $null -ne $localTags.RemoteNcVmName) {
  $localTags.RemoteNcVmName = ""
}

$remote = Get-NetworkControllerMultisiteConfiguration -ConnectionUri $uriRemote
$remoteMeta = $remote.ResourceMetadata
$remoteTags = $remote.Tags
if ($null -ne $remoteTags -and $null -ne $remoteTags.RemoteClusterName) {
  $remoteTags.RemoteClusterName = ""
}
if ($null -ne $remoteTags -and $null -ne $remoteTags.RemoteNcVmName) {
  $remoteTags.RemoteNcVmName = ""
}

$prop = new-object Microsoft.Windows.NetworkController.NetworkControllerMultisiteProperties

Set-NetworkControllerMultisiteConfiguration -Properties $prop -ResourceMetadata $localMeta -Tags $localTags @paramsHash -Force | Out-Null
Set-NetworkControllerMultisiteConfiguration -ConnectionUri $uriRemote -Properties $prop -ResourceMetadata $remoteMeta -Tags $remoteTags -Force | Out-Null

}
## [END] Remove-MultisiteConfiguration ##
function Remove-PublicIpAddress {
<#

.SYNOPSIS
Delete Public IP Address

.DESCRIPTION
This script is used to Delete Public IP Addresses

.ROLE
Administrators

#>

param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIpAddressName,

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
$existing = Get-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName @paramsHash
throwIfResourceManaged $existing

# Delete Public Ip Address
Remove-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value "Success" -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Remove-PublicIpAddress ##
function Set-FcncRestClientSubjectName {
<#

.SYNOPSIS
Updates the Network Controller rest client certificate subject names

.DESCRIPTION
Adds the specified name to the Network Controller rest client certificate subject names for FCNC

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string] $subjectNameToAdd
)

$nc = Get-NetworkControllerOnFailoverCluster
if ($nc.RestClientCertificateSubjectNames.split(',') -inotcontains $subjectNameToAdd) {
    $names = @($subjectNameToAdd)
    $nc = Get-NetworkControllerOnFailoverCluster
    $names += $nc.RestClientCertificateSubjectNames
    Set-NetworkControllerOnFailoverCluster -ClientAuthentication X509 -RestClientCertificateThumbprints $nc.RestClientCertificateThumbprints -RestClientCertificateSubjectNames $names
}
Get-NetworkControllerOnFailoverCluster

}
## [END] Set-FcncRestClientSubjectName ##
function Set-MultisiteConfiguration {
<#

.SYNOPSIS
Set the multisite configuration on 2 sites

.DESCRIPTION
Set the multisite configuration for both sites, and optionally set their names in the metadata information.

.ROLE
Administrators

#>
param
  ([Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $uriLocal,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $uriRemote,
  [Parameter(Mandatory = $false)]
  [String] $localNcName,
  [Parameter(Mandatory = $false)]
  [String] $remoteNcName,
  [Parameter(Mandatory = $false)]
  [String] $localClusterName,
  [Parameter(Mandatory = $false)]
  [String] $remoteClusterName,
  [Parameter(Mandatory = $false)]
  [String] $securityGroup,
  [Parameter(Mandatory = $false)]
  [String] $friendlyNameLocal,
  [Parameter(Mandatory = $false)]
  [String] $friendlyNameRemote,
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
$restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Start-Transcript -Path "sdn-wac-multisite-setting.log" -Append -IncludeInvocationHeader -Confirm:$false -Force | Out-Null

Import-Module NetworkController
Set-StrictMode -Version 5.0

# Format our strings - these need to not have an HTTPS prefix in the site properties,
# but they do need a prefix for putting the Set-Multisite cmdlets
# This allows us to pass in uris with or without the HTTPS prefix

$HTTPS = "https://"
$uriRemote = $uriRemote -replace $HTTPS
$uriLocal = $uriLocal -replace $HTTPS

$certLoggingReplacement = "Certificate not logged"

function getEncodedCert($ncName, $ncUri) {
  # Try using node name instead
  [byte[]] $certData = @()

  if (-not [string]::IsNullOrEmpty($ncName)) {
    try {
      $certData = Invoke-Command -ComputerName $ncName -ScriptBlock {
        $cert = (get-NetworkController).servercertificate
        # ADD FCNC SUPPORT!
        return $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      }
    }
    catch {
      # Intentionally empty so we'll hit the below case
    }
  }

  if ($certData.length -eq 0) {
    try {
      $request = [System.Net.WebRequest]::Create($ncUri)
      $request.GetResponse();
    } catch {
      $certData = $request.ServicePoint.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    }
  }


  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certData)
  if ($cert.Issuer -ne $cert.Subject) {
    # If the issuer and subject aren't equal, then the cert isn't self signed and doesn't need to be passed along
    # If not self signed, the certificate is issued from a Domain CA or any other common Certificate Authority.
    Write-Host "Ignoring cert because cert is not self-signed"
    Write-Host $cert.Issuer
    Write-Host $cert.Subject
    return $null
  }

  Write-Host "Found cert to export"
  Write-Host $cert.Subject
  return [System.Convert]::ToBase64String($certData)
}

function generateMultisiteProperties($sourceUri, $siteUri, $securityGroup, $siteCert, $siteFriendlyName) {
  $certBasedPeering = [string]::IsNullOrEmpty($securityGroup)

  $prop = New-Object Microsoft.Windows.NetworkController.NetworkControllerMultisiteProperties
  if ($certBasedPeering) {
    $prop.CertificateSubjectName = $sourceUri
  }
  else {
    $prop.SecurityGroup = $securityGroup
  }
  $prop.Sites = New-Object Microsoft.Windows.NetworkController.NetworkControllerSite
  $prop.Sites[0].ResourceId = "remoteSite"
  $prop.Sites[0].Properties = New-Object Microsoft.Windows.NetworkController.NetworkControllerSiteProperties
  $prop.Sites[0].Properties.RestIPAddress = $siteUri
  if ($certBasedPeering) {
    $prop.Sites[0].Properties.CertificateSubjectName = $siteUri
    $prop.Sites[0].Properties.EncodedCertificate = $siteCert
  }
  $prop.Sites[0].ResourceMetadata = New-Object Microsoft.Windows.NetworkController.ResourceMetadata
  $prop.Sites[0].ResourceMetadata.ResourceName = $siteFriendlyName

  if ($certBasedPeering) {
    $prop.Sites[0].Properties.EncodedCertificate = $certLoggingReplacement
    Write-Host ($prop | ConvertTo-Json -depth 5)
    $prop.Sites[0].Properties.EncodedCertificate = $siteCert
  } else {
    Write-Host ($prop | ConvertTo-Json -depth 5)
  }

  return $prop
}

$certBasedPeering = [string]::IsNullOrEmpty($securityGroup)

$certRemote = ""
if ($certBasedPeering) {
  $certRemote = getEncodedCert -ncUri ($HTTPS + $uriRemote)
}

$prop = generateMultisiteProperties -sourceUri $uriLocal -siteUri $uriRemote -securityGroup $securityGroup -siteCert $certRemote -siteFriendlyName $friendlyNameRemote
$metadata = New-Object Microsoft.Windows.NetworkController.ResourceMetadata
$metadata.ResourceName = $friendlyNameLocal
$tags = @{
  RemoteClusterName = $remoteClusterName
  RemoteNcVmName    = $remoteNcName
  LocalNcVmName = $localNcName
}
Set-NetworkControllerMultisiteConfiguration @paramsHash -Properties $prop -ResourceMetadata $metadata -Tags $tags -Force
Write-Host "Set the configuration on the local site"

$certLocal = ""
if ($certBasedPeering) {
  $certLocal = getEncodedCert -ncUri ($HTTPS + $uriLocal)
}

$prop = generateMultisiteProperties -sourceUri $uriRemote -siteUri $uriLocal -securityGroup $securityGroup -siteCert $certLocal -siteFriendlyName $friendlyNameLocal
$metadata = New-Object Microsoft.Windows.NetworkController.ResourceMetadata
$metadata.ResourceName = $friendlyNameRemote
$tags = @{
  RemoteClusterName = $localClusterName
  RemoteNcVmName    = $localNcName
  LocalNcVmName = $remoteNcName
}
Set-NetworkControllerMultisiteConfiguration -ConnectionUri ($HTTPS + $uriRemote) -Properties $prop -ResourceMetadata $metadata -Tags $tags -Force
Write-Host "Set the configuration on the remote site"

}
## [END] Set-MultisiteConfiguration ##
function Set-MultisiteConfigurationNames {
<#

.SYNOPSIS
Set the multisite site names on 2 sites

.DESCRIPTION
Set the multisite configuration's Resource Metadata for either or both sites.
If a friendly name for the remote is specified, multisite must already be deployed

.ROLE
Administrators

#>
param
(
  [Parameter(Mandatory = $false)]
  [String] $remoteUri,
  [Parameter(Mandatory = $false)]
  [String] $localFriendlyName,
  [Parameter(Mandatory = $false)]
  [String] $remoteFriendlyName,
  [Parameter(Mandatory = $false)]
  [String] $localNcVmName,
  [Parameter(Mandatory = $false)]
  [String] $remoteNcVmName,
  [Parameter(Mandatory = $false)]
  [String] $localClusterName,
  [Parameter(Mandatory = $false)]
  [String] $remoteClusterName,
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Off

function getUpdatedConfig([object] $restParamsHash, $localName, $localClusterName, $remoteName, $remoteClusterName, $remoteNcVm) {
  $config = $null

  # 1. Get a configuration that can be fully edited. Ensure that the config is populated with any previous information
  if ($null -eq $restParamsHash.ConnectionUri -or "" -eq $restParamsHash.ConnectionUri) {
    return $config
  }

  try {
    $config = Get-NetworkControllerMultisiteConfiguration @restParamsHash
  }
  catch {
    $config = New-Object Microsoft.Windows.NetworkController.NetworkControllerMultisite
    $config.properties = New-Object Microsoft.Windows.NetworkController.NetworkControllerMultisiteProperties
  }

  if ($null -eq $config.ResourceMetadata) {
    $config.ResourceMetadata = New-Object Microsoft.Windows.NetworkController.ResourceMetadata
  }

  $oldTags = $config.Tags

  $metadata = $config.ResourceMetadata
  $tags = @{}

  if ($null -ne $oldTags) {
    $tags = [PSCustomObject]@{
      RemoteClusterName = $oldTags.RemoteClusterName
      RemoteNcVmName = $oldTags.RemoteNcVmName
      LocalNcVmName = $oldTags.LocalNcVmName
    }
  }
  $config.tags = $tags

  # 2. Add in new information to config
  if ($null -ne $localName  -and "" -ne $localName) {
    $metadata.ResourceName = $localName
  }

  if ($null -ne $remoteClusterName -and "" -ne $remoteClusterName) {
    $tags.RemoteClusterName = $remoteClusterName
  }

  if ($null -ne $remoteNcVm  -and "" -ne $remoteNcVm) {
    $tags.RemoteNcVmName = $remoteNcVm
  }

  if ($null -ne $localNcVm  -and "" -ne $localNcVm) {
    $tags.LocalNcVmName = $localNcVm
  }

  if (($null -ne $config.Properties.Sites) -and ($null -ne $config.Properties.Sites[0])) {
    $site = $config.Properties.Sites[0]
    if ($null -eq $site.ResourceMetadata) {
      $site.ResourceMetadata = New-Object Microsoft.Windows.NetworkController.ResourceMetadata
    }
    if ($null -ne $remoteName -and "" -ne $remoteName) {
      $site.ResourceMetadata.ResourceName = $remoteName
    }
  }

  return $config
}

$remoteHash = @{'ConnectionUri' = $remoteUri}
$localConfig = getUpdatedConfig -restParamsHash $paramsHash -localName $localFriendlyName -localClusterName $localClusterName -remoteName $remoteFriendlyName -remoteClusterName $remoteClusterName -remoteNcVm $remoteNcVmName
$remoteConfig = getUpdatedConfig -restParamsHash $remoteHash -localName $remoteFriendlyName -localClusterName $remoteClusterName -remoteName $localFriendlyName -remoteClusterName $localClusterName -remoteNcVm $localNcVmName

Set-NetworkControllerMultisiteConfiguration @paramsHash -Properties $localConfig.Properties -Tags $localConfig.Tags -ResourceMetadata $localConfig.ResourceMetadata -Force

if ($null -ne $remoteUri -and "" -ne $remoteUri) {
  Set-NetworkControllerMultisiteConfiguration -ConnectionUri $remoteUri -Properties $remoteConfig.Properties -Tags $remoteConfig.Tags -ResourceMetadata $remoteConfig.ResourceMetadata -Force
}

}
## [END] Set-MultisiteConfigurationNames ##
function Set-MultisiteConfigurationPrimary {
<#

.SYNOPSIS
Set the multisite configuration on 2 sites

.DESCRIPTION
Set the multisite configuration primary site once multisite peering is already established

.ROLE
Administrators

#>
param
(
  [Parameter(Mandatory = $True)]
  [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Version 5.0

$prop = New-Object Microsoft.Windows.NetworkController.NetworkControllerMultisitePrimaryProperties

Set-NetworkControllerMultisitePrimary -Properties $prop @paramsHash -Force

}
## [END] Set-MultisiteConfigurationPrimary ##
function Set-NCNodeNames {
<#

.SYNOPSIS
Set the NC Node names for the cluster node

.DESCRIPTION
Set the NC Node names for the cluster node

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $true)]
    [String[]]
    $nodeNames
)

Set-StrictMode -Version 5.0

New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\' -Name 'NetworkControllerNodeNames' -Value $nodeNames -PropertyType "MultiString" -Force

}
## [END] Set-NCNodeNames ##
function Start-Capture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $ipAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $routerIP,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList =@()
$pktmonunload = pktmon unload
for($i = 0; $i -lt $ipAddress.Length; $i++)
{
    $j = $i+1
    $pktmonfilter = pktmon filter add -i $ipAddress[$i] $routerIP[$i] -d arp
    $filterList += "Filter"+$j+ ": "+ "IpAddresses" + ": " + $ipAddress[$i] + ", " + $routerIP[$i] + "; " + "EtherType" + ": " + "ARP"

    $k = $j+1
    $pktmonfilter = pktmon filter add -i $ipAddress[$i] $routerIP[$i] -p 179
    $filterList += "Filter"+$k+ ": "+ "IpAddresses" + ": " + $ipAddress[$i] + ", " + $routerIP[$i] +  "; " + "Port" + ": " + "179"
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse


}
## [END] Start-Capture ##
function Start-ClientCertWorkflow {
<#

.SYNOPSIS

.DESCRIPTION

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string[]] $clusterNodes,
    [Parameter(Mandatory = $true)]
    [bool] $isEce,
    [Parameter(Mandatory = $true)]
    [string] $subjectName,
    [bool] $cleanUp = $false,
    [bool] $findExistingCert = $true
)

# Install SDN Express module
Install-PackageProvider -Name NuGet -MinimumVersion "2.8.5.201" -Force | Out-Null
Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck | Out-Null
$module = $null
$props = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\SdnInstall\ -ErrorAction SilentlyContinue
if ($null -ne $props -and $null -ne $props.SdnExpressPath) {
    $modulePath = Join-Path ($props.SdnExpressPath) -ChildPath "SdnExpress.psm1"
    Import-Module -Name $modulePath | Out-Null
} else {
    Install-Module -Name SdnExpress -Confirm:$false -Force | Out-Null
    Import-Module -Name SdnExpress | Out-Null
    $module = Get-Module -Name SdnExpress -ErrorAction SilentlyContinue
    Import-Module "$($module.ModuleBase)\Sdnexpress.psm1" -Force | Out-Null
}

if ($isEce) {
    # Import Azure Local CA and Client Certificate
    Import-SdnExpressCARootOntoRemoteServer -Hosts $clusterNodes | Out-Null
    $ClientCert = Import-AzureLocalClientCertificate -Hosts $clusterNodes -CleanUpCerts $cleanUp
} else {
    $ClientCert = New-SdnExpressClientAuthCertificate -Hosts $clusterNodes -SubjectName $subjectName -CleanUpCerts $cleanUp -findExistingCert $findExistingCert
}   

if ($null -ne $ClientCert) {
    $ClientCert.Thumbprint
}

}
## [END] Start-ClientCertWorkflow ##
function Start-IPSecGatewayScenarioDIPHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Gateway and its associated Host for IPSec Gateway Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $clientIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $tenantIPAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $tenantPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

if(($remoteClientPort -eq "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Encapusulation Support"

    }
}
elseif(($remoteClientPort -eq "") -and ($tenantPort -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $tenantPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Port" + ": " + $tenantPort + "; " + "Transport Protocol" + ": " + $protocol+  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $tenantPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Port" + ": " + $tenantPort +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -ne "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddresss -p $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; "+ "Port" + ": " + $remoteClientPort + "; "  + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; "+ "Port" + ": " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p  $tenantPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Ports" + ": " + $tenantPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p  $tenantPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $clientIPAddress + ", " + $tenantIPAddress + "Port" + ": " + $tenantPort + ", " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}

$pktmonFilter = pktmon filter add -i $clientIPAddress -p 53
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $clientIPAddress + "; " + "Port" + ": " + "53"

$pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -d arp -e
$filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress + "; " + "EtherType" + ": " + "ARP"+ "; " + "Encapsulation Support"

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-IPSecGatewayScenarioDIPHostCapture ##
function Start-IPSecGatewayScenarioGatewayHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Gateway and its associated Host for IPSec Gateway Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $destinationIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $sourceIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $clientIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $externalIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $tenantIPAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $tenantPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $destinationIpAddress $sourceIPAddress -e
$filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $destinationIpAddress + ", " + $sourceIPAddress +  "; " + "Encapusulation Support"


$pktmonFilter = pktmon filter add -i $destinationIpAddress $externalIPAddress -e
$filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $destinationIpAddress + ", " + $externalIPAddress +  "; " + "Encapusulation Support"



if(($remoteClientPort -eq "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -eq "") -and ($tenantPort -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort + "; " + "Transport Protocol" + ": " + $protocol+  "; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -ne "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $remoteClientPort -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; "+ "Port" + ": " + $remoteClientPort + "; "  + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $remoteClientPort -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; "+ "Port" + ": " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort $remoteClientPort  -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Ports" + ": " + $tenantPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort $remoteClientPort -e
        $filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort + ", " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-IPSecGatewayScenarioGatewayHostCapture ##
function Start-IPSecGatewayScenarioMUXHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Muxes and its associated Hosts for IPSec Gateway Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $destinationIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $sourceIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @()

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $destinationIpAddress $sourceIPAddress -e
$filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $destinationIpAddress + ", " + $sourceIPAddress +  "; " + "Encapusulation Support"


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-IPSecGatewayScenarioMUXHostCapture ##
function Start-InboundNatScenarioMuxHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in inbound NAT Scenario for Muxs and it's associated hosts

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Encapsulation Support"
    }
}
else
{
     if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $frontendPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort+ "; " + "Encapsulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InboundNatScenarioMuxHostCapture ##
function Start-InboundNatScenarioServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in inbound NAT Scenario for Server

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $backEndPort,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [String] $networkInterfaceIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload


if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Encapsulation Support"
    }
}
else
{
     if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $frontendPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort+ "; " + "Encapsulation Support"
    }
}

$pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress $remoteClientIpAddress -p $backEndPort
$filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $backEndPort


$pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress -p 53
$filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $networkInterfaceIpAddress + "; " + "Port" + ": " + "53"


$pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress $remoteClientIpAddress -d arp -e
$filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress + ", " + $remoteClientIpAddress + "; " + "EtherType" + ": " + "ARP" +"; " + "Encapusulation Support"


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InboundNatScenarioServerCapture ##
function Start-InternalLoadBalancingDIPCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Internal Load Balancing CA VIP Scenario for Network Interfaces associated Hosts

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $privateIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $vip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $dip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

for($i=0; $i -lt $privateIPAddress.Length; $i++)
{
    $k = $i+1
    $pktmonFilter = pktmon filter add -i $privateIPAddress[$i] $remoteClientIpAddress -d arp -e
    $filterList += "Filter"+$k+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"
}

$l = $k+1
$pktmonFilter = pktmon filter add -i $vip $dip
$filterList += "Filter"+$l+ ": "+ "IpAddresses" + ": " + $vip + ", " + $dip

if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $l+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -t $protocol -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
        }
    }
    else
    {
        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $l+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"
        }
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $l+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        }
    }
    else
    {
        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $l+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"

        }
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InternalLoadBalancingDIPCapture ##
function Start-InternalLoadBalancingDIPServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Internal Load Balancing CA VIP Scenario for
Network Interface associated Host and Source VM associated Host

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $privateIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $vip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $dip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

for($i=0; $i -lt $privateIPAddress.Length; $i++)
{
    $k = $i+1
    $pktmonFilter = pktmon filter add -i $privateIPAddress[$i] $remoteClientIpAddress -d arp -e
    $filterList += "Filter"+$k+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"
}

$m = $k+1
$pktmonFilter = pktmon filter add -i $vip $dip -e
$filterList += "Filter"+$m+ ": "+ "IpAddresses" + ": " + $vip + ", " + $dip +"; " + "Encapusulation Support"


if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $n = $m+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter"+$n+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $o = $j+1
            $p = $n+$o
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -t $protocol -e
            $filterList += "Filter"+$p+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
        }
    }
    else
    {
        $n = $m+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter"+$n+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $o = $j+1
            $p = $n+$o
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -e
            $filterList += "Filter"+$p+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"
        }
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $n = $m+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter"+$n+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $o = $j+1
            $p = $n+$o
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
            $filterList += "Filter"+$p+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
        }
    }
    else
    {
        $n = $m+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter"+$n+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $o = $j+1
            $p = $n+$o
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
            $filterList += "Filter"+$p+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"
        }
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InternalLoadBalancingDIPServerCapture ##
function Start-InternalLoadBalancingMUXCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Internal Load Balancing CA VIP Scenario for MUx and its associated Hosts

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $dip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @()

$pktmonUnload = pktmon unload

if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"
    }
}
else
{
     if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"
    }
}


$pktmonFilter = pktmon filter add -i $vip $dip  -e
$filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $vip + ", " + $dip +  "; " + "Encapusulation Support"

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InternalLoadBalancingMUXCapture ##
function Start-InternalLoadBalancingMUXDIPServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Internal Load Balancing CA VIP Scenario for MUx and its associated Hosts

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $privateIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $dip,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}
$filterList = @();

$pktmonUnload = pktmon unload


$l = 1
$pktmonFilter = pktmon filter add -i $vip $dip -e
$filterList += "Filter"+$l+ ": "+ "IpAddresses" + ": " + $vip + ", " + $dip +"; " + "Encapusulation Support"


if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $m = $l+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter"+$m+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $m+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -t $protocol -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
        }
    }
    else
    {
        $m = $l+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter"+$m+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $m+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"
        }
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $m = $l+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter"+$m+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $m+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
        }
    }
    else
    {
        $m = $l+1
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter"+$m+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"

        for($j=0; $j -lt $privateIPAddress.Length; $j++)
        {
            $n = $j+1
            $o = $m+$n
            $pktmonFilter = pktmon filter add -i $privateIPAddress[$j] $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
            $filterList += "Filter"+$o+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$j] + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"
        }
    }
}

for($k=0; $k -lt $privateIPAddress.Length; $k++)
{
    $q = $k+1
    $r = $o+$q
    $pktmonFilter = pktmon filter add -i $privateIPAddress[$k] $remoteClientIpAddress -d arp -e
    $filterList += "Filter"+$r+ ": "+ "IpAddresses" + ": " + $privateIPAddress[$k] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InternalLoadBalancingMUXDIPServerCapture ##
function Start-InternalLoadBalancingServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Public/Private Load Balancing Scenario for Server

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $privateIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload


for($i=0; $i -lt $privateIPAddress.Length; $i++)
{
    $j = $i+1
    $pktmonFilter = pktmon filter add -i $privateIPAddress[$i] $remoteClientIpAddress -d arp -e
    $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $privateIPAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"
}

$k = $j + 1
if($remoteClientPort -eq "")
{

    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter"+ $k + ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter"+ $k + ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $frontendPort +"; " + "Encapusulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter"+ $k + ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter"+ $k + ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-InternalLoadBalancingServerCapture ##
function Start-L3GatewayScenarioDIPCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Gateway and its associated Host for L3 Gateway Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $clientIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $tenantIPAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $tenantPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

if(($remoteClientPort -eq "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Encapusulation Support"

    }
}
elseif(($remoteClientPort -eq "") -and ($tenantPort -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $tenantPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Port" + ": " + $tenantPort + "; " + "Transport Protocol" + ": " + $protocol+  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $tenantPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Port" + ": " + $tenantPort +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -ne "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddresss -p $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; "+ "Port" + ": " + $remoteClientPort + "; "  + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; "+ "Port" + ": " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p  $tenantPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $clientIPAddress + ", " + $tenantIPAddress +  "; " + "Ports" + ": " + $tenantPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -p  $tenantPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $clientIPAddress + ", " + $tenantIPAddress + "Port" + ": " + $tenantPort + ", " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}

$pktmonFilter = pktmon filter add -i $clientIPAddress -p 53
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $clientIPAddress + "; " + "Port" + ": " + "53"

$pktmonFilter = pktmon filter add -i $clientIPAddress $tenantIPAddress -d arp -e
$filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $clientIPAddress + ", " + $tenantIPAddress + "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-L3GatewayScenarioDIPCapture ##
function Start-L3GatewayScnearioCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Gateway and its associated Host for L3 Gateway Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vLanID,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $clientIPAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $tenantIPAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $tenantPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload


if(($remoteClientPort -eq "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID  -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -t $protocol -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -eq "") -and ($tenantPort -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID  -p $tenantPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Port" + ": " + $tenantPort + "; " + "Transport Protocol" + ": " + $protocol+  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort -t $protocol -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort + "; " + "Transport Protocol" + ": " + $protocol+  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID  -p $tenatPtenantPortort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Port" + ": " + $tenantPort +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenatPtenantPortort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort +  "; " + "Encapusulation Support"
    }
}
elseif(($remoteClientPort -ne "") -and ($tenantPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID -p $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Port" + ": " + $remoteClientPort + "; "  + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $remoteClientPort -t $protocol -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; "+ "Port" + ": " + $remoteClientPort + "; "  + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID -p $tenatPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Port" + ": " + $remoteClientPort +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenatPort $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; "+ "Port" + ": " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID -p $tenantPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "VLANID" + ": " + $vLanID + "; " + "Ports" + ": " + $tenantPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort $remoteClientPort -t $protocol -e
        $filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Ports" + ": " + $tenantPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +  "; " + "Encapusulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -v $vLanID -p $tenantPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; "  + "VLANID" + ": " + $vLanID + "; "+ "Port" + ": " + $tenantPort + ", " + $remoteClientPort +  "; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $tenantIPAddress $clientIPAddress -p $tenantPort $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $tenantIPAddress + ", " + $clientIPAddress +  "; " + "Port" + ": " + $tenantPort + ", " + $remoteClientPort +  "; " + "Encapusulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-L3GatewayScnearioCapture ##
function Start-LoadBalancingMuxHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Public/Private Scenario for Muxs and it's associated hosts

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Encapsulation Support"
    }
}
else
{
     if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $frontendPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort+ "; " + "Encapsulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-LoadBalancingMuxHostCapture ##
function Start-LoadBalancingServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Public/Private Load Balancing Scenario for Server

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontEndIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $networkInterfaceIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"

        $j = 1
        for($i = 0; $i -lt $networkInterfaceIpAddress.Length; $i++ )
        {
            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -t $protocol -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] -p 53 -e
            $filterList += "Filter"+ $j + ": "+ "IpAddress" + ": " + $networkInterfaceIpAddress[$i] + "; " + "Port" + ": " + "53"+ "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -d arp -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; "+ "Encapusulation Support"
        }
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $frontendPort+ "; " + "Encapsulation Support"

        $j = 1
        for($i = 0; $i -lt $networkInterfaceIpAddress.Length; $i++ )
        {
            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] -p 53
            $filterList += "Filter"+ $j + ": "+ "IpAddress" + ": " + $networkInterfaceIpAddress[$i] + "; " + "Port" + ": " + "53"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -d arp -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; "+ "Encapusulation Support"
        }
    }
}
else
{
     if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $frontendPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"

        $j = 1
        for($i = 0; $i -lt $networkInterfaceIpAddress.Length; $i++ )
        {
            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -p $remoteClientPort -t $protocol -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol+ "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] -p 53 -e
            $filterList += "Filter"+ $j + ": "+ "IpAddress" + ": " + $networkInterfaceIpAddress[$i] + "; " + "Port" + ": " + "53"+ "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -d arp -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; "+ "Encapusulation Support"
        }
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $frontEndIpAddress $remoteClientIpAddress -p $frontendPort $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $frontEndIpAddress + ", " + $remoteClientIpAddress + "Ports" + ": " + $frontendPort + ", " + $remoteClientPort+ "; " + "Encapsulation Support"

        $j = 1
        for($i = 0; $i -lt $networkInterfaceIpAddress.Length; $i++ )
        {
            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -p $remoteClientPort -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress + "Port" + ": " + $remoteClientPort+ "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] -p 53 -e
            $filterList += "Filter"+ $j + ": "+ "IpAddress" + ": " + $networkInterfaceIpAddress[$i] + "; " + "Port" + ": " + "53"+ "; " + "Encapsulation Support"

            $j = $j+1
            $pktmonFilter = pktmon filter add -i $networkInterfaceIpAddress[$i] $remoteClientIpAddress -d arp -e
            $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $networkInterfaceIpAddress[$i] + ", " + $remoteClientIpAddress +  "; " + "EtherType" + ": " + "ARP" + "; "+ "Encapusulation Support"

        }
    }
}


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-LoadBalancingServerCapture ##
function Start-NetworkControllerGatewayandHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Network controller VM and Gateways and its associated Hosts

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfNc,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfGateway,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfGateway -d arp
$filterList += "Filter1" + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfGateway + "; " + "EtherType" + ": " + "ARP"

$pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfGateway -p 5985
$filterList += "Filter2" + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfGateway + "; " + "Port" + ": " + "5985"

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerGatewayandHostCapture ##
function Start-NetworkControllerHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $ipAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

for($i = 0; $i -lt $ipAddress.Length; $i++)
{
    $j = $i+1
    $pktmonFilter = pktmon filter add -i $ipAddress[$i] -d arp
    $filterList += "Filter"+ $j + ": "+ "IpAddress" + ": " + $ipAddress[$i] + "; " + "EtherType" + ": " + "ARP"
}

$k = $j+1
$pktmonFilter = pktmon filter add -p 6640
$filterList += "Filter"+ $k + ": "+ "Port" + ": " + "6640"

$l = $k+1
$pktmonFilter = pktmon filter add -p 443
$filterList += "Filter"+ $l + ": "+ "Port" + ": " + "443"

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerHostCapture ##
function Start-NetworkControllerMuxandHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Network controller VM and Mux and its associated Hosts

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfNc,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfMux,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfMux -d arp
$filterList += "Filter1" + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfMux + "; " + "EtherType" + ": " + "ARP"

$pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfMux -p 8560
$filterList += "Filter2" + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfMux + "; " + "Port" + ": " + "8560"


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerMuxandHostCapture ##
function Start-NetworkControllerNodeGatewayCommunicationCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Network controller VM and Gateways and its associated Hosts

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfNc,


    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $ipAddressOfGateways,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$j = 0
for($i = 0; $i -lt $ipAddressOfGateways.Length; $i++)
{
    $j = $j+1
    $pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfGateways[$i] -d arp
    $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfGateways[$i] + "; " + "EtherType" + ": " + "ARP"

    $j = $j+1
    $pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfGateways[$i] -p 5985
    $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfGateways[$i] + "; " + "Port" + ": " + "5985"
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerNodeGatewayCommunicationCapture ##
function Start-NetworkControllerNodeMuxCommunicationCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Network controller VM and Mux and its associated Hosts

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddressOfNc,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [array] $ipAddressOfMuxes,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$j = 0
for($i = 0; $i -lt $ipAddressOfMuxes.Length; $i++)
{
    $j = $j+1
    $pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfMuxes[$i] -d arp
    $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfMuxes[$i] + "; " + "EtherType" + ": " + "ARP"

    $j = $j+1
    $pktmonFilter = pktmon filter add -i $ipAddressOfNc $ipAddressOfMuxes[$i] -p 8560
    $filterList += "Filter"+ $j + ": "+ "IpAddresses" + ": " + $ipAddressOfNc + ", " + $ipAddressOfMuxes[$i] + "; " + "Port" + ": " + "8560"
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerNodeMuxCommunicationCapture ##
function Start-NetworkControllerServerCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $ipAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue

)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $ipAddress -d arp
$filterList += "Filter1"+ ": "+ "IpAddress" + ": " + $ipAddress + "; " + "EtherType" + ": " + "ARP"

$pktmonFilter = pktmon filter add -i $ipAddress -p 6640
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $ipAddress + "; " + "Port" + ": " + "6640"

$pktmonFilter = pktmon filter add -i $ipAddress -p 443
$filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $ipAddress + "; " + "Port" + ": " + "443"


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}


$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-NetworkControllerServerCapture ##
function Start-OutboundNatCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Outbound NAT Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $backendIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $backendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -d arp -e
$filterList += "Filter1" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "EtherType" + ": " + "ARP" + "; " + "Encapsulation Support"


$pktmonFilter = pktmon filter add -i $backendIpAddress -p 53 -e
$filterList += "Filter2" + ": " + "IpAddress" + ": " + $backendIpAddress + "; " + "Port" + ": " + "53" + "; " + "Encapsulation Support"


if (($backendPort -eq "") -and ($remoteClientPort -eq "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -t $protocol
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Transport Protocol" + ": " + $protocol

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Encapsulation Support"
    }
}
elseif (($backendPort -eq "") -and ($remoteClientPort -ne "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"

    }
    else {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -p $remoteClientPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort + "; " + "Encapsulation Support"
    }
}
elseif (($backendPort -ne "") -and ($remoteClientPort -eq "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort + "; " + "Transport Protocol" + ": " + $protocol

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddressl -p $backendPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddressl -p $backendPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort + "; " + "Encapsulation Support"
    }
}
else {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort $remoteClientPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $backendPort + ", " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort $remoteClientPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $backendPort + ", " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $backendIpAddress $remoteClientIpAddress -p $backendPort $remoteClientPort
        $filterList += "Filter3" + ": " + "IpAddresses" + ": " + $backendIpAddress + ", " + $remoteClientIpAddress + "Port" + ": " + $backendPort + ", " + $remoteClientPort

        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -p $backendPort $remoteClientPort -e
        $filterList += "Filter4" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "Port" + ": " + $backendPort + ", " + $remoteClientPort + "; " + "Encapsulation Support"
    }
}

if ($buildValue -ge "19402") {
    $pktmonStart = pktmon start -c
}
else {
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-OutboundNatCapture ##
function Start-OutboundNatMuxHostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for Outbound NAT Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $frontendIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $backendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}
$filterList = @();

$pktmonUnload = pktmon unload

if (($backendPort -eq "") -and ($remoteClientPort -eq "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Encapsulation Support"
    }
}
elseif (($backendPort -eq "") -and ($remoteClientPort -ne "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $remoteClientPort + "; " + "Encapsulation Support"
    }
}
elseif (($backendPort -ne "") -and ($remoteClientPort -eq "")) {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddressl -p $backendPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Port" + ": " + $backendPort + "; " + "Encapsulation Support"
    }
}
else {
    if ($protocol.ToLower() -ne "any") {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -t $protocol -p $backendPort $remoteClientPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "; " + "Ports" + ": " + $backendPort + ", " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol + "; " + "Encapsulation Support"
    }
    else {
        $pktmonFilter = pktmon filter add -i $frontendIpAddress $remoteClientIpAddress -p $backendPort $remoteClientPort -e
        $filterList += "Filter1" + ": " + "IpAddresses" + ": " + $frontendIpAddress + ", " + $remoteClientIpAddress + "Port" + ": " + $backendPort + ", " + $remoteClientPort + "; " + "Encapsulation Support"
    }
}

if ($buildValue -ge "19402") {
    $pktmonStart = pktmon start -c
}
else {
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-OutboundNatMuxHostCapture ##
function Start-PktmonCounter {
<#

.SYNOPSIS
Run Packetmon counter

.DESCRIPTION
This Script is used to Run the PacketMon Counters

.ROLE
Administrators

#>


$pktmonCounter = pktmon counter

if($pktmonCounter -eq "All counters are zero.")
{
    $hostName = $null
}
else
{

    $name = hostname
    $hostName =  $name+"."+(Get-CIMInstance CIM_ComputerSystem).Domain
    $resetCounter = pktmon reset
    $PktmonStop = Pktmon stop
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hostName -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-PktmonCounter ##
function Start-PktmonUnloadandFilter {
<#

.SYNOPSIS
Start the Packetmon

.DESCRIPTION
This Script is used to Start the PacketMon

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $routerIP
)


$pktmonUnload = pktmon unload
$PktmonFilter = pktmon filter add -i $routerIP -t icmp
$pktmonStart = pktmon start

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $pktmonStart -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-PktmonUnloadandFilter ##
function Start-PublicIPScnearioMuxHostCaputure {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in Muxes and its associated Hosts for Public Ip Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $publicIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload


if($remoteClientPort -eq "")
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; "  + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Encapusulation Support"

    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress + "Port" + ": " + $remoteClientPort +"; " + "Encapusulation Support"

    }
}


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-PublicIPScnearioMuxHostCaputure ##
function Start-PublicIPScnearioVMandHostCaputure {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture in VM and its associated Host for Public Ip Scenario

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $publicIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteClientIpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $backendPort,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $remoteClientPort,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $privateIpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload


if(($backendPort -eq "") -and ($remoteClientPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +"; " + "Encapusulation Support"

    }
}
elseif(($backendPort -eq "") -and ($remoteClientPort -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $remoteClientPort +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $remoteClientPort +"; " + "Encapusulation Support"

    }
}
elseif(($backendPort -ne "") -and ($remoteClientPort -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; "  + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -t $protocol -p $backendPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $backendPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Encapusulation Support" +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -p $backendPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " + $backendPort +"; " + "Encapusulation Support" +"; " + "Encapusulation Support"

    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -t $protocol -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress +  "; " + "Port" + ": " +  $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -t $protocol -p $backendPort $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress +  "; " + "Ports" + ": " + $backendPort +", "+ $remoteClientPort + "; " + "Transport Protocol" + ": " + $protocol +"; " + "Encapusulation Support"

    }
    else
    {
        $pktmonFilter = pktmon filter add -i $publicIpAddress $remoteClientIpAddress -p $remoteClientPort -e
        $filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $publicIpAddress + ", " + $remoteClientIpAddress + "Port" + ": " + $remoteClientPort +"; " + "Encapusulation Support"

        $pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -p $backendPort $remoteClientPort -e
        $filterList += "Filter2"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress + "Ports" + ": " + $backendPort + ", " + $remoteClientPort +"; " + "Encapusulation Support"

    }
}

$pktmonFilter = pktmon filter add -i $privateIpAddress -p 53
$filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $privateIpAddress + "; " + "Port" + ": " + "53"


$pktmonFilter = pktmon filter add -i $privateIpAddress $remoteClientIpAddress -d arp -e
$filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $privateIpAddress + ", " + $remoteClientIpAddress + "; " + "EtherType" + ": " + "ARP" +"; " + "Encapusulation Support"


if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-PublicIPScnearioVMandHostCaputure ##
function Start-VMtoVMConnectionCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for VM to VM connection

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm1IpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm2IpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm1Port,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm2Port,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -d arp -e
$filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "; " + "EtherType" + ": " + "ARP"  + "; " + "Encapsulation Support"

$pktmonFilter = pktmon filter add -i $vm1IpAddress -p 53
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $vm1IpAddress + "; " + "Port" + ": " + "53"

$pktmonFilter = pktmon filter add -i $vm2IpAddress -p 53
$filterList += "Filter3"+ ": "+ "IpAddress" + ": " + $vm2IpAddress + "; " + "Port" + ": " + "53"


if(($vm1port -eq "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -t $protocol -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -eq "") -and ($vm2Port -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -t $protocol -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
     }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -ne "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -t $protocol -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port + "; "  + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port  + "; " + "Encapsulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -t $protocol -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Ports" + ": " + $vm1Port +", "+ $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -e
        $filterList += "Filter4"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "Port" + ": " + $vm1Port + ", " + $vm2Port  + "; " + "Encapsulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-VMtoVMConnectionCapture ##
function Start-VMtoVMConnectionVM1HostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for VM to VM connection

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm1IpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm2IpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm1Port,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm2Port,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -d arp -e
$filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "; " + "EtherType" + ": " + "ARP"  + "; " + "Encapsulation Support"

$pktmonFilter = pktmon filter add -i $vm1IpAddress -p 53
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $vm1IpAddress + "; " + "Port" + ": " + "53"


if(($vm1port -eq "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -eq "") -and ($vm2Port -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -ne "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port + "; "  + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port  + "; " + "Encapsulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Ports" + ": " + $vm1Port +", "+ $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "Port" + ": " + $vm1Port + ", " + $vm2Port  + "; " + "Encapsulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-VMtoVMConnectionVM1HostCapture ##
function Start-VMtoVMConnectionVM2HostCapture {
<#

.SYNOPSIS
Start the capture

.DESCRIPTION
This Script is used to Start the capture for VM to VM connection

.ROLE
Administrators

#>
param(

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm1IpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $vm2IpAddress,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm1Port,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $vm2Port,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $protocol,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $buildValue
)

if(!(Test-Path "C:\Program Files\wiresharkdissect"))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wiresharkuri = "https://aka.ms/getwsdissect"
    $wiresharkPackagePath = "c:\wireshark"
    if(!(Test-Path $wiresharkPackagePath))
    {
        New-Item -Path $wiresharkPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $wiresharkuri -OutFile "c:\wireshark\wiresharkdissect.exe"
    Start-Process -Wait -FilePath "c:\wireshark\wiresharkdissect.exe " -ArgumentList '/S','/v','/qn' -PassThru
    Remove-Item -Path $wiresharkPackagePath -Recurse -Force
}

$payloadservice = Get-Service -Name PayloadParser -ErrorAction SilentlyContinue
if($payloadservice -eq $null)
{
    $parseruri = "https://aka.ms/payloadparser"
    $parserPackagePath = "c:\payloadparser"
    if(!(Test-Path $parserPackagePath))
    {
        New-Item -Path $parserPackagePath -ItemType "directory" | Out-Null
    }
    Invoke-WebRequest -Uri $parseruri -OutFile "c:\payloadparser\PayloadParser.zip"
    Expand-Archive "c:\payloadparser\payloadParser.zip" -DestinationPath $parserPackagePath -ErrorAction SilentlyContinue
    $webDeployInstallerFilePath = "C:\payloadparser\PayloadParser\PayloadParserSetup.msi"
    Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$webDeployInstallerFilePath`" /qn /passive" -Wait
    Remove-Item -Path $parserPackagePath -Recurse -Force
}

$filterList = @();

$pktmonUnload = pktmon unload

$pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -d arp -e
$filterList += "Filter1"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "; " + "EtherType" + ": " + "ARP"  + "; " + "Encapsulation Support"

$pktmonFilter = pktmon filter add -i $vm2IpAddress -p 53
$filterList += "Filter2"+ ": "+ "IpAddress" + ": " + $vm2IpAddress + "; " + "Port" + ": " + "53"


if(($vm1port -eq "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -eq "") -and ($vm2Port -ne ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm2Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Port" + ": " + $vm2Port  + "; " + "Encapsulation Support"
    }
}
elseif(($vm1port -ne "") -and ($vm2Port -eq ""))
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port + "; "  + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; "+ "Port" + ": " + $vm1Port  + "; " + "Encapsulation Support"
    }
}
else
{
    if($protocol.ToLower() -ne "any")
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -t $protocol -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress +  "; " + "Ports" + ": " + $vm1Port +", "+ $vm2Port + "; " + "Transport Protocol" + ": " + $protocol  + "; " + "Encapsulation Support"
    }
    else
    {
        $pktmonFilter = pktmon filter add -i $vm1IpAddress $vm2IpAddress -p $vm1Port $vm2Port -e
        $filterList += "Filter3"+ ": "+ "IpAddresses" + ": " + $vm1IpAddress + ", " + $vm2IpAddress + "Port" + ": " + $vm1Port + ", " + $vm2Port  + "; " + "Encapsulation Support"
    }
}

if($buildValue -ge "19402")
{
    $pktmonStart = pktmon start -c
}
else
{
    $pktmonStart = pktmon start --etw
}

$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'FilterList' -Value $filterList -ErrorAction SilentlyContinue

$myResponse

}
## [END] Start-VMtoVMConnectionVM2HostCapture ##
function Stop-Capture {
<#

.SYNOPSIS
stop the capture

.DESCRIPTION
This Script is used to stop the capture and format the file to Text document

.ROLE
Administrators

#>
param(

[Parameter(Mandatory = $true)]
[ValidateNotNullorEmpty()]
[string] $buildValue
)

$pktmonStop = pktmon stop

$filePath = ($pktmonStop -match "Log file").split(' ')[2].trim()
[Environment]::SetEnvironmentVariable("PARSER_FILES_PATH", $filePath.Replace('PktMon.etl', ''), "Machine")

$pktmonMerge = netsh trace merge PktMon.etl PktMon1.etl
$deleteItem = Remove-Item PktMon.etl -Force
$renameItem = Rename-Item PktMon1.etl PktMon.etl
$textFormatting = pktmon etl2txt PktMon.etl -o PktMonText.txt
$pcapngFormatting = pktmon etl2pcap PktMon.etl -o PktMon.pcapng

$startservice = Start-Service -Name PayloadParser
Start-Sleep -Seconds 4
$stopservice = Stop-Service -Name PayloadParser -Force
$logfilePath = $filePath.Replace('etl', 'txt')



$myResponse = New-Object -TypeName psobject

$myResponse | Add-Member -MemberType NoteProperty -Name 'LogFilePath' -Value $logfilePath -ErrorAction SilentlyContinue

$myResponse

}
## [END] Stop-Capture ##
function Test-MultisiteConfiguration {
<#

.SYNOPSIS
Validate whether a remote site can be successfully peered with the local site

.DESCRIPTION
Uses a remote site's NC URI to determine if the two sites should be able to be
peered successfully

.ROLE
Readers

#>
param
(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [String] $remoteUri,
    [Parameter(Mandatory = $false)]
    [int] $state = 3, # To be interpreted as a PeeringState (3 = Still Evaluating)
    [Parameter(Mandatory = $True)]
    [object] $restParams
)

$paramsHash = @{}
if ($null -ne $restParams) {
  $restParams.psobject.properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }
}

Import-Module NetworkController
Set-StrictMode -Version 5.0

enum PeeringState {
  Valid = 0
  NoConnect = 1
  BrownBrown = 2
  StillEvaluating = 3
}

function isEmpty([object[]] $globals) {
  if ($null -eq $globals) {
    return $true
  } else {
    return $globals.length -eq 0
  }
}

function isGreenfield([object] $restParamsHash) {
  $isGreenfield = isEmpty -globals (Get-NetworkControllerAccessControlList @restParamsHash)
  $isGreenfield = $isGreenfield -and (isEmpty -globals (Get-NetworkControllerSecurityTag @restParamsHash))
  $isGreenfield = $isGreenfield -and (isEmpty -globals (Get-NetworkControllerRouteTable @restParamsHash))
  $isGreenfield = $isGreenfield -and (isEmpty -globals (Get-NetworkControllerServiceInsertion @restParamsHash))
  $isGreenfield = $isGreenfield -and (isEmpty -globals (Get-NetworkControllerVirtualNetwork @restParamsHash))
  $isGreenfield = $isGreenfield -and (isEmpty -globals (Get-NetworkControllerLearnedIpAddress @restParamsHash))

  return $isGreenfield
}

function gatherIpPools([object] $restParamsHash) {
  $lnets = Get-NetworkControllerLogicalNetwork @restParamsHash
  $ipPoolProps = @()

  foreach($lnet in $lnets) {
    if ($null -ne $lnet) {
      $lsubnets = $lnet.properties.subnets
      foreach ($lsubnet in $lsubnets) {
        if ($null -ne $lsubnet) {
          $ipPools = $lsubnet.properties.ippools
          foreach ($ipPool in $ipPools) {
            if ($null -ne $ipPool) {
              $ipPoolProps += $ipPool.properties
            }
          }
        }
      }
    }
  }

  return $ipPoolProps
}

$result = [PSCustomObject]@{
  LocalIps = $null
  LocalMacs = $null
  RemoteIps = $null
  RemoteMacs = $null
  State = $state
}

if ($result.state -eq [PeeringState]::StillEvaluating) {
  # Check to see if either site is a greenfield site
  # It's more likely that the remote will be the greenfield, so check that first
  $remoteHash = @{'ConnectionUri' = $remoteUri}
  $isRemoteGreenfield = isGreenfield -restParamsHash $remoteHash

  if (-not $isRemoteGreenfield) {
    $isLocalGreenfield = isGreenfield -restParamsHash $paramsHash
    if (-not $isLocalGreenfield) {
      $result.state = [PeeringState]::BrownBrown
    }
  }
}

if ($result.state -eq [PeeringState]::StillEvaluating) {
  [array] $result.LocalIps = gatherIpPools -restParamsHash $paramsHash
  [array] $result.RemoteIps = gatherIpPools -restParamsHash $remoteHash

  [array] $result.LocalMacs = (Get-NetworkControllerMacPool @paramsHash).properties
  [array] $result.RemoteMacs = (Get-NetworkControllerMacPool -ConnectionUri $remoteUri).properties
}

$result | ConvertTo-Json -depth 4 | ConvertFrom-Json

}
## [END] Test-MultisiteConfiguration ##
function Test-RSATOnGateway {

<#
.SYNOPSIS
WAC Validation Gateway Script

.DESCRIPTION
This script validates the Windows Admin Center and checks if its ready to be used against the given NetworkController instance
For now, this script will test:
  - if RSAT for clustering and networkcontroller is available (install it if not available)
  - test by doing a PUT/GET/DELETE against a given NC resource
  - the script also tests if the OS is client SKU in which case Add-WindowsFeature is switched from Add-WindowsOptionalFeature ?

Returns:
  - an empty string if all validations were successful
  - a string[] of errors in case of failures

.ROLE
Readers
#>
param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $installRSAT
)

$RsatInstallResult = @{
  result = ""
  isRsatInstalled = ""
  isSuccess = $false
  exceptionDetails = ""
}

Start-Transcript -Path "sdn-wac-validation-rsat.log" -Append -IncludeInvocationHeader -Confirm:$false -Force | Out-Null

$clusteringRSATFeatureName_Server = 'RSAT-Clustering-Powershell'
$clusteringRSATFeatureName_Client = 'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0'

$sdnRSATFeatureName_Server = 'RSAT-NetworkController'
$sdnRSATFeatureName_Client = 'Rsat.NetworkController.Tools~~~~0.0.1.0'

$rsatOtherError       = "RsatOtherError"
$rsatClientGatewayNotElevated = "clientGatewayNotElevated"

[bool] $isClientSku = $false

$computerInfo = Get-ComputerInfo
$isClientSku = ($computerInfo.WindowsInstallationType -ieq 'client')
Write-Host "isClientSku: $isClientSku"

try {

    if($isClientSku) {

      # WINDOWS  CLIENT  SKU  RSAT  INSTALL
      Write-Host "Reading $clusteringRSATFeatureName_Client install status"
      Write-Host "Reading $sdnRSATFeatureName_Client install status"

      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = New-Object Security.Principal.WindowsPrincipal $identity
      $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
      Write-Host "isElevated: $($isElevated)"
      Write-Host "installRSAT: $($installRSAT)"
      $clusterModule = Get-Module -Name FailoverClusters -ListAvailable
      $ncModule = Get-Module -Name NetworkController -ListAvailable

      if($installRSAT) {

        # if we're expected to install and its already installed, then no-op
        if( $null -ne $ncModule -and $null -ne $clusterModule ) {

          Write-Host "cluster and nc module found!"
          # no-op
          Stop-Transcript | Out-Null
          $RsatInstallResult.result = ""
          $RsatInstallResult.isRsatInstalled = $true
          $RsatInstallResult.isSuccess = $true
          $RsatInstallResult.exceptionDetails = ""
          $RsatInstallResult
          exit

        } else {

          # install rsat (this will most likely fail in WAC, todo: follow up with componentization team)
          # so fail fast and prevent progress
          # $addedRsat = Add-WindowsCapability -Online -Name $sdnRSATFeatureName_Client

          if ($null -eq $clusterModule) {
            Write-Host "cluster module not found"
          }
          if ($null -eq $ncModule) {
            Write-Host "nc module not found"
          }
          Stop-Transcript | Out-Null
          $RsatInstallResult.result = $rsatClientGatewayNotElevated
          $RsatInstallResult.isRsatInstalled = $false
          $RsatInstallResult.isSuccess = $false
          $RsatInstallResult.exceptionDetails = ""
          $RsatInstallResult
          exit
        }
      } else {

        # if installRSAT is false just return the current installation status
        Write-Host "RSAT installation not requested"
        Stop-Transcript | Out-Null
        $RsatInstallResult.result = ""
        $RsatInstallResult.isRsatInstalled = ($null -ne $ncModule -and $null -ne $clusterModule)
        $RsatInstallResult.isSuccess = $true
        $RsatInstallResult.exceptionDetails = ""
        $RsatInstallResult
        exit
      }
    } else {

      # WINDOWS  SERVER  SKU  RSAT  INSTALL
      Write-Host "Reading $clusteringRSATFeatureName_Server install status"
      Write-Host "Reading $sdnRSATFeatureName_Server install status"
      $clusterFeature = Get-WindowsFeature -Name 'RSAT-Clustering-Powershell' -ErrorAction SilentlyContinue -Verbose
      $sdnFeature = Get-WindowsFeature -Name 'RSAT-NetworkController' -ErrorAction SilentlyContinue -Verbose
      if($null -eq $sdnFeature -or $null -eq $clusterFeature) {

        if ($null -eq $clusterFeature) {
          Write-Host "RSAT tools not found, run Get-WindowsFeature -Name $clusteringRSATFeatureName_Server, to diagnose"
        }
        if ($null -eq $sdnFeature) {
          Write-Host "RSAT tools not found, run Get-WindowsFeature -Name $sdnRSATFeatureName_Server, to diagnose"
        }
        Stop-Transcript | Out-Null

        $RsatInstallResult.result = $rsatUnavailableErrorMessage
        $RsatInstallResult.isRsatInstalled = $false
        $RsatInstallResult.isSuccess = $false
        $RsatInstallResult.exceptionDetails = $rsatUnavailableErrorMessage
        $RsatInstallResult
        exit
      }

      if($sdnFeature.Installed -eq $false -or $clusterFeature.Installed -eq $false) {

        if($installRSAT -eq $false) {
          Write-Host "RSAT tools is not installed, skipping install as requested"
          $RsatInstallResult.result = ""
          $RsatInstallResult.isRsatInstalled = $false
          $RsatInstallResult.isSuccess = $true
          $RsatInstallResult.exceptionDetails = ""
          $RsatInstallResult
          exit
        }

        Write-Host "RSAT tools is available but not installed, installing using...Add-WindowsFeature -Name $clusteringRSATFeatureName_Server"
        $clusterInstallationOutcome = Add-WindowsFeature -Name $clusteringRSATFeatureName_Server -Verbose

        Write-Host "RSAT tools is available but not installed, installing using...Add-WindowsFeature -Name $sdnRSATFeatureName_Server"
        $sdnInstallationOutcome = Add-WindowsFeature -Name $sdnRSATFeatureName_Server -Verbose

        if($sdnInstallationOutcome.Success -eq $true -and $clusterInstallationOutcome.Success -eq $true) {
            Write-Host "RSAT Installation successfull"

            $RsatInstallResult.result = ""
            $RsatInstallResult.isRsatInstalled = $true
            $RsatInstallResult.isSuccess = $true
            $RsatInstallResult.exceptionDetails = ""
            $RsatInstallResult
            exit

        } else {

            $RsatInstallResult.result = $rsatUnavailableErrorMessage
            $RsatInstallResult.isRsatInstalled = $false
            $RsatInstallResult.isSuccess = $false
            $RsatInstallResult.exceptionDetails = $rsatUnavailableErrorMessage
            $RsatInstallResult
            exit
        }
        Write-Host "RSAT tools completed"

      } else {

        #RSAT is already installed
        $RsatInstallResult.result = 'Success'
        $RsatInstallResult.isRsatInstalled = $true
        $RsatInstallResult.isSuccess = $true
        $RsatInstallResult.exceptionDetails = ""
        $RsatInstallResult
        exit
      }
    }
} catch {

    Write-Host "Unknown error while installing RSAT"
    Write-Host "Exception: "
    Write-Host $_.Exception.ToString()
    Stop-Transcript | Out-Null

    $RsatInstallResult.result = 'Failed'
    $RsatInstallResult.isRsatInstalled = $false
    $RsatInstallResult.isSuccess = $false
    $RsatInstallResult.exceptionDetails = $_.Exception.ToString()
    $RsatInstallResult
    exit
}

Write-Host "RSAT validation completed!"
Stop-Transcript | Out-Null

$RsatInstallResult.result = $rsatOtherError
$RsatInstallResult.isRsatInstalled = $false
$RsatInstallResult.isSuccess = $true
$RsatInstallResult.exceptionDetails = ""
$RsatInstallResult

}
## [END] Test-RSATOnGateway ##
function Update-PublicIpAddress {
<#

.SYNOPSIS
Update Public IP Address in the cluster

.DESCRIPTION
This script is used to Update Public IP Addresses in the cluster

.ROLE
Administrators

#>

param
(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIpAddressName,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $publicIPAllocationMethod,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $idleTimeoutInMinutes,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [String] $ipAddress,

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
$existing = Get-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName @paramsHash
throwIfResourceManaged $existing
$metadata = $existing.ResourceMetadata
$tags = $existing.Tags

$publicIPProperties = New-Object Microsoft.Windows.NetworkController.PublicIpAddressProperties

$publicIPProperties.PublicIPAllocationMethod = $publicIPAllocationMethod
$publicIPProperties.IdleTimeoutInMinutes = $idleTimeoutInMinutes

if ($publicIPAllocationMethod.ToLower() -eq "static") {
  $publicIPProperties.IPAddress = $ipAddress
}

$result = New-NetworkControllerPublicIpAddress -ResourceId $publicIpAddressName -Properties $publicIPProperties -ResourceMetadata $metadata -Tags $tags @paramsHash -Force

# Preparing Object Response
$myResponse = New-Object -TypeName psobject
$myResponse | Add-Member -MemberType NoteProperty -Name 'Result' -Value $result -ErrorAction SilentlyContinue
$myResponse

Remove-Variable -Name Clients -Scope Script -Force

}
## [END] Update-PublicIpAddress ##
function Add-FolderShare {
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
## [END] Add-FolderShare ##
function Add-FolderShareNameUser {
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
## [END] Add-FolderShareNameUser ##
function Add-FolderShareUser {
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
## [END] Add-FolderShareUser ##
function Compress-ArchiveFileSystemEntity {
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
## [END] Compress-ArchiveFileSystemEntity ##
function Disable-KdcProxy {
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
## [END] Disable-KdcProxy ##
function Disable-SmbOverQuic {
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
## [END] Disable-SmbOverQuic ##
function Edit-FolderShareInheritanceFlag {
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
## [END] Edit-FolderShareInheritanceFlag ##
function Edit-FolderShareUser {
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
## [END] Edit-FolderShareUser ##
function Edit-SmbFileShare {
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
## [END] Edit-SmbFileShare ##
function Edit-SmbServerCertificateMapping {
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
## [END] Edit-SmbServerCertificateMapping ##
function Enable-SmbOverQuic {
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
## [END] Enable-SmbOverQuic ##
function Expand-ArchiveFileSystemEntity {
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
## [END] Expand-ArchiveFileSystemEntity ##
function Get-BestHostNode {
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
## [END] Get-BestHostNode ##
function Get-Certificates {
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
## [END] Get-Certificates ##
function Get-ComputerName {
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
## [END] Get-ComputerName ##
function Get-FileNamesInPath {
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
## [END] Get-FileNamesInPath ##
function Get-FileSystemEntities {
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
## [END] Get-FileSystemEntities ##
function Get-FileSystemRoot {
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
## [END] Get-FileSystemRoot ##
function Get-FolderItemCount {
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
## [END] Get-FolderItemCount ##
function Get-FolderOwner {
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
## [END] Get-FolderOwner ##
function Get-FolderShareNames {
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
## [END] Get-FolderShareNames ##
function Get-FolderSharePath {
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
## [END] Get-FolderSharePath ##
function Get-FolderShareStatus {
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
## [END] Get-FolderShareStatus ##
function Get-FolderShareUsers {
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
## [END] Get-FolderShareUsers ##
function Get-IsAzureTurbineServer {
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
## [END] Get-IsAzureTurbineServer ##
function Get-ItemProperties {
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
## [END] Get-ItemProperties ##
function Get-ItemType {
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
## [END] Get-ItemType ##
function Get-LocalGroups {
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
## [END] Get-LocalGroups ##
function Get-LocalUsers {
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
## [END] Get-LocalUsers ##
function Get-OSDetails {
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
## [END] Get-OSDetails ##
function Get-ShareEntities {
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
## [END] Get-ShareEntities ##
function Get-Smb1InstallationStatus {
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
## [END] Get-Smb1InstallationStatus ##
function Get-SmbFileShareDetails {
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
## [END] Get-SmbFileShareDetails ##
function Get-SmbOverQuicSettings {
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
## [END] Get-SmbOverQuicSettings ##
function Get-SmbServerCertificateHealth {
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
## [END] Get-SmbServerCertificateHealth ##
function Get-SmbServerCertificateMapping {
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
## [END] Get-SmbServerCertificateMapping ##
function Get-SmbServerCertificateValues {
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
## [END] Get-SmbServerCertificateValues ##
function Get-SmbServerSettings {

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
## [END] Get-SmbServerSettings ##
function Get-SmbShareAccess {
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
## [END] Get-SmbShareAccess ##
function Get-StorageFileShare {
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
## [END] Get-StorageFileShare ##
function Get-TempFolderPath {
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
## [END] Get-TempFolderPath ##
function Move-File {
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
## [END] Move-File ##
function New-File {
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
## [END] New-File ##
function New-Folder {
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
## [END] New-Folder ##
function New-SmbFileShare {
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
## [END] New-SmbFileShare ##
function Remove-AllShareNames {
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
## [END] Remove-AllShareNames ##
function Remove-FileSystemEntity {
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
## [END] Remove-FileSystemEntity ##
function Remove-FolderShareUser {
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
## [END] Remove-FolderShareUser ##
function Remove-SmbServerCertificateMapping {
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
## [END] Remove-SmbServerCertificateMapping ##
function Remove-SmbShare {
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
## [END] Remove-SmbShare ##
function Rename-FileSystemEntity {
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
## [END] Rename-FileSystemEntity ##
function Restore-ConfigureSmbServerCertificateMapping {
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
## [END] Restore-ConfigureSmbServerCertificateMapping ##
function Set-SmbOverQuicServerSettings {
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
## [END] Set-SmbOverQuicServerSettings ##
function Set-SmbServerCertificateMapping {
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
## [END] Set-SmbServerCertificateMapping ##
function Set-SmbServerSettings {
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
## [END] Set-SmbServerSettings ##
function Test-FileSystemEntity {
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
## [END] Test-FileSystemEntity ##
function Uninstall-Smb1 {
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
## [END] Uninstall-Smb1 ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCq/v2kkDKCMXij
# /ZUi7zhVYTOhHOvOs4gvsyYaAyEIwqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID2NVZVA4n+R5KvTxBeX/kvm
# msmG7+NGz02upE+t1qEJMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAgFd+qT8PkANCdVuMyp97NaDYMQcBCUHdTEqwZ3LqhavQuAoyw2FmnsXn
# slsy/UCBwYDBIzN2IiJptdQxzVyOX3FEsWIyOWcStarfeduAAd0yuTcWDJWT7mGC
# gii4Y2tqvNRZRgYNNcUPgJ5gaGwpU+aHCi76RwABuVCsnA72d/aC3nZh/xyJbEyU
# shv00uJPF2/FxKK9aKQEgM4u2vIx1WfhT2B3dUsQ/K/nWJq0BSUPLgQ5XOM0G8Re
# 6yuPjGJwTJu/TOMu5nFtbdWYQBr+YE7/oXZBjyjf1Caz4W7NOHBgkzw/in/kC937
# csSB8rf9KwcHAJOHc/SD3g6apgODnKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDWVuH6cQwykFwQu3S/PaH1BhvAgZwJqCXjVfH08KNSKgIGaO/1UBg9
# GBMyMDI1MTExMDE3MTYzMi45MThaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgkIB+D5XIzmVQABAAACCTANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTVaFw0yNjA0MjIxOTQyNTVaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDClEow9y4M3f1S9z1xtNEETwWL1vEiiw0oD7SXEdv4
# sdP0xsVyidv6I2rmEl8PYs9LcZjzsWOHI7dQkRL28GP3CXcvY0Zq6nWsHY2QamCZ
# FLF2IlRH6BHx2RkN7ZRDKms7BOo4IGBRlCMkUv9N9/twOzAkpWNsM3b/BQxcwhVg
# sQqtQ8NEPUuiR+GV5rdQHUT4pjihZTkJwraliz0ZbYpUTH5Oki3d3Bpx9qiPriB6
# hhNfGPjl0PIp23D579rpW6ZmPqPT8j12KX7ySZwNuxs3PYvF/w13GsRXkzIbIyLK
# EPzj9lzmmrF2wjvvUrx9AZw7GLSXk28Dn1XSf62hbkFuUGwPFLp3EbRqIVmBZ42w
# cz5mSIICy3Qs/hwhEYhUndnABgNpD5avALOV7sUfJrHDZXX6f9ggbjIA6j2nhSAS
# Iql8F5LsKBw0RPtDuy3j2CPxtTmZozbLK8TMtxDiMCgxTpfg5iYUvyhV4aqaDLwR
# BsoBRhO/+hwybKnYwXxKeeOrsOwQLnaOE5BmFJYWBOFz3d88LBK9QRBgdEH5CLVh
# 7wkgMIeh96cH5+H0xEvmg6t7uztlXX2SV7xdUYPxA3vjjV3EkV7abSHD5HHQZTrd
# 3FqsD/VOYACUVBPrxF+kUrZGXxYInZTprYMYEq6UIG1DT4pCVP9DcaCLGIOYEJ1g
# 0wIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFEmL6NHEXTjlvfAvQM21dzMWk8rSMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBcXnxvODwk4h/jbUBsnFlFtrSuBBZb7wSZ
# fa5lKRMTNfNlmaAC4bd7Wo0I5hMxsEJUyupHwh4kD5qkRZczIc0jIABQQ1xDUBa+
# WTxrp/UAqC17ijFCePZKYVjNrHf/Bmjz7FaOI41kxueRhwLNIcQ2gmBqDR5W4TS2
# htRJYyZAs7jfJmbDtTcUOMhEl1OWlx/FnvcQbot5VPzaUwiT6Nie8l6PZjoQsuxi
# asuSAmxKIQdsHnJ5QokqwdyqXi1FZDtETVvbXfDsofzTta4en2qf48hzEZwUvbkz
# 5smt890nVAK7kz2crrzN3hpnfFuftp/rXLWTvxPQcfWXiEuIUd2Gg7eR8QtyKtJD
# U8+PDwECkzoaJjbGCKqx9ESgFJzzrXNwhhX6Rc8g2EU/+63mmqWeCF/kJOFg2eJw
# 7au/abESgq3EazyD1VlL+HaX+MBHGzQmHtvOm3Ql4wVTN3Wq8X8bCR68qiF5rFas
# m4RxF6zajZeSHC/qS5336/4aMDqsV6O86RlPPCYGJOPtf2MbKO7XJJeL/UQN0c3u
# ix5RMTo66dbATxPUFEG5Ph4PHzGjUbEO7D35LuEBiiG8YrlMROkGl3fBQl9bWbgw
# 9CIUQbwq5cTaExlfEpMdSoydJolUTQD5ELKGz1TJahTidd20wlwi5Bk36XImzsH4
# Ys15iXRfAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjkyMDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQB8
# 762rPTQd7InDCQdb1kgFKQkCRKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwOwjAiGA8yMDI1MTExMDA3MTIw
# MloYDzIwMjUxMTExMDcxMjAyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvA7C
# AgEAMAoCAQACAhWRAgH/MAcCAQACAhLHMAoCBQDsvWBCAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBABJVM6yZJMQJ0OgEgle+7FkS3adZc72zmR2t9DbhiwkM
# 0SJJqBey/gWbaqZL3pRY/AB3Fs6MGPWyjL3VnFcWZUaVlmaZZp+HLFr9Mhk6etqU
# VV8aqKHmsRX3ix/5vwUzvxeHEB8tJVrct/wIvOU0S/ySD4XROYnqEMjOZhFDkOYW
# ikktrZ0wB3nTdEhP95TfxkZyG93Bo3+0UEppIvYk9zwY7FOAPFw990DcwJr855Zn
# uX0+lViglh1wK9wVgQZbPUTqY8bqzz+AoFlXmbBIR539tbCfd5Lz+Y4KN08OyiOM
# y5ErDdF+19tM/ihCwW1au47vKhGa0KWDgsy5J0Ji1/wxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgkIB+D5XIzmVQABAAAC
# CTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCAGEfs+VfX6gV4c7PSUnvigyR4dkfy3f+rZJuyE2K3j
# NjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGgbLB7IvfQCLmUOUZhjdUqK
# 8bikfB6ZVVdoTjNwhRM+MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIJCAfg+VyM5lUAAQAAAgkwIgQgYevmSpE5N/hkJDG5Xm0q2UKS
# Cn9Nf4Fi0M0SQEldABEwDQYJKoZIhvcNAQELBQAEggIAFFVZgJevVEzMlKuEgBy4
# 9Mct0TcCFmByykSW6tlZcHaJ1GcYvL25vnZ6UGK2Ru3OWzGEN86Ea+iOjOTO4vko
# MfGuSH3ls1u5bAGhw7CnIfEYMmzTFpuvqYzewRt2IkZL7ZyXOywGtMYfhNErgM9/
# rUbHiEcs+9ZXv5ylZSqG9pDSY9DBk5hsuPKCZMZawq6jFZAWOf3nv52zgBlYzgOt
# kZ2UJkkxgPNLaJ12VDlnGpnLGbIMVEpWybaLH93XCZAp2fxu+ZUFggSwYaZXj/Gl
# GqtOmv0/UO4fwjiggdYHn4FV0sT1sX63n1ht5q5an5tOxcQvmolFB/6I/1MxdqgH
# R1Wvw1eBwg4Dx0eTJaDCI3DGBLMdbFSsD7Q24r1mcrx1LpMX/IDPbu3/1IeHddOj
# j9i87itjyesWktACNA49wE6gIDmWeUrLzAUNPNjmjLFqyw+TAya49RimmDFsDX1w
# SNTUh+TXimwwS+Z/3ci6igygl3xbLvG0AV9MrXqfaE7cagmVZ5S9BjABleFqmChU
# HVZjoV5Rt01cFv6JLIary9OAp+RAc8i8ED8prt98vOTie0F3/coEitopWQ2f9oKq
# 4cLMhUYOd6KA8xUYxCaDISWu7rCUK1AKNPhEiZniv4tJLDb50uETXXR/66oSZORL
# GYdNAcv0GNIc+HFrBp9GVvI=
# SIG # End signature block
