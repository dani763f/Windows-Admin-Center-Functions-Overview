function Complete-WACNSP2SVPNConfiguration {
<#

.SYNOPSIS
Download, Extract VPN Folder File & Configure Point to Site VPN

.DESCRIPTION
This script is used to download VPN Client, extract VPN Folder File & Configure Point to Site VPN

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $AccessToken,
    [Parameter(Mandatory = $true)]
    [String]
    $ClientID,
    [Parameter(Mandatory = $true)]
    [String]
    $VNetSubnets, #"10.8.0.0/24;11.8.0.0/26"
    [Parameter(Mandatory = $true)]
    [String]
    $Subscription,
    [Parameter(Mandatory = $true)]
    [String]
    $ResourceGroup,
    [Parameter(Mandatory = $true)]
    [String]
    $GatewayName,
    [Parameter(Mandatory = $true)]
    [String]
    $VirtualNetwork,
    [Parameter(Mandatory = $true)]
    [String]
    $AddressSpace,
    [Parameter(Mandatory = $true)]
    [String]
    $Location
   
)
#Function to log event
function Log-MyEvent($Message){
    Try {
        $eventLogName = "ANA-LOG"
        $eventID = Get-Random -Minimum -1 -Maximum 65535
        #Create WAC specific Event Source if not exists
        $logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $eventLogName} 
        if (!$logFileExists) {
            New-EventLog -LogName $eventLogName -Source $eventLogName
        }
        #Prepare Event Log content and Write Event Log
        Write-EventLog -LogName $eventLogName -Source $eventLogName -EntryType Information -EventID $eventID -Message $Message

        $result = "Success"
    }
    Catch [Exception] {
        $result = $_.Exception.Message
    }
}

Function Build-Vpn( 
[Parameter(Mandatory = $true)]
[string]$XmlFilePathBuild,
[Parameter(Mandatory = $true)]
[string]$ProfileNameBuild,
[Parameter(Mandatory = $true)]
[string]$VNetGatewayNameBuild
)
{
    Log-MyEvent -Message "VPN Client Build started"
    
    #Enabling SC Config on demand
    $scConfigResult=CMD /C "sc config dmwappushservice start=demand"

    $a = Test-Path $xmlFilePathBuild
    echo $a

    $ProfileXML = Get-Content $xmlFilePathBuild

    echo $XML

    $ProfileNameBuildEscaped = $ProfileNameBuild -replace ' ', '%20'

    $Version = 201606090004

    $ProfileXML = $ProfileXML -replace '<', '&lt;'
    $ProfileXML = $ProfileXML -replace '>', '&gt;'
    $ProfileXML = $ProfileXML -replace '"', '&quot;'

    $nodeCSPURI = './Vendor/MSFT/VPNv2'
    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_VPNv2_01"

    $session = New-CimSession

    try
    {
        $newInstance = New-Object Microsoft.Management.Infrastructure.CimInstance $className, $namespaceName
        $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("ParentID", "$nodeCSPURI", 'String', 'Key')
        $newInstance.CimInstanceProperties.Add($property)
        $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("InstanceID", "$ProfileNameBuildEscaped", 'String', 'Key')
        $newInstance.CimInstanceProperties.Add($property)
        $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("ProfileXML", "$ProfileXML", 'String', 'Property')
        $newInstance.CimInstanceProperties.Add($property)

        $session.CreateInstance($namespaceName, $newInstance)
        Log-MyEvent -Message "VPN Client Build completed."

        #Delete from RegEdit
        Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $VNetGatewayNameBuild -ErrorAction SilentlyContinue
        Log-MyEvent -Message "Removed from VNetGatewayNotConfigured RegEdit"

        #Delete File & Folders

        $folderToDelete = Split-Path -Path $xmlFilePathBuild

        Remove-Item -path $folderToDelete -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -path $folderToDelete'.zip' -Force -Recurse -ErrorAction SilentlyContinue

        Log-MyEvent -Message "Trying to connect to VPN....."
        #Connect to this VPN
        $vpnConnected = rasdial $ProfileNameBuild
        Log-MyEvent -Message "VPN Connection established successfully."

        $Message = "Created $ProfileNameBuild profile."
        
        return "success"
    }
    catch [Exception]
    {
        Log-MyEvent -Message "Error Occured during establishing VPN"
        $Message = "Unable to create $ProfileNameBuild profile: $_"
        Log-MyEvent -Message $Message
        
        return $_.Exception.Message
    }
}

#Main operation started
Log-MyEvent -Message "Starting Gateway -'$GatewayName'"

$azureRmModule = Get-Module AzureRM -ListAvailable | Microsoft.PowerShell.Utility\Select-Object -Property Name -ErrorAction SilentlyContinue
if (!$azureRmModule.Name) {
    Log-MyEvent -Message "AzureRM module Not Available. Installing AzureRM Module"
    $packageProvIntsalled = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $armIntalled = Install-Module AzureRm -Force
    Log-MyEvent -Message "Installed AzureRM Module successfully"
} 
else
{
    Log-MyEvent -Message "AzureRM Module Available"
}

import-module AzureRm

Log-MyEvent -Message "Imported AzureRM Module successfully"

#Login into Azure
#$logInRes = Login-AzureRmAccount -AccessToken $AccessToken -AccountId $ClientID
Log-MyEvent -Message "Logging in and selecting subscription..."
#Select Subscription
#$selectSubRes = Select-AzureRmSubscription -SubscriptionId $Subscription
$selectSubRes = Add-AzureRmAccount -AccessToken $AccessToken -AccountId $ClientID -Subscription $Subscription
if($selectSubRes)
{
    Log-MyEvent -Message "Selected Subscription successfully"

    #Select Gateway and generate URL to download VPN Client
    $profile = New-AzureRmVpnClientConfiguration -ResourceGroupName $ResourceGroup -Name $GatewayName -AuthenticationMethod "EapTls"
    if($profile)
    {
        Log-MyEvent -Message "URL generated to download VPN Client"

        #Create a Temp Folder if not exists
        $tempPath = "C:\WAC-TEMP"
        if (!(Test-Path $tempPath)) {
            $TempfolderCreated = New-Item -Path $tempPath -ItemType directory
        }

        #Delete previously downloaded zip file and extracted folder (if any)
        if (Test-Path "$tempPath\$GatewayName.zip") {
                Log-MyEvent -Message "Previous zip file found. deleting it.."
                Remove-Item -path "$tempPath\$GatewayName.zip" -Force -Recurse -ErrorAction SilentlyContinue
                Log-MyEvent -Message "Previous zip file deleted successfully."
        }
        if (Test-Path "$tempPath\$GatewayName") {
            Log-MyEvent -Message "Previous extracted folder found. deleting it.."
            Remove-Item -path "$tempPath\$GatewayName" -Force -Recurse -ErrorAction SilentlyContinue
            Log-MyEvent -Message "Previous extracted folder deleted successfully."
        }
    
        #Download VPN Client and save into a local temp folder
        $output = "$tempPath\" + $GatewayName + ".zip"
        $downLoadUrl = Invoke-WebRequest -Uri $profile.VPNProfileSASUrl -OutFile $output
        Log-MyEvent -Message "VPN Client downloaded successfully"

        #Extract zip
        $DestinationFolder = "$tempPath\" + $GatewayName
        Expand-Archive $output -DestinationPath $DestinationFolder
        Log-MyEvent -Message "VPN Client extracted successfully"

        #Read VPN Setting from Generic folder
        [xml]$XmlDocument = Get-Content -Path $DestinationFolder/Generic/VpnSettings.xml
        $vpnDNSRecord = $XmlDocument.VpnProfile.VpnServer
        Log-MyEvent -Message "Fetched VPN DNS record from VpnSettings.xml file in Generic foder"

        #Create a new VPN Profile name - check uniqueness
        $randomNumber = Get-Random -Minimum -1 -Maximum 65535
        $newVpnProfileName ='WACVPN-' + $randomNumber + '.xml'
        $isVpnAailable = 0
        while($isVpnAailable -eq 0)
        {
            if(!(Get-VpnConnection -Name $newVpnProfileName.split(".")[0] -ErrorAction SilentlyContinue))
            {
                $isVpnAailable=1
            }
            else
            { 
                $randomNumber = Get-Random -Minimum -1 -Maximum 65535
                $newVpnProfileName = 'WACVPN-' + $randomNumber + '.xml'
                $isVpnAailable=0
            }
        }
        try
        {
            Log-MyEvent -Message "Finalized VPN profile unique name"

            $xml_Path = $DestinationFolder + '\' + $newVpnProfileName
 
            #Set RasMan RegEdit value to 1
            $rasManPath = "HKLM:\System\CurrentControlSet\Services\RasMan\IKEv2"
            if((get-item -Path $rasManPath -ErrorAction SilentlyContinue))
            {
                Set-ItemProperty -Path $rasManPath -Name DisableCertReqPayload -Value 1
            }
            Log-MyEvent -Message "Updated RasMan to 1 in RegEdit"

            # Create the XML File Tags
            $xmlWriter = New-Object System.XMl.XmlTextWriter($xml_Path, $Null)
            $xmlWriter.Formatting = 'Indented'
            $xmlWriter.Indentation = 1
            $XmlWriter.IndentChar = "`t"
            $xmlWriter.WriteStartDocument()
            $xmlWriter.WriteStartElement('VPNProfile')
            $xmlWriter.WriteEndElement()
            $xmlWriter.WriteEndDocument()
            $xmlWriter.Flush()
            $xmlWriter.Close()
            Log-MyEvent -Message "XML File creation started"

            #Creating Root Node -NativeProfile
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("NativeProfile")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $xmlDoc.Save($xml_Path)

            #Creating Node -Servers
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("Servers")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile").AppendChild($siteCollectionNode)

            #Adding VPN DNS Record
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode($vpnDNSRecord));
            $xmlDoc.Save($xml_Path)

            #Creating Native Protocolol Type
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("NativeProtocolType")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile").AppendChild($siteCollectionNode)

            #Adding IKEv2
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("IKEv2"));
            $xmlDoc.Save($xml_Path)

            #Creating Authentication
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("Authentication")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile").AppendChild($siteCollectionNode)
            $xmlDoc.Save($xml_Path)
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("MachineMethod")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile/Authentication").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("Certificate"));
            $xmlDoc.Save($xml_Path)

            #Creating RoutingPolicyType
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("RoutingPolicyType")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("SplitTunnel"));
            $xmlDoc.Save($xml_Path)

            #Creating DisableClassBasedDefaultRoute
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("DisableClassBasedDefaultRoute")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/NativeProfile").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("true"));
            $xmlDoc.Save($xml_Path)

            #Create Route
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("Route")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $xmlDoc.Save($xml_Path)

            #Get VNet Subnets and populate Address and prefix
            $allVnetSubnets = $VNetSubnets.split(";")
            foreach ($currentSubnet in $allVnetSubnets) {
                $address = $currentSubnet.split("/")[0]
                $prefixSize = $currentSubnet.split("/")[1]

                $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
                $siteCollectionNode = $xmlDoc.CreateElement("Address")
                $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/Route").AppendChild($siteCollectionNode)
                $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode($address));

                $siteCollectionNode = $xmlDoc.CreateElement("PrefixSize")
                $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/Route").AppendChild($siteCollectionNode)
                $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode($prefixSize));
    
                $xmlDoc.Save($xml_Path)
            }

            #Create TrafficFilter
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("TrafficFilter")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $xmlDoc.Save($xml_Path)

            #Get VNet Subnets and populate Address and prefix
            $allVnetSubnets = $VNetSubnets.split(";")
            foreach ($currentSubnet in $allVnetSubnets) {
                $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
                $siteCollectionNode = $xmlDoc.CreateElement("RemoteAddressRanges")
                $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile/TrafficFilter").AppendChild($siteCollectionNode)
                $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode($currentSubnet));
    
                $xmlDoc.Save($xml_Path)
            }

            #Creating AlwaysOn
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("AlwaysOn")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("true"));
            $xmlDoc.Save($xml_Path)

            #Creating DeviceTunnel
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("DeviceTunnel")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("true"));
            $xmlDoc.Save($xml_Path)

            #Creating RegisterDNS
            $xmlDoc = [System.Xml.XmlDocument](Get-Content $xml_Path);
            $siteCollectionNode = $xmlDoc.CreateElement("RegisterDNS")
            $nodeCreation = $xmlDoc.SelectSingleNode("//VPNProfile").AppendChild($siteCollectionNode)
            $RootFolderTextNode = $siteCollectionNode.AppendChild($xmlDoc.CreateTextNode("true"));
            $xmlDoc.Save($xml_Path)

            #Removing XML Declaration 
            (Get-Content $xml_Path -raw).Replace('<?xml version="1.0"?>', '') | Set-Content $xml_Path;
            Log-MyEvent -Message "XML File creation completed"

            $returnType = ""
            $returnMsg = ""
            #Building VPN Client

            $buildStatus = Build-Vpn -XmlFilePathBuild $xml_Path -ProfileNameBuild $newVpnProfileName.split(".")[0] -VNetGatewayNameBuild $GatewayName
            if($buildStatus -eq "success")
            {
                #Create Registry Key and add Value to it
                $vpnConfiguredRegEditPath="HKLM:\Software\WAC\VPNConfigured"
                if(!(get-item -Path $vpnConfiguredRegEditPath -ErrorAction SilentlyContinue))
                {
                    $regKeyCreated = New-Item -Path HKLM:\Software -Name WAC\VPNConfigured -Force
                }
                $regKeyValue = $Subscription + ':' + $ResourceGroup + ':' + $GatewayName+ ':' + $VirtualNetwork+ ':' + $AddressSpace+':'+ $Location
    
                #Delete the previous gateway entry if already exists
                $readAllRegEdit = Get-Item -path $vpnConfiguredRegEditPath
                Foreach($thisRegEdit in $readAllRegEdit.Property)
                {
                    $thisRegValue = Get-ItemPropertyValue -path $vpnConfiguredRegEditPath -name $thisRegEdit
                    if($thisRegValue.ToLower() -eq $regKeyValue.ToLower())
                    {
                            Log-MyEvent -Message "Found previous connection with this Gateway. Deleting it"
                            Remove-ItemProperty -path $vpnConfiguredRegEditPath -name $thisRegEdit
                            Remove-VpnConnection -Name $thisRegEdit -Force -ErrorAction SilentlyContinue
                    }
                }
     
                Set-ItemProperty -Path $vpnConfiguredRegEditPath -Name $newVpnProfileName.split(".")[0] -Value $regKeyValue
                Log-MyEvent -Message "Logged into RegEdit successfully"

                $returnType = "success"
                $returnMsg = ""
            }
            else
            {
                #Delete from RegEdit
                Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $GatewayName -ErrorAction SilentlyContinue
                Log-MyEvent -Message "Removed from VNetGatewayNotConfigured RegEdit"
                $returnType = "fail"
                $returnMsg = "Building VPN on target machine failed"
            }
        }
        Catch [Exception] {
           Log-MyEvent -Message "Error occured during downloading and building VPN client"
           Log-MyEvent -Message $_.Exception.Message
           #Delete from RegEdit
           Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $GatewayName -ErrorAction SilentlyContinue
           Log-MyEvent -Message "Removed from VNetGatewayNotConfigured RegEdit"
           $returnType = "fail"
           $returnMsg = $_.Exception.Message
        }
        Log-MyEvent -Message "Ending Building process for -'$GatewayName'"
        $myResponse = New-Object -TypeName psobject

        $myResponse | Add-Member -MemberType NoteProperty -Name 'Status' -Value $returnType -ErrorAction SilentlyContinue
        $myResponse | Add-Member -MemberType NoteProperty -Name 'Message' -Value $returnMsg -ErrorAction SilentlyContinue

        $myResponse
    }
    else
    {
    
        Log-MyEvent -Message "Error Downloading VPN Client"
        #Delete from RegEdit
        Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $GatewayName -ErrorAction SilentlyContinue
        Log-MyEvent -Message "Removed from VNetGatewayNotConfigured RegEdit"
        Log-MyEvent -Message "Ending Building process with error for -'$GatewayName'"
    }
}
else
{
   Log-MyEvent -Message "Error in subscription selection."
   #Delete from RegEdit
   Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $GatewayName -ErrorAction SilentlyContinue
   Log-MyEvent -Message "Removed from VNetGatewayNotConfigured RegEdit"
   Log-MyEvent -Message "Ending Building process with error for -'$GatewayName'"
}
}
## [END] Complete-WACNSP2SVPNConfiguration ##
function Disable-WACNSAzureRmContextAutosave {
<#

.SYNOPSIS
Disable AzureRm Context Auto save

.DESCRIPTION
This script is used to disable AzureRm Context Auto save

.ROLE
Administrators

#>
$azureRmModule = Get-Module AzureRM -ListAvailable | Microsoft.PowerShell.Utility\Select-Object -Property Name -ErrorAction SilentlyContinue
if (!$azureRmModule.Name) {   
    $packageProvIntsalled = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $armIntalled = Install-Module AzureRm -Force   
} 
Disable-AzureRmContextAutosave
}
## [END] Disable-WACNSAzureRmContextAutosave ##
function Get-WACNSClientAddressSpace {
<#

.SYNOPSIS
Get Client Address Space

.DESCRIPTION
This script is used to get client address space

.ROLE
Readers

#>
$clientAddressSpace = ""
Try
{
    #Fetch the IP Address of the Machine. There might be many IP Addresses, Here first index is getting fetched
    $ip = get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.Ipaddress.length -gt 1}
    $cidr = (Get-NetIPAddress -IPAddress $ip.ipaddress[0]).PrefixLength
    $clientaddr = "127.0.0.1/32"

    function INT64-toIP() { 
      param ([int64]$int) 
      return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    } 

    if ($cidr){
        $ipaddr = [Net.IPAddress]::Parse($ip.ipaddress[0])
        $maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
        $networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
        $clientAddressSpace = "$networkaddr/$cidr"
    }
}
Catch
{
    $clientAddressSpace = ""
}
$clientAddressSpace
}
## [END] Get-WACNSClientAddressSpace ##
function Get-WACNSNetworks {
<#

.SYNOPSIS
Gets the network ip configuration.

.DESCRIPTION
Gets the network ip configuration. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>
Import-Module NetAdapter
Import-Module NetTCPIP
Import-Module DnsClient

Set-StrictMode -Version 5.0
$ErrorActionPreference = 'SilentlyContinue'

# Get all net information
$netAdapter = Get-NetAdapter

# conditions used to select the proper ip address for that object modeled after ibiza method.
# We only want manual (set by user manually), dhcp (set up automatically with dhcp), or link (set from link address)
# fe80 is the prefix for link local addresses, so that is the format want if the suffix origin is link
# SkipAsSource -eq zero only grabs ip addresses with skipassource set to false so we only get the preffered ip address
$ipAddress = Get-NetIPAddress | Where-Object {($_.SuffixOrigin -eq 'Manual') -or ($_.SuffixOrigin -eq 'Dhcp') -or (($_.SuffixOrigin -eq 'Link') -and (($_.IPAddress.StartsWith('fe80:')) -or ($_.IPAddress.StartsWith('2001:'))))}

$netIPInterface = Get-NetIPInterface
$netRoute = Get-NetRoute -PolicyStore ActiveStore
$dnsServer = Get-DnsClientServerAddress

# Load in relevant net information by name
Foreach ($currentNetAdapter in $netAdapter) {
    $result = New-Object PSObject

    # Net Adapter information
    $result | Add-Member -MemberType NoteProperty -Name 'InterfaceAlias' -Value $currentNetAdapter.InterfaceAlias
    $result | Add-Member -MemberType NoteProperty -Name 'InterfaceIndex' -Value $currentNetAdapter.InterfaceIndex
    $result | Add-Member -MemberType NoteProperty -Name 'InterfaceDescription' -Value $currentNetAdapter.InterfaceDescription
    $result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $currentNetAdapter.Status
    $result | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value $currentNetAdapter.MacAddress
    $result | Add-Member -MemberType NoteProperty -Name 'LinkSpeed' -Value $currentNetAdapter.LinkSpeed

    # Net IP Address information
    # Primary addresses are used for outgoing calls so SkipAsSource is false (0)
    # Should only return one if properly configured, but it is possible to set multiple, so collect all
    $primaryIPv6Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 0)}
    if ($primaryIPv6Addresses) {
        $ipArray = New-Object System.Collections.ArrayList
        $linkLocalArray = New-Object System.Collections.ArrayList
        Foreach ($address in $primaryIPv6Addresses) {
            if ($address -ne $null -and $address.IPAddress -ne $null -and $address.IPAddress.StartsWith('fe80')) {
                $linkLocalArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            else {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
        }
        $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv6Address' -Value $ipArray
        $result | Add-Member -MemberType NoteProperty -Name 'LinkLocalIPv6Address' -Value $linkLocalArray
    }

    $primaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 0)}
    if ($primaryIPv4Addresses) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $primaryIPv4Addresses) {
            $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
        }
        $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv4Address' -Value $ipArray
    }

    # Secondary addresses are not used for outgoing calls so SkipAsSource is true (1)
    # There will usually not be secondary addresses, but collect them just in case
    $secondaryIPv6Adresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 1)}
    if ($secondaryIPv6Adresses) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $secondaryIPv6Adresses) {
            $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
        }
        $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv6Address' -Value $ipArray
    }

    $secondaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 1)}
    if ($secondaryIPv4Addresses) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $secondaryIPv4Addresses) {
            $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
        }
        $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv4Address' -Value $ipArray
    }

    # Net IP Interface information
    $currentDhcpIPv4 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4')}
    if ($currentDhcpIPv4) {
        $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv4' -Value $currentDhcpIPv4.Dhcp
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $true
    }
    else {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $false
    }

    $currentDhcpIPv6 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6')}
    if ($currentDhcpIPv6) {
        $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv6' -Value $currentDhcpIPv6.Dhcp
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $true
    }
    else {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $false
    }

    # Net Route information
    # destination prefix for selected ipv6 address is always ::/0
    $currentIPv6DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '::/0')}
    if ($currentIPv6DefaultGateway) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $currentIPv6DefaultGateway) {
            if ($address.NextHop) {
                $ipArray.Add($address.NextHop) > $null
            }
        }
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6DefaultGateway' -Value $ipArray
    }

    # destination prefix for selected ipv4 address is always 0.0.0.0/0
    $currentIPv4DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '0.0.0.0/0')}
    if ($currentIPv4DefaultGateway) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $currentIPv4DefaultGateway) {
            if ($address.NextHop) {
                $ipArray.Add($address.NextHop) > $null
            }
        }
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4DefaultGateway' -Value $ipArray
    }

    # DNS information
    # dns server util code for ipv4 is 2
    $currentIPv4DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 2)}
    if ($currentIPv4DnsServer) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $currentIPv4DnsServer) {
            if ($address.ServerAddresses) {
                $ipArray.Add($address.ServerAddresses) > $null
            }
        }
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4DNSServer' -Value $ipArray
    }

    # dns server util code for ipv6 is 23
    $currentIPv6DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 23)}
    if ($currentIPv6DnsServer) {
        $ipArray = New-Object System.Collections.ArrayList
        Foreach ($address in $currentIPv6DnsServer) {
            if ($address.ServerAddresses) {
                $ipArray.Add($address.ServerAddresses) > $null
            }
        }
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6DNSServer' -Value $ipArray
    }

    $adapterGuid = $currentNetAdapter.InterfaceGuid
    if ($adapterGuid) {
      $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapterGuid)"
      $ipv4Properties = Get-ItemProperty $regPath
      if ($ipv4Properties -and $ipv4Properties.NameServer) {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $true
      } else {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $false
      }

      $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($adapterGuid)"
      $ipv6Properties = Get-ItemProperty $regPath
      if ($ipv6Properties -and $ipv6Properties.NameServer) {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $true
      } else {
        $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $false
      }
    }

    $result
}

}
## [END] Get-WACNSNetworks ##
function Get-WACNSRootCertValue {
<#

.SYNOPSIS
Storing Root and Client certificate, and then generate certificate value

.DESCRIPTION
This script is used to Storing Root and Client certificate provided by users, and then generate certificate value

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $RootCertPath,
    [Parameter(Mandatory = $true)]
    [String]
    $ClientCertPath,
    [Parameter(Mandatory = $true)]
    [String]
    $Password
)
$certName = ""
$content = ""

#Import Root certificate to Localmachine Root
if (Test-Path $RootCertPath) {
    $rootCertImported = Import-Certificate -FilePath $RootCertPath -certstorelocation 'Cert:\LocalMachine\Root'
    $certName = $rootCertImported.Subject.Split('=')[1]
    $content = @(
		[System.Convert]::ToBase64String($rootCertImported.RawData, 'InsertLineBreaks')
    )
    #Removing uploaded root cert file
    Remove-Item -path $RootCertPath -Force -Recurse -ErrorAction SilentlyContinue
}

#Import Client certificate to Localmachine My
if (Test-Path $ClientCertPath) {

    $securePassword = ConvertTo-SecureString $Password -asplaintext -force 
    $clientCertImported = Import-PfxCertificate -FilePath $ClientCertPath -CertStoreLocation Cert:\LocalMachine\My -Password $securePassword
    
    #Removing uploaded client cert file
    Remove-Item -path $ClientCertPath -Force -Recurse -ErrorAction SilentlyContinue
}

if($clientCertImported)
{
	$result = New-Object System.Object
	$result | Add-Member -MemberType NoteProperty -Name 'RootCertName' -Value $certName
	$result | Add-Member -MemberType NoteProperty -Name 'Content' -Value $content
	$result
}
}
## [END] Get-WACNSRootCertValue ##
function Get-WACNSVNetGatewayNameFromRegEdit {
<#

.SYNOPSIS
Reading Virtual Network Gateway information from Event Log

.DESCRIPTION
This Script is used to read Virtual Network Gateway information from Event Log

.ROLE
Administrators

#>

function Return-Object($rawData,$keyName)
{
	#Preparing Result object
    $subscriptionID = $rawData.Split(":")[0]
    $resourceGroup = $rawData.Split(":")[1]
    $vNetGateway = $rawData.Split(":")[2]

    $result = New-Object System.Object
    $result | Add-Member -MemberType NoteProperty -Name 'SubscriptionID' -Value $subscriptionID
    $result | Add-Member -MemberType NoteProperty -Name 'ResourceGroup' -Value $resourceGroup
    $result | Add-Member -MemberType NoteProperty -Name 'VNetGateway' -Value $vNetGateway
    $result | Add-Member -MemberType NoteProperty -Name 'KeyName' -Value $keyName
    $result
}

#Fetching from RegEdit (Only available/not configured)
$regEditPath = "HKLM:\Software\WAC\VNetGatewayNotConfigured"
$regItems = Get-Item -path $regEditPath -ErrorAction SilentlyContinue
Foreach($regitem in $regItems.Property)
{
  $regValue = Get-ItemPropertyValue -path $regEditPath -name $regitem
  Return-Object $regValue $regitem
}
}
## [END] Get-WACNSVNetGatewayNameFromRegEdit ##
function Get-WACNSVPNGatewayStatus {
<#

.SYNOPSIS
Check if the same gateway record is available

.DESCRIPTION
This Script is used to check if the same gateway record is available

.ROLE
Readers

#>
Param(
    [Parameter(Mandatory = $true)]
    [string] $Subscription,
    [Parameter(Mandatory = $true)]
    [string] $ResourceGroup,
    [Parameter(Mandatory = $true)]
    [string] $VNetGateway
)

$result = $false

$regKeyValue = $Subscription + ":" + $ResourceGroup + ":" + $VNetGateway

$vpnConfiguredRegEditPath = "HKLM:\Software\WAC\VNetGatewayNotConfigured"
if((Get-Item -Path $vpnConfiguredRegEditPath -ErrorAction SilentlyContinue))
{
    #check previous gateway entry if already exists
    $readAllRegEdit = Get-Item -Path $vpnConfiguredRegEditPath
    $isRecordAvailable = "0"
    Foreach($thisRegEdit in $readAllRegEdit.Property)
    {
        $thisRegValue = Get-ItemPropertyValue -Path $vpnConfiguredRegEditPath -Name $thisRegEdit
        if($thisRegValue.ToLower() -eq $regKeyValue.ToLower())
        {
            $isRecordAvailable = "1"
        }
    }

    if($isRecordAvailable -eq "1")
    {
         $result = $true
    }
    else
    {
         $result = $false
    }

}
else
{
    $result = $false
}

$result
}
## [END] Get-WACNSVPNGatewayStatus ##
function Get-WACNSVpnConnections {
<#

.SYNOPSIS
Get VPN Connections

.DESCRIPTION
This script is used to List all VPN Connection by reading from Registration Key and
matching with machine connected P2S VPn and Return Details

.ROLE
Readers

#>
Try
{
    $allVpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
    #Get VPN Profile Names from Registration Key
    $regEditPath = "HKLM:\SOFTWARE\WAC\VPNConfigured"
    $regItems = Get-Item -path $regEditPath -ErrorAction SilentlyContinue
    Foreach($regitem in $regItems.Property)
    {
        #Check if VPN Connection is available or not
        $thisVpn = $allVpnConnections | Where-Object {$_.name -eq $regitem} -ErrorAction SilentlyContinue
        if($thisVpn)
        {
            $regValue = Get-ItemPropertyValue -path $regEditPath -name $regitem -ErrorAction SilentlyContinue

            if($regValue)
            {
                #Generating response
                $connectionName = $regitem
                $description = "Point to Site VPN to Azure Virtual Network '"+ $regValue.split(":")[3]+"'"
                $connectionStatus = $thisVpn.ConnectionStatus
                $tunnelType = $thisVpn.TunnelType
                $vNetGatewayAddress = $thisVpn.ServerAddress
                $subscription = $regValue.split(":")[0]
                $resourceGroup = $regValue.split(":")[1]
                $vNetGateway = $regValue.split(":")[2]
                $virtualNetwork = $regValue.split(":")[3]
                $localNetworkAddressSpace = $regValue.split(":")[4]
                $location = $regValue.split(":")[5]

                #Preparing Object
                $myResponse = New-Object -TypeName psobject
                $myResponse | Add-Member -MemberType NoteProperty -Name 'Name' -Value $connectionName -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'Description' -Value $description -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'ConnectionStatus' -Value $connectionStatus -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'TunnelType' -Value $tunnelType -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'VnetGatewayAddress' -Value $vNetGatewayAddress -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'Subscription' -Value $subscription -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'ResourceGroup' -Value $resourceGroup -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'VnetGateway' -Value $vNetGateway -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'VirtualNetwork' -Value $virtualNetwork -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'LocalNetworkAddressSpace' -Value $localNetworkAddressSpace -ErrorAction SilentlyContinue
                $myResponse | Add-Member -MemberType NoteProperty -Name 'Location' -Value $location -ErrorAction SilentlyContinue


                $myResponse
            }
        }
    }
}
Catch [Exception]{
    $myResponse = "Failed"
    $myResponse
}

}
## [END] Get-WACNSVpnConnections ##
function New-WACNSLogMyEvent {
<#

.SYNOPSIS
Logging My Event in Event Log

.DESCRIPTION
Logging My Event in Event Log

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $LogMessage
)
#Function to log event
function Log-MyEvent($Message){
    Try {
        $eventLogName = "ANA-LOG"
        $eventID = Get-Random -Minimum -1 -Maximum 65535
        #Create WAC specific Event Source if not exists
        $logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $eventLogName} 
        if (!$logFileExists) {
            New-EventLog -LogName $eventLogName -Source $eventLogName
        }
        #Prepare Event Log content and Write Event Log
        Write-EventLog -LogName $eventLogName -Source $eventLogName -EntryType Information -EventID $eventID -Message $Message

        $result = "Success"
    }
    Catch [Exception] {
        $result = $_.Exception.Message
    }
}

Log-MyEvent -Message "$LogMessage" 

}
## [END] New-WACNSLogMyEvent ##
function New-WACNSRegEditNotConfigured {
<#

.SYNOPSIS
Writing Virtual Network Gateway information into Event Log

.DESCRIPTION
This Script is used to store newly created Virtual Network Gateway information into Event Log

.ROLE
Administrators

#>
Param(
    [Parameter(Mandatory = $true)]
    [string] $Subscription,
    [Parameter(Mandatory = $true)]
    [string] $ResourceGroup,
    [Parameter(Mandatory = $true)]
    [string] $VNetGateway
)

$result = ""
Try {
    
    #Create Registry Key and add Value to it
    if(!(get-item -Path HKLM:\Software\WAC\VNetGatewayNotConfigured -ErrorAction SilentlyContinue))
    {
        $regKeyCreated = New-Item -Path HKLM:\Software -Name WAC\VNetGatewayNotConfigured -Force
    }
    $regKeyValue = $Subscription + ":" + $ResourceGroup + ":" + $VNetGateway
    Set-ItemProperty -Path HKLM:\Software\WAC\VNetGatewayNotConfigured -Name $VNetGateway -Value $regKeyValue
    
    $result = "Success"
}
Catch {
    $result = "Failed"
}
$result
}
## [END] New-WACNSRegEditNotConfigured ##
function New-WACNSSelfSignedRootCertificate {
<#

.SYNOPSIS
Create a Self-Signed Root certificate & Client Certificate

.DESCRIPTION
This script creates a Self-Signed Root certificate
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $VNetGatewayName
   
)
$content=""
Try
{
    #Finalizing name of the certificate
    $uniqueRootCertName = $VNetGatewayName+'-P2SRoot-'+(Get-Date -UFormat "%m%d%Y%H%M")
    $uniqueClientCertName = $VNetGatewayName+'-P2SClient-'+(Get-Date -UFormat "%m%d%Y%H%M")

    #Creating Root Certificate
    $myCert = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=$uniqueRootCertName" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -KeyUsageProperty Sign -KeyUsage CertSign

    #Creating client certificate
    $myClientCert = New-SelfSignedCertificate -Type Custom -DnsName $uniqueClientCertName -KeySpec Signature -Subject "CN=$uniqueClientCertName" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -Signer $myCert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") 

    #Create a Temp Folder if not exists
    $tempPath = "C:\WAC-TEMP"
    if (!(Test-Path $tempPath)) {
       $tempfolderCreated = New-Item -Path $tempPath -ItemType directory
    }

    #Moving Root certificate from 'Cert:\LocalMachine\My' to 'Cert:\LocalMachine\Root'
    $exportLocation = $tempPath+"\$uniqueRootCertName.cer"
    $certExported = Export-Certificate -cert $myCert -filepath $exportLocation
    $certImported = Import-Certificate -FilePath $exportLocation -certstorelocation 'cert:\LocalMachine\Root'

    #Get Base64 Certificate Content
    $content = @(
		[System.Convert]::ToBase64String($myCert.RawData, 'InsertLineBreaks')
    )

    #Deleting temporary exported certificate file
    if (Test-Path $exportLocation) {
         Remove-Item -path $exportLocation -Force -Recurse -ErrorAction SilentlyContinue
    }
}
Catch [Exception]
{
    $content = $_.Exception.Message
}

$Result = New-Object System.Object
$Result | Add-Member -MemberType NoteProperty -Name 'RootCertName' -Value $uniqueRootCertName
$Result | Add-Member -MemberType NoteProperty -Name 'Content' -Value $content
$Result

}
## [END] New-WACNSSelfSignedRootCertificate ##
function New-WACNSTempFolder {
<#

.SYNOPSIS
Create a Temporary Folder in C drive of Target server

.DESCRIPTION
This script creates a Temporary Folder in C drive of Target server

.ROLE
Administrators

#>
$tempPath = "C:\WAC-TEMP"
if (!(Test-Path $tempPath)) {
    $tempFolderCreated = New-Item -Path $tempPath -ItemType directory
}
$tempPath
}
## [END] New-WACNSTempFolder ##
function Remove-WACNSNotConfiguredGateway {
<#

.SYNOPSIS
Remove Not found gateway or not valid provisioning status of Gateway entry from VNetGatewayNotConfigured RegEdit

.DESCRIPTION
This script is used to Remove Not found gateway or not valid provisioning status of Gateway entry from VNetGatewayNotConfigured RegEdit

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $VNetGatewayName,
    [Parameter(Mandatory = $true)]
    [String]
    $TenantId,
    [Parameter(Mandatory = $true)]
    [String]
    $AppId
)
#Function to log event
function Log-MyEvent($Message) {
    Try {
        $eventLogName = "ANA-LOG"
        $eventID = Get-Random -Minimum -1 -Maximum 65535
        #Create WAC specific Event Source if not exists
        $logFileExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $eventLogName} 
        if (!$logFileExists) {
            New-EventLog -LogName $eventLogName -Source $eventLogName
        }
        #Prepare Event Log content and Write Event Log
        Write-EventLog -LogName $eventLogName -Source $eventLogName -EntryType Information -EventID $eventID -Message $Message

        $result = "Success"
    }
    Catch [Exception] {
        $result = $_.Exception.Message
    }
}

Log-MyEvent -Message "Gateway $VNetGatewayName doesn't exists or in failed state. so deleting this Gateway. Directory ID- $TenantId and App Id- $AppId" 
Remove-ItemProperty -path HKLM:\Software\WAC\VNetGatewayNotConfigured -name $VNetGatewayName
Log-MyEvent -Message "Gateway $VNetGatewayName has been deleted" 
}
## [END] Remove-WACNSNotConfiguredGateway ##
function Remove-WACNSVpnConnection {
<#

.SYNOPSIS
Remove VPN Connection

.DESCRIPTION
This script is used to remove VPN Connection

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $ConnectionName
   
)
#Removing VPN Connection
Remove-VpnConnection -Name $ConnectionName -Force

#Removing Item from RegEdit
Remove-ItemProperty -path HKLM:\Software\WAC\VPNConfigured -name $ConnectionName
}
## [END] Remove-WACNSVpnConnection ##
function Set-WACNSDhcpIP {
<#

.SYNOPSIS
Sets configuration of the specified network interface to use DHCP and updates DNS settings.

.DESCRIPTION
Sets configuration of the specified network interface to use DHCP and updates DNS settings. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)] [string] $interfaceIndex,
    [Parameter(Mandatory = $true)] [string] $addressFamily,
    [string] $preferredDNS,
    [string] $alternateDNS)

Import-Module NetTCPIP

$ErrorActionPreference = 'Stop'

$ipInterface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
$netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue
if ($addressFamily -eq "IPv4") {
    $prefix = '0.0.0.0/0'
}
else {
    $prefix = '::/0'
}

$netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue

# avoid extra work if dhcp already set up
if ($ipInterface.Dhcp -eq 'Disabled') {
    if ($netIPAddress) {
        $netIPAddress | Remove-NetIPAddress -Confirm:$false
    }
    if ($netRoute) {
        $netRoute | Remove-NetRoute -Confirm:$false
    }

    $ipInterface | Set-NetIPInterface -DHCP Enabled
}

# reset or configure dns servers
$interfaceAlias = $ipInterface.InterfaceAlias
if ($preferredDNS) {
    netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
    if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
        netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
    }
}
else {
    netsh.exe interface $addressFamily delete dnsservers name="$interfaceAlias" address=all
}

# captures exit code of netsh.exe
$LASTEXITCODE

}
## [END] Set-WACNSDhcpIP ##
function Set-WACNSP2SVPNStatus {
<#

.SYNOPSIS
Connect / Disconnect P2S VPN

.DESCRIPTION
This script is used to Connect / Disconnect P2S VPN

.ROLE
Administrators

#>
param(
    [Parameter(Mandatory = $true)]
    [String]
    $VpnProfileName,
    [Parameter(Mandatory = $true)]
    [Int]
    $StatusFlag
    #Flag "1" is to Connect VPN. Flaf "0" to disconnect VPN.
)
if($StatusFlag -eq 1)
{
    #Connect VPN
	$result = rasdial $VpnProfileName
	$result = [String] $result
}
Elseif($StatusFlag -eq 0)
{
    #Disconnect VPN
    $result =  rasdial $VpnProfileName /disconnect
    $result= [String] $result
}
else
{
    $result = "No flag provided. Use 1 to connect and 0 to disconnect"
}
$statusProperty = "success"
$contentProperty = $result

if($result -match 'error' -or $result -match 'unacceptable' -or $result -match 'not')
{
	$statusProperty = "error"
}

#Preparing response Object
$response = New-Object System.Object
$response | Add-Member -MemberType NoteProperty -Name 'status' -Value $statusProperty
$response | Add-Member -MemberType NoteProperty -Name 'content' -Value $contentProperty
$response
}
## [END] Set-WACNSP2SVPNStatus ##
function Set-WACNSStaticIP {
<#

.SYNOPSIS
Sets configuration of the specified network interface to use a static IP address and updates DNS settings.

.DESCRIPTION
Sets configuration of the specified network interface to use a static IP address and updates DNS settings. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)] [string] $interfaceIndex,
    [Parameter(Mandatory = $true)] [string] $ipAddress,
    [Parameter(Mandatory = $true)] [string] $prefixLength,
    [string] $defaultGateway,
    [string] $preferredDNS,
    [string] $alternateDNS,
    [Parameter(Mandatory = $true)] [string] $addressFamily)

Import-Module NetTCPIP

Set-StrictMode -Version 5.0
$ErrorActionPreference = 'Stop'

$netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue

if ($addressFamily -eq "IPv4") {
    $prefix = '0.0.0.0/0'
}
else {
    $prefix = '::/0'
}

$netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue

if ($netIPAddress) {
    $netIPAddress | Remove-NetIPAddress -Confirm:$false
}
if ($netRoute) {
    $netRoute | Remove-NetRoute -Confirm:$false
}

Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -DHCP Disabled

try {
    # this will fail if input is invalid
    if ($defaultGateway) {
        $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily $addressFamily -ErrorAction Stop
    }
    else {
        $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -AddressFamily $addressFamily -ErrorAction Stop
    }
}
catch {
    # restore net route and ip address to previous values
    if ($netRoute -and $netIPAddress) {
        $netIPAddress | New-NetIPAddress -DefaultGateway $netRoute.NextHop -PrefixLength $netIPAddress.PrefixLength
    }
    elseif ($netIPAddress) {
        $netIPAddress | New-NetIPAddress
    }
    throw
}

$interfaceAlias = $netIPAddress.InterfaceAlias
if ($preferredDNS) {
    netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
    if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
        netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
    }
    return $LASTEXITCODE
}
else {
    return 0
}



}
## [END] Set-WACNSStaticIP ##
function Add-WACNSAdministrators {
<#

.SYNOPSIS
Adds administrators

.DESCRIPTION
Adds administrators

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory=$true)]
    [String] $usersListString
)


$usersToAdd = ConvertFrom-Json $usersListString
$adminGroup = Get-LocalGroup | Where-Object SID -eq 'S-1-5-32-544'

Add-LocalGroupMember -Group $adminGroup -Member $usersToAdd

Register-DnsClient -Confirm:$false

}
## [END] Add-WACNSAdministrators ##
function Disconnect-WACNSAzureHybridManagement {
<#

.SYNOPSIS
Disconnects a machine from azure hybrid agent.

.DESCRIPTION
Disconnects a machine from azure hybrid agent and uninstall the hybrid instance service.
The supported Operating Systems are Windows Server 2012 R2 and above.

.ROLE
Administrators

.PARAMETER tenantId
    The GUID that identifies a tenant in AAD

.PARAMETER authToken
    The authentication token for connection

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $tenantId,
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
    Remove-Variable -Name HybridAgentPackage -Scope Script -Force
}

<#

.SYNOPSIS
The main function.

.DESCRIPTION
Disconnects a machine from azure hybrid agent.

#>

function main(
    [string]$tenantId,
    [string]$authToken
) {
    $err = $null
    $args = @{}

   # Disconnect Azure hybrid agent
   & $HybridAgentExecutable disconnect --access-token $authToken

   # Uninstall Azure hybrid instance metadata service
   Uninstall-Package -Name $HybridAgentPackage -ErrorAction SilentlyContinue -ErrorVariable +err

   if ($err) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not uninstall the package. Error: $err"  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        throw $err
   }

}


###############################################################################
# Script execution starts here
###############################################################################
setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $tenantId $authToken

    return @()
} finally {
    cleanupScriptEnv
}

}
## [END] Disconnect-WACNSAzureHybridManagement ##
function Get-WACNSAzureHybridManagementConfiguration {
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
    $config = & $HybridAgentExecutable show

    if (-not $config) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue
        return @()
    }

    $configData = @{}

    foreach ($item in $config) {
        if ($item -match '^\s*(.*?):\s*(.*)$') {
            $key = getKey($matches[1].Trim())
            $value = $matches[2].Trim()
            $configData[$key] = $value
        }
    }

    if ($configData.Count -gt 0) {
        return @{
            machine = $configData['ResourceName'];
            resourceGroup = $configData['ResourceGroupName'];
            subscriptionId = $configData['SubscriptionID'];
            tenantId = $configData['TenantID'];
            vmId = $configData['VMID'];
            azureRegion = $configData['Location'];
            agentVersion = $configData['AgentVersion'];
            agentStatus = $configData['AgentStatus'];
            agentLastHeartbeat = $configData['AgentLastHeartbeat'];
            agentErrorDetails = $configData['AgentErrorDetails'];
            agentErrorCode = $configData['AgentErrorCode'];
        }
    } else {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message "[$ScriptName]:Could not find the Azure hybrid agent configuration."  -ErrorAction SilentlyContinue

        Write-Error @($err)[0]
        return @()
    }
}

function getKey([string]$key) {
    # Modify key names based on first three/two words if the words > 1 else pick first word as the key
    $newKey = ""
    $words = $key -split '\s+'
    if ($words.Count -ge 3) {
        $newKey = $words[0] + $words[1] + $words[2]
    } elseif ($words.Count -eq 2) {
        $newKey = $words[0] + $words[1]
    } else {
        $newKey = $words[0]
    }
    return $newKey
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
## [END] Get-WACNSAzureHybridManagementConfiguration ##
function Get-WACNSAzureHybridManagementOnboardState {
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
## [END] Get-WACNSAzureHybridManagementOnboardState ##
function Get-WACNSCimServiceDetail {
<#

.SYNOPSIS
Gets services in details using MSFT_ServerManagerTasks class.

.DESCRIPTION
Gets services in details using MSFT_ServerManagerTasks class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
)

import-module CimCmdlets

Invoke-CimMethod -Namespace root/microsoft/windows/servermanager -ClassName MSFT_ServerManagerTasks -MethodName GetServerServiceDetail

}
## [END] Get-WACNSCimServiceDetail ##
function Get-WACNSCimSingleService {
<#

.SYNOPSIS
Gets the service instance of CIM Win32_Service class.

.DESCRIPTION
Gets the service instance of CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Get-CimInstance $keyInstance

}
## [END] Get-WACNSCimSingleService ##
function Resolve-WACNSDNSName {
<#

.SYNOPSIS
Resolve VM Provisioning

.DESCRIPTION
Resolve VM Provisioning

.ROLE
Administrators

#>

Param
(
    [string] $computerName
)

$succeeded = $null
$count = 0;
$maxRetryTimes = 15 * 100 # 15 minutes worth of 10 second sleep times
while ($count -lt $maxRetryTimes)
{
  $resolved =  Resolve-DnsName -Name $computerName -ErrorAction SilentlyContinue

    if ($resolved)
    {
      $succeeded = $true
      break
    }

    $count += 1

    if ($count -eq $maxRetryTimes)
    {
        $succeeded = $false
    }

    Start-Sleep -Seconds 10
}

Write-Output @{ "succeeded" = $succeeded }

}
## [END] Resolve-WACNSDNSName ##
function Resume-WACNSCimService {
<#

.SYNOPSIS
Resume a service using CIM Win32_Service class.

.DESCRIPTION
Resume a service using CIM Win32_Service class.

.ROLE
Readers

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName ResumeService

}
## [END] Resume-WACNSCimService ##
function Set-WACNSAzureHybridManagement {
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
    The correlation ID for the connection

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
    [Parameter(Mandatory = $true)]
    [string]
    $correlationId
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
    & $HybridAgentExecutable connect --resource-group $resourceGroup --tenant-id $tenantId --location $azureRegion `
                                     --subscription-id $subscriptionId --access-token $authToken --correlation-id $correlationId

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
## [END] Set-WACNSAzureHybridManagement ##
function Set-WACNSVMPovisioning {
<#

.SYNOPSIS
Prepare VM Provisioning

.DESCRIPTION
Prepare VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [array]$disks
)

$output = @{ }

$requiredDriveLetters = $disks.driveLetter
$volumeLettersInUse = (Get-Volume | Sort-Object DriveLetter).DriveLetter

$output.Set_Item('restartNeeded', $false)
$output.Set_Item('pageFileLetterChanged', $false)
$output.Set_Item('pageFileLetterNew', $null)
$output.Set_Item('pageFileLetterOld', $null)
$output.Set_Item('pageFileDiskNumber', $null)
$output.Set_Item('cdDriveLetterChanged', $false)
$output.Set_Item('cdDriveLetterNew', $null)
$output.Set_Item('cdDriveLetterOld', $null)

$cdDriveLetterNeeded = $false
$cdDrive = Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Microsoft.PowerShell.Utility\Select-Object -First 1
if ($cdDrive -ne $null) {
    $cdDriveLetter = $cdDrive.DriveLetter.split(':')[0]
    $output.Set_Item('cdDriveLetterOld', $cdDriveLetter)

    if ($requiredDriveLetters.Contains($cdDriveLetter)) {
        $cdDriveLetterNeeded = $true
    }
}

$pageFileLetterNeeded = $false
$pageFile = Get-WmiObject Win32_PageFileusage
if ($pageFile -ne $null) {
    $pagingDriveLetter = $pageFile.Name.split(':')[0]
    $output.Set_Item('pageFileLetterOld', $pagingDriveLetter)

    if ($requiredDriveLetters.Contains($pagingDriveLetter)) {
        $pageFileLetterNeeded = $true
    }
}

if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $capitalCCharNumber = 67;
    $capitalZCharNumber = 90;

    for ($index = $capitalCCharNumber; $index -le $capitalZCharNumber; $index++) {
        $tempDriveLetter = [char]$index

        $willConflict = $requiredDriveLetters.Contains([string]$tempDriveLetter)
        $inUse = $volumeLettersInUse.Contains($tempDriveLetter)
        if (!$willConflict -and !$inUse) {
            if ($cdDriveLetterNeeded) {
                $output.Set_Item('cdDriveLetterNew', $tempDriveLetter)
                $cdDrive | Set-WmiInstance -Arguments @{DriveLetter = $tempDriveLetter + ':' } > $null
                $output.Set_Item('cdDriveLetterChanged', $true)
                $cdDriveLetterNeeded = $false
            }
            elseif ($pageFileLetterNeeded) {

                $computerObject = Get-WmiObject Win32_computersystem -EnableAllPrivileges
                $computerObject.AutomaticManagedPagefile = $false
                $computerObject.Put() > $null

                $currentPageFile = Get-WmiObject Win32_PageFilesetting
                $currentPageFile.delete() > $null

                $diskNumber = (Get-Partition -DriveLetter $pagingDriveLetter).DiskNumber

                $output.Set_Item('pageFileLetterNew', $tempDriveLetter)
                $output.Set_Item('pageFileDiskNumber', $diskNumber)
                $output.Set_Item('pageFileLetterChanged', $true)
                $output.Set_Item('restartNeeded', $true)
                $pageFileLetterNeeded = $false
            }

        }
        if (!$cdDriveLetterNeeded -and !$pageFileLetterNeeded) {
            break
        }
    }
}

# case where not enough drive letters available after iterating through C-Z
if ($cdDriveLetterNeeded -or $pageFileLetterNeeded) {
    $output.Set_Item('preProvisioningSucceeded', $false)
}
else {
    $output.Set_Item('preProvisioningSucceeded', $true)
}


Write-Output $output


}
## [END] Set-WACNSVMPovisioning ##
function Start-WACNSCimService {
<#

.SYNOPSIS
Start a service using CIM Win32_Service class.

.DESCRIPTION
Start a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName StartService

}
## [END] Start-WACNSCimService ##
function Start-WACNSVMProvisioning {
<#

.SYNOPSIS
Execute VM Provisioning

.DESCRIPTION
Execute VM Provisioning

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [bool] $partitionDisks,

    [Parameter(Mandatory = $true)]
    [array]$disks,

    [Parameter(Mandatory = $true)]
    [bool]$pageFileLetterChanged,

    [Parameter(Mandatory = $false)]
    [string]$pageFileLetterNew,

    [Parameter(Mandatory = $false)]
    [int]$pageFileDiskNumber,

    [Parameter(Mandatory = $true)]
    [bool]$systemDriveModified
)

$output = @{ }

$output.Set_Item('restartNeeded', $pageFileLetterChanged)

if ($pageFileLetterChanged) {
    Get-Partition -DiskNumber $pageFileDiskNumber | Set-Partition -NewDriveLetter $pageFileLetterNew
    $newPageFile = $pageFileLetterNew + ':\pagefile.sys'
    Set-WMIInstance -Class Win32_PageFileSetting -Arguments @{name = $newPageFile; InitialSize = 0; MaximumSize = 0 } > $null
}

if ($systemDriveModified) {
    $size = Get-PartitionSupportedSize -DriveLetter C
    Resize-Partition -DriveLetter C -Size $size.SizeMax > $null
}

if ($partitionDisks -eq $true) {
    $dataDisks = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number
    for ($index = 0; $index -lt $dataDisks.Length; $index++) {
        Initialize-Disk  $dataDisks[$index].DiskNumber -PartitionStyle GPT -PassThru |
        New-Partition -Size $disks[$index].volumeSizeInBytes -DriveLetter $disks[$index].driveLetter |
        Format-Volume -FileSystem $disks[$index].fileSystem -NewFileSystemLabel $disks[$index].name -Confirm:$false -Force > $null;
    }
}

Write-Output $output

}
## [END] Start-WACNSVMProvisioning ##
function Suspend-WACNSCimService {
<#

.SYNOPSIS
Suspend a service using CIM Win32_Service class.

.DESCRIPTION
Suspend a service using CIM Win32_Service class.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$Name
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName PauseService

}
## [END] Suspend-WACNSCimService ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAqM2ML7oTJ66Jb
# qPI/2v33x4kXAKA7Y6PzpmrzR61GAKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGML58Mi+6lpauHmW7Y8Dk0u
# /E8nWaBYmZi9h2YdxeB/MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAUXX83IGkJbKSf0J0YPg5MIiZC0gOMG7pPuKvoNyb2zOiPTmpXtaEA4RQ
# fp02OnuiVbIuHSH2z7VABpRyKvUokG3ux70Q/X4/sli0ReH9HsmgvWjIUPNdkRGy
# 01ga+WQ54akrqw3NeLe2hvbpQk4bYOxoNJuVFhULA13DL13vyd9cJ1n431f7Hd51
# NgJMvPeXtFid0m9wbNoxGFi9wp9tJFJ4CxYO0SxyOfWbEBZub1lYWBK7rH7KRoVZ
# v20NF/VNu8ecoUD/sa2R3/vZycVf1++tfuDL07OGF7WdeNiU5Q8405by507apdIv
# elvKHFsFChsfBkYiL4G93dbGXblZoqGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDJdgRaMIZsnTykDTBStq3KytQDgJdW/bEM6E3oYzsBjQIGaPCDIpUy
# GBMyMDI1MTExMDE3MTY0Mi41NjRaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# MC8GCSqGSIb3DQEJBDEiBCAt8CAPkEMCZVVTNzR2w8pnwGFu7USePJL5WZmVc2ey
# TjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIE2ay/y0epK/X3Z03KTcloqE
# 8u9IXRtdO7Mex0hw9+SaMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIKR7IU2e6ysw8AAQAAAgowIgQgl7M7lF6SJNEDfsIAyNIJMwba
# dk3UE3kNzaUgIEBT6kkwDQYJKoZIhvcNAQELBQAEggIAgXnkMKEqpIatMZMNPH1y
# ljImZjlReMAAKsz2tnvc4ChmdXuIrmR7rA3UOJy1ASIC8qrt/ZhV4j50tuIVCm10
# Y7DyYEWvWIhn3PvwrwkjmP9/+qmPIXubtlYOLW+cjt+xaThbYwqMRvqiO1doGNOB
# ddTEZFuUllmiAG20TP7THqeYG7vsXcKJiSlWBqlWE8RLwVBBNqjqyCLCt2bzlM2+
# b8el56zSLbxQOX2Lq8sgVD117++3VgMD5eigB9GQz9QEWDkxCOUcC+4os6hNPETL
# 9Lop8JFqXPhsnbWDl6/AfDgA6FkLFnLA4tVYr9UDMHrvxHp//rBpPf5GdvyhiiVl
# D4rBzx+DO/WDhXBXOSiLfMi+34yhbFI1iNWTtS8S2MteMU2KvFqiIf7pYCIWjvcf
# nC55xXAsyIgQLxODfYN+DajBzyfZ4CnVtPeIQU5EdBcJQHDZ7atOJzJfjIJEwE42
# w9pXiEgABqR1JCFHvTJlg9QgnbfOGBQIFURJa6mDb4oysWNXnaZd+VmPZRTXfa86
# a/vS1PT6kP5Kcs0LTH2pusKIOQkwo6ld8nRrhwBtq+3wNl4YNItn5gdk0QQwglNG
# JWosVUp83ARU1vUiclFW40coiKQAQ71uXquwiaRn1ZqkTdlze8nW5tdXN4Vxiq87
# ozKK1CJLR1nXmdbrpbBlidw=
# SIG # End signature block
