function Add-WACFCCauClusterRole {
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
## [END] Add-WACFCCauClusterRole ##
function Add-WACFCSmeClusterNodes {
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
## [END] Add-WACFCSmeClusterNodes ##
function Disable-WACFCCauClusterRole {
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
## [END] Disable-WACFCCauClusterRole ##
function Enable-WACFCCauClusterRole {
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
## [END] Enable-WACFCCauClusterRole ##
function Find-WACFCClusterUpdateModule {
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
## [END] Find-WACFCClusterUpdateModule ##
function Find-WACFCCommandProperty {
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
## [END] Find-WACFCCommandProperty ##
function Find-WACFCUrpStatus {
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
## [END] Find-WACFCUrpStatus ##
function Get-WACFCAvailableClusterUpdates {

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
## [END] Get-WACFCAvailableClusterUpdates ##
function Get-WACFCAvailableFeatureUpdates {
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
## [END] Get-WACFCAvailableFeatureUpdates ##
function Get-WACFCCPUAvailabilityPreCheck {
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
## [END] Get-WACFCCPUAvailabilityPreCheck ##
function Get-WACFCClusterReportList {
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
## [END] Get-WACFCClusterReportList ##
function Get-WACFCClusterReportResult {
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
## [END] Get-WACFCClusterReportResult ##
function Get-WACFCDiskSpaceOnVolumePreCheck {
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
## [END] Get-WACFCDiskSpaceOnVolumePreCheck ##
function Get-WACFCIsDellApexCp {
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
## [END] Get-WACFCIsDellApexCp ##
function Get-WACFCKsrClusterProperty {
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
## [END] Get-WACFCKsrClusterProperty ##
function Get-WACFCLastCauReport {
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
## [END] Get-WACFCLastCauReport ##
function Get-WACFCMSCluster_Cluster {
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
## [END] Get-WACFCMSCluster_Cluster ##
function Get-WACFCMSCluster_Node {
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
## [END] Get-WACFCMSCluster_Node ##
function Get-WACFCMemoryAvailabilityPreCheck {
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
## [END] Get-WACFCMemoryAvailabilityPreCheck ##
function Get-WACFCOSBuildnumber {
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
## [END] Get-WACFCOSBuildnumber ##
function Get-WACFCReleaseChannelPreCheck {
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
## [END] Get-WACFCReleaseChannelPreCheck ##
function Get-WACFCRunDetails {
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
## [END] Get-WACFCRunDetails ##
function Get-WACFCSmbFileShareDetailsFC {
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
## [END] Get-WACFCSmbFileShareDetailsFC ##
function Get-WACFCSmeClientAccessPointIsAvailable {
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
## [END] Get-WACFCSmeClientAccessPointIsAvailable ##
function Get-WACFCSmeClusterDisk {
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
## [END] Get-WACFCSmeClusterDisk ##
function Get-WACFCSmeClusterDiskVolume {
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
## [END] Get-WACFCSmeClusterDiskVolume ##
function Get-WACFCSmeClusterGroup {
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
## [END] Get-WACFCSmeClusterGroup ##
function Get-WACFCSmeClusterGroupFailoverSettings {
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
## [END] Get-WACFCSmeClusterGroupFailoverSettings ##
function Get-WACFCSmeClusterGroupGeneralSettings {
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
## [END] Get-WACFCSmeClusterGroupGeneralSettings ##
function Get-WACFCSmeClusterNetwork {
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
## [END] Get-WACFCSmeClusterNetwork ##
function Get-WACFCSmeClusterNetworkInterface {
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
## [END] Get-WACFCSmeClusterNetworkInterface ##
function Get-WACFCSmeClusterNode {
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
## [END] Get-WACFCSmeClusterNode ##
function Get-WACFCSmeClusterNodeFQDN {
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
## [END] Get-WACFCSmeClusterNodeFQDN ##
function Get-WACFCSmeClusterProperties {
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
## [END] Get-WACFCSmeClusterProperties ##
function Get-WACFCSmeClusterRequiredFeatures {
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
## [END] Get-WACFCSmeClusterRequiredFeatures ##
function Get-WACFCSmeClusterResource {
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
## [END] Get-WACFCSmeClusterResource ##
function Get-WACFCSmeClusterStatus {
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
## [END] Get-WACFCSmeClusterStatus ##
function Get-WACFCSmeNodeCurrentVersion {
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
## [END] Get-WACFCSmeNodeCurrentVersion ##
function Get-WACFCSolutionUpdate {
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
## [END] Get-WACFCSolutionUpdate ##
function Get-WACFCSolutionUpdateEnvironment {
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
## [END] Get-WACFCSolutionUpdateEnvironment ##
function Get-WACFCSolutionUpdateRun {
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
## [END] Get-WACFCSolutionUpdateRun ##
function Get-WACFCSolutionUpdateRunAll {
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
## [END] Get-WACFCSolutionUpdateRunAll ##
function Get-WACFCSolutionUpdateRunAllXml {
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
## [END] Get-WACFCSolutionUpdateRunAllXml ##
function Get-WACFCSolutionUpdateRunXml {
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
## [END] Get-WACFCSolutionUpdateRunXml ##
function Get-WACFCUpdatesHistory {
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
## [END] Get-WACFCUpdatesHistory ##
function Get-WACFCVirtualDiskPreCheck {
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
## [END] Get-WACFCVirtualDiskPreCheck ##
function Install-WACFCRsatFailoverClusterFoD {
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
## [END] Install-WACFCRsatFailoverClusterFoD ##
function Install-WACFCSmeClusterCmdlets {
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
## [END] Install-WACFCSmeClusterCmdlets ##
function Move-WACFCSmeClusterGroup {
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
## [END] Move-WACFCSmeClusterGroup ##
function New-WACFCSmeCluster {
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
## [END] New-WACFCSmeCluster ##
function New-WACFCSmeClusterGroup {
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
## [END] New-WACFCSmeClusterGroup ##
function Remove-WACFCSmeCluster {
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
## [END] Remove-WACFCSmeCluster ##
function Remove-WACFCSmeClusterGroup {
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
## [END] Remove-WACFCSmeClusterGroup ##
function Remove-WACFCSmeClusterNode {
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
## [END] Remove-WACFCSmeClusterNode ##
function Remove-WACFCSmeClusterResource {
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
## [END] Remove-WACFCSmeClusterResource ##
function Rename-WACFCSmeClusterGroup {
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
## [END] Rename-WACFCSmeClusterGroup ##
function Resume-WACFCSmeClusterNode {
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
## [END] Resume-WACFCSmeClusterNode ##
function Set-WACFCSmeClusterGroupFailoverSettings {
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
## [END] Set-WACFCSmeClusterGroupFailoverSettings ##
function Set-WACFCSmeClusterGroupGeneralSettings {
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
## [END] Set-WACFCSmeClusterGroupGeneralSettings ##
function Set-WACFCSmeClusterGroupStartupPriority {
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
## [END] Set-WACFCSmeClusterGroupStartupPriority ##
function Set-WACFCVcoAdmin {
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
## [END] Set-WACFCVcoAdmin ##
function Start-WACFCClusterUpdateRun {

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
## [END] Start-WACFCClusterUpdateRun ##
function Start-WACFCSmeClusterGroup {
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
## [END] Start-WACFCSmeClusterGroup ##
function Start-WACFCSmeClusterResource {
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
## [END] Start-WACFCSmeClusterResource ##
function Start-WACFCSmeClusterService {
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
## [END] Start-WACFCSmeClusterService ##
function Start-WACFCSolutionUpdate {
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
## [END] Start-WACFCSolutionUpdate ##
function Stop-WACFCClusterUpdateRun {

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
## [END] Stop-WACFCClusterUpdateRun ##
function Stop-WACFCSmeClusterGroup {
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
## [END] Stop-WACFCSmeClusterGroup ##
function Stop-WACFCSmeClusterResource {
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
## [END] Stop-WACFCSmeClusterResource ##
function Stop-WACFCSmeClusterService {
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
## [END] Stop-WACFCSmeClusterService ##
function Suspend-WACFCSmeClusterNode {
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
## [END] Suspend-WACFCSmeClusterNode ##
function Test-WACFCClusterAwareUpdatingRole {
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
## [END] Test-WACFCClusterAwareUpdatingRole ##
function Test-WACFCClusterUpdateReadiness {
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
## [END] Test-WACFCClusterUpdateReadiness ##
function Test-WACFCSmeCluster {
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
## [END] Test-WACFCSmeCluster ##
function Test-WACFCSmeClusterResourceFailure {
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
## [END] Test-WACFCSmeClusterResourceFailure ##
function Update-WACFCClusterFunctionalLevel {
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
## [END] Update-WACFCClusterFunctionalLevel ##
function Add-WACFCFolderShare {
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
## [END] Add-WACFCFolderShare ##
function Add-WACFCFolderShareNameUser {
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
## [END] Add-WACFCFolderShareNameUser ##
function Add-WACFCFolderShareUser {
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
## [END] Add-WACFCFolderShareUser ##
function Compress-WACFCArchiveFileSystemEntity {
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
## [END] Compress-WACFCArchiveFileSystemEntity ##
function Disable-WACFCKdcProxy {
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
## [END] Disable-WACFCKdcProxy ##
function Disable-WACFCSmbOverQuic {
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
## [END] Disable-WACFCSmbOverQuic ##
function Dismount-WACFCStorageVHD {
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
## [END] Dismount-WACFCStorageVHD ##
function Edit-WACFCFolderShareInheritanceFlag {
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
## [END] Edit-WACFCFolderShareInheritanceFlag ##
function Edit-WACFCFolderShareUser {
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
## [END] Edit-WACFCFolderShareUser ##
function Edit-WACFCSmbFileShare {
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
## [END] Edit-WACFCSmbFileShare ##
function Edit-WACFCSmbServerCertificateMapping {
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
## [END] Edit-WACFCSmbServerCertificateMapping ##
function Edit-WACFCStorageVolume {
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
## [END] Edit-WACFCStorageVolume ##
function Enable-WACFCSmbOverQuic {
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
## [END] Enable-WACFCSmbOverQuic ##
function Expand-WACFCArchiveFileSystemEntity {
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
## [END] Expand-WACFCArchiveFileSystemEntity ##
function Format-WACFCStorageVolume {
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
## [END] Format-WACFCStorageVolume ##
function Get-WACFCBestHostNode {
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
## [END] Get-WACFCBestHostNode ##
function Get-WACFCBitLocker {
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
## [END] Get-WACFCBitLocker ##
function Get-WACFCCertificates {
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
## [END] Get-WACFCCertificates ##
function Get-WACFCComputerName {
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
## [END] Get-WACFCComputerName ##
function Get-WACFCFileNamesInPath {
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
## [END] Get-WACFCFileNamesInPath ##
function Get-WACFCFileSystemEntities {
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
## [END] Get-WACFCFileSystemEntities ##
function Get-WACFCFileSystemRoot {
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
## [END] Get-WACFCFileSystemRoot ##
function Get-WACFCFolderItemCount {
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
## [END] Get-WACFCFolderItemCount ##
function Get-WACFCFolderOwner {
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
## [END] Get-WACFCFolderOwner ##
function Get-WACFCFolderShareNames {
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
## [END] Get-WACFCFolderShareNames ##
function Get-WACFCFolderSharePath {
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
## [END] Get-WACFCFolderSharePath ##
function Get-WACFCFolderShareStatus {
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
## [END] Get-WACFCFolderShareStatus ##
function Get-WACFCFolderShareUsers {
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
## [END] Get-WACFCFolderShareUsers ##
function Get-WACFCIsAzureTurbineServer {
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
## [END] Get-WACFCIsAzureTurbineServer ##
function Get-WACFCItemProperties {
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
## [END] Get-WACFCItemProperties ##
function Get-WACFCItemType {
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
## [END] Get-WACFCItemType ##
function Get-WACFCLocalGroups {
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
## [END] Get-WACFCLocalGroups ##
function Get-WACFCLocalUsers {
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
## [END] Get-WACFCLocalUsers ##
function Get-WACFCOSDetails {
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
## [END] Get-WACFCOSDetails ##
function Get-WACFCShareEntities {
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
## [END] Get-WACFCShareEntities ##
function Get-WACFCSmb1InstallationStatus {
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
## [END] Get-WACFCSmb1InstallationStatus ##
function Get-WACFCSmbFileShareDetails {
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
## [END] Get-WACFCSmbFileShareDetails ##
function Get-WACFCSmbOverQuicSettings {
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
## [END] Get-WACFCSmbOverQuicSettings ##
function Get-WACFCSmbServerCertificateHealth {
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
## [END] Get-WACFCSmbServerCertificateHealth ##
function Get-WACFCSmbServerCertificateMapping {
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
## [END] Get-WACFCSmbServerCertificateMapping ##
function Get-WACFCSmbServerCertificateValues {
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
## [END] Get-WACFCSmbServerCertificateValues ##
function Get-WACFCSmbServerSettings {

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
## [END] Get-WACFCSmbServerSettings ##
function Get-WACFCSmbShareAccess {
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
## [END] Get-WACFCSmbShareAccess ##
function Get-WACFCStorageDisk {
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
## [END] Get-WACFCStorageDisk ##
function Get-WACFCStorageFileShare {
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
## [END] Get-WACFCStorageFileShare ##
function Get-WACFCStorageQuota {

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
## [END] Get-WACFCStorageQuota ##
function Get-WACFCStorageResizeDetails {

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
## [END] Get-WACFCStorageResizeDetails ##
function Get-WACFCStorageVolume {
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
## [END] Get-WACFCStorageVolume ##
function Get-WACFCTempFolderPath {
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
## [END] Get-WACFCTempFolderPath ##
function Initialize-WACFCStorageDisk {
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
## [END] Initialize-WACFCStorageDisk ##
function Install-WACFCStorageFSRM {

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
## [END] Install-WACFCStorageFSRM ##
function Mount-WACFCStorageVHD {
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
## [END] Mount-WACFCStorageVHD ##
function Move-WACFCFile {
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
## [END] Move-WACFCFile ##
function New-WACFCFile {
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
## [END] New-WACFCFile ##
function New-WACFCFolder {
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
## [END] New-WACFCFolder ##
function New-WACFCSmbFileShare {
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
## [END] New-WACFCSmbFileShare ##
function New-WACFCStorageQuota {
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
## [END] New-WACFCStorageQuota ##
function New-WACFCStorageVHD {
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
## [END] New-WACFCStorageVHD ##
function New-WACFCStorageVolume {
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
## [END] New-WACFCStorageVolume ##
function Remove-WACFCAllShareNames {
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
## [END] Remove-WACFCAllShareNames ##
function Remove-WACFCFileSystemEntity {
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
## [END] Remove-WACFCFileSystemEntity ##
function Remove-WACFCFolderShareUser {
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
## [END] Remove-WACFCFolderShareUser ##
function Remove-WACFCSmbServerCertificateMapping {
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
## [END] Remove-WACFCSmbServerCertificateMapping ##
function Remove-WACFCSmbShare {
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
## [END] Remove-WACFCSmbShare ##
function Remove-WACFCStorageQuota {
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
## [END] Remove-WACFCStorageQuota ##
function Remove-WACFCStorageVolume {
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
## [END] Remove-WACFCStorageVolume ##
function Rename-WACFCFileSystemEntity {
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
## [END] Rename-WACFCFileSystemEntity ##
function Resize-WACFCStorageVolume {
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
## [END] Resize-WACFCStorageVolume ##
function Restore-WACFCConfigureSmbServerCertificateMapping {
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
## [END] Restore-WACFCConfigureSmbServerCertificateMapping ##
function Set-WACFCSmbOverQuicServerSettings {
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
## [END] Set-WACFCSmbOverQuicServerSettings ##
function Set-WACFCSmbServerCertificateMapping {
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
## [END] Set-WACFCSmbServerCertificateMapping ##
function Set-WACFCSmbServerSettings {
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
## [END] Set-WACFCSmbServerSettings ##
function Set-WACFCStorageDiskOffline {
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
## [END] Set-WACFCStorageDiskOffline ##
function Test-WACFCFileSystemEntity {
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
## [END] Test-WACFCFileSystemEntity ##
function Uninstall-WACFCSmb1 {
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
## [END] Uninstall-WACFCSmb1 ##
function Update-WACFCStorageQuota {
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
## [END] Update-WACFCStorageQuota ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpyO0kF6NrPbq2
# TpunZvFmQ1uTYZ5X0VklHnpvWFM9AKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIt+R05ul8/T6oq5pSB61k2m
# C63w4pz3sbMsY77F/MW6MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAJkkmqBbwgMICt9fF1hYsW2GkLINsOtj9mMe9Ax7H041pj3Md+Nz+WPft
# 9IoOjVxXpoIWU7o4vRu8mbPlIl9GRil0THd4Z/SLaJ5k231/ffFe/Rjkc51gyMlE
# zoNtmw8MX29J60x7yMlKog+gJz/dycePtoXO6YyWiuWuW2/XpESP51X18rgNSpyz
# up7V0heHfOFHO6zz0J6XFSnqkPQ4HoDJDsBsdYNTLUscap49Q5t0Bv4u1E7JdL0e
# kjwNNUkXCfJcnTs8P2x323h/qc1M8gDPGYTJINfz2SwtORJ1Ssf3GtcnyJVTb+CY
# 6ALZ9/cRx4w8UcDkkkoQF7EY2G0/1aGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBhq/buKmJLzupHZZpMxjVtl77l+LiFIW09uK9n/4PkTwIGaPAq2iaj
# GBMyMDI1MTExMDE3MTYxOC44NzFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046REMwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgO7HlwAOGx0ygABAAACAzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NDZaFw0yNjA0MjIxOTQyNDZaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046REMwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQChl0MH5wAnOx8Uh8RtidF0J0yaFDHJYHTpPvRR16X1
# KxGDYfT8PrcGjCLCiaOu3K1DmUIU4Rc5olndjappNuOgzwUoj43VbbJx5PFTY/a1
# Z80tpqVP0OoKJlUkfDPSBLFgXWj6VgayRCINtLsUasy0w5gysD7ILPZuiQjace5K
# xASjKf2MVX1qfEzYBbTGNEijSQCKwwyc0eavr4Fo3X/+sCuuAtkTWissU64k8rK6
# 0jsGRApiESdfuHr0yWAmc7jTOPNeGAx6KCL2ktpnGegLDd1IlE6Bu6BSwAIFHr7z
# OwIlFqyQuCe0SQALCbJhsT9y9iy61RJAXsU0u0TC5YYmTSbEI7g10dYx8Uj+vh9I
# nLoKYC5DpKb311bYVd0bytbzlfTRslRTJgotnfCAIGMLqEqk9/2VRGu9klJi1j9n
# VfqyYHYrMPOBXcrQYW0jmKNjOL47CaEArNzhDBia1wXdJANKqMvJ8pQe2m8/ciby
# DM+1BVZquNAov9N4tJF4ACtjX0jjXNDUMtSZoVFQH+FkWdfPWx1uBIkc97R+xRLu
# PjUypHZ5A3AALSke4TaRBvbvTBYyW2HenOT7nYLKTO4jw5Qq6cw3Z9zTKSPQ6D5l
# yiYpes5RR2MdMvJS4fCcPJFeaVOvuWFSQ/EGtVBShhmLB+5ewzFzdpf1UuJmuOQT
# TwIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFLIpWUB+EeeQ29sWe0VdzxWQGJJ9MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCQEMbesD6TC08R0oYCdSC452AQrGf/O89G
# Q54CtgEsbxzwGDVUcmjXFcnaJSTNedBKVXkBgawRonP1LgxH4bzzVj2eWNmzGIwO
# 1FlhldAPOHAzLBEHRoSZ4pddFtaQxoabU/N1vWyICiN60It85gnF5JD4MMXyd6pS
# 8eADIi6TtjfgKPoumWa0BFQ/aEzjUrfPN1r7crK+qkmLztw/ENS7zemfyx4kGRgw
# Y1WBfFqm/nFlJDPQBicqeU3dOp9hj7WqD0Rc+/4VZ6wQjesIyCkv5uhUNy2LhNDi
# 2leYtAiIFpmjfNk4GngLvC2Tj9IrOMv20Srym5J/Fh7yWAiPeGs3yA3QapjZTtfr
# 7NfzpBIJQ4xT/ic4WGWqhGlRlVBI5u6Ojw3ZxSZCLg3vRC4KYypkh8FdIWoKirji
# dEGlXsNOo+UP/YG5KhebiudTBxGecfJCuuUspIdRhStHAQsjv/dAqWBLlhorq2OC
# aP+wFhE3WPgnnx5pflvlujocPgsN24++ddHrl3O1FFabW8m0UkDHSKCh8QTwTkYO
# wu99iExBVWlbYZRz2qOIBjL/ozEhtCB0auKhfTLLeuNGBUaBz+oZZ+X9UAECoMhk
# ETjb6YfNaI1T7vVAaiuhBoV/JCOQT+RYZrgykyPpzpmwMNFBD1vdW/29q9nkTWoE
# hcEOO0L9NzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkRDMDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDN
# rxRX/iz6ss1lBCXG8P1LFxD0e6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LxEVDAiGA8yMDI1MTExMDExMDAz
# NloYDzIwMjUxMTExMTEwMDM2WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvERU
# AgEAMAoCAQACAge4AgH/MAcCAQACAhMSMAoCBQDsvZXUAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAAdyeZCa0qHogiGUHVOYF7fACBvkx/B/x7v3uR7hk/z2
# 2bXzxzpsyrjPeE9/+tshtk30PQcIupBvz5jFhT0NdeZNHDFoexprDn3wLUvbJuoX
# dmTFflBSMDe6GfmwOn7PY+LVexDmeVKFWdJxy6YpCmAGfum+wj18YTBZ+ITaokou
# VJqeMzskDeKHVd2SLQyttGatftolkwznIkXTkf2t/5fSKmSLkQ3U0u1gtQHChkDn
# oIEGW3fzLlL2t0ieOp02vR+SunlFxqUZ+RJzk+FuHiATs4IvtIQUkzfNFlOUt9iH
# Cj6UIbM4GgR6sg4+1W/P/uACNAJ/TMxNwJJ3xqxxAeoxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgO7HlwAOGx0ygABAAAC
# AzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCAvXW38rtcw+o6NL9lqG8qIMlaCEt96N1ObwaLhROzO
# 1TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIEsD3RtxlvaTxFOZZnpQw0Dk
# sPmVduo5SyK9h9w++hMtMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIDux5cADhsdMoAAQAAAgMwIgQg/5DNms7Sd8UtpZacMoCY1q5/
# 2qdlavBPw1sTL5V3yNIwDQYJKoZIhvcNAQELBQAEggIAORDLHZyN0Ii5XgKpKXTf
# th6Q1Y+3RRj4ZCTS3S19u9xpmyz+ujJrsUOGjZXq9rRR0vm4kFGaeDjwqkoyt6MN
# oGkLWjBh1l2LwCdmPe0v530GVtXq4Lg/qhjMrG6EUQo9cAhqdebA6QAHYRKJ1M1i
# nFv2kou55vaL3vu2SY9sNKEJ89p75yubTagXOL373tMv0C1ltdqOhCGZyCFKHI4A
# he7zZLgGUPzhJT13j1cMS7OBqvDHkLX56RojxzPc+8HB93119fJhzZ6PdrAJuNfU
# kegwOwOELladBhdHUAempKYOuFmk9xJSvVXhzxJMuW07O6rqoE/baDFwrCmyumE3
# 2l1rO/2wfQNO4HOVjEdLLeg9sqVA/dnodSsHG1IUa9VInwCFJncRhLnPgt3Hq5aI
# POqoSTy9Aj2V8YIrZhiFfEqbKGSHpOMuWHfTBZuecQRcD9d5NZ2NbmoldftnP2LY
# Hxitzoak2tNlewnXwq6lRXHwH051+rF9QO2VKsLxnDhf+OiRJiiv6OsMdJcPC40E
# V+2fhIEO03UtTzPD1Q7qhx19gUGfW1BC+pTUfRC7Ib6lzfJ4mgjS2QrqEtpTwMHy
# B2JwCil69PPdJqpyL6NdLl4cXICDgztwdGOLjAoxUUeCAdj5MbX3am32WCU6eNwJ
# kzCyB/ArNzGYrMKK/AImfP0=
# SIG # End signature block
