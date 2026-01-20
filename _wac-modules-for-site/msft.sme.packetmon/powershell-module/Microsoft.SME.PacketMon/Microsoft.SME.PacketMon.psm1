function Confirm-WACPMPrerequisitesInstalled {
<#
.SYNOPSIS
Script that checks if prerequisites are installed

.DESCRIPTION
This script checks if Wireshark Dissector and Payload Parser are installed.
These applications are required to parse ETL and ETW data captured by Packet Monitor

.ROLE
Readers

#>

function checkIfWiresharkDissectorIsInstalled {
  $regPath = @(
    "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  if (Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
    [bool]($_.PSobject.Properties.name -match "DisplayName") -and  $_.DisplayName -like "*wireshark*" }) {
    return $true
  }
  return $false
}

function checkIfPayloadParserIsInstalled {
  if (Get-Service -Name "PayloadParser" -ErrorAction SilentlyContinue) {
    return $true
  }
  return $false
}

###############################################################################
# Script execution starts here...
###############################################################################
$applications = @{}
$wiresharkInstalled = checkIfWiresharkDissectorIsInstalled
$payloadParserInstalled = checkIfPayloadParserIsInstalled

$applications.Add('wireshark', $wiresharkInstalled)
$applications.Add('payloadParser', $payloadParserInstalled)

$applications

}
## [END] Confirm-WACPMPrerequisitesInstalled ##
function ConvertFrom-WACPMCapturedData {
<#
.SYNOPSIS
Parse captured data

.DESCRIPTION
Parse captured data by running it through the PayloadParser

.ROLE
Readers

#>

Param(
  [Parameter(Mandatory = $true)]
  [String] $filePath
)

if ([String]::IsNullOrWhiteSpace($filePath) -or -not(Test-Path($filePath))) {
  return;
}

function Delete-File($Path) {
  if (Test-Path $Path) {
    Remove-Item -Path $Path -Force
  }
}

Push-Location

$parserDir = (Get-ChildItem $filePath).DirectoryName.TrimEnd('\')
$fileName = (Get-ChildItem $filePath).Name.TrimEnd('\')

# Set environment variable for PayloadParser to get generated ETL files
$PARSER_FILES_PATH = $parserDir + '\'
[Environment]::SetEnvironmentVariable("PARSER_FILES_PATH", $PARSER_FILES_PATH, "Machine")

Set-Location $parserDir

# PayloadParser only accepts an ETL file with the name 'PktMon.etl'.
# So, if the file the user passed has a different name, we rename it
$wasRenamed = $false;
$pktMonFileName = "PktMon.etl"
$pktmonETLPath = Join-Path $parserDir $pktMonFileName
if ($fileName.ToLower() -ne "pktmon.etl") {
  Delete-File -Path $pktmonETLPath
  Rename-Item -Path $filePath -NewName $pktmonETLPath -Force
  $wasRenamed = $true;
}

$logfilePath = $pktmonETLPath.Replace('etl', 'txt')

# Delete the existing PktMOn.txt file since the PayloadParser creates a new file
Delete-File -Path $logfilePath

# Parse data using payload parser. Generates a file PktMon.txt
Start-Service -Name PayloadParser

# We sleep to give the Payload Parser time to complete
Start-Sleep -Seconds 5
Stop-Service -Name PayloadParser -Force

if ($wasRenamed) {
  Rename-Item -Path $pktmonETLPath -NewName $filePath -Force
}

Pop-Location

if (Test-Path($logfilePath)) {
  return $logfilePath
}

}
## [END] ConvertFrom-WACPMCapturedData ##
function Copy-WACPMFileToServer {
<#

.SYNOPSIS
Upload file from localhost to remote server

.DESCRIPTION
Upload file from localhost to remote server

.Parameter source
Source Path

.Parameter destination
Destination Path

.Parameter destinationServer
Server to upload file to

.Parameter username
Server to upload file to

.Parameter password
User password

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [ValidateScript( { Test-Path $_ -PathType 'Leaf' })]
  [String]$source,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$destination,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$destinationServer,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$username,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$encryptedPassword
)

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode($encryptedData) {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

function Get-UserCredentials {
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [String]$username,
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [String]$encryptedPassword
    )

    $password = DecryptDataWithJWKOnNode $encryptedPassword
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword
    return $credential
}

$Script:credential = Get-UserCredentials $username $encryptedPassword
$Script:serverName = $destinationServer

function Copy-FileToDestinationServer() {
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [String]$source,
      [Parameter(Mandatory = $true)]
      [ValidateScript( { Test-Path $_ -isValid })]
      [String]$destination
    )

    # Delete the remote file first if it exists
    Invoke-Command -ComputerName $Script:serverName -Credential $Script:credential -ScriptBlock {
      param($destination)
      if (Test-Path $destination) {
        Remove-Item -Path $destination -Force -ErrorAction SilentlyContinue
      }
    } -ArgumentList $destination

    # Upload the file
    $session = New-PSSession -ComputerName $Script:serverName -Credential $Script:credential
    Copy-Item -Path $source -ToSession $session -Destination $Destination
  }

  function Get-AdminSmbShare {
    $adminSharedFolder = Invoke-Command -ComputerName $Script:serverName -Credential $Script:credential -ScriptBlock {
      return (Get-SmbShare -Name "ADMIN$").Name;
    } -ArgumentList $destination

    return $adminSharedFolder
  }

  function Get-FreeDisk {
    $disk = Invoke-Command -ComputerName $Script:serverName -Credential $Script:credential -ScriptBlock {
      Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Microsoft.PowerShell.Utility\Select-Object  -Last 1
    }

    return $disk
  }

  function Transfer-FileToServer() {
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [String]$username,
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [String]$password,
      [Parameter(Mandatory = $true)]
      [ValidateScript( { Test-Path $_ -isValid })]
      [String]$source
    )
    $serverName = $Script:serverName
    $smbShare = Get-AdminSmbShare
    $shareName = Get-FreeDisk

    # TODO: This is under test to see which between Start-BitsTransfer and Copy-Item is faster
    net use $shareName \\$serverName\$smbShare $password /USER:$username
    Start-BitsTransfer -Source $source -Destination "S:\Pktmon" -TransferType Upload
    net use $shareName /delete
  }


  ###############################################################################
  # Script execution starts here
  ###############################################################################
  if (-not ($env:pester)) {

    $sourcePath = $ExecutionContext.InvokeCommand.ExpandString($source)
    Copy-FileToDestinationServer -Source $sourcePath -Destination $destination

    $fileExists = Invoke-Command -ComputerName $Script:serverName -Credential $Script:credential -ScriptBlock {
      param($destination)
      return (Test-Path $destination);
    } -ArgumentList $destination

    if ($fileExists) {
      return New-Object PSObject -Property @{success = $true; }
    }
    else {
      return New-Object PSObject -Property @{success = $false; }
    }
  }

}
## [END] Copy-WACPMFileToServer ##
function Get-WACPMComponents {
<#

.SYNOPSIS
Get a list of all pktmon components as json and parse to custom result object

.DESCRIPTION
Get a list of all pktmon components as json and parse to custom result object

.ROLE
Readers

#>

# Method is used to convert components' properties format to a more workable one
# from Properties: {@{p1=v1}, @{p1=v2}, @{p2=v3}} (array of hashtables)
# to Properties: {p1,p2} where p1 = {v1,v2} and p2=v3 (hashtable of values)
function convertProperties($componentList) {
  $componentList.components | ForEach-Object {

    $convertedProperties = @{ }
    $_.Properties | ForEach-Object {
      $propName = $_.Name
      if ($propName -eq "Nic ifIndex" -or $propName -eq "EtherType") {
        $convertedProperties[$propName] += , $_.Value
      }
      else {
        $convertedProperties.Add($propName, $_.Value)
      }
    }

    $_.Properties = $convertedProperties
  }
}

function getVmSwitches($componentList) {
    return $componentList | Where-Object { $_.Type -eq "VMS Protocol Nic" }
}

# For the purpose of building correct associations
# consider adapters to be the components that are not filter, protocol or a virtual switch
function getAdapters($componentList, $nameMap) {
    $adapterList = $componentList | Where-Object { $_.Type -ne "Protocol" -and $_.Type -ne "Filter" -and $_.Type -ne "VMS Protocol Nic" }
    $adapterList | ForEach-Object {
      # Handle the adapter duplicates
      handleAdapterDuplicate $_ $adapterList $nameMap
    }

    return $adapterList
}

function getFilters($componentList) {
  return $componentList | Where-Object {$_.Type -eq "Filter"}
}

function getProtocols($componentList) {
  return $componentList | Where-Object {$_.Type -eq "Protocol"}
}

# Method finds virtual adapters associated with a given virtual switch in a given list of adapters
# It also updates the names of the duplicate items in the name map
function getVirtualAdaptersPerVSwitch($vmSwitchComponent, $adapterComponents, $nameMap) {
    $vSwitchExtIfIndex = $vmSwitchComponent.Properties."Ext ifIndex"

    $vadapters = $adapterComponents | Where-Object { $_.Properties."Ext ifIndex" -eq $vSwitchExtIfIndex }
    $vadapters | ForEach-Object {
        $currentAdapter = $_
        $currentAdapter.Grouped = $true
        # Each adapter and its duplicate belong to its group
        $currentAdapter.ComponentGroup = $currentAdapter.Name
        $nameMap["$($currentAdapter.Id)"].ComponentGroup = $currentAdapter.ComponentGroup

        # Find the filters for each virtual adapter
        processComponentFilters $currentAdapter $filters $nameMap

        # Find the protocols for each virtual adapter
        processComponentProtocols $currentAdapter $protocols $nameMap
    }

    return $vadapters
}

# Method finds the virtual network adapters in a given list of virtual adapters
function getVirtualNetworkAdapters($virtualAdapters) {
    return $virtualAdapters | Where-Object { $_.Type -eq "Host vNic" }
}

# Method finds the vm network adapters in a given list of virtual adapters
function getVirtualMachineNetworkAdapters($virtualAdapters) {
    return $virtualAdapters | Where-Object { $_.Type -eq "VM Nic" }
}

# Method finds the physical adapters associated with a virtual switch in a given list of adapters
function getPhysicalAdaptersPerVSwitch($vmSwitchComponent, $adapterComponents, $nameMap) {
  $physicalComponents = @()

  # Get all Nic ifIndex values for the vm switch. One VM switch can have multiple Nic ifIndex values. Each Nic ifIndex maps to one physical adapter.
  $nicIfIndices = $vmSwitchComponent.Properties."Nic ifIndex"

  $nicIfIndices | ForEach-Object {
    $nicIdx = $_
    $adapterComponents | Where-Object { $_.Properties."ifIndex" -eq $nicIdx } | ForEach-Object {
        $_.Grouped = $true
        $_.ComponentGroup = $_.Name
        $nameMap["$($_.Id)"].ComponentGroup = $_.ComponentGroup

        # Get the filters for each physical adapter
        processComponentFilters $_ $filters $nameMap

        # Get the protocols for each physical adapter
        processComponentProtocols $_ $protocols $nameMap

        $physicalComponents += $_
    }
  }

  return $physicalComponents
}

# Finds the duplicate adapter and updates its name in the map and updates the component's edges
function handleAdapterDuplicate($adapter, $adapterComponents, $nameMap) {
  # All adapter duplicates are of type Miniport. If the adapter we're trying to process is Miniport, then ignore
  if ($adapter.Type -eq "Miniport") {
    return
  }

  $adapter | Add-Member -NotePropertyName DuplicateIds -NotePropertyValue @()

  $duplicate = $adapterComponents | Where-Object { $_.Id -ne $adapter.Id -and $_.Properties.ifIndex -eq $adapter.Properties.ifIndex -and $_.Properties."MAC Address" -eq $adapter.Properties."MAC Address" }
  if ($duplicate) {
      $duplicate = $duplicate[0]
      $duplicate.Grouped = $true
      $duplicate.ComponentGroup = $adapter.ComponentGroup

      $nameMap["$($duplicate.Id)"].Name = $adapter.Name
      $nameMap["$($duplicate.Id)"].ComponentGroup = $duplicate.ComponentGroup

      # Only duplicate components carry the info about the edges, so make sure to add it to the actual component
      if($duplicate.Type -eq "Miniport") {
        $adapter.Edges = $duplicate.Edges
      }
      $adapter.DuplicateIds += $duplicate.Id
  }
}

# Process data for current filter and return the next one
function getNextFilter($component, $currentFilter, $filters, $nameMap) {
  $ifIndex = $currentFilter.Properties["ifIndex"]

  # Each filter belongs to the group of its adapter component
  $nextFilter = $filters | Where-Object {$_.Properties["Lower ifIndex"] -eq $ifIndex}

  if ($nextFilter) {
    $nextFilter.Grouped = $true
    $nextFilter.ComponentGroup = $component.ComponentGroup
    $nameMap["$($nextFilter.Id)"].ComponentGroup = $nextFilter.ComponentGroup
  }

  return $nextFilter
}

# Method finds all filters build on top of a component in order and
# adds them to the component as a property
function processComponentFilters($component, $filters, $nameMap) {
  $ifIndex = $component.Properties["ifIndex"]

  $componentFilters = $filters | Where-Object {$_.Properties["Miniport ifIndex"] -eq $ifIndex}

  if ($componentFilters) {
    # Array will contain the component's filters in the order they are applied
    $orderedFilters = @()

    # Handle 1st filter separately - 1st filter doesn't have Lower ifIndex in its properties
    $firstFilter = $componentFilters | Where-Object {-not $_.Properties["Lower ifIndex"]}
    $firstFilter.Grouped = $true
    $firstFilter.ComponentGroup = $component.ComponentGroup

    $nameMap["$($firstFilter.Id)"].ComponentGroup = $firstFilter.ComponentGroup
    $orderedFilters += $firstFilter

    # The rest of the filtes in the sequence are chained one after the other
    $currentFilter = $firstFilter
    while ($currentFilter) {
      $nextFilter = getNextFilter $component $currentFilter $componentFilters $nameMap
      $orderedFilters += $nextFilter
      $currentFilter = $nextFilter
    }

    $component | Add-Member -NotePropertyName Filters -NotePropertyValue $orderedFilters
  }

}

function processComponentProtocols($component, $protocols, $nameMap) {
  $ifIndex = $component.Properties["ifIndex"]

  $componentProtocols = $protocols | Where-Object {$_.Properties["Miniport ifIndex"] -eq $ifIndex}

  $componentProtocols | ForEach-Object {
    # Each protocol belongs to the group of its adapter component
    $_.Grouped = $true
    $_.ComponentGroup = $component.ComponentGroup
    $nameMap["$($_.Id)"].ComponentGroup = $_.ComponentGroup
  }

  if ($componentProtocols) {
    if ($componentProtocols.GetType().name -eq 'PSCustomObject') {
      $componentProtocols = @($componentProtocols)
    }
    $component | Add-Member -NotePropertyName Protocols -NotePropertyValue $componentProtocols
  }
}

# Method builds the adapter associations for a given virtual switch from a given list of adapters.
# It adds 3 properties to the virtual switch component:
# virtualNetworkAdapters - the list of virtual network adapters for this switch out of all adapters
# virtualMachineNetworkAdapters - the list of vm network adapters for this switch
# physicalNetworkAdapters - the list of physical adapters associated with this switch
# Filters - list of filters applied on top of the switch in order
# Protocols - list of protocols applied on top of the switch
function processVmSwitchComponent($vmSwitchComponent, $adapterComponents, $filters, $protocols, $nameMap) {
    $addedProperties = @{ }

    # 1. Populate the switch name (in case it's missing) and component group
    if (-not $vmSwitchComponent.Name) {
      $name = $vmSwitchComponent.Properties."Switch Name"
      $vmSwitchComponent.Name = $name

      $nameMap["$($vmSwitchComponent.Id)"].Name = $name
    }

    $vmSwitchComponent.Grouped = $true
    $vmSwitchComponent.ComponentGroup = $vmSwitchComponent.Name
    $nameMap["$($vmSwitchComponent.Id)"].ComponentGroup = $vmSwitchComponent.ComponentGroup

    # 2. Handle the vswitch duplicates - virtual switches have 1 original and (at least) 2 duplicates
    $vmSwitchComponent | Add-Member -NotePropertyName DuplicateIds -NotePropertyValue @()

    $duplicates = $adapterComponents | Where-Object {$_.Properties.ifIndex -eq $vmSwitchComponent.Properties."Ext ifIndex"}
    $duplicates | ForEach-Object {
      $_.Grouped = $true
      $_.ComponentGroup = $vmSwitchComponent.ComponentGroup
      $vmSwitchComponent.DuplicateIds += $_.Id

      $nameMap["$($_.Id)"].Name = $vmSwitchComponent.Name
      $nameMap["$($_.Id)"].ComponentGroup = $vmSwitchComponent.ComponentGroup

      # Only the Miniport duplicate has the vswitch Edges
      # Also grab the ifIndex, we need it for finding the filters and protocols
      if($_.Type -eq "Miniport") {
        $vmSwitchComponent.Edges = $_.Edges
        $vmSwitchComponent.Properties["ifIndex"] = $_.Properties["ifIndex"]
      }
    }

    # 3. Find all virtual adapters associated with a given virtual switch
    $virtualAdapters = getVirtualAdaptersPerVSwitch $vmSwitchComponent $adapterComponents $nameMap

    # 4 Group the virtual adapters into categories
    # 4.1 Find the Virtual Network Adapters from the virtual components:
    $virtualNetworkAdapters = @()
    $vnas = getVirtualNetworkAdapters $virtualAdapters
    $vnas | ForEach-Object {
      $virtualNetworkAdapters += $_
    }
    $addedProperties += @{"virtualNetworkAdapters" = $virtualNetworkAdapters }

    # 4.2 Find the Virtual Machine Network Adapters from the virtual components:
    $virtualMachineNetworkAdapters = @()
    $vmnas = getVirtualMachineNetworkAdapters $virtualAdapters
    $vmnas | ForEach-Object {
      $virtualMachineNetworkAdapters += $_
    }
    $addedProperties += @{"virtualMachineNetworkAdapters" = $virtualMachineNetworkAdapters }

    # 5. Find all physical adapters associated with a given virtual switch
    $physicalAdapters = @()
    $pas = getPhysicalAdaptersPerVSwitch $vmSwitchComponent $adapterComponents $nameMap
    $pas | ForEach-Object {
      $physicalAdapters += $_
    }
    $addedProperties += @{"physicalNetworkAdapters" = $physicalAdapters }

    # 6. Get the filters for the switch
    processComponentFilters $vmSwitchComponent $filters $nameMap

    # 7. Get the protocols for the switch
    processComponentProtocols $vmSwitchComponent $protocols $nameMap

    $vmSwitchComponent | Add-Member -NotePropertyMembers $addedProperties
    return $vmSwitchComponent
}


###############################################################################
# Script execution starts here...
###############################################################################

$components = pktmon list -i --json | ConvertFrom-Json

# (1) Convert Properties and (2) Name map between component id and component name
$nameMap = @{ }
$components | ForEach-Object {
  $componentGroup = $_.Group

  $_.Components | ForEach-Object {
    $componentName = $_.Name

    $_ | Add-Member -NotePropertyName Grouped -NotePropertyValue $false
    $_ | Add-Member -NotePropertyName ComponentGroup -NotePropertyValue $componentGroup

    $convertedProperties = @{ }

    if (-not($nameMap.ContainsKey("$($_.Id)"))) {
        $nameMap.Add("$($_.Id)", @{"Name" = $componentName; "ComponentGroup" = $componentGroup})
    }

    $_.Properties | ForEach-Object {

      $propName = $_.Name
      if ($propName -eq "Nic ifIndex" -or $propName -eq "EtherType") {
        $convertedProperties[$propName] += , $_.Value
      }
      else {
        $convertedProperties.Add($propName, $_.Value)
      }
    }

    $_.Properties = $convertedProperties
  }
}


$componentList = $components.Components


$vmSwitchComponents = getVmSwitches $componentList
$adapters = getAdapters $componentList $nameMap
$filters = getFilters $componentList
$protocols = getProtocols $componentList

$vmSwitches = @( )

# Construct the associated objects for each vm switch on the system
$vmSwitchComponents | ForEach-Object {
    $vmSwitches += processVmSwitchComponent $_ $adapters $filters $protocols $nameMap
}

$floatingGroup = @{"Name" = "Standalone Adapters"; "Type" = "Unbound" }

$floatingAdapters = @()
$adapters | Where-Object { !$_.Grouped -and $_.Type -ne "HTTP" } | ForEach-Object {
  $_.Grouped = $true

  processComponentFilters $_ $filters $nameMap
  processComponentProtocols $_ $protocols $nameMap

  $floatingAdapters += $_
}

$floatingGroup += @{"Adapters" = $floatingAdapters }

$floatingGroup = [PSCustomObject]$floatingGroup
$vmSwitches += $floatingGroup

# THE END RESULT
# Tree - list of VM switch association trees
# NameMap - map between component id and component name
$result = [PSCustomObject]@{"treeList" = $vmSwitches; "nameMap" = $nameMap }
$result

}
## [END] Get-WACPMComponents ##
function Get-WACPMCounters {
<#

.SYNOPSIS
Get current pktmon counters

.DESCRIPTION
Get current pktmon counters

.ROLE
Readers

#>
pktmon counters

}
## [END] Get-WACPMCounters ##
function Get-WACPMLogPath {
<#

.SYNOPSIS
Get path for pktmon log file

.DESCRIPTION
Get path for pktmon log file

.PARAMETER logType
File extension. Recognised file extensions are etl, txt, and pcapng.

.ROLE
Administrators

#>

Param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [string] $logType
)

if (-not(@('ETL', 'TXT', 'PCAPNG').Contains($logType.ToUpper()))) {
  Throw "Invalid file extensions: $logType. Recognised file extensions are etl, txt, and pcapng.";
}

Push-Location

$Script:logFileDir = [Environment]::GetEnvironmentVariable("PARSER_FILES_PATH", "Machine").TrimEnd('\')

Set-Location $Script:logFileDir

function getExistingPathToType($extension) {
  $fileName = switch($extension) {
    ETL { "PktMon.etl" }
    TXT { "PktMonText.txt" }
    PCAPNG { "PktMon.pcapng"}
  }

  $logPath = $Script:logFileDir + "\$fileName"
  if (Test-Path $logPath) {
    return $logPath
  }

  return $null
}

function getNewPathToType($type) {
  $etlLogPath = getExistingPathToType "ETL"
  if (!$etlLogPath) {
    # We need the ETL file to convert to txt or pcapng format
    return $null
  }

  if ($type -eq "ETL") {
    return $etlLogPath
  }

  # If we have a previously stored log with given extension, we want to make sure to clean it up first
  $existingLogPath = getExistingPathToType $type
  if ($existingLogPath) {
    Remove-Item $existingLogPath
  }

  switch($type) {
    TXT {
      # Convert log file to text format.
      # pktmon etl2txt PktMon.etl --out PktMonText.txt | Out-Null
      pktmon format PktMon.etl --out PktMonText.txt | Out-Null
    }

    PCAPNG {
      # Convert log file to pcapng format. Dropped packets are not included by default.
      # pktmon etl2pcap PktMon.etl --out PktMon.pcapng | Out-Null
      pktmon pcapng PktMon.etl --out PktMon.pcapng | Out-Null
    }
  }

  return getExistingPathToType $type
}

###############################################################################
# Script execution starts here...
###############################################################################
$logType = $logType.ToUpper()
getNewPathToType $logType

}
## [END] Get-WACPMLogPath ##
function Get-WACPMPacketMonitorLogFile {
<#
.SYNOPSIS
Gets the packet monitoring log file

.DESCRIPTION
Return path to captured data file

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $action,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $logFilesDir
)

function Get-PktmonLogFilePath($PktmonResult, $logFilesDir) {
    if ($null -eq $PktmonResult) {
      return
    }


    $logFilesDir = $ExecutionContext.InvokeCommand.ExpandString($logFilesDir)
    $pathToEtl = Join-Path $logFilesDir "PktMon.etl"
    if (-not(Test-Path $pathToEtl)) {
        return
    }

    return $pathToEtl
  }

function Get-PktmonStatus() {
    $pktmonHelp = pktmon help
    if (-not ($pktmonHelp -match "status")) {
        return $null
    }

    <##
    There are time when you stop pktmon and it shows All Counters zero message
    and there is no packet event data file. This checks that pktmon is running and
    data is being save to a file. This file we are checking for is later passed to
    the PayloadParser where it is converted from ETL to json format.
  #>
    $pktmonStatus = pktmon status

    # if packetmon is not running, the size of the array will be 2.
    if ($pktmonStatus.length -eq 2) {
        return $null
    }

    return $pktmonStatus
}


###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    $action = $action.ToLower()

    if ($action -eq "stop") {
        $pktmonResult = pktmon stop
    }
    elseif ($action -eq "status") {
        $pktmonResult = Get-PktmonStatus
    }
    else {
        return;
    }

    return Get-PktmonLogFilePath -PktmonResult $pktmonResult -logFilesDir $logFilesDir
}

}
## [END] Get-WACPMPacketMonitorLogFile ##
function Get-WACPMPartitionedData {
<#
.SYNOPSIS
Partition parsed packetMon data

.DESCRIPTION
Partition parsed packetMon data into chunks of 100MB or less

.PARAMETER sourceFile
Path to log file

.ROLE
Readers

#>

Param(
  [Parameter(Mandatory = $true)]
  [string] $sourceFile
)

$generatedFile = [System.Collections.ArrayList]@()

$upperBound = 100MB

$fileSize = (Get-Item $sourceFile).length / 1MB

$parentFolder = Split-Path -Parent $sourceFile

# Delete existing files
Get-Item -Path $parentFolder\PktMonChunk*.txt | Remove-Item -Force -ErrorAction SilentlyContinue


$reader = [io.file]::OpenRead($sourceFile)

$buffer = New-Object byte[] $upperBound

$count = $idx = 1

try {
  # "Splitting $sourceFile using $upperBound bytes per file."
  do {
    $count = $reader.Read($buffer, 0, $buffer.Length)
    if ($count -gt 0) {
      $destinationFile = (Join-Path $parentFolder "PktMonChunk{0}.txt") -f ($idx)
      $writer = [io.file]::OpenWrite($destinationFile)
      try {
        # "Writing to $destinationFile"
        $writer.Write($buffer, 0, $count)
      }
      finally {
        [Void]$generatedFile.Add($destinationFile)
        $writer.Close()
      }
    }
    $idx ++
  } while ($count -gt 0)
}
finally {
  $reader.Close()
}

return $generatedFile

}
## [END] Get-WACPMPartitionedData ##
function Get-WACPMPktMonInstallStatus {
<#

.SYNOPSIS
Check if pktmon is installed or not

.DESCRIPTION
Check if pktmon is installed or not

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

function main() {
    try {
        $pktmonHelp = PktMon.exe help
    }
    catch {
        return @{ state = "NotSupported" }
    }

    if ($pktmonHelp -match "unload") {
        return @{ state = "Available" }
    }
    
    return @{ state = "NotSupported" }
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    return main
}

}
## [END] Get-WACPMPktMonInstallStatus ##
function Get-WACPMSavedLogs {
<#

.SYNOPSIS
Get path for pktmon log file

.DESCRIPTION
Get path for pktmon log file

.ROLE
Readers

#>
Param(
  [Parameter(Mandatory = $true)]
  [string] $logFolder
)


function Get-PktMonSavedLogs($logFolder) {

  $result = [System.Collections.ArrayList]@()

  $savesLocation = Join-Path $env:SystemDrive $logFolder

  if (-not(Test-Path($savesLocation))) {
    New-Item -Path $savesLocation -ItemType "directory" -Force | Out-Null
  }

  # We only open ETL files because we need to run it through the PayloadParser.
  Get-ChildItem $savesLocation | Where-Object { $_.Name -match "ETL" } | Sort-Object -Property LastWriteTime -Descending | ForEach-Object {
    $log = @{"Name" = $_.Name; "Path" = Join-Path $savesLocation $_.Name; "LastWriteTime" = $_.LastWriteTime }
    # $result += $log
    $result.Add($log) | Out-Null
  }

  return ,$result
}

Get-PktMonSavedLogs -LogFolder $logFolder

}
## [END] Get-WACPMSavedLogs ##
function Import-WACPMCapture {
<#
.SYNOPSIS
Get pktmon capture results

.DESCRIPTION
Get packet monitor logs. These are the results from the PayloadParser

.PARAMETER pathToLog
Path to log file

.ROLE
Readers

#>


Param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullorEmpty()]
  [string] $pathToLog
)

$contents = Get-Content $pathToLog -Raw -Encoding UTF8
$contents

}
## [END] Import-WACPMCapture ##
function Import-WACPMPrerequisite {
<#
.SYNOPSIS
Script downloads Packet Monintor prerequsites

.DESCRIPTION
This script downloads prerequsites needed to parse Packet Monitor ETL data

.Parameter uri
URI for the prerequisite

.Parameter destinationFolder
Folder to save file to

.Parameter fileName
Name of the prerequisite to install. wireshark.exe or payloadparser.zip

.ROLE
Readers
#>


param (
  [Parameter(Mandatory = $true)]
  [String]$uri,
  [Parameter(Mandatory = $true)]
  [String]$destinationFolder,
  [Parameter(Mandatory = $true)]
  [String]$fileName
)

function Compress-WiresharkDissectorFile {
  param (
    [Parameter(Mandatory = $true)]
    [String]$sourcePath,
    [Parameter(Mandatory = $true)]
    [String]$destinationPath
  )

  $prerequisiteName = (Get-Item $sourcePath).BaseName.ToLower()
  if ($prerequisiteName -eq "wireshark") {
    Compress-Archive -Path $sourcePath -DestinationPath $destinationPath -Update
  }

  return destinationPath;
}

$destinationFolder = $ExecutionContext.InvokeCommand.ExpandString($destinationFolder)
if (-not(Test-Path $destinationFolder)) {
  New-Item -Path $destinationFolder -ItemType "Directory" -Force | Out-Null
}

$downloadLocation = Join-Path -Path $destinationFolder -ChildPath $fileName

# Remove the file if it exists. This is because the file could be corrupted or a more recent version is available
if (Test-Path $downloadLocation) {
  Remove-Item -Path $downloadLocation -Recurse -Force
}

Invoke-WebRequest -Uri $uri -OutFile $downloadLocation

if (Test-Path $downloadLocation) {
  $fileName = (Get-Item -Path $downloadLocation).Name
  return New-Object PSObject -Property @{executablePath = $downloadLocation; fileName = $fileName }
}

}
## [END] Import-WACPMPrerequisite ##
function Install-WACPMPayloadParser {
<#
.SYNOPSIS
Script installs PayloadParser

.DESCRIPTION
This script installs PayloadParser

.Parameter executablePath
Path to PayloadParser

.ROLE
Readers
#>


param (
  [Parameter(Mandatory = $true)]
  [String]$path
)

$path = $ExecutionContext.InvokeCommand.ExpandString($path)

$parentDir = Split-path -Parent $path
Expand-Archive $path -DestinationPath $parentDir -ErrorAction SilentlyContinue

$destinationDir = Join-Path -Path $parentDir -ChildPath "PayloadParser"
$installerFilePath = "$destinationDir\PayloadParserSetup.msi"
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/i `"$installerFilePath`" /qn /passive" -Wait | Out-Null

# Remove the executable downloaded
Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $destinationDir -Recurse -Force -ErrorAction SilentlyContinue

if (Get-Service "PayloadParser") {
  return New-Object PSObject -Property @{success = $true; }
}
else {
  return New-Object PSObject -Property @{success = $false; }
}

}
## [END] Install-WACPMPayloadParser ##
function Install-WACPMWiresharkDissector {
<#
.SYNOPSIS
Script installs Wireshark Dissector

.DESCRIPTION
This script installs Wireshark Dissector

.Parameter path
Path to install Wireshark Dissector

.ROLE
Readers
#>


param (
  [Parameter(Mandatory = $true)]
  [String]$path
)


function checkIfWiresharkDissectorIsInstalled {
  $regPath = @(
    "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  if (Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
    [bool]($_.PSobject.Properties.name -match "DisplayName") -and  $_.DisplayName -like "*wireshark*" }) {
    return $true
  }
  return $false
}

$path = $ExecutionContext.InvokeCommand.ExpandString($path)

Start-Process -FilePath $path -ArgumentList "/S", "/v", "/qn" -PassThru | Out-Null

# Stop the process on completion
$wiresharkProcess = Get-Process | Where-Object { $_.Product -eq "Wireshark Dissect" -or $_.ProcessName -eq "Un_A" }
if ($wiresharkProcess) {

  $count = 0
  while ($true) {

    # Somwtimes, the Wireshark installer process does not stop and we need to force it
    # to stop if Wireshark is installed successfully. We continue to poll until it is installed
    $wiresharkInstalled = checkIfWiresharkDissectorIsInstalled
    if ($wiresharkInstalled) {
      $wiresharkProcess | Stop-Process -Force | Out-Null
      return New-Object PSObject -Property @{success = $true; }
    }

    $count += 1

    # This buffer time ensures the installation and post-installation clean-up is done before we stop the process
    Start-Sleep -Seconds 5

    # If the installer is not done in 10seconds, we might have a problem. We force stop the installer and throw a timeOut error
    if ($count -gt 2) {
      $wiresharkProcess | Stop-Process -Force | Out-Null
      Throw (new-object System.TimeoutException)
    }
  }
}

# Remove the executable downloaded
Remove-Item -Path $path -Force -ErrorAction SilentlyContinue

if ($wiresharkInstalled) {
  return New-Object PSObject -Property @{success = $true; }
} else {
  return New-Object PSObject -Property @{success = $false; }
}

}
## [END] Install-WACPMWiresharkDissector ##
function Resolve-WACPMDestinationFilePath {
<#
.SYNOPSIS
Resolves a string to a valid path that includes the destination server

.DESCRIPTION
Resolves a string to a valid path that includes the destination server

.Parameter path
String of path to resolve

.Parameter server
Destination server

.ROLE
Readers
#>

param (
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$path,
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [String]$server
)


function Resolve-DestinationPath() {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$path,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$server
  )

  $path = $ExecutionContext.InvokeCommand.ExpandString($path)

  # Create the destination folder if it does not exist
  $parentFolder = Split-Path -Parent $path

  if (-not(Test-Path $parentFolder)) {
    New-Item -Path $parentFolder -ItemType Directory -Force | Out-Null
  }

  $rootDrive = (Get-Location).Drive.Root
  $newPath = $path.Replace($rootDrive, "").Trim("\")

  $server = "\\" + $server.Trim("\")
  $resolvedPath = Join-Path -Path $server -ChildPath $newPath
  return $resolvedPath
}

$resolvedPath = Resolve-DestinationPath -Path $path -Server $server
return $resolvedPath

}
## [END] Resolve-WACPMDestinationFilePath ##
function Resolve-WACPMFilePath {
<#
.SYNOPSIS
Resolves a string to a valid path

.DESCRIPTION
Resolves a string to a valid path

.Parameter path
String of path to resolve

.ROLE
Readers
#>

param (
  [Parameter(Mandatory = $false)]
  [String]$path,
  [Parameter(Mandatory = $false)]
  [String]$smbShare
)

# We do not know the drives that are available in the destination node we need to upload
# the file to. So we need to use $ENV:Temp. This is a string that we need to resolve
# and get a valid name for. This string will be the resoved path we pass to the
# upload and install functions
if (-not([String]::IsNullOrWhiteSpace($path))) {
  $resolvedPath = $ExecutionContext.InvokeCommand.ExpandString($Path)

  $parentDir = Split-path -Parent $resolvedPath
  if (-not(Test-Path $parentDir)) {
    New-Item -Path $parentDir -ItemType "Directory" -Force | Out-Null
  }

  return $resolvedPath
}
elseif (-not([String]::IsNullOrWhiteSpace($smbShare))) {
  $destinationFolder = (Get-SmbShare -Name $smbShare).Path
  $resolvedPath = Join-Path -Path $destinationFolder -ChildPath $path
  return $resolvedPath
}

}
## [END] Resolve-WACPMFilePath ##
function Save-WACPMLog {
<#

.SYNOPSIS
Get path for pktmon log file

.DESCRIPTION
Get path for pktmon log file

.ROLE
Readers

#>
Param(
  [Parameter(Mandatory = $true)]
  [string] $srcLogPath,
  [Parameter(Mandatory = $true)]
  [string] $destLogFolder,
  [Parameter(Mandatory = $true)]
  [string] $logName,
  [Parameter(Mandatory = $true)]
  [boolean] $newCapture
)

$Script:srcLogPath = $srcLogPath
$Script:destLogFolder = $destLogFolder
$Script:logName = $logName


function Remove-FilesByExtension {
  Param(
    [Parameter(Mandatory = $true)]
    [string] $extension,
    [Parameter(Mandatory = $true)]
    [string] $location
  )

  $logsSorted = Get-ChildItem $location -File | Where-Object { $_.Name -match $extension } | Sort-Object -Property LastWriteTime -Descending

  # If destination folder exists, check if we need to clear some of its contents
  $savedLogsCount = $logsSorted.Count

  # Limit number of saved logs - only keep the 5 most recent logs
  $maxSaveCount = 5

  # If we have more logs than our limit clean the oldest ones
  if ($maxSaveCount -le $savedLogsCount) {
    $logsToDelete = $logsSorted | Microsoft.PowerShell.Utility\Select-Object -Last ($savedLogsCount - $maxSaveCount + 1)

    $logsToDelete | ForEach-Object {
      Remove-Item -Path "$($location)\$($_.Name)"
    }
  }
}

function Get-FileExtension($fileName) {
  if ($fileName -match "etl") { return "etl" }
  elseif ($fileName -match "txt") { return "txt" }
  elseif ($fileName -match "pcapng") { return "pcapng" }
}

function Save-CapturedLog($isNewCapture) {
  if ($isNewCapture) {
    # If no source - nothing to copy
    if (-not (Test-Path $Script:srcLogPath)) {
      return $null
    }

    $savesLocation = Join-Path $env:SystemDrive $Script:destLogFolder
    if (Test-Path $savesLocation) {
      # If destination folder exists, check if we need to clear some of its contents
      $extension = Get-FileExtension $Script:logName
      Remove-FilesByExtension -Extension $extension -Location $savesLocation
    }
    else {
      New-Item $savesLocation -ItemType Directory -Force | Out-Null
    }

    # Finally, copy the file
    $destination = Join-Path $savesLocation $Script:logName
    Copy-Item -Path $Script:srcLogPath -Destination $destination
  }
  else {
    $savedLog = Get-Item $Script:logName
    if ($savedLog) {
      $savedLog.LastWriteTime = (Get-Date)
    }
  }
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
  Save-CapturedLog -isNewCapture $newCapture
}

}
## [END] Save-WACPMLog ##
function Set-WACPMFilters {

<#

.SYNOPSIS
add pktmon filters

.DESCRIPTION
add pktmon filters

.ROLE
Readers

#>
Param(
    [Parameter(Mandatory = $true)]
    [string[]] $filters
)

pktmon unload

foreach ($filter in $filters) {
  $command = 'pktmon filter add' + $filter
  Invoke-Expression $command
}

}
## [END] Set-WACPMFilters ##
function Start-WACPMCapture {
<#

.SYNOPSIS
start pktmon capture

.DESCRIPTION
start pktmon capture

.PARAMETER startArgs
A string of flags (and their values) to pass to the `pktmon start` command.
Example "--components nics --etw".
For more details on usage, see: pktmon start help

.PARAMETER filters
An array of string of flags (and their values) to pass to the `pktmon filter add` command.
Example "--ip 192.168.20.1 192.168.20.100".
For more details on usage, see: pktmon filter add help

.ROLE
Readers
#>

Param(
    [Parameter(Mandatory = $false)]
    [PSCustomObject] $startArgs,
    [Parameter(Mandatory = $false)]
    [System.Array] $filters,
    [Parameter(Mandatory = $false)]
    [string] $logFilesDir
)

function isEmpty ($object) {
    if ($null -eq $object) {
        return $true
    }

    return $object.count -eq 0
}

function Add-Filters($filters) {
    if ( isEmpty($filters) ) { return; }

    foreach ($filter in $filters) {

        # Add capture filter
        if (-not([string]::IsNullOrWhitespace($filter))) {
            $filterCommand = "pktmon filter add " + $filter
            Invoke-Expression -Command $filterCommand
        }
    }
}

function Parse-StartArguments() {
    param (
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$arguments
    )

    if (isEmpty($arguments)) {
        return '';
    }

    $result = ''
    if (-not(isEmpty($arguments.component))) {
        $components = $arguments.component -join " "
        $result += " --comp $($components)"
    }

    if ($arguments.dropped) {
        $result += " --type drop"
    }

    return $result.Trim();
}

function Start-PktMon($parsedStartArguments, $logFilesDir) {
    $logFilesDir = $ExecutionContext.InvokeCommand.ExpandString($logFilesDir)
    if (-not(Test-Path $logFilesDir)) {
        New-Item -Path $logFilesDir -ItemType Directory | Out-Null
    }

    # TODO: Test with smaller files.
    # File size in MB
    # NOTE: (22 April 2021) File size limited to 100MB since the Payload Parser
    # as of this date hangs if you try to parse larger files
    $fileSize = 40

    $pathToEtl = Join-Path $logFilesDir "PktMon.etl"
    $startCommand = "pktmon start --etw --file-size $($fileSize) --file-name '$($pathToEtl)'"

    # Add parse start arguments
    $startCommand = $startCommand + ' ' + $parsedStartArguments

    Invoke-Expression -Command $startCommand.Trim()
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    # Reset any previous state of the tool
    Invoke-Expression -Command "pktmon unload"

    Add-Filters -Filters $filters

    $parsedStartArguments = Parse-StartArguments -Arguments $startArgs
    Start-PktMon $parsedStartArguments $logFilesDir
}

}
## [END] Start-WACPMCapture ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeLVghIDzNgzPk
# ZehD+xWmpeduFL6v0nKVl5LKw1e5raCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOTI9XCjJwlqkq5Y30HAZ2+J
# sFEz0OHZi/vTmnnzOF5jMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAmbr+mINwiZG/zQalA9SLHJEs0uWBD+kJzoRX/VO3WeMCixDN1BlH+pBC
# SBTMDIqNfXTTwrBIkLHopmFu1+IbDvFhj3yZezprYlO4BucyCtZOx84sb3NwTuSa
# 1mnBtxz5LNQD8U3+7qcryXIb5oYOOzBDlI78gNwB1tGGEivM9wBCXVvB3J1+tnqP
# CCd7SFaPg0DX6mZT7VaApQthZWMGbzg7tzDqStK3roVZiLLXzSb4yxv/Chvthy+C
# bcSABjgWBnj6DrnO0iSeiDHgL4A3TmYDmFuMsVwiCoSh8w+5GTvpxCk+v+rruXqD
# AMoayonKGLPOYMrUXraiTDj1gauWKKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBo/CN0qzrUVFE1hjKSkhbf3uyqYkotO9njFKIyFa9mpAIGaO/YTs9Y
# GBMyMDI1MTExMDE3MTc1My4xMzlaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# MC8GCSqGSIb3DQEJBDEiBCBaFt8ZC5mziWBjt/0kcEg1TDbAQFAsj3LSu5jXCc9l
# jDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPON6gEYB5bLzXLWuUmL8Zd8
# xXAsqXksedFyolfMlF/sMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAICeVB0IRR9uKEAAQAAAgIwIgQgla+KcZeP3OgOwPzMHQvgcHA0
# cYXa3F0K4iFZ1wTSMqwwDQYJKoZIhvcNAQELBQAEggIAsF1uk4a1WUP4tOHisRw4
# jcLvTwvUUJRrm5+NSVNsRehi4fFpzWnOlis9HjBCRl1sL7QaWFUgLV137ukj3/uV
# RmJ2AMUQ8G/pLIz/JXO1ihbgpwQvwalRFKMypryliH0zKaBuhrjEakCBDxSIeNR7
# x+q0NQZIO+sMSvYZeDosSigvQ0NWr7Titx+VThBr7NbORpIdjPygYDl2OhKbDKQM
# dKupjWA3cCTNVN74OZvLvXEjil2XiSM9yNv2MEq1SWo0orBiMt46sVo8sQ32MEMN
# MmGR+IwNW5klHy4lMWnvhRg4M9beSSNPft+S+TdZLDh3Kj3gVojOO+x1qoxUaZg4
# co/Zo39mrlJePXDPQ0jGGkwRSh6Y9ImZusV+Z7il2fctqDLT+qrVFVrKWJ93iFhg
# 0swUWa+09rSiOZTgGKMvyONNLgLoiaU7GWtKoOgllLTRMjp2cW5sOQ9KElplo/JI
# qirZmUjZn559qaSUzzGKE74jduLm3ovZkUDrG4nl8LDHtsgSI9SH6r5ZV1YAMZNp
# t0BcGDXGJVEHN5/0hFjVezU521XJmEuAQxmtGnps1xmfJyD6W3714RjU/Fb9vGgw
# 5CO5RVLJ2BqM6asG9whnCSf6UtXYoZKYHHxmxSjLhkQNRXbkONZLdnBAJD5kZ1X7
# ut27qnL99cCJmVQWp9R0y7A=
# SIG # End signature block
