function Add-WACCCAdapterToVmSwitch {
<#

.SYNOPSIS
Configure management network adapters.

.DESCRIPTION
Configure management network adapters.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$switchName
)

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-ManagementAdapters" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function calcNameForOldAdapter($newName) {
    $oldAdapterSuffix = ' (old)'
    $oldAdapters = @{}

    $key = "$($newName)$($oldAdapterSuffix)*"
    Get-NetAdapter | Foreach-Object {
        if ($_.Name -Like ($key)) {
            $oldAdapters[$_.Name] = ''
        }
    }

    $index = 0
    $temp = "$($newName)$($oldAdapterSuffix)"

    while ($null -ne $oldAdapters[$temp]) {
        $index++
        $temp = "$($newName)$($oldAdapterSuffix)$($index)"
    }

    return $temp
}

function renameAdapter($adapterName, $newName) {
    $currentAdapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue

    # Handles retry case where the adapter was already re-named in a previous, partially successful run
    if ($null -eq $currentAdapter) {
        # If we can't find an adapter with the given name, assume it was already renamed
        ##SkipCheck=true##
        $message = "[Add-AdapterToVmSwitch]: Adapter with given name " + $adapterName + " could not be found, attempting to select adapter with name " + $newName
        ##SkipCheck=false##
        writeInfoLog $message

        $currentAdapter = Get-NetAdapter -Name $newName -ErrorAction SilentlyContinue

        # If an adapter can't be found with either the given name or new name, we've entered an unrecoverable state and require a rollback before attempting again
        if ($null -eq $currentAdapter) {
            $errorLog = "[Add-AdapterToVmSwitch]: No adapter was found with name " + $newName + ", unexpected state - exiting with error"
            writeErrorLog $errorLog
            throw $errorLog
        }
    }

    if ($currentAdapter.Name -ne $newName) {
        $prevManagementAdapter = Get-NetAdapter -Name $newName -ErrorAction SilentlyContinue

        if ($null -ne $prevManagementAdapter) {
            try {
                $oldAdapterName = calcNameForOldAdapter $newName
                $prevManagementAdapter | Rename-NetAdapter -NewName $oldAdapterName -ErrorAction Stop

                $message = "[Add-AdapterToVmSwitch]: Renamed old management adapter from " + $prevManagementAdapter.Name + " to " + $oldAdapterName
                writeInfoLog $message
            }
            catch {
                $err1 = $_.Exception.Message
                if ($err1) {
                    $errorLog = "[Add-AdapterToVmSwitch]: Couldn't rename old management adapter from " + $prevManagementAdapter.Name + " to " + $oldAdapterName + ". Error: " + $err1
                    writeErrorLog $errorLog
                }
            }
        }

        try {
            Rename-NetAdapter -Name $currentAdapter.Name -NewName $newName -ErrorAction Stop

            $message = "[Add-AdapterToVmSwitch]: Renamed management adapter from " + $currentAdapter.Name + " to " + $newName
            writeInfoLog $message
        }
        catch {
            $err1 = $_.Exception.Message
            if ($err1) {
                $errorLog = "[Add-AdapterToVmSwitch]: Couldn't rename adapter for " + $currentAdapter.Name + ". Error: " + $err1
                writeErrorLog $errorLog

                return $null;
            }
        }
    }
    else {
        $message = "[Add-AdapterToVmSwitch]: Selected adapter is already named " + $newName + ", skipping renaming"
        writeInfoLog $message
    }
}

function main($adapterName, $switchName) {
    $newName = 'Management Physical 2'

    renameAdapter $adapterName $newName

    try {
        Add-VMSwitchTeamMember -VMSwitchName $switchName -NetAdapterName $newName

        Register-DnsClient

        return $true
    }
    catch {
        $err1 = $_.Exception.Message
        if ($err1) {
            $errorLog = "[Configure-ManagementAdapters]: Couldn't Add-VMSwitchTeamMember: Adapter for switch: " + $switchName + ". Error: " + $err1
            writeErrorLog $errorLog

            return $false
        }
    }
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $adapterName $switchName
}

}
## [END] Add-WACCCAdapterToVmSwitch ##
function Add-WACCCNetIntents {
<#

.SYNOPSIS
Add ATC networking intents.

.DESCRIPTION
Add ATC networking intents.

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [PSObject[]]$intents
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-AddNetIntents" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

    function main([PSObject[]] $intents) {
        $results = @{}

        foreach ($intent in $intents) {
            try {
                $params = @{
                    name                     = $intent.name
                    adapterName              = $intent.adapterName
                    clusterName              = $intent.clusterName
                    management               = $intent.management
                    compute                  = $intent.compute
                    storage                  = $intent.storage
                    storageVLANs             = $intent.storageVLANs
                    adapterPropertyOverrides = $intent.adapterPropertyOverrides
                    switchPropertyOverrides  = $intent.switchOverrides
                    qosPolicyOverrides       = $intent.qosPolicyOverrides
                }

                if($null -ne $intent.storageIpOverride -and $intent.storageIpOverride) {
                    $storageOverride = New-NetIntentStorageOverrides
                    $storageOverride.EnableAutomaticIPGeneration = $false
                    $params.Add('StorageOverrides', $storageOverride)
                }

                Add-NetIntent @params

                $regKeyPath = 'HKLM:\Cluster'
                [string]$guid = Get-ItemPropertyValue -Path $regKeyPath -Name 'ClusterNameResource' -ErrorAction SilentlyContinue
                $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                if($clusterResource -ne $null) {
                    $state = $clusterResource.state
                    writeInfoLog $state
                }
                if ($clusterResource.state -ne "Online") {
                    $clusterResource | Start-ClusterResource
                    $message = "Started cluster resource"
                    writeInfoLog $message

                    for ($i = 0; $i -lt 5 ; $i++) {
                        $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                        if ($clusterResource.state -ne "Online") {
                            Start-Sleep 15
                        }
                        else {
                            $message = "Cluster resource is now online"
                            writeInfoLog $message
                            break;
                        }
                    }

                    $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                    if ($clusterResource.state -ne "Online") {
                        $message = "Unable to start cluster resource"
                        writeInfoLog $message
                    }
                } else {
                    $message = "Cluster resource is online"
                    writeInfoLog $message
                }

                $message = "Successfully added intent for intent with name " + $intent.name
                writeInfoLog $message

                $results[$intent.name] = $true
            }
            catch {
                $err = $_.Exception.Message
                $results[$intent.name] = $false
                if ($err) {
                    $errorLog = "Couldn't add intent for intent with name " + $intent.name + ". Error: " + $err
                    writeErrorLog $errorLog
                }
            }
        }

        return $results
    }

    ###############################################################################
    # Script execution starts here...
    ###############################################################################
    if (-not ($env:pester)) {
        Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

        return main $intents
    }

}
## [END] Add-WACCCNetIntents ##
function Add-WACCCUserToAdminGroup {
<#
.SYNOPSIS
Adds user to the Administrators group.

.DESCRIPTION
Adds user to the Administrators group.

.ROLE
Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $Username
)
function addUserToAdministratorsGroup() {
    try {
        $administratorsGroup = (Get-LocalGroup -SID S-1-5-32-544)

        # First check if user is already in the group.
        $isUserInGroup = $null -ne (Get-LocalGroupMember -Group $administratorsGroup -Member $Username -ErrorAction SilentlyContinue)
        if (-not $isUserInGroup) {
            # double check if user is in-role of S-1-5-32-544 (Adminstrators), this happens if user is domain administrator.
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            if ($currentUser.Name -ieq $Username) {
                $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
                $isUserInGroup = $principal.IsInRole("S-1-5-32-544")
            }
        }

        if (-not $isUserInGroup) {
            $err = $null
            Add-LocalGroupMember -Group $administratorsGroup -Member $Username -ErrorAction SilentlyContinue -ErrorVariable +err

            # Ignore member exists error, due to the issue: https://microsoft.visualstudio.com/OS/_workitems/edit/41149827
            # Get-LocalGroupMember cannot access user when entered as domainname.full.path\username as opposed to domainname\username
            # but when we come to add the user we hit the error - MemberExists,Microsoft.PowerShell.Commands.AddLocalGroupMemberCommand
            if ($err -and $Err.FullyQualifiedErrorId -ne 'MemberExists,Microsoft.PowerShell.Commands.AddLocalGroupMemberCommand') {
                return @{
                    IsSuccess = $false
                    ErrorMessage = @($err)[0].toString()
                }
            }
        }

        return @{
            IsSuccess = $true
            ErrorMessage = ''
        }
    } catch {
        return @{
            IsSuccess = $false
            ErrorMessage = $_.ToString()
        }
    }
}

addUserToAdministratorsGroup

}
## [END] Add-WACCCUserToAdminGroup ##
function Disable-WACCCAdapter {
<#

.SYNOPSIS
Disables a network adapter.

.DESCRIPTION
Disables a network adapter.

.ROLE
Administrators

.PARAMETER adapterName
    The name of the network adapter.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $adapterName
)

Set-StrictMode -Version 5.0;
$result = Disable-NetAdapter -Name $adapterName -Confirm:$false

Register-DnsClient

return $result

}
## [END] Disable-WACCCAdapter ##
function Disable-WACCCAdapters {
<#

.SYNOPSIS
Disables given adapters.

.DESCRIPTION
Disables given adapters.

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [PSObject]$adapterNames
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SmeHciScripts-DisableAdapters" -Scope Script

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function disableAdapters($adapterNames) {
    $result = @{
        success = $true
        failedAdapters = @()
    }

    foreach ($adapterName in $adapterNames) {
        try {
            Disable-NetAdapter -Name $adapterName -Confirm:$false
            $infoLog = "Successfully disabled network adapter with name " + $adapterName
            writeInfoLog $infoLog
        } catch {
            $err = $_.Exception.Message
            $errorLog = "An error occured while trying to disable network adapter with name " + $adapterName + ". Error: " + $err
            writeErrorLog $errorLog

            $result.failedAdapters = $result.failedAdapters + $adapterName
            $result.success = $false
        }
    }

    return $result
}

function main($adapterNames) {
    return disableAdapters $adapterNames
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    return main $adapterNames
}
}
## [END] Disable-WACCCAdapters ##
function Enable-WACCCAdapter {
<#

.SYNOPSIS
Enables a network adapter.

.DESCRIPTION
Enables a network adapter.

.ROLE
Administrators

.PARAMETER adapterName
    The name of the network adapter.

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $adapterName
)

Set-StrictMode -Version 5.0;
$result = Enable-NetAdapter -Name $adapterName -Confirm:$false

Register-DnsClient

return $result

}
## [END] Enable-WACCCAdapter ##
function Enable-WACCCAdapters {
<#

.SYNOPSIS
Enables given adapters.

.DESCRIPTION
Enables given adapters.

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [PSObject]$adapterNames
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SmeHciScripts-EnableAdapters" -Scope Script

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function enableAdapters($adapterNames) {
    $result = @{
        success = $true
        failedAdapters = @()
    }

    foreach ($adapterName in $adapterNames) {
        try {
            Enable-NetAdapter -Name $adapterName -Confirm:$false
            $infoLog = "Successfully enable network adapter with name " + $adapterName
            writeInfoLog $infoLog
        } catch {
            $err = $_.Exception.Message
            $errorLog = "An error occured while trying to enable network adapter with name " + $adapterName + ". Error: " + $err
            writeErrorLog $errorLog

            $result.failedAdapters = $result.failedAdapters + $adapterName
            $result.success = $false
        }
    }

    return $result
}

function main($adapterNames) {
    return enableAdapters $adapterNames
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    main $adapterNames
}
}
## [END] Enable-WACCCAdapters ##
function Enable-WACCCClusterS2D {
<#

.SYNOPSIS
Enable Cluster Storage Spaces Direct.

.DESCRIPTION
Enable Cluster Storage Spaces Direct.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $False)]
    [string]
    $cacheState,

    [Parameter(Mandatory = $False)]
    [string]
    $cacheModeSSD,

    [Parameter(Mandatory = $False)]
    [string]
    $cacheDeviceModel,

    [Parameter(Mandatory = $True)]
    [string]
    $scenarioNumber
)

$Output = @()

if ($scenarioNumber -eq '1') {
    # Simple Scenario 1
    $Output = Enable-ClusterStorageSpacesDirect -Confirm:$False
}
ElseIf ($scenarioNumber -eq '2' -and $cacheState -eq "Enabled") {
    # Scenario 2
    $Output = Enable-ClusterStorageSpacesDirect -Confirm:$False -CacheState $cacheState
    Set-ClusterStorageSpacesDirect -CacheModeSSD $cacheModeSSD
}
ElseIf ($scenarioNumber -eq '2' -and $cacheState -eq "Disabled") {
    # Scenario 2
    $Output = Enable-ClusterStorageSpacesDirect -Confirm:$False -CacheState $cacheState
}
ElseIf ($scenarioNumber -eq '3' -and $cacheDeviceModel -eq '') {
    # Scenario 3 - no cache drive model specified.
    $Output = Enable-ClusterStorageSpacesDirect -Confirm:$False
}
ElseIf ($scenarioNumber -eq '3') {
    # Scenario 3 - cache specified.
    $Output = Enable-ClusterStorageSpacesDirect -Confirm:$False -CacheDeviceModel $cacheDeviceModel
    Set-ClusterStorageSpacesDirect -CacheModeSSD $cacheModeSSD
}

$currentDate = Get-Date -UFormat "%m.%d.%Y-%H.%M"
$path = "C:\Windows\Cluster\Reports\EnableClusterS2D" + $currentDate + ".html"
if ($Output) {
    Get-Content -Encoding Unicode $Output.EnableReportName | Out-File -LiteralPath $path
} else{
    return @{
        IsSuccess = $false
    }
}
@{ IsSuccess = $true; Path = $path }


}
## [END] Enable-WACCCClusterS2D ##
function Enable-WACCCRdma {
<#

.SYNOPSIS
Enable RDMA.

.DESCRIPTION
Enable RDMA.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]]$nics
)

function enableRdma() {
    try {
        Enable-NetAdapterRdma -Name $nics

        return @{
            IsSuccess = $true
            ErrorMessage = ''
        }
    } catch {
        return @{
            IsSuccess = $false
            ErrorMessage = $_.ToString()
        }
    }
}

enableRdma

}
## [END] Enable-WACCCRdma ##
function Get-WACCCAdapterConfigurationEvents {
<#

.SYNOPSIS
Get events for virtual machines hosted on this server.

.DESCRIPTION
Get event from the following logs on this server:
    'WindowsAdminCenter'
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$provider
)

Set-StrictMode -Version 5.0;

Microsoft.PowerShell.Diagnostics\get-winevent -FilterHashtable @{ LogName= `
    'WindowsAdminCenter';`
    level= 1,2,3,4; `
    StartTime=((Get-Date).AddMinutes(-30))} `
    -MaxEvents 45 -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object Id, TimeCreated, LogName, Level, Message, MachineName, ProviderName | Where-Object { $_.ProviderName -eq $provider }

}
## [END] Get-WACCCAdapterConfigurationEvents ##
function Get-WACCCCandidateServer {
<#

.SYNOPSIS
Validate that this server is a validate candidate cluster node.

.DESCRIPTION
To be a cluster node the following must be true:

1. Not Already a cluster node.
2. The current user is a member of the administrators group.
3. The server version is valid.

.ROLE
Readers

.PARAMETER isAzureStackHci
    Flag indicating whether script is validating in Azure Stack HCI context

#>

param (
    [Parameter(Mandatory = $true)]
    [bool]
    $isAzureStackHci,

    [Parameter(Mandatory = $true)]
    [string]
    $username
)

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue
Import-Module FailoverClusters -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

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
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-CandidateServer.ps1" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name Server2008R2BuildNumber -Option ReadOnly -Value 7600 -Scope Script
    Set-Variable -Name Server2012BuildNumber -Option ReadOnly -Value 9200 -Scope Script
    Set-Variable -Name Server2012R2BuildNumber -Option ReadOnly -Value 9600 -Scope Script
    Set-Variable -Name Server2016BuildNumber -Option ReadOnly -Value 14393 -Scope Script
    Set-Variable -Name Server2019BuildNumber -Option ReadOnly -Value 17763 -Scope Script
    Set-Variable -Name AzureStackHciSkuNumber -Option ReadOnly -Value 406 -Scope Script
    Set-Variable -Name ServerVersionValidPropertyName -Option ReadOnly -Value "ServerVersionValid" -Scope Script
    Set-Variable -Name UserIsLocalAdministratorPropertyName -Option ReadOnly -Value "UserIsLocalAdministrator" -Scope Script
    Set-Variable -Name ServerIsClusterMemberPropertyName -Option ReadOnly -Value "ServerIsClusterMember" -Scope Script
    Set-Variable -Name OSBuildNumberPropertyName -Option ReadOnly -Value "OSBuildNumber" -Scope Script
    Set-Variable -Name OSQualityReleaseVersionPropertyName -Option ReadOnly -Value "OSQualityReleaseVersion" -Scope Script
    Set-Variable -Name OSNamePropertyName -Option ReadOnly -Value "OSName" -Scope Script
    Set-Variable -Name ServerModelPropertyName -Option ReadOnly -Value "ServerModelName" -Scope Script
    Set-Variable -Name ServerManufacturerPropertyName -Option ReadOnly -Value "ServerManufacturerName" -Scope Script
    Set-Variable -Name OSNamePathPropertyName -Option ReadOnly -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Scope Script
    Set-Variable -Name OSProductNamePropertyName -Option ReadOnly -Value "ProductName" -Scope Script
    Set-Variable -Name ServerDomainPropertyName -Option ReadOnly -Value "ServerDomain" -Scope Script
    Set-Variable -Name ServerIsDomainJoinedPropertyName -Option ReadOnly -Value "ServerIsDomainJoined" -Scope Script
    Set-Variable -Name IsVMPropertyName -Option ReadOnly -Value "isVM" -Scope Script
    Set-Variable -Name HasLessThanTwoProcessorsPropertyName -Option ReadOnly -Value "hasLessThanTwoProcessors" -Scope Script
    Set-Variable -Name VirtualMachine -Option ReadOnly -Value "Virtual Machine" -Scope Script
    Set-Variable -Name ComputerSystemInstance -Option ReadOnly -Value (Get-CimInstance Win32_ComputerSystem) -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>
function cleanupScriptEnv() {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name Server2008R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2012R2BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2016BuildNumber -Scope Script -Force
    Remove-Variable -Name Server2019BuildNumber -Scope Script -Force
    Remove-Variable -Name AzureStackHciSkuNumber -Scope Script -Force
    Remove-Variable -Name ServerVersionValidPropertyName -Scope Script -Force
    Remove-Variable -Name UserIsLocalAdministratorPropertyName -Scope Script -Force
    Remove-Variable -Name ServerIsClusterMemberPropertyName -Scope Script -Force
    Remove-Variable -Name OSBuildNumberPropertyName -Scope Script -Force
    Remove-Variable -Name OSQualityReleaseVersionPropertyName -Scope Script -Force
    Remove-Variable -Name OSNamePropertyName -Scope Script -Force
    Remove-Variable -Name ServerModelPropertyName -Scope Script -Force
    Remove-Variable -Name ServerManufacturerPropertyName -Scope Script -Force
    Remove-Variable -Name OSNamePathPropertyName -Scope Script -Force
    Remove-Variable -Name OSProductNamePropertyName -Scope Script -Force
    Remove-Variable -Name ServerDomainPropertyName -Scope Script -Force
    Remove-Variable -Name ServerIsDomainJoinedPropertyName -Scope Script -Force
    Remove-Variable -Name ComputerSystemInstance -Scope Script -Force
    Remove-Variable -Name IsVMPropertyName -Scope Script -Force
    Remove-Variable -Name HasLessThanTwoProcessorsPropertyName -Scope Script -Force
    Remove-Variable -Name VirtualMachine -Scope Script -Force
}

<#

.SYNOPSIS
Get the the build number for the OS installed on this server.

.DESCRIPTION
Get the the build number for the OS installed on this server.

#>

function getBuildNumber {
    return [System.Environment]::OSVersion.Version.Build
}

function getOsQualityReleaseVersion() {
    $versionInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Microsoft.PowerShell.Utility\Select-Object UBR
    return $versionInfo.UBR
}

function getSkuNumber {
    $osData = gcim win32_operatingsystem
    return $osData.OperatingSystemSKU
}

<#

.SYNOPSIS
Is the server version supported for the requested cluster type?

.DESCRIPTION
HyperConverged is supported for Server 2016 and for build numbers greater than
or equal to Server 2019.  The builds do not stop increasing and this scripts must
be future proof.

#>

function isServerVersionSupported($isAzureStackHci) {
    $buildNumber = getBuildNumber
    $skuNumber = getSkuNumber

    # In the case of Azure Stack HCI SKU all OS versions are supported (for now)
    if ($isAzureStackHci -eq $true) {
        return ( $skuNumber -eq $AzureStackHciSkuNumber )
    }

    return ($skuNumber -ne $AzureStackHciSkuNumber) -and (($buildNumber -eq $Server2016BuildNumber) -or ($buildNumber -ge $Server2019BuildNumber))
}

<#

.SYNOPSIS
Retrieves the operating system product name for the server.

.DESCRIPTION
Retrieves the operating system product name for the server.

#>

function getOperatingSystemProductName() {
    $operatingSystemName = Get-ItemPropertyValue -Path $OSNamePathPropertyName -Name $OSProductNamePropertyName

    return $operatingSystemName
}

<#

.SYNOPSIS
Is this server already a cluster member?

.DESCRIPTION
Is this server already a cluster member?

#>

function isClusterMember() {
    $cluster = Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

    return !!$cluster
}

function hasLessThanTwoProcessors() {
    return (Get-CimInstance -ClassName Win32_Processor).NumberOfCores -lt 2
}

function isVM() {
    return $ComputerSystemInstance.model -eq $VirtualMachine;
}

<#

.SYNOPSIS
Is current user a local administrator of the node?

.DESCRIPTION
Is current user a local administrator of the node?

#>

function isLocalAdmin($username) {
    $AdministratorsGroup = (Get-LocalGroup -SID S-1-5-32-544)
    $user = Microsoft.PowerShell.LocalAccounts\Get-LocalGroupMember -Group $AdministratorsGroup -Member $username -ErrorAction SilentlyContinue -ErrorVariable +err
    if (!!$user) {
        return !!$user
    }
    else {
        $isAnAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole($AdministratorsGroup)
        return !!$isAnAdmin
    }
}

function isServerDomainJoined() {
    return $ComputerSystemInstance.PartOfDomain
}

function getServerDomain() {
    return $ComputerSystemInstance.Domain
}

function getServerModel() {
    return $ComputerSystemInstance.Model
}

function getServerManufacturer() {
    return $ComputerSystemInstance.Manufacturer
}


<#

.SYNOPSIS
Main

.DESCRIPTION
An explicit main function to fetch the settings.

#>

function main($isAzureStackHci, $username) {
    $isServerVersionSupported = isServerVersionSupported $isAzureStackHci

    $isClusterMember = isClusterMember

    $isUserLocalAdministrator = isLocalAdmin $username

    $osBuildNumber = getBuildNumber

    $osQualityReleaseVersion = getOsQualityReleaseVersion

    $osProductName = getOperatingSystemProductName

    $serverModel = getServerModel

    $serverManufacturer = getServerManufacturer

    $isServerDomainJoined = isServerDomainJoined

    $serverDomain = getServerDomain

    $isVM = isVM

    $hasLessThanTwoProcessors = hasLessThanTwoProcessors


    return New-Object PSObject -Property @{
        $ServerVersionValidPropertyName       = $isServerVersionSupported;
        $UserIsLocalAdministratorPropertyName = $isUserLocalAdministrator;
        $ServerIsDomainJoinedPropertyName     = $isServerDomainJoined
        $ServerDomainPropertyName             = $serverDomain;
        $ServerIsClusterMemberPropertyName    = $isClusterMember;
        $OSBuildNumberPropertyName            = $osBuildNumber;
        $OSQualityReleaseVersionPropertyName  = $osQualityReleaseVersion;
        $OSNamePropertyName                   = $osProductName;
        $ServerModelPropertyName              = $serverModel
        $ServerManufacturerPropertyName       = $serverManufacturer
        $IsVMPropertyName                     = $isVM
        $HasLessThanTwoProcessorsPropertyName = $hasLessThanTwoProcessors
    }
}

###############################################################################
# Script execution starts here
###############################################################################

setupScriptEnv

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue

    if (-not($clusterModule)) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: The required PowerShell module (FailoverClusters) was not found." -ErrorAction SilentlyContinue

        Write-Error $strings.FailoverClustersModuleRequired

        return @{ }
    }

    return main $isAzureStackHci $username
}
finally {
    cleanupScriptEnv
}

}
## [END] Get-WACCCCandidateServer ##
function Get-WACCCCluster {
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

$cluster = FailoverClusters\Get-Cluster -ErrorAction SilentlyContinue -ErrorVariable +err

return !!$cluster
}
## [END] Get-WACCCCluster ##
function Get-WACCCClusterNodeNames {
<#

.SYNOPSIS
Gets cluster node names.

.DESCRIPTION
Gets cluster node names.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

$nodeNames = Get-ClusterNode -ErrorAction SilentlyContinue

if ($null -eq $nodeNames) {
    return $null
}

return @($nodeNames.Name)
}
## [END] Get-WACCCClusterNodeNames ##
function Get-WACCCClusterReportList {
<#

.SYNOPSIS
List available report XML, HTM and MHT files.

.DESCRIPTION
List available XML, HTM and MHT files of provided type: validation or creation.

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$reportType
)

Set-StrictMode -Version 5.0

$ReportPath = "${env:windir}\Cluster\Reports"
$XmlReports = @(Get-ChildItem "${ReportPath}\Validation*.xml" |
    Microsoft.PowerShell.Utility\Sort-Object -Descending LastWriteTime |
    Microsoft.PowerShell.Utility\Select-Object -Property @{Name = "Path"; Expression = {$_.FullName}}, @{Name = "Date"; Expression = {$_.LastWriteTime}})

$HtmlReports = @()
$lastTestJsonPath = "${env:windir}\Cluster\Reports\WacLastTest.json"
if (Test-Path -Path $lastTestJsonPath) {
    $result = Get-Content -Path $lastTestJsonPath -Encoding UTF8 | ConvertFrom-Json
    if ($result.Type -eq $reportType -and $result.Status -eq "OK" -and (Test-Path $result.Htm)) {
        $item = Get-Item -Path $result.Htm
        $HtmlReports = @(@{
            Path = $result.Htm
            Date = $item.LastWriteTime
        })
    }
}

$Hostname = HOSTNAME.EXE
$Fqdn = [System.Net.Dns]::GetHostEntry($Hostname).HostName
@{
    XmlReports = $XmlReports
    HtmlReports = $HtmlReports
    DownloadHostName = $Fqdn
}
}
## [END] Get-WACCCClusterReportList ##
function Get-WACCCClusterReportResult {
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
$Reader.Dispose()

$Result
}
## [END] Get-WACCCClusterReportResult ##
function Get-WACCCConfigurationEvents {
<#

.SYNOPSIS
Get events for virtual machines hosted on this server.

.DESCRIPTION
Get event from the following logs on this server:
    'WindowsAdminCenter'
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

Microsoft.PowerShell.Diagnostics\get-winevent -FilterHashtable @{ LogName= `
    'WindowsAdminCenter';`
    level= 1,2,3,4; `
    StartTime=((Get-Date).AddHours(-2))} `
    -MaxEvents 10 -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object Id, TimeCreated, LogName, Level, Message, MachineName, ProviderName | Where-Object { $_.ProviderName -eq 'SmeHciScripts-ManagementAdapters' }

return $true

}
## [END] Get-WACCCConfigurationEvents ##
function Get-WACCCDomainControllerValidity {
<#
.SYNOPSIS
Validates if domain is reachable.

.DESCRIPTION
Validates if domain is reachable.

.ROLE
Readers
#>

param(
    [Parameter(Mandatory = $True)]
    [string]
    $DomainName
)

$result = Test-NetConnection $DomainName
return @{
    PingSucceeded = $result.PingSucceeded
}

}
## [END] Get-WACCCDomainControllerValidity ##
function Get-WACCCDomainStatus {
<#
.SYNOPSIS
Validates if server is domain-joined, and if so, retrieves the domain, and checks if user is in Administrators group.

.DESCRIPTION
Validates if server is domain-joined, and if so, retrieves the domain, and checks if user is in Administrators group.

.ROLE
Readers
#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $DomainAccountName
)
function getDomainStatusOfServer() {
    $IsDomainJoined = $false
    $DomainName = ''
    $isInAdminsGroup = $false
    try {
        $ServerInformation = Get-CimInstance Win32_ComputerSystem
        $IsDomainJoined = $ServerInformation.PartOfDomain
        if ($IsDomainJoined -eq $true) {
            $DomainName = $ServerInformation.Domain
            $AdministratorsGroup = (Get-LocalGroup -SID S-1-5-32-544)
            $isInAdminsGroup = Microsoft.PowerShell.LocalAccounts\Get-LocalGroupMember -Group $AdministratorsGroup -Member $DomainAccountName  -ErrorAction SilentlyContinue -ErrorVariable +err
            if (-not $isInAdminsGroup) {
                # double check if user is in-role of S-1-5-32-544 (Adminstrators), this happens if user is domain administrator.
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                if ($currentUser.Name -ieq $DomainAccountName) {
                    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
                    $isInAdminsGroup = $principal.IsInRole("S-1-5-32-544")
                }
            }
        }
        return @{
            isSuccess = $true
            isDomainJoined = $IsDomainJoined
            domainName = $DomainName
            isDomainAccountInAdminsGroup = !!$isInAdminsGroup
            errorMessage = ''
        }
    } catch {
        $errorMessage = $_.Exception.Message
        return @{
            isSuccess = $false
            isDomainJoined = $IsDomainJoined
            domainName = $DomainName
            isDomainAccountInAdminsGroup = !!$isInAdminsGroup
            errorMessage = $errorMessage
        }
    }
}

getDomainStatusOfServer

}
## [END] Get-WACCCDomainStatus ##
function Get-WACCCFaultDomainSiteConfiguration {
<#

.SYNOPSIS
Gets the fault domain site configuration for the cluster.

.DESCRIPTION
Gets the fault domain site configuration for the cluster.

.ROLE
Readers

#>

enum SiteValue {
    FirstSite = 1
    SecondSite = 2
}
$siteConfiguration = @{ IsSiteCountValid = $true }

$faultDomain = Get-ClusterFaultDomain
$sites = @()

$faultDomain | ForEach-Object {
    if ($_.Type -eq "Site") {
        $sites += @{ Name = $_.Name; Label = $_.Name }
    }
}

if ($sites.Count -ne 2) {
    $siteConfiguration.IsSiteCountValid = $false

    $sites | ForEach-Object {
        $_.Value = $null
    }
}
else {
    $sites[0] += @{ Value = [SiteValue]::FirstSite }
    $sites[1] += @{ Value = [SiteValue]::SecondSite }
}

$serverSites = @()
$faultDomainNodes = $faultDomain | Where-Object { $_.Type -eq "Node" }

$faultDomainNodes | ForEach-Object {
    $serverData = @{ ServerName = $_.Name }

    $siteName = $_.ParentName
    $site = $sites | Where-Object { $_.Name -eq $siteName }

    if ($site -eq $null) {
        $serverData += @{ Site = $null }
    }
    else {
        $serverData += @{ Site = $site }
    }

    $serverSites += $serverData
}

$siteConfiguration += @{ Sites = $sites }
$siteConfiguration += @{ Servers = $serverSites }
return $siteConfiguration

}
## [END] Get-WACCCFaultDomainSiteConfiguration ##
function Get-WACCCIpsOnNode {
<#

.SYNOPSIS
Gets results of checking if a set of IP addresses are on the on the node.

.DESCRIPTION
Gets results of checking if a set of IP addresses are on the on the node.

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory=$false)]
    [string[]]$ipAddresses
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-GetIpsOnNode" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function findIpAddresses($ipAddresses) {
    $results = @{}

    $message = "Searching for IP addresses " + $ipAddresses + " on node"
    writeInfoLog $message

    if ($null -ne $ipAddresses -and $ipAddresses.Count -gt 0) {
        foreach ($ipAddress in $ipAddresses) {
            if ($null -ne (Get-NetIPAddress -ErrorAction SilentlyContinue)) {
                $results[$ipAddress] = $true
            } else {
                $results[$ipAddress] = $false
            }
        }
    }

    $message = "IP address search results on node: " + ($results | ConvertTo-Json -Depth 4)
    writeInfoLog $message

    return $results
}

function main($ipAddresses) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return findIpAddresses $ipAddresses
}

return main $ipAddresses

}
## [END] Get-WACCCIpsOnNode ##
function Get-WACCCLastBootTime {
<#
.SYNOPSIS
Gets the last boot time for the server.

.DESCRIPTION
Gets the last boot time for the server.

.ROLE
Readers
#>

$lastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$result = $lastBootUpTime.ToFileTimeUtc()
return @{
    LastBootUpTime = ([Math]::Round($result / 10000))
}
}
## [END] Get-WACCCLastBootTime ##
function Get-WACCCNetIntentStatus {
<#

.SYNOPSIS
Get ATC networking intent status.

.DESCRIPTION
Get ATC networking intent status.

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory=$true)]
    [string[]]$intentNames,

    [Parameter(Mandatory=$true)]
    [string]$clusterName
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-Get-NetIntentStatus" -ErrorAction SilentlyContinue
Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function getIntentsStatus($intentNames, $clusterName) {
    $results = @{ statuses = @{} }

    foreach ($intentName in $intentNames) {
        $results.statuses[$intentName] = @{}
        # TODO: Go back to using cluster names from 22H2
        $statuses = Get-NetIntentStatus -Name $intentName -ClusterName 'localhost'

        foreach ($status in $statuses) {
            $results.statuses[$intentName][$status.host] = @{
                configurationStatus = $status.ConfigurationStatus
                provisioningStatus = $status.ProvisioningStatus
            }
        }
    }

    return $results
}

function main($intentNames, $clusterName) {

    $regKeyPath = 'HKLM:\Cluster'
                [string]$guid = Get-ItemPropertyValue -Path $regKeyPath -Name 'ClusterNameResource' -ErrorAction SilentlyContinue
                $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                if($clusterResource -ne $null) {
                    $state = $clusterResource.state
                    writeInfoLog $state
                }
                if ($clusterResource.state -ne "Online") {
                    $clusterResource | Start-ClusterResource
                    $message = "Started cluster resource"
                    writeInfoLog $message

                    for ($i = 0; $i -lt 5 ; $i++) {
                        $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                        if ($clusterResource.state -ne "Online") {
                            Start-Sleep 15
                        }
                        else {
                            $message = "Cluster resource is now online"
                            writeInfoLog $message
                            break;
                        }
                    }

                    $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                    if ($clusterResource.state -ne "Online") {
                        $message = "Unable to start cluster resource"
                        writeInfoLog $message
                    }
                } else {
                    $message = "Cluster resource is now online"
                    writeInfoLog $message
                }

    return getIntentsStatus $intentNames $clusterName
}

return main $intentNames $clusterName

}
## [END] Get-WACCCNetIntentStatus ##
function Get-WACCCNetIntents {
<#

.SYNOPSIS
Get ATC networking intent.

.DESCRIPTION
Get ATC networking intent.

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory=$true)]
    [string[]]$intentNames,

    [Parameter(Mandatory=$true)]
    [string]$clusterName
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-GetNetIntents" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function getIntents($intentNames, $clusterName) {
    $results = @{}

    foreach ($intentName in $intentNames) {
        $message = "Attempting to retrieved intent with name " + $intentName
        writeInfoLog $message

        $intent = $null

        try {
            $intent = Get-NetIntent -Name $intentName -ClusterName $clusterName
        } catch {
            $err = $_.Exception.Message
            if ($err) {
                $errorLog = "Couldn't get intent for intent with name " + $intentName + ". Error: " + $err
                writeErrorLog $errorLog
            }
        }

        if ($null -ne $intent) {
            $message = "Successfully retrieved intent with name " + $intent.IntentName
            writeInfoLog $message

            $intentResult = @{
                intentName = $intent.IntentName;
                isComputeIntentSet = $intent.IsComputeIntentSet;
                isStorageIntentSet = $intent.IsStorageIntentSet;
                isManagementIntentSet = $intent.IsManagementIntentSet;
                netAdapterNamesAsList = $intent.NetAdapterNamesAsList;
                adapterAdvancedParametersOverride = $intent.AdapterAdvancedParametersOverride;
                qosPolicyOverride = $intent.QosPolicyOverride;
                switchConfigOverride = $intent.SwitchConfigOverride;
            }

            $message = "Attempting to retrieved intent status with name " + $intent.IntentName
            writeInfoLog $message

            try {
                $intentStatus = Get-NetIntentStatus -Name $intentName -ClusterName $clusterName
            } catch {
                $err = $_.Exception.Message
                if ($err) {
                    $errorLog = "Couldn't get intent status for intent with name " + $intentName + ". Error: " + $err
                    writeErrorLog $errorLog
                }
            }

            $successful = @{}
            if ($null -ne $intentStatus) {
                foreach ($serverIntentStatus in $intentStatus) {
                    $successful[$serverIntentStatus.Host] = $serverIntentStatus.ConfigurationStatus -eq 'Success'
                }
            }

            $results[$intentName.ToLower()] = @{
                intent = $intentResult
                successful = $successful
            }
        }
    }

    $message = "Finished retrieving intents"
    writeInfoLog $message

    return $results
}

function main($intentNames, $clusterName) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return getIntents $intentNames $clusterName
}

return main $intentNames $clusterName
}
## [END] Get-WACCCNetIntents ##
function Get-WACCCNetIntentsSwitchNames {
<#

.SYNOPSIS
Get ATC networking intent.

.DESCRIPTION
Get ATC networking intent.

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory=$true)]
    [string[]]$intentNames,

    [Parameter(Mandatory=$true)]
    [string]$clusterName,

    [Parameter(Mandatory=$true)]
    [string]$nodeName
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-GetNetIntents" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function main($intentNames, $clusterName, $nodeName) {
    $message = "Attempting to retrieved intents goal state"
    writeInfoLog $message

    try {
        $goalState = (Get-NetIntentAllGoalStates -ClusterName $clusterName)[$nodeName]
    } catch {
        $err = $_.Exception.Message
        if ($err) {
            $errorLog = "Failed to retrieve intents goal state. Error: " + $err
            writeErrorLog $errorLog
        }

        return $null
    }

    $vSwitchNames = @{}

    foreach ($intentName in $intentNames) {
        $message = "Getting vSwitch name for intent with name " + $intentName
        writeInfoLog $message

        try {
            if ($null -ne $goalState[$intentName.ToLower()] -and $goalState[$intentName].SwitchConfig.SwitchName) {
                $vSwitchNames[$intentName.ToLower()] = $goalState[$intentName].SwitchConfig.SwitchName
            } else {
                $message = "Couldn't find vSwitch name for intent with name " + $intentName
                writeInfoLog $message

                $vSwitchNames[$intentName.ToLower()] = $null
            }
        } catch {
            $err = $_.Exception.Message
            if ($err) {
                $errorLog = "Couldn't get vSwitch name for intent with name " + $intentName + ". Error: " + $err
                writeErrorLog $errorLog
            }

            $vSwitchNames[$intentName.ToLower()] = $null
        }
    }

    return $vSwitchNames
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $intentNames $clusterName $nodeName
}
}
## [END] Get-WACCCNetIntentsSwitchNames ##
function Get-WACCCNetworkAdapters {
<#

.SYNOPSIS
Gets the network interfaces of a server.

.DESCRIPTION
Gets the network interfaces of a server.

.ROLE
Readers

#>
Param (
    [Parameter(Mandatory=$false)]
    [string]$adapterName = ''
)

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

enum InterfaceOperationalStatus {
    Up = 1
    Down = 2
    Testing = 3
    Unknown = 4
    Dormant = 5
    NotPresent = 6
    LowerlayerDown = 7
}

<#

.SYNOPSIS
Setup script runtime environment.

.DESCRIPTION
Setup script runtime environment.

#>

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Get-NetworkAdapters" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name VirtualAdapterInterfaceDescription -Option ReadOnly -Value "Hyper-V Virtual Ethernet Adapter" -Scope Script
    Set-Variable -Name NetAdapterInterfaceDescriptions -Option ReadOnly -Value "NetAdapterInterfaceDescriptions" -Scope Script
    Set-Variable -Name NetAdapterInterfaceDescription -Option ReadOnly -Value "NetAdapterInterfaceDescription" -Scope Script
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
    Remove-Variable -Name VirtualAdapterInterfaceDescription -Scope Script -Force
    Remove-Variable -Name NetAdapterInterfaceDescriptions -Scope Script -Force
    Remove-Variable -Name NetAdapterInterfaceDescription -Scope Script -Force
}

<#

.SYNOPSIS
Helper function to write the info logs to info stream.

.DESCRIPTION
Helper function to write the info logs to info stream.


.PARAMETER logMessage
log message

#>

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage
}

<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorMessage
error message

#>
function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function groupAdaptersBySpeed {
    param (
         [Parameter(Mandatory = $true)]
         [object[]]
         $rawData
    )
    $speedGrouped = $rawData | Group-Object Speed
    return $speedGrouped
}

function Get-NetAdapterDeviceBus()
{
    Param([parameter(ValueFromPipeline)] $adapter)

    $pnpId = $adapter.PnPDeviceID

    if ($null -eq $pnpId) {
        return $null
    }

    $device = Get-PnpDevice $pnpId
    $enumerator = $device | Get-PnpDeviceProperty DEVPKEY_Device_EnumeratorName
    return $enumerator.Data
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER networkId
The unique identifier of the request cluster network, or empty (null) to request all networks.

#>

setupScriptEnv

[hashtable]$retVal = @{}

try {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    $models = @()

    $physicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue -ErrorVariable +err

    if ('' -ne $adapterName) {
        $adapters = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue -ErrorVariable +err
    }
    else {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue -ErrorVariable +err
    }
    if ($err) {
        $message = "[$ScriptName]: Couldn't get the network adapters of this server. Error: $err"
        writeErrorLog $message

		$err

        return $models;
    }

    $virtualSwitchesArray = @()
    $cmdletInfo = Get-Command 'Get-VMSwitch' -ErrorAction SilentlyContinue
    if ($null -ne $cmdletInfo) {
        $virtualSwitchesArray = @(Get-VMSwitch)
    }

    $physicalAdaptersHash = @{}
    $virtualSwitchesHash = @{}
    $ipConfig = $null

    # Build a hash table of interface descriptions to virtual switches.
    foreach ($switch in $virtualSwitchesArray) {
        # If not a Switch Enabled Team (SET) switch use the NetAdapterInterfaceDescription property.
        # If it is a SET switch use the NetAdapterInterfaceDescriptions array property.
        if ($switch.PSObject.Properties.Match($NetAdapterInterfaceDescriptions).Count -eq 0) {
            if ($switch.$NetAdapterInterfaceDescription) {
                $virtualSwitchesHash += @{ $switch.$NetAdapterInterfaceDescription = $switch }
            }
        } else {
            foreach($interfaceDescription in $switch.$NetAdapterInterfaceDescriptions) {
                $virtualSwitchesHash += @{$interfaceDescription = $switch }
            }
        }
    }

    # Used to figure out which adapters are virtual switches and which are physical
    # needed so we can display virtual switches as 'In Use' while still displaying them
    foreach ($physicalAdapter in $physicalAdapters) {
        if (-not $physicalAdaptersHash.ContainsKey($physicalAdapter.MacAddress)) {
            $physicalAdaptersHash += @{$physicalAdapter.MACAddress = $physicalAdapter}
        }
    }

    foreach ($adapter in $adapters) {
        try {
            $isBoundToSwitch = Get-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID vms_pp -ErrorAction SilentlyContinue
        } catch {}
        if ($null -eq $isBoundToSwitch) {
            $isBoundToSwitch = $false
        } else {
            $isBoundToSwitch = $isBoundToSwitch.Enabled
        }

        try {
            $isIpv4Enabled = Get-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID ms_tcpip -ErrorAction SilentlyContinue
        } catch {}
        if ($null -eq $isIpv4Enabled) {
            $isIpv4Enabled = $false
        } else {
            $isIpv4Enabled = $isIpv4Enabled.Enabled
        }

        $attachedToSwitch = (!![bool]($virtualSwitchesHash[$adapter.InterfaceDescription])) -and ($isBoundToSwitch) -and -not ($isIpv4Enabled)

        try {
            $ipConfig = ($adapter | Get-NetIPAddress -AddressFamily "IPv4" -ErrorAction SilentlyContinue -ErrorVariable err)
        } catch
        { }

        if ($err) {
            $message = "[$ScriptName]: Couldn't get the IP address for $($adapter.Name). Error: $err"
            writeErrorLog $message

            $ipConfig = $null
            $ipAddressProperties = @{
                'IPAddress' = '';
                'SubnetMask' = '';
            }
        } else {
            if ($null -ne $ipConfig) {
                $firstItem = @($ipConfig)[0];
                $ipAddressProperties = @{
                    'IPAddress' = $firstItem.IPAddress;
                    'SubnetMask' = $firstItem.PrefixLength;
                }
            }
        }

        $err = $null

        try {
            $ipv6Enabled = $adapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue -ErrorVariable err
        } catch { }

        $IPv6AddressesProperties = @{
            'IPv6Addresses' = @();
            'IPv6Prefixes' = @();
            'IPv6Enabled' = $false;
        }

        if ($err) {
            $message = "[$ScriptName]: Couldn't determine if IPv6 is enabled for $($adapter.Name). Error: $err"
            writeErrorLog $message
        } else {
            if ($null -ne $ipv6Enabled) {
                $IPv6AddressesProperties['IPv6Enabled'] = $ipv6Enabled.Enabled
            }
        }

        $err = $null

        if ($IPv6AddressesProperties['IPv6Enabled'] -eq $true) {
            try {
                $ipv6Config = @(($adapter | Get-NetIPAddress -AddressFamily "IPv6" -ErrorAction SilentlyContinue -ErrorVariable err) | Microsoft.PowerShell.Core\Where-Object { !$_.IPAddress.StartsWith("fe80:") })
            } catch
            { }

            if ($err) {
                $message = "[$ScriptName]: Couldn't get the IPv6 addresses for $($adapter.Name). Error: $err"
                writeErrorLog $message
            } else {
                if ($null -ne $ipv6Config) {
                    foreach ($ipv6 in $ipv6Config) {
                        $IPv6AddressesProperties['IPv6Addresses'] += $ipv6.IPAddress
                        $IPv6AddressesProperties['IPv6Prefixes'] += $ipv6.PrefixLength
                    }
                }
            }

            $err = $null
        }

        try {
            if ($null -ne $ipConfig) {
                $netIPConfig = $adapter | Get-NetIPConfiguration -ErrorAction SilentlyContinue -ErrorVariable err
            } else {
                $netIPConfig = $null
                $err = "No IP configuration object found for adapter."
            }
        } catch { }

        $netIPConfigProperties = @{
            'DefaultGateway' = '';
            'StaticIp' = '';
        }

        if ($err -and $null -eq $netIPConfig) {
            $message = "[$ScriptName]: Couldn't get the IP configuration for $($adapter.Name). Error: $err"
            writeErrorLog $message

            $netIPConfig = $null
        } else {
            if ($null -ne $netIPConfig) {
                $firstItem = @($netIPConfig)[0];
                if ($null -ne $firstItem.IPv4DefaultGateway) {
                    $netIPConfigProperties.DefaultGateway = $firstItem.IPv4DefaultGateway.nexthop;
                }

                if ($null -ne $firstItem.NetIPv4Interface) {
                    $dhcp = $firstItem.NetIPv4Interface.Dhcp;
                    if ($dhcp -eq 'Enabled') {
                        $netIPConfigProperties.StaticIp = $false;
                    } else {
                        $netIPConfigProperties.StaticIp = $true;
                    }
                }
            }
        }

        $err = $null
        $machineInfo = Get-CimInstance win32_computersystem
        $IsPhysicalMachine = $machineInfo.model -ne 'Virtual Machine'

        $properties = @{
          'Name' = $adapter.Name;
          'InterfaceIndex' = $adapter.InterfaceIndex;
          'Description' = $adapter.InterfaceDescription;
          'Speed' = $adapter.LinkSpeed;
          'MACAddress' = $adapter.MACAddress;
          'Status' = if ($null -eq $adapter.Status) { "Unknown" } else { $adapter.Status };
          'Driver' = $adapter.DriverFileName;
          'VlanId' = $adapter.VLANID;
          'Server' = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName;
          'Connectivity' = '';
          'isAttachedToVSwitch' = $attachedToSwitch;
          'IsVirtual' = if ($null -eq $adapter.MACAddress) { $false } else { (-Not $physicalAdaptersHash.Contains($adapter.MACAddress)) };
          'HasInboxDriver' = $IsPhysicalMachine -and $adapter.DriverProvider -eq 'Microsoft'
        }

        $properties += $ipAddressProperties
        $properties += $IPv6AddressesProperties
        $properties += $netIPConfigProperties

        try {
          $hwInfo = $adapter | Get-NetAdapterHardwareInfo -ErrorAction SilentlyContinue -ErrorVariable err
        } catch {
          $hwInfo = $null
        }

        if ($err) {
            $message = "[$ScriptName]: Couldn't Get-NetAdapterHardwareInfo for $($adapter.Name). Error: $err"
            writeErrorLog $message

            $hwProperties = @{
              'Bus'= '';
              'Device' = '';
              'Function' = '';
            }
          } else {
            $hwProperties = @{
              'Bus'= $hwInfo.Bus;
              'Device' = $hwInfo.Device;
              'Function' = $hwInfo.Function;
            }
          }

        $properties += $hwProperties
        $err = $null

        try {
            $dnsClient = $adapter | Get-DnsClient -ErrorAction SilentlyContinue -ErrorVariable err
        } catch {
            $dnsClient = $null
        }

        if ($err) {
            $message = "[$ScriptName]: Couldn't Get-DnsClient for $($adapter.Name). Error: $err"
            writeErrorLog $message

            $dnsClientProperties = @{
                'ConnextionSpecificSuffix'= '';
            }
        } else {
            $dnsClientProperties = @{
                'ConnectionSpecificSuffix'= $dnsClient.ConnectionSpecificSuffix
            }
        }

        $properties += $dnsClientProperties
        $err = $null

        try {
            $dnsClientServerAddress = @($adapter | Get-DnsClientServerAddress -AddressFamily 'IPv4' -ErrorAction SilentlyContinue -ErrorVariable err)
        } catch {
            $dnsClientServerAddress = $null
        }

        $dnsClientServerAddressProperties = @{
            'DnsServerAddresses' = @();
        }

        if ($err) {
            $message = "[$ScriptName]: Couldn't Get-DnsClientServerAddress for $($adapter.Name). Error: $err"
            writeErrorLog $message
        } else {
            if ($null -ne $dnsClientServerAddress) {
                foreach ($address in $dnsClientServerAddress) {
                    $dnsClientServerAddressProperties['DnsServerAddresses'] += $address.ServerAddresses
                }
            }
        }

        $properties += $dnsClientServerAddressProperties
        $err = $null

        try {
            $deviceBus = Get-NetAdapterDeviceBus -adapter $adapter -ErrorAction SilentlyContinue -ErrorVariable err
        } catch {
            $dnsClientServerAddress = $null
        }

        if ($err) {
            $message = "[$ScriptName]: Couldn't Get-NetAdapterDeviceBus for $($adapter.Name). Error: $err"
            writeErrorLog $message

            $deviceBusProperties = @{
                'DeviceBus' = '';
            }
        } else {
            $deviceBusProperties = @{
                'DeviceBus' = $deviceBus;
            }
        }

        $properties += $deviceBusProperties
        $err = $null

        $advProperties = @{
            'RDMACapable' = '';
            'RDMAType' = '';
        }

        $properties += $advProperties

        $model = New-Object psobject -Prop $properties
        $models += $model
    }

    $retVal.rawData = $models
    $retVal.existingVirtualSwitches = $virtualSwitchesArray
    $filtered = $models | Microsoft.PowerShell.Core\Where-Object -FilterScript { $_.speed -ne '0 bps' -and $_.status -ieq 'up' -and $_.HasInboxDriver }
    if ($null -ne $filtered) {
      $retVal.filtered = $filtered
      $retVal.speedGroup = groupAdaptersBySpeed $filtered
      $speedString = $null
      $retVal.speedGroup | ForEach-Object { $speedString += $_.count.ToString() + ' ' + $_.name + ';' }
    }

	return $retVal
} finally {
    cleanupScriptEnv
}

}
## [END] Get-WACCCNetworkAdapters ##
function Get-WACCCPhysicalDisk {
<#

.SYNOPSIS
Get physical disk information.

.DESCRIPTION
Get physical disk information.

.ROLE
Readers

#>

# This returns every drive connected to the local server, including boot, virtual, etc.
$GetValidationDiskInfo = Get-CimInstance -Namespace root\microsoft\windows\cluster\validation -ClassName MSFTCluster_ValidationDiskInfo | Where-Object ExcludeFromTests -Eq $False

# This returns every drive connected to the local server plus many of the ones connected to other servers in the cluster
$GetPhysicalDisk = Get-PhysicalDisk

$Output = @()

$GetValidationDiskInfo | ForEach-Object {
    # Properties from ValidationDiskInfo, strip whitespace
    $SerialNumber = $_.SerialNumber -Replace '\s',''
    $Page83Id = $_.Page83Id -Replace '\s',''

    # Find matching PhysicalDisk, using either SerialNumber or UniqueId (depends on the type of drive)
    $Matches = @() # Empty
    $Matches += $GetPhysicalDisk | Where-Object SerialNumber -Like $SerialNumber
    $Matches += $GetPhysicalDisk | Where-Object UniqueId -Like $Page83Id

    If ($Matches) {
        $PhysicalDisk = $Matches[0] # Simply use the first match (it's possible it matched both ways)

        # Synthesize "type" from MediaType and BusType
        If ($PhysicalDisk.BusType -Eq "NVMe") {
            $Type = $PhysicalDisk.BusType
            $IsMediaType = $false
        }
        Else { # SATA, SAS, PMEM
            $Type = $PhysicalDisk.MediaType
            $IsMediaType = $true
        }

        # Join into combined object
        $Obj = [PsCustomObject]@{
            "Server"       = $_.PSComputerName
            "Type"         = $Type
            "IsMediaType"  = $IsMediaType
            "Model"        = $PhysicalDisk.FriendlyName
            "SerialNumber" = $PhysicalDisk.SerialNumber
            "Size"         = [math]::truncate($PhysicalDisk.Size / 1GB)
            "Firmware"     = $PhysicalDisk.FirmwareVersion
            "Location"     = $PhysicalDisk.PhysicalLocation
            "StatusColor"  = $PhysicalDisk.HealthStatus
            "StatusText"   = $PhysicalDisk.OperationalStatus
        }
        $Output += $Obj
    }
}

$Output

}
## [END] Get-WACCCPhysicalDisk ##
function Get-WACCCRestartPending {
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

function Get-SystemNameChangeStatus {
    $nvName = Get-ItemPropertyValue -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "NV Hostname"
    $name = Get-ItemPropertyValue -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "Hostname"
    $nvDomain = Get-ItemPropertyValue -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "NV Domain"
    $domain = Get-ItemPropertyValue -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "Domain"
    return ($nvName -ne $name) -or ($nvDomain -ne $domain)
}

function Test-PendingReboot {
    $value = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
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
## [END] Get-WACCCRestartPending ##
function Get-WACCCRolesAndFeatures {
<#

.SYNOPSIS
Gets a list of Features / Roles / Role Services on the target server.

.DESCRIPTION
The data returned for each includes name, description, installstate, installed?... Can be called with a FeatureList or FeatureType both of which are optional.

.EXAMPLE
./GetFeaturesAndRoles.ps1
When called with no parameters, returns data for all roles, features and role services available on the server

.EXAMPLE
./GetFeaturesAndRoles.ps1 -FeatureList 'Web-Server'
When called with a FeatureList (e.g. Web-Server) returns details for the given feature if it is available

.EXAMPLE
./GetFeaturesAndRoles.ps1 -FeatureType 'Role'
When called with a FeatureType ('Role', 'Feature' or 'Role Service) returns details for all avilable features of that FeatureType

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $False)]
    [string[]]
    $FeatureList = '',

    [Parameter(Mandatory = $False)]
    [ValidateSet('Role', 'Role Service', 'Feature', IgnoreCase = $False)]
    [string]
    $FeatureType = ''
)

Import-Module ServerManager

$result = $null
$isVM = 'false'
$hostname = ''

if ($FeatureList) {
    $result = Get-WindowsFeature $FeatureList
}
else {
    if ($FeatureType) {
        $result = Get-WindowsFeature | Where-Object { $_.FeatureType -EQ $FeatureType }
    }
    else {
        $result = Get-WindowsFeature
    }
}

if ($result.name -eq 'Hyper-V' -OR $result.name -eq 'Hyper-V') {
    $machineInfo = Get-CimInstance win32_computersystem   # can tell if it's a VM.

    if ($machineInfo.model -eq 'Virtual Machine') {
        $isVm = 'true'
        $hostname = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').GetValue('HostName')
    }
}

return New-Object PSObject -Property @{
    "results"  = $result
    "hostname" = $hostname
    "isVM"     = $isVM
}


}
## [END] Get-WACCCRolesAndFeatures ##
function Get-WACCCS2DEnabled {
<#

.SYNOPSIS
Get if S2D enabled.

.DESCRIPTION
Get if S2D enabled.

.ROLE
Readers

#>

(Get-Cluster).S2DEnabled
}
## [END] Get-WACCCS2DEnabled ##
function Get-WACCCServerDynamicSiteName {
<#

.SYNOPSIS
Gets the dynamic site name set on the machine by AD.

.DESCRIPTION
Gets the dynamic site name set on the machine by AD.

.ROLE
Readers

#>

enum SiteValue {
    DefaultSite = 0
    FirstSite = 1
}

$siteRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$sitePropertyName = "DynamicSiteName"
$defaultSiteName = "Default-First-Site-Name"

$dynamicSiteRegistry = Get-ItemProperty -Path $siteRegistryPath -Name $sitePropertyName

$dynamicSite = @{ Name = $dynamicSiteRegistry.DynamicSiteName; Label = $dynamicSiteRegistry.DynamicSiteName}
if (!($dynamicSiteRegistry.DynamicSiteName -eq $defaultSiteName)) {
    $dynamicSite += @{ Value = [SiteValue]::FirstSite }
}
else {
    $dynamicSite += @{ Value = [SiteValue]::DefaultSite }
}

return $dynamicSite

}
## [END] Get-WACCCServerDynamicSiteName ##
function Get-WACCCSupportedRdmaMode {
<#
.SYNOPSIS
Determines if RDMA is supported on adapters & if so, retrieves their supported mode (iWARP, RoCE, etc).

.DESCRIPTION
Determines if RDMA is supported on adapters & if so, retrieves their supported mode (iWARP, RoCE, etc).

.ROLE
Readers
#>

param (
    [Parameter(Mandatory = $true)]
    [string[]]$nics
)

function getSupportedRDMAMode() {

    Set-Variable -Name NetworkDirectRegKey -Option Constant -Value "*NetworkDirect" -ErrorAction SilentlyContinue
    Set-Variable -Name NetworkDirectTechnologyRegKey -Option Constant -Value "*NetworkDirectTechnology" -ErrorAction SilentlyContinue
    Set-Variable -Name EnabledState -Option Constant -Value "Enabled" -ErrorAction SilentlyContinue
    Set-Variable -Name iWARP -Option Constant -Value "iWARP" -ErrorAction SilentlyContinue
    Set-Variable -Name RoCE -Option Constant -Value "RoCE" -ErrorAction SilentlyContinue
    Set-Variable -Name RoCEv2 -Option Constant -Value "RoCEv2" -ErrorAction SilentlyContinue

    try {
        $output = @()
        $isMissingRegKeys = $false

        foreach ($nic in $nics) {
            $networkDirectRegKeyResult = Get-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectRegKey

            if ($null -eq $networkDirectRegKeyResult) {
                $isMissingRegKeys = $true
                break
            }

            $networkDirectTechnologyRegKeyResult = Get-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectTechnologyRegKey -AllProperties

            if ($null -eq $networkDirectTechnologyRegKeyResult) {
                $isMissingRegKeys = $true
                break
            }

            # There are edge cases in which the user's hardware does support RDMA, but the *NetworkDirectTechnology reg key is not set correctly. Example: It might say 'Device Default'.
            # In this case, we check the list of valid values in the 'ValidDisplayValues' property (array), and set a valid reg key value manually.
            # The priority, if we manually set the type is: iWARP --> RoCEv2 --> RoCE, as below.

            if ($networkDirectTechnologyRegKeyResult.DisplayValue -ne $iWARP -and $networkDirectTechnologyRegKeyResult.DisplayValue -ne $RoCE -and $networkDirectTechnologyRegKeyResult.DisplayValue -ne $RoCEv2) {
                if ($networkDirectTechnologyRegKeyResult.ValidDisplayValues -contains $iWARP) {
                    Set-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectTechnologyRegKey -DisplayValue $iWARP -RegistryValue 1
                } elseif ($networkDirectTechnologyRegKeyResult.ValidDisplayValues -contains $RoCEv2) {
                    Set-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectTechnologyRegKey -DisplayValue $RoCEv2 -RegistryValue 4
                } elseif ($networkDirectTechnologyRegKeyResult.ValidDisplayValues -contains $RoCE) {
                    Set-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectTechnologyRegKey -DisplayValue $RoCE -RegistryValue 3
                }
                $networkDirectTechnologyRegKeyResult = Get-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword $NetworkDirectTechnologyRegKey -AllProperties
            }

            $output += [PsCustomObject]@{
                "adapterName"                = $nic
                "isRdmaSupportedOnAdapter"   = $true
                "supportedRdmaMode"          = $networkDirectTechnologyRegKeyResult.DisplayValue
            }
        }

        return @{
            isSuccess = $true
            adapterResults = $output
            errorMessage = ""
            isMissingRegKeys = $isMissingRegKeys
        }
    } catch {
        return @{
            isSuccess = $false
            adapterResults = @()
            errorMessage =  $_.Exception.Message
            isMissingRegKeys = $false
        }
    }
}

getSupportedRDMAMode

}
## [END] Get-WACCCSupportedRdmaMode ##
function Get-WACCCVirtualSwitchConfigurationEvents {
<#

.SYNOPSIS
Get events for virtual machines hosted on this server.

.DESCRIPTION
Get event from the following logs on this server:
    'WindowsAdminCenter'
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

Microsoft.PowerShell.Diagnostics\get-winevent -FilterHashtable @{ LogName= `
    'WindowsAdminCenter';`
    level= 1,2,3,4; `
    StartTime=((Get-Date).AddHours(-2))} `
    -MaxEvents 20 -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object Id, TimeCreated, LogName, Level, Message, MachineName, ProviderName | Where-Object { $_.ProviderName -eq 'SmeHciScripts-VirtualSwitch' }

}
## [END] Get-WACCCVirtualSwitchConfigurationEvents ##
function Get-WACCCVirtualSwitches {
<#

.SYNOPSIS
Get virtual switches.

.DESCRIPTION
Get virtual switches.

.ROLE
Administrators

#>

return Get-VMSwitch
}
## [END] Get-WACCCVirtualSwitches ##
function Get-WACCCWindowsUpdateStatus {
<#
.SYNOPSIS
Get windows update history through COM object by Windows Update Agent API.

.DESCRIPTION
Get windows update history through COM object by Windows Update Agent API.

.ROLE
Readers
#>

function getWindowsUpdatesHistory() {

    try {
        $session = Microsoft.PowerShell.Utility\New-Object -ComObject "Microsoft.Update.Session" 
 
        $searcher = $session.CreateUpdateSearcher() 
     
        $historyCount = $searcher.GetTotalHistoryCount() 
    
        # there is no update history available.
        if ($historyCount -eq 0) {
            return @{
                IsSuccess       = $true
                IsUpdateHistory = $false
                ErrorMessage    = $null
            }
        }

        $updatesHistory = $Searcher.QueryHistory(0, $historyCount) | Microsoft.PowerShell.Core\Where-Object { $_.Operation -eq 1 } | `
            Microsoft.PowerShell.Utility\Select-Object Title, `
        @{Name = "InstallState"; Expression = { $_.ResultCode } }, `
        @{Name = "UpdateID"; Expression = { $_.UpdateIdentity | Microsoft.PowerShell.Utility\Select-Object UpdateID } } | `
            Microsoft.PowerShell.Utility\Select-Object -Property * -ExcludeProperty UpdateID -ExpandProperty UpdateID

        return @{
            IsSuccess       = $true
            IsUpdateHistory = $true
            ErrorMessage    = $null
            UpdatesHistory  = @{ Data = $updatesHistory }
        }
    } 
    catch {
        return @{
            IsSuccess       = $false
            IsUpdateHistory = $false
            ErrorMessage    = $_.ToString()
        }
    }
}

getWindowsUpdatesHistory

}
## [END] Get-WACCCWindowsUpdateStatus ##
function Get-WACCCWindowsUpdates {
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
$objResults = $objSearcher.Search("IsInstalled = 0")

if (!$objResults -or !$objResults.Updates) {
    return $null
}

foreach ($objResult in $objResults.Updates) {
    $objResult | Microsoft.PowerShell.Utility\Select-Object Title, IsMandatory, RebootRequired, MsrcSeverity, `
    @{Name = "UpdateID"; Expression = { $_.Identity | Microsoft.PowerShell.Utility\Select-Object UpdateID } } | `
        Microsoft.PowerShell.Utility\Select-Object -Property * -ExcludeProperty UpdateID -ExpandProperty UpdateID
}

}
## [END] Get-WACCCWindowsUpdates ##
function Install-WACCCFeature {
<#
.SYNOPSIS
Installs a feature on the target server.

.DESCRIPTION
Installs a feature on the target server.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $true)]
    [string]
    $FeatureName
  )

Import-Module ServerManager

$feature = Get-WindowsFeature -Name $FeatureName

Enum InstallStatus {
  Failed = 0
  Succeeded = 1
  NoSuchFeature = 2
  AlreadyInstalled = 3
  Pending = 4
  NestedVirtualizationNotEnabled = 5
}

$result = $Null
$status = $Null
$success = $False

If ($feature) {
  If ($feature.Where({ $_.InstallState -eq 'Available' -or $_.InstallState -eq 'UninstallPending' -or $_.InstallState -eq 'InstallPending'})) {
    Try {
      $result = Install-WindowsFeature -Name $FeatureName
      $success = $result -and $result.Success
      $status = if ($success) { [InstallStatus]:: Succeeded } Else { [InstallStatus]:: Failed }
    }
    Catch {
      If($success -and $Restart -and $result.restartNeeded -eq 'Yes') {
        $status = [InstallStatus]:: Pending
        $error.clear()
      } Else {
        Throw
      }
      Catch {
        If($success -and $Restart -and $result.restartNeeded -eq 'Yes') {
          $status = [InstallStatus]:: Pending
          $error.clear()
        }
        Else {
          Throw
        }
      }
    }
  } Else {
    $success = $True
    $status = [InstallStatus]:: AlreadyInstalled
  }
} Else {
  $success = $False
  $status = [InstallStatus]:: NoSuchFeature
}

@{ Success = $success ; Name = $feature.Name ; Status = $status ; Result = $result }
}
## [END] Install-WACCCFeature ##
function Install-WACCCRolesAndFeatures {
<#

.SYNOPSIS
Installs a Feature/Role/Role Service on the target server.

.DESCRIPTION
Installs a Feature/Role/Role Service on the target server, using Install-WindowsFeature PowerShell cmdlet. Returns a status object
that contains the following properties:
success - true/false depending on if the overall operation Succeeded
status - status message
result - response from Install-WindowsFeature call

.PARAMETER FeatureName
Is a required parameter and is the name of the Role/Feature/Role Service to install

.PARAMETER IncludeAllSubFeature
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.PARAMETER IncludeManagementTools
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'ManagementOData'
Installs the feature 'ManagementObject' without subfeature and management tools

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'Web-Server' -IncludeAllSubFeature -IncludeManagementTools
Installs the role 'Web-Server' with all dependencies and management tools

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'ManagementOData'
Installs the feature 'ManagementObject' without subfeature and management tools.

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [string[]]
    $FeatureNames,

    [Parameter(Mandatory = $False)]
    [Switch]
    $IncludeAllSubFeature,

    [Parameter(Mandatory = $False)]
    [Switch]
    $IncludeManagementTools,

    [Parameter(Mandatory = $False)]
    [Switch]
    $WhatIf
)

$ErrorActionPreference = "Stop"

Import-Module ServerManager


Enum InstallStatus {
    Failed = 0
    Succeeded = 1
    NoSuchFeature = 2
    AlreadyInstalled = 3
    Pending = 4
    NestedVirtualizationNotEnabled = 5
}

Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048

$Output = @()

foreach ($featureName in @($FeatureNames)) {
    $feature = Get-WindowsFeature -Name $featureName
    $success = $False
    $status = $Null
    $result = $Null
    If ($feature) {
        If ($feature.Where( { $_.InstallState -eq 'Available' -or $_.InstallState -eq 'UninstallPending' -or $_.InstallState -eq 'InstallPending' } )) {
            Try {
                $result = Install-WindowsFeature -Name $featureName -IncludeAllSubFeature:$IncludeAllSubFeature -IncludeManagementTools:$IncludeManagementTools -WhatIf:$WhatIf
                $success = $result -and $result.Success
                $status = if ($success) { [InstallStatus]::Succeeded } Else { [InstallStatus]::Failed }
                If ($featureName -eq 'NetworkHUD' -and $success) {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                    Install-Module -Name Az.StackHCI.NetworkHUD -Force | Out-Null
                }
            }
            Catch {
                If ($featureName -eq 'Hyper-V') {
                    $success = $False
                    $status = [InstallStatus]::NestedVirtualizationNotEnabled
                }
                Else {
                    Throw
                }
            }
        }
        Else {
            $success = $True
            $status = [InstallStatus]::AlreadyInstalled
        }
    }
    Else {
        $success = $False
        $status = [InstallStatus]::NoSuchFeature
    }

    # Join into combined object
    $Obj = [PsCustomObject]@{
        "success" = $success
        "status"  = $status
        "name"    = $feature.name
        "result"  = $result
    }

    $Output += $Obj
}

$Output

}
## [END] Install-WACCCRolesAndFeatures ##
function Install-WACCCWindowsUpdatesCC {
<#

.SYNOPSIS
Create a scheduled task to run a powershell script file to installs all available windows updates through ComObject.

.DESCRIPTION
Create a scheduled task to run a powershell script file to installs given windows updates through ComObject.
This is a workaround since CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
More details see https://msdn.microsoft.com/en-us/library/windows/desktop/aa387288(v=vs.85).aspx

.ROLE
Administrators

.PARAMETER serverSelection
  update service server

.PARAMETER updateIDs
  the list of update IDs to be installed

#>

param (
    [Parameter(Mandatory = $true)]
    [int16]$serverSelection,
    [Parameter(Mandatory = $true)]
    [String[]]$updateIDs,
    [Parameter(Mandatory = $true)]
    [boolean]
    $fromTaskScheduler
)

function installWindowsUpdates() {
    param (
        [int16]
        $serverSelection,
        [String[]]
        $updateIDs
    )
    $objServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager';
    $objSession = New-Object -ComObject 'Microsoft.Update.Session';
    $objSearcher = $objSession.CreateUpdateSearcher();
    $objSearcher.ServerSelection = $serverSelection;
    $serviceName = 'Windows Update';
    $search = 'IsInstalled = 0';
    $objResults = $objSearcher.Search($search);
    $Updates = $objResults.Updates;
    $FoundUpdatesToDownload = $Updates.Count;

    $NumberOfUpdate = 1;
    $objCollectionDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $updateCount = $updateIDs.Count;
    Foreach ($Update in $Updates) {
        If ($Update.Identity.UpdateID -in $updateIDs) {
            Write-Progress -Activity 'Downloading updates' -Status `"[$NumberOfUpdate/$updateCount]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate / $updateCount * 100));
            $NumberOfUpdate++;
            Write-Debug `"Show` update` to` download:` $($Update.Title)`" ;
            Write-Debug 'Accept Eula';
            $Update.AcceptEula();
            Write-Debug 'Send update to download collection';
            $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
            $objCollectionTmp.Add($Update) | Out-Null;

            $Downloader = $objSession.CreateUpdateDownloader();
            $Downloader.Updates = $objCollectionTmp;
            Try {
                Write-Debug 'Try download update';
                $DownloadResult = $Downloader.Download();
            } <#End Try#>
            Catch {
                If ($_ -match 'HRESULT: 0x80240044') {
                    Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
                } <#End If $_ -match 'HRESULT: 0x80240044'#>

                Return
            } <#End Catch#>

            Write-Debug 'Check ResultCode';
            Switch -exact ($DownloadResult.ResultCode) {
                0 { $Status = 'NotStarted'; }
                1 { $Status = 'InProgress'; }
                2 { $Status = 'Downloaded'; }
                3 { $Status = 'DownloadedWithErrors'; }
                4 { $Status = 'Failed'; }
                5 { $Status = 'Aborted'; }
            } <#End Switch#>

            If ($DownloadResult.ResultCode -eq 2) {
                Write-Debug 'Downloaded then send update to next stage';
                $objCollectionDownload.Add($Update) | Out-Null;
            } <#End If $DownloadResult.ResultCode -eq 2#>
        }
    }

    $ReadyUpdatesToInstall = $objCollectionDownload.count;
    Write-Verbose `"Downloaded` [$ReadyUpdatesToInstall]` Updates` to` Install`" ;
    If ($ReadyUpdatesToInstall -eq 0) {
        Return;
    } <#End If $ReadyUpdatesToInstall -eq 0#>

    $NeedsReboot = $false;
    $NumberOfUpdate = 1;

    <#install updates#>
    Foreach ($Update in $objCollectionDownload) {
        Write-Progress -Activity 'Installing updates' -Status `"[$NumberOfUpdate/$ReadyUpdatesToInstall]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate / $ReadyUpdatesToInstall * 100));
        Write-Debug 'Show update to install: $($Update.Title)';

        Write-Debug 'Send update to install collection';
        $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
        $objCollectionTmp.Add($Update) | Out-Null;

        $objInstaller = $objSession.CreateUpdateInstaller();
        $objInstaller.Updates = $objCollectionTmp;

        Try {
            Write-Debug 'Try install update';
            $InstallResult = $objInstaller.Install();
        } <#End Try#>
        Catch {
            If ($_ -match 'HRESULT: 0x80240044') {
                Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
            } <#End If $_ -match 'HRESULT: 0x80240044'#>

            Return;
        } #End Catch

        If (!$NeedsReboot) {
            Write-Debug 'Set instalation status RebootRequired';
            $NeedsReboot = $installResult.RebootRequired;
        } <#End If !$NeedsReboot#>
        $NumberOfUpdate++;
    } <#End Foreach $Update in $objCollectionDownload#>
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
        installWindowsUpdates $serverSelection $updateIDs;
        return;
    }
}
else {
    #In non-WDAC environment script file will not be available on the machine
    #Hence, a dynamic script is created which is executed through the task Scheduler
    $ScriptFile = $env:LocalAppData + "\Install-Updates.ps1"
}

#Create a scheduled task
$TaskName = "SMEWindowsUpdateInstallUpdates"

$User = [Security.Principal.WindowsIdentity]::GetCurrent()
$Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

#$OFS is a special variable that contains the string to be used as the Ouptut Field Separator.
#This string is used when an array is converted to a string.  By default, this is " " (white space).
#Change it to separate string array $updateIDs as xxxxx,yyyyyy etc.
$OFS = ","
$tempUpdateIds = [string]$updateIDs

if ($isWdacEnforced) {
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.ClusterCreation; Install-WACCCWindowsUpdatesCC -fromTaskScheduler `$true -serverSelection $serverSelection -updateIDs $tempUpdateIds}"""
}
else {
    (Get-Command installWindowsUpdates).ScriptBlock | Set-Content -path $ScriptFile
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Set-Location -Path $env:LocalAppData; .\Install-Updates.ps1 -serverSelection $serverSelection -updateIDs $tempUpdateIds}"""
}
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
            Write-EventLog -LogName Application -Source "SME Windows Updates Install Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
            Write-Error "Can't connect to Schedule service" -ErrorAction Stop
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
    $RootFolder.DeleteTask($TaskName, 0)
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

#Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
#Wait for running task finished
$RootFolder.GetTask($TaskName).Run(0) | Out-Null
while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
    Start-Sleep -s 1
}

#Clean up
$RootFolder.DeleteTask($TaskName, 0)
if (!$isWdacEnforced) {
    Remove-Item $ScriptFile
}
## [END] Install-WindowsUpdates ##

}
## [END] Install-WACCCWindowsUpdatesCC ##
function Invoke-WACCCAdapterTeamingCheck {
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
    [PSObject[]]$adapters
)

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

function determineAdapterTeaming($item, $remaining) {
    $mismatches = $remaining | Where-Object -FilterScript { $_ -ne $item }
    if ($mismatches) {
        return $false;
    }
    return $true;
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
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER serverNames
The servers to add to the cluster.

#>

function main([PSObject[]] $adapters) {
    $first = $adapters[0]
    $rest = $adapters[1..($adapters.length - 1)]
    return determineAdapterTeaming $first $rest
}

###############################################################################
# Script execution starts here...
###############################################################################

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

return main $adapters

}
## [END] Invoke-WACCCAdapterTeamingCheck ##
function Join-WACCCDomain {
<#
.SYNOPSIS
Joins server to domain.

.DESCRIPTION
Joins server to domain.

.ROLE
Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $IsNewName,
    [Parameter(Mandatory = $true)]
    [string]
    $NewComputerName,
    [Parameter(Mandatory = $true)]
    [string]
    $DomainName,
    [Parameter(Mandatory = $true)]
    [string]
    $Username,
    [Parameter(Mandatory = $true)]
    [string]
    $Password
)

function addComputerToDomain() {
    try {
        $serverInformation = Get-CimInstance Win32_ComputerSystem
        if ($serverInformation.PartOfDomain -and ($serverInformation.Domain -ieq $DomainName)) {
            # quit since the domain name and machine name are already configured.
            return @{
                IsSuccess    = $true
                ErrorMessage = $null
            }
        }

        # current planned name to avoid renaming again.
        $plannedNewName = Get-ItemPropertyValue -Path hklm:System\CurrentControlSet\Services\Tcpip\Parameters -Name "NV Hostname"
        if ($IsNewName -and ($plannedNewName -ine $NewComputerName)) {
            $err = $null
            Rename-Computer -NewName $NewComputerName -ErrorAction SilentlyContinue -ErrorVariable +err
            if ($err) {
                return @{
                    IsSuccess    = $false
                    ErrorMessage = @($err)[0].ToString()
                    Rename       = $true
                }
            }

            Start-Sleep 2
        }

        $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $securePassword
        $err = $null
        if ($IsNewName) {
            $joined = Add-computer -DomainName $Domainname -Credential $creds -Force -Options JoinWithNewName, AccountCreate -PassThru -ErrorAction SilentlyContinue -ErrorVariable +err
        }
        else {
            $joined = Add-Computer -DomainName $DomainName -Credential $creds -Force -Options AccountCreate -PassThru -ErrorAction SilentlyContinue -ErrorVariable +err
        }

        # Notes:
        # list of possible FullyQualifiedErrorId code
        #   "FailToRenameAfterJoinDomain,Microsoft.PowerShell.Commands.AddComputerCommand"
        #     - rename was failed.
        #   "AddComputerToSameDomain,Microsoft.PowerShell.Commands.AddComputerCommand"
        #     - if machine name was already on the domain.

        if ($err) {
            return @{
                IsSuccess             = $false
                ErrorMessage          = @($err)[0].ToString()
                FullyQualifiedErrorId = @($err)[0].FullyQualifiedErrorId
            }
        }

        return @{
            IsSuccess        = $true
            ErrorMessage     = $null
            Joined           = $joined
        }
    }
    catch {
        return @{
            IsSuccess    = $false
            ErrorMessage = $_.ToString()
            Catched      = $true
        }
    }
}

addComputerToDomain

}
## [END] Join-WACCCDomain ##
function New-WACCCCluster {
<#

.SYNOPSIS
Create cluster from given servers.

.DESCRIPTION
Create cluster from given servers with specified parameters.

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [string]$clusterName,

    [Parameter(Mandatory = $true)]
    [string[]]$nodes,

    [Parameter(Mandatory = $false)]
    [boolean]
    $noStorage,

    [Parameter(Mandatory = $false)]
    [string[]]$networkSpaces,

    [Parameter(Mandatory = $false)]
    [string[]]$addresses
)

$HashArguments = @{ }

if ($networkSpaces) {
    $HashArguments['IgnoreNetwork'] = $networkSpaces
}

if ($addresses) {
    $HashArguments['StaticAddress'] = $addresses
}

Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-NewCluster" -ErrorAction SilentlyContinue

Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

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
Helper function to write info to event log stream.

.DESCRIPTION
Helper function to write info to event log stream.


.PARAMETER errorRecords
May, or may not, be an array of info...

#>

function writeInfo($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
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

writeInfo "Creating cluster with name ${clusterName}."

$clusterObject = New-Cluster -Name $clusterName -Node $nodes -NoStorage:$noStorage @HashArguments -Force `
    -ErrorAction SilentlyContinue -ErrorVariable +errorRecords -WarningVariable +warningRecords

writeInfo "Created cluster with name ${clusterName}."

$HtmlReports = @(Get-ChildItem "${env:windir}\Cluster\Reports\Create Cluster Wizard ${clusterName}*.htm" -ErrorAction SilentlyContinue |
    Microsoft.PowerShell.Utility\Sort-Object -Descending LastWriteTime |
    Microsoft.PowerShell.Utility\Select-Object -Property @{Name = "Path"; Expression = { $_.FullName } }, @{Name = "Date"; Expression = { $_.LastWriteTime } }, @{Name = "Diff"; Expression = { ($nowtime - $_.CreationTime).TotalHours -lt 1 } } |
    Where-Object -Property Diff -eq $True)

writeInfo "Created cluster report."

if ($HtmlReports.Count -gt 0) {
    $htmlPath = $HtmlReports[0].Path
    $lastTestJsonPath = "${env:windir}\Cluster\Reports\WacLastTest.json"
    $result = @{
        Type   = "CreateClusterWizard"
        Htm    = $htmlPath
        Status = "OK"
        Date   = (Get-Date).ToString()
        ISODate = Get-Date -Format "o"
    }
    $result | ConvertTo-Json | Set-Content -Path $lastTestJsonPath -Encoding UTF8
}

writeInfo "Created result object."

if ($errorRecords) {
    writeErrors $errorRecords
    return $null
}

if ($warningRecords) {
    writeWarnings $warningRecords
}

writeInfo "Wrote errors and warnings if any."

return $clusterObject

}
## [END] New-WACCCCluster ##
function Remove-WACCCVirtualSwitches {
<#

.SYNOPSIS
Remove virtual switches.

.DESCRIPTION
Remove virtual switches.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $false)]
    [bool]$removeManagementSwitches = $false,
    [Parameter(Mandatory = $false)]
    [string[]]$existingSwitchesToKeep = @()
)

$vmSwitches = Get-VMSwitch

if ($removeManagementSwitches -eq $false) {
    $vmSwitches = $vmSwitches | Where-Object { $_.name -NotLike '*Management*' }
}
else {
    $managementSwitches = $vmSwitches | Where-Object {$_.name -eq 'Management Virtual Switch'}

    foreach ($switch in $managementSwitches) {
        # Note: Management Physical 1 is cleaned up with removal of VMNetworkAdapter and VMSwitch, only Management Physical 2 is set as a team member
        Remove-VMSwitchTeamMember -VMSwitchName $switch.name -NetAdapterName 'Management Physical 2' -ErrorAction SilentlyContinue
        Remove-VMNetworkAdapter -ManagementOS -Name 'Management' -SwitchName $switch.name -ErrorAction SilentlyContinue
    }
}

# Filter the switches from above to exclude existing switches
$switchesToRemove = @()
foreach ($switch in $vmSwitches) {
    if (-not $existingSwitchesToKeep.contains($switch.Name)) {
        $switchesToRemove += @($switch)
    }
}

$switchesToRemove | Remove-VMSwitch -Force:$true -ErrorAction SilentlyContinue

Register-DnsClient -ErrorAction SilentlyContinue

}
## [END] Remove-WACCCVirtualSwitches ##
function Reset-WACCCStorageDrives {
<#

.SYNOPSIS
Clean and reset storage provider cache.

.DESCRIPTION
Clean and reset storage provider cache

.ROLE
Administrators

#>

Update-StorageProviderCache
Get-StoragePool | Where-Object IsPrimordial -Eq $False | Set-StoragePool -IsReadOnly:$False -ErrorAction SilentlyContinue
Get-StoragePool | Where-Object IsPrimordial -Eq $False | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$False -ErrorAction SilentlyContinue
Get-StoragePool | Where-Object IsPrimordial -Eq $False | Remove-StoragePool -Confirm:$False -ErrorAction SilentlyContinue
Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
Get-Disk | Where-Object Number -Ne $Null | Where-Object IsBoot -Ne $True | Where-Object IsSystem -Ne $True | Where-Object PartitionStyle -Ne RAW | ForEach-Object {
    $_ | Set-Disk -IsOffline:$False
    $_ | Set-Disk -IsReadOnly:$False
    $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$False
    $_ | Set-Disk -IsReadOnly:$True
    $_ | Set-Disk -IsOffline:$True
}

}
## [END] Reset-WACCCStorageDrives ##
function Restart-WACCCServer {
<#

.SYNOPSIS
Restart server.

.DESCRIPTION
Restart server.

.ROLE
Administrators

#>

param(
    [Parameter(Mandatory = $True)]
    [string]
    $Server
)

Restart-Computer -ComputerName $Server -Force

}
## [END] Restart-WACCCServer ##
function Restart-WACCCWinRM {
<#

.SYNOPSIS
Restart Windows Remote Management.

.DESCRIPTION
Restart Windows Remote Management.

.ROLE
Administrators

#>

#
# Restaring WinRM disconnects and terminates current PowerShell session.
# A scheduled task avoids of crash of Restart-Sevice operaion.
#
$TaskName = "WACOneTimeRestartWinRMTask"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$ScriptBlock = {
    Restart-Service -Name WinRM -Force
    Unregister-ScheduledTask -TaskName "WACOneTimeRestartWinRMTask" -Confirm:$false -ErrorAction SilentlyContinue
}

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -command `"& {$ScriptBlock}`""
$task = Register-ScheduledTask -Action $action -TaskName $TaskName -User "NT Authority\System"
$task.Settings.DisallowStartIfOnBatteries = $false
$settings = $task.settings
Set-ScheduledTask -TaskName $TaskName -Settings $settings
Start-ScheduledTask -TaskName $TaskName

}
## [END] Restart-WACCCWinRM ##
function Set-WACCCAdapterNames {
<#

.SYNOPSIS
Set network adapter names.

.DESCRIPTION
Set network adapter names.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PSObject[]]$adapters
)

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-SetAdapterNames" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function calculateNameForOldAdapter($newName) {
    $oldAdapters = @{}

    # Search for adapters that start with newName and insert them into oldAdapters
    $key = "$($newName)*"
    Get-NetAdapter | Foreach-Object { 
        if ($_.Name -Like ($key)) {
            $oldAdapters[$_.Name] = ''
        }
    }

    $index = 0
    $temp = "$($newName)"

    # Find next available index to append to newName
    while ($null -ne $oldAdapters[$temp]) {
        $index++
        $temp = "$($newName)$($index)"
    }

    return $temp
}

function renameAdapter($adapter, [ref]$renames) {
    $currentAdapter = Get-NetAdapter -InterfaceIndex $adapter.InterfaceIndex

    if ($null -eq $currentAdapter) {
        $errorLog = "No adapter was found with interface index " + $adapter.interfaceIndex + ", unexpected state - exiting with error"
        writeErrorLog $errorLog

        $renames.Value[$currentAdapter.Name] = @{
            name = $adapter.name
            success = $false
        }

        return
    }

    if ($currentAdapter.Name -ne $adapter.name) {
        $adapterWithSameName = Get-NetAdapter -Name $adapter.name -ErrorAction SilentlyContinue

        if ($null -ne $adapterWithSameName) {
            try {
                $oldAdapterName = calculateNameForOldAdapter $adapter.name
                $adapterWithSameName | Rename-NetAdapter -NewName $oldAdapterName -ErrorAction Stop

                $message = "Renamed adapter from " + $adapter.name + " to " + $oldAdapterName
                writeInfoLog $message

                $renames.Value[$adapter.name] = @{
                    name = $oldAdapterName
                    success = $true
                }
            }
            catch {
                $err1 = $_.Exception.Message
                if ($err1) {
                    $errorLog = "Couldn't rename old management adapter from " + $adapter.name + " to " + $oldAdapterName + ". Error: " + $err1
                    writeErrorLog $errorLog
                }

                $renames.Value[$adapter.name] = @{
                    name = $oldAdapterName
                    success = $false
                }
            }
        }

        try {
            Rename-NetAdapter -Name $currentAdapter.Name -NewName $adapter.name -ErrorAction Stop
    
            $message = "Renamed management adapter from " + $currentAdapter.Name + " to " + $adapter.name
            writeInfoLog $message

            $renames.Value[$currentAdapter.Name] = @{
                name = $adapter.name
                success = $true
            }
        }
        catch {
            $err1 = $_.Exception.Message
            if ($err1) {
                $errorLog = "Couldn't rename adapter for " + $currentAdapter.Name + ". Error: " + $err1
                writeErrorLog $errorLog
            }

            $renames.Value[$currentAdapter.Name] = @{
                name = $adapter.name
                success = $false
            }
        }
    }
    else {
        $message = "Selected adapter is already named " + $adapter.name + ", skipping renaming"
        writeInfoLog $message

        $renames.Value[$currentAdapter.Name] = @{
            name = $adapter.name
            success = $true
        }
    }
}

function main($adapters) {
    $renames = @{}
    
    for ($i = 0; $i -lt $adapters.length; $i++) {
        renameAdapter $adapters[$i] ([ref]$renames)
    }

    return $renames
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $adapters
}
}
## [END] Set-WACCCAdapterNames ##
function Set-WACCCDCBConfiguration {
<#

.SYNOPSIS
Configure Data-Center-Bridging for RDMA.

.DESCRIPTION
Configure Data-Center-Bridging for RDMA.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [int]$clusterPriority,
    [Parameter(Mandatory = $true)]
    [int]$clusterBandwidthReservation,
    [Parameter(Mandatory = $true)]
    [int]$storagePriority,
    [Parameter(Mandatory = $true)]
    [int]$storageBandwidthReservation,
    [Parameter(Mandatory = $true)]
    [string[]]$nics
)

enum QoSFailureClassification {
    ClusterQoSPolicyDifferentPriority = 1
    ClusterQoSTrafficDifferentBandwidth = 2
    StorageQoSPolicyDifferentPriority = 3
    StorageQoSTrafficDifferentBandwidth = 4
}

function configureDCB() {
    try {
        ###############################################################################
        # Constants
        ###############################################################################

        Set-Variable -Name Cluster -Option Constant -Value "Cluster" -ErrorAction SilentlyContinue
        Set-Variable -Name SMB -Option Constant -Value "SMB" -ErrorAction SilentlyContinue
        Set-Variable -Name DefaultTraffic -Option Constant -Value "DEFAULT" -ErrorAction SilentlyContinue

        $failures = @()

        $clusterPriorityAsSByte = [System.Convert]::ToSByte($clusterPriority)
        $storagePriorityAsSByte = [System.Convert]::ToSByte($storagePriority)
        $clusterPriorityAsByte = [System.Convert]::ToByte($clusterPriority)
        $storagePriorityAsByte = [System.Convert]::ToByte($storagePriority)
        $clusterBandwidthAsByte = [System.Convert]::ToByte($clusterBandwidthReservation)
        $storageBandwidthAsByte = [System.Convert]::ToByte($storageBandwidthReservation)

        # Set policy for Cluster Heartbeats.
        # QoS Cluster Policy:
        $existingClusterPolicy = Get-NetQosPolicy -Name $Cluster -ErrorAction SilentlyContinue
        if ($existingClusterPolicy) {
            if ($existingClusterPolicy.PriorityValue -ne $clusterPriorityAsSByte) {
                $failures += @{
                    "failureClassification" = [QoSFailureClassification]::ClusterQoSPolicyDifferentPriority
                    "currentPriority" = $existingClusterPolicy.PriorityValue
                    "currentBandwidth" = ""
                }
            }
        } else {
            New-NetQosPolicy $Cluster -Cluster -PriorityValue8021Action $clusterPriorityAsSByte | Out-Null
        }

        # QoS Cluster Traffic:
        $existingClusterTraffic = Get-NetQosTrafficClass -Name $Cluster -ErrorAction SilentlyContinue
        if ($existingClusterTraffic) {
            if (($existingClusterTraffic.Priority -ne $clusterPriorityAsByte) -or ($existingClusterTraffic.BandwidthPercentage -ne $clusterBandwidthAsByte)) {
                $failures += @{
                    "failureClassification" = [QoSFailureClassification]::ClusterQoSTrafficDifferentBandwidth
                    "currentPriority" = $existingClusterPolicy.Priority
                    "currentBandwidth" = $existingClusterTraffic.BandwidthPercentage
                }
            }
        } else {
            New-NetQosTrafficClass $Cluster -Priority $clusterPriorityAsByte -BandwidthPercentage $clusterBandwidthAsByte -Algorithm ETS | Out-Null
        }

        # Set policy for SMB-Direct.
        # QoS SMB Policy:
        $existingSMBPolicy = Get-NetQosPolicy -Name $SMB -ErrorAction SilentlyContinue
        if ($existingSMBPolicy) {
            if ($existingSMBPolicy.PriorityValue -ne $storagePriorityAsSByte) {
                $failures += @{
                    "failureClassification" = [QoSFailureClassification]::StorageQoSPolicyDifferentPriority
                    "currentPriority" = $existingSMBPolicy.PriorityValue
                    "currentBandwidth" = ""
                }
            }
        } else {
            New-NetQosPolicy $SMB -NetDirectPortMatchCondition 445 -PriorityValue8021Action $storagePriorityAsSByte | Out-Null
        }

        Enable-NetQosFlowControl -Priority $storagePriorityAsByte | Out-Null
        
        # QoS SMB Traffic:
        $existingSMBTraffic = Get-NetQosTrafficClass -Name $SMB -ErrorAction SilentlyContinue
        if ($existingSMBTraffic) {
            if (($existingSMBTraffic.Priority -ne $storagePriorityAsByte) -or ($existingSMBTraffic.BandwidthPercentage -ne $storageBandwidthAsByte)) {
                $failures += @{
                    "failureClassification" = [QoSFailureClassification]::StorageQoSTrafficDifferentBandwidth
                    "currentPriority" = $existingSMBTraffic.Priority
                    "currentBandwidth" = $existingSMBTraffic.BandwidthPercentage
                }
            }
        } else {
            New-NetQosTrafficClass $SMB -Priority $storagePriorityAsByte -BandwidthPercentage $storageBandwidthAsByte -Algorithm ETS | Out-Null
        }

        # Block DCBX settings from the switch.
        foreach ($nic in $nics) {
            Enable-NetAdapterQos -InterfaceAlias $nic | Out-Null
            Set-NetQosDcbxSetting -InterfaceAlias $nic -Willing $False -Confirm:$false | Out-Null
        }

        # Set policy for default traffic.
        New-NetQosPolicy $DefaultTraffic -Default -PriorityValue8021Action 0 | Out-Null

        return @{
            IsSuccess = $true
            KnownFailures = $failures
            ErrorMessage = ''
        }
    } catch {
        return @{
            IsSuccess = $false
            KnownFailures = @()
            ErrorMessage = $_.ToString()
        }
    }
}

configureDCB

}
## [END] Set-WACCCDCBConfiguration ##
function Set-WACCCIcmpPingFirewall {
<#

.SYNOPSIS
Configure ICMP Ping firewall.

.DESCRIPTION
Configure ICMP Ping firewall.

.ROLE
Administrators

.PARAMETER OperationId
Operation ID

.PARAMETER Enable
State of firewall to be enabled.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$OperationId,
    [Parameter(Mandatory = $true)]
    [boolean]$Enable
)

Set-StrictMode -Version 5.0
Import-Module -Name Microsoft.PowerShell.Management

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter"
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-ConfigureAdapters-SetIcmpPingFirewall"
Set-Variable -Name IcmPing4In -Option Constant -Value "FPS-ICMP4-ERQ-In"

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
}

$rule = Get-NetFirewallRule -Name $IcmPing4In -ErrorAction SilentlyContinue | `
    Microsoft.PowerShell.Utility\Select-Object Name,DisplaName,Enabled,Status
if (-not $rule) {
    $message = "$OperationId; Not found FPS-ICMP4-ERQ-In: $Enable PreEnabled: $preEnabled Enabled: $enabled"
    writeErrorLog $message
    return
}

$preEnabled = $false

if ($Enable) {
    # Enabled property is not boolean but enum.
    if ($rule.Enabled -eq "True") {
        $preEnabled = $true
        $enabled = $true
    } else {
        Enable-NetFirewallRule -Name $IcmPing4In
        $enabled = $true
    }
} else {
    # Enabled property is not boolean but enum.
    if ($rule.Enabled -eq "True") {
        Disable-NetFirewallRule -Name $IcmPing4In
        $enabled = $false
    }
}

$message = "$OperationId; $IcmPing4In ($Enable) PreEnabled: $preEnabled Enabled: $enabled"
writeInfoLog $message

@{
    PreEnabled = $preEnabled
    Enabled = $enabled
}

}
## [END] Set-WACCCIcmpPingFirewall ##
function Set-WACCCNetAdaptersIp {
<#

.SYNOPSIS
Set ATC networking intents.

.DESCRIPTION
Set ATC networking intents.

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [PSObject[]]$data
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-SetAdaptersIp" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

function main([PSObject[]] $adapters) {
    $results = @{}

    foreach ($adapter in $adapters) {
        try {
            Remove-NetIPAddress -InterfaceAlias $adapter.name -Confirm:$false -ErrorAction SilentlyContinue

            $message = "Successfully removed IP for adapter with name " + $adapter.name
            writeInfoLog $message

            Register-DnsClient -ErrorAction SilentlyContinue

            $message = "Successfully registered DNS client when applying IP to adapter with name " + $adapter.name
            writeInfoLog $message

            Remove-NetRoute -InterfaceAlias $adapter.name -Confirm:$false -ErrorAction SilentlyContinue

            $message = "Successfully removed net route for adapter with name " + $adapter.name
            writeInfoLog $message

            New-NetIPAddress -InterfaceAlias $adapter.name -IPAddress $adapter.ipAddress -AddressFamily IPv4 -PrefixLength $adapter.prefixLength

            $message = "Successfully set IP for adapter with name " + $adapter.name
            writeInfoLog $message

            $results[$adapter.name] = $true
        } catch {
            $err = $_.Exception.Message
            $results[$adapter.name] = $false
            if ($err) {
                $errorLog = "Couldn't set IP for adapter with name " + $adapter.name + ". Error: " + $err
                writeErrorLog $errorLog
            }
        }
    }

    return $results
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $data
}
}
## [END] Set-WACCCNetAdaptersIp ##
function Set-WACCCNetIntents {
<#

.SYNOPSIS
Set ATC networking intents.

.DESCRIPTION
Set ATC networking intents.

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [PSObject[]]$intents
)

Set-StrictMode -Version 5.0

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-SetNetIntents" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}
function main([PSObject[]] $intents) {
    $results = @{}

    foreach ($intent in $intents) {
        try {
            $params = @{
                name                     = $intent.name
                clusterName              = $intent.clusterName
                adapterPropertyOverrides = $intent.adapterPropertyOverrides
                switchOverrides          = $intent.switchOverrides
                qosPolicyOverrides       = $intent.qosPolicyOverrides
            }

            if($null -ne $intent.storageIpOverride -and $intent.storageIpOverride) {
                $storageOverride = New-NetIntentStorageOverrides
                $storageOverride.EnableAutomaticIPGeneration = $false
                $params.Add('StorageOverrides', $storageOverride)
            }

            Set-NetIntent @params

            $regKeyPath = 'HKLM:\Cluster'
            [string]$guid = Get-ItemPropertyValue -Path $regKeyPath -Name 'ClusterNameResource' -ErrorAction SilentlyContinue
            $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
            if($clusterResource -ne $null) {
                $state = $clusterResource.state
                writeInfoLog $state
            }
            if ($clusterResource.state -ne "Online") {
                $clusterResource | Start-ClusterResource
                $message = "Started cluster resource"
                writeInfoLog $message

                for ($i = 0; $i -lt 5 ; $i++) {
                    $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                    if ($clusterResource.state -ne "Online") {
                        Start-Sleep 15
                    }
                    else {
                        $message = "Cluster resource is now online"
                        writeInfoLog $message
                        break;
                    }
                }

                $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                if ($clusterResource.state -ne "Online") {
                    $message = "Unable to start cluster resource"
                    writeInfoLog $message
                }
            } else {
                $message = "Cluster resource is online"
                writeInfoLog $message
            }

            $message = "Successfully set intent for intent with name " + $intent.name
            writeInfoLog $message

            $results[$intent.name] = $true
        }
        catch {
            $err = $_.Exception.Message
            $results[$intent.name] = $false
            if ($err) {
                $errorLog = "Couldn't set intent for intent with name " + $intent.name + ". Error: " + $err
                writeErrorLog $errorLog
            }
        }
    }

    return $results
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $intents
}

}
## [END] Set-WACCCNetIntents ##
function Set-WACCCNetworkAdapters {
<#

.SYNOPSIS
Configure network adapters.

.DESCRIPTION
Configure network adapters.

.ROLE
Administrators

.PARAMETER data
Wrapper object containing adapters to be updated, packet size, encapsulation overhead, and operation ID

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PSObject[]]$data
)

# Add strict mode back when refactoring script for error codes
# Strict mode doesn't work with current design with optional properties on the $adapter input
# Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-ConfigureAdapters" -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Helper function to write the info logs to info stream.

.DESCRIPTION
Helper function to write the info logs to info stream.


.PARAMETER logMessage
log message

#>

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage -ErrorAction SilentlyContinue
}
<#

.SYNOPSIS
Helper function to write the errors to error stream.

.DESCRIPTION
Helper function to write the errors to error stream.


.PARAMETER errorMessage
error message

#>
function writeErrorLog($operationId, $interfaceIndex, $smeErrorCode, $logMessage, $errorMessage) {
    $errorLog = "$operationId;$interfaceIndex;$smeErrorCode;$logMessage;$errorMessage"
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorLog -ErrorAction SilentlyContinue
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
Log parameter input per adapter

.DESCRIPTION
Log parameter input per adapter


.PARAMETER adapter
The adapter to log properties of

.PARAMETER operationId
reference to the operation ID from script input

#>
function recordParameters($adapter, $operationId) {
    $message = $operationId + ';' + 'interfaceIndex: ' + $adapter.interfaceIndex + ';' + 'name: ' + $adapter.adapterName + ';' + 'ipAddress: ' + $adapter.ipAddress + ';' + 'prefixLength: ' + $adapter.prefixLength + ';' + 'vlanId: ' + $adapter.vlanId
    writeInfoLog $message
}

<#

.SYNOPSIS
Calculate name for adapter with same name

.DESCRIPTION
Calculate name for adapter with the same name as the adapter passed into the script.

.PARAMETER newName
The name being assigned to the adapter passed into the script.

#>
function calcNameForOldAdapter($newName) {
    $oldAdapterSuffix = ' (old)'
    $oldAdapters = @{}

    $key = "$($newName)$($oldAdapterSuffix)*"
    Get-NetAdapter | Foreach-Object { 
        if ($_.Name -Like ($key)) {
            $oldAdapters[$_.Name] = ''
        }
    }

    $index = 0
    $temp = "$($newName)$($oldAdapterSuffix)"

    while ($null -ne $oldAdapters[$temp]) {
        $index++
        $temp = "$($newName)$($oldAdapterSuffix)$($index)"
    }

    return $temp
}

<#

.SYNOPSIS
Rename the adapter with same name

.DESCRIPTION
Rename the adapter with the same name using Rename-NetAdapter

.PARAMETER adapterWithSameName
The adapter to rename

#>
function renameAdapterWithSameName($adapter, $adpaterWithSameName, $operationId, [ref]$AdapterErrors) {
    try {
        if ($null -ne $adapterWithSameName) {
            $oldAdapterName = calcNameForOldAdapter $adapter.adapterName
            Rename-NetAdapter -Name $adapterWithSameName.Name -NewName $oldAdapterName

            $message = $operationId + ';' + $adapter.InterfaceIndex + ': RENAME_OLD_ADAPTER Interface index - ' + $adapterWithSameName.InterfaceIndex
            writeInfoLog $message
        }
        else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_RENAMING_OLD_ADAPTER'
            writeInfoLog $message
        }
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't Rename-NetAdapter " + $adapterWithSameName.InterfaceIndex + " to " + $oldAdapterName
            writeErrorLog $operationId $adapter.InterfaceIndex 1 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 1
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Rename the adapter

.DESCRIPTION
Rename the adapter with Rename-NetAdapter

.PARAMETER adapter
The adapter to rename

.PARAMETER operationId
reference to the operation ID from script input

#>
function renameAdapter($adapter, $realAdapter, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        if ($adapter.adapterName -ne $realAdapter.Name) {
            $adapterWithSameName = Get-NetAdapter -Name $adapter.adapterName -ErrorAction SilentlyContinue
            renameAdapterWithSameName $adapter $adapterWithSameName $operationId ([ref]$AdapterErrors)

            $AdapterHasChanged.Value = $true

            Rename-NetAdapter -Name $realAdapter.Name -NewName $adapter.adapterName

            $message = $operationId + ';' + $adapter.InterfaceIndex + ': RENAME_ADAPTER'
            writeInfoLog $message
        }
        else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_RENAMING_ADAPTER'
            writeInfoLog $message
        }
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't Rename-NetAdapter " + $realAdapter.Name + " to " + $adapter.adapterName
            writeErrorLog $operationId $adapter.interfaceIndex 1 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 1
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Update the ip address and subnet of the given adapter

.DESCRIPTION
Update the ip address and subnet of the given adapter by using Remove-NetIPAddress followed by New-NetIPAddress


.PARAMETER adapter
reference to the adapter data from script input

.PARAMETER realAdapter
reference to the adapter object from Get-NetAdapter

.PARAMETER operationId
reference to the operation ID from script input

#>
function updateIpAndPrefix($adapter, $realAdapter, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        $existingIp = Get-NetIPAddress -InterfaceIndex $realAdapter.InterfaceIndex -IPAddress $adapter.ipAddress -ErrorAction SilentlyContinue
        $existingConfig = Get-NetIPConfiguration -InterfaceIndex $realAdapter.InterfaceIndex -ErrorAction SilentlyContinue

        if ($adapter.defaultGateway -eq '') {
            $adapter.defaultGateway = $null
        }

        if ($null -eq $existingIp`
            -or $null -eq $existingConfig`
            -or $existingIp.IPAddress -ne $adapter.ipAddress`
            -or $existingIp.PrefixLength -ne $adapter.prefixLength`
            -or ($null -ne $adapter.defaultGateway -and ($null -eq $existingConfig.IPv4DefaultGateway`
            -or $null -eq $existingConfig.IPv4DefaultGateway.NextHop`
            -or $existingConfig.IPv4DefaultGateway.NextHop -ne $adapter.defaultGateway))) {
            $AdapterHasChanged.Value = $true

            Remove-NetIPAddress -InterfaceIndex $realAdapter.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue

            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': REMOVED_NETIPADDRESS'
            writeInfoLog $message

            Register-DnsClient -ErrorAction SilentlyContinue

            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': REGISTERED_DNS_CLIENT'
            writeInfoLog $message

            Remove-NetRoute -InterfaceIndex $realAdapter.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue

            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': REMOVED_NETROUTE'
            writeInfoLog $message

            if ($null -ne $adapter.defaultGateway) {
                New-NetIPAddress -InterfaceIndex $realAdapter.InterfaceIndex -AddressFamily 'IPv4' -IPAddress $adapter.ipAddress -PrefixLength $adapter.prefixLength -DefaultGateway $adapter.defaultGateway -ErrorAction Stop
            } 
            else {
                New-NetIPAddress -InterfaceIndex $realAdapter.InterfaceIndex -AddressFamily 'IPv4' -IPAddress $adapter.ipAddress -PrefixLength $adapter.prefixLength -ErrorAction Stop
            }
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NEW_IPADDRESS_SET'
            writeInfoLog $message
        }
        else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_UPDATING_NETIPADDRESS'
            writeInfoLog $message
        }
        
        if ($null -ne $adapter.dnsServerAddresses -and $adapter.dnsServerAddresses.count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $realAdapter.InterfaceIndex -ServerAddresses @($adapter.dnsServerAddresses) -ErrorAction Stop
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': SET_DNS_SERVER_ADDRESSES'
        } else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_UPDATING_DNS_SERVER_ADDRESSES'
        }
        writeInfoLog $message
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't update IP address for " + $realAdapter.Name
            writeErrorLog $operationId $realAdapter.InterfaceIndex 2 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 2
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Remove IPv6 from given adapter if previously disabled.

.DESCRIPTION
Remove IPv6 from given adapter if previously disabled by using Disable-NetAdapterBinding with ComponentID set to ms_tcpip6


.PARAMETER adapter
reference to the adapter data from script input

.PARAMETER realAdapter
reference to the adapter object from Get-NetAdapter

.PARAMETER operationId
reference to the operation ID from script input

#>
function removeIPv6($adapter, $realAdapter, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        $ipv6Binding = Get-NetAdapterBinding -Name $realAdapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        $ipv6Enabled = $ipv6Binding.Enabled

        if ($ipv6Enabled -eq $true -and $adapter.iPv6Enabled -eq $false) {
            $AdapterHasChanged.Value = $true
    
            Disable-NetAdapterBinding -Name $realAdapter.Name -ComponentID ms_tcpip6

            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': DISABLE_IPV6'
            writeInfoLog $message
        } else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_DISABLING_IPV6'
            writeInfoLog $message
        }
    } catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't disable IPv6 for " + $realAdapter.Name
            writeErrorLog $operationId $realAdapter.InterfaceIndex 2 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 2
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Disable DHCP and set DadTransmits to be zero.

.DESCRIPTION
Disable DHCP and set DadTransmits to be zero to avoid duplicated ip addresses created.


.PARAMETER adapter
reference to the adapter data from script input

.PARAMETER realAdapter
reference to the adapter object from Get-NetAdapter

.PARAMETER operationId
reference to the operation ID from script input

#>
function updateDhcpAndDadTransmits($adapter, $realAdapter, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        $existingIp = Get-NetIPAddress -InterfaceIndex $realAdapter.InterfaceIndex -IPAddress $adapter.ipAddress -ErrorAction SilentlyContinue
        if ($null -eq $existingIp -or $existingIp.PrefixLength -ne $adapter.prefixLength) {
            $AdapterHasChanged.Value = $true

            Set-NetIPInterface -InterfaceIndex $realAdapter.InterfaceIndex -AddressFamily 'IPv4' -DadTransmits 0 -Dhcp Disabled -ErrorAction SilentlyContinue

            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': DISABLE_DHCP_DADTRANSMITS_ZERO'
            writeInfoLog $message
        }
        else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_UPDATING_DHCP_DADTRANSMITS'
            writeInfoLog $message
        }

        $netInterfaces = @(Get-NetIPInterface -InterfaceIndex $realAdapter.InterfaceIndex -ErrorAction SilentlyContinue)
        foreach ($interface in $netInterfaces) {
            if ($adapter.staticIp -eq $true -and $interface.Dhcp -eq 'Enabled') {
                $AdapterHasChanged.Value = $true

                Set-NetIPInterface -InterfaceIndex $realAdapter.InterfaceIndex -Dhcp Disabled

                $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': DISABLED_DHCP_' + $interface.AddressFamily
                writeInfoLog $message
            } else {
                $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': KEPT_DHCP_STATE_' + $interface.AddressFamily
                writeInfoLog $message
            }
        }
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't disable DHCP and set DadTransmits to be zero for " + $realAdapter.Name
            writeErrorLog $operationId $realAdapter.InterfaceIndex 2 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 2
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Update the VLAN ID of the given adapter

.DESCRIPTION
Update the VLAN ID of the given adapter by using Set-NetAdapter


.PARAMETER adapter
reference to the adapter data from script input

.PARAMETER realAdapter
reference to the adapter object from Get-NetAdapter

.PARAMETER operationId
reference to the operation ID from script input

#>
function updateVlanId($adapter, $realAdapter, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        if ($realAdapter.VlanID -ne $adapter.vlanId) {
            $AdapterHasChanged.Value = $true

            Set-NetAdapter -Name $realAdapter.Name -VlanID $adapter.vlanId -NoRestart -Confirm:$false
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': VLAN_ID_SET'
            writeInfoLog $message
        }
        else {
            $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_UPDATING_VLAN_ID_SET'
            writeInfoLog $message
        }
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = "[Configure-Adapters]: Couldn't set Set-NetAdapter for " + $realAdapter.name + "With Vlan ID " + $adapter.vlanId
            writeErrorLog $operationId $realAdapter.InterfaceIndex 3 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 3
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Update advanced properties of the given adapter

.DESCRIPTION
Update advanced properties of the given adapter by using Set-NetAdapterAdvancedProperty


.PARAMETER adapter
reference to the adapter data from script input

.PARAMETER inputPacketSize
reference to the packet size from script input

.PARAMETER inputEncapsulationOverhead
reference to the encapsulation overhead from script input

.PARAMETER operationId
reference to the operation ID from script input

#>
function setAdvancedProperties($realAdapter, $inputPacketSize, $inputEncapsulationOverhead, $operationId, [ref]$AdapterErrors, [ref]$AdapterHasChanged) {
    try {
        $AdapterHasChanged.Value = $true

        $advancedProperties = Get-NetAdapterAdvancedProperty -Name $realAdapter.Name -IncludeHidden -AllProperties | Where-Object RegistryKeyword -Like '`**'
        $advancedProperties | Reset-NetAdapterAdvancedProperty -Name $realAdapter.Name -ErrorAction SilentlyContinue -NoRestart
        $resetProperties = @(
            'NVGRE Encapsulated Task Offload'
            'VXLAN Encapsulated Task Offload'
            'Recv Segment Coalescing (IPv4)'
            'Recv Segment Coalescing (IPv6)'
            'RSS Load Balancing Profile'
        )
        Reset-NetAdapterAdvancedProperty -Name $realAdapter.Name -DisplayName $resetProperties -NoRestart -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*PacketDirect' -RegistryValue 0 -NoRestart -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*RSS' -RegistryValue 1 -NoRestart -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*VMQ' -RegistryValue 1 -NoRestart -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*RssOnHostVPorts' -RegistryValue 1 -NoRestart -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*SRIOV' -RegistryValue 1 -NoRestart -ErrorAction SilentlyContinue

        $packetSize = 1514
        if ($null -ne $inputPacketSize) {
            $packetSize = $inputPacketSize
        }

        if ($null -ne ($advancedProperties | Where-Object RegistryKeyword -Like '`*JumboPacket')) {
            Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -IncludeHidden -AllProperties -RegistryKeyword '*JumboPacket' -RegistryValue $packetSize -NoRestart
        }
        else {
            New-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*JumboPacket' -RegistryValue $packetSize -NoRestart
        }

        $encapsulationOverhead = 0
        if ($null -ne $inputEncapsulationOverhead) {
            $encapsulationOverhead = $inputEncapsulationOverhead
        }

        if ($null -ne ($advancedProperties | Where-Object RegistryKeyword -Like '`*EncapOverhead')) {
            Set-NetAdapterAdvancedProperty -Name $realAdapter.Name -IncludeHidden -AllProperties -RegistryKeyword '*EncapOverhead' -RegistryValue $encapsulationOverhead -NoRestart
        }
        else {
            New-NetAdapterAdvancedProperty -Name $realAdapter.Name -RegistryKeyword '*EncapOverhead' -RegistryValue $encapsulationOverhead -NoRestart
        }

        $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': ADVANCED_PROPERTIES_SET'
        writeInfoLog $message
    }
    catch {
        $err = $_.Exception.Message
        if ($err) {
            $logMessage = ":[Configure-Adapters]: Couldn't set Set-NetAdapterAdvancedProperty for " + $realAdapter.Name
            writeErrorLog $operationId $realAdapter.InterfaceIndex 4 $logMessage $err
        }

        $AdapterErrors.Value.Add(@{
            errorCode = 4
            errorMessage = $err
        })
    }
}

<#

.SYNOPSIS
Update adapter configurations

.DESCRIPTION
Update adapter configurations


.PARAMETER adapters
reference to the list of adapter data from script input

.PARAMETER inputPacketSize
reference to the packet size from script input

.PARAMETER inputEncapsulationOverhead
reference to the encapsulation overhead from script input

.PARAMETER operationId
reference to the operation ID from script input

#>
function setAdapterConfiguration($adapter, $inputPacketSize, $inputEncapsulationOverhead, $operationId) {
    $AdapterErrors = [System.Collections.Generic.List[PSObject]]::new()
    $AdapterHasChanged = $false
    recordParameters $adapter $operationId

    try {
        $realAdapter = Get-NetAdapter -InterfaceIndex $adapter.interfaceIndex -ErrorAction Stop
    } catch {
        $err = $_.Exception.Message

        if ($err) {
            $logMessage = ":[Configure-Adapters]: Couldn't retrieve real adapter for adapter with name " + $adapter.Name
            writeErrorLog $operationId $adapter.InterfaceIndex 10 $logMessage $err
        }

        $AdapterErrors.Add(@{
            errorCode = 10
            errorMessage = $err
        })

        return @{ errors = $AdapterErrors }
    }

    updateDhcpAndDadTransmits $adapter $realAdapter $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)

    # refresh current data into the adapter once
    Restart-NetAdapter -Name $realAdapter.Name

    $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': REFRESHED_ADAPTER_DATA'
    writeInfoLog $message

    # sleep to make sure adapter is stable before configuring
    Start-Sleep 2

    renameAdapter $adapter $realAdapter $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)

    # update adapter again with new name
    $realAdapter = Get-NetAdapter -InterfaceIndex $adapter.interfaceIndex
    updateIpAndPrefix $adapter $realAdapter $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)
    updateVlanId $adapter $realAdapter $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)
    removeIPv6 $adapter $realAdapter $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)

    if ($null -ne $inputPacketSize -or $null -ne $inputEncapsulationOverhead) {
        setAdvancedProperties $realAdapter $inputPacketSize $inputEncapsulationOverhead $operationId ([ref]$AdapterErrors) ([ref]$AdapterHasChanged)
    }
    else {
        $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': NOT_SETTING_ADVANCED_PROPERTIES'
        writeInfoLog $message
    }

    if (-not $AdapterErrors.Count -gt 0) {
        $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': CONFIGURE_ADAPTER_SUCCESS'
        writeInfoLog $message
    }
    else {
        $logMessage = ":[Configure-Adapters]: Configure adapter failed for adapter with name " + $realAdapter.Name
        writeErrorLog $operationId $realAdapter.InterfaceIndex 5 $logMessage $err
    }

    if ($AdapterHasChanged -eq $true) {
        Restart-NetAdapter -Name $realAdapter.Name

        $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': RESTARTED_ADAPTER'
        writeInfoLog $message
    }
    else {
        $message = $operationId + ';' + $realAdapter.InterfaceIndex + ': HAS_NO_CHANGES'
        writeInfoLog $message
    }

    Register-DnsClient -ErrorAction SilentlyContinue
    $message = $operationId + ';' + $realAdapter.InterfaceIndex + ':[Configure-Adapters]: Registered DNS Client'
    writeInfoLog $message

    return @{ errors = $AdapterErrors }
}

<#

.SYNOPSIS
main.

.DESCRIPTION
The main biz logic of this script.

.PARAMETER serverNames
The server network adapter configuration that needs to be set.

#>

function main([PSObject[]] $data) {
    $message = $data.operationId + ';' + $data.adapter.interfaceIndex + ':[Configure-Adapters]: Starting adapter configuration'
    writeInfoLog $message

    return setAdapterConfiguration $data.adapter $data.packetSize $data.encapsulationOverhead $data.operationId
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $data
}

}
## [END] Set-WACCCNetworkAdapters ##
function Set-WACCCServerSite {
<#

.SYNOPSIS
Sets the fault domain site to a server.

.DESCRIPTION
Sets the fault domain site to a server. Creates a new site or renames an already existing one.

.ROLE
Administrators

#>

Param (
    [Parameter(Mandatory = $true)]
    [string]$firstSiteName,
    [Parameter(Mandatory = $true)]
    [string]$secondSiteName,

    [Parameter(Mandatory = $false)]
    [string[]]$firstSiteServerNames,
    [Parameter(Mandatory = $false)]
    [string[]]$secondSiteServerNames
)

$faultDomain = Get-ClusterFaultDomain
$faultDomainSites = $faultDomain | Where-Object { $_.Type -eq "Site" }

$firstSiteExists = ($faultDomainSites | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Name) -contains $firstSiteName
$secondSiteExists = ($faultDomainSites | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty Name) -contains $secondSiteName

if (!$firstSiteExists) {
    New-ClusterFaultDomain -Name $firstSiteName -Type Site
}
if (!$secondSiteExists) {
    New-ClusterFaultDomain -Name $secondSiteName -Type Site
}

$firstSiteServerNames | ForEach-Object {
    Set-ClusterFaultDomain -Name $_ -Parent $firstSiteName
}

$secondSiteServerNames | ForEach-Object {
    Set-ClusterFaultDomain -Name $_ -Parent $secondSiteName
}

# Cleanup sites with no children
$sitesToClean = $faultDomainSites | Where-Object { $_.Children -eq $null }
$sitesToClean | ForEach-Object {
    Remove-ClusterFaultDomain -Name $_.Name
}

}
## [END] Set-WACCCServerSite ##
function Set-WACCCSingleManagementAdapter {
<#

.SYNOPSIS
Configure management network adapters.

.DESCRIPTION
Rename chosen adapter to 'Management', rename previous 'Management' to 'Unknown (was Management)'

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterName
)

Set-StrictMode -Version 5.0

$err = $null
$managementName = 'Management'
$oldManagementName = 'Unknown (was Management)'
$tempName = 'TempName'

if ($adapterName -eq $managementName) {
    return $true
} else {
    $isManagementExist = !!(Get-NetAdapter -Name $managementName -ErrorAction SilentlyContinue)
    $isUnknownExist = !!(Get-NetAdapter -Name $oldManagementName -ErrorAction SilentlyContinue)

    if ($isUnknownExist) {
        Rename-NetAdapter -Name $oldManagementName -NewName $tempName

        if ($adapterName -eq $oldManagementName) {
            $adapterName = $tempName
        }
    }

    if ($isManagementExist) {
        Rename-NetAdapter -Name $managementName -NewName $oldManagementName
    }

    Rename-NetAdapter -Name $adapterName -NewName $managementName


    if ($isUnknownExist -and $adapterName -ne $tempName) {
        Rename-NetAdapter -Name $tempName -NewName $adapterName
    }

    return $true
}

}
## [END] Set-WACCCSingleManagementAdapter ##
function Set-WACCCVirtualManagementNetworkAdapters {
<#

.SYNOPSIS
Configure management network adapters.

.DESCRIPTION
Configure management network adapters.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterName1,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterName2,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterSubnetMask,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$adapterIPAddress,

    [Parameter(Mandatory = $false)]
    [string]$adapterDefaultGateway,

    [Parameter(Mandatory = $false)]
    [string]$adapterConnectionSpecificSuffix,

    [Parameter(Mandatory = $false)]
    [string[]]$adapterDnsServerAddresses,

    [Parameter(Mandatory = $false)]
    [string]$adapterVlanId
)

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name ScriptName -Option ReadOnly -Value "Configure-ManagementAdapters" -Scope Script -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-ManagementAdapters" -ErrorAction SilentlyContinue

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

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
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

function calcNameForOldAdapter($newName) {
    $oldAdapterSuffix = ' (old)'
    $oldAdapters = @{}

    $key = "$($newName)$($oldAdapterSuffix)*"
    Get-NetAdapter | Foreach-Object { 
        if ($_.Name -Like ($key)) {
            $oldAdapters[$_.Name] = ''
        }
    }

    $index = 0
    $temp = "$($newName)$($oldAdapterSuffix)"

    while ($null -ne $oldAdapters[$temp]) {
        $index++
        $temp = "$($newName)$($oldAdapterSuffix)$($index)"
    }

    return $temp
}

function renameAdapter($adapterName, $newName) {
    $currentAdapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue

    # If an adapter can't be found with either the given name, we've entered an unrecoverable state and require a rollback before attempting again
    if ($null -eq $currentAdapter) {
        $errorLog = "[Configure-ManagementAdapters]: No adapter was found with name " + $newName + ", unexpected state - exiting with error"
        writeErrorLog $errorLog
        throw $errorLog
    }

    if ($currentAdapter.Name -ne $newName) {
        $prevManagementAdapter = Get-NetAdapter -Name $newName -ErrorAction SilentlyContinue

        if ($null -ne $prevManagementAdapter) {
            try {
                $oldAdapterName = calcNameForOldAdapter $newName
                $prevManagementAdapter | Rename-NetAdapter -NewName $oldAdapterName -ErrorAction Stop

                $message = "[Configure-ManagementAdapters]: Renamed old management adapter from " + $prevManagementAdapter.Name + " to " + $oldAdapterName
                writeInfoLog $message
            }
            catch {
                $err1 = $_.Exception.Message
                if ($err1) {
                    $errorLog = "[Configure-ManagementAdapters]: Couldn't rename old management adapter from " + $prevManagementAdapter.Name + " to " + $oldAdapterName + ". Error: " + $err1
                    writeErrorLog $errorLog
                }
            }
        }

        try {
            Rename-NetAdapter -Name $currentAdapter.Name -NewName $newName -ErrorAction Stop
    
            $message = "[Configure-ManagementAdapters]: Renamed management adapter from " + $currentAdapter.Name + " to " + $newName
            writeInfoLog $message
        }
        catch {
            $err1 = $_.Exception.Message
            if ($err1) {
                $errorLog = "[Configure-ManagementAdapters]: Couldn't rename adapter for " + $currentAdapter.Name + ". Error: " + $err1
                writeErrorLog $errorLog
    
                return $null;
            }
        }
    }
    else {
        $message = "[Configure-ManagementAdapters]: Selected adapter is already named " + $newName + ", skipping renaming"
        writeInfoLog $message
    }
}

function multipleSelection($adapterName,
$adapterSubnetMask,
$adapterIPAddress,
$adapterDefaultGateway,
$adapterConnectionSpecificSuffix,
$adapterDnsServerAddresses,
$adapterVlanId) {

    $err1 = $null
    # 1. rename each adapter
    # 2. create virtual switch and bind physical adapter to it.
    # 3. create virtual network adapter and set its ipaddress, subnet mask and vlan id.
    # 4. remove ip address, subnet mask and vlan id from physical adapter.

    $newName = 'Management Physical 1'
    renameAdapter $adapterName $newName

    $switchName = 'Management Virtual Switch'
    $switchArgs = @{ 'Name' = $switchName; }
    $switchArgs += @{ 'NetAdapterName' = $newName; }
    $switchArgs += @{ 'AllowManagementOS' = $false; }
    $switchArgs += @{ 'EnableIov' = $true; }
    $switchArgs += @{ 'EnablePacketDirect' = $false; }
    $switchArgs += @{ 'EnableEmbeddedTeaming' = $true; }

    try {
        New-VMSwitch @switchArgs

        $message = 'VIRTUAL_SWITCH_CREATED'
        writeInfoLog $message
    }
    catch {
        $err1 = $_.Exception.Message
        if ($err1) {
            $errorLog = "[Configure-ManagementAdapters]: Couldn't create New-VMSwitch " + $switchName + ". Error: " + $err1
            writeErrorLog $errorLog

            return $null;
        }
    }

    try {
        Add-VMNetworkAdapter -ManagementOS -Name 'Management' -SwitchName $switchName

        $message = 'VIRTUAL_NETWORK_ADAPTER_CREATED'
        writeInfoLog $message

        if ($adapterVlanId -ne $null -and $adapterVlanId -ne "") {
            Set-VMNetworkAdapterVlan -ManagementOS -Access -VlanId $adapterVlanId -ErrorAction Stop
            $message = 'SET_VIRTUAL_ADAPTER_VLAN'
        } else {
            $message = 'NO_PHYSICAL_ADAPTER_VLAN'
        }
        writeInfoLog $message

        $virtualAdapter = Get-NetAdapter -Name "vEthernet (Management)"

        Set-NetIPInterface -InterfaceIndex $virtualAdapter.InterfaceIndex -Dhcp Disabled

        $message = 'MADE_IP_STATIC'
        writeInfoLog $message

        Disable-NetAdapterBinding -Name $virtualAdapter.Name -ComponentID ms_tcpip6

        $message = 'DISABLED_IPV6'
        writeInfoLog $message

        Remove-NetIPAddress -InterfaceIndex $virtualAdapter.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue

        $message = 'REMOVED_NETIPADDRESS'
        writeInfoLog $message

        if ($adapterDefaultGateway -ne $null -and $adapterDefaultGateway -ne "") {
            New-NetIPAddress -InterfaceIndex $virtualAdapter.InterfaceIndex -AddressFamily 'IPv4' -IPAddress $adapterIPAddress -PrefixLength $adapterSubnetMask -DefaultGateway $adapterDefaultGateway -ErrorAction Stop
            $message = 'NEW_IPADDRESS_SET_WITH_DEFAULT_GATEWAY'
        } else {
            New-NetIPAddress -InterfaceIndex $virtualAdapter.InterfaceIndex -AddressFamily 'IPv4' -IPAddress $adapterIPAddress -PrefixLength $adapterSubnetMask -ErrorAction Stop
            $message = 'NEW_IPADDRESS_SET_WITHOUT_DEFAULT_GATEWAY'
        }
        writeInfoLog $message

        if ($adapterConnectionSpecificSuffix -ne $null -and $adapterConnectionSpecificSuffix -ne "") {
            Set-DnsClient -InterfaceIndex $virtualAdapter.InterfaceIndex -ConnectionSpecificSuffix $adapterConnectionSpecificSuffix -ErrorAction Stop
            $message = 'SET_CONNECTION_SUFFIX'
        } else {
            $message = 'NO_PHYSICAL_ADAPTER_CONNECTION_SUFFIX'
        }
        writeInfoLog $message

        if ($adapterDnsServerAddresses -ne $null -and $adapterDnsServerAddresses.count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $virtualAdapter.InterfaceIndex -ServerAddresses $adapterDnsServerAddresses -ErrorAction Stop
            $message = 'SET_DNS_SERVER_ADDRESSES'
        } else {
            $message = "NO_PHYSICAL_ADAPTER_DNS_SERVER_ADDRESSES"
        }
        writeInfoLog $message

        Register-DnsClient -ErrorAction SilentlyContinue
        $message = 'REGISTERED_DNS_CLIENT'
        writeInfoLog $message
    } 
    catch {
        $err1 = $_.Exception.Message
        if ($err1) {
            $errorLog = "[Configure-ManagementAdapters]: Couldn't Add-VMNetworkAdapter: Management for switch: " + $switchName + ". Error: " + $err1
            writeErrorLog $errorLog

            return $null;
        }
    }

    return $virtualAdapter
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    $virtualAdapter = multipleSelection $adapterName1 $adapterSubnetMask $adapterIPAddress $adapterDefaultGateway $adapterConnectionSpecificSuffix $adapterDnsServerAddresses $adapterVlanId

    return $virtualAdapter
}
}
## [END] Set-WACCCVirtualManagementNetworkAdapters ##
function Set-WACCCVirtualSwitches {
<#

.SYNOPSIS
Configure virtual switches.

.DESCRIPTION
Configure virtual switches.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PSObject[]]$data
)

Set-StrictMode -Version 5.0

Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
Import-LocalizedData -BindingVariable strings -FileName strings.psd1 -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-VirtualSwitch" -ErrorAction SilentlyContinue
#Set-Variable -Name ScriptName -Option ReadOnly -Value "Configure-VirtualSwitches" -Scope Script -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($operationId, $interfaceIndex, $smeErrorCode, $logMessage, $errorMessage) {
    $errorLog = "$operationId;$interfaceIndex;$smeErrorCode;$logMessage;$errorMessage"
    if ('' -ne $interfaceIndex) {
        $Global:AdapterHasError = $true
    }
    else {
        $Global:AllAdaptersError = $true
    }
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorLog -ErrorAction SilentlyContinue
}

function tryCall {
    Param (
        [Parameter(Mandatory)][string]$name,
        [Parameter(Mandatory)][string]$contextInfo,
        [Parameter(Mandatory)][string]$operationId,
        [Parameter(Mandatory)][scriptblock]$command,
        [string]$interfaceIndex
    )

    Process {
        try {
            $command.Invoke()
            writeInfoLog "[$operationId] Completed $name $contextInfo"
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage) {
                writeErrorLog $operationId $interfaceIndex 0 "Failed to $name $contextInfo" $errorMessage
            }

        }
    }
}

<#

.SYNOPSIS
Creates simple virtual switch in the simplest case

.DESCRIPTION
Creates simple virtual switch in the simplest case

.ROLE
Administrators

.PARAMETER serverNames
The servers to add to the cluster of which this server is a member.

#>

function createSimpleVirtualSwitch($adapters, $switchName, $loadBalancingAlgorithm, $vmmq, $queuePairs, $operationId, $physicalNics, $isRdmaEnabled) {
    $newNames = @()
    $vlanId = @{ }
    $physicalAdapters = @()

    if ($null -ne $physicalNics) {
        # Special case of 2:1 vNIC:pNIC mapping when RDMA & Stretch are both enabled.
        $physicalAdapters = $physicalNics
    } else {
        $physicalAdapters = $adapters
    }

    foreach ($adapter in $physicalAdapters) {
        $newNames += $adapter.name

        # figure out if VlanID is effective on the physical adapter.
        $vlanId[$adapter.name] = 0
        if (("VlanID" -in $adapter.PSobject.Properties.Name) -and ($adapter.VlanId -ne 0)) {
            $current = Get-NetAdapter -Name $adapter.name -ErrorAction SilentlyContinue
            if (($null -ne $current) -and ($null -ne $current.VlanID) -and (0 -ne $current.VlanID)) {
                $vlanId[$adapter.name] = $adapter.VlanId
            }
        }
    }

    $Global:AllAdaptersError = $false
    tryCall -name 'New-VMSwitch' -contextInfo $switchName -operationId $operationId -command {
        New-VMSwitch -Name $switchName -NetAdapterName $newNames -AllowManagementOS $false -EnableIov $true -EnablePacketDirect $false -EnableEmbeddedTeaming $true -ErrorAction Stop
    }

    tryCall -name 'Set-VMSwitchTeam' -contextInfo "LoadBalancingAlgorithm for $switchName" -operationId $operationId -command {
        Set-VMSwitchTeam -Name $switchName -LoadBalancingAlgorithm $loadBalancingAlgorithm -Confirm:$false -ErrorAction Stop
    }

    tryCall -name 'Set-VMSwitch' -contextInfo "DefaultQueueVmmqEnabled for $switchName" -operationId $operationId -command {
        if ($queuePairs -ne 0) {
            Set-VMSwitch -Name $switchName -DefaultQueueVmmqEnabled $vmmq -DefaultQueueVrssEnabled $true -DefaultQueueVmmqQueuePairs $queuePairs -Confirm:$false -ErrorAction Stop
        }
        else {
            Set-VMSwitch -Name $switchName -DefaultQueueVmmqEnabled $vmmq -DefaultQueueVrssEnabled $true -Confirm:$false -ErrorAction Stop
        }
    }

    if ($Global:AllAdaptersError -eq $false) {
        $i = 0
        foreach ($adapter in $adapters) {
            $i += 1
            $vNICName = "vSMB$($i)"

            if ($null -ne $physicalNics) {
                if ($adapter.vNicType -eq 1) {
                    $nicType = 'Local'
                } else {
                    $nicType = 'Remote'
                }

                $vNICName = $vNICName + " " + $nicType
            }

            $vNICName = $vNICName.trim()
            $Global:AdapterHasError = $false

            if ($vlanId[$adapter.name] -ne 0) {
                tryCall -name 'Set-NetAdapter' -contextInfo " vlanId for $($adapter.name)" -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                    Set-NetAdapter -Name $adapter.name -VlanID 0 -Confirm:$false -ErrorAction Stop
                }
            }

            $message = $operationId + ';' + 'Setting configuration for adapter: ' + $adapter.name
            writeInfoLog $message

            $message = $operationId + ';' + 'Add-VMNetworkAdapter ' + $vNICName
            writeInfoLog $message

            tryCall -name 'Add-VMNetworkAdapter' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex  -operationId $operationId -command {
                Add-VMNetworkAdapter -ManagementOS -Name $vNICName -SwitchName $switchName -ErrorAction Stop
            }

            tryCall -name 'Rename-NetAdapter' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                Rename-NetAdapter -Name "*$vNICName*" -NewName $vNICName -ErrorAction Stop
            }

            Start-Sleep -Seconds 5

            # RDMA for Case 1 - One simple converged vSwitch:
            # It is always a 1 pNIC : vNIC mapping. RDMA must be enabled on all vNICs in this case.

            # RDMA for Case 2 - One compute-only vSwitch:
            # The non-teamed pNICs should be configured for RDMA, but we do NOT need to enable it on vNICs. (Thus, it is not enabled in createComputeVirtualSwitch()).

            # RDMA for Case 3 - Two vSwitches:
            # The storage-designated pNICs should be RDMA enabled, and RDMA must be enabled on the resulting vNICs.
            
            if ($isRdmaEnabled -eq $true) {
                tryCall -name 'Enable-NetAdapterRdma' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex  -operationId $operationId -command {
                    Enable-NetAdapterRdma -Name $vNICName -ErrorAction Stop        
                }
            }
            
            tryCall -name 'Set-VMNetworkAdapterTeamMapping' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex  -operationId $operationId -command {
                Set-VMNetworkAdapterTeamMapping -ManagementOS -VMNetworkAdapterName $vNICName -PhysicalNetAdapterName $adapter.name -ErrorAction Stop
            }

            tryCall -name 'Set-NetIPInterface' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex  -operationId $operationId -command {
                Set-NetIPInterface -InterfaceAlias $vNICName -AddressFamily 'IPv4' -DadTransmits 0 -Dhcp Disabled -ErrorAction Stop
            }

            tryCall -name 'New-NetIPAddress' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                if ($null -ne $adapter.defaultGateway -and $adapter.defaultGateway -ne '') {
                    New-NetIPAddress -InterfaceAlias $vNICName -IPAddress $adapter.ipAddress -PrefixLength $adapter.subnetMask -DefaultGateway $adapter.defaultGateway -AddressFamily IPv4 -ErrorAction Stop
                }
                else {
                    New-NetIPAddress -InterfaceAlias $vNICName -IPAddress $adapter.ipAddress -PrefixLength $adapter.subnetMask -AddressFamily IPv4 -ErrorAction Stop
                }
            }

            tryCall -name 'Set-VMNetworkAdapter' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                if ($queuePairs -ne 0) {
                    Set-VMNetworkAdapter -Name $vNICName -ManagementOS -VmmqEnabled $vmmq -VrssEnabled $true -VmmqQueuePairs $queuePairs -Confirm:$false -ErrorAction Stop
                }
                else {
                    Set-VMNetworkAdapter -Name $vNICName -ManagementOS -VmmqEnabled $vmmq -VrssEnabled $true -Confirm:$false -ErrorAction Stop
                }
            }

            if (($adapter.vlanId -ne 0) -and ($null -ne $adapter.vlanId)) {
                tryCall -name 'Set-VMNetworkAdapterIsolation' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                    Set-VMNetworkAdapterIsolation -ManagementOS -VMNetworkAdapterName $vNICName -IsolationMode Vlan -DefaultIsolationID $adapter.vlanId -AllowUntaggedTraffic $true -ErrorAction Stop
                }
            }

            tryCall -name 'Restart-NetAdapter' -contextInfo $vNICName -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                Restart-NetAdapter $vNICName -ErrorAction Stop
            }

            if (-not $Global:AdapterHasError) {
                $message = $operationId + ';' + $adapter.InterfaceIndex + ': CONFIGURE_ADAPTER_SUCCESS ' + $vNICName
                writeInfoLog $message
            }
        }
    }
}

<#

.SYNOPSIS
Create switch for compute only.

.DESCRIPTION
Create switch for compute only.

.ROLE
Administrators

.PARAMETER serverNames
The servers to add to the cluster of which this server is a member.

#>

function createComputeVirtualSwitch($adapters, $switchName, $loadBalancingAlgorithm, $vmmq, $queuePairs, $operationId) {
    $err = $null
    $newNames = @()
    $vlanId = @{ }
    foreach ($adapter in $adapters) {
        $newNames += $adapter.name
        $vlanId[$adapter.name] = 0
        if (("VlanID" -in $adapter.PSobject.Properties.Name) -and ($adapter.VlanId -ne 0)) {
            $current = Get-NetAdapter -Name $adapter.name -ErrorAction SilentlyContinue
            if (($null -ne $current) -and ($null -ne $current.VlanID) -and (0 -ne $current.VlanID)) {
                $vlanId[$adapter.name] = $adapter.VlanId
            }
        }
    }

    $Global:AllAdaptersError = $false

    tryCall -name 'New-VMSwitch' -contextInfo $switchName -operationId $operationId -command {
        New-VMSwitch -Name $switchName -NetAdapterName $newNames -AllowManagementOS $false -EnableIov $true -EnablePacketDirect $false -EnableEmbeddedTeaming $true -ErrorAction Stop
    }

    tryCall -name 'Set-VMSwitchTeam' -contextInfo "LoadBalancingAlgorithm for $switchName" -operationId $operationId -command {
        Set-VMSwitchTeam -Name $switchName -LoadBalancingAlgorithm $loadBalancingAlgorithm -Confirm:$false -ErrorAction Stop
    }

    tryCall -name 'Set-VMSwitch' -contextInfo "DefaultQueueVmmqEnabled for $switchName" -operationId $operationId -command {
        if ($queuePairs -ne 0) {
            Set-VMSwitch -Name $switchName -DefaultQueueVmmqEnabled $vmmq -DefaultQueueVrssEnabled $true -DefaultQueueVmmqQueuePairs $queuePairs -Confirm:$false -ErrorAction Stop
        }
        else {
            Set-VMSwitch -Name $switchName -DefaultQueueVmmqEnabled $vmmq -DefaultQueueVrssEnabled $true -Confirm:$false -ErrorAction Stop
        }
    }

    if ($Global:AllAdaptersError -eq $false) {
        foreach ($adapter in $adapters) {
            $Global:AdapterHasError = $false
            if ($vlanId[$adapter.name] -ne 0) {
                tryCall -name 'Set-NetAdapter' -contextInfo " vlanId for $($adapter.name)" -interfaceIndex $adapter.interfaceIndex -operationId $operationId -command {
                    Set-NetAdapter -Name $adapter.name -VlanID 0 -Confirm:$false -ErrorAction Stop
                }
            }


            if (-not $Global:AdapterHasError) {
                $message = $operationId + ';' + $adapter.InterfaceIndex + ': CONFIGURE_ADAPTER_SUCCESS ' + $adapter.name
                writeInfoLog $message
            }
        }
    }
}

<#

.SYNOPSIS
Create switch for compute and storage.

.DESCRIPTION
Create switch for compute and storage.

.ROLE
Administrators

.PARAMETER serverNames
The servers to add to the cluster of which this server is a member.

#>

function createComputeAndStorageVirtualSwitches(
    $computeAdapters,
    $storageAdapters,
    $switchName,
    $storageSwitchName,
    $computeLoadBalancingAlgorithm,
    $computeVmmq,
    $computeQueuePairs,
    $storageLoadBalancingAlgorithm,
    $storageVmmq,
    $storageQueuePairs,
    $operationId,
    $isRdmaEnabled) {
    $message = $operationId + ';Compute switch creation'
    writeInfoLog $message

    createComputeVirtualSwitch $computeAdapters $switchName $computeLoadBalancingAlgorithm $computeVmmq $computeQueuePairs $operationId

    $message = $operationId + ';Storage switch creation'
    writeInfoLog $message

    createSimpleVirtualSwitch $storageAdapters $storageSwitchName $storageLoadBalancingAlgorithm $storageVmmq $storageQueuePairs $operationId $null $isRdmaEnabled
}

<#

.SYNOPSIS
main

.DESCRIPTION
main

.ROLE
Administrators

.PARAMETER serverNames
The servers to add to the cluster of which this server is a member.

#>

function main([PSObject[]] $data) {
    $message = $data.operationId + ';Starting Configure-VirtualSwitches script'
    writeInfoLog $message

    try {
        foreach ($adapter in $data.otherAdapters) {
            $message = $data.operationId + ';' + $adapter.interfaceIndex + ': CONFIGURE_ADAPTER_SUCCESS ' + $adapter.name
            writeInfoLog $message
        }
    } catch { }

    if ($data.scriptNumber -eq 0) {
        $message = $data.operationId + ';Simple no choices switch creation'
        writeInfoLog $message

        $result = createSimpleVirtualSwitch $data.adapters $data.switchName $data.loadBalancingAlgorithm $data.useVmmq $data.defaultQueuePairs $data.operationId $null $data.isRdmaEnabled
    }
    elseif ($data.scriptNumber -eq 1) {
        $message = $data.operationId + ';Compute switch creation'
        writeInfoLog $message

        $result = createComputeVirtualSwitch $data.adapters $data.switchName $data.loadBalancingAlgorithm $data.useVmmq $data.defaultQueuePairs $data.operationId
    }
    elseif ($data.scriptNumber -eq 2) {
        $computeAdapters = $data.adapters
        $storageAdapters = $data.storageAdapters

        $message = $data.operationId + ';Compute and Storage switch creation'
        writeInfoLog $message

        $result = createComputeAndStorageVirtualSwitches $computeAdapters $storageAdapters $data.switchName $data.storageSwitchName $data.loadBalancingAlgorithm $data.useVmmq $data.defaultQueuePairs $data.storageLoadBalancingAlgorithm $data.storageUseVmmq $data.storageDefaultQueuePairs $data.operationId $data.isRdmaEnabled
    }
    elseif ($data.scriptNumber -eq 3) {
        $message = $data.operationId + ';Simple no choices switch creation - stretch & RDMA special case'
        writeInfoLog $message

        $result = createSimpleVirtualSwitch $data.adapters $data.switchName $data.loadBalancingAlgorithm $data.useVmmq $data.defaultQueuePairs $data.operationId $data.physicalNics $data.isRdmaEnabled
    }

    writeInfoLog "$($data.operationId);END_OF_COMPUTE_VIRTUAL_SWITCH_CREATED"
    return $result
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue
    Get-VMSwitch | Where-Object { $_.name -NotLike '*Management*' }| Remove-VMSwitch -Force:$true -ErrorAction SilentlyContinue
    return main $data
}

}
## [END] Set-WACCCVirtualSwitches ##
function Test-WACCCADTrust {
<#

.SYNOPSIS
Check if server is trusted within the domain.

.DESCRIPTION
Check if server is trusted within the domain.

.ROLE
Readers

#>

return Test-ComputerSecureChannel

}
## [END] Test-WACCCADTrust ##
function Test-WACCCClusterName {
<#

.SYNOPSIS
Check if cluster with given name is enabled.

.DESCRIPTION
Check if cluster with given name is enabled.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string]$computerName
)

Set-StrictMode -Version 5.0
Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue

try {
    $cluster = Get-AdComputer $computerName

    return @{ "isNameTaken" = $cluster.Enabled }
}
catch {
    return @{ "isNameTaken" = $False }
}
finally { }


}
## [END] Test-WACCCClusterName ##
function Test-WACCCClusterNetwork {
<#

.SYNOPSIS
Runs cluster validation on the current cluster.

.DESCRIPTION
Runs cluster validation on the current cluster.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string[]]$servers
)

Set-StrictMode -Version 5.0
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue
Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

$result = @{
    Type = "NetworkTest"
    Htm = $null
    Status = "NG"
    Date = (Get-Date).ToString()
    ISODate = Get-Date -Format "o"
}

$clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if (-not $clusterModule) {
    $errorLog = "[Test-ClusterNetwork]: Failed to load failover cluster module, throwing error and returning early."
    writeErrorLog $errorLog

    ## force to throw an error if it couldn't load the failover cluster module
    Import-Module -Name FailoverClusters -ErrorAction Stop
    return
}



try {
    Get-ChildItem "${env:windir}\Cluster\Reports\Validation Data*.xml" -ErrorAction SilentlyContinue |`
        Remove-Item -Force -ErrorAction SilentlyContinue
    $output = Test-Cluster -Node $servers -Include "Networking"

    $infoLog = "[Test-ClusterNetwork]: Successfully tested cluster."
    writeInfoLog $infoLog
} catch {
    $err = $_.Exception.Message
    $errorLog = "[Test-ClusterNetwork]: An error occured while trying to test cluster. Error: " + $err
    writeErrorLog $errorLog

    throw $_.Exception
}

$lastTestJsonPath = "${env:windir}\Cluster\Reports\WacLastTest.json"
if ($null -ne $output) {
    $result.Htm = $output.fullName
    $result.Status = "OK"
    $result | ConvertTo-Json | Set-Content -Path $lastTestJsonPath -Encoding UTF8
}

$infoLog = "[Test-ClusterNetwork]: Script completed, returning results."
writeInfoLog $infoLog

$result

}
## [END] Test-WACCCClusterNetwork ##
function Test-WACCCClusterStorage {
<#

.SYNOPSIS
Test cluster storage.

.DESCRIPTION
Test cluster storage.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string[]]$Servers
)

Set-StrictMode -Version 5.0
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

function setupScriptEnv() {
    Set-Variable -Name ClusterValidationCategoryId "Cluster" -Option ReadOnly -Scope Script
    Set-Variable -Name ConfigurationValidationCategoryId "Configuration" -Option ReadOnly -Scope Script
    Set-Variable -Name DasStorageValidationCategoryId "Storage Spaces Direct" -Option ReadOnly -Scope Script
    Set-Variable -Name HyperVValidationCategoryId "Hyper-V";
    Set-Variable -Name InventoryValidationCategoryId "Inventory" -Option ReadOnly -Scope Script
    Set-Variable -Name NetworkingValidationCategoryId "Networking" -Option ReadOnly -Scope Script
    Set-Variable -Name StorageValidationCategoryId -Value "Storage" -Option ReadOnly -Scope Script
}

setupScriptEnv
$clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if (-not $clusterModule) {
    ## force to throw an error if it couldn't load the failover cluster module
    Import-Module -Name FailoverClusters -ErrorAction Stop
    return
}

$output = Test-Cluster -Node $Servers -Include $DasStorageValidationCategoryId
$lastTestJsonPath = "${env:windir}\Cluster\Reports\WacLastTest.json"
$result = @{
    Type = "CreateStorage"
    Htm = $null
    Status = "NG"
    Date = (Get-Date).ToString()
    ISODate = Get-Date -Format "o"
}

if ($null -ne $output) {
    $result.Htm = $output.fullName
    $result.Status = "OK"
    $result | ConvertTo-Json | Set-Content -Path $lastTestJsonPath -Encoding UTF8
}

$result

}
## [END] Test-WACCCClusterStorage ##
function Test-WACCCConnectivityParallel {
<#

.SYNOPSIS
Test network connectivity sequentially.

.DESCRIPTION
Test network connectivity sequentially.

.ROLE
Readers

.PARAMETER data
The data to use to test connectivity.

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [PSObject]$data
)

Set-StrictMode -Version 5.0
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-ConfigureAdapters-TestConnectivity" -ErrorAction SilentlyContinue

$PingTest =
{
    # Native code adapted from ping.exe source code
    $NativePingCode = @"
namespace SME
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Threading;
    using Microsoft.Win32.SafeHandles;

    internal class SafeHGlobal : SafeHandleMinusOneIsInvalid
    {
        public int Size { get; private set; }

        public SafeHGlobal(int cb): base(true)
        {
            this.handle = Marshal.AllocHGlobal(cb);
            this.Size = cb;
        }

        private SafeHGlobal() : base(true) { }
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal sealed class SafeIcmpHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern bool IcmpCloseHandle(IntPtr handle);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern SafeIcmpHandle Icmp6CreateFile();
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern SafeIcmpHandle IcmpCreateFile();
        internal static readonly IntPtr InvalidHandle = new IntPtr(-1);
        internal static SafeIcmpHandle CreateIcmp6()
        {
            var icmpHandle = Icmp6CreateFile();
            int errorCode = Marshal.GetLastWin32Error();

            if (icmpHandle.Equals(SafeIcmpHandle.InvalidHandle))
            {
                Marshal.ThrowExceptionForHR(errorCode);
            }
            return icmpHandle;
        }

        internal static SafeIcmpHandle CreateIcmp4()
        {
            var icmpHandle = IcmpCreateFile();
            int errorCode = Marshal.GetLastWin32Error();

            if (icmpHandle.Equals(SafeIcmpHandle.InvalidHandle))
            {
                Marshal.ThrowExceptionForHR(errorCode);
            }
            return icmpHandle;
        }

        private SafeIcmpHandle()
            : base(true)
        {
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        override protected bool ReleaseHandle()
        {
            return IcmpCloseHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IPOptions
    {
        // ttl: max hops to reach destination
        internal byte ttl;
        internal byte tos;
        internal byte flags;
        internal byte optionsSize;
        internal IntPtr optionsData;

        internal IPOptions(byte ttl, bool dontFragment)
        {
            this.ttl = ttl;
            this.tos = 0;
            this.flags = dontFragment ? (byte)2 : (byte)0;
            this.optionsSize = 0;
            this.optionsData = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IcmpResponse
    {
        internal uint Address;
        internal IPStatus Status;
        internal uint RoundTripTime;
    }

    public static class ExtensionMethods
    {
        internal static UInt32 GetAddressAsUInt32(this IPAddress address)
        {
            if (address == null)
            {
                throw new ArgumentNullException("address");
            }

            if (address.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new InvalidCastException("Cannot call on non Ipv4 address");
            }

            return BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        }
    }

    public class PingResponse
    {
        public IPAddress Source { get; set; }
        public IPAddress Responder { get; set; }
        public IPStatus Status { get; set; }
        public int RoundTripTime { get; set; }
    }

    public class Icmp
    {
        static readonly int PayloadSize = 32;
        static readonly int MaxResponseSize = 256;
        static readonly uint Timeout = 100;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal extern static uint IcmpSendEcho2Ex(
            SafeIcmpHandle icmpHandle,
            IntPtr Event,
            IntPtr apcRoutine,
            IntPtr apcContext,
            uint sourceSocketAddress,
            uint destSocketAddress,
            [In]SafeHGlobal data,
            ushort dataSize,
            ref IPOptions options,
            SafeHGlobal replyBuffer,
            uint replySize, uint timeout);

        public static IEnumerable<PingResponse> Ping(IPAddress sourceAddress, IPAddress destinationAddress, int count, int interval, int ttl)
        {
            if (sourceAddress == null)
            {
                throw new ArgumentNullException("sourceAddress");
            }

            if (destinationAddress == null)
            {
                throw new ArgumentNullException("destinationAddress");
            }

            if (sourceAddress.AddressFamily != destinationAddress.AddressFamily)
            {
                throw new ArgumentException("addresses must be of the same family");
            }

            return Pinging(sourceAddress, destinationAddress, count, interval, (byte)ttl);
        }

        private static IEnumerable<PingResponse> Pinging(IPAddress sourceAddress, IPAddress destinationAddress, int count, int interval, byte ttl)
        {
            IPOptions options = new IPOptions(ttl, true);
            using (var icmpHandle = SafeIcmpHandle.CreateIcmp4())
            {
                using (SafeHGlobal payload = new SafeHGlobal(PayloadSize), response = new SafeHGlobal(MaxResponseSize))
                {
                    for (int i = 0; i < count; i++)
                    {
                        if (i != 0) {
                            Thread.Sleep(interval);
                        }

                        yield return IPv4Ping(sourceAddress, destinationAddress, icmpHandle, payload, response, ref options);
                    }
                }
            }

            yield break;
        }

        private static PingResponse IPv4Ping(
            IPAddress sourceAddress,
            IPAddress destinationAddress,
            SafeIcmpHandle icmpHandle,
            SafeHGlobal payload,
            SafeHGlobal response,
            ref IPOptions options)
        {
            var echoResponse = IcmpSendEcho2Ex(
                icmpHandle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                sourceAddress.GetAddressAsUInt32(),
                destinationAddress.GetAddressAsUInt32(),
                payload,
                (ushort)payload.Size,
                ref options,
                response,
                (uint)response.Size,
                Timeout);
            if (echoResponse == 0)
            {
                int errorCode = Marshal.GetLastWin32Error();
                return new PingResponse
                {
                    Source = sourceAddress,
                    Responder = IPAddress.None,
                    Status = (IPStatus)errorCode,
                    RoundTripTime = 0
                };
            }

            IcmpResponse icmpReply = (IcmpResponse)Marshal.PtrToStructure(response.DangerousGetHandle(), typeof(IcmpResponse));
            var responseAddress = new IPAddress(icmpReply.Address);
            return new PingResponse {
                Source = sourceAddress,
                Responder = responseAddress,
                Status = icmpReply.Status,
                RoundTripTime = (int)icmpReply.RoundTripTime
            };
        }
    }
}
"@

    Add-Type -TypeDefinition $NativePingCode
    Remove-Variable NativePingCode
    function testNetConnectivity($source, $destination, $operationId) {
        $src = [System.Net.IPAddress]::Parse($source)
        $dest = [System.Net.IPAddress]::Parse($destination)
        $pingPassed = $false
        foreach ($pingResponse in [SME.Icmp]::Ping($src, $dest, 10, 1000, 1)) {
            # TODO: we can send back more detailed error code of why ping failed
            # status codes defined here: https://docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ipstatus?view=netframework-4.8
            if ($pingResponse.Status -eq 0) {
                $pingPassed = $true
            }
            else {
                # allow some time for ping to start working, fail if ping passes then is dropped
                # pass for "fail fail pass pass pass"
                # fail for "fail fail pass fail fail"
                $pingPassed = $false
            }
        }
        if ($pingPassed) {
            $result = @{ Ping = $true }
        }
        else {
            $result = @{ Ping = $false }
        }

        return $result
    }

    $adapter = $args[0]
    $destination = $args[1]
    $pingResult = testNetConnectivity $adapter.sourceAddress $destination $data.operationId
    $result = @{
        Server             = $adapter.server
        AdapterName        = $adapter.adapterName
        SourceAddress      = $adapter.sourceAddress
        DestinationAddress = $destination
        Output             = $pingResult.Ping
    }

    $result
}

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage -ErrorAction SilentlyContinue | Out-Null
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue | Out-Null
}

function main([PSObject[]] $data) {
    #   $data.inputs is an array of type -
    #   export interface ConnectivityTestAddressesPerAdapter {
    #     server: string;
    #     adapterName: string;
    #     sourceAddress: string;
    #     destinationAddresses: string[];
    # }
    $message = "$($data.operationId);Testing connectivity"
    writeInfoLog $message

    $results = @()

    try {

        $jobs = $data.inputs | ForEach-Object {
            foreach ($destination in $_.destinationAddresses) {
                $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
                if ($running.Count -ge 8) {
                    $running | Wait-Job -Any | Out-Null
                }

                Start-Job -ArgumentList $_, $destination -ScriptBlock $PingTest
            }
        }

        $jobs | Wait-Job | Out-Null
        $jobs | Get-Job | ForEach-Object {
            if ($_.State -eq 'Failed') {
               throw $_.ChildJobs[0].JobStateInfo.Reason.Message;
            }
        }

        $results = $jobs | Receive-Job

    }
    catch {
        $err = $_.Exception.Message
        $errorLog = "[Test-ConnectivityParallel]: Test-NetConnection error. Error: $err"
        writeErrorLog $errorLog
        throw $err
    }

    foreach ($result in $results) {
        $message = "$($data.operationId);source: $($result.SourceAddress) destination:  $($result.DestinationAddress) Result: $($result.Output)"
        writeInfoLog $message
    }

    return @($results)
}

###############################################################################
# Script execution starts here...
###############################################################################

if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue | Out-Null

    return main $data
}

}
## [END] Test-WACCCConnectivityParallel ##
function Test-WACCCInternetConnectivity {
<#
.SYNOPSIS
Verifies if nodes are internet connected.

.DESCRIPTION
Verifies if nodes are internet connected.

.ROLE
Readers
#>

$result = Test-NetConnection

return @{
  connectivityCheckedSucceeded = $result.PingSucceeded
}

}
## [END] Test-WACCCInternetConnectivity ##
function Test-WACCCNewComputerNameAlreadyTaken {
<#
.SYNOPSIS
Validates if new server name is already taken.

.DESCRIPTION
Validates if new server name is already taken.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [string]
    $NewComputerName,
    [Parameter(Mandatory = $true)]
    [string]
    $DomainName,
    [Parameter(Mandatory = $true)]
    [string]
    $Username,
    [Parameter(Mandatory = $true)]
    [string]
    $Password
)

Set-StrictMode -Version 5.0
Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue

function TestNewComputerNameAlreadyTaken() {
    try {
        # skip if it's already joined with the new name.
        $computerSystem = Get-CimInstance Win32_ComputerSystem
        $joined = $computerSystem.PartOfDomain -and ($computerSystem.Domain -ieq $DomainName)
        if ($joined -and $computerSystem.Name -ieq $NewComputerName) {
            return @{
                Status = "Configured"
                Joined = $joined
            }
        }

        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force 
        $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
        $ADComputer = Get-ADComputer -Server $DomainName -Identity $NewComputerName -Credential $Creds -ErrorAction SilentlyContinue -ErrorVariable +err

        # if computer account doesn't exist or is not enabled, it can be used.
        if ($null -eq $AdComputer) {
            return @{
                Status = "NotUsed"
                Joined = $joined
            }
        }

        if (-not $AdComputer.Enabled) {
            return @{
                Status = "NotEnabled"
                Joined = $joined
            }
        }

        return @{
            Status = "Used"
            Joined = $joined
        }
    }
    catch {
        return @{
            Status = "NotUsed"
            Joined = $joined
        }
    }
}

TestNewComputerNameAlreadyTaken

}
## [END] Test-WACCCNewComputerNameAlreadyTaken ##
function Test-WACCCRdma {
<#

.SYNOPSIS
Test RDMA enabled.

.DESCRIPTION
Test RDMA enabled.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [string[]]$nics
)

function testRdmaEnabledConfig() {
    try {
        $isRdmaEnabled = $true
        $isSmbInterfaceValidForRdma = $true

        $netAdapterRdma = Get-NetAdapterRdma $nics
        
        if (($netAdapterRdma | Where-Object {$_.Enabled -ne $true }).Count -gt 0) {
            $isRdmaEnabled = $false
        }

        $smbInterfaceData = Get-SmbClientNetworkInterface

        foreach ($nic in $nics) {
            $rdmaCapableNic = $smbInterfaceData | Where-Object {$_.FriendlyName -eq $nic }
            if ($rdmaCapableNic -and $rdmaCapableNic.RdmaCapable -eq $False) {
                $isSmbInterfaceValidForRdma = $false
            }
        }

        return @{
            isSuccess = $true
            isRdmaEnabled = $isRdmaEnabled
            isSmbInterfaceValidForRdma = $isSmbInterfaceValidForRdma
            errorMessage = ''
        }
    } catch {
        return @{
            isSuccess = $false
            isRdmaEnabled = $false
            isSmbInterfaceValidForRdma = $false
            errorMessage =  $_.Exception.Message
        }
    }
}

testRdmaEnabledConfig
}
## [END] Test-WACCCRdma ##
function Test-WACCCScriptCanBeRun {
<#

.SYNOPSIS
Test that a basic script can be run on a server.

.DESCRIPTION
Test that a basic script can be run on a server.

.ROLE
Readers

#>

param(
    [Parameter(Mandatory = $True)]
    [string]
    $nodeName
)

return @{ ScriptCanRun = $true }

}
## [END] Test-WACCCScriptCanBeRun ##
function Test-WACCCSmeCluster {
<#

.SYNOPSIS
Runs cluster validation on the servers to be clustered.

.DESCRIPTION
Runs cluster validation on the servers to be clustered.

.ROLE
Readers

#>

Param (
    [Parameter(Mandatory = $true)]
    [string[]]$servers
)

Set-StrictMode -Version 5.0
Import-Module -Name FailoverClusters -ErrorAction SilentlyContinue

function setupScriptEnv() {
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Test-SmeCluster" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name ClusterValidationCategoryId "Cluster" -Option ReadOnly -Scope Script
    Set-Variable -Name ConfigurationValidationCategoryId "Configuration" -Option ReadOnly -Scope Script
    Set-Variable -Name DasStorageValidationCategoryId "Storage Spaces Direct" -Option ReadOnly -Scope Script
    Set-Variable -Name HyperVValidationCategoryId "Hyper-V" -Option ReadOnly -Scope Script
    Set-Variable -Name InventoryValidationCategoryId "Inventory" -Option ReadOnly -Scope Script
    Set-Variable -Name NetworkingValidationCategoryId "Networking" -Option ReadOnly -Scope Script
    Set-Variable -Name StorageValidationCategoryId "Storage" -Option ReadOnly -Scope Script
}

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}

$result = @{
    Type = "CreateCluster"
    Htm = $null
    Status = "NG"
    Date = (Get-Date).ToString()
    ISODate = Get-Date -Format "o"
}

setupScriptEnv

$clusterModule = Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue
if (-not $clusterModule) {
    $errorLog = "[Test-SmeCluster]: Failed to load failover cluster module, throwing error and returning early."
    writeErrorLog $errorLog

    ## force to throw an error if it couldn't load the failover cluster module
    Import-Module -Name FailoverClusters -ErrorAction Stop
    return
}

$IncludesTests = @(
    $InventoryValidationCategoryId
    $NetworkingValidationCategoryId
    $ConfigurationValidationCategoryId
)

try {
    Get-ChildItem "${env:windir}\Cluster\Reports\Validation Data*.xml" -ErrorAction SilentlyContinue |`
        Remove-Item -Force -ErrorAction SilentlyContinue

    $output = Test-Cluster -Node $servers -Include $IncludesTests
    
    $infoLog = "[Test-SmeCluster]: Successfully tested cluster."
    writeInfoLog $infoLog
} catch {
    $err = $_.Exception.Message
    $errorLog = "[Test-SmeCluster]: An error occured while trying to test cluster. Error: " + $err
    writeErrorLog $errorLog

    throw $_.Exception
}

$lastTestJsonPath = "${env:windir}\Cluster\Reports\WacLastTest.json"
if ($null -ne $output) {
    $result.Htm = $output.fullName
    $result.Status = "OK"
    $result | ConvertTo-Json | Set-Content -Path $lastTestJsonPath -Encoding UTF8
}

$infoLog = "[Test-SmeCluster]: Script completed, returning results."
writeInfoLog $infoLog

$result
}
## [END] Test-WACCCSmeCluster ##
function Update-WACCCDnsLookup {
<#

.SYNOPSIS
Refresh DNS lookup and net neighbor table.

.DESCRIPTION
Refresh DNS lookup and net neighbor table.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$servers
)

# Make sure to resolve all server DNS names first
foreach ($serverName in $servers) {
    # Force each server to re-register themselves with DNS server, if possible, worst case 
    # will cause a DNS lookup for the server
    try {
        $session = New-CimSession -ComputerName $serverName -ErrorAction SilentlyContinue           
        Register-DnsClient -CimSession $session -ErrorAction SilentlyContinue
    } catch {}
}

# We sleep to allow for DNS to propagate if it works
Start-Sleep 2

Clear-DnsClientCache -ErrorAction SilentlyContinue
Remove-NetNeighbor -State Unreachable -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetNeighbor -State Stale -Confirm:$false -ErrorAction SilentlyContinue

foreach($serverName in $servers) {
    Resolve-DnsName $serverName -ErrorAction SilentlyContinue
}

$connectionResult = New-Object boolean[] $servers.count;
# Test the connection on all servers after DNS we've resolved all DNS records
for (($i = 0); $i -lt $servers.count; $i++) {
    try {
        $serverName = $servers[$i]
        Test-Connection $serverName -ErrorAction Stop
        $connectionResult[$i] = $true
    } 
    catch {
        $connectionResult[$i] = $false
    }
}

return $connectionResult

}
## [END] Update-WACCCDnsLookup ##
function Update-WACCCNetIntentAdapters {
<#

.SYNOPSIS
Set ATC networking intent adapters.

.DESCRIPTION
Set ATC networking intent adapters.

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [PSObject[]]$intents
)

Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SmeHciScripts-UpdateNetIntentAdapters" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $logMessage  -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $errorMessage -ErrorAction SilentlyContinue
}
function main([PSObject[]] $intents) {
    $results = @{}

    foreach ($intent in $intents) {
        try {
            $params = @{
                name = $intent.name
                adapterName = $intent.adapterName
                clusterName = $intent.clusterName
            }

            Update-NetIntentAdapter @params

            $regKeyPath = 'HKLM:\Cluster'
            [string]$guid = Get-ItemPropertyValue -Path $regKeyPath -Name 'ClusterNameResource' -ErrorAction SilentlyContinue
            $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
            if($clusterResource -ne $null) {
                $state = $clusterResource.state
                writeInfoLog $state
            }
            if ($clusterResource.state -ne "Online") {
                $clusterResource | Start-ClusterResource
                $message = "Started cluster resource"
                writeInfoLog $message

                for ($i = 0; $i -lt 5 ; $i++) {
                    $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                    if ($clusterResource.state -ne "Online") {
                        Start-Sleep 15
                    }
                    else {
                        $message = "Cluster resource is now online"
                        writeInfoLog $message
                        break;
                    }
                }

                $clusterResource = Get-ClusterResource -Name $guid -ErrorAction SilentlyContinue
                if ($clusterResource.state -ne "Online") {
                    $message = "Unable to start cluster resource"
                    writeInfoLog $message
                }
            } else {
                $message = "Cluster resource is online"
                writeInfoLog $message
            }

            $message = "Successfully set adapters for intent with name " + $intent.name
            writeInfoLog $message

            $results[$intent.name] = $true
        } catch {
            $err = $_.Exception.Message
            $results[$intent.name] = $false
            if ($err) {
                $errorLog = "Couldn't set adapers for intent with name " + $intent.name + ". Error: " + $err
                writeErrorLog $errorLog
            }
        }
    }

    return $results
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return main $intents
}

}
## [END] Update-WACCCNetIntentAdapters ##
function Add-WACCCFolderShare {
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
## [END] Add-WACCCFolderShare ##
function Add-WACCCFolderShareNameUser {
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
## [END] Add-WACCCFolderShareNameUser ##
function Add-WACCCFolderShareUser {
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
## [END] Add-WACCCFolderShareUser ##
function Compress-WACCCArchiveFileSystemEntity {
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
## [END] Compress-WACCCArchiveFileSystemEntity ##
function Disable-WACCCKdcProxy {
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
## [END] Disable-WACCCKdcProxy ##
function Disable-WACCCSmbOverQuic {
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
## [END] Disable-WACCCSmbOverQuic ##
function Edit-WACCCFolderShareInheritanceFlag {
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
## [END] Edit-WACCCFolderShareInheritanceFlag ##
function Edit-WACCCFolderShareUser {
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
## [END] Edit-WACCCFolderShareUser ##
function Edit-WACCCSmbFileShare {
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
## [END] Edit-WACCCSmbFileShare ##
function Edit-WACCCSmbServerCertificateMapping {
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
## [END] Edit-WACCCSmbServerCertificateMapping ##
function Enable-WACCCSmbOverQuic {
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
## [END] Enable-WACCCSmbOverQuic ##
function Expand-WACCCArchiveFileSystemEntity {
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
## [END] Expand-WACCCArchiveFileSystemEntity ##
function Get-WACCCBestHostNode {
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
## [END] Get-WACCCBestHostNode ##
function Get-WACCCCertificates {
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
## [END] Get-WACCCCertificates ##
function Get-WACCCComputerName {
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
## [END] Get-WACCCComputerName ##
function Get-WACCCFileNamesInPath {
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
## [END] Get-WACCCFileNamesInPath ##
function Get-WACCCFileSystemEntities {
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
## [END] Get-WACCCFileSystemEntities ##
function Get-WACCCFileSystemRoot {
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
## [END] Get-WACCCFileSystemRoot ##
function Get-WACCCFolderItemCount {
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
## [END] Get-WACCCFolderItemCount ##
function Get-WACCCFolderOwner {
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
## [END] Get-WACCCFolderOwner ##
function Get-WACCCFolderShareNames {
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
## [END] Get-WACCCFolderShareNames ##
function Get-WACCCFolderSharePath {
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
## [END] Get-WACCCFolderSharePath ##
function Get-WACCCFolderShareStatus {
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
## [END] Get-WACCCFolderShareStatus ##
function Get-WACCCFolderShareUsers {
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
## [END] Get-WACCCFolderShareUsers ##
function Get-WACCCIsAzureTurbineServer {
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
## [END] Get-WACCCIsAzureTurbineServer ##
function Get-WACCCItemProperties {
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
## [END] Get-WACCCItemProperties ##
function Get-WACCCItemType {
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
## [END] Get-WACCCItemType ##
function Get-WACCCLocalGroups {
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
## [END] Get-WACCCLocalGroups ##
function Get-WACCCLocalUsers {
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
## [END] Get-WACCCLocalUsers ##
function Get-WACCCOSDetails {
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
## [END] Get-WACCCOSDetails ##
function Get-WACCCShareEntities {
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
## [END] Get-WACCCShareEntities ##
function Get-WACCCSmb1InstallationStatus {
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
## [END] Get-WACCCSmb1InstallationStatus ##
function Get-WACCCSmbFileShareDetails {
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
## [END] Get-WACCCSmbFileShareDetails ##
function Get-WACCCSmbOverQuicSettings {
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
## [END] Get-WACCCSmbOverQuicSettings ##
function Get-WACCCSmbServerCertificateHealth {
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
## [END] Get-WACCCSmbServerCertificateHealth ##
function Get-WACCCSmbServerCertificateMapping {
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
## [END] Get-WACCCSmbServerCertificateMapping ##
function Get-WACCCSmbServerCertificateValues {
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
## [END] Get-WACCCSmbServerCertificateValues ##
function Get-WACCCSmbServerSettings {

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
## [END] Get-WACCCSmbServerSettings ##
function Get-WACCCSmbShareAccess {
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
## [END] Get-WACCCSmbShareAccess ##
function Get-WACCCStorageFileShare {
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
## [END] Get-WACCCStorageFileShare ##
function Get-WACCCTempFolderPath {
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
## [END] Get-WACCCTempFolderPath ##
function Move-WACCCFile {
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
## [END] Move-WACCCFile ##
function New-WACCCFile {
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
## [END] New-WACCCFile ##
function New-WACCCFolder {
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
## [END] New-WACCCFolder ##
function New-WACCCSmbFileShare {
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
## [END] New-WACCCSmbFileShare ##
function Remove-WACCCAllShareNames {
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
## [END] Remove-WACCCAllShareNames ##
function Remove-WACCCFileSystemEntity {
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
## [END] Remove-WACCCFileSystemEntity ##
function Remove-WACCCFolderShareUser {
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
## [END] Remove-WACCCFolderShareUser ##
function Remove-WACCCSmbServerCertificateMapping {
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
## [END] Remove-WACCCSmbServerCertificateMapping ##
function Remove-WACCCSmbShare {
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
## [END] Remove-WACCCSmbShare ##
function Rename-WACCCFileSystemEntity {
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
## [END] Rename-WACCCFileSystemEntity ##
function Restore-WACCCConfigureSmbServerCertificateMapping {
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
## [END] Restore-WACCCConfigureSmbServerCertificateMapping ##
function Set-WACCCSmbOverQuicServerSettings {
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
## [END] Set-WACCCSmbOverQuicServerSettings ##
function Set-WACCCSmbServerCertificateMapping {
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
## [END] Set-WACCCSmbServerCertificateMapping ##
function Set-WACCCSmbServerSettings {
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
## [END] Set-WACCCSmbServerSettings ##
function Test-WACCCFileSystemEntity {
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
## [END] Test-WACCCFileSystemEntity ##
function Uninstall-WACCCSmb1 {
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
## [END] Uninstall-WACCCSmb1 ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAT+DZ3eg1tl8k9
# L+Vzeqjosm56UlxwbwFl6j13CmsH8aCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEKrpcxztwaseONpA1Z7+iB3
# BQqiw32TXFwCS6/GENfeMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAj49Sru2dFC7pU6OKX2ctMuKAuy0kGg/GNNfrIDUxQgHbVHujVhzXZWI/
# pO/N1a9grctErMJm02AGuOLZCkM2k2OfdYPnnLkkOS6nqqmPyu3C3lOltSRYzF7p
# Ml0UCrETB+XNUDkE44fDiMlQiCu2Rpy10cpyjC+y9M1cyz6XZKFdiN9oJ6PKrLvT
# uVEto9MQvGcFpq6dNQyuPkZNUgawcNDmi//45RW05H+78WPx5PRJzCbXmXgQnnug
# 5FhQHqxCOetcpIybh5B7QhVfJoEKJINHsR89oY0NxsQxmQrmPB3q3NolVUkqwiRB
# Qtu3RnNYAgXOt+blNUGpa5EeldtdQqGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAaAiSDchhWPb7roTLnrDEYInVC9qVg9DJ7jNhwCQR2LwIGaPACsRvT
# GBMyMDI1MTExMDE3MTczMy40NTFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTAwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgh4nVhdksfZUgABAAACCDANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTNaFw0yNjA0MjIxOTQyNTNaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC1y3AI5lIz3Ip1nK5BMUUbGRsjSnCz/VGs33zvY0Ne
# shsPgfld3/Z3/3dS8WKBLlDlosmXJOZlFSiNXUd6DTJxA9ik/ZbCdWJ78LKjbN3t
# FkX2c6RRpRMpA8sq/oBbRryP3c8Q/gxpJAKHHz8cuSn7ewfCLznNmxqliTk3Q5LH
# qz2PjeYKD/dbKMBT2TAAWAvum4z/HXIJ6tFdGoNV4WURZswCSt6ROwaqQ1oAYGvE
# ndH+DXZq1+bHsgvcPNCdTSIpWobQiJS/UKLiR02KNCqB4I9yajFTSlnMIEMz/Ni5
# 38oGI64phcvNpUe2+qaKWHZ8d4T1KghvRmSSF4YF5DNEJbxaCUwsy7nULmsFnTaO
# jVOoTFWWfWXvBuOKkBcQKWGKvrki976j4x+5ezAP36fq3u6dHRJTLZAu4dEuOooU
# 3+kMZr+RBYWjTHQCKV+yZ1ST0eGkbHXoA2lyyRDlNjBQcoeZIxWCZts/d3+nf1ji
# SLN6f6wdHaUz0ADwOTQ/aEo1IC85eFePvyIKaxFJkGU2Mqa6Xzq3qCq5tokIHtjh
# ogsrEgfDKTeFXTtdhl1IPtLcCfMcWOGGAXosVUU7G948F6W96424f2VHD8L3FoyA
# I9+r4zyIQUmqiESzuQWeWpTTjFYwCmgXaGOuSDV8cNOVQB6IPzPneZhVTjwxbAZl
# aQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFKMx4vfOqcUTgYOVB9f18/mhegFNMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBRszKJKwAfswqdaQPFiaYB/ZNAYWDa040X
# TcQsCaCua5nsG1IslYaSpH7miTLr6eQEqXczZoqeOa/xvDnMGifGNda0CHbQwtpn
# IhsutrKO2jhjEaGwlJgOMql21r7Ik6XnBza0e3hBOu4UBkMl/LEX+AURt7i7+RTN
# sGN0cXPwPSbTFE+9z7WagGbY9pwUo/NxkGJseqGCQ/9K2VMU74bw5e7+8IGUhM2x
# spJPqnSeHPhYmcB0WclOxcVIfj/ZuQvworPbTEEYDVCzSN37c0yChPMY7FJ+HGFB
# NJxwd5lKIr7GYfq8a0gOiC2ljGYlc4rt4cCed1XKg83f0l9aUVimWBYXtfNebhpf
# r6Lc3jD8NgsrDhzt0WgnIdnTZCi7jxjsIBilH99pY5/h6bQcLKK/E6KCP9E1YN78
# fLaOXkXMyO6xLrvQZ+uCSi1hdTufFC7oSB/CU5RbfIVHXG0j1o2n1tne4eCbNfKq
# UPTE31tNbWBR23Yiy0r3kQmHeYE1GLbL4pwknqaip1BRn6WIUMJtgncawEN33f8A
# YGZ4a3NnHopzGVV6neffGVag4Tduy+oy1YF+shChoXdMqfhPWFpHe3uJGT4GJEiN
# s4+28a/wHUuF+aRaR0cN5P7XlOwU1360iUCJtQdvKQaNAwGI29KOwS3QGriR9F2j
# OGPUAlpeEzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkEwMDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCN
# kvu0NKcSjdYKyrhJZcsyXOUTNKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwcHzAiGA8yMDI1MTExMDA4MDkw
# M1oYDzIwMjUxMTExMDgwOTAzWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvBwf
# AgEAMAoCAQACAh2GAgH/MAcCAQACAhKWMAoCBQDsvW2fAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAI/S3ii5ILu/9aaJiCqSvpPWjF7iYtvxZe2WcBku1a72
# jzpqw9emmLYoHL7RyKbtCDGZolXsMLsoJf0wcETAykp+9yWE0TmJ0kPQmI7NDyg+
# PiEO6tfCo8nnpPxVr9KsFeH+pcmATHdFHsEwEINpflgST2+y8KayePiUXR/bCZo3
# GEMunaW5p91Qzrt45PtzYvfhwJkRaoxXWk2ij7U0FUTDeOsmFBbeGkIieTYVaa36
# h8vst8/qVZcrsir4lXAMsN60xxumMU6ggW3OM6P23QgwLzmUYEln2QT7wRwXoxcA
# 8e79tZ6ebFS7pSVdQ103nSKmFDiKja3BlxlxchggZZcxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgh4nVhdksfZUgABAAAC
# CDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCGHPpSaD4qGOCyJbiZcOzmT56Ahefn6mAFGS3q3c3L
# fzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EII//jm8JHa2W1O9778t9+Ft2
# Z5NmKqttPk6Q+9RRpmepMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIIeJ1YXZLH2VIAAQAAAggwIgQgxOp5huUKoLmpqggmxtRWAnWe
# tUqaf40ZJpK4j6HSKG4wDQYJKoZIhvcNAQELBQAEggIABb56LC0X8EXGT/Y2HUyB
# xHYQ6/UdxZrYNIcC0XQUXLl1g37xTWKUintKQRSVuyK+rqzFMQ07VGfQ3T72193F
# 38USA0jgjnFg1gFc/4OR0B5yNGSPOQ5jiPIEqzP/VITW2gOX2Kl74Ps9Xn2eMggF
# qQoV/f5wkypDZGdrLN5bmyVT1aqz5X+KzjB44uM+SywaJ03oPCBBRhAewx3EKE68
# yjKb1B+6CTAfJE2uktRVFlAsuoOR7RqwgIbJq9cL+lU7T3fdOECHd0T10r4WGrOa
# S0I6a+NKcddoIbK+/plnmd1okL3Glmg+QpcMmVJ0k0NaCHKwHzRCpIaojy1oEDua
# //XkmFgypHrqm2Op1m0Vlq2bRCFwHTPNYP9iDJnM0B4wQAxSXxZXQnGd6E5+l8tQ
# oMPhPuja7kpuuv08zX3niAr0N6ae1w9MqBgjohGR6fQN1eIANIWzLi8H4wypVA+n
# IBY3Q9tOkGGBsBUJDf8ja0uEKlvcufCAf2KEoyLmFg+Q6qEKHc7uaYnwivYmUY+V
# R94ofIScje2mnJvqUe8CbEBJ0f/qtwx8o4gk4nojbF2JCv2jZqDtGO2lWDYHe50y
# TGhwTguT8ktD4xJshoKwGv8h2LdKeE/iL7ktgHYLBshf6ta2V5q4O0YMvFkUj9zZ
# dPGeuKQi8bACngOO+S8JM14=
# SIG # End signature block
