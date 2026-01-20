function Disconnect-WACSMHybridManagement {
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
## [END] Disconnect-WACSMHybridManagement ##
function Get-WACSMAntimalwareSoftwareStatus {
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
## [END] Get-WACSMAntimalwareSoftwareStatus ##
function Get-WACSMAzureProtectionStatus {
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
## [END] Get-WACSMAzureProtectionStatus ##
function Get-WACSMAzureVMStatus {
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
## [END] Get-WACSMAzureVMStatus ##
function Get-WACSMBmcInfo {
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
## [END] Get-WACSMBmcInfo ##
function Get-WACSMCimDiskRegistry {
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
## [END] Get-WACSMCimDiskRegistry ##
function Get-WACSMCimDiskSummary {
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
## [END] Get-WACSMCimDiskSummary ##
function Get-WACSMCimMemorySummary {
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
## [END] Get-WACSMCimMemorySummary ##
function Get-WACSMCimNetworkAdapterSummary {
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
## [END] Get-WACSMCimNetworkAdapterSummary ##
function Get-WACSMCimProcessorSummary {
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
## [END] Get-WACSMCimProcessorSummary ##
function Get-WACSMClientConnectionStatus {
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
## [END] Get-WACSMClientConnectionStatus ##
function Get-WACSMClusterInformation {
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
## [END] Get-WACSMClusterInformation ##
function Get-WACSMComputerIdentification {
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
## [END] Get-WACSMComputerIdentification ##
function Get-WACSMCrashEvents {
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
## [END] Get-WACSMCrashEvents ##
function Get-WACSMDiagnosticDataSetting {
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
## [END] Get-WACSMDiagnosticDataSetting ##
function Get-WACSMDiskSummaryDownlevel {
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
## [END] Get-WACSMDiskSummaryDownlevel ##
function Get-WACSMEnvironmentVariables {
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
## [END] Get-WACSMEnvironmentVariables ##
function Get-WACSMHybridManagementConfiguration {
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
## [END] Get-WACSMHybridManagementConfiguration ##
function Get-WACSMHybridManagementStatus {
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
## [END] Get-WACSMHybridManagementStatus ##
function Get-WACSMHyperVEnhancedSessionModeSettings {
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
## [END] Get-WACSMHyperVEnhancedSessionModeSettings ##
function Get-WACSMHyperVGeneralSettings {
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
## [END] Get-WACSMHyperVGeneralSettings ##
function Get-WACSMHyperVHostPhysicalGpuSettings {
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
## [END] Get-WACSMHyperVHostPhysicalGpuSettings ##
function Get-WACSMHyperVLiveMigrationSettings {
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
## [END] Get-WACSMHyperVLiveMigrationSettings ##
function Get-WACSMHyperVMigrationSupport {
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
## [END] Get-WACSMHyperVMigrationSupport ##
function Get-WACSMHyperVNumaSpanningSettings {
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
## [END] Get-WACSMHyperVNumaSpanningSettings ##
function Get-WACSMHyperVRoleInstalled {
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
## [END] Get-WACSMHyperVRoleInstalled ##
function Get-WACSMHyperVStorageMigrationSettings {
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
## [END] Get-WACSMHyperVStorageMigrationSettings ##
function Get-WACSMLicenseStatusChecks {
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
## [END] Get-WACSMLicenseStatusChecks ##
function Get-WACSMMemorySummaryDownLevel {
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
## [END] Get-WACSMMemorySummaryDownLevel ##
function Get-WACSMMmaStatus {
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
## [END] Get-WACSMMmaStatus ##
function Get-WACSMNetworkSummaryDownlevel {
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
## [END] Get-WACSMNetworkSummaryDownlevel ##
function Get-WACSMNumberOfLoggedOnUsers {
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
## [END] Get-WACSMNumberOfLoggedOnUsers ##
function Get-WACSMPowerConfigurationPlan {
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
## [END] Get-WACSMPowerConfigurationPlan ##
function Get-WACSMProcessorSummaryDownlevel {
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
## [END] Get-WACSMProcessorSummaryDownlevel ##
function Get-WACSMRbacEnabled {
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
## [END] Get-WACSMRbacEnabled ##
function Get-WACSMRbacSessionConfiguration {
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
## [END] Get-WACSMRbacSessionConfiguration ##
function Get-WACSMRebootPendingStatus {
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
## [END] Get-WACSMRebootPendingStatus ##
function Get-WACSMRemoteDesktop {
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
## [END] Get-WACSMRemoteDesktop ##
function Get-WACSMSQLServerEndOfSupportVersion {
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
## [END] Get-WACSMSQLServerEndOfSupportVersion ##
function Get-WACSMServerConnectionStatus {
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
## [END] Get-WACSMServerConnectionStatus ##
function Install-WACSMMonitoringDependencies {
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
## [END] Install-WACSMMonitoringDependencies ##
function New-WACSMEnvironmentVariable {
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
## [END] New-WACSMEnvironmentVariable ##
function Remove-WACSMEnvironmentVariable {
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
## [END] Remove-WACSMEnvironmentVariable ##
function Restart-WACSMOperatingSystem {
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
## [END] Restart-WACSMOperatingSystem ##
function Set-WACSMComputerIdentification {
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
## [END] Set-WACSMComputerIdentification ##
function Set-WACSMDiagnosticDataSetting {
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
## [END] Set-WACSMDiagnosticDataSetting ##
function Set-WACSMEnvironmentVariable {
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
## [END] Set-WACSMEnvironmentVariable ##
function Set-WACSMHybridManagement {
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
## [END] Set-WACSMHybridManagement ##
function Set-WACSMHyperVEnhancedSessionModeSettings {
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
## [END] Set-WACSMHyperVEnhancedSessionModeSettings ##
function Set-WACSMHyperVHostGeneralSettings {
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
## [END] Set-WACSMHyperVHostGeneralSettings ##
function Set-WACSMHyperVHostLiveMigrationSettings {
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
## [END] Set-WACSMHyperVHostLiveMigrationSettings ##
function Set-WACSMHyperVHostNumaSpanningSettings {
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
## [END] Set-WACSMHyperVHostNumaSpanningSettings ##
function Set-WACSMHyperVHostStorageMigrationSettings {
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
## [END] Set-WACSMHyperVHostStorageMigrationSettings ##
function Set-WACSMPowerConfigurationPlan {
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
## [END] Set-WACSMPowerConfigurationPlan ##
function Set-WACSMRemoteDesktop {
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
## [END] Set-WACSMRemoteDesktop ##
function Start-WACSMDiskPerf {
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
## [END] Start-WACSMDiskPerf ##
function Stop-WACSMCimOperatingSystem {
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
## [END] Stop-WACSMCimOperatingSystem ##
function Stop-WACSMDiskPerf {
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
## [END] Stop-WACSMDiskPerf ##
function Add-WACSMAdministrators {
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
## [END] Add-WACSMAdministrators ##
function Disconnect-WACSMAzureHybridManagement {
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
## [END] Disconnect-WACSMAzureHybridManagement ##
function Get-WACSMAzureHybridManagementConfiguration {
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
## [END] Get-WACSMAzureHybridManagementConfiguration ##
function Get-WACSMAzureHybridManagementOnboardState {
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
## [END] Get-WACSMAzureHybridManagementOnboardState ##
function Get-WACSMCimServiceDetail {
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
## [END] Get-WACSMCimServiceDetail ##
function Get-WACSMCimSingleService {
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
## [END] Get-WACSMCimSingleService ##
function Resolve-WACSMDNSName {
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
## [END] Resolve-WACSMDNSName ##
function Resume-WACSMCimService {
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
## [END] Resume-WACSMCimService ##
function Set-WACSMAzureHybridManagement {
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
## [END] Set-WACSMAzureHybridManagement ##
function Set-WACSMVMPovisioning {
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
## [END] Set-WACSMVMPovisioning ##
function Start-WACSMCimService {
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
## [END] Start-WACSMCimService ##
function Start-WACSMVMProvisioning {
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
## [END] Start-WACSMVMProvisioning ##
function Suspend-WACSMCimService {
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
## [END] Suspend-WACSMCimService ##

# SIG # Begin signature block
# MIIoVQYJKoZIhvcNAQcCoIIoRjCCKEICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAo8oHzzhbLtkeC
# BGFH5HWdadteNMmurdWtTowVDs5fY6CCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGiYwghoiAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAASEmOIS4HijMV0AAAAA
# BIQwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB/L
# uh8KSrhwKM+nhFkuMWE209mOkBgwMGgHBZPu5nP1MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAhcZzbRSf1JV+ON7jJw9SG99LKwpBsotXAov0
# 70YXlD3yze1gNFUiXXelEIGKwSHEZyCZdLOQ3hRlb7au08oflT4n8cSkfynG+sSQ
# GhIGIDV/Gh8u6kUfYdPn2PdgwyLJCuSrTdPIokte7igVbDpe5F/M0nfhyofM65sG
# CgruQ+U6x4dS54BcKPIp5JasdHZz06mU5nJzVZswMu5aA3+3pe1Fxmhb2iPKQE6w
# jKAFBOl13ikGo6QQJP14Hvw1VS4iX2/27RRC90Wf9qank534Ua8iL5Xx5+SpJs84
# JOuAXHzkjxF67V7GKZgHXe6deLdOvkOFFRhDfau1d0xPikzEmqGCF7AwghesBgor
# BgEEAYI3AwMBMYIXnDCCF5gGCSqGSIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDxgw2wBnoud+9jsDYZ2mG6HMY1YoCH7/jg
# s/ogfmZMWwIGaQIupPgGGBMyMDI1MTExMDE3MTYxNS45MDlaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo1NTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEf4wggcoMIIFEKADAgECAhMzAAACG9Cy
# uAJn93LPAAEAAAIbMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgzMFoXDTI2MTExMzE4NDgzMFowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjU1MUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# jsWd52ZZkzB5Xe5g/l2GsOjAz30sg6jVxfFJV+w4xIDVyaI3LO8bIpmzYul3AZHg
# 50UIQ8PrSRZGpQqFkRNu+o3YKJ4g2uGYBRksHnHYR0uVSCQg58ThkYyeplGX3oAv
# GRVuPIpQtAiTsR76A/gdoU7HDwEbb73bJwTyrbKHhR+WaMy9DQHI4k5Qo4+bZDs0
# kj76bvhJvdGU+S8zxQBp7UAhjJnFqKxIusSITE7zCCR422ELhkhVVOFqK2w6h1MA
# vILe76hxRIcPj0SBL2r8O9tx5njU4+tg2rAdU153pmyhqazdpUccYBE9wDRFUd/e
# 9CoWx7TdnUicB+Mai7RT6qse7e5aGqX1B7bnj/ZHvrrfF+BJEIlS9iDXAUgekvXZ
# +FZmjvLwP+dN+0/crh++r4e8FknF7EX6IJfnmNeDN/68Z59kbaJ1f+P5mnKYfydC
# eZmxrGpS0taWkDk36D3jPVZflvxrc+1rhCIlM5v9agLEFI12QiBTfpOBOBr3AGCP
# k+eH0+latjQajug+2/BD12qb82500LQytUWT2ota/HYnRgSv1jvZ0/dml1FsxWYz
# OnCrjfdB/7N6pNySt4vn+PGN6dFLim7kxos+B9WfQPezJi3fuKyyDAB9zSHPj1Zu
# 8nZfecZJ9um4zj7DFgvJXTDTnG5qlG4ZdbFRa/rrfzkCAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBS2vp93/lxLppNK8OkauJ2AvNmIUDAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAZkU1XxQD4OTM3GTht32TXShIfPBoMfSsFsBQqFOZqLJOxyJOllIBFpmp
# vOtGNPkC5Z8ldG8aCpvgFNo/jDWeT5FiW53dAj9KnZxpsQ3Pf5fRzSGHRcxEMOdX
# IVzDJwcZUX0cjfxna7ydNv8eXB/Xk6G6SyrR2OH6S1LHMW11m3UvKF+eLjIPl45r
# ximuDCoEd+ad0lOAXA5/vZOKN5n/ePYeP0LRchZX0Q6H8n/ZmSPMlbli3MO851Q0
# 9RmT/ZGHa+/Fdy+WLDrwcYykV9mUy/4TbwKw6FtdR6ZPHxMdIi1pk8Y2mC/GzCq0
# LCsH0uTFeQ6Q7Nc3MRmER/3mLWUhbaWHgX1FbYchvR22b+Bup+YPR5Q/0BhaaAN6
# AIBfcGs+u/nJoIByyZKA8cTyCmnUI/4vW6D4vywg3XBFf4f2DwFHy/evsC+58KMl
# +k2wa05X2kK0T/bCPLhaov9ZXyobawfNOLYGiauKT2FWvbwZzHIFCTxjBww6Pt5u
# RvCE/jnUcf/xhlOGMn6iKO9Xt49vZTE2SfIBk/34iLTRBJ6H7aGPTTQnza3OfWu1
# /dRycC6Wl5ons3PjnGXTSKSxXllJPmg6R/ulGonP/UCYoJ6mN+EXjfyDLPXLqsr9
# 1+VTG1rYzRCjPwBFAHv4EIwaE0ajCrf75eUGI3+oXU0UP6rloZ8wggdxMIIFWaAD
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
# 2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIDWTCCAkECAQEwggEBoYHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo1NTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAhoV6r49M4GBd
# 41K1RYB1Z0f4zuCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy8fk0wIhgPMjAyNTExMTAxNTA3NTdaGA8yMDI1
# MTExMTE1MDc1N1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7Lx+TQIBADAKAgEA
# AgISnwIB/zAHAgEAAgITaTAKAgUA7L3PzQIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# CwUAA4IBAQB2SgSG/8eNTflm91O/ukiebVreVyMMe27OB6Jh0PrZBIudN+aESjS0
# vMJgMbF8+bl9W7wWbx1t63g4yll5P0kZ8MCPEa7B56qXDZLJkPhKa+aO02JFwL+s
# jYj3gjrZhvkKMZLH3ZcC7o2f+kWVOdB8/Z6AbmFxKtwO1UVh+QJ2Hpc0w+RTsFqk
# f6g5z7lzvYc3o1LVSnxvrznLublBjUW1jmLzK5tzm0ltjWgE24bLaS9QkAaT5zrY
# vmYrhA9OheiO7/Gz7CeSBPk3Wdn0slu3qmfVtRiZ68+/xn+rM2M1xG3bcaehP/7I
# Odv66Qw+PUT8nP80tHi9uC1eKCfwxRoeMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIb0LK4Amf3cs8AAQAAAhswDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgPtmij1HRyzhGB+1bYqQ8ZHikh5penz3JqgjOdDDYuOswgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAwJRSVuD2jmMcQCFXdLuJAwDpUVNZ6bc6d
# fJU83Q2LgDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAACG9CyuAJn93LPAAEAAAIbMCIEIEFhbzxFpCns6VDbZd7S4Y6SZuJhqZ7ZN+C0
# Ys5kt6jvMA0GCSqGSIb3DQEBCwUABIICAFbzF83Y5j8YIRqIZVTGxn09XP9IQR7u
# dm/Xnd3H/wrO4MTd+kP1r0IVblTdTx33JRxB4fncSzsVvLnK1iKSQo1Df63BQZLu
# /dcN+KjmYf0OldgE0c1b4+M6CZ9lY5CUC+ZblvMm4bBldICogXMKRnTCDohtVVul
# 5YcfXowaz0WBgcbDPM5ZgmKy1N/q+ejwL/OaOe7A2B4ayOQ0mCo1HWk9BOPignS6
# sMm6qxhxxLGpMKesKOcjJzZM32GS+BPGQGAbBoPHtJHWxhfaspaDmvPshEALqIeO
# lEdFTrNluUGCFqDmHyrldkNhA6Qo2TCm6eDoSR0EjtJo9nEO+ld9j9oBl2Etc+sc
# fuXVSR4kfg8p7DEwr2/kQxG6fc01D7PtGDQyyNJerMKiSkwAOF+v40/T9snzQ+dV
# j7GWLK+95ao1arZ7amPfPrGaMlX3K4cv+uesO+n6FFpa7lOURct7z9CUk5DAEgk8
# aDJK0zJacEreF5e+b4HFvuCHvMbYYg48KH2BV7qfdjcHVf8uj5MSxqCH1CxkUFvb
# T1aKKls0+dvJYHjO9MgYlh/v3I5xB5BLDtdivnATsiNPZDgji5ouIPJWmSS725CP
# ov9CD+pOUtJB15+6FZ6P62s+P0xv7I/Q96Bk/Y75bcHhojbDJ2YLOLMDARllmC09
# VZHfZqkGBuVG
# SIG # End signature block
