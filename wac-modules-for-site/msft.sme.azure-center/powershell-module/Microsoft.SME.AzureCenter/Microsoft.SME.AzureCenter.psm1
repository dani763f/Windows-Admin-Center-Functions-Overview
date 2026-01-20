function Add-WACACAdministrators {
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
## [END] Add-WACACAdministrators ##
function Disconnect-WACACAzureHybridManagement {
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
## [END] Disconnect-WACACAzureHybridManagement ##
function Get-WACACAzureHybridManagementConfiguration {
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
## [END] Get-WACACAzureHybridManagementConfiguration ##
function Get-WACACAzureHybridManagementOnboardState {
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
## [END] Get-WACACAzureHybridManagementOnboardState ##
function Get-WACACCimServiceDetail {
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
## [END] Get-WACACCimServiceDetail ##
function Get-WACACCimSingleService {
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
## [END] Get-WACACCimSingleService ##
function Resolve-WACACDNSName {
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
## [END] Resolve-WACACDNSName ##
function Resume-WACACCimService {
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
## [END] Resume-WACACCimService ##
function Set-WACACAzureHybridManagement {
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
## [END] Set-WACACAzureHybridManagement ##
function Set-WACACVMPovisioning {
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
## [END] Set-WACACVMPovisioning ##
function Start-WACACCimService {
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
## [END] Start-WACACCimService ##
function Start-WACACVMProvisioning {
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
## [END] Start-WACACVMProvisioning ##
function Suspend-WACACCimService {
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
## [END] Suspend-WACACCimService ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCE8Xo0ScepfCFS
# P91HUn9BG/8JnSyzCVRLllMYWKd0gqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJFh2QFMvHL/1hWewzxRqGDT
# A8FQicCN5KJ3MuK4bcBoMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAfAPn8EtjF4ZRTaY0x/X13COwXKbbCcml16CllfNu7PHKNhfGCz9KBFqC
# vse603NNH9/yzXE/3ioJsJ5mKdIMhHaTrx+vpKfKU4vVa4UNrVs+u0pQudKt6ALH
# WRqEHmoukMJzF85uCRmfl4z9u6a+i7bQADn4XQkTn/NQr2oxbU2ovt4cVL/YD8tt
# BMMoN5rRmAq+SpCGJrlpHX4F8GUuxhd+SCw2xCfjYJxcGwKmdEeWnln7eEo7R74i
# uViX6lZV+51yGcpvE+rJPA5L3dkg/rcunmVNInREh6W0hkM+gzQEJxRCiQPizRfh
# 7uCXe7YJh0nZP8ZLkH/gJCmTFlnMvaGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDwJvy0zYLdsLtCpVKhKMx7z4pey0jNTVovaDA+19Gu/QIGaPC4AH3E
# GBMyMDI1MTExMDE3MTU0MS4yNTJaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAg9XmkcUQOZG5gABAAACDzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQz
# MDRaFw0yNjA0MjIxOTQzMDRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCl6DTurxf66o73G0A2yKo1/nYvITBQsd50F52SQzo2
# cSrt+EDEFCDlSxZzWJD7ujQ1Z1dMbMT6YhK7JUvwxQ+LkQXv2k/3v3xw8xJ2mhXu
# wbT+s1WOL0+9g9AOEAAM6WGjCzI/LZq3/tzHr56in/Z++o/2soGhyGhKMDwWl4J4
# L1Fn8ndtoM1SBibPdqmwmPXpB9QtaP+TCOC1vAaGQOdsqXQ8AdlK6Vuk9yW9ty7S
# 0kRP1nXkFseM33NzBu//ubaoJHb1ceYPZ4U4EOXBHi/2g09WRL9QWItHjPGJYjuJ
# 0ckyrOG1ksfAZWP+Bu8PXAq4s1Ba/h/nXhXAwuxThpvaFb4T0bOjYO/h2LPRbdDM
# cMfS9Zbhq10hXP6ZFHR0RRJ+rr5A8ID9l0UgoUu/gNvCqHCMowz97udo7eWODA7L
# aVv81FHHYw3X5DSTUqJ6pwP+/0lxatxajbSGsm267zqVNsuzUoF2FzPM+YUIwiOp
# gQvvjYIBkB+KUwZf2vRIPWmhAEzWZAGTox/0vj4eHgxwER9fpThcsbZGSxx0nL54
# Hz+L36KJyEVio+oJVvUxm75YEESaTh1RnL0Dls91sBw6mvKrO2O+NCbUtfx+cQXY
# S0JcWZef810BW9Bn/eIvow3Kcx0dVuqDfIWfW7imeTLAK9QAEk+oZCJzUUTvhh2h
# YQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFJnUMQ2OtyAhLR/MD2qtJ9lKRP9ZMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBTowbo1bUE7fXTy+uW9m58qGEXRBGVMEQi
# FEfSui1fhN7jS+kSiN0SR5Kl3AuV49xOxgHo9+GIne5Mpg5n4NS5PW8nWIWGj/8j
# kE3pdJZSvAZarXD4l43iMNxDhdBZqVCkAYcdFVZnxdy+25MRY6RfaGwkinjnYNFA
# 6DYL/1cxw6Ya4sXyV7FgPdMmxVpffnPEDFv4mcVx3jvPZod7gqiDcUHbyV1gaND3
# PejyJ1MGfBYbAQxsynLX1FUsWLwKsNPRJjynwlzBT/OQbxnzkjLibi4h4dOwcN+H
# 4myDtUSnYq9Xf4YvFlZ+mJs5Ytx4U9JVCyW/WERtIEieTvTRgvAYj/4Mh1F2Elf8
# cdILgzi9ezqYefxdsBD8Vix35yMC5LTnDUoyVVulUeeDAJY8+6YBbtXIty4phIki
# hiIHsyWVxW2YGG6A6UWenuwY6z9oBONvMHlqtD37ZyLn0h1kCkkp5kcIIhMtpzEc
# PkfqlkbDVogMoWy80xulxt64P4+1YIzkRht3zTO+jLONu1pmBt+8EUh7DVct/33t
# uW5NOSx56jXQ1TdOdFBpgcW8HvJii8smQ1TQP42HNIKIJY5aiMkK9M2HoxYrQy2M
# oHNOPySsOzr3le/4SDdX67uobGkUNerlJKzKpTR5ZU0SeNAu5oCyDb6gdtTiaN50
# lCC6m44sXjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjMzMDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBe
# tIzj2C/MkdiI03EyNsCtSOMdWqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwoxTAiGA8yMDI1MTExMDA5MDMw
# MVoYDzIwMjUxMTExMDkwMzAxWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvCjF
# AgEAMAoCAQACAhyzAgH/MAcCAQACAhLrMAoCBQDsvXpFAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAGPxkuwiqVjmFwHtyH7vaBk6eSwEkK9NLuckWmhhwjWV
# DdmQJ7s2wepvoTY+vNfMlw4juJqYiafX/JCrXxVDsjnSzdY/g5K2GTCJORI25PQR
# ZjV6C/sO6xg/vLp8u/792rgIC5z3awDGDRIL6uriV644HGlHXS3S7HLAcVmHewHg
# mRN1/7hYvFEoLHDiJYSnvIoUoTkQtJbGS6Zwnd4Vy0VFHPN7bthlgyLSo/T2HIdZ
# mPDzoaUCipnYmUAbAyShCMF/7U2GjdW02ZYTWANVkAHqYiOJVNK++jvbdvbKLpHG
# vnQZnyk/t5iwixLHvgP6i1HyJZ5UugQBWu71HwwxDTAxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAg9XmkcUQOZG5gABAAAC
# DzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCPOLyfsOcc9NJkbvGuGDeHNk3/mNbr+l747e0ZfgPN
# QTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIN1Hd5UmKnm7FW7xP3niGsfH
# Jt4xR8Xu+MxgXXc0iqn4MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIPV5pHFEDmRuYAAQAAAg8wIgQgrWNCvaOBX7TMdMxI2uEPazgw
# U1Z8Q8qGTlBvTOzmiKIwDQYJKoZIhvcNAQELBQAEggIAHOC1lSGnVFFxPPp1cuIu
# 34iIZCVr8kK5/6DumS8mgytwEZwsWVjCfSCh5p1NqFnLuMScndtv1sAEg1zASoMZ
# CuUp8C4vjZMNx5u5pZ1pCPtXjgPHXlnG/e8eNINjT08FG02aC+H7PeNFgPgx7tWv
# PH2l7p2hSY/u74/hm07jZn6ZKT/uFWBK0yvnOuZKYAm3D8uH1mX/9D8NEAVG4KJe
# q7BYlUxnoD9wYKaZMrbgJyTr3Ft8/PuhR2imvarAJy48x43RPglopgujFc17VHqQ
# 1ylkB35Udqx655murWLiWvZFwxEwjsngqvZW8vEFNdW02bHBsz820p5QqeA/uUnP
# W4mhZAUeigmsk0IOyIoQPqjWSrCoKBEv0sMhjNPvCA8tPGw/hnu5VvVsfCWRP9KP
# 6tyQQlYVH/dNW6iKwA/Nr69Lw6/2AAL9MYQlLUo5erjldTL0NVKrTCeF/renOsFN
# rdQV7Ne1eCBeT1LFPWfrLs/PAlB5FHqjsvcynxfq2uP+KQ+c61xwxm+I+4dYvXb/
# NZ/QTNNdnsKBwAsXgTSTz8fI4faV2Q5404TNmKdanPSaZrzYvuBErg7P8/quCFsc
# EgFULxKBiNSg6BIYKM91Eo2gacjvSVJdqIJpJiPTo1NpuP56wMgiho6cabK9o/tf
# Cc5OdQ38HNqUzq4++RB7vRw=
# SIG # End signature block
