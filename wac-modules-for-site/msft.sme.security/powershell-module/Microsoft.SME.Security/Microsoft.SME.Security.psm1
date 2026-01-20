function Add-WACSEWdacPolicy {
<#
.SYNOPSIS
    Add a Windows Defender Application Control (WDAC) supplemental policy
.DESCRIPTION
    Add a Windows Defender Application Control (WDAC) supplemental policy
.ROLE
    Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [String]$filePath
)
    
Set-StrictMode -Version 5.0;

$Script:eventId = 0
function Write-WdacEventLog {
    param (
        [Parameter(Mandatory = $false)]
        [String]$EntryType,
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    if (!$entryType) {
        $entryType = 'Error'
    }

    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Add-WdacPolicy.ps1"

    # Create the event log if it does not exists
    New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
        -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

    $Script:eventId += 1
}

function Add-WdacPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [String]$filePath
    )

    $policyPath = [IO.Path]::GetFullPath( $filePath )
    Add-ASLocalWDACSupplementalPolicy -Path $policyPath -ErrorAction SilentlyContinue -ErrorVariable err

    # See https://github.com/PowerShell/PowerShell/pull/10840
    if (!!$err -and $err[0] -isnot [System.Management.Automation.FlowControlException]) {
        $errorMessage = "There was an error adding the supplemental WDAC policy.  Error: $err. File: $policyPath"
        Write-WdacEventLog -message $errorMessage
        throw $err
    }

    [xml]$xmlFile = Get-Content -Path $policyPath -ErrorAction SilentlyContinue
    $policyId = $xmlFile.SiPolicy.PolicyID
    Copy-Item -Path "$env:InfraCSVRootFolderPath\CloudMedia\Security\WDAC\Stage\$policyId.cip" -Destination "$env:InfraCSVRootFolderPath\CloudMedia\Security\WDAC\Active" -Force -ErrorAction SilentlyContinue -ErrorVariable err

    if (!!$err) {
        $errorMessage = "There was an error applying the supplemental WDAC policy. Error: $err."
        Write-WdacEventLog -message $errorMessage
        throw $err
    }
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    $errorMessage = "Couldn't add supplemental WDAC policy. Module 'Microsoft.AS.Infra.Security.WDAC' does not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."

    Import-Module -Name Microsoft.AS.Infra.Security.WDAC -ErrorAction SilentlyContinue -ErrorVariable err

    if (!!$err) {
        Write-WdacEventLog -Message $errorMessage
        Write-Error -Message $errorMessage
    }
    else {
        Add-WdacPolicy -FilePath $filePath
    }
}

}
## [END] Add-WACSEWdacPolicy ##
function Get-WACSEAszProperties {
<#

.SYNOPSIS
Check-ASZ

.DESCRIPTION
Checks if server has ASZ deployed

.ROLE
Readers

#>

$bitlockerModuleExists = $null -ne (Get-Command -Module AzureStackBitlockerAgent)
$osConfigAgentExists = $null -ne (Get-Command -Module AzureStackOSConfigAgent)
$wdacModuleExists = $null -ne (Get-Command -Module Microsoft.AS.Infra.Security.WDAC)
$serverInfo = Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object operatingSystemSKU, buildNumber

$aszProperties = @{}
$aszProperties.Add("bitlockerModuleExists", $bitlockerModuleExists)
$aszProperties.Add("osConfigAgentExists", $osConfigAgentExists)
$aszProperties.Add("wdacModuleExists", $wdacModuleExists)
$aszProperties.Add("serverInfo", $serverInfo)

$aszProperties

}
## [END] Get-WACSEAszProperties ##
function Get-WACSECluster {
<#
.SYNOPSIS
Gets cluster object

.DESCRIPTION
Gets cluster object

.ROLE
Readers

#>

Import-Module FailoverClusters
FailoverClusters\Get-Cluster | Microsoft.PowerShell.Utility\Select-Object securityLevel, securityLevelForStorage

}
## [END] Get-WACSECluster ##
function Get-WACSEClusterSecuritySettings {
<#
.SYNOPSIS
Get array of Azure Stack HCI Security Settings

.DESCRIPTION
Get array of Azure Stack HCI Security Settings
    [
        Boot volume bitlocker encyption
        Side Channel Mitigation
        Credential Guard
        SMB signing
        Drift Control
    ]

.ROLE
Administrators

#>

function Get-SecurityBaseline {
  $wacAuthorityId = "E17005D5-A50E-4E57-BE94-1D4FA69C6F93"
  $wacLiteAuthorityId = "8345CBE6-CEFC-462A-8219-78F3FC0377C1"
  $securityBaselineId = "64329a05-92b9-450e-a0b3-b2f9185100c1"
  $wacAuthorityConfigDocs = Get-OsConfigurationDocument -SourceId $wacAuthorityId -Id $securityBaselineId

  $doc = if ($null -eq $wacAuthorityConfigDocs) { Get-OsConfigurationDocument -SourceId $wacLiteAuthorityId -Id $securityBaselineId } else { $wacAuthorityConfigDocs}

  if ($null -eq $doc) {
    Write-GetAszSettingsEventLog -Message "Couldn't query ASZ Security Settings. Security Baseline document not found."
    return $false
  }


  $securityBaseline = $doc | Get-OsConfigurationDocumentResult | ConvertFrom-Json
  $status = ($securityBaseline.OsConfiguration.Document).status
  if ($status.state -ne "completed") {
    return $false
  }

  return $true
}

function Get-AszSecuritySettings {
  # Get Boot volume bitlocker encyption setting
  $bootVolumeBitlockerEncryption = Get-ASLocalBitlockerEnforced

  # Get Side Channel Mitigation setting
  $sideChannelMitigation = Get-ASSecurity -FeatureName SideChannelMitigation -Local

  # Get Credential Guard setting
  $credentialGuard = Get-ASSecurity -FeatureName CredentialGuard -Local

  # Get SMB signing setting
  $smbSigning = Get-ASSecurity -FeatureName SMBSigning -Local

  # Get Drift Control setting
  $driftControl = Get-ASSecurity -FeatureName DriftControl -Local

  # Get Security Baseline
  $securityBaseline = Get-SecurityBaseline


  $settingsStatus = @{}
  $settingsStatus.Add("bootVolumeBitlockerEncryption", $bootVolumeBitlockerEncryption)
  $settingsStatus.Add("sideChannelMitigation", $sideChannelMitigation)
  $settingsStatus.Add("credentialGuard", $credentialGuard)
  $settingsStatus.Add("smbSigning", $smbSigning)
  $settingsStatus.Add("driftControl", $driftControl)
  $settingsStatus.Add("securityBaseline", $securityBaseline)

  $settingsStatus
}

$Script:eventId = 0
function Write-GetAszSettingsEventLog {
  param (
    [Parameter(Mandatory = $false)]
    [String]$entryType,
    [Parameter(Mandatory = $true)]
    [String]$message
  )

  if (!$entryType) {
    $entryType = 'Error'
  }

  $LogName = "WindowsAdminCenter"
  $LogSource = "msft.sme.security"
  $ScriptName = "Get-ClusterSecuritySettings.ps1"

  # Create the event log if it does not exists
  New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
    -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

  $Script:eventId += 1
}

###############################################################################
# Script execution starts here
###############################################################################
$bitlockerModuleExists = $null -ne (Get-Command -Module AzureStackBitlockerAgent)
$osConfigAgentExists = $null -ne (Get-Command -Module AzureStackOSConfigAgent)
if ($bitlockerModuleExists -and $osConfigAgentExists) {
  Get-AszSecuritySettings
}
else {
  Write-GetAszSettingsEventLog -Message "Couldn't query ASZ Security Settings. Modules 'AzureStackBitlockerAgent' and 'AzureStackOSConfigAgent' do not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."
}

}
## [END] Get-WACSEClusterSecuritySettings ##
function Get-WACSEClusterSpecificSettings {
<#
.SYNOPSIS
Get array of cluster-specific Azure Stack HCI Security Settings

.DESCRIPTION
Get array of cluster-specific Azure Stack HCI Security Settings
    [
        Data Volume Bitlocker
        SMB Cluster encryption
    ]

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

<#

.SYNOPSIS
Setup the script environment.

.DESCRIPTION
Setup the script environment.  Create read only (constant) variables
that add context to the said constants.

#>
function setupScriptEnv() {
    Set-Variable -Name SMBEncryptionFeatureName -Option ReadOnly -Value "SMBClusterEncryption" -Scope Script
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
    Remove-Variable -Name SMBEncryptionFeatureName -Scope Script -Force
}

setupScriptEnv

# Get SMB Cluster encryption setting
$smbClusterEncryption = Get-ASSecurity -FeatureName $SMBEncryptionFeatureName -Local


# Get Data volumes bitlocker setting
# (Only a cluster cmdlet - no local support for data volume encryption)
# TODO 03-03-2023: Update when ECE removal is done. We cannot use ECE with WAC since ECE requires CredSSP
# $dataVolumeEncryption = Get-ASBitlockerDataVolumeEncryptionStatus

$settingsStatus = @{}
# $settingsStatus.Add("dataVolumeEncryption", $dataVolumeEncryption)
$settingsStatus.Add("smbClusterEncryption", $smbClusterEncryption)

cleanupScriptEnv

$settingsStatus

}
## [END] Get-WACSEClusterSpecificSettings ##
function Get-WACSEComputerInfo {
<#

.SYNOPSIS
Get-ComputerInfo

.DESCRIPTION
Gets OSDisplayVersion, OsOperatingSystemSKU, and OsBuildNumber information

.ROLE
Readers

#>

$computerInfo = Get-ComputerInfo | Microsoft.PowerShell.Utility\Select-Object OSDisplayVersion, OsOperatingSystemSKU
$computerInfo | Add-Member -Name 'OsBuildNumber' -Type NoteProperty -Value ([System.Environment]::OSVersion.Version.Build)

$computerInfo

}
## [END] Get-WACSEComputerInfo ##
function Get-WACSEMicrosoftOsConfigModuleVersion {
<#
.SYNOPSIS
Gets the highest version of the Microsoft.OSConfig module installed.

.DESCRIPTION
Gets the highest version of the Microsoft.OSConfig module installed.

.ROLE
Administrators

#>

$osConfigModule = "Microsoft.OSConfig"
$module = Get-InstalledModule -Name $osConfigModule -ErrorAction SilentlyContinue `
            | Microsoft.PowerShell.Utility\Sort-Object Version -Descending `
            | Microsoft.PowerShell.Utility\Select-Object -First 1
return $module.Version.ToString()
}
## [END] Get-WACSEMicrosoftOsConfigModuleVersion ##
function Get-WACSENodeDataVolumesBitlockerStatus {
<#
.SYNOPSIS
Get array of cluster shared data volumes bitlocker status

.DESCRIPTION
Get array of cluster shared data volumes bitlocker status

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$Script:eventId = 0
function Write-WdacEventLog {
    param (
        [Parameter(Mandatory = $false)]
        [String]$EntryType,
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    if (!$entryType) {
        $entryType = 'Error'
    }

    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Get-NodeDataVolumesBitlockerStatus.ps1"

    # Create the event log if it does not exists
    New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
        -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

    $Script:eventId += 1
}

function Get-BitlockerStatus {
    $result = @()

    $bitLockerVolumes = Get-AsBitlocker -volumeType ClusterSharedVolume -Local -ErrorAction SilentlyContinue -ErrorVariable err
    if (!!$err) {
        $errorMessage = "There was an error getting the bitlocker status. Error: $err."
        Write-WdacEventLog -message $errorMessage
        throw $err
    }

    foreach ($volume in $bitLockerVolumes) {
        $volumeInfo = Get-Volume -FilePath $volume.mountPoint
        $volumeName = $volumeInfo.FileSystemLabel
        $path = $volumeInfo.Path
        $volumeId = (Split-Path -Path $path -Leaf).Split('{}')[1]

        $newObject = $volume | Microsoft.PowerShell.Utility\Select-Object *, @{Name = 'VolumeId'; Expression = { $volumeId } }, @{Name = 'VolumeName'; Expression = { $volumeName } }
        $result += $newObject 
    }

    return $result
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    $errorMessage = "Couldn't get shared volumes bitlocker status. Module 'Microsoft.AS.Infra.Security.WDAC' does not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."

    Import-Module -Name Microsoft.AS.Infra.Security.WDAC -ErrorAction SilentlyContinue -ErrorVariable err

    if (!!$err) {
        Write-WdacEventLog -Message $errorMessage
        Write-Error -Message $errorMessage
    }
    else {
        Get-BitlockerStatus
    }
}

}
## [END] Get-WACSENodeDataVolumesBitlockerStatus ##
function Get-WACSEPreferenceActions {
<#

.SYNOPSIS
Get Actions for Threats.

.DESCRIPTION
Get Custom SetActions Which Are More Prefferable.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$Preference = Get-MpPreference

$preferenceDefaultActions = $Preference.ThreatIDDefaultAction_Actions
$preferenceDefaultActionsIDs = $Preference.ThreatIDDefaultAction_Ids

$actionsHash = @{}

$actionsHash.Add('Actions', $preferenceDefaultActions)
$actionsHash.Add('Ids', $preferenceDefaultActionsIDs)

return $actionsHash
}
## [END] Get-WACSEPreferenceActions ##
function Get-WACSERealTimeMonitoringState {
<#

.SYNOPSIS
Get Real Time Monitoring State.

.DESCRIPTION
Get Real Time Monitoring State.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$Preference = Get-MpPreference

return $Preference.DisableRealtimeMonitoring
}
## [END] Get-WACSERealTimeMonitoringState ##
function Get-WACSESecuredCoreFeatures {
<#
.SYNOPSIS
Get Secured-Core Features

.DESCRIPTION
Get array of secured-core features
    [
        TPM 2.0,
        Secure Boot,
        VBS,
        HVCI,
        Boot DMA Protection,
        SystemGuard
    ]

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

# tpm version check
function CheckTpmVersion {
  $TpmObj = Get-CimInstance -classname Win32_Tpm -namespace root\cimv2\Security\MicrosoftTpm

  if ($null -ne $TpmObj) {
    return $TpmObj.SpecVersion[0] -eq "2"
  }

  return $false
}

<#
Check whether VBS is enabled and running
0.	VBS is not enabled.
1.	VBS is enabled but not running.
2.	VBS is enabled and running.
#>
function CheckVBS {
  return (Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
}

<#
# device guard checked used for hcvi and system guard
0.	No services running.
1.	If present, Windows Defender Credential Guard is running.
2.	If present, HVCI is running.
3.	If present, System Guard Secure Launch is running.
4.	If present, SMM Firmware Measurement is running.
#>
function CheckDGSecurityServicesRunning($_val) {
  $DGObj = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard

  # loop to avoid out of index out of bounds errors
  for ($i = 0; $i -lt $DGObj.SecurityServicesRunning.length; $i++) {
    if ($DGObj.SecurityServicesRunning[$i] -eq $_val) {
      return $true
    }
  }

  return $false
}

<#
Indicates whether the Windows Defender Credential Guard or HVCI service has been configured.
0.	No services configured.
1.	If present, Windows Defender Credential Guard is configured.
2.	If present, HVCI is configured.
3.	If present, System Guard Secure Launch is configured.
4.	If present, SMM Firmware Measurement is configured.
#>
function CheckDGSecurityServicesConfigured($_val) {
  $DGObj = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard
  if ($_val -in $DGObj.SecurityServicesConfigured) {
    return $true
  }

  return $false
}

# bootDMAProtection check
$bootDMAProtectionCheck =
@"
  namespace SystemInfo
    {
      using System;
      using System.Runtime.InteropServices;

      public static class NativeMethods
      {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            /// </summary>
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
          SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
          IntPtr SystemInformation,
          Int32 SystemInformationLength,
          out Int32 ReturnLength);

        public static byte BootDmaCheck() {
          Int32 result;
          Int32 SystemInformationLength = 1;
          IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
          Int32 ReturnLength;

          result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

          if (result == 0) {
            byte info = Marshal.ReadByte(SystemInformation, 0);
            return info;
          }

          return 0;
        }
      }
    }
"@
Add-Type -TypeDefinition $bootDMAProtectionCheck

function checkSecureBoot {
  if ((Get-Command Confirm-SecureBootUEFI -ErrorAction  SilentlyContinue) -ne $null) {
    <#
    For devices that Standard hardware security is not supported, this means that the device does not meet
    at least one of the requirements of standard hardware security.
    This causes the Confirm-SecureBootUEFI command to fail with the error:
      Cmdlet not supported on this platform: 0xC0000002
   #>
    try {
      return Confirm-SecureBootUEFI
    }
    catch {
      return $false
    }
  }
  return $false
}


###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
  $securedCoreFeatures = @{}

  # Status: Security is running
  # Configured: Security service is enabled/configured
  $TPM20Obj = @{"Status" = CheckTpmVersion; "Configured" = $null }
  $secureBoot = @{"Status" = checkSecureBoot; "Configured" = $null }
  $bootDMAProtection = @{"Status" = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0; "Configured" = $null }

  $vbsStatus = [int](CheckVBS)
  $vbsRunning = if ($vbsStatus -eq 2) { $true } else { $false }
  $vbsConfigured = if ($vbsStatus -gt 0) { $true } else { $false }
  $VBS = @{"Status" = $vbsRunning; "Configured" = $vbsConfigured }
  $HVCI = @{"Status" = CheckDGSecurityServicesRunning(2); "Configured" = CheckDGSecurityServicesConfigured(2) }

  $securedCoreFeatures.Add("tpm20", $TPM20Obj)
  $securedCoreFeatures.Add("secureBoot", $secureBoot)
  $securedCoreFeatures.Add("bootDMAProtection", $bootDMAProtection)
  $securedCoreFeatures.Add("vbs", $VBS)
  $securedCoreFeatures.Add("hvci", $HVCI)

  # Current logic for showing System Guard (DRTM) in secured-core:
  # NOTE: This is temporary and can change in next releases of HCI
  # 10.0.20348 - WS2022 - Shown
  # 10.0.26100 - WS2025 - Shown
  # 10.0.20349 - HCI w/LCM 22H2  - Hidden
  # 10.0.25398 - HCI w/LCM 23H2  - Hidden
  # 10.0.26100 - HCI w/LCM       - Hidden
  $operatingSystemSKU = [int](Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU
  $hciOperatingSystemSKU = 406

  $lcmModuleExists = Get-Module Microsoft.AzureStack.Lcm.PowerShell -ListAvailable -ErrorAction SilentlyContinue
  $shouldHideSystemGuard = ($operatingSystemSKU -eq $hciOperatingSystemSKU) -and ($null -ne $lcmModuleExists)
  if (!$shouldHideSystemGuard) {
    $systemGuard = @{"Status" = CheckDGSecurityServicesRunning(3); "Configured" = CheckDGSecurityServicesConfigured(3) }
    $securedCoreFeatures.Add("systemGuard", $systemGuard)
  }

  $securedCoreFeatures
}

}
## [END] Get-WACSESecuredCoreFeatures ##
function Get-WACSESecuredCoreOsConfigFeatures {
<#
.SYNOPSIS
Get Secured-Core Features using OsConfiguration module

.DESCRIPTION
Get array of secured-core features
    [
        TPM 2.0,
        Secure Boot,
        VBS,
        HVCI,
        Boot DMA Protection,
        SystemGuard
    ]

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0;

# Set OsConfiguration document and get the result, or $null on failure
function OsConfigurationSetDocumentGetResult {

  [CmdletBinding()]
  Param (
    [Parameter(Mandatory)]
    [String] $Id,

    [Parameter(Mandatory)]
    [String] $Content
  )

  # Set the document to get securedcore settings
  #Set-OsConfigurationDocument -Content $Content -Wait -TimeoutInSeconds 300
  Set-OsConfigurationDocument -Content $Content -Wait

  $result = Get-OsConfigurationDocumentResult -Id $Id | ConvertFrom-Json

  return $result.OsConfiguration.Scenario[0]
}

# Use OsConfiguration to check SecuredCore states
$jsonDocumentToGetSecuredCoreSettingStates =
@"
{
  "OsConfiguration":{
      "Document":{
        "schemaversion":"1.0",
        "id":"10088660-1861-4131-96e8-f32e85011100",
        "version":"10056C2C71F6A41F9AB4A601AD00C8B5BC7531576233010B13A221A9FE1BE100",
        "context":"device",
        "scenario":"SecuredCoreState"
      },
      "Scenario":[
        {
            "name":"SecuredCoreState",
            "schemaversion":"1.0",
            "action":"get",
            "SecuredCoreState":{
              "VirtualizationBasedSecurityStatus": "0",
              "HypervisorEnforcedCodeIntegrityStatus": "0",
              "SystemGuardStatus": "0",
              "SecureBootState": "0",
              "TPMVersion": "",
              "BootDMAProtection": "0"
            }
        }
      ]
  }
}
"@

function GetSecuredCoreSettingStates {

  # Set the document to get securedcore settings
  $result = OsConfigurationSetDocumentGetResult -Id "10088660-1861-4131-96e8-f32e85011100" -Content $jsonDocumentToGetSecuredCoreSettingStates
  $Script:securedCoreStatus = $result.status

  return $result.SecuredCoreState
}

$jsonDocumentToGetSecuredCoreSettingConfigurations =
@"
{
  "OsConfiguration":{
      "Document":{
        "schemaversion":"1.0",
        "id":"47e88660-1861-4131-96e8-f32e85011e55",
        "version":"3C356C2C71F6A41F9AB4A601AD00C8B5BC7531576233010B13A221A9FE1BE7A0",
        "context":"device",
        "scenario":"SecuredCore"
      },
      "Scenario":[
        {
            "name":"SecuredCore",
            "schemaversion":"1.0",
            "action":"get",
            "SecuredCore":{
              "EnableVirtualizationBasedSecurity": "0",
              "HypervisorEnforcedCodeIntegrity": "0",
              "ConfigureSystemGuardLaunch": "0"
            }
        }
      ]
  }
}
"@

function GetSecuredCoreSettingConfigurations {

  # Set the document to get securedcore settings
  $result = OsConfigurationSetDocumentGetResult -Id "47e88660-1861-4131-96e8-f32e85011e55" -Content $jsonDocumentToGetSecuredCoreSettingConfigurations

  return $result.SecuredCore
}

function CheckTpmVersion {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory)]
    $status
  )
  if ([bool]($SecuredCoreStates.PSobject.Properties.name -match "TPMVersion") -and $status -ne "failed") {
    return $null -ne $SecuredCoreStates.TPMVersion -and $SecuredCoreStates.TPMVersion[0] -eq "2"
  }
  return $false
}

function getFeatureStatus {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory)]
    [String] $securedCoreState,

    [Parameter(Mandatory)]
    $expectedStateValue
  )

  foreach ($status in $Script:securedCoreStatus) {
    # handle tpm separately to make sure it exists
    if ($securedCoreState -eq "TPMVersion") {
      return CheckTpmVersion $status.state
    }
    # check for failed status
    if ($status.name -eq $securedCoreState -and $status.state -eq "failed") {
      return $false
    }
    return ($SecuredCoreStates | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty $securedCoreState) -eq $expectedStateValue
  }
}

$SecuredCoreStates = GetSecuredCoreSettingStates
$SecuredCoreConfigurations = GetSecuredCoreSettingConfigurations

# String with a list of TPM version such as "2.0, 0, 1.16"
$TPM20Obj = @{"Status" = getFeatureStatus "TPMVersion" "2"; "Configured" = $null }
# Indicates whether secure boot is enabled. The value is one of the following: 0 - Not supported, 1 - Enabled, 2 - Disabled
$secureBoot = @{"Status" = getFeatureStatus "SecureBootState" 1; "Configured" = $null }
# Boot DMA Protection status. 1 - Enabled, 2 - Disabled
$bootDMAProtection = @{"Status" = getFeatureStatus "BootDMAProtection" 1; "Configured" = $null }
# Virtualization-based security status. Value is one of the following: 0 - Running, 1 - Reboot required, 2 - 64 bit architecture required, 3 - not licensed, 4 - not configured, 5 - System doesn't meet hardware requirements, 42 - Other. Event logs in Microsoft-Windows-DeviceGuard have more details
$VBS = @{"Status" = getFeatureStatus "VirtualizationBasedSecurityStatus" 0; "Configured" = $SecuredCoreConfigurations.EnableVirtualizationBasedSecurity -eq 1 }
# Hypervisor Enforced Code Integrity (HVCI) status. 0 - Running, 1 - Reboot required, 2 - Not configured, 3 - VBS not running
$HVCI = @{"Status" = getFeatureStatus "HypervisorEnforcedCodeIntegrityStatus" 0; "Configured" = $SecuredCoreConfigurations.HypervisorEnforcedCodeIntegrity -eq 2 }

$securedCoreFeatures = @{}

$securedCoreFeatures.Add("tpm20", $TPM20Obj)
$securedCoreFeatures.Add("secureBoot", $secureBoot)
$securedCoreFeatures.Add("bootDMAProtection", $bootDMAProtection)
$securedCoreFeatures.Add("vbs", $VBS)
$securedCoreFeatures.Add("hvci", $HVCI)

# Current logic for showing System Guard (DRTM) in secured-core:
# NOTE: This is temporary and can change in next releases of HCI
# 10.0.20348 - WS2022 - Shown
# 10.0.26100 - WS2025 - Shown
# 10.0.20349 - HCI w/LCM 22H2  - Hidden
# 10.0.25398 - HCI w/LCM 23H2  - Hidden
# 10.0.26100 - HCI w/LCM       - Hidden
$operatingSystemSKU = [int](Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU
$hciOperatingSystemSKU = 406

$lcmModuleExists = Get-Module Microsoft.AzureStack.Lcm.PowerShell -ListAvailable -ErrorAction SilentlyContinue
$shouldHideSystemGuard = ($operatingSystemSKU -eq $hciOperatingSystemSKU) -and ($null -ne $lcmModuleExists)
if (!$shouldHideSystemGuard) {
  # System Guard status. 0 - Running, 1 - Reboot required, 2 - Not configured, 3 - System doesn't meet hardware requirements
  $systemGuard = @{"Status" = getFeatureStatus "SystemGuardStatus" 0; "Configured" = $SecuredCoreConfigurations.ConfigureSystemGuardLaunch -eq 1 }
  $securedCoreFeatures.Add("systemGuard", $systemGuard)
}

$securedCoreFeatures

}
## [END] Get-WACSESecuredCoreOsConfigFeatures ##
function Get-WACSESecurityConfigurations {
<#
.SYNOPSIS
Gets the security configurations for the specified scenario. 

.DESCRIPTION
Gets the security configurations for the specified scenario. 

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]$Scenario
)

$securityConfigurations = Get-OSConfigDesiredConfiguration -Scenario $Scenario
return $securityConfigurations

}
## [END] Get-WACSESecurityConfigurations ##
function Get-WACSEServerType {
<#
.SYNOPSIS
Gets the server type (developed for Windows Server 2025).

.DESCRIPTION
Gets the server type (developed for Windows Server 2025).

.ROLE
Administrators

#>

function Get-RegistryValue([String] $LiteralPath, [String] $Name, [Object] $Default) {
    try {
        return [Microsoft.Win32.Registry]::GetValue($LiteralPath.Replace("HKLM:\", "HKEY_LOCAL_MACHINE\"), $Name, $Default)
    } catch {
        # Ignored.
    }

    return $Default
}

function Get-ServerTypeInfo() {
    $result = "WorkgroupMember"

    $domainController = Get-RegistryValue -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SysvolReady"
    if (-not [String]::IsNullOrEmpty($domainController)) {
        $result = "DomainController"
    } else {
        $domainMember = Get-RegistryValue -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Domain"

        if (-not [String]::IsNullOrEmpty($domainMember)) {
            $result = "DomainMember"
        }
    }

    $result
}

return Get-ServerTypeInfo
}
## [END] Get-WACSEServerType ##
function Get-WACSEStatusSummary {
<#

.SYNOPSIS
Get Summary Object.

.DESCRIPTION
Get Summary:
    - Latest Detected Threat
    - Latest Scan Date and Type
    - Scheduled Scan Date and Type
    - Threat Definition Version
    - Version Creation Date.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$ComputerStatus = Get-MpComputerStatus;
$ThreatDetection = Get-MpThreatDetection;
$MpPreference = Get-MpPreference;

$summaryHash = @{}

# Latest Threat Detected
if ($ThreatDetection) {
    $threatsTime = $ThreatDetection.InitialDetectionTime
    if ($threatsTime) {
        if ($threatsTime -is [system.array]) {
            $summaryHash.Add('latestThreatTime', $threatsTime[$threatsTime.Length-1]);
        } else {
            $summaryHash.Add('latestThreatTime', $threatsTime);
        }
    }
} else {
    $summaryHash.Add('latestThreatDate', $null);
}

# Latest Scan
$latestScanTime = $null
$latestScanType = $null
if ($null -eq $ComputerStatus.QuickScanStartTime ) {
    if ($null -eq $ComputerStatus.FullScanStartTime) {
        $summaryHash.Add('latestScanTime', $null);
        $summaryHash.Add('latestScanType', $null);
    }
    else {
        $latestScanTime = $ComputerStatus.FullScanStartTime;
        $latestScanType = 2;
    }
}
else {
    if ($null -eq $ComputerStatus.FullScanStartTime) {
        $latestScanTime = $ComputerStatus.QuickScanStartTime
        $latestScanType = 1;
    }
    else {
        if ($ComputerStatus.QuickScanStartTime -gt $ComputerStatus.FullScanStartTime) {
            $latestScanTime = $ComputerStatus.QuickScanStartTime
            $latestScanType = 1;
        }
        else {
            $latestScanTime = $ComputerStatus.FullScanStartTime
            $latestScanType = 2;
        }
    }
}

if ($summaryHash.ContainsKey('latestScanTime')) {
  $summaryHash.latestScanTime = $latestScanTime
} else {
  $summaryHash.Add('latestScanTime', $latestScanTime)
}

if ($summaryHash.ContainsKey('latestScanType')) {
  $summaryHash.latestScanType = $latestScanType
} else {
  $summaryHash.Add('latestScanType', $latestScanType)
}

# Next Scheduled Scan
$scanDay = [int]$MpPreference.ScanScheduleDay
$scanMinutes = [int]$MpPreference.ScanScheduleTime.TotalMinutes
$scanTimeSpan = New-Timespan -minutes $scanMinutes
$scanDateTime = [DateTime]($scanTimeSpan.Ticks);
$scanTime = $scanDateTime.ToString('t')
$scanType = [int]$MpPreference.ScanParameters
$summaryHash.Add('scanDay', $scanDay)
$summaryHash.Add('scanTime', $scanTime)
$summaryHash.Add('scanType', $scanType)

return $summaryHash

}
## [END] Get-WACSEStatusSummary ##
function Get-WACSEThreatDetections {
<#

.SYNOPSIS
Get Array of Detected Threats.

.DESCRIPTION
Get Array of Detected Threat Object
    [
        ThreatID,
        Detected Threat Name,
        Detected File,
        Time and Date,
        Threat Alert Level,
        Threat Status,
        Threat Category,
        Threat Default Action
    ].

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$ThreatDetection = Get-MpThreatDetection

$tableEntryObjectsArray = @()

foreach ($detectedThreat in $ThreatDetection) {
    $tableEntryHash = @{}

    $threatID = $detectedThreat.ThreatID
    $tableEntryHash.Add('ThreatID', [string]$threatID)

    # Detected Threat
    $threat = Get-MpThreat -ThreatID $threatID
    $threatName = $threat.ThreatName
    $tableEntryHash.Add('DetectedThreat', $threatName)

    # Item
    $threatFileLongName = $threat.Resources[0]
    $threatFileSplitted = $threatFileLongName -split "file:_"
    $tableEntryHash.Add('Item', $threatFileSplitted[1])

    $dateTime = $detectedThreat.InitialDetectionTime
    $tableEntryHash.Add('DateTime', $dateTime.ToString('g'))

    $tableEntryHash.Add('AlertLevel', $threat.SeverityID)

    $tableEntryHash.Add('Status', $detectedThreat.ThreatStatusID)

    $tableEntryHash.Add('Category', $threat.CategoryID)

    $tableEntryHash.Add('DefaultAction', $detectedThreat.CleaningActionID)

    $tableEntryObject = New-Object -TypeName psobject -Property $tableEntryHash
    $tableEntryObjectsArray += $tableEntryObject
}

return $tableEntryObjectsArray

}
## [END] Get-WACSEThreatDetections ##
function Get-WACSEVBSRequiredSecurityProperties {
<#
.SYNOPSIS
Gets the required security properties for Virtualization-Based Security (VBS).

.DESCRIPTION
Gets the required security properties for Virtualization-Based Security (VBS).
https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.deviceguard.requiredsecurityproperties

Return values best described here:
https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security#use-win32_deviceguard-wmi-class

.ROLE
Administrators

#>

$RequiredSecurityProperties = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue `
                                | Microsoft.PowerShell.Utility\Select-Object RequiredSecurityProperties
return $RequiredSecurityProperties
}
## [END] Get-WACSEVBSRequiredSecurityProperties ##
function Get-WACSEWdacPolicyInfo {
<#
.SYNOPSIS
Get Windows Defender Application Control (WDAC) Policy Info

.DESCRIPTION
Get Windows Defender Application Control (WDAC) Policy Info

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0;

$Script:eventId = 0
function Write-GetWdacEventLog {
  param (
    [Parameter(Mandatory = $false)]
    [String]$entryType,
    [Parameter(Mandatory = $true)]
    [String]$message
  )

  if (!$entryType) {
    $entryType = 'Error'
  }

  $LogName = "WindowsAdminCenter"
  $LogSource = "msft.sme.security"
  $ScriptName = "Set-WdacPolicyMode.ps1"

  # Create the event log if it does not exists
  New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
    -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

  $Script:eventId += 1
}

###############################################################################
# Script execution starts here
###############################################################################
$wdacModuleExists = $null -ne (Get-Command -Module Microsoft.AS.Infra.Security.WDAC)
if ($wdacModuleExists) {
  # Refresh policy when we have some event flooding issue
  Invoke-WDACRefreshPolicyTool | Out-Null

  Get-ASLocalWDACPolicyInfo
} else {
  Write-GetWdacEventLog -Message "Couldn't query WDAC policy. Module 'Microsoft.AS.Infra.Security.WDAC' does not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."
}

}
## [END] Get-WACSEWdacPolicyInfo ##
function Get-WACSEWdacPolicyMode {
<#
.SYNOPSIS
Get Windows Defender Application Control (WDAC) Policy setting

.DESCRIPTION
Get Windows Defender Application Control (WDAC) Policy setting
Returned values
    0: Not deployed
    1: Audit
    2: Enforcement

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

Get-ASLocalWDACPolicyMode

}
## [END] Get-WACSEWdacPolicyMode ##
function Install-WACSEMicrosoftOsConfigModule {
<#
.SYNOPSIS
Installs the required Microsoft.OSConfig module if the module is not found. 

.DESCRIPTION
Installs the required Microsoft.OSConfig module if the module is not found. 
NOTE: OsConfiguration module is the older set of PS cmdlets that are shipped with the OS. They are a lot more low level and accept JSON directly.
Microsoft.OSConfig module builds on top of OsConfiguration.

.ROLE
Administrators

#>

$osConfigModule = "Microsoft.OSConfig"
$moduleExists = Get-InstalledModule -Name $osConfigModule -AllVersions -ErrorAction silentlycontinue

if ($moduleExists) {
    # No installation performed
    return $false
} else {
    # Install the package providers if not already installed
    Get-PackageProvider -Name PowerShellGet -ForceBootstrap | Out-Null
    Get-PackageProvider -Name NuGet -ForceBootstrap | Out-Null

    Install-Module -Name $osConfigModule -Repository PSGallery -Scope AllUsers -Force
    return $true
}

}
## [END] Install-WACSEMicrosoftOsConfigModule ##
function Remove-WACSEWdacPolicy {
<#
.SYNOPSIS
    Remove a Windows Defender Application Control (WDAC) supplemental policy
.DESCRIPTION
    Remove a Windows Defender Application Control (WDAC) supplemental policy
.ROLE
    Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [String]$policyGuid
)
    
Set-StrictMode -Version 5.0;

$Script:eventId = 0
function Write-WdacEventLog {
    param (
        [Parameter(Mandatory = $false)]
        [String]$EntryType,
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    if (!$entryType) {
        $entryType = 'Error'
    }

    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Add-WdacPolicy.ps1"

    # Create the event log if it does not exists
    New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
        -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

    $Script:eventId += 1
}

function Remove-WdacPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [String]$policyGuid
    )

    Remove-ASLocalWDACSupplementalPolicy -PolicyGuid $policyGuid -ErrorAction SilentlyContinue -ErrorVariable err

    # See https://github.com/PowerShell/PowerShell/pull/10840
    if (!!$err -and $err[0] -isnot [System.Management.Automation.FlowControlException]) {
        $errorMessage = "There was an error removing the supplemental WDAC policy.  Error: $err. Policy: $policyGuid"
        Write-WdacEventLog -message $errorMessage
        throw $err
    }

    $policyFilePath = "$env:InfraCSVRootFolderPath\CloudMedia\Security\WDAC\Active\$policyGuid.cip"

    if (Test-Path -Path $policyFilePath -PathType Leaf) {
        Remove-Item -Path $policyFilePath -Force -ErrorAction SilentlyContinue -ErrorVariable err

        if (!!$err) {
            $errorMessage = "There was an error removing the supplemental WDAC policy. Error: $err. File: $policyGuid"
            Write-WdacEventLog -message $errorMessage
            throw $err
        }
    }
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    $errorMessage = "Couldn't remove supplemental WDAC policy. Module 'Microsoft.AS.Infra.Security.WDAC' does not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."

    Import-Module -Name Microsoft.AS.Infra.Security.WDAC -ErrorAction SilentlyContinue -ErrorVariable err

    if (!!$err) {
        Write-WdacEventLog -Message $errorMessage
        Write-Error -Message $errorMessage
    }
    else {
        Remove-WdacPolicy -PolicyGuid $policyGuid
    }
}

}
## [END] Remove-WACSEWdacPolicy ##
function Set-WACSEClusterSecuritySettings {
<#
.SYNOPSIS
Script that enables and disables Azure Stack HCI Security Settings

.DESCRIPTION
Script that enables and disables Azure Stack HCI Security Settings

.Parameter SettingName
Name of cluster security setting whose status needs to be toggled. Either one of the following:
 bootVolumeBitlockerEncryption, sideChannelMitigation, credentialGuard,
 smbClusterEncryption, smbSigning, driftControl

.Parameter action
Action to perform, either enable (1) or disable (0) a cluster security setting
Allowed value:
  0: Disable
  1: Enable

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]$settingName,
  [Parameter(Mandatory = $true)]
  [String]$action,
  [Parameter()]
  [array]$mountPoints
)

function setupScriptEnv() {
  $BuildNumber23H2 = 25398
  $isOlderThan23H2 = [System.Environment]::OSVersion.Version.Build -lt $BuildNumber23H2
  if ($isOlderThan23H2) {
    Set-Variable -Name SMBEncryptionFeatureName -Option ReadOnly -Value "SMBEncryption" -Scope Script
  }
  else {
    Set-Variable -Name SMBEncryptionFeatureName -Option ReadOnly -Value "SMBClusterEncryption" -Scope Script
  }
}

<#

.SYNOPSIS
Cleanup the script environment.

.DESCRIPTION
Cleanup the script environment.

#>

function cleanupScriptEnv() {
  Remove-Variable -Name SMBEncryptionFeatureName -Scope Script -Force
}

# Enable Action
function EnableClusterSecuritySetting {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string]$SettingName,
    [Parameter()]
    [array]$mountPoints
  )

  switch ($SettingName) {
    "bootVolumeBitlockerEncryption" {
      Enable-ASHostLocalVolumeEncryption
    }
    "sideChannelMitigation" {
      # Enabling these settings requires system reboot for the settings to take effect
      Enable-ASSecurity -FeatureName SideChannelMitigation -Local
    }
    "credentialGuard" {
      # Enabling these settings requires system reboot for the settings to take effect
      Enable-ASSecurity -FeatureName CredentialGuard -Local
    }
    "smbClusterEncryption" {
      Enable-ASSecurity -FeatureName $SMBEncryptionFeatureName -Local
    }
    "smbSigning" {
      Enable-ASSecurity -FeatureName SMBSigning -Local
    }
    "driftControl" {
      Enable-ASSecurity -FeatureName DriftControl -Local
    }
    "dataVolumeBitLocker" {
      $mountPoints | ForEach-Object {
        Enable-ASBitlocker -VolumeType ClusterSharedVolume -Local -MountPoint $_
      }
    }
  }
}


# Disable Action
function DisableClusterSecuritySetting {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string]$SettingName,
    [Parameter()]
    [array]$mountPoints
  )

  switch ($SettingName) {
    "bootVolumeBitlockerEncryption" {
      Disable-ASHostLocalVolumeEncryption
    }
    "sideChannelMitigation" {
      # Disabling these settings requires system reboot for the settings to take effect
      # Applying these settings will put your system at risk to silicon-based microarchitectural
      # and speculative execution side-channel vulnerabilities
      # To run this and bypass the confirmation prompt, add -Confirm:$false
      Disable-ASSecurity -FeatureName SideChannelMitigation -Local -Confirm:$false
    }
    "credentialGuard" {
      # Disabling these settings requires system reboot for the settings to take effect
      Disable-ASSecurity -FeatureName CredentialGuard -Local
    }
    "smbClusterEncryption" {
      Disable-ASSecurity -FeatureName $SMBEncryptionFeatureName -Local
    }
    "smbSigning" {
      Disable-ASSecurity -FeatureName SMBSigning -Local
    }
    "driftControl" {
      # By disabling OSConfig drift control the system will no longer be able to auto-correct
      # any out-of-band security related changes
      # To run this and cmdlet by pass the confirmation prompt use -Confirm:$false
      Disable-ASSecurity -FeatureName DriftControl -Local -Confirm:$false
    }
    "dataVolumeBitLocker" {
      $mountPoints | ForEach-Object {
        Disable-ASBitlocker -VolumeType ClusterSharedVolume -Local -MountPoint $_
      }
    }
  }
}


Add-Type -TypeDefinition @"
   public enum ActionType {
        Disable,
        Enable
    }
"@

function ToggleSecurityFeature {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string]$action,
    [Parameter()]
    [String]$settingName,
    [Parameter()]
    [array]$mountPoints
  )
  if ([ActionType]$action -eq [ActionType]::Enable) {
    EnableClusterSecuritySetting -SettingName $settingName -MountPoints $mountPoints
  }
  elseif ([ActionType]$action -eq [ActionType]::Disable) {
    DisableClusterSecuritySetting -SettingName $settingName -MountPoints $mountPoints
  }
  else {
    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Set-ClusterSecuritySettings.ps1"
    $Message = "Invalid toggle action passed: $action"
    $EntryType = 'Error'

    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource `
      -EventId 0 -Category 0 -EntryType $EntryType `
      -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue
  }
}

$Script:eventId = 0
function Write-SetAszSettingsEventLog {
  param (
    [Parameter(Mandatory = $false)]
    [String]$entryType,
    [Parameter(Mandatory = $true)]
    [String]$message
  )

  if (!$entryType) {
    $entryType = 'Error'
  }

  $LogName = "WindowsAdminCenter"
  $LogSource = "msft.sme.security"
  $ScriptName = "Set-ClusterSecuritySettings.ps1"

  # Create the event log if it does not exists
  New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
    -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

  $Script:eventId += 1
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
  setupScriptEnv

  $bitlockerModuleExists = $null -ne (Get-Command -Module AzureStackBitlockerAgent)
  $osConfigAgentExists = $null -ne (Get-Command -Module AzureStackOSConfigAgent)
  if ($bitlockerModuleExists -and $osConfigAgentExists) {
    ToggleSecurityFeature -Action $action -SettingName $settingName -MountPoints $mountPoints
  }
  else {
    Write-SetAszSettingsEventLog -Message "Couldn't toggle ASZ Security Settings. Modules 'AzureStackBitlockerAgent' and 'AzureStackOSConfigAgent' do not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."
  }

  cleanupScriptEnv
}

}
## [END] Set-WACSEClusterSecuritySettings ##
function Set-WACSEClusterTrafficEncryption {
<#

.SYNOPSIS
Sets cluster traffic encryption

.DESCRIPTION
Sets cluster traffic encryption

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $encryptCoreTraffic,
  [Parameter(Mandatory = $false)]
  [uint32]
  $encryptStorageTraffic
)
Import-Module FailoverClusters
$cluster = Get-Cluster;

$cluster.SecurityLevel = $encryptCoreTraffic

if ($encryptStorageTraffic)
{
  $cluster.SecurityLevelForStorage = $encryptStorageTraffic
}

}
## [END] Set-WACSEClusterTrafficEncryption ##
function Set-WACSERealTimeMonitoringState {
<#

.SYNOPSIS
Set Real Time Monitoring State.

.DESCRIPTION
Set Real Time Monitoring State to On or Off.

.ROLE
Administrators

#>

Param(
    [Int32]$DisableRealtimeMonitoring
)

Set-StrictMode -Version 5.0;

Set-MpPreference -DisableRealtimeMonitoring $DisableRealtimeMonitoring
}
## [END] Set-WACSERealTimeMonitoringState ##
function Set-WACSEScheduledScan {
<#

.SYNOPSIS
Set Date, Time and Type for Recurrent Scan.

.DESCRIPTION
Set Date, Time and Type for Recurrent Scan.

.Parameter ScanParameters
Specifies the scan type to use during a scheduled scan. The acceptable values for this parameter are:
  1: Quick scan
  2: Full scan

.Parameter ScanScheduleDay
Specifies the day of the week on which to perform a scheduled scan.
Alternatively, specify everyday for a scheduled scan or never. The acceptable values for this parameter are:
  0: Everyday
  1: Sunday
  2: Monday
  3: Tuesday
  4: Wednesday
  5: Thursday
  6: Friday
  7: Saturday
  8: Never

.ROLE
Administrators

#>

Param(
    [Int32]$ScanParameters,
    [Int32]$ScanScheduleDay
)

switch ($ScanParameters) {
  1 { $ScanType = 'QuickScan' }
  2 { $ScanType = 'FullScan' }
}

Set-StrictMode -Version 5.0;
Set-MpPreference -ScanParameters $ScanType -ScanScheduleDay $ScanScheduleDay

}
## [END] Set-WACSEScheduledScan ##
function Set-WACSESecuredCoreFeatures {
<#
.SYNOPSIS
Script that enables and disables Secured Core Features

.DESCRIPTION
Script that enables and disables Secured Core Features
  1. You CAN enable configurable code integrity without either HVCI or Cred Guard.
  2. You CAN enable HVCI without either configurable code integrity or Cred Guard.
  3. You CAN enable Cred Guard without either configurable code integrity or HVCI.
  4. You CANNOT enable either Cred Guard or HVCI without Virtualization Based Security.

.Parameter selectedFeatures
All selected features to toggle on/off.

.Parameter action
Value to set to either enable (1) or disable (0) feature

.Parameter secureBoot
Set RequirePlatformSecurityFeatures to 1 (Secure Boot only) or 3 (Secure Boot and DMA protection)

.Parameter featureDetails
An list of object containing the details (e.g. status) of the secured core features

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [PSCustomObject[]]$selectedFeatures,
  [Parameter(Mandatory = $true)]
  [String]$action,
  [Parameter(Mandatory = $false)]
  [String]$secureBoot,
  [Parameter(Mandatory = $false)]
  [PSCustomObject[]]$featureDetails
)


$Script:action = [int]$action
if (-not($Script:action -in @(0, 1))) {
  Throw "Invalid value for parameter $Script:action. Use 0 to disable or 1 to enable a secured core feature"
}
$Script:actionWord = if ($Script:action -eq 0 ) { 'disable' } else { 'enable' };


$Script:secureBoot = [int]$secureBoot
if (-not($Script:secureBoot -in @(0, 1, 3))) {
  Throw "Invalid value for parameter $Script:secureBoot. Use 0 (Disable RequirePlatformSecurityFeatures), 1 (Secure Boot only) or 3 (Secure Boot and DMA protection)"
}

$Script:selectedFeatures = $selectedFeatures
$Script:featureDetails = $featureDetails

<##
  https://social.technet.microsoft.com/wiki/contents/articles/36183.windows-server-2016-device-guard-faq.aspx#:~:text=Credential%20Guard%20%3D%20a%20credential%20protection%20feature%20that,user%20credentials%20from%20being%20accessible%20from%20the%20OS
  1. You CAN enable configurable code integrity without either HVCI or Cred Guard.
  2. You CAN enable HVCI without either configurable code integrity or Cred Guard.
  3. You CAN enable Cred Guard without either configurable code integrity or HVCI.
  4. You CANNOT enable either Cred Guard or HVCI without Virtualization Based Security.
#>


<#
  Check if the script is being run remotely. This check is necessary because
  when UEFI lock is set, it should not be possible to toggle secured core features
 #>
function checkRemote {
  if ($PSSenderInfo -or (Get-Host).Name -eq 'ServerRemoteHost') {
    return $true
  }
  return $false
}
$Script:isRemoteConnection = checkRemote

function getFeatureStatuses($featureName) {
  foreach ($feature in $Script:featureDetails) {
    if ($feature.securityFeature -like $featureName) {
      return ($feature.configured -or $feature.status)
    }
  }
  return
}

function ExecuteCommandAndLog($_cmd) {
  try {
    Invoke-Expression $_cmd | Out-String
  }
  catch {
    Write-Host "Exception while exectuing $_cmd"
    Throw $_.Exception.Message
  }
}

# Check if is Virtual Machine
function checkIsVM {
  $model = (Get-WmiObject win32_computersystem).model
  $model = $model.ToString().ToUpperInvariant()
  return $model.Contains("VM") -or $model.Contains("VIRTUAL")
}
$Script:isVirtualMachine = checkIsVM

# TODO: Do we need to check for prerequisites

<# NOTE: System Guard is NOT supported for virtual machines #>
function toggleSystemGuard() {
  if ($Script:isVirtualMachine) {
    Write-Error "System Guard is not supported for Virtual Machines"
    return;
  }

  $systemGuardStatus = getFeatureStatuses('systemGuard')
  if ($systemGuardStatus -ne $null -and
    (
      ($Script:action -eq 0 -and !$systemGuardStatus) -or
      ($Script:action -eq 1 -and $systemGuardStatus)
    )) {
    return
  }

  $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
  if (-Not(Test-Path $path)) {
    New-Item $path -Force
  }
  Set-ItemProperty -path $path -name "Enabled" -value $Script:action -Type "DWORD" -Force
  return $path
}

function toggleVBS() {
  $vbsStatus = getFeatureStatuses('vbs')
  if (
    $vbsStatus -ne $null -and
    (
      ($Script:action -eq 0 -and !$vbsStatus) -or
      ($Script:action -eq 1 -and $vbsStatus)
    )) {
    return
  }

  $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard"
  if (-Not(Test-Path $path)) {
    New-Item $path -Force
  }

  # For Windows 10 version 1607 and later
  $uefiLock = Get-ItemProperty -Path $path | `
    Microsoft.PowerShell.Utility\Select-Object "Locked" -ExpandProperty "Locked" -ErrorAction SilentlyContinue

  # Check UEFI lock for Windows 10 version 1511 and earlier
  $uefiUnlock = Get-ItemProperty -Path $path | `
    Microsoft.PowerShell.Utility\Select-Object "Unocked" -ExpandProperty "Unocked" -ErrorAction SilentlyContinue

  if (($uefiLock -eq 1 -or $uefiUnlock -eq 0) -and $Script:isRemoteConnection) {
    Throw "UEFI lock enabled. Cannot $Script:actionWord VBS remotely."
  }

  $currentSecureBootValue = Get-ItemProperty -Path $path | `
    Microsoft.PowerShell.Utility\Select-Object "RequirePlatformSecurityFeatures" -ExpandProperty "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue

  if ($Script:action -eq 0) {
    # Note: all other VBS features (HVCI, Cred Guard) need to be disabled as well, or VBS will automatically turn on
    toggleHVCI($Script:action)
    toggleCredentialGuard($Script:action)

    Set-ItemProperty -path $path -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type "DWORD" -Force

    # Disable secure boot
    if ($currentSecureBootValue) {
      Remove-ItemProperty -Path $path -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
    }
  }

  if ($Script:action -eq 1) {
    Set-ItemProperty -path $path -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type "DWORD" -Force

    # Enable Secure Boot
    if ($Script:secureBoot -in @(1, 3)) {
      <#
        - 1: Secure Boot only
        - 3: Secure Boot and DMA protection.
      #>
      Set-ItemProperty -path $path -name "RequirePlatformSecurityFeatures" -value $Script:secureBoot -Type "DWORD" -Force
    }
  }

  return $path
}


function toggleHVCI () {
  # https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#how-to-turn-off-hvci

  $hvciStatus = getFeatureStatuses('hvci')
  if (
    $hvciStatus -ne $null -and
    (
      ($Script:action -eq 0 -and !$hvciStatus) -or
      ($Script:action -eq 1 -and $hvciStatus)
    )) {
    return
  }

  $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
  if (-Not(Test-Path $path)) {
    New-Item $path -Force
  }

  $uefiLock = Get-ItemProperty -Path $path | `
    Microsoft.PowerShell.Utility\Select-Object "Locked" -ExpandProperty "Locked" -ErrorAction SilentlyContinue

  if ($uefiLock -eq 1 -and $Script:isRemoteConnection) {
    Throw "UEFI lock enabled. Cannot $Script:actionWord HVCI remotely."
  }

  if ($Script:action -eq 0) {
    Remove-ItemProperty -Path $path -Name "WasEnabledBy" -ErrorAction SilentlyContinue
  }

  if ($Script:action -eq 1) {
    # Note: VBS will automatically turn on if you enable a VBS feature (HVCI, Cred Guard)
    toggleVBS(1)
    Set-ItemProperty -path $path -name "WasEnabledBy" -value 0 -Type "DWORD" -Force
  }

  # Toggle HVCI
  Set-ItemProperty -path $path -name "Enabled" -value $Script:action -Type "DWORD" -Force

  return $path
}

function toggleCredentialGuard() {
  <## TODO: To be used for credential guard Phase 3
  $credentialGuardStatus = getFeatureStatuses('credentialGuard')
  if (
    $credentialGuardStatus -ne $null -and
    (
      ($Script:action -eq 0 -and !$credentialGuardStatus) -or ($Script:action -eq 1 -and $credentialGuardStatus)
    )) {
    return
  } #>

  # HACK: Phase 2. Credential guard is not returned in the features object
  $securityServicesConfigured = (Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesConfigured
  if ( $securityServicesConfigured.Length -gt 0 -and
    ( $Script:action -eq 0 -and (-not(1 -in $securityServicesConfigured))) -or
    ($Script:action -eq 1 -and (1 -in $securityServicesConfigured))) {
    return;
  }

  $path = "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA"
  if (-Not(Test-Path $path)) {
    New-Item $path -Force
  }

  <#
    0: (Disabled) Turns off Windows Defender Credential Guard remotely if configured previously without UEFI Lock
    1: (Enabled with UEFI lock) Turns on Windows Defender Credential Guard with UEFI lock
    2: (Enabled without lock) Turns on Windows Defender Credential Guard without UEFI lock
  #>
  $credGuardValue = Get-ItemProperty -Path $path | `
    Microsoft.PowerShell.Utility\Select-Object "LsaCfgFlags" -ExpandProperty "LsaCfgFlags" -ErrorAction SilentlyContinue

  if ($credGuardValue -eq 1 -and $Script:isRemoteConnection) {
    Throw "UEFI lock enabled. Cannot $Script:actionWord Credential Guard remotely."
  }

  if ($Script:action -eq 0) {
    Remove-ItemProperty -path $path -name "LsaCfgFlags" -ErrorAction SilentlyContinue -Force

    # This setting is persisted in EFI (firmware) variables so we need to delete it
    $settingPath = "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard
    "
    Remove-ItemProperty -Path $settingPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

    # Set of commands to run SecConfig.efi to delete UEFI variables if were set in pre OS
    $FreeDrive = Get-ChildItem function:[s-z]: -Name | Where-Object { !(Test-Path $_) } | Get-random
    ExecuteCommandAndLog 'mountvol $FreeDrive /s'
    Copy-Item "$env:windir\System32\SecConfig.efi" $FreeDrive\EFI\Microsoft\Boot\SecConfig.efi -Force | Out-String
    ExecuteCommandAndLog 'bcdedit /create "{0cb3b571-2f2e-4343-a879-d86a476d7215}" /d DGOptOut /application osloader'
    ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" path \EFI\Microsoft\Boot\SecConfig.efi'
    ExecuteCommandAndLog 'bcdedit /set "{bootmgr}" bootsequence "{0cb3b571-2f2e-4343-a879-d86a476d7215}"'
    ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" loadoptions DISABLE-LSA-ISO,DISABLE-VBS'
    ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" device partition=$FreeDrive'
    ExecuteCommandAndLog 'mountvol $FreeDrive /d'
  }
  else {
    toggleVBS(1)
    Set-ItemProperty -path $path -name "LsaCfgFlags" -value 1 -Type "DWORD" -Force
  }

  return $path
}


###############################################################################
# Script execution starts here
###############################################################################

foreach ($selectedFeat in $Script:selectedFeatures) {
  if ($selectedFeat.securityFeature -eq 'vbs') {
    toggleVBS
  }
  elseif ($selectedFeat.securityFeature -eq 'hvci') {
    toggleHVCI
  }
  elseif ($selectedFeat.securityFeature -eq 'credentialGuard') {
    toggleCredentialGuard
  }
  elseif ($selectedFeat.securityFeature -eq 'systemGuard') {
    toggleSystemGuard
  }
  else {
    $errorMessage = 'Allowed feature values (case-sensitive): vbs, hvci, systemGuard, and credentialGuard'
    Throw $errorMessage
  }
}

}
## [END] Set-WACSESecuredCoreFeatures ##
function Set-WACSESecuredCoreOsConfigFeatures {
<#
.SYNOPSIS
Script that enables and disables Secured Core Features

.DESCRIPTION
Script that enables and disables Secured Core Features
  1. You CAN enable configurable code integrity without either HVCI or Cred Guard.
  2. You CAN enable HVCI without either configurable code integrity or Cred Guard.
  3. You CAN enable Cred Guard without either configurable code integrity or HVCI.
  4. You CANNOT enable either Cred Guard or HVCI without Virtualization Based Security.

.Parameter selectedFeatures
All selected features to toggle on/off.

.Parameter action
Value to set to either enable (1) or disable (0) feature

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [PSCustomObject[]]$selectedFeatures,
  [Parameter(Mandatory = $true)]
  [String]$action
)

$Script:selectedFeatures = $selectedFeatures

$Script:failedState = @{failureState = @{}}
# Check status of selected features after set calls and capture error on failure
function CheckStatus {
  Param([Parameter(Mandatory = $true)] $Status)

  foreach ($featStatus in $Status) {
    if ($Script:SecuredCoreConfigurations.ContainsKey($featStatus.name) -and $featStatus.state -eq "failed") {
      $errState = $featStatus.state
      $errCode = $featStatus.ErrorCode
      $errorMsg = "State: $errState, Error: $errCode"
      $Script:failedState.failureState.Add($featStatus.name, $errorMsg)
    }
  }

  return $Script:failedState
}


# Set OsConfiguration document to get current configuration values
function OsConfigurationSetDocumentGetResult {

  [CmdletBinding()]
  Param (
    [Parameter(Mandatory)]
    [String] $Id,

    [Parameter(Mandatory)]
    [String] $Content
  )

  # Set the document to get securedcore settings
  #Set-OsConfigurationDocument -Content $Content -Wait -TimeoutInSeconds 300
  Set-OsConfigurationDocument -Content $Content -Wait

  $result = Get-OsConfigurationDocumentResult -Id $Id | ConvertFrom-Json

  return $result.OsConfiguration.Scenario[0]
}

$jsonDocumentToGetSecuredCoreSettingConfigurations =
@"
{
  "OsConfiguration":{
      "Document":{
        "schemaversion":"1.0",
        "id":"47e88660-1861-4131-96e8-f32e85011e55",
        "version":"3C356C2C71F6A41F9AB4A601AD00C8B5BC7531576233010B13A221A9FE1BE7A0",
        "context":"device",
        "scenario":"SecuredCore"
      },
      "Scenario":[
        {
            "name":"SecuredCore",
            "schemaversion":"1.0",
            "action":"get",
            "SecuredCore":{
              "EnableVirtualizationBasedSecurity": "0",
              "HypervisorEnforcedCodeIntegrity": "0",
              "ConfigureSystemGuardLaunch": "0"
            }
        }
      ]
  }
}
"@

function GetSecuredCoreSettingConfigurations {

  # Set the document to get securedcore settings
  $result = OsConfigurationSetDocumentGetResult -Id "47e88660-1861-4131-96e8-f32e85011e55" -Content $jsonDocumentToGetSecuredCoreSettingConfigurations

  return $result.SecuredCore
}

$jsonDocumentToSetSecuredCoreSettingConfigurationsTemplate =
@"
{
  "OsConfiguration":{
      "Document":{
        "schemaversion":"1.0",
        "id":"74e88660-1861-4131-96e8-f32e85011e55",
        "version":"C8B5BC7531576233010B13A221A9FE1BE7A03C356C2C71F6A41F9AB4A601AD00",
        "context":"device",
        "scenario":"SecuredCore"
      },
      "Scenario":[
        {
            "name":"SecuredCore",
            "schemaversion":"1.0",
            "action":"set",
            "SecuredCore":{
              "EnableVirtualizationBasedSecurity": "1",
              "HypervisorEnforcedCodeIntegrity": "2",
              "ConfigureSystemGuardLaunch": "1"
            }
        }
      ]
  }
}
"@

# Set the configurations based on $Script:SecuredCoreConfigurations
function SetSecuredCoreSettingsUsingOsConfiguration() {

  # Get current configuration values
  $SecuredCoreConfigurations = GetSecuredCoreSettingConfigurations

  # Toggle the settings
  $jsonDocumentObject = $jsonDocumentToSetSecuredCoreSettingConfigurationsTemplate | ConvertFrom-Json

  if ($Script:SecuredCoreConfigurations.ContainsKey("EnableVirtualizationBasedSecurity"))
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.EnableVirtualizationBasedSecurity = $Script:SecuredCoreConfigurations.EnableVirtualizationBasedSecurity
  }
  else
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.EnableVirtualizationBasedSecurity = $SecuredCoreConfigurations.EnableVirtualizationBasedSecurity
  }

  if ($Script:SecuredCoreConfigurations.ContainsKey("HypervisorEnforcedCodeIntegrity"))
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.HypervisorEnforcedCodeIntegrity = $Script:SecuredCoreConfigurations.HypervisorEnforcedCodeIntegrity
  }
  else
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.HypervisorEnforcedCodeIntegrity = $SecuredCoreConfigurations.HypervisorEnforcedCodeIntegrity
  }

  if ($Script:SecuredCoreConfigurations.ContainsKey("ConfigureSystemGuardLaunch"))
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.ConfigureSystemGuardLaunch = $Script:SecuredCoreConfigurations.ConfigureSystemGuardLaunch
  }
  else
  {
    $jsonDocumentObject.OsConfiguration.Scenario[0].SecuredCore.ConfigureSystemGuardLaunch = $SecuredCoreConfigurations.ConfigureSystemGuardLaunch
  }

  $jsonDocumentToSetSecuredCoreSettings = ConvertTo-Json -InputObject $jsonDocumentObject -Depth 5

  # Set the document to get securedcore settings
  #Set-OsConfigurationDocument -Content $jsonDocumentToSetSecuredCoreSettings -Wait -TimeoutInSeconds 300
  Set-OsConfigurationDocument -Content $jsonDocumentToSetSecuredCoreSettings -Wait

  # Return false on timeout.
  $documentState = Get-OsConfigurationDocument -Id "74e88660-1861-4131-96e8-f32e85011e55" | Microsoft.PowerShell.Utility\Select-Object "State"
  if ("DocumentStateCompleted" -ne $documentState.state) {
    return $null
  }

  $result = Get-OsConfigurationDocumentResult -Id "74e88660-1861-4131-96e8-f32e85011e55" | ConvertFrom-Json

  return CheckStatus $result.OsConfiguration.Scenario[0].Status
}

$Script:SecuredCoreConfigurations = @{}

function ToggleSecuredCoreSettingConfiguration() {
  foreach ($selectedFeat in $Script:selectedFeatures) {
    if ($selectedFeat.securityFeature -eq 'vbs') {
      $Script:SecuredCoreConfigurations.Add("EnableVirtualizationBasedSecurity", $action)
    }
    elseif ($selectedFeat.securityFeature -eq 'hvci') {
      if ($action -eq "1") {
        $Script:SecuredCoreConfigurations.Add("HypervisorEnforcedCodeIntegrity", "2")
      }
      else {
        $Script:SecuredCoreConfigurations.Add("HypervisorEnforcedCodeIntegrity", "0")
      }
    }
    elseif ($selectedFeat.securityFeature -eq 'credentialGuard') {
      $Script:SecuredCoreConfigurations.Add("ConfigureCredentialGuard", $action)
    }
    elseif ($selectedFeat.securityFeature -eq 'systemGuard') {
      if ($action -eq "1") {
        $Script:SecuredCoreConfigurations.Add("ConfigureSystemGuardLaunch", "1")
      }
      else {
        $Script:SecuredCoreConfigurations.Add("ConfigureSystemGuardLaunch", "2")
      }
    }
    else {
      $errorMessage = 'Allowed feature values (case-sensitive): vbs, hvci, systemGuard, and credentialGuard'
      Throw $errorMessage
    }
  }
  $Script:SecuredCoreConfigurations
}

$Script:SecuredCoreConfigurations
ToggleSecuredCoreSettingConfiguration
$Script:SecuredCoreConfigurations
SetSecuredCoreSettingsUsingOsConfiguration

}
## [END] Set-WACSESecuredCoreOsConfigFeatures ##
function Set-WACSESecurityConfigurations {
<#
.SYNOPSIS
Sets the security configurations for the specified scenario to make it compliant.

.DESCRIPTION
Sets the security configurations for the specified scenario to make it compliant.

NOTE: This will attempt to make everything in the scenario compliant except settings
which do not have a default value, unless the "Setting" parameter is specified which in
that case it only sets those to their default (compliant value).

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]$Scenario,
    [Parameter(Mandatory = $false)]
    [String[]]$Setting
)

# If any setting is specified, only set those configuration
if ($Setting -and $Setting.Count -gt 0) {
    Set-OSConfigDesiredConfiguration -Scenario $Scenario -Setting $Setting -Default -Force
} else {
    # Try to set all configurations to default, compliant value
    Set-OSConfigDesiredConfiguration -Scenario $Scenario -Default -Force
}

}
## [END] Set-WACSESecurityConfigurations ##
function Set-WACSEThreatAction {
<#

.SYNOPSIS
Set Given Threat Default Action to Given Threat.

.DESCRIPTION
Set Given Threat Default Action to Given Threat.

.ROLE
Administrators

#>

Param(
    [string]$chosenAction,
    [string]$threatID
)

Set-StrictMode -Version 5.0;

$threatID = [int64]$threatID

Set-MpPreference -ThreatIDDefaultAction_Ids $threatID -ThreatIDDefaultAction_Actions $chosenAction
}
## [END] Set-WACSEThreatAction ##
function Set-WACSEWdacPolicyMode {
<#
.SYNOPSIS
Set Windows Defender Application Control (WDAC) Policy setting

.DESCRIPTION
Set Windows Defender Application Control (WDAC) Policy mode to Audit(1) or Enforced(2)

.Parameter mode
Policy mode to set to either: Audit (1) or Enforcement (2)

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]$mode
)

Add-Type -TypeDefinition @"
   public enum PolicyMode {
        Audit = 1,
        Enforced = 2
    }
"@

function ToggleWdacPolicyMode {
  [CmdletBinding()]
  param (
    [Parameter()]
    [string]$mode
  )

  if ([PolicyMode]$mode -eq [PolicyMode]::Audit) {
    Enable-ASLocalWDACPolicy -Mode Audit
  }
  elseif ([PolicyMode]$mode -eq [PolicyMode]::Enforced) {
    Enable-ASLocalWDACPolicy -Mode Enforced
  }
  else {
    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Set-WDACPolicyMode.ps1"
    $Message = "Invalid WDAC policy mode passed: $mode"
    $EntryType = 'Error'

    # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource `
      -EventId 0 -Category 0 -EntryType $EntryType `
      -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue
  }
}

$Script:eventId = 0
function Write-SetWdacEventLog {
  param (
    [Parameter(Mandatory = $false)]
    [String]$entryType,
    [Parameter(Mandatory = $true)]
    [String]$message
  )

  if (!$entryType) {
    $entryType = 'Error'
  }

  $LogName = "WindowsAdminCenter"
  $LogSource = "msft.sme.security"
  $ScriptName = "Set-WdacPolicyMode.ps1"

  # Create the event log if it does not exists
  New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
    -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

  $Script:eventId += 1
}


###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
  $wdacModuleExists = $null -ne (Get-Command -Module Microsoft.AS.Infra.Security.WDAC)
  if ($wdacModuleExists) {
    ToggleWdacPolicyMode -Mode $mode
  } else {
    Write-SetWdacEventLog -Message "Couldn't toggle WDAC policy mode. Module 'Microsoft.AS.Infra.Security.WDAC' does not exist on this server. Ensure that you are running the latest version of Azure Stack HCI."
  }
}

}
## [END] Set-WACSEWdacPolicyMode ##
function Start-WACSEMpScan {
<#

.SYNOPSIS
Start Scan.

.DESCRIPTION
Start Scan.

.Parameter ScanType
Specifies the scan type to use during a scheduled scan. The acceptable values for this parameter are:
  FullScan
  QuickScan

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $true)]
  [string]$ScanType
)

Set-StrictMode -Version 5.0;

switch ($ScanType) {
  1 { $ScanTypeValue = 'QuickScan' }
  2 { $ScanTypeValue = 'FullScan' }
}

Start-MpScan -ScanType $ScanTypeValue

}
## [END] Start-WACSEMpScan ##
function Test-WACSEOsConfigModule {
<#

.SYNOPSIS
Test-OSConfigModule

.DESCRIPTION
Checks if OSConfiguration Module is present

.ROLE
Readers

#>

$Script:eventId = 0
function Write-OsConfigEventToEventLog {
  param (
    [Parameter(Mandatory = $false)]
    [String]$entryType,
    [Parameter(Mandatory = $true)]
    [String]$message
  )

  if (!$entryType) {
    $entryType = 'Warning'
  }

  $LogName = "WindowsAdminCenter"
  $LogSource = "msft.sme.security"
  $ScriptName = "Test-OsConfigModule.ps1"

  # Create the event log if it does not exists
  New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

  # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
  Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
    -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

  $Script:eventId += 1
}

$jsonDocumentToGetSecuredCoreSettingStates =
@"
{
  "OsConfiguration":{
      "Document":{
        "schemaversion":"1.0",
        "id":"10088660-1861-4131-96e8-f32e85011100",
        "version":"10056C2C71F6A41F9AB4A601AD00C8B5BC7531576233010B13A221A9FE1BE100",
        "context":"device",
        "scenario":"SecuredCoreState"
      },
      "Scenario":[
        {
            "name":"SecuredCoreState",
            "schemaversion":"1.0",
            "action":"get",
            "SecuredCoreState":{
              "VirtualizationBasedSecurityStatus": "0",
              "HypervisorEnforcedCodeIntegrityStatus": "0",
              "SystemGuardStatus": "0",
              "SecureBootState": "0",
              "TPMVersion": "",
              "BootDMAProtection": "0"
            }
        }
      ]
  }
}
"@

function Test-OsConfigFeatureEnabled {
  ########## 13-Spetember-2022 ##########
  ### 1. Should WAC be enabling OSConfig if it's not enabled so that these security
  # settings can be read through WAC? - OsConfig is designed to be released only to
  # ASZ HCI (for now), but because WSD does not support velocity based composition,
  # its binaries are released to every server edition as part of 7C/8C update/KB. The
  # feature itself is guarded/blocked by WSD EKB. EKB is designed and can only be
  # enabled on ASZ HCI. It leaves the "weird" situation, OsConfig is released/present
  # in server edition (FE server 2022) but not enabled (cannot be enabled for server
  # edition except ASZ HCI.
  ### 2. Then how can we improve validation such that an OS update doesn't break
  # OSConfig using WAC? This last update broke every single WAC customer out there
  # using WAC to manage their HCI cluster - We should validate that these OS updates
  # don't break existing WAC functionality. However, it is one exception (which is also surprised to us)
  # we have to handle, we do not expect to have another one in future.
  Import-Module -Name OsConfiguration -ErrorAction SilentlyContinue -ErrorVariable err

  if (!!$err) {
    Write-OsConfigEventToEventLog -Message "There was an error importing the OsConfiguration module. Error: $err"
    return $false
  }

  try {
    Set-OsConfigurationDocument -Content $jsonDocumentToGetSecuredCoreSettingStates -Wait
  }
  catch {
    Write-OsConfigEventToEventLog -Message "There was an error setting the OS configuration document. Error: $err"
    return $false
  }

  return $true
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
  Test-OsConfigFeatureEnabled
}

}
## [END] Test-WACSEOsConfigModule ##
function Test-WACSEWdacPolicyFilePath {
<#
.SYNOPSIS
    Test if a filepath belongs to a cluster shared volume
.DESCRIPTION
    Test if a filepath belongs to a cluster shared volume
.ROLE
    Administrators
#>

param (
    [Parameter(Mandatory = $true)]
    [String]$filePath
)

enum ValidationErrorType {
    FileDoesNotExist
    NoClusterVolume
    FileNotOnClusterVolume
}

$ErrorActionPreference = "Stop"

$Script:eventId = 0
function Write-WdacEventLog {
    param (
        [Parameter(Mandatory = $false)]
        [String]$EntryType,
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    if (!$entryType) {
        $entryType = 'Error'
    }

    $LogName = "WindowsAdminCenter"
    $LogSource = "msft.sme.security"
    $ScriptName = "Test-WdacPolicyFilePath.ps1"

    # Create the event log if it does not exists
    New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    # EntryType: Error, Information, FailureAudit, SuccessAudit, Warning
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId $Script:eventId -Category 0 -EntryType $EntryType `
        -Message "[$ScriptName]: $Message" -ErrorAction SilentlyContinue

    $Script:eventId += 1
}

function Test-WdacPolicyFilePath {
    param (
        [Parameter(Mandatory = $true)]
        [String]$filePath
    )

    $policyPath = [IO.Path]::GetFullPath($filePath)
    if (-not (Test-Path -Path $policyPath -PathType Leaf)) {
        $errorMessage = "The policy file path does not exist."
        Write-WdacEventLog -message $errorMessage
        return @{ result = $false; error = [ValidationErrorType]::FileDoesNotExist }
    }

    $clusterName = (Get-Cluster).name
    $clusterSharedVolumes = Get-ClusterSharedVolume -Cluster $clusterName

    if ($clusterSharedVolumes.Count -eq 0) {
        $errorMessage = "No cluster shared volumes were found."
        Write-WdacEventLog -message $errorMessage
        return @{ result = $false; error = [ValidationErrorType]::NoClusterVolume }
    }

    $matchFound = $false
    foreach ($volume in $clusterSharedVolumes) {
        $volumePath = [IO.Path]::GetFullPath($volume.SharedVolumeInfo.FriendlyVolumeName)
        if ($policyPath.StartsWith( $volumePath, [StringComparison]::OrdinalIgnoreCase )) {
            $matchFound = $true
            break
        }
    }

    if (-not $matchFound) {
        $errorMessage = "The policy file must be on a cluster shared volume."
        Write-WdacEventLog -message $errorMessage
        return @{ result = $false; error = [ValidationErrorType]::FileNotOnClusterVolume }
    }

    return @{ result = $true; error = $null }
}

###############################################################################
# Script execution starts here
###############################################################################
if (-not ($env:pester)) {
    Test-WdacPolicyFilePath -filePath $filePath
}

}
## [END] Test-WACSEWdacPolicyFilePath ##
function Update-WACSEMicrosoftOsConfigModule {
<#
.SYNOPSIS
Updates the Microsoft.OSConfig module.

.DESCRIPTION
Updates the Microsoft.OSConfig module.

.ROLE
Administrators

#>

$osConfigModule = "Microsoft.OSConfig"

# Find the installed version of the module that is imported in the current session
$installedModule = Get-InstalledModule -Name $osConfigModule -ErrorAction silentlycontinue

# Find the latest available version of the module
$latestModule = Find-Module -Name $osConfigModule -Repository PSGallery -ErrorAction silentlycontinue

# Check if an update is available
if ($installedModule -and $latestModule -and ($latestModule.Version -gt $installedModule.Version)) {
    # Update the module
    Uninstall-Module -Name $osConfigModule -AllVersions -Force
    Install-Module -Name $osConfigModule -Scope AllUsers -Repository PSGallery -Force
    return $true
} else {
    # No update performed
    return $false
}

}
## [END] Update-WACSEMicrosoftOsConfigModule ##

# SIG # Begin signature block
# MIIoUgYJKoZIhvcNAQcCoIIoQzCCKD8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZtlPT9AMWdWvO
# 6ViSJ/og2etjKPG0gvU/EGsZkvvINKCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP50
# 4Ln/lK4ZLN6EnejTGEECJ9oEX1mzi3ZsOruBHu/yMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAuQcvZuIDql/W+eVekyayymQ1DNL/qQszaZ0F
# zV7xT4SR+7FC0BE8AH7i/JHWh6dHNQSpi4/7nboA6t9Fv+7xFr2MjAQst/yAPTQG
# BsZH0hEJXtLaN9O+E+gS+tJZeOzGsgBug6zoQ+X6CCqh0Z32MJy5bDh94U8NenPZ
# 4fwvcJcOAwNx0sDUk4mJTgSj4uXKAZwMOYJfKe29TN3B02TFDYzX5msbiTgArpRX
# Fk/NrSZ1CoTqGLxQ/RNdGKpDTTZt7hdr5BY4klO16dR/l3uU+2NLR7VWg3xmUNA3
# GjCrZ/jliwNJXleqistmF88l4brQFmMofeMsZihRTB6IB3SJP6GCF60wghepBgor
# BgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCCF4YwgheCAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCjjNWmozfoSjgYOe8B9eeHKVSkEQ+ljypJ
# PPnWJqvETgIGaQH+PrAtGBMyMDI1MTExMDE3MTgxNi40MThaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjo2QjA1LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggcoMIIFEKADAgECAhMzAAACEUUY
# OZtDz/xsAAEAAAIRMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgxM1oXDTI2MTExMzE4NDgxM1owgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjZCMDUtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# z7m7MxAdL5Vayrk7jsMo3GnhN85ktHCZEvEcj4BIccHKd/NKC7uPvpX5dhO63W6V
# M5iCxklG8qQeVVrPaKvj8dYYJC7DNt4NN3XlVdC/voveJuPPhTJ/u7X+pYmV2qeh
# TVPOOB1/hpmt51SzgxZczMdnFl+X2e1PgutSA5CAh9/Xz5NW0CxnYVz8g0Vpxg+B
# q32amktRXr8m3BSEgUs8jgWRPVzPHEczpbhloGGEfHaROmHhVKIqN+JhMweEjU2N
# XM2W6hm32j/QH/I/KWqNNfYchHaG0xJljVTYoUKPpcQDuhH9dQKEgvGxj2U5/3Fq
# 1em4dO6Ih04m6R+ttxr6Y8oRJH9ZhZ3sciFBIvZh7E2YFXOjP4MGybSylQTPDEFA
# tHHgpkskeEUhsPDR9VvWWhekhQx3qXaAKh+AkLmz/hpE3e0y+RIKO2AREjULJAKg
# f+R9QnNvqMeMkz9PGrjsijqWGzB2k2JNyaUYKlbmQweOabsCioiY2fJbimjVyFAG
# k5AeYddUFxvJGgRVCH7BeBPKAq7MMOmSCTOMZ0Sw6zyNx4Uhh5Y0uJ0ZOoTKnB3K
# fdN/ba/eKHFeEhi3WqAfzTxiy0rMvhsfsXZK7zoclqaRvVl8Q48J174+eyriypY9
# HhU+ohgiYi4uQGDDVdTDeKDtoC/hD2Cn+ARzwE1rFfECAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBRifUUDwOnqIcvfb53+yV0EZn7OcDAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEApEKdnMeIIUiU6PatZ/qbrwiDzYUMKRczC4Bp/XY1S9NmHI+2c3dcpwH2
# SOmDfdvIIqt7mRrgvBPYOvJ9CtZS5eeIrsObC0b0ggKTv2wrTgWG+qktqNFEhQei
# pdURNLN68uHAm5edwBytd1kwy5r6B93klxDsldOmVWtw/ngj7knN09muCmwr17Jn
# sMFcoIN/H59s+1RYN7Vid4+7nj8FcvYy9rbZOMndBzsTiosF1M+aMIJX2k3EVFVs
# uDL7/R5ppI9Tg7eWQOWKMZHPdsA3ZqWzDuhJqTzoFSQShnZenC+xq/z9BhHPFFbU
# tfjAoG6EDPjSQJYXmogja8OEa19xwnh3wVufeP+ck+/0gxNi7g+kO6WaOm052F4s
# iD8xi6Uv75L7798lHvPThcxHHsgXqMY592d1wUof3tL/eDaQ0UhnYCU8yGkU2XJn
# ctONnBKAvURAvf2qiIWDj4Lpcm0zA7VuofuJR1Tpuyc5p1ja52bNZBBVqAOwyDhA
# mqWsJXAjYXnssC/fJkee314Fh+GIyMgvAPRScgqRZqV16dTBYvoe+w1n/wWs/yST
# UsxDw4T/AITcu5PAsLnCVpArDrFLRTFyut+eHUoG6UYZfj8/RsuQ42INse1pb/cP
# m7G2lcLJtkIKT80xvB1LiaNvPTBVEcmNSvFUM0xrXZXcYcxVXiYwggdxMIIFWaAD
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
# Hm5TaGllbGQgVFNTIEVTTjo2QjA1LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAKyp8q2VdgAq1
# VGkzd7PZwV6zNc2ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy8TeMwIhgPMjAyNTExMTAxMTQxMjNaGA8yMDI1
# MTExMTExNDEyM1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7LxN4wIBADAHAgEA
# AgIAjTAHAgEAAgISlDAKAgUA7L2fYwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQB02xqVve52GVGtHhNoCuFzK6bAUvVEcaaQrChMze5yPkHNUU594OSn9nCw
# F7vzQMNNVG+rZnqy5CpuXjUyGmw+r0ZX1qFrp6vaH9WUmrKPRsG7UJBPleSyLLf5
# XSywV5XkHv9oM9OM2M3YQSYpIHWtt1u6k+z0CDZ109H236MXYxEScbRp9dOmUtaB
# fPsPzDcZ0GZp68vL17RAGX10t23dda1I+U0smTrEDJBcahiZE3yxaD3FgB994QKC
# MU+CwcF/lsf15cByVbzntDElRg2dniW3aKqSvyrQTWvajIziOdg7zjHQYlcQcqoY
# Wm2tl0DL0iHF3WsE44sYKp/ZY88uMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAIRRRg5m0PP/GwAAQAAAhEwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgnUehuFWUHSBq+x3vqLPU+QW0QyYHxYNtyMcWHId8OvQwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCAsrTOpmu+HTq1aXFwvlhjF8p2nUCNNCEX/OWLH
# NDMmtzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAC
# EUUYOZtDz/xsAAEAAAIRMCIEIDaFsum3raEC1LC9oydtYfc2gaOv0QFTTEXiu3oJ
# yiaqMA0GCSqGSIb3DQEBCwUABIICAJa0V037TQwgPw2r9V32c9Y4tw2cwD4mqsTB
# 4EB0i+F0IUONGkwfa9akjW6Dj97yWlYnGY/tVY/VJDx2b5TEU0lEqL9SdcVXRPtw
# S01UpjV4a2VlajpXf5G0juPOPNsGacEqMzIazBJqkzzDM+y2U8AbUNMXREv2RQpK
# h9EgaJLVG9GpZEFrmJOLubtvsTzz8ww7v0gDcwCyrX0LU8sK3YjQRu2xbS95qxVz
# UNn+pSsylYMbzCedlIBZyYDLE0/zUbzhZstTKf7f6qAvPTicaleLNuhx7w0dW/pa
# LESzIVRbp2UnuiuQdT3iwayPmW7LU9u457h2iyHqkG9g+L/7hM4Vpv6r44Sjxh8U
# 86Kni8y0h6QMWKnesxUJXHWOCyD2HzafZe67arfhUh16Xr2cl0ZH2A6ZRIrfqbEE
# zhO7wokRD4qDtPDVcgG+eCtDa7x7E7FalN3a37xtFVRgotU3DZwZxNTd+0SQYXSG
# U5kX+xMqOpeDQpp8YAnQNaxUSmRyeIfwllAFagrWEvQYGjx8f1PLVFH88/RVVg7i
# kT4z4SIgyaMDM0LeumX5s0GupVStaWpH54zYGo4Yp97JlooCGgc/37Qc0hwREAuE
# k8T9TatIVcZbY8DhoNqgtWDDaTX7McvRX98JBAk6zMGTVMEHH8V/edDzCdUM1oVu
# hXmXZiQ1
# SIG # End signature block
