function Disable-WACSIInsightsCapability {
<#

.SYNOPSIS
Deactivates a capability, which stops data collection for that capability and prevents the capability from being invoked.

.DESCRIPTION
Deactivates a capability, which stops data collection for that capability and prevents the capability from being invoked.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
)
Import-Module SystemInsights

Disable-InsightsCapability -Name $name -confirm:$false

}
## [END] Disable-WACSIInsightsCapability ##
function Disable-WACSIInsightsCapabilitySchedule {
<#

.SYNOPSIS
Disables periodic predictions for the specified capabilities.

.DESCRIPTION
Disables periodic predictions for the specified capabilities.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
 )
Import-Module SystemInsights

Disable-InsightsCapabilitySchedule -Name $name -Confirm:$false

}
## [END] Disable-WACSIInsightsCapabilitySchedule ##
function Enable-WACSIInsightsCapability {
<#

.SYNOPSIS
Activates a capability, which starts all data collection for that capability, allows the capability to be invoked, and enables users to set custom configuration information.

.DESCRIPTION
Activates a capability, which starts all data collection for that capability, allows the capability to be invoked, and enables users to set custom configuration information.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
)
Import-Module SystemInsights

Enable-InsightsCapability -Name $name

}
## [END] Enable-WACSIInsightsCapability ##
function Enable-WACSIInsightsCapabilitySchedule {
<#

.SYNOPSIS
Enables periodic predictions for the specified capabilities.

.DESCRIPTION
Enables periodic predictions for the specified capabilities.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
 )
Import-Module SystemInsights

Enable-InsightsCapabilitySchedule -Name $name

}
## [END] Enable-WACSIInsightsCapabilitySchedule ##
function Get-WACSIClusterSettings {
<#

.SYNOPSIS
Gets item property values for clustered storage settings.

.DESCRIPTION
Gets item property values for clustered storage settings.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.ROLE
Readers

#>
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$ClusterNode       = $false
$CollectionEnabled = $null
$TotalStorageState = $null
$VolumeState       = $null

try
{
    Import-Module FailoverClusters -ErrorAction Stop
    # store result in a variable so the script will only output one item in the array
    $cluster = Get-Cluster -Name $env:COMPUTERNAME -WarningAction SilentlyContinue -ErrorAction Stop
    if ($cluster -ne $null) {
      $ClusterNode = $true;
    }
}
catch
{
    $ClusterNode = $false
}

if ($ClusterNode -eq $true)
{
    $systemDataArchiver = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\SystemDataArchiver -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (($systemDataArchiver -ne $null) -and ($systemDataArchiver.ClusterVolumesAndDisks -ne $null))
    {
        $CollectionEnabled = $systemDataArchiver.ClusterVolumesAndDisks -ne 0
    }

    $totalStorage = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemInsights\Capabilities\Total storage consumption forecasting' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (($totalStorage -ne $null) -and ($totalStorage.ClusterVolumesAndDisks -ne $null))
    {
        $TotalStorageState = $totalStorage.ClusterVolumesAndDisks
    }

    $volume = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemInsights\Capabilities\Volume consumption forecasting' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (($volume -ne $null) -and ($volume.ClusterVolumes -ne $null))
    {
        $VolumeState = $volume.ClusterVolumes
    }
}

@{
    ClusterNode       = $ClusterNode;
    CollectionEnabled = $CollectionEnabled;
    TotalStorageState = $TotalStorageState;
    VolumeState       = $VolumeState
} | Write-Output

}
## [END] Get-WACSIClusterSettings ##
function Get-WACSIInsightsCapability {
<#

.SYNOPSIS
Invokes Get-InsightsCapability

.DESCRIPTION
Invokes Get-InsightsCapability
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.ROLE
Readers

#>
Import-Module SystemInsights
Get-InsightsCapability

}
## [END] Get-WACSIInsightsCapability ##
function Get-WACSIInsightsCapabilityAction {
<#

.SYNOPSIS
Invokes Get-InsightsCapabilityAction.

.DESCRIPTION
Invokes Get-InsightsCapabilityAction.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Readers

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
)
Import-Module SystemInsights

Get-InsightsCapabilityAction -Name $name

}
## [END] Get-WACSIInsightsCapabilityAction ##
function Get-WACSIInsightsCapabilityResultCombo {
<#

.SYNOPSIS
Invokes Get-InsightsCapabilityResultCombo.

.DESCRIPTION
Invokes Get-InsightsCapabilityResultCombo.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name

.PARAMETER usesAnomalyFilter

.PARAMETER minutesToSubtract

.PARAMETER hoursToSubtract

.PARAMETER daysToSubtract

.PARAMETER monthsToSubtract

.PARAMETER diskIdentifier

.ROLE
Readers

#>
param (
  [Parameter(Mandatory = $true)]
  [string]$name,

  [Parameter(Mandatory = $true)]
  [boolean]$usesAnomalyFilter,

  [Parameter(Mandatory = $true)]
  [int]$minutesToSubtract,

  [Parameter(Mandatory = $true)]
  [int]$hoursToSubtract,

  [Parameter(Mandatory = $true)]
  [int]$daysToSubtract,

  [Parameter(Mandatory = $true)]
  [int]$monthsToSubtract,

  [string]$diskIdentifier

)
Import-Module SystemInsights, Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility
$resultWithoutHistory = Get-InsightsCapabilityResult -Name $name
$resultWithHistory = Get-InsightsCapabilityResult -Name $name -History

$outputData = $null
$diskList = @()

if ($resultWithHistory) {
  $path = $resultWithoutHistory.output

  $outputData = $null

  if ($null -ne $path -and $path -ne '') {
    $outputData = Get-Content -Path $path -Encoding UTF8 | Microsoft.PowerShell.Utility\ConvertFrom-Json
  }


  if ($usesAnomalyFilter) {
    if ($outputData -and $outputData.AnomalyDetectionResults) {
      # Use += to avoid single disks not returning an array
      $diskList += $outputData.AnomalyDetectionResults | ForEach-Object { $_.Identifier } | Sort-Object | Get-Unique
      if ($diskList.length -gt 0) {
        if (!$diskIdentifier -or !$diskList.contains($diskIdentifier)) {
          $diskIdentifier = ''
          $diskIdentifier = $diskList | Microsoft.PowerShell.Utility\Select-Object -First 1
        }
        foreach ($set in $outputData.AnomalyDetectionResults) {
          if ($set.Identifier) {
            if ($set.Identifier -eq $diskIdentifier) {
              if ($set.Series -and ($set.Series.length -gt 0)) {
                $set.Series = $set.Series | Microsoft.PowerShell.Utility\Sort-Object -Property DateTime
                # We use the last value in the series as the day to filter back from
                $lastDate = $set.Series.DateTime | Microsoft.PowerShell.Utility\Select-Object -Last 1
                if ($lastDate) {
                  $filterDate = $lastDate.AddMinutes(-$minutesToSubtract).AddHours(-$hoursToSubtract).AddDays(-$daysToSubtract).AddMonths(-$monthsToSubtract)
                  $set.Series = $set.Series | Where-Object { $_.DateTime -gt $filterDate }
                }
              }
              else {
                $set.Series = $()
              }
            }
            else {
              $set.Series = $()
            }
          }
        }
      }
    }
  }

  if ($null -ne $outputData) {
    $outputData | Microsoft.PowerShell.Utility\Add-Member -NotePropertyName 'DiskList' -NotePropertyValue $diskList
    $outputData = $outputData | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -Depth 5
  }
}

$scheduleData = Get-InsightsCapabilitySchedule -name $name
$capabilityList = Get-InsightsCapability

$combinedResults = @{ }
$combinedResults += @{"historyResult" = $resultWithHistory }
$combinedResults += @{"capabilityResult" = $resultWithoutHistory }
$combinedResults += @{"outputResult" = $outputData }
$combinedResults += @{"scheduleResult" = $scheduleData }
$combinedResults += @{"capabilityListResult" = $capabilityList }
Write-Output $combinedResults

}
## [END] Get-WACSIInsightsCapabilityResultCombo ##
function Get-WACSIInsightsCapabilitySchedule {
<#

.SYNOPSIS
Invokes Get-InsightsCapabilitySchedule

.DESCRIPTION
Invokes Get-InsightsCapabilitySchedule
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
Specifies a capability using a capability name

.ROLE
Readers

#>
param (
  [Parameter(Mandatory = $true)]
  [string]
  $name
)
Import-Module SystemInsights

Get-InsightsCapabilitySchedule -Name $name

}
## [END] Get-WACSIInsightsCapabilitySchedule ##
function Get-WACSIInsightsFeature {
<#

.SYNOPSIS
Invokes Get-WindowsFeature

.DESCRIPTION
Invokes Get-WindowsFeature
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.ROLE
Readers

#>
Import-Module ServerManager

Get-WindowsFeature -Name 'System-Insights','RSAT-System-Insights', 'System-DataArchiver'

}
## [END] Get-WACSIInsightsFeature ##
function Get-WACSISystemDriveLetter {
<#

.SYNOPSIS
Get system drive

.DESCRIPTION
Get system drive

.ROLE
Readers

#>
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$systemDriveLetter = (Get-WmiObject Win32_OperatingSystem).SystemDrive

Write-Output $systemDriveLetter

}
## [END] Get-WACSISystemDriveLetter ##
function Get-WACSITempPath {
<#

.SYNOPSIS
Returns the path of the current user's temporary folder.

.DESCRIPTION
Returns the path of the current user's temporary folder.

.ROLE
Readers

#>
Import-Module Microsoft.PowerShell.Utility

$newTempFile = [System.IO.Path]::GetTempPath() | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5

Write-Output $newTempFile

}
## [END] Get-WACSITempPath ##
function Install-WACSIInsightsFeature {
<#

.SYNOPSIS
Invokes Install-WindowsFeature.

.DESCRIPTION
Invokes Install-WindowsFeature.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.ROLE
Administrators

#> 
Import-Module ServerManager

Install-WindowsFeature -Name 'System-Insights','RSAT-System-Insights', 'System-DataArchiver'

}
## [END] Install-WACSIInsightsFeature ##
function Install-WACSINugetFromTemp {
<#

.SYNOPSIS

.DESCRIPTION

.PARAMETER path

.PARAMETER title

.PARAMETER id

.PARAMETER version

.PARAMETER dllName

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $true)]
    [string]$path,

    [Parameter(Mandatory = $true)]
    [string]$title,

    [Parameter(Mandatory = $true)]
    [string]$id,

    [Parameter(Mandatory = $true)]
    [string]$version,

    [Parameter(Mandatory = $true)]
    [string]$dllName
)
Import-Module SystemInsights, Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

$sourceDirectoryPath = $path + $id + "." + $version

$destinationDirectoryPath = $env:SystemDrive + "\ProgramData\Microsoft\Windows\SystemInsights\InstalledCapabilities\" + $id

try {
    if (Test-Path $destinationDirectoryPath) { Remove-Item $destinationDirectoryPath -Force -Recurse; }

    Copy-Item -Path $sourceDirectoryPath -Destination $destinationDirectoryPath -Recurse -Force

    $dllPath = $destinationDirectoryPath + "\" + $dllName

    Add-InsightsCapability -Name $title -Library $dllPath -Confirm:$false

    Restart-Service DPS

    $policiesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Insights\Parameters"
    if (Test-Path $policiesPath) {
        $currentSetting = Get-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($currentSetting -eq $null) {
            Set-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -Force
            Restart-Service Insights
        }
        else {
            if ($currentSetting.MaxSerializedLengthInMB -lt 100) {
                Set-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -Force
            }
            Restart-Service Insights
        }
    }
    else {
        New-Item -Path $policiesPath -Force
        New-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -PropertyType DWORD -Force
        Restart-Service Insights
    }

    if (Test-Path $path) { Remove-Item $path -Force -Recurse; }

}
catch {
    @{
        errorDetail = ("$($_.Exception.Message) $($_.CategoryInfo.GetMessage())");
        hResult     = $_.Exception.hResult;
    } | Microsoft.PowerShell.Utility\Write-Output
    throw $_
}
}
## [END] Install-WACSINugetFromTemp ##
function Invoke-WACSIInsightsCapability {
<#

.SYNOPSIS
Invokes Invoke-InsightsCapability.

.DESCRIPTION
Invokes Invoke-InsightsCapability.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string]
    $name
)
Import-Module SystemInsights

Invoke-InsightsCapability -Name $name -Confirm:$false

}
## [END] Invoke-WACSIInsightsCapability ##
function Remove-WACSIInsightsCapability {
<#

.SYNOPSIS
Remove insights capability and restart service.

.DESCRIPTION
Remove insights capability and restart service.

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $true)]
    [string]$title
)
Import-Module SystemInsights, Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility

try {
    Remove-InsightsCapability -Name $title -Confirm:$false -ErrorAction Stop

    Restart-Service DPS -ErrorAction Stop
} catch {
    @{
        errorDetail = ("$($_.Exception.Message) $($_.CategoryInfo.GetMessage())");
        hResult = $_.Exception.hResult;
    } | Microsoft.PowerShell.Utility\Write-Output
    throw $_
}
}
## [END] Remove-WACSIInsightsCapability ##
function Set-WACSIClusterSettings {
<#

.SYNOPSIS
Sets item property values for clustered storage settings.

.DESCRIPTION
Sets item property values for clustered storage settings.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER systemDataArchiverValue

.PARAMETER totleStorageValue

.PARAMETER volumeValue

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [uint32]
  $systemDataArchiverValue,
  [Parameter(Mandatory = $true)]
  [uint32]
  $totalStorageValue,
  [Parameter(Mandatory = $true)]
  [uint32]
  $volumeValue
)
Import-Module Microsoft.PowerShell.Management

$systemDataArchiverPath = 'HKLM:\SOFTWARE\Microsoft\Windows\SystemDataArchiver'
$totalStoragePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemInsights\Capabilities\Total storage consumption forecasting'
$volumePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemInsights\Capabilities\Volume consumption forecasting'

# system data archiver
Stop-Service -Name DPS

if (Test-Path $systemDataArchiverPath)
{
  Set-ItemProperty -Path $systemDataArchiverPath -Name ClusterVolumesAndDisks -Value $systemDataArchiverValue
}
else
{
  New-Item -Path $systemDataArchiverPath -Force
  New-ItemProperty -Path $systemDataArchiverPath -Name ClusterVolumesAndDisks -Value $systemDataArchiverValue -PropertyType DWORD -Force
}

Start-Service -Name DPS

#  total storage
if (Test-Path $totalStoragePath)
{
  Set-ItemProperty -Path $totalStoragePath -Name ClusterVolumesAndDisks -Value $totalStorageValue
}
else
{
  New-Item -Path $totalStoragePath -Force
  New-ItemProperty -Path $totalStoragePath -Name ClusterVolumesAndDisks -Value $totalStorageValue -PropertyType DWORD -Force
}

#  volume
if (Test-Path $volumePath)
{
  Set-ItemProperty -Path $volumePath -Name ClusterVolumes -Value $volumeValue
}
else
{
  New-Item -Path $volumePath -Force
  New-ItemProperty -Path $volumePath -Name ClusterVolumes -Value $volumeValue -PropertyType DWORD -Force
}

}
## [END] Set-WACSIClusterSettings ##
function Set-WACSIInsightsCapabilityActionCombo {
<#

.SYNOPSIS

.DESCRIPTION
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
.PARAMETER okPath
.PARAMETER warningPath
.PARAMETER criticalPath
.PARAMETER errorPath
.PARAMETER nonePath
.PARAMETER okUsername
.PARAMETER okPassword
.PARAMETER warningUsername
.PARAMETER warningPassword
.PARAMETER criticalUsername
.PARAMETER criticalPassword
.PARAMETER errorUsername
.PARAMETER errorPassword
.PARAMETER noneUsername
.PARAMETER nonePassword
.PARAMETER okIncluded
.PARAMETER warningIncluded
.PARAMETER criticalIncluded
.PARAMETER errorIncluded
.PARAMETER noneIncluded
.PARAMETER okDelete
.PARAMETER warningDelete
.PARAMETER criticalDelete
.PARAMETER errorDelete
.PARAMETER noneDelete
.PARAMETER commonCredentialsUsed
.PARAMETER commonUsername
.PARAMETER commonPassword

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string] $name,
    [string] $okPath,
    [string] $warningPath,
    [string] $criticalPath,
    [string] $errorPath,
    [string] $nonePath,
    [string] $okUsername,
    [string] $okPassword,
    [string] $warningUsername,
    [string] $warningPassword,
    [string] $criticalUsername,
    [string] $criticalPassword,
    [string] $errorUsername,
    [string] $errorPassword,
    [string] $noneUsername,
    [string] $nonePassword,
    [bool] $okIncluded,
    [bool] $warningIncluded,
    [bool] $criticalIncluded,
    [bool] $errorIncluded,
    [bool] $noneIncluded,
    [bool] $okDelete,
    [bool] $warningDelete,
    [bool] $criticalDelete,
    [bool] $errorDelete,
    [bool] $noneDelete,
    [bool] $commonCredentialsUsed,
    [string] $commonUsername,
    [string] $commonPassword

)
Import-Module SystemInsights

function Get-Cred() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$password,

        [Parameter(Mandatory = $true)]
        [string]$username
    )
    Import-Module Microsoft.PowerShell.Utility, Microsoft.PowerShell.Security

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $username, $securePass
}

$okException = $null
$warningException = $null
$criticalException = $null
$errorException = $null
$noneException = $null

if ($okIncluded) {
    try {
        if ($okDelete) {
            Remove-InsightsCapabilityAction -Name $name -Type "Ok" -Confirm:$false
        }
        else {
            $cred = $null;
            if ($commonCredentialsUsed) {
                $cred = Get-Cred -UserName $commonUsername -Password $commonPassword;
            }
            else {
                $cred = Get-Cred -UserName $okUsername -Password $okPassword;
            }
            Set-InsightsCapabilityAction -Name $name -Type "Ok" -Action $okPath -ErrorAction "stop" -Confirm:$false -ActionCredential $cred;
        }
    }
    catch {
        $okException = $_
    }
}

if ($warningIncluded) {
    try {
        if ($warningDelete) {
            Remove-InsightsCapabilityAction -Name $name -Type "Warning" -Confirm:$false
        }
        else {
            $cred = $null;
            if ($commonCredentialsUsed) {
                $cred = Get-Cred -UserName $commonUsername -Password $commonPassword;
            }
            else {
                $cred = Get-Cred -UserName $warningUsername -Password $warningPassword;
            }
            Set-InsightsCapabilityAction -Name $name -Type "Warning" -Action $warningPath -ErrorAction "stop" -Confirm:$false -ActionCredential $cred;
        }
    }
    catch {
        $okException = $_
    }
}

if ($criticalIncluded) {
    try {
        if ($criticalDelete) {
            Remove-InsightsCapabilityAction -Name $name -Type "Critical" -Confirm:$false
        }
        else {
            $cred = $null;
            if ($commonCredentialsUsed) {
                $cred = Get-Cred -UserName $commonUsername -Password $commonPassword;
            }
            else {
                $cred = Get-Cred -UserName $criticalUsername -Password $criticalPassword;
            }
            Set-InsightsCapabilityAction -Name $name -Type "Critical" -Action $criticalPath -ErrorAction "stop" -Confirm:$false -ActionCredential $cred;
        }
    }
    catch {
        $okException = $_
    }
}

if ($errorIncluded) {
    try {
        if ($errorDelete) {
            Remove-InsightsCapabilityAction -Name $name -Type "Error" -Confirm:$false
        }
        else {
            $cred = $null;
            if ($commonCredentialsUsed) {
                $cred = Get-Cred -UserName $commonUsername -Password $commonPassword;
            }
            else {
                $cred = Get-Cred -UserName $errorUsername -Password $errorPassword;
            }
            Set-InsightsCapabilityAction -Name $name -Type "Error" -Action $errorPath -ErrorAction "stop" -Confirm:$false -ActionCredential $cred;
        }
    }
    catch {
        $okException = $_
    }
}

if ($noneIncluded) {
    try {
        if ($noneDelete) {
            Remove-InsightsCapabilityAction -Name $name -Type "None" -Confirm:$false
        }
        else {
            $cred = $null;
            if ($commonCredentialsUsed) {
                $cred = Get-Cred -UserName $commonUsername -Password $commonPassword;
            }
            else {
                $cred = Get-Cred -UserName $noneUsername -Password $nonePassword;
            }
            Set-InsightsCapabilityAction -Name $name -Type "None" -Action $nonePath -ErrorAction "stop" -Confirm:$false -ActionCredential $cred;
        }
    }
    catch {
        $okException = $_
    }
}

# return obj with specific errs to give to notifications pane
@{okException = $okException; warningException = $warningException; criticalException = $criticalException; errorException = $errorException; noneException = $noneException}

}
## [END] Set-WACSIInsightsCapabilityActionCombo ##
function Set-WACSIInsightsCapabilitySchedule {
<#

.SYNOPSIS
Invokes Set-InsightsCapabilitySchedule.

.DESCRIPTION
Invokes Set-InsightsCapabilitySchedule.
The supported Operating Systems are Windows Server 2019.
Copyright (c) Microsoft Corp 2018.

.PARAMETER name
.PARAMETER daily
.PARAMETER hourly
.PARAMETER minute
.PARAMETER monday
.PARAMETER tuesday
.PARAMETER wednesday
.PARAMETER thursday
.PARAMETER friday
.PARAMETER saturday
.PARAMETER sunday
.PARAMETER at
.PARAMETER minutesInterval
.PARAMETER hoursInterval
.PARAMETER daysInterval

.ROLE
Administrators

#>
param (
  [Parameter(Mandatory = $true)] [string] $name,
  [Parameter(Mandatory = $false)] [bool] $daily,
  [Parameter(Mandatory = $false)] [bool] $hourly,
  [Parameter(Mandatory = $false)] [bool] $minute,
  [Parameter(Mandatory = $false)] [bool] $monday,
  [Parameter(Mandatory = $false)] [bool] $tuesday,
  [Parameter(Mandatory = $false)] [bool] $wednesday,
  [Parameter(Mandatory = $false)] [bool] $thursday,
  [Parameter(Mandatory = $false)] [bool] $friday,
  [Parameter(Mandatory = $false)] [bool] $saturday,
  [Parameter(Mandatory = $false)] [bool] $sunday,
  [Parameter(Mandatory = $false)] [datetime] $at,
  [Parameter(Mandatory = $false)] [uint16] $minutesInterval,
  [Parameter(Mandatory = $false)] [uint16] $hoursInterval,
  [Parameter(Mandatory = $false)] [uint16] $daysInterval
)
Import-Module SystemInsights

$arguments = @{}
$arguments += @{"name" = $name}

$daysOfWeek = @()

if ($monday) {
  $daysOfWeek += "Monday"
}

if ($tuesday) {
  $daysOfWeek += "Tuesday"
}

if ($wednesday) {
  $daysOfWeek += "Wednesday"
}

if ($thursday) {
  $daysOfWeek += "Thursday"
}

if ($friday) {
  $daysOfWeek += "Friday"
}

if ($saturday) {
  $daysOfWeek += "Saturday"
}

if ($sunday) {
  $daysOfWeek += "Sunday"
}


if ($daily) {
  $arguments += @{"Daily" = $true}
  $arguments += @{"at" = $at}
  if ($daysInterval)
  {
    $arguments += @{"daysInterval" = $daysInterval}
  }
  else
  {
    $arguments += @{"daysOfWeek" = $daysOfWeek}
  }
}

if ($hourly) {
  $arguments += @{"Hourly" = $true}
  $arguments += @{"hoursInterval" = $hoursInterval}
  $arguments += @{"daysOfWeek" = $daysOfWeek}
}


if ($minute) {
  $arguments += @{"Minute" = $true}
  $arguments += @{"minutesInterval" = $minutesInterval}
  $arguments += @{"daysOfWeek" = $daysOfWeek}
}

Set-InsightsCapabilitySchedule @arguments

}
## [END] Set-WACSIInsightsCapabilitySchedule ##
function Update-WACSINugetFromTemp {
<#

.SYNOPSIS

.DESCRIPTION

.PARAMETER path

.PARAMETER title

.PARAMETER id

.PARAMETER version

.PARAMETER dllName

.ROLE
Administrators

#>
Param
(
    [Parameter(Mandatory = $true)]
    [string]$path,

    [Parameter(Mandatory = $true)]
    [string]$title,

    [Parameter(Mandatory = $true)]
    [string]$id,

    [Parameter(Mandatory = $true)]
    [string]$version,

    [Parameter(Mandatory = $true)]
    [string]$dllName
)
Import-Module SystemInsights, Microsoft.PowerShell.Utility, Microsoft.PowerShell.Security

$sourceDirectoryPath = $path + $id + "." + $version

$destinationDirectoryPath = $env:SystemDrive + "\ProgramData\Microsoft\Windows\SystemInsights\InstalledCapabilities\" + $id

try {
    if (Test-Path $destinationDirectoryPath) { Remove-Item $destinationDirectoryPath -Force -Recurse; }

    Copy-Item -Path $sourceDirectoryPath -Destination $destinationDirectoryPath -Recurse -Force

    $dllPath = $destinationDirectoryPath + "\" + $dllName

    Update-InsightsCapability -Name $title -Library $dllPath -Confirm:$false

    Restart-Service DPS

    $policiesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Insights\Parameters"
    if (Test-Path $policiesPath) {
        $currentSetting = Get-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($currentSetting -eq $null) {
            Set-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -Force
            Restart-Service Insights
        }
        else {
            if ($currentSetting.MaxSerializedLengthInMB -lt 100) {
                Set-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -Force
            }
            Restart-Service Insights
        }
    }
    else {
        New-Item -Path $policiesPath -Force
        New-ItemProperty -Path $policiesPath -Name MaxSerializedLengthInMB -Value 100 -PropertyType DWORD -Force
        Restart-Service Insights
    }

    if (Test-Path $path) { Remove-Item $path -Force -Recurse; }

}
catch {
    @{
        errorDetail = ("$($_.Exception.Message) $($_.CategoryInfo.GetMessage())");
        hResult     = $_.Exception.hResult;
    } | Microsoft.PowerShell.Utility\Write-Output
    throw $_
}
}
## [END] Update-WACSINugetFromTemp ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoxUKeusAXLgPw
# PwH4e/rf5rOQYESpwSSy+1SaJhC5Y6CCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGKuLAYCPJa90G822Rngudx6
# lEBXq+KmlUXBXjGEwJ+GMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEARf1f7himHK3mJL/JYpF/cJneBDndw8iQQNY433XMz4GYmPKlIk38bvKL
# gLuT12R0dFyf5DcfQ4oIcXoyiiMhBl9dkHTjmMRdPaHtOJxdGkRGtPi7UY+KdMHJ
# XpsWMHg0c4X02qLL+wmJ2TuB/zENHcHhwKLzD6D1908g4iuc9XIPRyesLzeHBOY5
# MRWAaWGeEtiRPaejfOPG1hIQ1IHJ9oZaC1qxn2wndAnL8FiVaQQ955HbBXJzufPA
# yhzdBbNxPxsHnMW4xf8GOpOK0ZZ4nom8HwT62gX1bylV9RssRh5Fdd2Xy7d0pBTY
# L10yD5ZOEyWTFT0PYSuEb+xKAQeN/6GCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCB/Boi5Awz3uW16UzpFuA2Y5YX5YrHr4T8Bc/RoTgXffwIGaPAq2ial
# GBMyMDI1MTExMDE3MTYxOS4xMDNaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# MC8GCSqGSIb3DQEJBDEiBCCM1cdsvGME4Ssii8AY4gKA8yZCiwTsDpCLQ1f5OtL1
# 0TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIEsD3RtxlvaTxFOZZnpQw0Dk
# sPmVduo5SyK9h9w++hMtMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIDux5cADhsdMoAAQAAAgMwIgQg/5DNms7Sd8UtpZacMoCY1q5/
# 2qdlavBPw1sTL5V3yNIwDQYJKoZIhvcNAQELBQAEggIAG2FfHW36hEi5QhsHyzdQ
# RWx8iMy0gZMsmNgb3DQY0CDISpinMfFZIgvMkbwepxhYDVPHuQtbAP8DfWjtCdKN
# t/TaUndoK3BgYbcItf73h25hRAhZWj6JAwkzWt6WlkjtlFHdwkmVz0VE/LXxsJ5q
# oaWkjZO/G/AiwxFoddrs5Q4RAVvomk2Aqw9136H6NI7pk/DAR6twIYu3z/Bnq1vt
# to72GrQxg6Iagi4na5ND/DTVvPk6N6Srk9pVivLrLd9zJx+NntRzuGruhRC8hppg
# A+2B4A+myXNJ5VAVDIbYelS32AYqPTEq4Xn5LSjy4TZUm2pBay7mxMknOZRm1tQN
# gXNCZS9reVCvy6MzQDsR9A1FsZiMhWdk1t+9CQid4WvFEk8PsTYlR4eUMfaBOYGQ
# i2Un3Js95eA1P4w3sI+eE4ukpk0rzm8mFJiyJH2Hx+nP0zWDL7gfr2Zo7y+W5vdz
# il8KRguOAHQJw5U24q86Qkbz4S2nv7r2k1qp9nodd6q8UdOnJk4c/03hMnHjn836
# 4Z8MMIIayQjXiLev9fzi3tEEgSGF+1RYnfwSS8kxs2ZMlYc+7FnQAQnHZk6RJ5E9
# YXo3qykwrzu0p55Ueyct/H0Fp556nsVOR1nNarRdV1UvXGH1aBQiaRQSEE40raog
# r1xYk4yhUNkBSujXnjyHM3A=
# SIG # End signature block
