function Get-WACSMSCutoverSummary {
<#

.SYNOPSIS
Get Cutover Summary

.DESCRIPTION
Get Cutover Summary

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('CutoverSummary', $true)


$status=1
$exception = $null
try {
  $result = Get-SmsState @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSCutoverSummary ##
function Get-WACSMSInventoryConfigDetail {
<#

.SYNOPSIS
Get Inventory config detail

.DESCRIPTION
Get Inventory config detail

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('InventoryConfigDetail', $true)
$parameters.Add('ComputerName', $computerName)

$status=1
$exception = $null
try {
  $result = Get-SmsState @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSInventoryConfigDetail ##
function Get-WACSMSInventoryDFSNDetail {
<#

.SYNOPSIS
Get Inventory DFSN Detail

.DESCRIPTION
Get Inventory DFSN Detail

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,
  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{
  'ErrorAction' = 'Stop';
  'Name' = $jobName;
  'InventoryDFSNDetail' = $true;
  'ComputerName' = $computerName;
}

$status=1
$exception = $null
try {
  $result = Get-SmsState @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSInventoryDFSNDetail ##
function Get-WACSMSInventorySMBDetail {
<#

.SYNOPSIS
Get Inventory SMB Detail

.DESCRIPTION
Get Inventory SMB Detail

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,
  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{
  'ErrorAction' = 'Stop';
  'Name' = $jobName;
  'InventorySMBDetail' = $true;
  'ComputerName' = $computerName;
}

$status=1
$exception = $null
try {
  $result = Get-SmsState @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSInventorySMBDetail ##
function Get-WACSMSInventorySummary {
<#

.SYNOPSIS
Get Inventory Summary

.DESCRIPTION
Get Inventory Summary

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('InventorySummary', $true)


$status=1
$exception = $null
try {
  $result = Get-SmsState @parameters
  if($result -eq $null) {
    $result = "null" # ability to detect null is lost in the conversion to JSON
  }
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSInventorySummary ##
function Get-WACSMSSmbNetFirewallRule {
<#

.SYNOPSIS
Get SMB Net Firewall Rule

.DESCRIPTION
Returns the status of the SMB firewall rules
To enable: Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing'|Set-NetFirewallRule -Profile 'Private, Domain' -Enabled true -PassThru

.ROLE
Readers

#>
Import-Module NetSecurity, Microsoft.PowerShell.Utility

 # Conversion to/from csv returns enums as text values, but does not retain Arrays or Complex Objects
 Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Microsoft.PowerShell.Utility\ConvertTo-Csv | Microsoft.PowerShell.Utility\ConvertFrom-Csv | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmbNetFirewallRule ##
function Get-WACSMSSmsCutover {
<#

.SYNOPSIS
Get Sms Cutover

.DESCRIPTION
Get Sms Cutover

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)


$status=1
$exception = $null
try {
  $result = Get-SmsCutover @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsCutover ##
function Get-WACSMSSmsCutoverPairing {
<#

.SYNOPSIS
Get SMS Cutover Pairing

.DESCRIPTION
Get SMS Cutover Pairing

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)

$status=1
$exception = $null
try {
  $result = Get-SmsCutoverPairing @parameters
  if($result -eq $null) {
    $result = "null" # ability to detect null is lost in the conversion to JSON
  }
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsCutoverPairing ##
function Get-WACSMSSmsDestinationConfig {
<#

.SYNOPSIS
Get Sms Destination config

.DESCRIPTION
Get Sms Destination config

.ROLE
Readers

#>
Param
(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$destinationComputerName,

    [Parameter(Mandatory = $false)]
    [string]$orchestratorComputerName,

    [Parameter(Mandatory = $false)]
    [int]$orchestratorPort
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('DestinationComputerName', $destinationComputerName)

if ($orchestatorComputerName) {
    $parameters.Add('OrchestratorComputerName', $orchestratorComputerName)
    $parameters.Add('OrchestratorPort', $orchestratorPort)
}

$status = 1
$exception = $null
try {
    $result = Get-SmsDestinationConfig @parameters
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsDestinationConfig ##
function Get-WACSMSSmsFeature {
<#

.SYNOPSIS
Get Sms Feature

.DESCRIPTION
Get Sms Feature

.ROLE
Readers

#>

<#########################################################################################################
 # File: get-smsfeature.ps1
 #
 # .DESCRIPTION
 #
 #  invokes Get-WindowsFeature
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #########################################################################################################>
Import-Module ServerManager

Get-WindowsFeature -Name 'SMS', 'SMS-PROXY'

}
## [END] Get-WACSMSSmsFeature ##
function Get-WACSMSSmsInventory {
<#

.SYNOPSIS
Get Sms Inventory

.DESCRIPTION
Get Sms Inventory

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)


$status=1
$exception = $null
try {
  $result = Get-SmsInventory @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsInventory ##
function Get-WACSMSSmsNasPrescan {
<#

.SYNOPSIS
Get Sms Nas Prescan

.DESCRIPTION
Get Sms Nas Prescan

.ROLE
Readers

#>
Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{
    'Name' = $jobName;
}

$status=1
$exception = $null
try {
    $result = Get-SmsNasPrescan @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsNasPrescan ##
function Get-WACSMSSmsRequiredVolumeSize {
<#

.SYNOPSIS
Get Sms Required Volume Size

.DESCRIPTION
Get Sms Required Volume Size

.ROLE
Readers

#>
Param (
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$srcComputerName,

    [Parameter(Mandatory = $true)]
    [array]$excludedShares,

    [Parameter(Mandatory = $true)]
    [bool]$anyExcludedShares
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$volumes = @{}
$volumeSizes = @{}
$volumesSorted = @{}
$shareSizes = @{}

# try {

    get-smsstate $jobName -ComputerName $srcComputerName -InventorySMBDetail -ErrorAction Ignore |
        foreach {
        if($_.Volume -eq $null){
          $shareVolume = $_.path.Substring(0,2)
        } else{
          $shareVolume = $_.Volume
        }
        $shareName = $_.Name
        $sharePath = $_.Path
        # echo "Doing $shareVolume - $shareName - $sharePath"
        if (!$volumes.containsKey($shareVolume)) {
            # echo "Did not contain $shareVolume"
            $sharePaths = @()
            if (!$anyExcludedShares -or !$excludedShares.Contains($sharePath)) {
                # echo "Not Excluded: $sharePath"
                $sharePaths += ($_.path.ToString())
                $volumes.Add($shareVolume, $sharePaths)
                $shareSizes.Add($_.path, $_.SizeTotal)
            }
            if (!$volumeSizes.containsKey($shareVolume)) {
                # echo "Adding to volumeSizes: $shareVolume"
                $volumeSizes.Add($shareVolume, 0)
            }
        }
        elseif (!$anyExcludedShares -or !$excludedShares.Contains($sharePath)) {
            # echo "Volume was in, adding share $shareVolume, $sharePath"
            # $sharePath = $volumes.$shareVolume
            $sharePaths = $volumes[$shareVolume]
            $sharePaths += ($_.path.ToString())
            $shareSizes.Add($_.path, $_.SizeTotal)
            $volumes.Set_Item($shareVolume, $sharePaths)
        }
    }

    $volumes.GetEnumerator() |
        foreach {
        $sortedSharePaths = $_.Value | Microsoft.PowerShell.Utility\Sort-Object
        $volumesSorted.Set_Item($_.Name, $sortedSharePaths)
    }

    $volumesSorted.GetEnumerator() |
        foreach {
        $currentVolume = $_.Name
        $currentShares = $_.Value
        if ($currentShares -is [array]) {
            ($currentShares.Count - 1)..0 |
                foreach {
                $currentShareName = $currentShares[$_].ToString()
                if ($shareSizes.ContainsKey($currentShareName)) {
                    if ($_ - 1 -ge 0) {
                        $contains = $true
                        $previousShareName =$currentShares[$_ - 1].ToString()
                        # if ($currentShareName -notcontains $previousShareNameToCompare) {
                        # echo "$previousShareName contains $currentShareName"

                        $path1Split = $previousShareName.split("\")
                        $path2Split = $currentShareName.split("\")

                        $path1Split = New-Object System.Collections.ArrayList(,$path1Split)
                        $path2Split = New-Object System.Collections.ArrayList(,$path2Split)
                        0..($path1Split.Count - 1) |
                            foreach {
                            $p1 = $path1Split[$_]
                            $p2 = $path2Split[$_]
                            # echo "$p1 equal $p2"
                            if(!($p1 -eq $p2)) {
                                $contains = 0
                            }
                        }
                        if($contains){
                            # echo "$currentShareName did contain $previousShareName"
                        } else {
                            # echo "$currentShareName did not contain $previousShareName"
                            $shareSize = $shareSizes.$currentShareName
                            $currentSize = $volumeSizes.$currentVolume
                            $volumeSizes.Set_Item($currentVolume, $currentSize + $shareSize)
                        }



                        # if((PathContains -path1 $currentShareName -path2 $previousShareName) -eq 1){
                        #     echo "$currentShareName did contain $previousShareName"
                        # } else {
                        #     echo "$currentShareName did not contain $previousShareName"
                        #     $shareSize = $shareSizes.$currentShareName
                        #     $currentSize = $volumeSizes.$currentVolume
                        #     $volumeSizes.Set_Item($currentVolume, $currentSize + $shareSize)
                        # }
                    }
                    else {
                        $shareSize = $shareSizes[$currentShareName]
                        $currentSize = $volumeSizes.$currentVolume
                        $volumeSizes.Set_Item($currentVolume, $currentSize + $shareSize)
                    }
                }
            }
        }
        else {
            if ($shareSizes.ContainsKey($currentShares)) {
                $shareSize = $shareSizes.$currentShares
                $currentSize = $volumeSizes.$currentVolume
                $volumeSizes.Set_Item($currentVolume, $currentSize + $shareSize)
            }
        }
    }
# }
# catch {

# }

$status = 1
@{Result = $volumeSizes; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsRequiredVolumeSize ##
function Get-WACSMSSmsState {
<#

.SYNOPSIS
Get Sms State

.DESCRIPTION
Get Sms State

.ROLE
Readers

#>

Param
(
    [string]$jobName,
    [string]$nasController
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')

if ($jobName) {
    $parameters.Add('Name', $jobName)
    if ($nasController) {
        $parameters.Add('NasController', $nasController)
        $parameters.Add('GetNasPrescanResult', $true)
    }
}

$status = 1
$exception = $null
try {
    $result = Get-SmsState @parameters
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsState ##
function Get-WACSMSSmsStats {
<#

.SYNOPSIS
Get Sms Stats

.DESCRIPTION
Get Sms Stats

.ROLE
Readers

#>

Param (
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

# Job list
$jobs = New-Object System.Collections.Generic.List[System.String]
get-smsstate | foreach { $jobs.Add($_.job) }

# Inventory
$inventoryDeviceCount = 0
$inventorySizeTotal = 0
$inventoryFilesTotal = 0
$inventoryJobsRunning = 0
$inventoryJobsPaused = 0
$inventoryJobsCompleted = 0


# Transfer
$transferDeviceCount = 0
$transferSizeTotal = 0
$transferFilesTotal = 0
$transferSizeTransferred = 0
$transferFilesTransferred = 0
$transferJobsRunning = 0
$transferJobsPaused = 0
$transferJobsCompleted = 0

# Cutover
$cutoverDeviceCount = 0
$cutoverJobsRunning = 0
$cutoverJobsPaused = 0
$cutoverJobsCompleted = 0

# JobSpecific
$runningJobStats = @()

# export enum SubOperationState {
#     NA,
#     NotStarted,
#     Running,
#     Succeeded,
#     Canceled,
#     Failed,
#     PartiallyFailed
# }
$SUBSTATE_NA = 0
$SUBSTATE_NOT_STARTED = 1
$SUBSTATE_RUNNING = 2
$SUBSTATE_SUCCEEDED = 3
$SUBSTATE_CANCELED = 4
$SUBSTATE_FAILED = 5
$SUBSTATE_PARTIALLYFAILED = 6
# export enum OperationType {
#     None = 0,
#     Inventory,
#     Transfer,
#     Cutover
# }
$OPERATION_NONE = 0
$OPERATION_INVENTORY = 1
$OPERATION_TRANSFER = 2
$OPERATION_CUTOVER = 3
# export enum OperationState {
#     None,
#     Idle,
#     Running,
#     Paused,
#     Canceled,
#     Failed,
#     Succeeded,
#     PartiallySucceeded
# }
$STATE_NONE = 0
$STATE_IDLE = 1
$STATE_RUNNING = 2
$STATE_PAUSED = 3
$STATE_CANCELED = 4
$STATE_FAILED = 5
$STATE_SUCCEEDED = 6
$STATE_PARTIALLYSUCCEEDED = 7

$NOT_RUNNING = 0
$INVENTORY_RUNNING = 1
$TRANSFER_RUNNING = 2
$CUTOVER_RUNNING = 3

# TODO: clean this up a bit. This feature was added last minute and went through 3 quick iterations so a bit messy
$debug = ''
try {
    foreach ($job in $jobs) {
        $jobIsRunning = $NOT_RUNNING

        #Determine if any phases running
        get-smsstate -name $job |
            foreach {
            if ($_.State.value__ -eq $STATE_RUNNING) {
                if ($_.LastOperation.value__ -eq $OPERATION_INVENTORY) {
                    $jobIsRunning = $INVENTORY_RUNNING
                }
                elseif ($_.LastOperation.value__ -eq $OPERATION_TRANSFER) {
                    $jobIsRunning = $TRANSFER_RUNNING
                }
                elseif ($_.LastOperation.value__ -eq $OPERATION_CUTOVER) {
                    $jobIsRunning = $CUTOVER_RUNNING
                }
            }
        }

        $tmpServerStats = @()
        $tmpJobStats = @{}
        # Inventory
        $tmpJobInventoryDevicesTotal = 0
        $tmpJobInventoryDevicesCompleted = 0
        get-smsstate -name $job -Inventorysummary -ErrorAction Ignore |
            foreach {
            if (!($_.InventoryState.value__ -eq $SUBSTATE_NA -or $_.InventoryState.value__ -eq $SUBSTATE_NOT_STARTED -or $_.InventoryState.value__ -eq $SUBSTATE_RUNNING)) {
                $tmpJobInventoryDevicesCompleted++;
            }
            if (!($_.InventoryState.value__ -eq $SUBSTATE_FAILED)) {
                $inventoryDeviceCount++
            }
            # if ($_.InventoryState.value__ -eq $SUBSTATE_RUNNING) {
            #     $inventoryJobsRunning++;
            # }
            if ($jobIsRunning -eq $INVENTORY_RUNNING) {
                $tmpStats = @{}
                $deviceTmp = @()
                $tmpStats.Add('Name', $_.SuppliedDeviceName)
                $tmpStats.Add('SubState', $_.InventoryState)

                # get-smsinventory -name $job -ErrorAction Ignore |
                #     foreach {
                #     $_.ComputerName | foreach {
                #         $deviceTmp += $_
                #     }
                # }
                # $tmp
                $tmpServerStats += $tmpStats
            }
            $inventorySizeTotal += $_.SizeTotal
            $inventoryFilesTotal += $_.FilesTotal

        }

        get-smsinventory -name $job -ErrorAction Ignore |
            foreach {
            $_.ComputerName | foreach {
                $tmpJobInventoryDevicesTotal++;
            }
        }

        # Transfer
        $tmpJobTransferSizeTotal = 0
        $tmpJobTransferSizeTransferred = 0
        get-smsstate -name $job -TransferSummary -ErrorAction Ignore |
            foreach {
            if (!($_.TransferState.value__ -eq $SUBSTATE_FAILED)) {
                $transferDeviceCount++
            }
            if ($jobIsRunning -eq $TRANSFER_RUNNING) {
                $tmpStats = @{}
                $deviceTmp = @()
                $tmpStats.Add('Name', $_.SourceDevice)
                $tmpStats.Add('SubState', $_.TransferState)
                $tmpStats.Add('Total', $_.SizeTotal)
                $tmpStats.Add('Complete', $_.SizeTransferred)
                $date = Get-Date
                $tmpStats.Add('Timestamp', $date)
                $tmpServerStats += $tmpStats
            }
            $transferSizeTotal += $_.SizeTotal
            $transferFilesTotal += $_.FilesTotal
            $transferSizeTransferred += $_.SizeTransferred
            $transferFilesTransferred += $_.FilesTransferred
            # $tmpJobTransferSizeTotal += $_.SizeTotal
            # $tmpJobTransferSizeTransferred += $_.SizeTransferred
        }

        # Cutover
        $tmpJobCutoverDevicesTotal = 0
        $tmpJobCutoverDevicesCompleted = 0
        get-smsstate -name $job -CutoverSummary -ErrorAction Ignore |
            foreach {
            $tmpJobCutoverDevicesTotal++
            if (!(($_.CutoverState.value__ -eq $SUBSTATE_NA) -Or ($_.CutoverState.value__ -eq $SUBSTATE_NOT_STARTED) -Or ($_.CutoverState.value__ -eq $SUBSTATE_RUNNING))) {
                $tmpJobCutoverDevicesCompleted++
            }
            if (!($_.CutoverState.value__ -eq $SUBSTATE_FAILED)) {
                $cutoverDeviceCount++
            }
            if ($jobIsRunning -eq $CUTOVER_RUNNING) {
                $tmpStats = @{}
                $deviceTmp = @()
                $tmpStats.Add('Name', $_.SourceDevice)
                $tmpStats.Add('SubState', $_.CutoverState)
                $tmpStats.Add('Total', 100)                  # Cutover has an internally calculated percentage out of 100%
                $tmpStats.Add('Complete', $_.CutoverProgress)
                $tmpServerStats += $tmpStats
            }
        }

        # Operation Totals
        $tmpJobName = ''
        get-smsstate -name $job |
            foreach {
            $tmpJobName = $_.job
            if ($_.LastOperation.value__ -eq $OPERATION_NONE) {
                # Placeholder
            }
            if ($_.LastOperation.value__ -eq $OPERATION_INVENTORY) {
                if ($_.State.value__ -eq $STATE_RUNNING) {
                    $tmpJobStats.Add('JobChartTotal', $tmpJobInventoryDevicesTotal)
                    $tmpJobStats.Add('JobChartCompleted', $tmpJobInventoryDevicesCompleted)
                    $tmpJobStats.Add('ChartType', 'inventoryChartDevices')
                    $tmpJobStats.Add('StatType', 'inventory')
                }
                switch ($_.State.value__) {
                    $STATE_RUNNING {$inventoryJobsRunning++}
                    $STATE_PAUSED {$inventoryJobsPaused++}
                    $STATE_PARTIALLYSUCCEEDED {$inventoryJobsCompleted++}
                    $STATE_SUCCEEDED {$inventoryJobsCompleted++}
                    $STATE_FAILED {$inventoryJobsCompleted++}
                }
            }
            elseif ($_.LastOperation.value__ -eq $OPERATION_TRANSFER) {
                $inventoryJobsCompleted++
                if ($_.State.value__ -eq $STATE_RUNNING) {
                    $tmpJobStats.Add('JobChartTotal', $tmpJobTransferSizeTotal)
                    $tmpJobStats.Add('JobChartCompleted', $tmpJobTransferSizeTransferred)
                    $tmpJobStats.Add('ChartType', 'transferChartSize')
                    $tmpJobStats.Add('StatType', 'transfer')
                }
                switch ($_.State.value__) {
                    $STATE_RUNNING {$transferJobsRunning++}
                    $STATE_PAUSED {$transferJobsPaused++}
                    $STATE_PARTIALLYSUCCEEDED {$transferJobsCompleted++}
                    $STATE_SUCCEEDED {$transferJobsCompleted++}
                    $STATE_FAILED {$transferJobsCompleted++}
                }
            }
            elseif ($_.LastOperation.value__ -eq $OPERATION_CUTOVER) {
                $inventoryJobsCompleted++
                $transferJobsCompleted++
                if ($_.State.value__ -eq $STATE_RUNNING) {
                    $tmpJobStats.Add('JobChartTotal', $tmpJobCutoverDevicesTotal)
                    $tmpJobStats.Add('JobChartCompleted', $tmpJobCutoverDevicesCompleted)
                    # $tmpJobStats.Add('CutoverDevicesRunning', $tmpJobCutoverDevicesRunning)
                    $tmpJobStats.Add('ChartType', 'cutoverChartDevices')
                    $tmpJobStats.Add('StatType', 'cutover')
                }
                switch ($_.State.value__) {
                    $STATE_RUNNING {$cutoverJobsRunning++}
                    $STATE_PAUSED {$cutoverJobsPaused++}
                    $STATE_PARTIALLYSUCCEEDED {$cutoverJobsCompleted++}
                    $STATE_SUCCEEDED {$cutoverJobsCompleted++}
                    $STATE_FAILED {$cutoverJobsCompleted++}
                }
            }
        }

        if ($tmpJobStats.Count -gt 0 -or !($jobIsRunning -eq $NOT_RUNNING)) {
            $tmpJobStats.Add('JobName', $tmpJobName)
            $tmpJobStats.Add('JobServerStats', $tmpServerStats)
            $runningJobStats += $tmpJobStats
        }
    }
}
catch {

}
$status = 1
$result = @{
    'InventoryDeviceCount'   = $inventoryDeviceCount;
    'InventorySizeTotal'     = $inventorySizeTotal;
    'InventoryFilesTotal'    = $inventoryFilesTotal;
    'InventoryJobsRunning'   = $inventoryJobsRunning;
    'InventoryJobsPaused'    = $inventoryJobsPaused;
    'InventoryJobsCompleted' = $inventoryJobsCompleted;
    'TransferDeviceCount'    = $transferDeviceCount;
    'TransferSizeTotal'      = $transferSizeTotal;
    'TransferFilesTotal'     = $transferFilesTotal;
    'TransferSizeTransferred'= $transferSizeTransferred;
    'TransferFilesTransferred' = $transferFilesTransferred;
    'TransferJobsRunning'    = $transferJobsRunning;
    'TransferJobsPaused'     = $transferJobsPaused;
    'TransferJobsCompleted'  = $transferJobsCompleted;
    'CutoverDeviceCount'     = $cutoverDeviceCount;
    'CutoverJobsRunning'     = $cutoverJobsRunning;
    'CutoverJobsPaused'      = $cutoverJobsPaused;
    'CutoverJobsCompleted'   = $cutoverJobsCompleted;
    'JobSpecificStats'       = $runningJobStats;
}

@{Result = $result; Status = $status; Error = $exception; Debug = $debug} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5


}
## [END] Get-WACSMSSmsStats ##
function Get-WACSMSSmsTransfer {
<#

.SYNOPSIS
Get Sms Transfer

.DESCRIPTION
Get Sms Transfer

.ROLE
Readers

#>
Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)


$status=1
$exception = $null
try {
  $result = Get-SmsTransfer @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsTransfer ##
function Get-WACSMSSmsTransferExcludedShares {
<#

.SYNOPSIS
Get Sms Transfer Exluded Shares

.DESCRIPTION
Get Sms Transfer Exluded Shares

.ROLE
Readers

#>
Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{
    'Name'             = $jobName;
    'ComputerName'     = $computerName;
    'ExcludeSMBShares' = $true;
    'ErrorAction'      = 'Stop';
}

$status = 1
$exception = $null
try {
    $result = Get-SmsTransferPairing @parameters
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsTransferExcludedShares ##
function Get-WACSMSSmsTransferExcludedSharesAndAFS {
<#

.SYNOPSIS
Get Sms Transfer Exluded Shares and AFS

.DESCRIPTION
Get Sms Transfer Exluded Shares and AFS

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName,

    [Parameter(Mandatory = $true)]
    [bool]$getAFSPairings
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$excludeParameters = @{
    'Name'             = $jobName;
    'ComputerName'     = $computerName;
    'ExcludeSMBShares' = $true;
    'ErrorAction'      = 'Stop';
}

$afsParameters = @{
    'Name'                    = $jobName;
    'ComputerName'            = $computerName;
    'TieredAFSVolumeSettings' = $true;
    'ErrorAction'             = 'Stop';
}

$status = 1
$exception = $null
$result = @{ }

try {
    function GetResultAsArray($outputCollection) {
        Import-Module Microsoft.PowerShell.Utility
        $resultArray = @()
        foreach ($item in $outputCollection) {
            $resultArray += $item
        }
        Write-Output -NoEnumerate $resultArray
    }

    $excludedShares = @()
    $excludedShares = Get-SmsTransferPairing @excludeParameters
    $excludedSharesAsArray = GetResultAsArray($excludedShares)
    $result += @{"ExcludeShares" = $excludedSharesAsArray }

    if($getAFSPairings){
        $afsPairings = @()
        $afsPairings = Get-SmsTransferPairing @afsParameters
        $afsPairingsAsArray = GetResultAsArray($afsPairings)
        $result += @{"AFSPairings" = $afsPairingsAsArray }
    }

}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception } | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsTransferExcludedSharesAndAFS ##
function Get-WACSMSSmsTransferPairing {
<#

.SYNOPSIS
Get Sms Transfer Pairing

.DESCRIPTION
Get Sms Transfer Pairing

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)

$status=1
$exception = $null
try {
  $result = Get-SmsTransferPairing @parameters
  if($result -eq $null) {
    $result = "null" # ability to detect null is lost in the conversion to JSON
  }
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsTransferPairing ##
function Get-WACSMSSmsTransferVolumePairing {
<#

.SYNOPSIS
Get Sms Transfer Volume Pairing

.DESCRIPTION
Get Sms Transfer Volume Pairing

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('ComputerName', $computerName)
$parameters.Add('VolumePairings', $true)

$status=1
$exception = $null
try {
  $result = Get-SmsTransferPairing @parameters
  if($result -eq $null) {
    $result = "null" # ability to detect null is lost in the conversion to JSON
  }
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSSmsTransferVolumePairing ##
function Get-WACSMSSmsVersion {
<#

.SYNOPSIS
Get Sms Version

.DESCRIPTION
Get Sms Version

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [bool]$getSms,

    [Parameter(Mandatory = $true)]
    [bool]$getSmsPS,

    [Parameter(Mandatory = $true)]
    [bool]$getSmsProxy
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$includedTypes = @();

if ($getSms) {
    $includedTypes += 'Sms';
}

if ($getSmsPS) {
    $includedTypes += 'SmsPS';
}

if ($getSmsProxy) {
    $includedTypes += 'SmsProxy';
}


$status = 1;
$exception = $null;
try {
    $result = Get-SmsVersion -Type $includedTypes;
}
catch {
    $exception = $_; # the exception
    $status = 0;
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5;

}
## [END] Get-WACSMSSmsVersion ##
function Get-WACSMSTemporaryFile {
<#

.SYNOPSIS
Get Temporary File

.DESCRIPTION
Get Temporary File

.ROLE
Readers

#>

Param
(
)
Import-Module Microsoft.PowerShell.Utility

$newTempFile = [System.IO.Path]::GetTempFileName() | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5

Write-Output $newTempFile

}
## [END] Get-WACSMSTemporaryFile ##
function Get-WACSMSTransferDFSNDetail {
<#

.SYNOPSIS
Get Transfer DFSN Detail

.DESCRIPTION
Get Transfer DFSN Detail

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName,

    [Parameter(Mandatory = $false)]
    [bool]$pipeToFile,

    [Parameter(Mandatory = $false)]
    [string]$filename
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility


$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('TransferDFSNDetail', $true)
$parameters.Add('ComputerName', $computerName)


$status = 1
$exception = $null
try {
    if (!$pipeToFile) {
        $result = Get-SmsState @parameters
        if($result -eq $null) {
            $result = "null" # ability to detect null is lost in the conversion to JSON
          }
    }
    else {
      $result = Get-SmsState @parameters | Microsoft.PowerShell.Utility\ConvertTo-Csv | Out-File $filename
    }
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSTransferDFSNDetail ##
function Get-WACSMSTransferFileDetail {
<#

.SYNOPSIS
Get Transfer File Detail

.DESCRIPTION
Get Transfer File Detail

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName,

    [Parameter(Mandatory = $false)]
    [bool]$pipeToFile,

    [Parameter(Mandatory = $false)]
    [string]$filename,

    [Parameter(Mandatory = $false)]
    [bool]$errorsOnly,

    [Parameter(Mandatory = $false)]
    [bool]$usersDownload,

    [Parameter(Mandatory = $false)]
    [bool]$groupsDownload
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('ComputerName', $computerName)

if ($usersDownload) {
    $parameters.Add('GetLocalUsersDetail', $true)
}
elseif ($groupsDownload) {
    $parameters.Add('GetLocalGroupsDetail', $true)
}
else {
    $parameters.Add('TransferFileDetail', $true)

    if ($errorsOnly) {
        $parameters.Add('ErrorsOnly', $true)
    }
}

$status = 1
$exception = $null
try {
    if (!$pipeToFile) {
        $result = Get-SmsState @parameters
    }
    else {
        # Select-Object -Skip 1 is to remove first line, as it is not CSV (powershell adds it)
        $result = Get-SmsState @parameters | Microsoft.PowerShell.Utility\ConvertTo-Csv |  Microsoft.PowerShell.Utility\Select-Object -Skip 1 | Microsoft.PowerShell.Utility\Out-File $filename
    }
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSTransferFileDetail ##
function Get-WACSMSTransferSMBDetail {
<#

.SYNOPSIS
Get Transfer SMB Detail

.DESCRIPTION
Get Transfer SMB Detail

.ROLE
Readers

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName,

    [Parameter(Mandatory = $false)]
    [bool]$pipeToFile,

    [Parameter(Mandatory = $false)]
    [string]$filename
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('TransferSMBDetail', $true)
$parameters.Add('ComputerName', $computerName)


$status = 1
$exception = $null
try {
    if (!$pipeToFile) {
        $result = Get-SmsState @parameters
        if($result -eq $null) {
            $result = "null" # ability to detect null is lost in the conversion to JSON
          }
    }
    else {
      $result = Get-SmsState @parameters | Microsoft.PowerShell.Utility\ConvertTo-Csv | Out-File $filename
    }
}
catch {
    $exception = $_ # the exception
    $status = 0
}
@{Result = $result; Status = $status; Error = $exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSTransferSMBDetail ##
function Get-WACSMSTransferSummary {
<#

.SYNOPSIS
Get Transfer Summary

.DESCRIPTION
Get Transfer Summary

.ROLE
Readers

#>

Param
(
  [Parameter(Mandatory = $true)]
  [string]$jobName,

  [Parameter(Mandatory = $true)]
  [bool]$getAFSSummary
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{ }
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('TransferSummary', $true)
enum TransferState {
  Running = 2
}
$status = 1
$exception = $null
try {
  $timestamp = Get-Date
  $transferSummaries = Get-SmsState @parameters
  $transferSummaries | Microsoft.PowerShell.Utility\Add-Member -MemberType NoteProperty -Name Timestamp -Value $timestamp

  if ($getAFSSummary) {
    $sourceMachines = Get-SmsState -TransferSummary -Name $jobName
    $tieredAfsSummaries = @()
    foreach ($machine in $sourceMachines) {
      if ($machine.TransferSummary.value__ -eq [TransferState]::Running) {
        $tieredAfsSummaries += Get-SmsState -Name $machine.Job -computername $machine.SourceDevice -TransferVolumeDetail -VolumeTypes TAFSEnabled
      }
    }
    $transferSummaries | Microsoft.PowerShell.Utility\Add-Member -MemberType NoteProperty -Name TieredAFSVolumes -Value $tieredAfsSummaries
  }
  $result = $transferSummaries
}
catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result = $result; Status = $status; Error = $exception } | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSTransferSummary ##
function Get-WACSMSWinEvent {
<#

.SYNOPSIS
Get Windows Event

.DESCRIPTION
Get Windows Event

.ROLE
Readers

#>

Param(
    [Parameter(Mandatory = $false)]
    [string]$computerName,

    [Parameter(Mandatory = $false)]
    [int]$maxEvents
)
Import-Module Microsoft.PowerShell.Utility

$parameters = @{}
$filterHashTable = @{}
if ($maxEvents) {
    $parameters.Add('MaxEvents', $maxEvents);
}
if ($computerName) {
    $parameters.Add('ComputerName', $computerName);
}
$filterHashTable.Add('LogName', 'SmsDebug');
$parameters.Add('FilterHashtable', $filterHashTable);

$status=1
$exception = $null
try {
#   $result = Get-WinEvent -FilterHashtable @{LogName = "SmsDebug"} -MaxEvents 10 -ComputerName brnichol-vm02.cfdev.nttest.microsoft.com
$result = Get-Host
# $result = winrm set winrm/config/client '@{TrustedHosts="*"}'
# $result = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Get-WACSMSWinEvent ##
function Get-WACSMSWindowsFeature {
<#

.SYNOPSIS
Get Windows Feature

.DESCRIPTION
Get Windows Feature

.ROLE
Readers

#>

<#########################################################################################################
 # File: Get-WindowsFeature.ps1
 #
 # .DESCRIPTION
 #
 #  invokes Get-WindowsFeature
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #########################################################################################################>

 #  Get-WindowsFeature -Name 'RSAT-Clustering-PowerShell'

 Param(
    [Parameter(Mandatory = $true)]
    [array]$names
)
Import-Module ServerManager

$parameters = @{
    'Name' = $names;
}

Get-WindowsFeature @parameters

}
## [END] Get-WACSMSWindowsFeature ##
function Import-WACSMSSmsModule {
<#

.SYNOPSIS
Import Sms Module

.DESCRIPTION
Import Sms Module

.ROLE
Administrators

#>


Param([string]$module)
Import-Module $module

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')

# $status=1
# $exception = $null
# try {
#   $result = Get-SmsState @parameters
# } catch {
#   $exception = $_ # the exception
#   $status = 0
# }
# @{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Import-WACSMSSmsModule ##
function Install-WACSMSSmsFeature {
<#

.SYNOPSIS
Install Sms Feature

.DESCRIPTION
Install Sms Feature

.ROLE
Administrators

#>

<#########################################################################################################
 # File: install-smsfeature.ps1
 #
 # .DESCRIPTION
 #
 #  invokes Install-WindowsFeature
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #########################################################################################################>
 Import-Module ServerManager
 Install-WindowsFeature -Name 'SMS','SMS-PROXY' -IncludeAllSubFeature -IncludeManagementTools

}
## [END] Install-WACSMSSmsFeature ##
function Install-WACSMSSmsProxy {
<#

.SYNOPSIS
Install Sms Proxy

.DESCRIPTION
Install Sms Proxy

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$userName,

    [Parameter(Mandatory = $true)]
    [string]$password,

    [Parameter(Mandatory = $true)]
    [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

# Install-WindowsFeature -Name "Web-Server" -IncludeAllSubFeature -IncludeManagementTools -ComputerName "Server1" -Credential "contoso.com\PattiFul"

function Get-Cred() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$password,

        [Parameter(Mandatory = $true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$cred = Get-Cred -Password $password -UserName $userName

$parameters = @{
    'Name'         = 'SMS-Proxy';
    'ComputerName' = $computerName;
    'Credential'   = $cred;
    'ErrorAction'  = 'Stop';
}

Install-WindowsFeature @parameters | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5

}
## [END] Install-WACSMSSmsProxy ##
function Install-WACSMSWindowsFeature {
<#

.SYNOPSIS
Install Windows Feature

.DESCRIPTION
Install Windows Feature

.ROLE
Administrators

#>

<#########################################################################################################
 # File: Install-WindowsFeature.ps1
 #
 # .DESCRIPTION
 #
 #  invokes Install-WindowsFeature
 #
 #  Copyright (c) Microsoft Corp 2018.
 #
 #########################################################################################################>

 #  Install-WindowsFeature -Name 'RSAT-Clustering-PowerShell'

 Param(
    [Parameter(Mandatory = $true)]
    [string]$name
)
Import-Module ServerManager

$parameters = @{
    'Name' = $name;
}

Install-WindowsFeature @parameters

}
## [END] Install-WACSMSWindowsFeature ##
function Invoke-WACSMSCommand {
<#

.SYNOPSIS
Invoke Command

.DESCRIPTION
Invoke Command

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory = $true)]
  [string]$computerName
)
Import-Module Microsoft.PowerShell.Utility
# $parameters = @{}
# $parameters.Add('ErrorAction', 'Stop')
# $parameters.Add('Name', $jobName)

# $status=1
# $exception = $null
# try {
#   $result = Start-SmsInventory @parameters
# } catch {
#   $exception = $_ # the exception
#   $status = 0
# }
# @{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

$command = 'Register-SmsProxy ' + $computerName + '-Force'

$sb = {param($p1) Invoke-Expression $p1;}
# Invoke-Command -ComputerName brnichol-vm02 $sb -ArgumentList $command

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('ComputerName', 'brnichol-vm02')
$parameters.Add('ArgumentList', $command)
$parameters.Add('UseSSL', $true)

$status=1
$exception = $null
try {
  $result = Invoke-Command $sb @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Invoke-WACSMSCommand ##
function New-WACSMSSmsCutover {
<#

.SYNOPSIS
New Sms Cutover

.DESCRIPTION
New Sms Cutover

.ROLE
Administrators

#>

Param(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$false)]
  [string]$destUserName,

  [Parameter(Mandatory=$false)]
  [string]$destPassword,

  [Parameter(Mandatory=$false)]
  [bool]$editDestCredentials,

  [Parameter(Mandatory=$false)]
  [bool]$editSourceCredentials,

  [Parameter(Mandatory=$false)]
  [string]$sourceUserName,

  [Parameter(Mandatory=$false)]
  [string]$sourcePassword,

  [Parameter(Mandatory=$false)]
  [bool]$editAdCredentials,

  [Parameter(Mandatory=$false)]
  [string]$adUserName,

  [Parameter(Mandatory=$false)]
  [string]$adPassword

)
Import-Module StorageMigrationService

function Get-Cred()
{
  Param(
    [Parameter(Mandatory=$true)]
    [string]$password,

    [Parameter(Mandatory=$true)]
    [string]$userName
  )
  Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

  $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
  return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
  'Name' = $jobName;
  'Force' = $true;
}

if ($editDestCredentials)
{
    $destCred = Get-Cred -Password $destPassword -UserName $destUserName
    $parameters.Add('DestinationCredential', $destCred)
}

if ($editSourceCredentials)
{
    $srcCred = Get-Cred -Password $sourcePassword -UserName $sourceUserName
    $parameters.Add('SourceCredential', $srcCred)
}

if ($editAdCredentials){
    $adCred = Get-Cred -Password $adPassword -UserName $adUserName
    $parameters.Add('ADCredential', $adCred)
}

New-SmsCutover @parameters

}
## [END] New-WACSMSSmsCutover ##
function New-WACSMSSmsInventory {
<#

.SYNOPSIS
New Sms Sms Inventory

.DESCRIPTION
New Sms Sms Inventory

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$userName,

    [Parameter(Mandatory = $true)]
    [string]$password,

    [Parameter(Mandatory = $true)]
    [string]$sourceOSEnum,

    [Parameter(Mandatory = $true)]
    [array]$computerNames,

    [bool]$adminShares,

    # [bool]$dfsr

    [bool]$dfsn

    # [bool]$migrateFailoverClusters
)
Import-Module StorageMigrationService

function Get-Cred() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$password,

        [Parameter(Mandatory = $true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$cred = Get-Cred -Password $password -UserName $userName

$parameters = @{
    'Name'             = $jobName;
    'SourceCredential' = $cred;
    'Force'            = $true;
}

if (!($computerNames -eq '')) {
    $parameters.Add('ComputerName', $computerNames)
}

if ($adminShares) {
    $parameters.Add('IncludeAdminShares', $adminShares)
}

# if ($dfsr) {
#     $parameters.Add('DFSR', $dfsr)
# }

if ($dfsn) {
    $parameters.Add('IncludeDFSN', $dfsn)
}

# if ($migrateFailoverClusters) {
#     $parameters.Add('MigrateFailoverClusters', $migrateFailoverClusters)
# }

if ($sourceOSEnum -eq 1) {
    $parameters.Add('SourceType', 'Linux');
} else {
    if ($sourceOSEnum -eq 2) {
        $parameters.Add('SourceType', 'Netapp');
    }
}

New-SmsInventory @parameters

}
## [END] New-WACSMSSmsInventory ##
function New-WACSMSSmsNasPrescan {
<#

.SYNOPSIS
New Sms Nas Prescan

.DESCRIPTION
New Sms Nas Prescan

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$controllerIpOrDomain,

    [Parameter(Mandatory = $true)]
    [string]$userName,

    [Parameter(Mandatory = $true)]
    [string]$password
)
Import-Module StorageMigrationService

function Get-Cred() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$password,

        [Parameter(Mandatory = $true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$cred = Get-Cred -Password $password -UserName $userName

$parameters = @{
    'Name' = $jobName;
    'NasControllerAddress' = $controllerIpOrDomain;
    'NasControllerCredential' = $cred;
    'Overwrite' = $true;
    'Force' = $true;
}

New-SmsNasPrescan @parameters

}
## [END] New-WACSMSSmsNasPrescan ##
function New-WACSMSSmsTransfer {
<#

.SYNOPSIS
New Sms Transfer

.DESCRIPTION
New Sms Transfer

.ROLE
Administrators

#>

Param(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$false)]
  [string]$sourceUserName,

  [Parameter(Mandatory=$false)]
  [string]$sourcePassword,

  [Parameter(Mandatory=$true)]
  [string]$destUserName,

  [Parameter(Mandatory=$true)]
  [string]$destPassword,

  [Parameter(Mandatory=$false)]
  [bool]$editSrc
)
Import-Module StorageMigrationService

function Get-Cred()
{
  Param(
    [Parameter(Mandatory=$true)]
    [string]$password,

    [Parameter(Mandatory=$true)]
    [string]$userName
  )
  Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

  $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
  return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$destCred = Get-Cred -Password $destPassword -UserName $destUserName
$parameters = @{
  'Name' = $jobName;
  'DestinationCredential' = $destCred;
  'Force' = $true;
}

if ($editSrc) {
  $sourceCred = Get-Cred -Password $sourcePassword -UserName $sourceUserName
  $parameters.Add('SourceCredential', $sourceCred)
}

New-SmsTransfer @parameters

}
## [END] New-WACSMSSmsTransfer ##
function Register-WACSMSSmsProxy {
<#

.SYNOPSIS
Register Sms Proxy

.DESCRIPTION
Register Sms Proxy

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$computerName
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

# $registerProxy = Register-SmsProxy $computerName -Force
# $registerProxyJson = $registerProxy | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5

# Write-Output $registerProxyJson

$parameters = @{}
$parameters.Add('ComputerName', $computerName)
$parameters.Add('Force', $true)
Register-SmsProxy @parameters

}
## [END] Register-WACSMSSmsProxy ##
function Remove-WACSMSSmsCutoverPairing {
<#

.SYNOPSIS
Remove Sms Cutover Pairing

.DESCRIPTION
Remove Sms Cutover Pairing

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService

Remove-SmsCutoverPairing -Name $jobName -ComputerName $computerName -Force

}
## [END] Remove-WACSMSSmsCutoverPairing ##
function Remove-WACSMSSmsInventory {
<#

.SYNOPSIS
Remove Sms Inventory
.DESCRIPTION
Remove Sms Inventory

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string[]]$jobName
)
Import-Module StorageMigrationService

foreach ($job in $jobName) {
  Remove-SmsInventory -Name $job -Force
}

}
## [END] Remove-WACSMSSmsInventory ##
function Remove-WACSMSSmsTransferPairing {
<#

.SYNOPSIS
Remove Sms Transfer Pairing

.DESCRIPTION
Remove Sms Transfer Pairing

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$true)]
  [string]$computerName
)
Import-Module StorageMigrationService

Remove-SmsTransferPairing -Name $jobName -ComputerName $computerName -Force

}
## [END] Remove-WACSMSSmsTransferPairing ##
function Resume-WACSMSSmsCutover {
<#

.SYNOPSIS
Resume Sms Cutover

.DESCRIPTION
Resume Sms Cutover

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService

Resume-SmsCutover -Name $jobName -Force

}
## [END] Resume-WACSMSSmsCutover ##
function Resume-WACSMSSmsTransfer {
<#

.SYNOPSIS
Resume Sms Transfer

.DESCRIPTION
Resume Sms Transfer

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService

Resume-SmsTransfer -Name $jobName -Force

}
## [END] Resume-WACSMSSmsTransfer ##
function Set-WACSMSSmsCutover {
<#

.SYNOPSIS
Set Sms Cutover

.DESCRIPTION
Set Sms Cutover

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$false)]
    [string]$destUserName,

    [Parameter(Mandatory=$false)]
    [string]$destPassword,

    [Parameter(Mandatory=$false)]
    [boolean]$editDestCredentials,

    [Parameter(Mandatory=$false)]
    [string]$sourceUserName,

    [Parameter(Mandatory=$false)]
    [string]$sourcePassword,

    [Parameter(Mandatory=$false)]
    [boolean]$editSourceCredentials,

    [Parameter(Mandatory=$false)]
    [boolean]$editSourceMaxRebootWait,

    [Parameter(Mandatory=$false)]
    [int]$sourceMaxRebootWait,

    [Parameter(Mandatory=$false)]
    [bool]$editAdCredentials,

    [Parameter(Mandatory=$false)]
    [string]$adUserName,

    [Parameter(Mandatory=$false)]
    [string]$adPassword
)
Import-Module  StorageMigrationService, Microsoft.PowerShell.Utility

function Get-Cred()
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
                'Name' = $jobName;
                'Force' = $true;
               }

if ($editSourceCredentials)
{
    $srcCred = Get-Cred -Password $sourcePassword -UserName $sourceUserName
    $parameters.Add('SourceCredential', $srcCred)
}

if ($editDestCredentials)
{
    $destCred = Get-Cred -Password $destPassword -UserName $destUserName
    $parameters.Add('DestinationCredential', $destCred)
}

if ($editAdCredentials)
{
    $adCred = Get-Cred -Password $adPassword -UserName $adUserName
    $parameters.Add('ADCredential', $adCred)
}

if($editSourceMaxRebootWait) {
    $parameters.Add('CutoverTimeout', $sourceMaxRebootWait)
}

$parameters.Add('ErrorAction', 'Stop')

$status=1
$exception = $null
try {
  $result = Set-SmsCutover @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Set-WACSMSSmsCutover ##
function Set-WACSMSSmsCutoverPairing {
<#

.SYNOPSIS
Set Sms Cutover Pairing

.DESCRIPTION
Set Sms Cutover Pairing

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$true)]
    [string]$computerName,

    [Parameter(Mandatory=$true)]
    [string]$newComputerName,

    [Parameter(Mandatory=$true)]
    [bool]$specifyNewName,

    [Parameter(Mandatory=$true)]
    [psobject]$networkPairings,

    [Parameter(Mandatory=$true)]
    [psobject]$staticSourceIp
)
Import-Module  StorageMigrationService, Microsoft.PowerShell.Utility

function Get-Cred()
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
                'Name' = $jobName;
                'Force' = $true;
                'ComputerName' = $computerName;
               }

$networkPairingHashtable = @{}
$networkPairings | ForEach-Object { $networkPairingHashtable[$_.Name] = $_.Value }

if($networkPairingHashtable.Count -gt 0) {
    $parameters.Add('NetworkPairings', $networkPairingHashtable);
}

$staticSourceIpHashtable = @{}
$staticSourceIp | ForEach-Object { $staticSourceIpHashtable[$_.Name] = $_.Value }

if($staticSourceIpHashtable.Count -gt 0) {
    $parameters.Add('StaticSourceIP', $staticSourceIpHashtable);
}

if($specifyNewName) {
    $parameters.Add('NewComputerName', $newComputerName);
}

$parameters.Add('ErrorAction', 'Stop')

$status=1
$exception = $null
try {
  $result = Set-SmsCutoverPairing @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Set-WACSMSSmsCutoverPairing ##
function Set-WACSMSSmsInventory {
<#

.SYNOPSIS
Set Sms Inventory

.DESCRIPTION
Set Sms Inventory

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [string]$userName,

    [string]$password,

    [array]$computerNames,

    [string]$linuxUsername,

    [Parameter(Mandatory = $true)]
    [bool]$editLinuxUsername,

    [string]$linuxPassword,

    [Parameter(Mandatory = $true)]
    [bool]$editLinuxPassword,

    [string]$privateKey,

    [Parameter(Mandatory = $true)]
    [bool]$editPrivateKey,

    [string]$passPhrase,

    [Parameter(Mandatory = $true)]
    [bool]$editPassPhrase,

    [string]$publicKeyFingerprint,

    [Parameter(Mandatory = $true)]
    [bool]$editPublicKeyFingerprint,

    [Parameter(Mandatory = $true)]
    [string]$sourceOSEnum,

    [Parameter(Mandatory = $true)]
    [bool]$adminShares,

    # [bool]$dfsr

    [bool]$dfsn,

    # [bool]$migrateFailoverClusters

    [Parameter(Mandatory = $true)]
    [bool]$editCredentials,

    [Parameter(Mandatory = $true)]
    [bool]$editDevices,

    [Parameter(Mandatory = $true)]
    [bool]$editAdminShares
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Security

function Get-Cred() {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$password,

        [Parameter(Mandatory = $true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
    'Name'  = $jobName;
    'Force' = $true;
}

if ($editDevices) {
    $parameters.Add('ComputerName', $computerNames)
}

if ($editCredentials) {
    $cred = Get-Cred -Password $password -UserName $userName
    $parameters.Add('SourceCredential', $cred)
}

if ($sourceOSEnum -eq 1) {
    if ($editLinuxUsername) {
        $parameters.Add('SourceHostUsername', $linuxUsername);
    }

    if ($editLinuxPassword) {
        $secureLinuxPassword = ConvertTo-SecureString -String $linuxPassword -AsPlainText -Force
        $parameters.Add('SourceHostPassword', $secureLinuxPassword);
    }

    if ($editPrivateKey) {
        $securePrivateKey = ConvertTo-SecureString -String $privateKey -AsPlainText -Force
        $parameters.Add('SourceHostPrivateKey', $securePrivateKey);
    }

    if ($editPassPhrase) {
        $securePassPhrase = ConvertTo-SecureString -String $passPhrase -AsPlainText -Force
        $parameters.Add('SourceHostPassphrase', $securePassPhrase);
    }

    if ($editPublicKeyFingerprint) {
        $parameters.Add('SourceHostFingerprint', $publicKeyFingerprint);
    }
}

if ($editAdminShares) {
    $parameters.Add('IncludeAdminShares', $adminShares)
}

# if ($dfsr) {
#     $parameters.Add('DFSR', $dfsr)
# }

if ($dfsn) {
    $parameters.Add('DFSN', $dfsn)
}

# if ($migrateFailoverClusters) {
#     $parameters.Add('MigrateFailoverClusters', $migrateFailoverClusters)
# }

Set-SmsInventory @parameters

}
## [END] Set-WACSMSSmsInventory ##
function Set-WACSMSSmsTransfer {
<#

.SYNOPSIS
Set Sms Transfer

.DESCRIPTION
Set Sms Transfer

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$false)]
    [string]$sourceUserName,

    [Parameter(Mandatory=$false)]
    [string]$sourcePassword,

    [Parameter(Mandatory=$false)]
    [string]$destUserName,

    [Parameter(Mandatory=$false)]
    [string]$destPassword,

    [Parameter(Mandatory=$false)]
    [bool]$skipMovePreExisting,

    [Parameter(Mandatory=$false)]
    [bool]$overrideTransferValidation,

    [Parameter(Mandatory=$false)]
    [int]$maxDuration,

    [Parameter(Mandatory=$false)]
    [int]$fileRetryInterval,

    [Parameter(Mandatory=$false)]
    [int]$fileRetryCount,

    [Parameter(Mandatory=$false)]
    [int]$transferType,

    [Parameter(Mandatory=$false)]
    [int]$checksumType,

    [Parameter(Mandatory=$false)]
    [bool]$editSourceCredentials,

    [Parameter(Mandatory=$false)]
    [bool]$editDestCredentials,

    [Parameter(Mandatory=$true)]
    [bool]$isUsersSupportedOrchestrator,

    [Parameter(Mandatory=$false)]
    [int]$usersMigrationSelectedEnum
)
Import-Module  StorageMigrationService

function Get-Cred()
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
                'Name' = $jobName;
                'Force' = $true;
               }

# if($skipPreexisting) {
    $parameters.Add('SkipMovePreExisting', $skipMovePreExisting)
    $parameters.Add('MaxDuration', $maxDuration)
    $parameters.Add('FileRetryIntervalInSec', $fileRetryInterval)
    $parameters.Add('FileRetryCount', $fileRetryCount)
    $parameters.Add('TransferType', $transferType)
    $parameters.Add('ChecksumType', $checksumType)

if ($editSourceCredentials)
{
    $sourceCred = Get-Cred -Password $sourcePassword -UserName $sourceUserName
    $parameters.Add('Credential', $sourceCred)
}

if ($editDestCredentials)
{
    $destCred = Get-Cred -Password $destPassword -UserName $destUserName
    $parameters.Add('DestinationCredential', $destCred)
}

if($isUsersSupportedOrchestrator)
{
    if ($usersMigrationSelectedEnum -eq 1){
      $parameters.Add('SecurityMigrationOption', 'MigrateAndRenameConflictingAccounts');
    } elseif ($usersMigrationSelectedEnum -eq 2) {
      $parameters.Add('SecurityMigrationOption', 'MigrateAndMergeConflictingAccounts');
    } elseif ($usersMigrationSelectedEnum -eq 3) {
      $parameters.Add('SecurityMigrationOption', 'SkipSecurityMigration');
    }
}

if ($overrideTransferValidation)
{
    $parameters.Add('OverrideTransferValidation', $overrideTransferValidation)
}

Set-SmsTransfer @parameters

}
## [END] Set-WACSMSSmsTransfer ##
function Set-WACSMSSmsTransferExcludedShares {
<#

.SYNOPSIS
Set Sms Transfer Excluded Shares

.DESCRIPTION
Set Sms Transfer Excluded Shares

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$true)]
    [string]$computerName,

    [Parameter(Mandatory=$true)]
    [array]$excludedShares
)
Import-Module  StorageMigrationService

$parameters = @{
                'Name' = $jobName;
                'Force' = $true;
                'ComputerName' = $computerName;
                'ExcludeSMBShares' = $excludedShares;
               }
Set-SmsTransferPairing @parameters

}
## [END] Set-WACSMSSmsTransferExcludedShares ##
function Set-WACSMSSmsTransferExcludedSharesAndAFS {
<#

.SYNOPSIS
Set Sms Transfer Excluded Shares and AFs

.DESCRIPTION
Set Sms Transfer Excluded Shares and AFs

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName,

    [Parameter(Mandatory = $true)]
    [string]$computerName,

    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [array]$excludedShares,

    [Parameter(Mandatory = $true)]
    [psobject]$afsPairings
)
Import-Module StorageMigrationService, Microsoft.PowerShell.Utility

if ($excludedShares.Count -ne 0) {
    $parameters = @{
        'Name'             = $jobName;
        'Force'            = $true;
        'ComputerName'     = $computerName;
        'ExcludeSMBShares' = $excludedShares;
    }
    Set-SmsTransferPairing @parameters
}

# New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass

# $volumePairingHashtable = @{}
# $volumePairings | ForEach-Object { $volumePairingHashtable[$_.Name] = $_.Value }

# if($volumePairingHashtable.Count -gt 0) {
#     $parameters.Add('VolumePairings', $volumePairingHashtable);
# }

$afsFinalList = @()
$afsPairings | ForEach-Object {
    $afsFinalList += New-Object Microsoft.StorageMigration.Commands.TieredAFSVolumeSetting $_.Volume, $_.IsTieredAFSEnabled, $_.MinimumFreeSpace
}

if ($afsFinalList.Count -gt 0) {
    $afsParameters = @{
        'Name'                    = $jobName;
        'ComputerName'            = $computerName;
        'TieredAFSVolumeSettings' = $afsFinalList;
        'Force'                   = $true;
    }
    Set-SmsTransferPairing @afsParameters
}

}
## [END] Set-WACSMSSmsTransferExcludedSharesAndAFS ##
function Set-WACSMSSmsTransferPairing {
<#

.SYNOPSIS
Set Sms Transfer Pairings

.DESCRIPTION
Set Sms Transfer Pairings

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$true)]
    [string]$computerName,

    [Parameter(Mandatory=$true)]
    [string]$destinationComputerName,

    # [Parameter(Mandatory=$true)]
    # [string]$destUserName,

    # [Parameter(Mandatory=$true)]
    # [string]$destPassword,

    # [Parameter(Mandatory=$true)]
    # [psobject]$devicePairings,

    # [bool]$editSourceCredentials,

    # [bool]$editDestCredentials,

    [bool]$editDevices
)
Import-Module  StorageMigrationService

function Get-Cred()
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$true)]
        [string]$userName
    )
    Import-Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility

    $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
    return New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $userName, $securePass
}

$parameters = @{
                'Name' = $jobName;
                'Force' = $true;
                'ComputerName' = $computerName;
                'DestinationComputerName' = $destinationComputerName;
               }

# if ($editDevices)
# {
#     # since the input object $devicePairings is a psObject, we need to make a hashtable
#     $deviceHashtable = @{}
#     $devicePairings.psobject.properties | ForEach-Object { $deviceHashtable[$_.Name] = $_.Value }

#     $parameters.Add('DevicePairings', $deviceHashtable)
# }

# if ($editSourceCredentials)
# {
#     $sourceCred = Get-Cred -Password $sourcePassword -UserName $sourceUserName
#     $parameters.Add('SourceCredentials', $sourceCred)
# }

# if ($editDestCredentials)
# {
#     $destCred = Get-Cred -Password $destPassword -UserName $destUserName
#     $parameters.Add('DestinationCredentials', $destCred)
# }

Set-SmsTransferPairing @parameters

# $parameters = @{}
# $parameters.Add('ErrorAction', 'Stop')

# $status=1
# $exception = $null
# try {
#   $result = Get-SmsState @parameters
# } catch {
#   $exception = $_ # the exception
#   $status = 0
# }
# @{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Set-WACSMSSmsTransferPairing ##
function Set-WACSMSSmsTransferVolumePairings {
<#

.SYNOPSIS
Set Sms Transfer Volume Pairings

.DESCRIPTION
Set Sms Transfer Volume Pairings

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$jobName,

    [Parameter(Mandatory=$true)]
    [string]$computerName,

    [Parameter(Mandatory=$true)]
    [psobject]$volumePairings
)
Import-Module  StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('ComputerName', $computerName)
$parameters.Add('Force', $true)

$volumePairingHashtable = @{}
$volumePairings | ForEach-Object { $volumePairingHashtable[$_.Name] = $_.Value }

if($volumePairingHashtable.Count -gt 0) {
    $parameters.Add('VolumePairings', $volumePairingHashtable);
}

$status=1
$exception = $null
try {
  $result = Set-SmsTransferPairing @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Set-WACSMSSmsTransferVolumePairings ##
function Start-WACSMSSmsCutover {
<#

.SYNOPSIS
Start Sms Cutover

.DESCRIPTION
Start Sms Cutover

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Start-SmsCutover -Name $jobName -Force

}
## [END] Start-WACSMSSmsCutover ##
function Start-WACSMSSmsInventory {
<#

.SYNOPSIS
Start Sms Inventory

.DESCRIPTION
Start Sms Inventory

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Start-SmsInventory -Name $jobName -Force

}
## [END] Start-WACSMSSmsInventory ##
function Start-WACSMSSmsNasPrescan {
<#

.SYNOPSIS
Start Sms Nas Prescan

.DESCRIPTION
Start Sms Nas Prescan

.ROLE
Administrators

#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$jobName
)
Import-Module StorageMigrationService

Start-SmsNasPrescan -Name $jobName -Force

}
## [END] Start-WACSMSSmsNasPrescan ##
function Start-WACSMSSmsTransfer {
<#

.SYNOPSIS
Start Sms Transfer

.DESCRIPTION
Start Sms Transfer

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Start-SmsTransfer -Name $jobName -Force

}
## [END] Start-WACSMSSmsTransfer ##
function Stop-WACSMSSmsCutover {
<#

.SYNOPSIS
Start Sms Cutover

.DESCRIPTION
Start Sms Cutover

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module StorageMigrationService
Stop-SmsCutover -Name $jobName -Force

}
## [END] Stop-WACSMSSmsCutover ##
function Stop-WACSMSSmsInventory {
<#

.SYNOPSIS
Stop Sms Inventory

.DESCRIPTION
Stop Sms Inventory

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Stop-SmsInventory -Name $jobName -Force

}
## [END] Stop-WACSMSSmsInventory ##
function Stop-WACSMSSmsTransfer {
<#

.SYNOPSIS
Stop Sms Transfer

.DESCRIPTION
Stop Sms Transfer

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Stop-SmsTransfer -Name $jobName -Force

}
## [END] Stop-WACSMSSmsTransfer ##
function Suspend-WACSMSSmsInventory {
<#

.SYNOPSIS
Suspend Sms Inventory

.DESCRIPTION
Suspend Sms Inventory

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName
)
Import-Module  StorageMigrationService

Suspend-SmsInventory -Name $jobName -Force

}
## [END] Suspend-WACSMSSmsInventory ##
function Suspend-WACSMSSmsTransfer {
<#

.SYNOPSIS
Suspend Sms Transfer

.DESCRIPTION
Suspend Sms Transfer

.ROLE
Administrators

#>

Param
(
    [Parameter(Mandatory = $true)]
    [string]$jobName
)
Import-Module  StorageMigrationService

Suspend-SmsTransfer -Name $jobName -Force

}
## [END] Suspend-WACSMSSmsTransfer ##
function Test-WACSMSLocal {
<#

.SYNOPSIS
Test Local

.DESCRIPTION
Test Local

.ROLE
Readers

#>

Param
(
)
Import-Module  Microsoft.PowerShell.Utility

$newTempFile = [System.IO.Path]::GetTempFileName()
echo 'sdfsdf' >> $newTempFile

Write-Output $newTempFile | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Test-WACSMSLocal ##
function Test-WACSMSSmsMigration {
<#

.SYNOPSIS
Test Sms Migration

.DESCRIPTION
Test Sms Migration

.ROLE
Administrators

#>

Param
(
  [Parameter(Mandatory=$true)]
  [string]$jobName,

  [Parameter(Mandatory=$true)]
  [string]$computerName,

  [Parameter(Mandatory=$true)]
  [string]$operation
)
Import-Module  StorageMigrationService, Microsoft.PowerShell.Utility

$parameters = @{}
$parameters.Add('ErrorAction', 'Stop')
$parameters.Add('Name', $jobName)
$parameters.Add('ComputerName', $computerName);
$parameters.Add('Operation', $operation);

$status=1
$exception = $null
try {
  $result = Test-SmsMigration @parameters
} catch {
  $exception = $_ # the exception
  $status = 0
}
@{Result=$result;Status=$status;Error=$exception} | Microsoft.PowerShell.Utility\ConvertTo-Json -depth 5

}
## [END] Test-WACSMSSmsMigration ##
function Clear-WACSMSEventLogChannel {
<#

.SYNOPSIS
Clear the event log channel specified.

.DESCRIPTION
Clear the event log channel specified.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>
 
Param(
    [string]$channel
)

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
}
## [END] Clear-WACSMSEventLogChannel ##
function Clear-WACSMSEventLogChannelAfterExport {
<#

.SYNOPSIS
Clear the event log channel after export the event log channel file (.evtx).

.DESCRIPTION
Clear the event log channel after export the event log channel file (.evtx).
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /ow:true

[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 

return $ResultFile

}
## [END] Clear-WACSMSEventLogChannelAfterExport ##
function Export-WACSMSEventLogChannel {
<#

.SYNOPSIS
Export the event log channel file (.evtx) with filter XML.

.DESCRIPTION
Export the event log channel file (.evtx) with filter XML.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [string]$filterXml
)

$segments = $channel.Split("-")
$name = $segments[-1]

$randomString = [GUID]::NewGuid().ToString()
$ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
$ResultFile = $ResultFile -replace "/", "-"

wevtutil epl "$channel" "$ResultFile" /q:"$filterXml" /ow:true

return $ResultFile

}
## [END] Export-WACSMSEventLogChannel ##
function Get-WACSMSCimEventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Server Manager CIM provider.

.DESCRIPTION
Get Log records of event channel by using Server Manager CIM provider.

.ROLE
Readers

#>

Param(
    [string]$FilterXml,
    [bool]$ReverseDirection
)

import-module CimCmdlets

$machineName = [System.Net.DNS]::GetHostByName('').HostName
Invoke-CimMethod -Namespace root/Microsoft/Windows/ServerManager -ClassName MSFT_ServerManagerTasks -MethodName GetServerEventDetailEx -Arguments @{FilterXml = $FilterXml; ReverseDirection = $ReverseDirection; } |
    ForEach-Object {
        $result = $_
        if ($result.PSObject.Properties.Match('ItemValue').Count) {
            foreach ($item in $result.ItemValue) {
                @{
                    ItemValue = 
                    @{
                        Description  = $item.description
                        Id           = $item.id
                        Level        = $item.level
                        Log          = $item.log
                        Source       = $item.source
                        Timestamp    = $item.timestamp
                        __ServerName = $machineName
                    }
                }
            }
        }
    }

}
## [END] Get-WACSMSCimEventLogRecords ##
function Get-WACSMSClusterEvents {
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
## [END] Get-WACSMSClusterEvents ##
function Get-WACSMSEventLogDisplayName {
<#

.SYNOPSIS
Get the EventLog log name and display name by using Get-EventLog cmdlet.

.DESCRIPTION
Get the EventLog log name and display name by using Get-EventLog cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>


return (Get-EventLog -LogName * | Microsoft.PowerShell.Utility\Select-Object Log,LogDisplayName)
}
## [END] Get-WACSMSEventLogDisplayName ##
function Get-WACSMSEventLogFilteredCount {
<#

.SYNOPSIS
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$filterXml
)

return (Get-WinEvent -FilterXml "$filterXml" -ErrorAction 'SilentlyContinue').count
}
## [END] Get-WACSMSEventLogFilteredCount ##
function Get-WACSMSEventLogRecords {
<#

.SYNOPSIS
Get Log records of event channel by using Get-WinEvent cmdlet.

.DESCRIPTION
Get Log records of event channel by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers
#>

Param(
    [string]
    $filterXml,
    [bool]
    $reverseDirection
)

$ErrorActionPreference = 'SilentlyContinue'
Import-Module Microsoft.PowerShell.Diagnostics;

#
# Prepare parameters for command Get-WinEvent
#
$winEventscmdParams = @{
    FilterXml = $filterXml;
    Oldest    = !$reverseDirection;
}

Get-WinEvent  @winEventscmdParams -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object recordId,
id, 
@{Name = "Log"; Expression = {$_."logname"}}, 
level, 
timeCreated, 
machineName, 
@{Name = "Source"; Expression = {$_."ProviderName"}}, 
@{Name = "Description"; Expression = {$_."Message"}}



}
## [END] Get-WACSMSEventLogRecords ##
function Get-WACSMSEventLogSummary {
<#

.SYNOPSIS
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.

.DESCRIPTION
Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

Param(
    [string]$channel
)

Import-Module Microsoft.PowerShell.Diagnostics

$channelList = $channel.split(",")

Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue |`
    Microsoft.PowerShell.Utility\Select-Object LogName, IsEnabled, RecordCount, IsClassicLog, LogType, OwningProviderName
}
## [END] Get-WACSMSEventLogSummary ##
function Set-WACSMSEventLogChannelStatus {
 <#

.SYNOPSIS
 Change the current status (Enabled/Disabled) for the selected channel.

.DESCRIPTION
Change the current status (Enabled/Disabled) for the selected channel.
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

Param(
    [string]$channel,
    [boolean]$status
)

$ch = Get-WinEvent -ListLog $channel
$ch.set_IsEnabled($status)
$ch.SaveChanges()
}
## [END] Set-WACSMSEventLogChannelStatus ##

# SIG # Begin signature block
# MIIoUQYJKoZIhvcNAQcCoIIoQjCCKD4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDCpsPlcK7+0w+l
# no95z5bLDbXfoZs1k8AwXgxR6ETVEKCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGiIwghoeAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAASEmOIS4HijMV0AAAAA
# BIQwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKe5
# H1M0K46EuWekrtggicF/wTiqE3DpAv4SOYPmPOv+MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAJ8NGqtx9X04rmUt7KDXCCmg/tbjcqa0nddSg
# FRAlRYKgLfYLX7qAlaVpLtM6NAFsgRVWPqxtO3ZAiuw4z8rnRPcV9+f4/751FHIB
# jNm7hmjU63a5eCYTWT1Z3PBeEOlf9Qta3Ufxqd9W3FkSlCidNq/tT7bzINRPKjaO
# MaT5iFwH6zfqSFW52a0eL1DKFlhEi2ekXE4NP3pfcxi2WIvqMY+tXvCSa9NVLz3/
# Y5RXemXvaC9my6x3XtMMtylm6X0S0oIgqMEO+NTUQ5nPpww5Xs8IWq6lxP8jv829
# dtYjMgQxiUkDIAeDXxOSxIi5ag7ihgINp9+tPyby4tk7fUsKL6GCF6wwgheoBgor
# BgEEAYI3AwMBMYIXmDCCF5QGCSqGSIb3DQEHAqCCF4UwgheBAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDapPsT+f9QzKbRlnIANKd+OPUWL/6Gz2/V
# xlBY8rnVUgIGaQJQq5/KGBIyMDI1MTExMDE3MTYyNS45NFowBIACAfSggdmkgdYw
# gdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMe
# blNoaWVsZCBUU1MgRVNOOjZGMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR+zCCBygwggUQoAMCAQICEzMAAAIcCVUV
# 18NZB9EAAQAAAhwwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjUwODE0MTg0ODMxWhcNMjYxMTEzMTg0ODMxWjCB0zELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046NkYxQS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCj
# DTEQBRoUjLIshd4XN4jwgrIE43a7QOvTYhITmn0bkJRd+cW7ZLQTWBYIy8Namilf
# qVHGOaCepovcG2daUFVOjzFQ1Fm7beJ7hgEwAkHtS3qaeqcdXC8MnEY7hMPdKesJ
# 37KDfkH1AV6Orejj44HK9ePKdrKlnK6RxBouwpC+jETwSUcfvNw5cQlaZTeudfNp
# b9LhIfc4+GhRtNNzLqdSArHmlFaJDbhQQ8tjNzEYmOqOTP4aIJYY8UcMx1bzqVpa
# +YKyWi5A+w3Z4GTx3ElwRmZbiXqnhO2Ghdx97EQD1h1hozPXRoyFk2l2w1oO0NBQ
# wMQLeTUPUzLr0xdI+VSYP3EXIOWReJVrsEISnddxW2pODMcbCvbwkPqgTvMQ9h65
# k6K4IFdNlKj/CTe1sOWwRJsg9XqKdiqvPGIxiqXF8J3MLcKKaH381P8uT39pT4jL
# Jz1vc5pPR1nzCAtpUMIYQtEyurIiZ0Ue/Qy51y3Nb+Q+xXclr25+kpa6MSI3cJb/
# 9fyEVr2PkiY15DNwyK3cyhJqgbCduJklfUjKJsimGWpxxcWTihNNI5AGwBTDxTSD
# A6czlQkPyYFQF3rk2no0GTHZy+IngjfgbJcUJbLLkW3VCwFjJV8Abco6EJ88dB/y
# VDMm8uvnthbRsP/FWzgCDiBNLopk3IUR9f2MV1GWvQIDAQABo4IBSTCCAUUwHQYD
# VR0OBBYEFFreY4LMHy7vOm8OHwwYpVgsKTtkMB8GA1UdIwQYMBaAFJ+nFV0AXmJd
# g/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGlt
# ZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUA
# A4ICAQCSVvrD915qJ3cG6NAK1YUF7Sf2mTJHL7LJYSDvSIPCgnm7R7Q77gZ6s3N1
# lvXNM+wcnwQYzKjUrvK0vbX6mZ0UxOXX08Lw4nljan5cpRDLZ0P6GCBEyYmANCyB
# s4LEdh476ODi36+DrXBSui/PMuQffPQ8lde+g24GP0t1r0KI0x3rTjnUq5t730Ct
# J/pkyPe3SnisVuBJrMOz7xMn7woDkZVpiM8eP2uUy4jdaOiERz1qmdDqEyMxyTeO
# UdkjCW5Vh5RATSqOYCl8y1MATNsxR1jywtO6cvUaRsNJ4qf07uWUEac23IzW4z0x
# 2/VXJaHTP8iuJAoiOe2qobKgXQe8Mc4VkLJQME8t+XKK7tjXND+w+i6exv3poF9B
# 2reHcs6fq36b0Sc3P8bozPNa+kmTpiBMdMip5A38X9emI+9t96Teer89hsvdq76Q
# F9FQeIIVdK+3qWivQcLrbq9SbP1k087HARYu5xyibGzLcnBYfv2+wz/sBGqgbmHp
# 3o1qF9o65E/hcj3G10fc9r80IvJCPEpfIvHPBDON12RfYSlMmeXKm6E+YR15rn1T
# PYTfTcvHJdKcoG8awCfJZgB+d6OvdgCIv1is3aXZ2fX3xGkDgMKb1C1liLALSrZ+
# 5S+6Lfg988hRkHJ/vAe65a7nSFj1YvHWQ4wjzHKjsAjpNo2ucjCCB3EwggVZoAMC
# AQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIy
# NVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9
# DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2
# Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N
# 7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXc
# ag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJ
# j361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjk
# lqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37Zy
# L9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M
# 269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLX
# pyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLU
# HMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode
# 2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYE
# FJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEB
# MEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# RG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEE
# AYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
# /zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt
# 4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsP
# MeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++
# Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9
# QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2
# wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aR
# AfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5z
# bcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nx
# t67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3
# Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+AN
# uOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/Z
# cGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNWMIICPgIBATCCAQGhgdmkgdYw
# gdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMe
# blNoaWVsZCBUU1MgRVNOOjZGMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBaZOIDTW7mbGr+
# dXGJEksw6yRUZ6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBCwUAAgUA7Lv3kzAiGA8yMDI1MTExMDA1MzMwN1oYDzIwMjUx
# MTExMDUzMzA3WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDsu/eTAgEAMAcCAQAC
# AggNMAcCAQACAhPqMAoCBQDsvUkTAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQAD
# ggEBAEt6S8GxRYW9plJpHyl63chnaxKzY0KK2wDAvs5rgXwt0bXYvcE8DKh96zPC
# WOQP8pgHhT4dqF2QxUjr5d5a91AeJtkoi5h11JuaIn2aQasVF2EWZZBum7r+havV
# QTS2aqdYsSyxRr0uKW6KT8Npf+3Q+w9NcWVINlbZYUSICJinLGsoEZAnX2DxP/dA
# M42ZyDrYP2w/MazawDDG9lAoUUftUjEOcsirBecOFhdkwEgc9oHCd06ZsE5nwfJi
# K7sZymakZX/l3zCDyYqRxsvHtfiT5FejMle3+Mghx2rFASii/FJKJEyNa5aIkQEh
# vd7ZswGkAbQJY4rLVbe0A640L2sxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAhwJVRXXw1kH0QABAAACHDANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCAmzfjDRUR5k6wD2OUvTP4l3C9l7T+SDlQ37QhBK3+NTDCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIKAgaSY2F2jv4oTt1aEj4TYK3HZEtahi+8mh0Ihy
# IcdoMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIc
# CVUV18NZB9EAAQAAAhwwIgQgd4M128EZAyGLrCziMgFleRJ2KAtczSxeGZFlyD7q
# /lUwDQYJKoZIhvcNAQELBQAEggIAnGVyLDPSaCdddwDva+ji2mEMsAsVyukNsBGb
# zBpuKWewkriIZST8LQlpZX/m9EWL8ngZuAB7/p91iisdD3fZpIL+EdZfwj94thKj
# eRrc0IScYMeWlMK1qeTmcTQ6XSaTaWwBKyHpcVArlMA4dvN950fLyk3X3SQ69N2o
# yP6rPtjM3Qmc89QFycM+Qc88gQDBCigXsj97EgYCuqNv8F5rQnQKUXQKsCs1rWvM
# sXf/Q3fbUod75hWHBKMGzElNX9HA0SltI88vBgUAlm3QhlWQSC5qxsrwzvGLf2h2
# 6duGOOUmxY3LUtvtc9WWghlUsnDdhGdeK+DhUSt7pNAxZLfGlPsqYJvDCVbJTuDw
# H1SMIP0yJMp6xYUzDnA/Nr8/HCVdAY6a/+zqllBpTELAMW+cLIETNtNAN2yNcFVv
# D0Z5/8zfXAQhY15AXlNpa0R4nNdAeEdEVATcDvyGEorMYh0fffT2p40iNy/WpKXU
# 3tEbikc8GtJ3bJZL14L5fQIHrfZcgD6+veDd/ZMarEMXAk91g3/plD3bAGd6r3a+
# uFLZD9Ubgs7STeYG1yz0WMVRfWUcNiuUoMJhVUdMvleltCS54Yte2jT5RPGBwq5j
# CDEg1ja2jvivxFBKlhG/dTLiUJOT+BRBFVJio2tabRPRi8qg6bE2X914zByFgGAC
# qwfpqfo=
# SIG # End signature block
