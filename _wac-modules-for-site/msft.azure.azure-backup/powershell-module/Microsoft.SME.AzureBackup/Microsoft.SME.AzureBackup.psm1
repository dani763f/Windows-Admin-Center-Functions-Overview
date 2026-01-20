function Get-WACABAgentStatus {
<#

.SYNOPSIS
Gets agent status

.DESCRIPTION
Gets agent status

.ROLE
Readers

#>

$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
$ErrorActionPreference = "Stop"
Try {
    $azureBackupModuleName = 'MSOnlineBackup'
    $azureBackupModule = Get-Module -ListAvailable -Name $azureBackupModuleName
    if ($azureBackupModule) {
        try {
            Import-Module MSOnlineBackup;
            [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetMachineRegistrationStatus($false)
        }
        catch {
            $false
        }
    }
    else {
        $false
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}
}
## [END] Get-WACABAgentStatus ##
function Get-WACABBackupDataDetails {
<#

.SYNOPSIS
Gets the number of backups total storage size and from Azure Backup agent.

.DESCRIPTION
Gets the number of backups total storage size and from Azure Backup agent.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $size = 0
    #  $count = 0

    $storage = Get-OBMachineUsage
    if ($storage) {
        $size = $storage.StorageUsedByMachineInBytes
    }

    $systemstaterp = 0
    $filefolderrp = 0

    $rps = Get-OBAllRecoveryPoints
    foreach ($rp in $rps) {
        if ($rp.DataSources -eq "System State") {
            $systemstaterp += 1;
        }
        else {
            $filefolderrp += 1;
        }
    }

    $props = @{
        storagespace  = $size
        systemstaterp = $systemstaterp
        filefolderrp  = $filefolderrp
    }

    $datadetails = New-Object PSObject
    Add-Member -InputObject $datadetails -MemberType NoteProperty -Name "datadetails" -Value $props
    $datadetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABBackupDataDetails ##
function Get-WACABCBDSRPInfo {
<#

.SYNOPSIS
Gets the backup items information for items present in current policy from MAB

.DESCRIPTION
Gets the backup items information for items present in current policy from MAB

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $array = @()
    $DSMap = @{}
    $err = $NULL
    $nextbackuptimeSsb = $NULL
    $nextbackuptimeFiles = $NULL
    $systemstatewriterid = 'DA57A531-E7E7-4346-9A68-B511F551DEB6'
    $systemstateapplicationid = '8C3D00F9-3CE9-4563-B373-19837BC2835E'
    $dscount = 0
    $processedforjobdscount = 0
    <#
 Try
 {
     $err = $NULL
     $task = Get-ScheduledTask | where-Object {$_.TaskName -eq 'Microsoft-OnlineBackup'}
     if ($task -eq $NULL){
         throw "exception"
     }
     $taskinfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName Microsoft-OnlineBackup -ErrorVariable $err
     if ($err){
         throw "exception"
     }
     $nextbackuptimeFiles = $taskinfo.nextruntime
 }
 Catch
 {
 }
 Try
 {
     $err = $NULL
     $task = Get-ScheduledTask | where-Object {$_.TaskName -eq 'Microsoft-OnlineBackup-SystemStateBackup'}
     if ($task -eq $NULL){
         throw "exception"
     }
     $taskinfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName Microsoft-OnlineBackup-SystemStateBackup -ErrorVariable $err
     if ($err -ne $NULL){
         throw "exception"
     }
     $nextbackuptimeSsb = $taskinfo.nextruntime
 }
 Catch
 {
 }
 #>
    $pols = @()
    $jobs = @()
 
    $pol = Get-OBPolicy -ErrorAction SilentlyContinue
    if ($pol) {
        $pols += $pol
    }
    try {
        $spol = Get-OBSystemStatePolicy 
        if ($spol) {
            $pols += $spol
        }
    }
    catch {
 
    }
 
    foreach ($pol in $pols) {
        if ($pol -and $pol.DsList -and $pol.DsList.datasourceid) {
            $dses = $pol.DsList
            for ($i = 0 ; $i -lt $dses.length; $i++) {
                $id = $dses[$i].DataSourceId
                $rpInfo = @(0 .. 9)
                $rpInfo = $rpInfo.ForEach( { $NULL })
                $rpInfo[0] = $dses[$i].DataSourceName
                $rpInfo[1] = $pol.policystate.ToString()
                if ($dses[$i].WriterId -eq $systemstatewriterid -and $dses[$i].ApplicationId -eq $systemstateapplicationid) {
                    $rpInfo[2] = $nextbackuptimeSsb
                }
                else {
                    $rpInfo[2] = $nextbackuptimeFiles
                }
 
                $rpinfo[3] = '-'
                $rpinfo[4] = '-'
                $rpinfo[5] = -1
                $rpinfo[6] = -1
                $rpinfo[7] = '-'
                $rpinfo[8] = '-'
                $rpinfo[9] = '-'
 
                $DSMap[$id] = @{
                    rpinfo    = $rpInfo
                    processed = $false
                }
                $dscount++
            }
        }
    }
 
    $jobs += Get-OBJob -previous 200 #-From ([DateTime]::UtcNow).AddDays(-7) -To ([DateTime]::UtcNow) 
 
    for ($i = $jobs.Count - 1 ; $i -ge 0; $i-- ) {
        if ($processedforjobdscount -eq $dscount) {
            break
        }
        $job = $jobs[$i]
        if ( ($job.jobtype -eq "Backup") -and $job.jobStatus -and $job.jobStatus.datasourcestatus -and $job.jobStatus.datasourcestatus.datasource ) {
            $dses = $job.JobStatus.DatasourceStatus
            for ($j = 0; $j -lt $dses.Length ; $j++) {
                $dsid = $job.JobStatus.DatasourceStatus[$j].Datasource.DataSourceId
                if ($DSMap.ContainsKey($dsid) -and $DSMap[$dsid].processed -eq $false) {
                    $rpInfo = $DSMap[$dsid].rpinfo
                    $rpInfo[3] = $job.JobStatus.starttime
                    if ($job.JobStatus.endtime) {
                        $rpInfo[4] = $job.JobStatus.endtime
                        $rpInfo[9] = ($job.JobStatus.endTime - $job.JobStatus.startTime).ToString()
                    }
                    else {
                        #    $rpInfo[4] =$NULL
                        $rpInfo[9] = ($job.JobStatus.startTime - $job.JobStatus.startTime).ToString()
                    }
                    $rpInfo[5] = $job.JobStatus.datasourcestatus[$j].errorinfo.errorcode
                    $rpInfo[6] = $job.JobStatus.datasourcestatus[$j].errorinfo.DetailedErrorCode
                    $rpInfo[7] = ''
                    $DSMap[$dsid].rpinfo = $rpInfo
                    $DSMap[$dsid].processed = $true
                    $processedforjobdscount++
                }
            }
        }
     
    }
 
    $sources = Get-OBRecoverableSource
    foreach ($ds in $sources) {
        $RecoverableItems = Get-OBRecoverableItem $ds
        $latestPIT = $RecoverableItems[0]
  
        if ($DSMap.ContainsKey($latestPIT.RecoverySourceID)) {
            $rpInfo = $DSMap[$latestPIT.RecoverySourceId].rpinfo
            $rpInfo[8] = $latestPIT.pointintime.ToLocalTime()
            $DSMap[$latestPIT.RecoverySourceId].rpinfo = $rpInfo
        }
    }
 
    foreach ($value in $DSMap.Values) {
        $props = @{
     
            name              = $value.rpinfo[0]
            policystate       = $value.rpinfo[1]
            nextbackuptime    = $value.rpinfo[2]
            starttime         = $value.rpinfo[3]
            endtime           = $value.rpinfo[4]
            errorcode         = $value.rpinfo[5]
            detailederrorcode = $value.rpinfo[6]
            msg               = $value.rpinfo[7]
            latestPIT         = $value.rpinfo[8]
            duration          = $value.rpinfo[9]
            processed         = $value.processed
        }
        $object = new-object psobject -Property $props
        $array += $object
    }
 
    $dsrp = New-Object PSObject
    Add-Member -InputObject $dsrp -MemberType NoteProperty -Name "dsrp" -Value $array
    $dsrp
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABCBDSRPInfo ##
function Get-WACABCustomerDetails {
 <#

.SYNOPSIS
Gets customer details from MAB

.DESCRIPTION
Gets the following items from MAB

       1. ContainerClientId

       2. VaultClientId

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$ContainerId = $null
$VaultId = $null

Try {
    $ContainerId = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure Backup\Config" -Name MachineId -ErrorAction SilentlyContinue
    $ContainerId = ($ContainerId).MachineId
}
Catch {

}
Try {
    $VaultId = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure Backup\Config" -Name ResourceId -ErrorAction SilentlyContinue
    $VaultId = ($VaultId).ResourceId
}
Catch {

}
function Get-MsiProperty {
    param([string]$guid, [string]$propertyName, [System.Text.StringBuilder]$stringBuilder)
    [int]$buffer = 0;
    [MsiInterop]::MsiGetProductInfo($guid, $propertyName, $null, [ref]$buffer) | Out-Null;

    $buffer++;

    if ($buffer -gt $stringBuilder.Capacity) {
        $stringBuilder.Capacity = $buffer;
    }

    [MsiInterop]::MsiGetProductInfo($guid, $propertyName, $stringBuilder, [ref]$buffer) | Out-Null;
    $stringBuilder.ToString(0, $buffer);
}


$pinvokeSignature = @'
using System.Runtime.InteropServices;
using System.Text;
public class MsiInterop
{

    [DllImport("msi.dll", CharSet=CharSet.Unicode)]
    public static extern int MsiGetProductInfo(string product, string property, [Out] StringBuilder valueBuf, ref int len);
}
'@

$ErrorActionPreference = "Stop"

Try {
    $VersionNumber = "-"
    Add-Type -TypeDefinition $pinvokeSignature
    $tempStringBuilder = New-Object System.Text.StringBuilder 0;
    #marsAgentProductId
    $guid = "{FFE6D16C-3F87-4192-AF94-DDBEFF165106}"
    $CompleteVersion = Get-MsiProperty $guid "VersionString" $tempStringBuilder;
    if (![string]::IsNullOrEmpty($CompleteVersion)) {
        $VersionNumber = $CompleteVersion.split(".")[2]
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

$props = @{
    ContainerId = $ContainerId
    VaultId = $VaultId
    AgentVersionNumber = $VersionNumber
}

$details = New-Object PSObject
Add-Member -InputObject $details -MemberType NoteProperty -Name "details" -Value $props
$details

}
## [END] Get-WACABCustomerDetails ##
function Get-WACABEnhancedSecurityStatus {
<#

.SYNOPSIS
Gets the enhanced security status on the target.

.DESCRIPTION
Gets the enhanced security status on the target.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $status = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetEnhancedSecurityStatus()
    $status = $status.TokenState.value__

    if ($status -eq 1) {
        $statusBool = $true
    }
    else {
        $statusBool = $false
    }

    $props = @{
        status = $statusBool
    }

    $statusdetails = New-Object PSObject
    Add-Member -InputObject $statusdetails -MemberType NoteProperty -Name "statusdetails" -Value $props
    $statusdetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABEnhancedSecurityStatus ##
function Get-WACABFileFolderPolicyFileSpec {
<#

.SYNOPSIS
Gets the file folder policy file spec.

.DESCRIPTION
Gets the file folder policy file spec.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexisted = $false
    $filespecs = @()

    $pol = Get-OBPolicy

    if ($pol) {
        $fileexisted = $true
        $array = @();
        $specs = Get-OBFileSpec $pol
        foreach ($fs in $specs) {
            $array += $fs.FileSpec
        }
        $filespecs = $array
    }

    $props = @{
        filespecs   = $filespecs
        fileexisted = $fileexisted
    }

    $specdetails = New-Object PSObject
    Add-Member -InputObject $specdetails -MemberType NoteProperty -Name "specdetails" -Value $props
    $specdetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABFileFolderPolicyFileSpec ##
function Get-WACABFileFolderPolicyState {
<#

.SYNOPSIS
Get file folder policy state.

.DESCRIPTION
Get file folder policy state.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexisted = $false
    $isPaused = $false

    $pol = Get-OBPolicy

    if ($pol) {
        $fileexisted = $true
        $state = Get-OBPolicyState $pol
        if ($State.ToString() -eq "Paused") {
            $isPaused = $true
        }
        elseif ($pol.State -and $pol.State.ToString() -eq "Valid") {
            $isPaused = $false
        }
    }

    $props = @{
        isPaused    = $isPaused
        fileexisted = $fileexisted
    }

    $statedetails = New-Object PSObject
    Add-Member -InputObject $statedetails -MemberType NoteProperty -Name "statedetails" -Value $props
    $statedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABFileFolderPolicyState ##
function Get-WACABIsBackupJobRunning {
<#

.SYNOPSIS
Fetches if there is a backup job running on the target

.DESCRIPTION
Fetches if there is a backup job running on the target

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $job = Get-OBJob
    if ($job -eq $NULL -or $job.JobType -ne 'Backup') {
        $false
    }
    else {
        $true
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABIsBackupJobRunning ##
function Get-WACABJobMetrics {
<#

.SYNOPSIS
Gets the metrics of job status from Azure Backup agent.

.DESCRIPTION
Gets the metrics of job status from Azure Backup agent.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $ongoing = 0
    $completed = 0
    $failed = 0
    $warning = 0

    $queryjobs = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::QueryJobs()

    if ($queryjobs.RunningJobs) {
        $ongoing = 1
    }

    $finishedjobs = $queryjobs.FinishedJobs
    foreach ($finishedjob in $finishedjobs) {
        #Is this list exclusive? Is there any other state falling into completed, failed or warning?
        #keeping a else separate in case some new states are added to MAB
        if ($finishedjob.JobStatus.JobState -eq "Completed") {
            $completed += 1;
        }
        elseif ($finishedjob.JobStatus.JobState -eq "Aborted") {
            $failed += 1;
        }
        elseif ($finishedjob.JobStatus.JobState -eq "CompletedWithWarning" -or
            $finishedjob.JobStatus.JobState -eq "CompletedWithWaitingForImportJob" -or
            $finishedjob.JobStatus.JobState -eq "CompletedWithWaitingForCopyBlob") {
            $warning += 1;
        }
        else {
            $warning += 1;
        }
    }

    #do we want current job status also?
    $last2jobs = get-objob -Previous 2
    $jobstatus = @()
    foreach ($job in $last2jobs) {
        $type = $job.JobType.ToString()
        $datatype = ''
        if ($job.jobstatus -and $job.JobStatus.DatasourceStatus -and $job.jobstatus.DatasourceStatus.datasource) {
            $datatype = $job.jobstatus.DatasourceStatus.datasource.datasourcename
        }

        $backupjobflag = $job.Jobtype -eq [Microsoft.Internal.CloudBackup.ObjectModel.OMCommon.CBJobType]::Backup
        $status = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::ConvertJobStatusToString($job.JobStatus.JobState, $backupjobflag)
        $time = $job.JobStatus.StartTime

        $props = @{
            type     = $type
            datatype = $datatype
            status   = $status
            time     = $time
        }
        $object = new-object psobject -Property $props
        $jobstatus += $object
    }

    $props = @{
        inProgress     = $ongoing
        success        = $completed
        failed         = $failed
        warning        = $warning
        jobstatusarray = $jobstatus
    }

    $JobMetrics = New-Object PSObject
    Add-Member -InputObject $JobMetrics -MemberType NoteProperty -Name "JobMetrics" -Value $props
    $JobMetrics
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABJobMetrics ##
function Get-WACABJobs {
<#

.SYNOPSIS
Gets the list of last 50 jobs from Azure Backup agent.

.DESCRIPTION
Gets the list of last 50 jobs from Azure Backup agent.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    #Get-OBJob -Previous 1 -ErrorAction SilentlyContinue | Select-Object jobStatus

    $array = @()
    $jobs = @()
    $currentjob = get-objob
    $queryjobs = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::QueryJobs()
    #$jobs = get-objob -Previous 50
    #$jobs += $currentjob
    $jobs += $queryjobs.FinishedJobs
    $jobs += $queryjobs.RunningJobs
    $errortype = [Microsoft.Internal.EnterpriseStorage.Dls.Utils.Errors.ErrorCode]
    foreach ($job in $jobs) {
        $backupitems = @()
        $jobtype = ''
        $jobstate = ''
        $starttime = ''
        $endtime = ''
        $problem = ''
        $resolution = ''
        $backupitemsstate = @()
        $dsesdetailederrorcode = @()
        $dseserrorcode = @()
        $dsesproblem = @()
        $dsesresolution = @()
        $dsesdatatransferred = @()
        if ($job.jobstatus -and $job.JobStatus.DatasourceStatus -and $job.jobstatus.DatasourceStatus.datasource) {
            $backupitems = @($job.jobstatus.DatasourceStatus.datasource.datasourcename)
        }
        else {
            continue;
        }
        $id = $job.JobId
        $jobtype = $job.JobType.ToString()
        $backupjobflag = $job.Jobtype -eq [Microsoft.Internal.CloudBackup.ObjectModel.OMCommon.CBJobType]::Backup
        $jobstate = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::ConvertJobStatusToString($job.JobStatus.JobState, $backupjobflag)
        $startTime = $job.JobStatus.StartTime
        $endTime = $job.JobStatus.EndTime
        $duration = ($job.JobStatus.EndTime - $job.JobStatus.StartTime).ToString()
        $joberrorcode = $job.JobStatus.ErrorInfo.ErrorCode

        if ($currentjob -and $job -eq $currentjob) {
            $endtime = ''
            $duration = ''
        }

        $dsstates = $job.jobstatus.DatasourceStatus
        foreach ($dsstate in $dsstates) {
        
            $backupitemsstate += [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::ConvertJobStatusToString($dsstate.jobstate, $backupjobflag)
            $dsesdetailederrorcode += $dsstate.ErrorInfo.DetailedErrorCode
            $dseserrorcode += $dsstate.ErrorInfo.ErrorCode
            $errorcode = $dsstate.ErrorInfo.ErrorCode -as $errortype
            $errorinfo = [Microsoft.Internal.EnterpriseStorage.Dls.Utils.Errors.ErrorInfo]::new($errorcode)
            $dsesproblem += $errorinfo.Problem
            $dsesresolution += $errorinfo.Resolution
            $dsesdatatransferred += $dsstate.byteprogress.progress
        }
    
        $props = @{
            backupitems         = $backupitems
            jobtype             = $jobtype
            jobstate            = $jobstate
            starttime           = $starttime
            endtime             = $endtime
            id                  = $id
            detailederrorcode   = $dsesdetailederrorcode
            errorcode           = $dseserrorcode
            problem             = $dsesproblem
            resolution          = $dsesresolution
            duration            = $duration
            backupitemsstate    = $backupitemsstate
            joberrorcode        = $joberrorcode
            dsesdatatransferred = $dsesdatatransferred
        }
        $object = new-object psobject -Property $props
        $array += $object
    }

    $Jobs = New-Object PSObject
    Add-Member -InputObject $Jobs -MemberType NoteProperty -Name "Jobs" -Value $array
    $Jobs
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABJobs ##
function Get-WACABOngoingJob {
<#

.SYNOPSIS
Gets ongoing job

.DESCRIPTION
Gets the ongoing job

.ROLE
Readers

#>

}
## [END] Get-WACABOngoingJob ##
function Get-WACABOngoingJobDetails {
<#

.SYNOPSIS
Gets the list jobs in one last week from Azure Backup agent.

.DESCRIPTION
Gets the list jobs in one last week from Azure Backup agent.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    #Get-OBJob -Previous 1 -ErrorAction SilentlyContinue | Select-Object jobStatus

    $isOngoing = $true
    $job = get-objob
    if (!$job)
    {
        $isOngoing = $false
        $job = Get-OBJob -Previous 1 -ErrorAction SilentlyContinue
    }

    $errortype = [Microsoft.Internal.EnterpriseStorage.Dls.Utils.Errors.ErrorCode]

    $backupitems = @()
    $jobtype = ''
    $jobstate = ''
    $starttime = ''
    $endtime = ''
    $problem = ''
    $resolution = ''
    $backupitemsstate = @()
    $dsesdetailederrorcode = @()
    $dseserrorcode = @()
    $dsesproblem = @()
    $dsesresolution = @()
    $dsesdatatransferred = @()
    if ($job.jobstatus -and $job.JobStatus.DatasourceStatus -and $job.jobstatus.DatasourceStatus.datasource) {
        $backupitems = @($job.jobstatus.DatasourceStatus.datasource.datasourcename)
    }
    else {
        continue;
    }
    $id = $job.JobId
    $jobtype = $job.JobType.ToString()
    $backupjobflag = $job.Jobtype -eq [Microsoft.Internal.CloudBackup.ObjectModel.OMCommon.CBJobType]::Backup
    $jobstate = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::ConvertJobStatusToString($job.JobStatus.JobState, $backupjobflag)
    $startTime = $job.JobStatus.StartTime
    $endTime = $job.JobStatus.EndTime
    $duration = ($job.JobStatus.EndTime - $job.JobStatus.StartTime).ToString()
    $joberrorcode = $job.JobStatus.ErrorInfo.ErrorCode

    if ($isOngoing) {
        $endtime = ''
        $duration = ''
    }

    $dsstates = $job.jobstatus.DatasourceStatus
    foreach ($dsstate in $dsstates) {

        $backupitemsstate += [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::ConvertJobStatusToString($dsstate.jobstate, $backupjobflag)
        $dsesdetailederrorcode += $dsstate.ErrorInfo.DetailedErrorCode
        $dseserrorcode += $dsstate.ErrorInfo.ErrorCode
        $errorcode = $dsstate.ErrorInfo.ErrorCode -as $errortype
        $errorinfo = [Microsoft.Internal.EnterpriseStorage.Dls.Utils.Errors.ErrorInfo]::new($errorcode)
        $dsesproblem += $errorinfo.Problem
        $dsesresolution += $errorinfo.Resolution
        $dsesdatatransferred += $dsstate.byteprogress.progress
    }

    $props = @{
        backupitems         = $backupitems
        jobtype             = $jobtype
        jobstate            = $jobstate
        starttime           = $starttime
        endtime             = $endtime
        id                  = $id
        detailederrorcode   = $dsesdetailederrorcode
        errorcode           = $dseserrorcode
        problem             = $dsesproblem
        resolution          = $dsesresolution
        duration            = $duration
        backupitemsstate    = $backupitemsstate
        joberrorcode        = $joberrorcode
        dsesdatatransferred = $dsesdatatransferred
    }

    $JobDetails = New-Object PSObject
    Add-Member -InputObject $JobDetails -MemberType NoteProperty -Name "JobDetails" -Value $props
    $JobDetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABOngoingJobDetails ##
function Get-WACABOverview {
<#

.SYNOPSIS
Gets overview info from MAB

.DESCRIPTION
Gets the following items from MAB

       1. Registration status of MAB Agent

       2. Vault name

       3. Subscription ID

       4. Update available(Y/N)

       5. State of last backup

       6. Latest RP

       7. Oldest RP

       8. Next Scheduled Backup

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $registrationstatus = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetMachineRegistrationStatus(0)
    $updateavailable = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetAgentUpdateInfo().showagentupdatepopup
    $subscriptionid = $NULL
    $vault = $NULL
    $resourceGroup = $NULL
    $vaultKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure Backup\Config" -Name ServiceResourceName -ErrorAction SilentlyContinue
    $subscriptionidKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure Backup\Config" -Name SubscriptionId -ErrorAction SilentlyContinue
    $rgkey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Azure Backup\Config" -Name ResourceGroupName -ErrorAction SilentlyContinue

    if ($vaultKey) {
        $vault = $vaultKey.ServiceResourceName
    }
    if ($subscriptionidKey) {
        $subscriptionid = $subscriptionidKey.SubscriptionId
    }
    if ($rgkey) {
        $resourceGroup = $rgkey.ResourceGroupName
    }


    $lastbackuperrorcode = 0
    $lastbackupdetailederrorcode = 0
    $latestrp = $NULL
    $oldestrp = $NULL
    $nextscheduledbackup = $NULL

    $jobs = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::QueryJobs()
    if ($jobs -and $jobs.lastbackupjob -and $jobs.lastbackupjob.jobstatus -and $jobs.lastbackupjob.jobstatus.errorinfo) {
        $lastbackuperrorcode = $jobs.lastbackupjob.jobstatus.errorinfo.errorcode
        $lastbackupdetailederrorcode = $jobs.lastbackupjob.jobstatus.errorinfo.detailederrorcode
    }

    $rpinfo = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetPolicyAndRPInfoForMachine()
    if ($rpinfo -and $rpinfo.RecoveryPointsInfo -and $rpinfo.RecoveryPointsInfo.latestcopy) {
        $latestrp = $rpinfo.RecoveryPointsInfo.latestcopy
    }


    if ($rpinfo -and $rpinfo.RecoveryPointsInfo -and $rpinfo.RecoveryPointsInfo.oldestcopy) {
        $oldestrp = $rpinfo.RecoveryPointsInfo.oldestcopy
    }

    $nextscheduledbackup = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetNextRunTimeOfScheduledTask()
    $dateTimeNow = Get-Date
    $dateTimeNow = $dateTimeNow.AddDays(-1)
    # Next scheduled time cannot be in the past
    if ($nextscheduledbackup -lt $dateTimeNow) {
        $nextscheduledbackup = ''
    }

    $props = @{
        registrationstatus          = $registrationstatus
        vault                       = $vault
        subscriptionid              = $subscriptionid
        resourcegroup               = $resourceGroup
        updateavailable             = $updateavailable
        lastbackuperrorcode         = $lastbackuperrorcode
        lastbackupdetailederrorcode = $lastbackupdetailederrorcode
        latestrp                    = $latestrp
        oldestrp                    = $oldestrp
        nextscheduledbackup         = $nextscheduledbackup
    }

    $overview = New-Object PSObject
    Add-Member -InputObject $overview -MemberType NoteProperty -Name "overview" -Value $props
    $overview
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABOverview ##
function Get-WACABPolicies {
<#

.SYNOPSIS
Gets the policy details from MAB

.DESCRIPTION
Gets the policy details from MAB

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $array = @()
    $policyTypeFileFolder = 0
    $policyTypeSystemState = 1
    function flattenScheduleRetention ($pol, $policytype) {
        $backupdays = @()
        $backuptime = @()
        $backupweeklyfrequency = 0
        $dailyretention = 0
        $weeklyretention = 0
        $monthlyretention = 0
        $yearlyretention = 0
        $dslist = ''
 
        if ($pol -and $pol.dslist) {
            $dslist = $pol.dslist.datasourcename
        }
 
        if ($pol -and $pol.backupschedule -and $pol.backupschedule) {
            $backupdays += $pol.backupschedule.schedulerundays
        }
 
        if ($pol -and $pol.backupschedule -and $pol.backupschedule.scheduleruntimes) {
            $backuptime += $pol.backupschedule.scheduleruntimes
        }
 
        if ($pol -and $pol.backupschedule -and $pol.backupschedule.scheduleweeklyfrequency) {
            $backupweeklyfrequency = $pol.backupschedule.scheduleweeklyfrequency
        }
 
        if ($pol -and $pol.RetentionPolicy) {
            $dailyretention = $pol.RetentionPolicy.RetentionDays
        }
 
        if ($pol -and $pol.RetentionPolicy -and $pol.RetentionPolicy.WeeklyLTRSchedule) {
            $weeklyretention = $pol.RetentionPolicy.WeeklyLTRSchedule.RetentionRange / 7
        }
 
        if ($pol -and $pol.RetentionPolicy -and $pol.RetentionPolicy.MonthlyLTRSchedule) {
            $monthlyretention = $pol.RetentionPolicy.MonthlyLTRSchedule.RetentionRange / 31
        }
     
     
        if ($pol -and $pol.RetentionPolicy -and $pol.RetentionPolicy.YearlyLTRSchedule) {
            $yearlyretention = $pol.RetentionPolicy.YearlyLTRSchedule.RetentionRange / 366
        }
 
        $dsArray = @()
        $dsArray += $dslist
        $props = @{
            policyguid            = $pol.PolicyName
            policystate           = $pol.PolicyState.ToString()
            dslist                = $dsArray
            backupdays            = $backupdays
            backuptime            = $backuptime
            backupweeklyfrequency = $backupweeklyfrequency
            dailyretention        = $dailyretention
            weeklyretention       = $weeklyretention
            monthlyretention      = $monthlyretention
            yearlyretention       = $yearlyretention
            policytype            = $policytype
        }
        $object = new-object psobject -Property $props
        return $object;
    }
 
    $fpol = Get-OBPolicy -ErrorAction SilentlyContinue
    if ($fpol) {
        $array += flattenScheduleRetention $fpol $policyTypeFileFolder
    }
    try {
        $spol = Get-OBSystemStatePolicy 
        if ($spol) {
            $array += flattenScheduleRetention $spol $policyTypeSystemState
        }
    }
    catch {
 
    }
 
    $policies = New-Object PSObject
    Add-Member -InputObject $policies -MemberType NoteProperty -Name "policies" -Value $array
    $policies
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABPolicies ##
function Get-WACABPolicyType {
<#

.SYNOPSIS
Fetches the currently present policy on the target

.DESCRIPTION
Fetches the currently present policy on the target

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexists = $false
    $ssbexists = $false

    $pol = Get-OBPolicy
    $ssbpol = Get-OBSystemStatePolicy

    if ($pol) {
        $fileexists = $true
    }
    if ($ssbpol) {
        $ssbexists = $true
    }

    $props = @{
        fileexists = $fileexists
        ssbexists  = $ssbexists
    }

    $policydetails = New-Object PSObject
    Add-Member -InputObject $policydetails -MemberType NoteProperty -Name "policydetails" -Value $props
    $policydetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABPolicyType ##
function Get-WACABPreSetupStatus {
<#########################################################################################################
 # File: GetPreSetupStatus.ps1
 #
 # .DESCRIPTION
 #
 #  Fetches the current status of the MARS agent on target
 #
 #  The supported Operating Systems are Windows Server 2008 R2, Window Server 2012, 
 #
 #  Windows Server 2012R2, Windows Server 2016.
 #
 #  Copyright (c) Microsoft Corp 2017.
 #
 #########################################################################################################>

<#

.SYNOPSIS
Gets pre setup status

.DESCRIPTION
Gets pre setup status

.ROLE
Readers

#>

<#
export enum CBPreSetupStatus {
    CannotConnectToTarget = 0,  // Connection failure
    DPMInstalled = 1,   // DPM/Venus/LaJolla installed
    DPMRAInstalled = 2,  // DPM_RA installed on target machine
    MARSAgentNotInstalled = 3,  // Agent not installed on target server
    MARSAgentNotRegisterted = 4,    // Agent is not registered
    MARSAgentInstalledAndRegistered = 5  // MARS agent is ready to use
    CurrentUserNotAdmin = 6  // Either honolulu server is not running in admin context or current user is not admin
}
#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
$ErrorActionPreference = "Stop"
Try {
    $dpm2012RAProductId = '34ACE441-5C52-40CD-A8E6-3521F76F92DA'
    $dpm2016RAProductId = '14DD5B44-17CE-4E89-8BEB-2E6536B81B35'
    $marsAgentProductId = 'FFE6D16C-3F87-4192-AF94-DDBEFF165106'
    $azureBackupModuleName = 'MSOnlineBackup'
    $dpmModuleName = 'DataProtectionManager'
    $dpmModule = Get-Module -ListAvailable -Name $dpmModuleName
    $azureBackupModule = Get-Module -ListAvailable -Name $azureBackupModuleName
    $installedProductList1 = @()
    $installedProductList2 = @()
    $installedProductList3 = @()
    $isAdmin = $false;

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (!$isAdmin) {
        6
        return
    }

    if ($dpmModule) {
        1
        return
    }
    if ($azureBackupModule) {
        Import-Module $azureBackupModuleName
        try {
            $registrationstatus = [Microsoft.Internal.CloudBackup.Client.Common.CBClientCommon]::GetMachineRegistrationStatus(0)
            if ($registrationstatus -eq $true) {
                5
            }
            else {
                4
            }
        }
        catch {
            7
        }
        return
    }
    $installedProductList1 = Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
    $installedProductList2 = Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
    $installedProductList3 = Get-Item -Path Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
    $isDPM2012RAInstalled = $false
    $isDPM2016RAInstalled = $false
    $isMARSAgentInstalled = $false
    foreach ($productId in $installedProductList1.GetSubKeyNames()) {
        if ($productId -contains $dpm2012RAProductId) {
            $isDPM2012RAInstalled = $true
            break
        }
        elseif ($productId -contains $dpm2016RAProductId) {
            $isDPM2016RAInstalled = $true
            break
        }
    }
    if (!$isDPM2012RAInstalled -and !$isDPM2016RAInstalled -and $isMARSAgentInstalled) {
        foreach ($productId in $installedProductList2.GetSubKeyNames()) {
            if ($productId -contains $dpm2012RAProductId) {
                $isDPM2012RAInstalled = $true
                break
            }
            elseif ($productId -contains $dpm2016RAProductId) {
                $isDPM2016RAInstalled = $true
                break
            }
        }
    }
    if (!$isDPM2012RAInstalled -and !$isDPM2016RAInstalled -and $isMARSAgentInstalled) {
        foreach ($productId in $installedProductList3.GetSubKeyNames()) {
            if ($productId -contains $dpm2012RAProductId) {
                $isDPM2012RAInstalled = $true
                break
            }
            elseif ($productId -contains $dpm2016RAProductId) {
                $isDPM2016RAInstalled = $true
                break
            }
        }
    }
    if ($isDPM2012RAInstalled -or $isDPM2016RAInstalled) {
        2
        return
    }
    if (!$azureBackupModule) {
        3
        return
    }
    else {
        0
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABPreSetupStatus ##
function Get-WACABProtectableItems {
<#

.SYNOPSIS
Gets the local file system root entities of the machine.

.DESCRIPTION
Gets the local file system root entities of the machine.

.ROLE
Readers

#>

function Get-FileSystemRoot
{
    $volumes = Get-Volumes;

    return $volumes |
        Microsoft.PowerShell.Utility\Select-Object @{Name="DisplayLabel"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
        @{Name="Path"; Expression={$_.Path +":\"}},
        @{Name="Name"; Expression={$_.DriveLetter +":\"}},
        @{Name="Size"; Expression={($_.Size - $_.SizeRemaining)}}
        #  @{Name="Caption"; Expression={$_.DriveLetter +":\"}},
}

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

    foreach($partition in Get-Partition)
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

    foreach($disk in Get-Disk)
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
    Name: Get-VolumeDownlevelOS
    Description: Gets the list of all applicable volumes from WS2012 and Ws2012R2 Operating Systems.
                 
.Returns
    The list of all applicable volumes
#>
function Get-VolumeDownlevelOS
{
    $volumes = @()
    $partitionsMapping = Get-VolumePathToPartition
    $disksMapping =  Get-DiskIdToDisk
    
    foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
    {
       $partition = $partitionsMapping.Get_Item($volume.Path)

       # Check if this volume is associated with a partition.
       if($partition)
       {
            # If this volume is associated with a partition, then get the disk to which this partition belongs.
            $disk = $disksMapping.Get_Item($partition.DiskId)

            # If the disk is a clustered disk then simply ignore this volume.
            if($disk -and $disk.IsClustered) {continue}
       }
  
       $volumes += $volume
    }


    return $volumes
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

    $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" }

    foreach($volume in @($subSystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume))
    {
        if(-not $applicableVolumePaths.Contains($volume.Path))
        {
            $applicableVolumePaths.Add($volume.Path, $null)
        }
    }

    foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
    {
        if(-not $applicableVolumePaths.Contains($volume.Path)) { continue }

        $volumes += $volume
    }

    return $volumes
}

<#
.Synopsis
    Name: Get-Volumes
    Description: Gets the local volumes of the machine.

.Returns
    The local volumes.
#>
function Get-Volumes
{
    Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing

    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    if ($isDownlevel)
    {
        $volumes = Get-VolumeDownlevelOS
    }
    else
    {
        $volumes = Get-VolumeWs2016AndAboveOS
    }

    return $volumes | Where-Object { [byte]$_.DriveLetter -ne 0 -and $_.DriveLetter -ne $null -and $_.Size -gt 0 -and $_.FileSystem -eq 'NTFS'};
}

Get-FileSystemRoot;

}
## [END] Get-WACABProtectableItems ##
function Get-WACABRPInfo {
<#

.SYNOPSIS
Gets the recovery points information from MAB

.DESCRIPTION
Gets the recovery points information from MAB

.ROLE
Readers

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $array = @()

    $rps = Get-OBAllRecoveryPoints
    foreach ($rp in $rps) {
        $time = $rp.BackupTime
        $rpinfo = $rp.DataSources
    
        $props = @{
            time   = $time
            rpinfo = $rpinfo
        }
        $object = new-object psobject -Property $props
    
        $array += $object
    }

    $Rps = New-Object PSObject
    Add-Member -InputObject $Rps -MemberType NoteProperty -Name "Rps" -Value $array
    $Rps
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABRPInfo ##
function Get-WACABRPMetrics {
<#

.SYNOPSIS
Gets the metrics of RP status from Azure Backup agent.

.DESCRIPTION
Gets the metrics of RP status from Azure Backup agent.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $systemstaterp = 0
    $filefolderrp = 0


    $rps = Get-OBAllRecoveryPoints
    foreach ($rp in $rps) {
        if ($rp.DataSources -eq "System State") {
            $systemstaterp += 1;
        }
        else {
            $filefolderrp += 1;
        }
    }

    $props = @{
        systemstaterp = $systemstaterp
        filefolderrp  = $filefolderrp
    }

    $RpMetrics = New-Object PSObject
    Add-Member -InputObject $RpMetrics -MemberType NoteProperty -Name "RpMetrics" -Value $props
    $RpMetrics
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABRPMetrics ##
function Get-WACABRecoverableItems {
<#

.SYNOPSIS
Gets the list of sources and PITS which can be recovered.

.DESCRIPTION
Gets the list of sources and PITS which can be recovered.

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $sources = Get-OBRecoverableSource
    $sourceNames = @()
    $itemsForAllSources = @()
    $itemTimesForAllSources = @()
    foreach ($source in $sources) {
        $items = @()
        $itemTimes = @()
        $sourceNames += $source.RecoverySourceName
        $itemsPerSource = Get-OBRecoverableItem $source
        foreach ($itemPerSource in $itemsPerSource) {
            $items += $itemPerSource
            $itemTimes += $itemPerSource.RecoveryPointLocalTime
        }
        $itemsForAllSources += , $items
        $itemTimesForAllSources += , $itemTimes
    }

    $props = @{
        sourceNames            = $sourceNames
        itemsForAllSources     = $itemsForAllSources
        itemTimesForAllSources = $itemTimesForAllSources
    }

    $recoverableitems = New-Object PSObject
    Add-Member -InputObject $recoverableitems -MemberType NoteProperty -Name "recoverableitems" -Value $props
    $recoverableitems
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABRecoverableItems ##
function Get-WACABSystemStatePolicyState {
<#

.SYNOPSIS
Fetches the system state policy state

.DESCRIPTION
Fetches the system state policy state

.ROLE
Readers

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $ssbexisted = $false
    $isPaused = $false

    $pol = Get-OBSystemStatePolicy

    if ($pol) {
        $ssbexisted = $true
        $state = Get-OBPolicyState $pol
        if ($State.ToString() -eq "Paused") {
            $isPaused = $true
        }
        elseif ($pol.State -and $pol.State.ToString() -eq "Valid") {
            $isPaused = $false
        }
    }

    $props = @{
        isPaused   = $isPaused
        ssbexisted = $ssbexisted
    }

    $statedetails = New-Object PSObject
    Add-Member -InputObject $statedetails -MemberType NoteProperty -Name "statedetails" -Value $props
    $statedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Get-WACABSystemStatePolicyState ##
function New-WACABCert {
 <#

.SYNOPSIS
Generates the certificate required to create a vault cred file and register the agent on target

.DESCRIPTION
Generates the certificate required to create a vault cred file and register the agent on target

.ROLE
Readers

#>

 Set-StrictMode -Version 5.0
 $Subject = "CN=Windows Azure Tools"
 $NotBefore = [DateTime]::Now.AddDays(-1)
 $NotAfter = $NotBefore.AddDays(2)
 $ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
 $AlgorithmName = "RSA"
 $KeyLength = 2048
 $KeySpec = "Exchange"
 $PathLength = -1
 $SignatureAlgorithm = "SHA1"
 $FriendlyName = "AzureBackupVaultCredCert"
 $StoreLocation = "LocalMachine"
 $Exportable = $true
 $EnhancedKeyUsage = '1.3.6.1.5.5.7.3.2'
 $KeyUsage = $null
 $SubjectAlternativeName = $null
 $CustomExtension = $null
 $SerialNumber = $null
 $AllowSMIME = $false

 $ErrorActionPreference = "Stop"
 if ([Environment]::OSVersion.Version.Major -lt 6) {
                 $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
                 throw $NotSupported
 }
 $ExtensionsToAdd = @()

 #region constants
 # contexts
 New-Variable -Name UserContext -Value 0x1 -Option ReadOnly -Force
 New-Variable -Name MachineContext -Value 0x2 -Option ReadOnly -Force
 # encoding
 New-Variable -Name Base64Header -Value 0x0 -Option ReadOnly -Force
 New-Variable -Name Base64 -Value 0x1 -Option ReadOnly -Force
 New-Variable -Name Binary -Value 0x3 -Option ReadOnly -Force
 New-Variable -Name Base64RequestHeader -Value 0x4 -Option ReadOnly -Force
 # SANs
 New-Variable -Name OtherName -Value 0x1 -Option ReadOnly -Force
 New-Variable -Name RFC822Name -Value 0x2 -Option ReadOnly -Force
 New-Variable -Name DNSName -Value 0x3 -Option ReadOnly -Force
 New-Variable -Name DirectoryName -Value 0x5 -Option ReadOnly -Force
 New-Variable -Name URL -Value 0x7 -Option ReadOnly -Force
 New-Variable -Name IPAddress -Value 0x8 -Option ReadOnly -Force
 New-Variable -Name RegisteredID -Value 0x9 -Option ReadOnly -Force
 New-Variable -Name Guid -Value 0xa -Option ReadOnly -Force
 New-Variable -Name UPN -Value 0xb -Option ReadOnly -Force
 # installation options
 New-Variable -Name AllowNone -Value 0x0 -Option ReadOnly -Force
 New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option ReadOnly -Force
 New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option ReadOnly -Force
 New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option ReadOnly -Force
 # PFX export options
 New-Variable -Name PFXExportEEOnly -Value 0x0 -Option ReadOnly -Force
 New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option ReadOnly -Force
 New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option ReadOnly -Force
 #endregion

 #region Subject processing
 # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
 $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
 $SubjectDN.Encode($Subject, 0x0)
 #endregion

 #region Extensions

 #region Enhanced Key Usages processing
 if ($EnhancedKeyUsage) {
                 $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
                 $EnhancedKeyUsage | ForEach-Object {
                                 $OID = New-Object -ComObject X509Enrollment.CObjectID
                                 $OID.InitializeFromValue("1.3.6.1.5.5.7.3.2")
                                 # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
                                 $OIDs.Add($OID)
                 }
                 # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
                 $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
                 $EKU.InitializeEncode($OIDs)
                 $ExtensionsToAdd += "EKU"
 }
 #endregion

 #region Key Usages processing
 if ($KeyUsage -ne $null) {
                 $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
                 $KU.InitializeEncode([int]$KeyUsage)
                 $KU.Critical = $true
                 $ExtensionsToAdd += "KU"
 }
 #endregion

 #region Basic Constraints processing
 if ($PSBoundParameters.Keys.Contains("IsCA")) {
                 # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
                 $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
                 if (!$IsCA) {$PathLength = -1}
                 $BasicConstraints.InitializeEncode($IsCA,$PathLength)
                 $BasicConstraints.Critical = $IsCA
                 $ExtensionsToAdd += "BasicConstraints"
 }
 #endregion

 #region SAN processing
 if ($SubjectAlternativeName) {
                 $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                 $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
                 foreach ($altname in $SubjectAlternativeName) {
                                 $Name = New-Object -ComObject X509Enrollment.CAlternativeName
                                 if ($altname.Contains("@")) {
                                                 $Name.InitializeFromString($RFC822Name,$altname)
                                 } else {
                                                 try {
                                                                 $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
                                                                 $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
                                                 } catch {
                                                                 try {
                                                                                 $Bytes = [Guid]::Parse($altname).ToByteArray()
                                                                                 $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
                                                                 } catch {
                                                                                 try {
                                                                                                 $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
                                                                                                 $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
                                                                                 } catch {$Name.InitializeFromString($DNSName,$altname)}
                                                                 }
                                                 }
                                 }
                                 $Names.Add($Name)
                 }
                 $SAN.InitializeEncode($Names)
                 $ExtensionsToAdd += "SAN"
 }
 #endregion

 #region Custom Extensions
 if ($CustomExtension) {
                 $count = 0
                 foreach ($ext in $CustomExtension) {
                                 # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
                                 $Extension = New-Object -ComObject X509Enrollment.CX509Extension
                                 $EOID = New-Object -ComObject X509Enrollment.CObjectId
                                 $EOID.InitializeFromValue($ext.Oid.Value)
                                 $EValue = [Convert]::ToBase64String($ext.RawData)
                                 $Extension.Initialize($EOID,$Base64,$EValue)
                                 $Extension.Critical = $ext.Critical
                                 New-Variable -Name ("ext" + $count) -Value $Extension
                                 $ExtensionsToAdd += ("ext" + $count)
                                 $count++
                 }
 }
 #endregion

 #endregion

 #region Private Key
 # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
 $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
 $PrivateKey.ProviderName = $ProviderName
 $AlgID = New-Object -ComObject X509Enrollment.CObjectId
 $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
 $PrivateKey.Algorithm = $AlgID
 # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
 $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
 $PrivateKey.Length = $KeyLength
 # key will be stored in current user certificate store
 $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
 $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
 $PrivateKey.Create()
 #endregion

 # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
 $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
 if ($PrivateKey.MachineContext) {
                 $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
 } else {
                 $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
 }
 $Cert.Subject = $SubjectDN
 $Cert.Issuer = $Cert.Subject
 $Cert.NotBefore = $NotBefore
 $Cert.NotAfter = $NotAfter
 foreach ($item in $ExtensionsToAdd) {$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
 if (![string]::IsNullOrEmpty($SerialNumber)) {
                 if ($SerialNumber -match "[^0-9a-fA-F]") {throw "Invalid serial number specified."}
                 if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
                 $Bytes = $SerialNumber -split "(.{2})" | Where-Object {$_} | ForEach-Object{[Convert]::ToByte($_,16)}
                 $ByteString = [Convert]::ToBase64String($Bytes)
                 $Cert.SerialNumber.InvokeSet($ByteString,1)
 }
 if ($AllowSMIME) {$Cert.SmimeCapabilities = $true}
 $SigOID = New-Object -ComObject X509Enrollment.CObjectId
 $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
 $Cert.SignatureInformation.HashAlgorithm = $SigOID
 # completing certificate request template building
 $Cert.Encode()

 # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
 $Request = New-Object -ComObject X509Enrollment.CX509enrollment
 $Request.InitializeFromRequest($Cert)
 $Request.CertificateFriendlyName = $FriendlyName
 $endCert = $Request.CreateRequest($Base64)
 $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
 [Byte[]]$CertBytes = [Convert]::FromBase64String($endCert)
 $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$CertBytes)

 $path = "cert:\LocalMachine\My\" + $certificate.Thumbprint

 $vaultCert = Get-ChildItem -path $path

 if($vaultCert)
 {
     $certPublicData = [System.Convert]::ToBase64String($vaultCert.RawData)
     $certPrivateData = [System.Convert]::ToBase64String($vaultCert.Export('Pfx'))
 }
 else
 {
     throw "=== Exception Exception Exception ==="
 }
 $props = @{
     privatedata = $certPrivateData
     publicdata = $certPublicData
     thumbprint = $vaultCert.Thumbprint
 }

 $generatecertificate = New-Object PSObject
 Add-Member -InputObject $generatecertificate -MemberType NoteProperty -Name "generatecertificate" -Value $props
 $generatecertificate

}
## [END] New-WACABCert ##
function New-WACABCertificate {
<#

.SYNOPSIS
Generates certificates

.DESCRIPTION
Generates certificates

.ROLE
Administrators

#>

# Works only for >= Windows 10 and Win Server 2016

$certName = "{0}{1}-{2}-vaultcredentials" -f 'prefix', 'subscriptionId', (Get-Date -f "M-d-yyyy")
$startTime = [System.DateTime]::UtcNow
$startTime = $startTime.AddMinutes(-15)
$endTime = [System.DateTime]::UtcNow
$endTime = $endTime.AddDays(1)
# keeping it here for reference
#$cert = New-SelfSignedCertificate -DnsName azurebackup -CertStoreLocation cert:\LocalMachine\My
$cert = New-SelfSignedCertificate -Subject "CN=Windows Azure Tools" -NotBefore $startTime -NotAfter $endTime -Provider "Microsoft Enhanced Cryptographic Provider v1.0" -KeyAlgorithm RSA -KeyExportPolicy Exportable -KeyLength 2048 -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -KeyUsage None
$certPublicData = [System.Convert]::ToBase64String($cert.RawData)
$certPrivateData = [System.Convert]::ToBase64String($cert.Export('Pfx'))
$props = @{
    privatedata = $certPrivateData
    publicdata = $certPublicData
    thumbprint = $cert.Thumbprint
}

$generatecertificate = New-Object PSObject
Add-Member -InputObject $generatecertificate -MemberType NoteProperty -Name "generatecertificate" -Value $props
$generatecertificate

}
## [END] New-WACABCertificate ##
function New-WACABCertificateMakeCert {
<#########################################################################################################
# File: GenerateCertificateMAkeCert.ps1
#
# .DESCRIPTION
#
#  Generates the certificate required to create a vault cred file and register the agent on target
#  Uses Makecert which needs to be present on target machine
#
#  The supported Operating Systems are Windows Server 2008 R2, Window Server 2012, 
#
#  Windows Server 2012R2, Windows Server 2016.
#
#  Copyright (c) Microsoft Corp 2017.
#
#########################################################################################################>

<#

.SYNOPSIS
Generates certificates

.DESCRIPTION
Generates certificates

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$certName = "{0}{1}-{2}-vaultcredentials" -f 'prefix', 'subscriptionId', (Get-Date -f "M-d-yyyy")
$certFileName = $certName + '.cer'
$startTime = [System.DateTime]::UtcNow
$startTime = $startTime.AddMinutes(-15)
$endTime = [System.DateTime]::UtcNow
$endTime = $endTime.AddDays(1)
$endTime = $endTime.tostring("MM/dd/yyyy")
$makecertResult = makecert.exe -r -pe -n CN=$certName -ss my -sr localmachine -eku 1.3.6.1.5.5.7.3.2 -len 2048 -e $endTime $certFileName
$certs = Get-ChildItem -Path "cert:\localMachine\my"
$vaultCert = $NULL
foreach ($cert in $certs)
{
    if($cert.SubjectName.Name -match $certName)
    {
        $vaultCert = $cert
        break;
    }
}
if($vaultCert)
{
    $certPublicData = [System.Convert]::ToBase64String($vaultCert.RawData)
    $certPrivateData = [System.Convert]::ToBase64String($vaultCert.Export('Pfx'))
}
else
{
    throw "=== Exception Exception Exception ==="
}
$props = @{
    privatedata = $certPrivateData
    publicdata = $certPublicData
    thumbprint = $vaultCert.Thumbprint
}

$generatecertificate = New-Object PSObject
Add-Member -InputObject $generatecertificate -MemberType NoteProperty -Name "generatecertificate" -Value $props
$generatecertificate

}
## [END] New-WACABCertificateMakeCert ##
function Register-WACABMARSAgent {
<#

.SYNOPSIS
Registers MARS agent

.DESCRIPTION
Registers MARS agent

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [String]
    $vaultCredString,
    [Parameter(Mandatory = $true)]
    [String]
    $passphrase
)
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $date = Get-Date
    $vaultcredPath = $env:TEMP + '\honoluluvaultcredential_' + $date.Day + "_" + $date.Month + "_" + $date.Year + "_" + '.vaultcredentials';
    $vaultCredString | Out-File $vaultcredPath
    Start-OBRegistration -VaultCredentials $vaultcredPath -Confirm:$false
    $securePassphrase = ConvertTo-SecureString -String $passphrase -AsPlainText -Force
    Set-OBMachineSetting -EncryptionPassphrase $securePassphrase -SecurityPIN " "
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}


}
## [END] Register-WACABMARSAgent ##
function Remove-WACABAllPolicies {
<#

.SYNOPSIS
Deletes agent status

.DESCRIPTION
Deletes agent status

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $false)]
    [string]
    $pin
)

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexisted = $false
    $ssbexisted = $false
    $filedeleted = $false
    $ssbdeleted = $false

    $pol = Get-OBPolicy
    $ssbpol = Get-OBSystemStatePolicy

    if ($pol) {
        $fileexisted = $true
    }
    if ($ssbpol) {
        $ssbexisted = $true
    }

    if ($pol -or $ssbpol) {
        if ($pol) {
            $ans = Remove-OBPolicy -Policy $pol -SecurityPIN $pin -Confirm:$false -DeleteBackup:$true
        }
        else {
            $ans = Remove-OBSystemStatePolicy -Policy $pol -SecurityPIN $pin -Confirm:$false -DeleteBackup:$true
        }

        $policy = get-obpolicy
        if ($policy) {
            $filedeleted = $false
        }
        else {
            $filedeleted = $true
        }

        $ssbpolicy = Get-OBSystemStatePolicy
        if ($ssbpolicy) {
            $ssbdeleted = $false
        }
        else {
            $ssbdeleted = $true
        }
    }

    $props = @{
        filedeleted = $filedeleted
        ssbdeleted  = $ssbdeleted
        fileexisted = $fileexisted
        ssbexisted  = $ssbexisted
    }

    $deletiondetails = New-Object PSObject
    Add-Member -InputObject $deletiondetails -MemberType NoteProperty -Name "deletiondetails" -Value $props
    $deletiondetails

}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Remove-WACABAllPolicies ##
function Remove-WACABSSBPolicy {
<#

.SYNOPSIS
 Deletes SSB policy backup data from Azure Backup agent.

.DESCRIPTION
 Deletes SSB policy backup data from Azure Backup agent.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $false)]
    [string]
    $pin
)

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $ssbexisted = $false
    $ssbdeleted = $false

    $ssbpol = Get-OBSystemStatePolicy

    if ($ssbpol) {
        $ssbexisted = $true
    }

    if ($ssbpol) {
        $ssbans = Remove-OBSystemStatePolicy -Policy $ssbpol -SecurityPIN $pin -Confirm:$false -DeleteBackup:$true
        if ($ssbans) {
            $ssbdeleted = $true
        }
        else {
            $ssbdeleted = $false
        }
    }

    $props = @{
        ssbdeleted = $ssbdeleted
        ssbexisted = $ssbexisted
    }

    $deletiondetails = New-Object PSObject
    Add-Member -InputObject $deletiondetails -MemberType NoteProperty -Name "deletiondetails" -Value $props
    $deletiondetails

}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Remove-WACABSSBPolicy ##
function Resume-WACABFileFolderPolicy {
<#

.SYNOPSIS
To resume the FileFolder policy

.DESCRIPTION
To resume the FileFolder policy

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexisted = $false
    $fileresumed = $false

    $pol = Get-OBPolicy

    if ($pol) {
        $fileexisted = $true
    }

    if ($pol) {
        $ans1 = Set-OBPolicyState $pol -Confirm:$false -State Valid -ErrorAction SilentlyContinue
        $ans2 = Set-OBPolicy $pol -Confirm:$false -ErrorAction SilentlyContinue
        if ($ans1 -and $ans2) {
            $fileresumed = $true
        }
        else {
            $fileresumed = $false
        }
    }

    $props = @{
        fileresumed = $fileresumed
        fileexisted = $fileexisted
    }

    $resumedetails = New-Object PSObject
    Add-Member -InputObject $resumedetails -MemberType NoteProperty -Name "resumedetails" -Value $props
    $resumedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Resume-WACABFileFolderPolicy ##
function Resume-WACABSystemStatePolicy {
<#

.SYNOPSIS
To resume the system state policy

.DESCRIPTION
To resume the system state policy

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $ssbexisted = $false
    $ssbresumed = $false

    $pol = Get-OBSystemStatePolicy

    if ($pol) {
        $ssbexisted = $true
    }

    if ($pol) {
        $ans1 = Set-OBPolicyState $pol -Confirm:$false -State Valid -ErrorAction SilentlyContinue
        $ans2 = Set-OBSystemStatePolicy $pol -Confirm:$false -ErrorAction SilentlyContinue
        if ($ans1 -and $ans2) {
            $ssbresumed = $true
        }
        else {
            $ssbresumed = $false
        }
    }

    $props = @{
        ssbresumed = $ssbresumed
        ssbexisted = $ssbexisted
    }

    $resumedetails = New-Object PSObject
    Add-Member -InputObject $resumedetails -MemberType NoteProperty -Name "resumedetails" -Value $props
    $resumedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Resume-WACABSystemStatePolicy ##
function Set-WACABFileFolderPolicy {
<#

.SYNOPSIS
 Modify file folder policy

.DESCRIPTION
 Modify file folder policy

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string[]]
    $filePath,
    [Parameter(Mandatory = $true)]
    [string[]]
    $daysOfWeek,
    [Parameter(Mandatory = $true)]
    [string[]]
    $timesOfDay,
    [Parameter(Mandatory = $true)]
    [int]
    $weeklyFrequency,

    [Parameter(Mandatory = $false)]
    [int]
    $retentionDays,

    [Parameter(Mandatory = $false)]
    [Boolean]
    $retentionWeeklyPolicy,
    [Parameter(Mandatory = $false)]
    [int]
    $retentionWeeks,

    [Parameter(Mandatory = $false)]
    [Boolean]
    $retentionMonthlyPolicy,
    [Parameter(Mandatory = $false)]
    [int]
    $retentionMonths,

    [Parameter(Mandatory = $false)]
    [Boolean]
    $retentionYearlyPolicy,
    [Parameter(Mandatory = $false)]
    [int]
    $retentionYears
)
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $timesOfDaySchedule = @()
    foreach ($time in $timesOfDay) {
        $timesOfDaySchedule += ([TimeSpan]$time)
    }
    $daysOfWeekSchedule = @()
    foreach ($day in $daysOfWeek) {
        $daysOfWeekSchedule += ([System.DayOfWeek]$day)
    }

    $schedule = New-OBSchedule -DaysOfWeek $daysOfWeekSchedule -TimesOfDay $timesOfDaySchedule -WeeklyFrequency $weeklyFrequency
    if ($daysOfWeekSchedule.Count -eq 7) {
        if ($retentionWeeklyPolicy -and $retentionMonthlyPolicy -and $retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionWeeklyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionWeeklyPolicy -and $retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionYearlyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionWeeklyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks
        }
        elseif ($retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        else {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays
        }
    }
    else {
        if ($retentionWeeklyPolicy -and $retentionMonthlyPolicy -and $retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionWeeklyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionWeeklyPolicy -and $retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionYearlyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
        elseif ($retentionWeeklyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks
        }
        elseif ($retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionYearlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionYearlyPolicy:$true -YearDaysOfWeek $daysOfWeekSchedule -YearTimesOfDay $timesOfDaySchedule -RetentionYears $retentionYears
        }
    }


    $oldPolicy = Get-OBPolicy
    if ($oldPolicy) {
        $ospec = Get-OBFileSpec $oldPolicy

        $p = Remove-OBFileSpec -FileSpec $ospec -Policy $oldPolicy -Confirm:$false

        $fileSpec = New-OBFileSpec -FileSpec $filePath

        Add-OBFileSpec -Policy $p -FileSpec $fileSpec -Confirm:$false
        Set-OBSchedule -Policy $p -Schedule $schedule -Confirm:$false
        Set-OBRetentionPolicy -Policy $p -RetentionPolicy $retention -Confirm:$false
        Set-OBPolicy -Policy $p -Confirm:$false
        $p
    }
    else {
        $policy = New-OBPolicy
        $fileSpec = New-OBFileSpec -FileSpec $filePath
        Add-OBFileSpec -Policy $policy -FileSpec $fileSpec
        Set-OBSchedule -Policy $policy -Schedule $schedule
        Set-OBRetentionPolicy -Policy $policy -RetentionPolicy $retention
        Set-OBPolicy -Policy $policy -Confirm:$false
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Set-WACABFileFolderPolicy ##
function Set-WACABMARSAgent {
<#

.SYNOPSIS
Sets MARS agent

.DESCRIPTION
Sets MARS agent

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$ErrorActionPreference = "Stop"
Try {
    $agentPath = $env:TEMP + '\MARSAgentInstaller.exe'
    Invoke-WebRequest -Uri 'https://aka.ms/azurebackup_agent' -OutFile $agentPath
    & $agentPath /q | out-null

    $env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
    $azureBackupModuleName = 'MSOnlineBackup'
    $azureBackupModule = Get-Module -ListAvailable -Name $azureBackupModuleName
    if ($azureBackupModule) {
        $true
    }
    else {
        $false
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}
}
## [END] Set-WACABMARSAgent ##
function Set-WACABSystemStatePolicy {
<#

.SYNOPSIS
Modify system state policy

.DESCRIPTION
Modify system state policy

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [string[]]
    $daysOfWeek,
    [Parameter(Mandatory = $true)]
    [string[]]
    $timesOfDay,
    [Parameter(Mandatory = $true)]
    [int]
    $weeklyFrequency,

    [Parameter(Mandatory = $false)]
    [int]
    $retentionDays,

    [Parameter(Mandatory = $false)]
    [Boolean]
    $retentionWeeklyPolicy,
    [Parameter(Mandatory = $false)]
    [int]
    $retentionWeeks,

    [Parameter(Mandatory = $false)]
    [Boolean]
    $retentionMonthlyPolicy,
    [Parameter(Mandatory = $false)]
    [int]
    $retentionMonths
)
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $oldPolicy = Get-OBSystemStatePolicy
    if ($oldPolicy) {
        return
    }
    $policy = New-OBPolicy
    $policy = Add-OBSystemState -Policy $policy

    $timesOfDaySchedule = @()
    foreach ($time in $timesOfDay) {
        $timesOfDaySchedule += ([TimeSpan]$time)
    }
    $daysOfWeekSchedule = @()
    foreach ($day in $daysOfWeek) {
        $daysOfWeekSchedule += ([System.DayOfWeek]$day)
    }

    $schedule = New-OBSchedule -DaysOfWeek $daysOfWeekSchedule -TimesOfDay $timesOfDaySchedule -WeeklyFrequency $weeklyFrequency
    if ($daysOfWeekSchedule.Count -eq 7) {
        if ($retentionWeeklyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionWeeklyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks
        }
        elseif ($retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        else {
            $retention = New-OBRetentionPolicy -RetentionDays $retentionDays
        }
    }
    else {
        if ($retentionWeeklyPolicy -and $retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
        elseif ($retentionWeeklyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionWeeklyPolicy:$true -WeekDaysOfWeek $daysOfWeekSchedule -WeekTimesOfDay $timesOfDaySchedule -RetentionWeeks $retentionWeeks
        }
        elseif ($retentionMonthlyPolicy) {
            $retention = New-OBRetentionPolicy -RetentionMonthlyPolicy:$true -MonthDaysOfWeek $daysOfWeekSchedule -MonthTimesOfDay $timesOfDaySchedule -RetentionMonths $retentionMonths
        }
    }
    Set-OBSchedule -Policy $policy -Schedule $schedule
    Set-OBRetentionPolicy -Policy $policy -RetentionPolicy $retention
    Set-OBSystemStatePolicy -Policy $policy -Confirm:$false
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Set-WACABSystemStatePolicy ##
function Start-WACABFileFolderBackup {
<#

.SYNOPSIS
Starts file folder backup

.DESCRIPTION
Starts file folder backup

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    Get-OBPolicy | Start-OBBackup
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}
}
## [END] Start-WACABFileFolderBackup ##
function Start-WACABRecoveryMount {
<#

.SYNOPSIS
 Start the recovery job.

.DESCRIPTION
 Start the recovery job.

.ROLE
Administrators

#>
param (
    [Parameter(Mandatory = $true)]
    [int]
    $sourcePosition,
    [Parameter(Mandatory = $true)]
    [int]
    $itemPosition
)


Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {

    $job = Get-OBJob
    $driveLetter = ''
    $timeout = new-timespan -Minutes 180
    $preempt = new-timespan -Minutes 29

    $recoveryStarted = $false
    $diskmounted = $false

    if ($job) {
        $recoveryStarted = $false
    }
    else {
        $sources = Get-OBRecoverableSource
        $items = Get-OBRecoverableItem $sources[$sourcePosition]
        $recoveryJob = Start-OBRecoveryMount $items[$itemPosition] -Async
        $stopWatch = [diagnostics.stopwatch]::StartNew()
        $recoveryStarted = $true
        do {
            Start-sleep -seconds 10
            $job = Get-OBJob
            if ($job -and $job.jobstatus -and $job.jobstatus.datasourcestatus[0]) {
                $driveLetter = $job.jobstatus.datasourcestatus[0].driveletter
            }
            if ([char]::IsLetter($driveLetter)) {
                $diskmounted = $true
                break
            }
            if ($stopWatch.elapsed -gt $timeout -or
                (($stopWatch.elapsed -gt $preempt -and $job.JobStatus.DatasourceStatus -and $Job.JobStatus.DatasourceStatus.length -gt 0) -and $job.JobStatus.DatasourceStatus[0].ByteProgress.Progress -lt 64 * 1024)) {
                break
            }
        } while ($true)
    }

    $props = @{
        recoveryStarted = $recoveryStarted
        diskmounted     = $diskmounted
    }

    $recoverystatus = New-Object PSObject
    Add-Member -InputObject $recoverystatus -MemberType NoteProperty -Name "recoverystatus" -Value $props
    $recoverystatus
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Start-WACABRecoveryMount ##
function Start-WACABSystemStateBackup {
<#

.SYNOPSIS
Starts system state backup

.DESCRIPTION
Starts system state backup

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    Start-OBSystemStateBackup
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}
}
## [END] Start-WACABSystemStateBackup ##
function Stop-WACABBackupJob {
<#

.SYNOPSIS
Stops backup job

.DESCRIPTION
Stops backup job

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $job = Get-OBJob
    if ($job -ne $NULL -and $job.JobType -eq "Backup") {
        Stop-OBJob -Job $job -Confirm:$false
        return $true
    }
    else {
        return $false;
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Stop-WACABBackupJob ##
function Stop-WACABRecoveryJob {
<#

.SYNOPSIS
Stops the currently ongoing backup job on the target

.DESCRIPTION
Stops the currently ongoing backup job on the target

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $job = Get-OBJob
    if ($job -ne $NULL -and $job.JobType.toString() -eq "Recovery") {
        Stop-OBJob -Job $job -Confirm:$false
        return $true
    }
    else {
        return $false;
    }
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Stop-WACABRecoveryJob ##
function Suspend-WACABFileFolderPolicy {
<#

.SYNOPSIS
To pause FileFolder policy

.DESCRIPTION
To pause FileFolder policy

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $fileexisted = $false
    $filepaused = $false

    $pol = Get-OBPolicy

    if ($pol) {
        $fileexisted = $true
    }

    if ($pol) {
        $ans1 = Set-OBPolicyState $pol -Confirm:$false -State Paused -ErrorAction SilentlyContinue
        $ans2 = Set-OBPolicy $pol -Confirm:$false -ErrorAction SilentlyContinue
        if ($ans1 -and $ans2) {
            $filepaused = $true
        }
        else {
            $filepaused = $false
        }
    }

    $props = @{
        filepaused  = $filepaused
        fileexisted = $fileexisted
    }

    $pausedetails = New-Object PSObject
    Add-Member -InputObject $pausedetails -MemberType NoteProperty -Name "pausedetails" -Value $props
    $pausedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Suspend-WACABFileFolderPolicy ##
function Suspend-WACABSystemStatePolicy {
<#

.SYNOPSIS
To pause the system state policy

.DESCRIPTION
To pause the system state policy

.ROLE
Administrators

#>
Set-StrictMode -Version 5.0
$env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
Import-Module MSOnlineBackup
$ErrorActionPreference = "Stop"
Try {
    $ssbexisted = $false
    $ssbpaused = $false

    $pol = Get-OBSystemStatePolicy

    if ($pol) {
        $ssbexisted = $true
    }

    if ($pol) {
        $ans1 = Set-OBPolicyState $pol -Confirm:$false -State Paused -ErrorAction SilentlyContinue
        $ans2 = Set-OBSystemStatePolicy $pol -Confirm:$false -ErrorAction SilentlyContinue
        if ($ans1 -and $ans2) {
            $ssbpaused = $true
        }
        else {
            $ssbpaused = $false
        }
    }

    $props = @{
        ssbpaused  = $ssbpaused
        ssbexisted = $ssbexisted
    }

    $pausedetails = New-Object PSObject
    Add-Member -InputObject $pausedetails -MemberType NoteProperty -Name "pausedetails" -Value $props
    $pausedetails
}
Catch {
    if ($error[0].ErrorDetails) {
        throw $error[0].ErrorDetails
    }
    throw $error[0]
}

}
## [END] Suspend-WACABSystemStatePolicy ##

# SIG # Begin signature block
# MIIoVQYJKoZIhvcNAQcCoIIoRjCCKEICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD2g7FFbYIYFi9U
# U8uUC1JG8TExgMC7TP6Ewbq92T0dAaCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMxs
# lHKwybFRspy5XchsEKSOkrjWbN7QWhSpoKTFBGsjMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAdvG0szFLN/+LlmQ4o25YbW3Tcj5xrlF2RU92
# TbYO8tOKrX3amUlyceRMvFgtANjyDPkSgxBARjbfmghPJrXCQsATmM3DLDFav9+g
# T55C9/n4AsuIoh42gw4b1F8j5WR9ePQnI8FRomxMYKwajIGcPNm6zemcQtWgsyeB
# BbaRiOI11y/rP6pJCCrFtbp0wjETKds0vU8LMOxhl8qu3ScCGyMLDz8duXCzpgFh
# B7areWGJeizVY0SAM5b4/A6p5SrqDyp8MberBH3CdLqcCxFnQngmeK7nZkEVmapJ
# NqzReBV50IQ072V7TMCFpqEmOLyZ6S/QHQybJNtMUosry5Yx3KGCF7AwghesBgor
# BgEEAYI3AwMBMYIXnDCCF5gGCSqGSIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAxWR+LNgn08Ab/t3rblNVASkfVxL28DtO3
# s9bbO4ORaQIGaQKOSQODGBMyMDI1MTExMDE3MTcyNC4wNjhaMASAAgH0oIHZpIHW
# MIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjozMjFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEf4wggcoMIIFEKADAgECAhMzAAACGqmg
# HQagD0OqAAEAAAIaMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTI1MDgxNDE4NDgyOFoXDTI2MTExMzE4NDgyOFowgdMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjMyMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# mYEAwSTz79q2V3ZWzQ5Ev7RKgadQtMBy7+V3XQ8R0NL8R9mupxcqJQ/KPeZGJTER
# +9Qq/t7HOQfBbDy6e0TepvBFV/RY3w+LOPMKn0Uoh2/8IvdSbJ8qAWRVoz2S9VrJ
# zZpB8/f5rQcRETgX/t8N66D2JlEXv4fZQB7XzcJMXr1puhuXbOt9RYEyN1Q3Z7Yj
# RkhfBsRc+SD/C9F4iwZqfQgo82GG4wguIhjJU7+XMfrv4vxAFNVg3mn1PoMWGZWi
# o+e14+PGYPVLKlad+0IhdHK5AgPyXKkqAhEZpYhYYVEItHOOvqrwukxVAJXMvWA3
# GatWkRZn33WDJVtghCW6XPLi1cDKiGE5UcXZSV4OjQIUB8vp2LUMRXud5I49FIBc
# E9nT00z8A+EekrPM+OAk07aDfwZbdmZ56j7ub5fNDLf8yIb8QxZ8Mr4RwWy/czBu
# V5rkWQQ+msjJ5AKtYZxJdnaZehUgUNArU/u36SH1eXKMQGRXr/xeKFGI8vvv5Jl1
# knZ8UqEQr9PxDbis7OXp2WSMK5lLGdYVH8VownYF3sbOiRkx5Q5GaEyTehOQp2Sf
# dbsJZlg0SXmHphGnoW1/gQ/5P6BgSq4PAWIZaDJj6AvLLCdbURgR5apNQQed2zYU
# gUbjACA/TomA8Ll7Arrv2oZGiUO5Vdi4xxtA3BRTQTUCAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBTwqyIJ3QMoPasDcGdGovbaY8IlNjAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEA1a72WFq7B6bJT3VOJ21nnToPJ9O/q51bw1bhPfQy67uy+f8x8akipzNL
# 2k5b6mtxuPbZGpBqpBKguDwQmxVpX8cGmafeo3wGr4a8Yk6Sy09tEh/Nwwlsyq7B
# RrJNn6bGOB8iG4OTy+pmMUh7FejNPRgvgeo/OPytm4NNrMMg98UVlrZxGNOYsifp
# RJFg5jE/Yu6lqFa1lTm9cHuPYxWa2oEwC0sEAsTFb69iKpN0sO19xBZCr0h5ClU9
# Pgo6ekiJb7QJoDzrDoPQHwbNA87Cto7TLuphj0m9l/I70gLjEq53SHjuURzwpmNx
# dm18Qg+rlkaMC6Y2KukOfJ7oCSu9vcNGQM+inl9gsNgirZ6yJk9VsXEsoTtoR7fM
# NU6Py6ufJQGMTmq6ZCq2eIGOXWMBb79ZF6tiKTa4qami3US0mTY41J129XmAglVy
# +ujSZkHu2lHJDRHs7FjnIXZVUE5pl6yUIl23jG50fRTLQcStdwY/LvJUgEHCIzjv
# lLTqLt6JVR5bcs5aN4Dh0YPG95B9iDMZrq4rli5SnGNWev5LLsDY1fbrK6uVpD+p
# svSLsNpht27QcHRsYdAMALXM+HNsz2LZ8xiOfwt6rOsVWXoiHV86/TeMy5TZFUl7
# qB59INoMSJgDRladVXeT9fwOuirFIoqgjKGk3vO2bELrYMN0QVwwggdxMIIFWaAD
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
# Hm5TaGllbGQgVFNTIEVTTjozMjFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8YrutmKpSrub
# CaAYsU4pt1Ft8DaggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQsFAAIFAOy8NTIwIhgPMjAyNTExMTAwOTU2MDJaGA8yMDI1
# MTExMTA5NTYwMlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7Lw1MgIBADAKAgEA
# AgIBswIB/zAHAgEAAgITATAKAgUA7L2GsgIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# CwUAA4IBAQB0j7yxUro/gzCtwCHCV01LfwTXHOumxuPzLsLl19QW1R/r2zdLJ8wR
# bWvxchEcqoapMRU7AEpJR4Rfm9OBHptRSddt9IRysrTU3cwkF7VQsf75aIu/n6Jr
# 4ukCJ2eLjVfZ1odthy+aaFfFUQNW+7BnxHsnpvW/Sg7oL4PwMFraxXeJFGEp8L35
# 0hjL+oN0FjUWoDDLWBGrgfJroJU6i25wJplmtBxv8CyZntcJq2xgzBE2n76LfwDq
# Aw2N9CEhXG03w2BVYNFqjxlb4/unXHloDuvWMSbyFo2Gt20SwyNZa+G02wpQq+4a
# rnd+1pAgKYXDz/wqtpeTb+qVxxPzswMNMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIaqaAdBqAPQ6oAAQAAAhowDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgDi/wWfz2G9dq8JmBB7ygwAFj6oWdL5jjE70eIVeECBEwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCdeiHHrbtpKcwB20doVU89WHIOH8S7w37u
# aHcDmemK+zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAACGqmgHQagD0OqAAEAAAIaMCIEIKPNFLzj+7E9mXDA/zdHxTSaFDNlSt/bn9SH
# lqQLiN7nMA0GCSqGSIb3DQEBCwUABIICAHpqcMPpjVZEPKqDGG4FpZVsg7OR28rz
# IvRrGL1KvWGq2LVkNCs92JhnQczwJT4HMXG32ax1Dy1qSyOtGQhUUO6liT+r4Vnw
# aknVRAaARfgJSnSCLkF68F0tWuc+VFD9NmNnCeUrhV7fCqMT6MkTIhv6qN8EQfBC
# aKwKDIxZ27VQdibqNCwWwGjsECADC+QcK/QpS+D4SvR33a232BM1tWVr8EzWmEl7
# a6xEyZqzMJBnrRg/IA4teZHTfgJfP7SkxWwzcvssTGVr03jyaV1A1B+1J1UQeAdV
# 1+boO0jQ4aISG2sfcHEba1XBkXii9PtriPRY+qGPiAT9dsjtoRvHNSwAtMYZILvM
# 2sFodtdd6xmhqvnN64O2gzj2AVgwS2XEibyyh8x8M8Km1L7z44+AS0Aus2IvSBod
# lhLR3nL2Dws6j312Hml+kaUUNYV+Vuz4kvZs7ZTwSS3ARXpcrmBq5W7V5kd+imtG
# CNpevxhVNTGD7Og5zX9xmxjPEfy778t5pwSNzP8IcDhLEtfV2OF+L0Yi2IEwxOXe
# vdEajQMGYToxL4czUCbADUu7ck9A+EsBAlse+S5fzP5JHmTn3w1weWP1ar+uBcXh
# OQbGApx4cEDXVrgHW53p+jBylKXpbsihcElGuP8cZNF3wXLZH0Vgo+8ARlg8KfvI
# K0dip4qTNVow
# SIG # End signature block
