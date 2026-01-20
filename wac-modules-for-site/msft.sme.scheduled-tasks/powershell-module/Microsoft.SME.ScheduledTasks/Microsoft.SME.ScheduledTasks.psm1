function Add-WACSTScheduledTaskAction {
<#

.SYNOPSIS
Adds a new action to existing scheduled task actions.

.DESCRIPTION
Adds a new action to existing scheduled task actions.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER actionExecute
    The name of executable to run. By default looks in System32 if Working Directory is not provided

.PARAMETER actionArguments
    The arguments for the executable.

.PARAMETER workingDirectory
    The path to working directory
#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [parameter(Mandatory=$true)]
    [string]
    $actionExecute,
    [string]
    $actionArguments,
    [string]
    $workingDirectory  
)

Import-Module ScheduledTasks

#
# Prepare action parameter bag
#
$taskActionParams = @{
    Execute = $actionExecute;
} 

if ($actionArguments) {
    $taskActionParams.Argument = $actionArguments;
}
if ($workingDirectory) {
     $taskActionParams.WorkingDirectory = $workingDirectory;
}

######################################################
#### Main script
######################################################

# Create action object
$action = New-ScheduledTaskAction @taskActionParams

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$actionsArray =  $task.Actions
$actionsArray += $action 
Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}
## [END] Add-WACSTScheduledTaskAction ##
function Add-WACSTScheduledTaskTrigger {
 <#

.SYNOPSIS
Adds a new trigger to existing scheduled task triggers.

.DESCRIPTION
Adds a new trigger to existing scheduled task triggers.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskDescription
    The description of the task.

.PARAMETER taskPath
    The task path.

.PARAMETER triggerAt
    The date/time to trigger the task.    

.PARAMETER triggerFrequency
    The frequency of the task occurence. Possible values Daily, Weekly, Monthly, Once, AtLogOn, AtStartup

.PARAMETER daysInterval
    The number of days interval to run task.

.PARAMETER weeklyInterval
    The number of weeks interval to run task.

.PARAMETER daysOfWeek
    The days of the week to run the task. Possible values can be an array of Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday

.PARAMETER username
    The username associated with the trigger.

.PARAMETER repetitionInterval
    The repitition interval.

.PARAMETER repetitionDuration
    The repitition duration.

.PARAMETER randomDelay
    The delay before running the trigger.
#>
 param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [AllowNull()][System.Nullable[DateTime]]
    $triggerAt,
    [parameter(Mandatory=$true)]
    [string]
    $triggerFrequency, 
    [Int32]
    $daysInterval, 
    [Int32]
    $weeksInterval,
    [string[]]
    $daysOfWeek,
    [string]
    $username,
    [string]
    $repetitionInterval,
    [string]
    $repetitionDuration,
    [boolean]
    $stopAtDurationEnd,
    [string]
    $randomDelay,
    [string]
    $executionTimeLimit
)

Import-Module ScheduledTasks

#
# Prepare task trigger parameter bag
#
$taskTriggerParams = @{} 

if ($triggerAt -and $triggerFrequency -in ('Daily','Weekly', 'Once')) {
   $taskTriggerParams.At =  $triggerAt;
}
   
    
# Build optional switches
if ($triggerFrequency -eq 'Daily' )
{
    $taskTriggerParams.Daily = $true;
    if ($daysInterval -ne 0) 
    {
       $taskTriggerParams.DaysInterval = $daysInterval;
    }
}
elseif ($triggerFrequency -eq 'Weekly')
{
    $taskTriggerParams.Weekly = $true;
    if ($weeksInterval -ne 0) 
    {
        $taskTriggerParams.WeeksInterval = $weeksInterval;
    }
    if ($daysOfWeek -and $daysOfWeek.Length -gt 0) 
    {
        $taskTriggerParams.DaysOfWeek = $daysOfWeek;
    }
}
elseif ($triggerFrequency -eq 'Once')
{
    $taskTriggerParams.Once = $true;
}
elseif ($triggerFrequency -eq 'AtLogOn')
{
    $taskTriggerParams.AtLogOn = $true;
}
elseif ($triggerFrequency -eq 'AtStartup')
{
    $taskTriggerParams.AtStartup = $true;
}

if ($username) 
{
   $taskTriggerParams.User = $username;
}


######################################################
#### Main script
######################################################

# Create trigger object
$triggersArray = @()
$triggerNew = New-ScheduledTaskTrigger @taskTriggerParams

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$triggersArray =  $task.Triggers

Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggerNew | out-null

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$trigger = $task.Triggers[0]


if ($repetitionInterval -and $trigger.Repetition -ne $null) 
{
   $trigger.Repetition.Interval = $repetitionInterval;
}
if ($repetitionDuration -and $trigger.Repetition -ne $null) 
{
   $trigger.Repetition.Duration = $repetitionDuration;
}
if ($stopAtDurationEnd -and $trigger.Repetition -ne $null) 
{
   $trigger.Repetition.StopAtDurationEnd = $stopAtDurationEnd;
}
if($executionTimeLimit) {
 $task.Triggers[0].ExecutionTimeLimit = $executionTimeLimit;
}

if([bool]($task.Triggers[0].PSobject.Properties.name -eq "RandomDelay")) 
{
    $task.Triggers[0].RandomDelay = $randomDelay;
}

if([bool]($task.Triggers[0].PSobject.Properties.name -eq "Delay")) 
{
    $task.Triggers[0].Delay = $randomDelay;
}

$triggersArray += $trigger

Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggersArray 
}
## [END] Add-WACSTScheduledTaskTrigger ##
function Disable-WACSTScheduledTask {
<#

.SYNOPSIS
Script to disable a scheduled tasks.

.DESCRIPTION
Script to disable a scheduled tasks.

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $true)]
  [String]
  $taskName
)
Import-Module ScheduledTasks

Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName

}
## [END] Disable-WACSTScheduledTask ##
function Enable-WACSTScheduledTask {
<#

.SYNOPSIS
Script to enable a scheduled tasks.

.DESCRIPTION
Script to enable a scheduled tasks.

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $true)]
  [String]
  $taskName
)

Import-Module ScheduledTasks

Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName

}
## [END] Enable-WACSTScheduledTask ##
function Get-WACSTEventLogs {
<#

.SYNOPSIS
Script to get event logs and sources.

.DESCRIPTION
Script to get event logs and sources. This is used to allow user selection when creating event based triggers.

.ROLE
Readers

#>

Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue

Get-WinEvent -ListLog * -ErrorAction SilentlyContinue

}
## [END] Get-WACSTEventLogs ##
function Get-WACSTScheduledTasks {
<#

.SYNOPSIS
Script to get list of scheduled tasks.

.DESCRIPTION
Script to get list of scheduled tasks.

.ROLE
Readers

#>

param (
  [Parameter(Mandatory = $false)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $false)]
  [String]
  $taskName
)

Import-Module ScheduledTasks

Add-Type -AssemblyName "System.Linq"
Add-Type -AssemblyName "System.Xml"
Add-Type -AssemblyName "System.Xml.Linq"

function ConvertTo-CustomTriggerType ($trigger) {
  $customTriggerType = ''
  if ($trigger.CimClass -and $trigger.CimClass.CimClassName) {
    $cimClassName = $trigger.CimClass.CimClassName
    if ($cimClassName -eq 'MSFT_TaskTrigger') {
        $ns = [System.Xml.Linq.XNamespace]('http://schemas.microsoft.com/windows/2004/02/mit/task')
        $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
        $d = [System.Xml.Linq.XDocument]::Parse($xml)
        $scheduleByMonth = $d.Descendants($ns + "ScheduleByMonth")
        if ($scheduleByMonth.Count -gt 0) {
          $customTriggerType = 'MSFT_TaskMonthlyTrigger'
        }
        else {
          $scheduleByMonthDOW = $d.Descendants($ns + "ScheduleByMonthDayOfWeek");
          if ($scheduleByMonthDOW.Count -gt 0) {
            $customTriggerType = 'MSFT_TaskMonthlyDOWTrigger'
          }
        }
    }
  }
  return $customTriggerType
}

function New-TaskWrapper
{
  param (
    [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
    $task
  )

  $task | Add-Member -MemberType NoteProperty -Name 'status' -Value $task.state.ToString()
  $info = Get-ScheduledTaskInfo $task

  $triggerCopies = @()
  for ($i=0;$i -lt $task.Triggers.Length;$i++)
  {
    $trigger = $task.Triggers[$i];
    $triggerCopy = $trigger.PSObject.Copy();
    if ($trigger -ne $null) {

        if ($trigger.StartBoundary -eq $null -or$trigger.StartBoundary -eq '')
        {
            $startDate = $null;
        }

        else
        {
            $startDate = [datetime]($trigger.StartBoundary)
        }

        $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerAtDate' -Value $startDate -TypeName System.DateTime

        if ($trigger.EndBoundary -eq $null -or$trigger.EndBoundary -eq '')
        {
            $endDate = $null;
        }

        else
        {
            $endDate = [datetime]($trigger.EndBoundary)
        }

        $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerEndDate' -Value $endDate -TypeName System.DateTime

        $customTriggerType = ConvertTo-CustomTriggerType -trigger $triggerCopy
        if ($customTriggerType) {
          $triggerCopy | Add-Member -MemberType NoteProperty -Name 'CustomParsedTriggerType' -Value $customTriggerType
        }

        $triggerCopies += $triggerCopy
    }

  }

  $task | Add-Member -MemberType NoteProperty -Name 'TriggersEx' -Value $triggerCopies

  New-Object -TypeName PSObject -Property @{

      ScheduledTask = $task
      ScheduledTaskInfo = $info
  }
}

if ($taskPath -and $taskName) {
  try
  {
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
    New-TaskWrapper $task
  }
  catch
  {
  }
} else {
    Get-ScheduledTask | ForEach-Object {
      New-TaskWrapper $_
    }
}

}
## [END] Get-WACSTScheduledTasks ##
function New-WACSTBasicTask {
<#

.SYNOPSIS
Creates and registers a new scheduled task.

.DESCRIPTION
Creates and registers a new scheduled task.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskDescription
    The description of the task.

.PARAMETER taskPath
    The task path.

.PARAMETER taskAuthor
    The task author.

.PARAMETER triggerAt
    The date/time to trigger the task.

.PARAMETER triggerFrequency
    The frequency of the task occurence. Possible values Daily, Weekly, Monthly, Once, AtLogOn, AtStartup

.PARAMETER triggerMonthlyFrequency
    The monthly frequencty of the task occurence. Possible values Monthly (day of month), MonthlyDOW( day of week)

.PARAMETER daysInterval
    The number of days interval to run task.

.PARAMETER weeklyInterval
    The number of weeks interval to run task.

.PARAMETER daysOfWeek
    The days of the week to run the task. Possible values can be an array of Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday

.PARAMETER months
    The months of the year that the task is to run. Possible values January thru February

.PARAMETER daysOfMonth
    The specific days of the month that the task can run. Possible values 1-31 and Last. This applies when the task frequency is Monthly.

.PARAMETER weeksOfMonth
    The specific weeks of the month that the task can run. Possible values 1-4 and Last. This applies when the task frequency is MonthlyDOW.

.PARAMETER actionExecute
    The name of executable to run. By default looks in System32 if Working Directory is not provided

.PARAMETER actionArguments
    The arguments for the executable.

.PARAMETER workingDirectory
    The path to working directory
#>

param (
  [parameter(Mandatory = $true)]
  [string]
  $taskName,
  [string]
  $taskDescription,
  [parameter(Mandatory = $true)]
  [string]
  $taskPath,
  [parameter(Mandatory = $true)]
  [string]
  $taskAuthor,
  [parameter(Mandatory = $true)]
  [string]
  $triggerFrequency,
  [string]
  $triggerMonthlyFrequency,
  [AllowNull()][System.Nullable[DateTime]]
  $triggerAt,
  [Int32]
  $daysInterval,
  [Int32]
  $weeklyInterval,
  [string[]]
  $daysOfWeek,
  [string[]]
  $months = @(),
  [string[]]
  $daysOfMonth = @(),
  [string[]]
  $weeksOfMonth = @(),
  [parameter(Mandatory = $true)]
  [string]
  $actionExecute,
  [string]
  $actionArguments,
  [string]
  $workingDirectory,
  [string]
  $eventLogName,
  [string]
  $eventLogSource,
  [Int32]
  $eventLogId,
  [string]
  $userGroupControl,
  [bool]
  $highestPrivilege
  #### WIP: Password relevant elements below.
  # [string]
  # $password
)

Import-Module ScheduledTasks

##SkipCheck=true##
$Source = @"

namespace SME {

    using System;
    using System.Linq;
    using System.Xml.Linq;

    public class TaskSchedulerXml
    {
        public XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        public XElement CreateMonthlyTrigger(DateTime startBoundary, bool enabled, string[] months, string[] days)
        {
            var element = new XElement(ns + "CalendarTrigger",
                new XElement(ns + "StartBoundary", startBoundary.ToString("s")),
                new XElement(ns + "Enabled", enabled),
                new XElement(ns + "ScheduleByMonth",
                        new XElement(ns + "DaysOfMonth",
                            from day in days
                            select new XElement(ns + "Day", day)
                        ),
                        new XElement(ns + "Months",
                            from month in months
                            select new XElement(ns + month)
                       )
                    )
                );
            return element;
        }

        public XElement CreateMonthlyDOWTrigger(DateTime startBoundary, bool enabled, string[] months, string[] days, string[] weeks)
        {
            var element = new XElement(ns + "CalendarTrigger",
                new XElement(ns + "StartBoundary", startBoundary.ToString("s")),
                new XElement(ns + "Enabled", enabled),
                new XElement(ns + "ScheduleByMonthDayOfWeek",
                        new XElement(ns + "Weeks",
                            from week in weeks
                            select new XElement(ns + "Week", week)
                        ),
                        new XElement(ns + "DaysOfWeek",
                            from day in days
                            select new XElement(ns + day)
                        ),
                        new XElement(ns + "Months",
                            from month in months
                            select new XElement(ns + month)
                       )
                    )
                );
            return element;
        }

        public XElement CreateEventTrigger(string eventLogName, string eventLogSource, string eventLogId, bool enabled)
        {
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

            var queryText = string.Format("*[System[Provider[@Name='{0}'] and EventID={1}]]", eventLogSource, eventLogId);

            var queryElement = new XElement("QueryList",
                            new XElement("Query", new XAttribute("Id", "0"), new XAttribute("Path", eventLogName),
                                new XElement("Select", new XAttribute("Path", eventLogName), queryText
                                )
                            )
                        );

            var element = new XElement(ns + "EventTrigger",
                    new XElement(ns + "Enabled", enabled),
                    new XElement(ns + "Subscription", queryElement.ToString()
                    )
                );

            return element;
        }

        public void UpdateTriggers(XElement newTrigger, XDocument d)
        {
            var triggers = d.Descendants(ns + "Triggers").FirstOrDefault();
            if (triggers != null) {
                triggers.ReplaceAll(newTrigger);
            }
        }
    }
  }

"@
##SkipCheck=false##

Add-Type -AssemblyName "System.Linq"
Add-Type -AssemblyName "System.Xml"
Add-Type -AssemblyName "System.Xml.Linq"
Add-Type -TypeDefinition $Source -Language CSharp  -ReferencedAssemblies ("System.Linq", "System.Xml", "System.Xml.Linq")

enum TriggerFrequency {
  Daily
  Weekly
  Monthly
  MonthlyDOW
  Once
  AtLogOn
  AtStartUp
  AtRegistration
  OnIdle
  OnEvent
  CustomTrigger
}

function New-ScheduledTaskXmlTemplate {
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $taskName,
    [Parameter(Mandatory = $true)]
    [string]
    $taskPath,
    [Parameter(Mandatory = $true)]
    [string]
    $taskDescription,
    [Parameter(Mandatory = $true)]
    [string]
    $taskAuthor,
    [Parameter(Mandatory = $true)]
    $taskActionParameters
  )

  # create a task as template
  $action = New-ScheduledTaskAction @taskActionParameters
  $trigger = New-ScheduledTaskTrigger -Once -At 12AM
  $settingSet = New-ScheduledTaskSettingsSet

  $principalParams = @{ }

  #### WIP: Password relevant elements below.

  # if ($password) {
  #   $principalParams += @{'User' = $userGroupControl
  #                   'Password' = $password
  #                 }
  # } else {
  #   if ($userGroupControl.EndsWith('$')) { # gMSA account specific setting
  #     $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Password"
  #   } else {
  #     $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Interactive"
  #   }
  #   $principalParams += @{'Principal' = $principal}
  # }

  if ($userGroupControl.EndsWith('$')) {
    # gMSA account specific setting
    $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Password"
  }
  else {
    $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Interactive"
  }
  $principalParams += @{'Principal' = $principal }

  Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Description $taskDescription -Trigger $trigger -Settings $settingSet @principalParams
  Set-Author -taskPath $taskPath -taskName $taskName -taskAuthor $taskAuthor

  $xml = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath
  Unregister-ScheduledTask -Confirm:$false -TaskName  $taskName -TaskPath $taskPath

  return $xml
}

function Set-MonthlyTrigger {
  param (
    [Parameter(Mandatory = $true)]
    $taskXml,
    [Parameter(Mandatory = $true)]
    [DateTime]
    $startBoundary,
    [Parameter(Mandatory = $true)]
    [Boolean]
    $enabled,
    [Parameter(Mandatory = $true)]
    [string]
    $triggerMonthlyFrequency,
    [Parameter(Mandatory = $true)]
    [string[]]
    $months,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]
    $daysOfMonth,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]
    $weeksOfMonth
  )

  $obj = New-Object SME.TaskSchedulerXml
  $element = $null
  if ($triggerMonthlyFrequency -eq 'Monthly') {
    $element = $obj.CreateMonthlyTrigger($startBoundary, $enabled, $months, $daysOfMonth)
  }
  elseif ( $triggerMonthlyFrequency -eq 'MonthlyDOW') {
    $element = $obj.CreateMonthlyDOWTrigger($startBoundary, $enabled, $months, $daysOfWeek, $weeksOfMonth)
  }

  $d = [System.Xml.Linq.XDocument]::Parse($taskXml)
  $obj.UpdateTriggers($element, $d)

  return $d.ToString()
}

function Set-EventTrigger {
  param (
    [Parameter(Mandatory = $true)]
    $taskXml,
    [Parameter(Mandatory = $true)]
    [Boolean]
    $enabled,
    [Parameter(Mandatory = $true)]
    [string]
    $eventLogName,
    [Parameter(Mandatory = $true)]
    [string]
    $eventLogSource,
    [Parameter(Mandatory = $true)]
    [string]
    $eventLogId
  )

  $obj = New-Object SME.TaskSchedulerXml
  $element = $obj.CreateEventTrigger($eventLogName, $eventLogSource, $eventLogId, $enabled)

  $d = [System.Xml.Linq.XDocument]::Parse($taskXml)
  $obj.UpdateTriggers($element, $d)

  return $d.ToString()
}

function Set-Author {
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $taskName,
    [Parameter(Mandatory = $true)]
    [string]
    $taskPath,
    [Parameter(Mandatory = $true)]
    [string]
    $taskAuthor
  )

  $task = Get-ScheduledTask -TaskPath $taskPath -TaskNAme $taskName
  $task.Author = $taskAuthor
  $task | Set-ScheduledTask
}

function Get-Principal {
  param (
    [string]
    $userId,
    [bool]
    $highestPrivilege,
    [string]
    $logonType
  )

  $principal = @{ }

  if ($userId) {
    $principal += @{'UserId' = $userId; }
  }

  if ($highestPrivilege) {
    $principal += @{'RunLevel' = 1 }
  }

  if ($logonType) {
    $principal += @{'LogonType' = $logonType }
  }

  return New-ScheduledTaskPrincipal @principal

}

function Set-Properties {
  param (
    [Parameter(Mandatory = $true)]
    $settings,
    [Parameter(Mandatory = $true)]
    $object
  )

  $settings.GetEnumerator() | ForEach-Object { if ($_.value) { $object[$_.key] = $_.value } }
}

function Set-ActionParameters {
  $taskActionParams = @{ }

  $settings = @{
    'Execute'          = $actionExecute
    'Argument'         = $actionArguments
    'WorkingDirectory' = $workingDirectory
  }

  Set-Properties -settings $settings -object $taskActionParams

  return $taskActionParams
}

function Set-TriggerParameters {
  $taskTriggerParams = @{ }

  switch ($triggerFrequency) {
    Daily { $taskTriggerParams.Daily = $true }
    Weekly { $taskTriggerParams.Weekly = $true }
    Monthly { $taskTriggerParams.Monthly = $true; }
    Once { $taskTriggerParams.Once = $true; }
    AtLogOn { $taskTriggerParams.AtLogOn = $true; }
    AtStartup { $taskTriggerParams.AtStartup = $true; }
  }

  $settings = @{
    'At'            = $triggerAt
    'DaysInterval'  = $daysInterval
    'WeeksInterval' = $weeklyInterval
    'DaysOfWeek'    = $daysOfWeek
  }

  Set-Properties -settings $settings -object $taskTriggerParams

  return $taskTriggerParams
}

function Test-UseXmlToCreateScheduledTask {
  return ($triggerFrequency -eq [TriggerFrequency]::Monthly) -Or ($triggerFrequency -eq [TriggerFrequency]::OnEvent)
}

#
# Prepare action parameter bag
#
$taskActionParams = Set-ActionParameters

#
# Prepare task trigger parameter bag
#
$taskTriggerParams = Set-TriggerParameters

######################################################
#### Main script
######################################################

if (-Not (Test-UseXmlToCreateScheduledTask)) {
  # Create action, trigger and default settings
  $action = New-ScheduledTaskAction @taskActionParams
  $trigger = New-ScheduledTaskTrigger @taskTriggerParams
  $settingSet = New-ScheduledTaskSettingsSet

  $principalParams = @{ }

  #### WIP: Password relevant elements below.

  # if ($password) {
  #   $principalParams += @{'User' = $userGroupControl
  #                   'Password' = $password
  #                 }
  # } else {
  #   if ($userGroupControl.EndsWith('$')) { # gMSA account specific setting
  #     $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Password"
  #   } else {
  #     $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Interactive"
  #   }
  #   $principalParams += @{'Principal' = $principal}
  # }

  if ($userGroupControl.EndsWith('$')) {
    # gMSA account specific setting
    $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Password"
  }
  else {
    $principal = Get-Principal -userId $userGroupControl -highestPrivilege $highestPrivilege -logonType "Interactive"
  }
  $principalParams += @{'Principal' = $principal }

  Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Description $taskDescription -Trigger $trigger -Settings $settingSet @principalParams
  Set-Author -taskPath $taskPath -taskName $taskName -taskAuthor $taskAuthor
}
else {

  $xml = New-ScheduledTaskXmlTemplate -taskName $taskName -taskPath $taskPath -taskDescription $taskDescription -taskAuthor $taskAuthor -taskActionParameters $taskActionParams
  $updatedXml = ''

  if ($triggerFrequency -eq [TriggerFrequency]::Monthly) {
    $updatedXml = Set-MonthlyTrigger -taskXml $xml -startBoundary $triggerAt -enabled $true -triggerMonthlyFrequency $triggerMonthlyFrequency -months $months -daysOfMonth $daysOfMonth -weeksOfMonth $weeksOfMonth
  }
  elseif ($triggerFrequency -eq [TriggerFrequency]::OnEvent) {
    $updatedXml = Set-EventTrigger -taskXml $xml -enabled $true -eventLogName $eventLogName -eventLogSource $eventLogSource -eventLogId $eventLogId
  }

  Register-ScheduledTask -Xml $updatedXml -TaskName  $taskName -TaskPath $taskPath
}

}
## [END] New-WACSTBasicTask ##
function Remove-WACSTScheduledTask {
<#

.SYNOPSIS
Script to delete a scheduled tasks.

.DESCRIPTION
Script to delete a scheduled tasks.

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $true)]
  [String]
  $taskName
)

Import-Module ScheduledTasks

ScheduledTasks\Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false

}
## [END] Remove-WACSTScheduledTask ##
function Remove-WACSTScheduledTaskAction {
<#

.SYNOPSIS
Removes action from scheduled task actions.

.DESCRIPTION
Removes action from scheduled task actions.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER actionExecute
    The name of executable to run. By default looks in System32 if Working Directory is not provided

.PARAMETER actionArguments
    The arguments for the executable.

.PARAMETER workingDirectory
    The path to working directory
#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [parameter(Mandatory=$true)]
    [string]
    $actionExecute,
    [string]
    $actionArguments,
    [string]
    $workingDirectory
)

Import-Module ScheduledTasks


######################################################
#### Main script
######################################################

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$actionsArray =  @()

$task.Actions| ForEach-Object {
    $matched = $true;  
  
    if( -not ([string]::IsNullOrEmpty($_.Arguments) -and [string]::IsNullOrEmpty($actionArguments)))
    {
        if ($_.Arguments -ne $actionArguments)
        {
            $matched = $false;
        }
    }

    $workingDirectoryMatched  = $true;
    if( -not ([string]::IsNullOrEmpty($_.WorkingDirectory) -and [string]::IsNullOrEmpty($workingDirectory)))
    {
        if ($_.WorkingDirectory -ne $workingDirectory)
        {
            $matched = $false;
        }
    }

    $executeMatched  = $true;
    if ($_.Execute -ne $actionExecute) 
    {
          $matched = $false;
    }

    if (-not ($matched))
    {
        $actionsArray += $_;
    }
}


Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}
## [END] Remove-WACSTScheduledTaskAction ##
function Set-WACSTScheduledTaskConditions {
<#

.SYNOPSIS
Set/modify scheduled task setting set.

.DESCRIPTION
Set/modify scheduled task setting set.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER dontStopOnIdleEnd
    Indicates that Task Scheduler does not terminate the task if the idle condition ends before the task is completed.
    
.PARAMETER idleDurationInMins
    Specifies the amount of time that the computer must be in an idle state before Task Scheduler runs the task.
    
.PARAMETER idleWaitTimeoutInMins
   Specifies the amount of time that Task Scheduler waits for an idle condition to occur before timing out.
    
.PARAMETER restartOnIdle
   Indicates that Task Scheduler restarts the task when the computer cycles into an idle condition more than once.
    
.PARAMETER runOnlyIfIdle
    Indicates that Task Scheduler runs the task only when the computer is idle.
    
.PARAMETER allowStartIfOnBatteries
    Indicates that Task Scheduler starts if the computer is running on battery power.
    
.PARAMETER dontStopIfGoingOnBatteries
    Indicates that the task does not stop if the computer switches to battery power.

.PARAMETER runOnlyIfNetworkAvailable
    Indicates that Task Scheduler runs the task only when a network is available. Task Scheduler uses the NetworkID parameter and NetworkName parameter that you specify in this cmdlet to determine if the network is available.

.PARAMETER networkId
    Specifies the ID of a network profile that Task Scheduler uses to determine if the task can run. You must specify the ID of a network if you specify the RunOnlyIfNetworkAvailable parameter.

.PARAMETER networkName
   Specifies the name of a network profile that Task Scheduler uses to determine if the task can run. The Task Scheduler UI uses this setting for display purposes. Specify a network name if you specify the RunOnlyIfNetworkAvailable parameter.

#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [Boolean]
    $stopOnIdleEnd,
    [string]
    $idleDuration,
    [string]
    $idleWaitTimeout,
    [Boolean]
    $restartOnIdle,
    [Boolean]
    $runOnlyIfIdle,
    [Boolean]
    $disallowStartIfOnBatteries,
    [Boolean]
    $stopIfGoingOnBatteries,
    [Boolean]
    $wakeToRun
)

Import-Module ScheduledTasks

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath;

# Idle related conditions.
$task.settings.RunOnlyIfIdle = $runOnlyIfIdle;

$task.Settings.IdleSettings.IdleDuration = $idleDuration;
$task.Settings.IdleSettings.WaitTimeout = $idleWaitTimeout;

$task.Settings.IdleSettings.RestartOnIdle = $restartOnIdle;
$task.Settings.IdleSettings.StopOnIdleEnd = $stopOnIdleEnd;

# Power related condition.
$task.Settings.DisallowStartIfOnBatteries = $disallowStartIfOnBatteries;

$task.Settings.StopIfGoingOnBatteries = $stopIfGoingOnBatteries;

$task.Settings.WakeToRun = $wakeToRun;

$task | Set-ScheduledTask;
}
## [END] Set-WACSTScheduledTaskConditions ##
function Set-WACSTScheduledTaskGeneralSettings {
<#

.SYNOPSIS
Creates and registers a new scheduled task.

.DESCRIPTION
Creates and registers a new scheduled task.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskDescription
    The description of the task.

.PARAMETER taskPath
    The task path.

.PARAMETER username
    The username to use to run the task.
#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [string]
    $taskDescription,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [string]
    $username
)

Import-Module ScheduledTasks

######################################################
#### Main script
######################################################

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
if($task) {
    
    $task.Description = $taskDescription;
  
    if ($username)
    {
        $task | Set-ScheduledTask -User $username ;
    } 
    else 
    {
        $task | Set-ScheduledTask
    }
}
}
## [END] Set-WACSTScheduledTaskGeneralSettings ##
function Set-WACSTScheduledTaskSecurity {
<#

.SYNOPSIS
Updates the security used to run a scheduled task.

.DESCRIPTION
Set which user or group should run the task. If blank, run with highest privileges.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task.

.PARAMETER taskPath
    The task path.

.PARAMETER username
    The username to use to run the task.

.PARAMETER password
    The password to use to validate the username.

.PARAMETER highestPrivilege
    Indicates whether to run the task with the highest privileges of an account.

.PARAMETER doNotStorePassword
    Indicates whether to store the password of an account if the task runs even when an account is not logged in.

.PARAMETER runAnytime
    Indicates whether to run the task regardless of if the account is logged in.

#>

param (
  [parameter(Mandatory = $true)]
  [string]
  $taskName,
  [string]
  $taskPath,
  [string]
  $username,
  [bool]
  $highestPrivilege
  #### WIP: Password relevant elements below.
  # [string]
  # $password,
  # [bool]
  # $doNotStorePassword
)

Import-Module ScheduledTasks

######################################################
#### Main script
######################################################

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath;
$isGMSA = $username.EndsWith('$');

$principal = $task.Principal;
$principal.UserId = $username;

if (($password) -or $isGMSA) {
  $principal.LogonType = 1;
}
else {
  $principal.LogonType = 3;
}

if ($highestPrivilege) {
  $principal.RunLevel = 1;
}
else {
  $principal.RunLevel = 0;
}

# Must re-register the task under the username and password under Password/S4U logons
if (($principal.LogonType -le 2) -and !$isGMSA) {
  $taskParams = @{'Settings' = $task.Settings;
    'Principal'              = $principal;
  }

  if ($task.Actions) {
    $taskParams += @{'Action' = $task.Actions; }
  }

  if ($task.Triggers) {
    $taskParams += @{'Trigger' = $task.Triggers; }
  }

  if ($task.Description) {
    $taskParams += @{'Description' = $task.Description; }
  }

  $newTask = New-ScheduledTask @taskParams;

  # Register some task to validate credentials, then "rename" (i.e. re-register the actual task)
  $randomFileName = [System.IO.Path]::GetRandomFileName();

  Register-ScheduledTask -TaskName $randomFileName -TaskPath $taskPath -InputObject $newTask -User $username -Password $password -ErrorAction Stop;
  Unregister-ScheduledTask -TaskName $randomFileName -taskPath $taskPath -Confirm:$false;

  Unregister-ScheduledTask -TaskName $taskName -taskPath $taskPath -Confirm:$false;
  Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $newTask -User $username -Password $password -ErrorAction Stop;

}
else {
  Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Principal $principal;
}

}
## [END] Set-WACSTScheduledTaskSecurity ##
function Set-WACSTScheduledTaskSettingsSet {
<#

.SYNOPSIS
Set/modify scheduled task setting set.

.DESCRIPTION
Set/modify scheduled task setting set.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER disallowDemandStart
    Indicates that the task cannot be started by using either the Run command or the Context menu.

.PARAMETER startWhenAvailable
    Indicates that Task Scheduler can start the task at any time after its scheduled time has passed.

.PARAMETER executionTimeLimitInMins
   Specifies the amount of time that Task Scheduler is allowed to complete the task.

.PARAMETER restartIntervalInMins
    Specifies the amount of time between Task Scheduler attempts to restart the task.

.PARAMETER restartCount
    Specifies the number of times that Task Scheduler attempts to restart the task.

.PARAMETER deleteExpiredTaskAfterInMins
    Specifies the amount of time that Task Scheduler waits before deleting the task after it expires.

.PARAMETER multipleInstances
   Specifies the policy that defines how Task Scheduler handles multiple instances of the task. Possible Enum values Parallel, Queue, IgnoreNew

.PARAMETER disallowHardTerminate
   Indicates that the task cannot be terminated by using TerminateProcess.
#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [Boolean]
    $allowDemandStart,
    [Boolean]
    $allowHardTerminate,
    [Boolean]
    $startWhenAvailable, 
    [string]
    $executionTimeLimit, 
    [string]
    $restartInterval, 
    [Int32]
    $restartCount, 
    [string]
    $deleteExpiredTaskAfter,
    [Int32]
    $multipleInstances  #Parallel, Queue, IgnoreNew
    
)

Import-Module ScheduledTasks

#
# Prepare action parameter bag
#

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath;

$task.settings.AllowDemandStart =  $allowDemandStart;
$task.settings.AllowHardTerminate = $allowHardTerminate;

$task.settings.StartWhenAvailable = $startWhenAvailable;

if ($executionTimeLimit -eq $null -or $executionTimeLimit -eq '') {
    $task.settings.ExecutionTimeLimit = 'PT0S';
} 
else 
{
    $task.settings.ExecutionTimeLimit = $executionTimeLimit;
} 

if ($restartInterval -eq $null -or $restartInterval -eq '') {
    $task.settings.RestartInterval = $null;
} 
else
{
    $task.settings.RestartInterval = $restartInterval;
} 

if ($restartCount -gt 0) {
    $task.settings.RestartCount = $restartCount;
}
<#if ($deleteExpiredTaskAfter -eq '' -or $deleteExpiredTaskAfter -eq $null) {
    $task.settings.DeleteExpiredTaskAfter = $null;
}
else 
{
    $task.settings.DeleteExpiredTaskAfter = $deleteExpiredTaskAfter;
}#>

if ($multipleInstances) {
    $task.settings.MultipleInstances = $multipleInstances;
}

$task | Set-ScheduledTask ;
}
## [END] Set-WACSTScheduledTaskSettingsSet ##
function Start-WACSTScheduledTask {
<#

.SYNOPSIS
Script to start a scheduled tasks.

.DESCRIPTION
Script to start a scheduled tasks.

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $true)]
  [String]
  $taskName
)

Import-Module ScheduledTasks

Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName | ScheduledTasks\Start-ScheduledTask

}
## [END] Start-WACSTScheduledTask ##
function Stop-WACSTScheduledTask {
<#

.SYNOPSIS
Script to stop a scheduled tasks.

.DESCRIPTION
Script to stop a scheduled tasks.

.ROLE
Administrators

#>

param (
  [Parameter(Mandatory = $true)]
  [String]
  $taskPath,

  [Parameter(Mandatory = $true)]
  [String]
  $taskName
)

Import-Module ScheduledTasks

Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName | ScheduledTasks\Stop-ScheduledTask

}
## [END] Stop-WACSTScheduledTask ##
function Update-WACSTScheduledTaskAction {
<#

.SYNOPSIS
Updates existing scheduled task action.

.DESCRIPTION
Updates existing scheduled task action.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER oldActionExecute
    The name of executable to run. By default looks in System32 if Working Directory is not provided

.PARAMETER newActionExecute
    The name of executable to run. By default looks in System32 if Working Directory is not provided

.PARAMETER oldActionArguments
    The arguments for the executable.

.PARAMETER newActionArguments
    The arguments for the executable.

.PARAMETER oldWorkingDirectory
    The path to working directory

.PARAMETER newWorkingDirectory
    The path to working directory
#>

param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [parameter(Mandatory=$true)]
    [string]
    $newActionExecute,
    [parameter(Mandatory=$true)]
    [string]
    $oldActionExecute,
    [string]
    $newActionArguments,
    [string]
    $oldActionArguments,
    [string]
    $newWorkingDirectory,
    [string]
    $oldWorkingDirectory
)

Import-Module ScheduledTasks


######################################################
#### Main script
######################################################

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$actionsArray = $task.Actions

foreach ($action in $actionsArray) {
    $argMatched = $true;
    if( -not ([string]::IsNullOrEmpty($action.Arguments) -and [string]::IsNullOrEmpty($oldActionArguments)))
    {
        if ($action.Arguments -ne $oldActionArguments)
        {
            $argMatched = $false;
        }
    }

    $workingDirectoryMatched  = $true;
    if( -not ([string]::IsNullOrEmpty($action.WorkingDirectory) -and [string]::IsNullOrEmpty($oldWorkingDirectory)))
    {
        if ($action.WorkingDirectory -ne $oldWorkingDirectory)
        {
            $workingDirectoryMatched = $false;
        }
    }

    $executeMatched  = $true;
    if ($action.Execute -ne $oldActionExecute) 
    {
          $executeMatched = $false;
    }

    if ($argMatched -and $executeMatched -and $workingDirectoryMatched)
    {
        $action.Execute = $newActionExecute;
        $action.Arguments = $newActionArguments;
        $action.WorkingDirectory = $newWorkingDirectory;
        break
    }
}


Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}
## [END] Update-WACSTScheduledTaskAction ##
function Update-WACSTScheduledTaskTrigger {
 <#

.SYNOPSIS
Adds a new trigger to existing scheduled task triggers.

.DESCRIPTION
Adds a new trigger to existing scheduled task triggers.

.ROLE
Administrators

.PARAMETER taskName
    The name of the task

.PARAMETER taskPath
    The task path.

.PARAMETER triggerClassName
    The cim class Name for Trigger being edited.

.PARAMETER triggersToCreate
    Collections of triggers to create/edit, should be of same type. The script will preserve any other trigger than cim class specified in triggerClassName. 
    This is done because individual triggers can not be identified by Id. Everytime update to any trigger is made we recreate all triggers that are of the same type supplied by user in triggers to create collection.
#>
 param (
    [parameter(Mandatory=$true)]
    [string]
    $taskName,
    [parameter(Mandatory=$true)]
    [string]
    $taskPath,
    [string]
    $triggerClassName,
    [object[]]
    $triggersToCreate
)

Import-Module ScheduledTasks

######################################################
#### Functions
######################################################


function Create-Trigger 
 {
    Param (
    [object]
    $trigger
    )

    if($trigger) 
    {
        #
        # Prepare task trigger parameter bag
        #
        $taskTriggerParams = @{} 
        # Parameter is not required while creating Logon trigger /startup Trigger
        if ($trigger.triggerAt -and $trigger.triggerFrequency -in ('Daily','Weekly', 'Once')) {
           $taskTriggerParams.At =  $trigger.triggerAt;
        }
   
    
        # Build optional switches
        if ($trigger.triggerFrequency -eq 'Daily')
        {
            $taskTriggerParams.Daily = $true;
            
            if ($trigger.daysInterval -and $trigger.daysInterval -ne 0) 
            {
               $taskTriggerParams.DaysInterval = $trigger.daysInterval;
            }
        }
        elseif ($trigger.triggerFrequency -eq 'Weekly')
        {
            $taskTriggerParams.Weekly = $true;
            if ($trigger.weeksInterval -and $trigger.weeksInterval -ne 0) 
            {
               $taskTriggerParams.WeeksInterval = $trigger.weeksInterval;
            }
            if ($trigger.daysOfWeek) 
            {
               $taskTriggerParams.DaysOfWeek = $trigger.daysOfWeek;
            }
        }
        elseif ($trigger.triggerFrequency -eq 'Once')
        {
            $taskTriggerParams.Once = $true;
        }
        elseif ($trigger.triggerFrequency -eq 'AtLogOn')
        {
            $taskTriggerParams.AtLogOn = $true;
        }
        elseif ($trigger.triggerFrequency -eq 'AtStartup')
        {
            $taskTriggerParams.AtStartup = $true;
        }
        
        if ($trigger.username) 
        {
           $taskTriggerParams.User = $trigger.username;
        }


        # Create trigger object
        $triggerNew = New-ScheduledTaskTrigger @taskTriggerParams

        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
       
        Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggerNew | out-null

        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
     

        if ($trigger.repetitionInterval -and $task.Triggers[0].Repetition -ne $null) 
        {
           $task.Triggers[0].Repetition.Interval = $trigger.repetitionInterval;
        }
        if ($trigger.repetitionDuration -and $task.Triggers[0].Repetition -ne $null) 
        {
           $task.Triggers[0].Repetition.Duration = $trigger.repetitionDuration;
        }
        if ($trigger.stopAtDurationEnd -and $task.Triggers[0].Repetition -ne $null) 
        {
           $task.Triggers[0].Repetition.StopAtDurationEnd = $trigger.stopAtDurationEnd;
        }
        if($trigger.executionTimeLimit) 
        {
            $task.Triggers[0].ExecutionTimeLimit = $trigger.executionTimeLimit;
        }
        if($trigger.randomDelay -ne '')
        {
            if([bool]($task.Triggers[0].PSobject.Properties.name -eq "RandomDelay")) 
            {
                $task.Triggers[0].RandomDelay = $trigger.randomDelay;
            }

            if([bool]($task.Triggers[0].PSobject.Properties.name -eq "Delay")) 
            {
                $task.Triggers[0].Delay = $trigger.randomDelay;
            }
        }

        if($trigger.enabled -ne $null) 
        {
            $task.Triggers[0].Enabled = $trigger.enabled;
        }

        if($trigger.endBoundary -and $trigger.endBoundary -ne '') 
        {
            $date = [datetime]($trigger.endBoundary);
            $task.Triggers[0].EndBoundary = $date.ToString("yyyy-MM-ddTHH:mm:sszzz"); #convert date to specific string.
        }

        # Activation date is also stored in StartBoundary for Logon/Startup triggers. Setting it in appropriate context
        if($trigger.triggerAt -ne '' -and $trigger.triggerAt -ne $null -and $trigger.triggerFrequency -in ('AtLogOn','AtStartup')) 
        {
            $date = [datetime]($trigger.triggerAt);
            $task.Triggers[0].StartBoundary = $date.ToString("yyyy-MM-ddTHH:mm:sszzz"); #convert date to specific string.
        }


        return  $task.Triggers[0];
       } # end if
 }

######################################################
#### Main script
######################################################

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$triggers = $task.Triggers;
$allTriggers = @()
try {

    foreach ($t in $triggers)
    {
        # Preserve all the existing triggers which are of different type then the modified trigger type.
        if ($t.CimClass.CimClassName -ne $triggerClassName) 
        {
            $allTriggers += $t;
        } 
    }

     # Once all other triggers are preserved, recreate the ones passed on by the UI
     foreach ($t in $triggersToCreate)
     {
        $newTrigger = Create-Trigger -trigger $t
        $allTriggers += $newTrigger;
     }

    Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $allTriggers
} 
catch 
{
     Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggers
     throw $_.Exception
}

}
## [END] Update-WACSTScheduledTaskTrigger ##

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAw5dpVuMUiihSZ
# cRV296OcAbasTyB3JassUTLJNQ1WgqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGgwwghoIAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINd7zPjxPRbgTYNO8jox2bVH
# 0lNEdHVSKwpoaz/W2rvpMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAFTOAdh7QfgpfVFZ1dhMYzll9IQl9CyqlhGnuVePA1j56Hi17ZshTHazs
# EmE+R8uzuPJuP6p2sUHuLb/Mn4o/ql7j55OzWjqsKiI+XovcEvyDttR6TTKeTT49
# kbMXaw7+6vdpwoBd1VP+PrlKy7mYzm4gWHZb9D+qM2eJt/gW8E6hjjWN5wFciNDt
# sQWZd5alZPxNq9niNtqlu6Av1dxno4bFzCrb9pBvkM66tf8yYn8R9qmzNQnLx7y0
# 5WxtUl+s1pe6O3AFtMP0yw344qg8NfZbf53JKlQxBOhUfT7i7xq8SnMsR0UUyKc/
# oeBQT7c/+CWJPlLiUlgh7YAPsu6M0qGCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCC
# F34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBTul3KNEIIZA4BzaOD4fxrtBBjI6Q1du3FblmHxoI3UQIGaO/mvvEM
# GBMyMDI1MTExMDE3MTc1NC4xMjlaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTkzNS0w
# M0UwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHsMIIHIDCCBQigAwIBAgITMwAAAgy5ZOM1nOz0rgABAAACDDANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQz
# MDBaFw0yNjA0MjIxOTQzMDBaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTkzNS0wM0UwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDKAVYmPeRtga/U6jzqyqLD0MAool23gcBN58+Z/Xsk
# YwNJsZ+O+wVyQYl8dPTK1/BC2xAic1m+JvckqjVaQ32KmURsEZotirQY4PKVW+eX
# wRt3r6szgLuic6qoHlbXox/l0HJtgURkzDXWMkKmGSL7z8/crqcvmYqv8t/slAF4
# J+mpzb9tMFVmjwKXONVdRwg9Q3WaPZBC7Wvoi7PRIN2jgjSBnHYyAZSlstKNrpYb
# 6+Gu6oSFkQzGpR65+QNDdkP4ufOf4PbOg3fb4uGPjI8EPKlpwMwai1kQyX+fgcgC
# oV9J+o8MYYCZUet3kzhhwRzqh6LMeDjaXLP701SXXiXc2ZHzuDHbS/sZtJ3627cV
# pClXEIUvg2xpr0rPlItHwtjo1PwMCpXYqnYKvX8aJ8nawT9W8FUuuyZPG1852+q4
# jkVleKL7x+7el8ETehbdkwdhAXyXimaEzWetNNSmG/KfHAp9czwsL1vKr4Rgn+pI
# IkZHuomdf5e481K+xIWhLCPdpuV87EqGOK/jbhOnZEqwdvA0AlMaLfsmCemZmupe
# jaYuEk05/6cCUxgF4zCnkJeYdMAP+9Z4kVh7tzRFsw/lZSl2D7EhIA6Knj6RffH2
# k7YtSGSv86CShzfiXaz9y6sTu8SGqF6ObL/eu/DkivyVoCfUXWLjiSJsrS63D0EH
# HQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFHUORSH/sB/rQ/beD0l5VxQ706GIMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQDZMPr4gVmwwf4GMB5ZfHSr34uhug6yzu4H
# UT+JWMZqz9uhLZBoX5CPjdKJzwAVvYoNuLmS0+9lA5S74rvKqd/u9vp88VGk6U7g
# MceatdqpKlbVRdn2ZfrMcpI4zOc6BtuYrzJV4cEs1YmX95uiAxaED34w02BnfuPZ
# XA0edsDBbd4ixFU8X/1J0DfIUk1YFYPOrmwmI2k16u6TcKO0YpRlwTdCq9vO0eEI
# ER1SLmQNBzX9h2ccCvtgekOaBoIQ3ZRai8Ds1f+wcKCPzD4qDX3xNgvLFiKoA6ZS
# G9S/yOrGaiSGIeDy5N9VQuqTNjryuAzjvf5W8AQp31hV1GbUDOkbUdd+zkJWKX4F
# mzeeN52EEbykoWcJ5V9M4DPGN5xpFqXy9aO0+dR0UUYWuqeLhDyRnVeZcTEu0xgm
# o+pQHauFVASsVORMp8TF8dpesd+tqkkQ8VNvI20oOfnTfL+7ZgUMf7qNV0ll0Wo5
# nlr1CJva1bfk2Hc5BY1M9sd3blBkezyvJPn4j0bfOOrCYTwYsNsjiRl/WW18NOpi
# wqciwFlUNqtWCRMzC9r84YaUMQ82Bywk48d4uBon5ZA8pXXS7jwJTjJj5USeRl9v
# jT98PDZyCFO2eFSOFdDdf6WBo/WZUA2hGZ0q+J7j140fbXCfOUIm0j23HaAV0ckD
# S/nmC/oF1jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNP
# MIICNwIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE5MzUtMDNFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDv
# u8hkhEMt5Z8Ldefls7z1LVU8pqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwALjAiGA8yMDI1MTExMDA2MDk1
# MFoYDzIwMjUxMTExMDYwOTUwWjB2MDwGCisGAQQBhFkKBAExLjAsMAoCBQDsvAAu
# AgEAMAkCAQACAWoCAf8wBwIBAAICE2QwCgIFAOy9Ua4CAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQsFAAOCAQEADKMX6ILazkhQemP4UrU/cnKBAe0Eu0OROx0nafmrwMq2
# glAGxBsYP0r4tW5E2GP/z8Bst8RowEORTEvRlDsTwAlZ9vObFvGuvbUcxLjM8MgI
# 5d7ZMpjfVRcTKiuj2GMcj+We917+jcsD7E0OBzLStfsfQ6qRuGCJmB8Fta2KuhFF
# 4l218T6F7lJnThWMWREQup53G9tRszRZZh2wfH6Dpxp5YzebT/WrhleuzQzTcBdl
# p0sN3IhazimeSGcyf2SrLJe7vourmyPb/olySnD86Eb6dt9OED3j8lSl1G257AWL
# cqunEbcNGTRuOrMM1d8t9ypfUm1+k8EUIzMLDLi5bjGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAACDLlk4zWc7PSuAAEAAAIM
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIAxYFKCXPVvfNmExvuhgDd8E8+le7oJJW1ZKvD4W7spN
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1SjXtwUxk3jowjk18gCD1THl
# w7nEz2Ket7muK45nwi0wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAgy5ZOM1nOz0rgABAAACDDAiBCA0Ia2tCIEbcoajq/vTmYoWGbIM
# 7xAVq5WlhscRQ8YZpjANBgkqhkiG9w0BAQsFAASCAgCSZIPbvoajJHppaXP83Ha9
# r65SXkUFOAhRTLx/4U5nrjP6wE+nA6P0i1TBPp5Cj8EGqh0ZlO+ZXaEOJGXX3lWC
# 19X/LY17KpgGaj6GodzESb4CPl8XHIVV60aApTnT+0TNDvpLYPnzUPYgrW6VkbOD
# Rk/kpSXZLgPAhov/ETdqHv80yqBC460Bdz788odTeMmYIoJl3k5LjU04wjMluWw0
# cGcdYFHcRee792i/JExhrb+zFlutQH7a/p8bSqdqkGPU/TD5iCdN81VUYmiXFCeC
# RFf6LawqxnS2v8grw36sYJ1XX4bTAkBWMxpPPzhi4EQ4TxzSf1UBjy11xflBqTeA
# ZsktkvWAp0r6x6M4v6is9Hj0M4+Z15fdRaQlDCd4isvE07zrYg5k9BKbsfts4g3U
# LPlxiKWrtaxt3bN2Dtklwpj22vW4qtjjvxVaq0JOOVoj4zTznfN5De9CRbkoJ8w+
# 7Gy84Y3nMsO+gKc86vlahy9Al7jxJE+3hfaOTp7hfTLK/B7ZxtFbx8DNaxbfZPFm
# IE21dQ8MTk75vVCm+0Qmc3p5ywY0NxlvQV9ZrR3gRjNjmBWbgfvzyqNSFclvtc06
# nDwwXhQJ89fXqKjQi1sA2Q0rSye6EEKELfHLEesoTiZfsWt0DBH1ML7XhZj2JyB6
# gbuMFC/WJrceOIxtviXJYg==
# SIG # End signature block
