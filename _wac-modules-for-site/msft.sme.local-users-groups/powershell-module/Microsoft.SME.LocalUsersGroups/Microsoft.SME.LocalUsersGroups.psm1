function Add-WACLGUserToLocalGroups {
<#

.SYNOPSIS
Adds a local or domain user to one or more local groups.

.DESCRIPTION
Adds a local or domain user to one or more local groups. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,

    [Parameter(Mandatory = $true)]
    [String[]]
    $GroupNames
)
Set-StrictMode -Version 5.0

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Stop'

# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
$Error.Clear()
# Get user name or object
$user = $null
$objUser = $null
if (Get-Command 'Get-LocalUser' -errorAction SilentlyContinue) {
    if ($UserName -like '*\*') { # domain user
        $user = $UserName
    } else {
        $user = Get-LocalUser -Name $UserName
    }
} else {
    if ($UserName -like '*\*') { # domain user
        $UserName = $UserName.Replace('\', '/')
    }
    $objUser = "WinNT://$UserName,user"
}
# Add user to groups
Foreach ($name in $GroupNames) {
    if (Get-Command 'Get-LocalGroup' -errorAction SilentlyContinue) {
        $group = Get-LocalGroup $name
        Add-LocalGroupMember -Group $group -Member $user
    }
    else {
        $group = $name
        try {
            $objGroup = [ADSI]("WinNT://localhost/$group,group")
            $objGroup.Add($objUser)
        }
        catch
        {
            # Append user and group name info to error message and then clear it
            $ErrMsg = $_.Exception.Message + " User: " + $UserName + ", Group: " + $group
            Write-Error $ErrMsg
            $Error.Clear()
        }
    }
}

}
## [END] Add-WACLGUserToLocalGroups ##
function Get-WACLGLocalGroupUsers {
<#

.SYNOPSIS
Get users belong to group.

.DESCRIPTION
Get users belong to group. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $group
)

Set-StrictMode -Version 5.0

# ADSI does NOT support 2016 Nano, meanwhile Get-LocalGroupMember does NOT support downlevel and also has bug
$ComputerName = (get-item Env:\COMPUTERNAME).Value
try {
    $groupconnection = [ADSI]("WinNT://localhost/$group,group")
    $contents = $groupconnection.Members() | ForEach-Object {
        $path=$_.GetType().InvokeMember("ADsPath", "GetProperty", $NULL, $_, $NULL)
        # $path will looks like:
        #   WinNT://ComputerName/Administrator
        #   WinNT://DomainName/Domain Admins
        # Find out if this is a local or domain object and trim it accordingly
        if ($path -like "*/$ComputerName/*"){
            $start = 'WinNT://' + $ComputerName + '/'
        }
        else {
            $start = 'WinNT://'
        }
        $name = $path.Substring($start.length)
        $name.Replace('/', '\') #return name here
    }
    return $contents
}
catch { # if above block failed (say in 2016Nano), use another cmdlet
    # clear existing error info from try block
    $Error.Clear()
    #There is a known issue, in some situation Get-LocalGroupMember return: Failed to compare two elements in the array.
    $contents = Get-LocalGroupMember -group $group
    $names = $contents.Name | ForEach-Object {
        $name = $_
        if ($name -like "$ComputerName\*") {
            $name = $name.Substring($ComputerName.length+1)
        }
        $name
    }
    return $names
}

}
## [END] Get-WACLGLocalGroupUsers ##
function Get-WACLGLocalGroups {
<#

.SYNOPSIS
Gets the local groups.

.DESCRIPTION
Gets the local groups. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [String]
    $SID
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
if ($SID)
{
    if ($isWinServer2016OrNewer)
    {
        Get-LocalGroup -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description,
                                          Name,
                                          @{Name="SID"; Expression={$_.SID.Value}},
                                          ObjectClass;
    }
    else
    {
        Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description, Name, SID, ObjectClass;
    }
}
else
{
    if ($isWinServer2016OrNewer)
    {
        Get-LocalGroup | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description,
                                Name,
                                @{Name="SID"; Expression={$_.SID.Value}},
                                ObjectClass;
    }
    else
    {
        Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description, Name, SID, ObjectClass
    }
}

}
## [END] Get-WACLGLocalGroups ##
function Get-WACLGLocalUserBelongGroups {
<#

.SYNOPSIS
Get a local user belong to group list.

.DESCRIPTION
Get a local user belong to group list. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName
)

Set-StrictMode -Version 5.0

Import-Module CimCmdlets -ErrorAction SilentlyContinue

$operatingSystem = Get-CimInstance Win32_OperatingSystem
$version = [version]$operatingSystem.Version
# product type 3 is server, version number ge 10 is server 2016
$isWinServer2016OrNewer = ($operatingSystem.ProductType -eq 3) -and ($version -ge '10.0')

# ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."

# Step 1: get the list of local groups
if ($isWinServer2016OrNewer) {
    $grps = net localgroup | Where-Object {$_ -AND $_ -match "^[*]"}  # group member list as "*%Fws\r\n"
    $groups = $grps.trim('*')
}
else {
    $grps = Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Name
    $groups = $grps.Name
}

# Step 2: in each group, list members and find match to target $UserName
$groupNames = @()
$regex = '^' + $UserName + '\b'
foreach ($group in $groups) {
    $found = $false
    #find group members
    if ($isWinServer2016OrNewer) {
        $members = net localgroup $group | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Microsoft.PowerShell.Utility\Select-Object -skip 4
        if ($members -AND $members.contains($UserName)) {
            $found = $true
        }
    }
    else {
        $groupconnection = [ADSI]("WinNT://localhost/$group,group")
        $members = $groupconnection.Members()
        ForEach ($member in $members) {
            $name = $member.GetType().InvokeMember("Name", "GetProperty", $NULL, $member, $NULL)
            if ($name -AND ($name -match $regex)) {
                $found = $true
                break
            }
        }
    }
    #if members contains $UserName, add group name to list
    if ($found) {
        $groupNames = $groupNames + $group
    }
}
return $groupNames

}
## [END] Get-WACLGLocalUserBelongGroups ##
function Get-WACLGLocalUsers {
<#

.SYNOPSIS
Gets the local users.

.DESCRIPTION
Gets the local users. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [String]
    $SID
)

Set-StrictMode -Version 5.0

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
if ($SID)
{
    if ($isWinServer2016OrNewer)
    {
        Get-LocalUser -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                         Description,
                                         Enabled,
                                         FullName,
                                         LastLogon,
                                         Name,
                                         ObjectClass,
                                         PasswordChangeableDate,
                                         PasswordExpires,
                                         PasswordLastSet,
                                         PasswordRequired,
                                         @{Name="SID"; Expression={$_.SID.Value}},
                                         UserMayChangePassword;
    }
    else
    {
        Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                      Description,
                                                                                      @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                      FullName,
                                                                                      LastLogon,
                                                                                      Name,
                                                                                      ObjectClass,
                                                                                      PasswordChangeableDate,
                                                                                      PasswordExpires,
                                                                                      PasswordLastSet,
                                                                                      PasswordRequired,
                                                                                      SID,
                                                                                      @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
    }
}
else
{
    if ($isWinServer2016OrNewer)
    {
        Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                               Description,
                               Enabled,
                               FullName,
                               LastLogon,
                               Name,
                               ObjectClass,
                               PasswordChangeableDate,
                               PasswordExpires,
                               PasswordLastSet,
                               PasswordRequired,
                               @{Name="SID"; Expression={$_.SID.Value}},
                               UserMayChangePassword;
    }
    else
    {
        Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                      Description,
                                                                                      @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                      FullName,
                                                                                      LastLogon,
                                                                                      Name,
                                                                                      ObjectClass,
                                                                                      PasswordChangeableDate,
                                                                                      PasswordExpires,
                                                                                      PasswordLastSet,
                                                                                      PasswordRequired,
                                                                                      SID,
                                                                                      @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
    }
}

}
## [END] Get-WACLGLocalUsers ##
function New-WACLGLocalGroup {
<#

.SYNOPSIS
Creates a new local group.

.DESCRIPTION
Creates a new local group. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $GroupName,

    [Parameter(Mandatory = $false)]
    [String]
    $Description
)

Set-StrictMode -Version 5.0

if (-not $Description) {
    $Description = ""
}

# ADSI does NOT support 2016 Nano, meanwhile New-LocalGroup does NOT support downlevel and also with known bug
$Error.Clear()
try {
    $adsiConnection = [ADSI]"WinNT://localhost"
    $group = $adsiConnection.Create("Group", $GroupName)
    $group.InvokeSet("description", $Description)
    $group.SetInfo();
}
catch [System.Management.Automation.RuntimeException]
{ # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
    if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
        Write-Error $_.Exception.Message
        return
    }
    # clear existing error info from try block
    $Error.Clear()
    New-LocalGroup -Name $GroupName -Description $Description
}

}
## [END] New-WACLGLocalGroup ##
function New-WACLGLocalUser {
<#

.SYNOPSIS
Creates a new local users.

.DESCRIPTION
Creates a new local users. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,

    [Parameter(Mandatory = $false)]
    [String]
    $FullName,

    [Parameter(Mandatory = $false)]
    [String]
    $Description,

    [Parameter(Mandatory = $false)]
    [String]
    $Password
)

Set-StrictMode -Version 5.0

if (-not $Description) {
    $Description = ""
}

if (-not $FullName) {
    $FullName = ""
}

if (-not $Password) {
    $Password = ""
}

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode($encryptedData) {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

# $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile New-LocalUser does NOT support downlevel and also with known bug
$Error.Clear()
try {
    $adsiConnection = [ADSI]"WinNT://localhost"
    $user = $adsiConnection.Create("User", $UserName)
    if ($Password) {
        $decryptedPassword = DecryptDataWithJWKOnNode $Password
        $user.SetPassword($decryptedPassword)
    }
    $user.InvokeSet("fullName", $FullName)
    $user.InvokeSet("description", $Description)
    $user.SetInfo()
}
catch [System.InvalidOperationException] {
    Write-Error $_.Exception.Message
    return @{
        valid = $false
        reason = "Error"
        data = $_.Exception.Message
    }
}
catch [System.Management.Automation.RuntimeException] {
    # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
    if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
        Write-Error $_.Exception.Message
    }
    # clear existing error info from try block
    $Error.Clear()
    if ($Password) {
        #Found a bug where the cmdlet will create a user even if the password is not strong enough
        New-LocalUser -Name $UserName -FullName $FullName -Description $Description -Password $Password;
    }
    else {
        New-LocalUser -Name $UserName -FullName $FullName -Description $Description -NoPassword;
    }
}

}
## [END] New-WACLGLocalUser ##
function Remove-WACLGLocalGroup {
<#

.SYNOPSIS
Delete a local group.

.DESCRIPTION
Delete a local group. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $GroupName
)

Set-StrictMode -Version 5.0

try {
    $adsiConnection = [ADSI]"WinNT://localhost";
    $adsiConnection.Delete("Group", $GroupName);
}
catch {
    # Instead of _.Exception.Message, InnerException.Message is more meaningful to end user
    Write-Error $_.Exception.InnerException.Message
    $Error.Clear()
}

}
## [END] Remove-WACLGLocalGroup ##
function Remove-WACLGLocalUser {
<#

.SYNOPSIS
Delete a local user.

.DESCRIPTION
Delete a local user. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName
)

Set-StrictMode -Version 5.0

try {
    $adsiConnection = [ADSI]"WinNT://localhost";
    $adsiConnection.Delete("User", $UserName);
}
catch {
    # Instead of _.Exception.Message, InnerException.Message is more meaningful to end user
    Write-Error $_.Exception.InnerException.Message
    $Error.Clear()
}

}
## [END] Remove-WACLGLocalUser ##
function Remove-WACLGLocalUserFromLocalGroups {
<#

.SYNOPSIS
Removes a local user from one or more local groups.

.DESCRIPTION
Removes a local user from one or more local groups. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,

    [Parameter(Mandatory = $true)]
    [String[]]
    $GroupNames
)

Set-StrictMode -Version 5.0

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
$Error.Clear()
$message = ""
$results = @()
if (!$isWinServer2016OrNewer) {
    $objUser = "WinNT://$UserName,user"
}
Foreach ($group in $GroupNames) {
    if ($isWinServer2016OrNewer) {
        # If execute an external command, the following steps to be done to product correct format errors:
        # -	Use "2>&1" to store the error to the variable.
        # -	Watch $Error.Count to determine the execution result.
        # -	Concatinate the error message to single string and sprit out with Write-Error.
        $Error.Clear()
        $result = & 'net' localgroup $group $UserName /delete 2>&1
        # $LASTEXITCODE here does not return error code, have to use $Error
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
    else {
        $objGroup = [ADSI]("WinNT://localhost/$group,group")
        $objGroup.Remove($objUser)
    }
}

}
## [END] Remove-WACLGLocalUserFromLocalGroups ##
function Remove-WACLGUsersFromLocalGroup {
<#

.SYNOPSIS
Removes local or domain users from the local group.

.DESCRIPTION
Removes local or domain users from the local group. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String[]]
    $users,

    [Parameter(Mandatory = $true)]
    [String]
    $group
)

Set-StrictMode -Version 5.0

$isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
# ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."

$message = ""
Foreach ($user in $users) {
    if ($isWinServer2016OrNewer) {
        # If execute an external command, the following steps to be done to product correct format errors:
        # -	Use "2>&1" to store the error to the variable.
        # -	Watch $Error.Count to determine the execution result.
        # -	Concatinate the error message to single string and sprit out with Write-Error.
        $Error.Clear()
        $result = & 'net' localgroup $group $user /delete 2>&1
        # $LASTEXITCODE here does not return error code, have to use $Error
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
    else {
        if ($user -like '*\*') { # domain user
            $user = $user.Replace('\', '/')
        }
        $groupInstance = [ADSI]("WinNT://localhost/$group,group")
        $groupInstance.Remove("WinNT://$user,user")
    }
}

}
## [END] Remove-WACLGUsersFromLocalGroup ##
function Rename-WACLGLocalGroup {
 <#

 .SYNOPSIS
Renames a local group.

.DESCRIPTION
Renames a local group. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $GroupName,

    [Parameter(Mandatory = $true)]
    [String]
    $NewGroupName
)

Set-StrictMode -Version 5.0

# ADSI does NOT support 2016 Nano, meanwhile Rename-LocalGroup does NOT support downlevel and also with known bug
$Error.Clear()
try {
    $adsiConnection = [ADSI]"WinNT://localhost"
    $group = $adsiConnection.Children.Find($GroupName, "Group")
    if ($group) {
        $group.psbase.rename($NewGroupName)
        $group.psbase.CommitChanges()
    }
}
catch [System.Management.Automation.RuntimeException]
{ # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
    if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
        Write-Error $_.Exception.Message
        return
    }
    # clear existing error info from try block
    $Error.Clear()
    Rename-LocalGroup -Name $GroupName -NewGroupName $NewGroupName
}

}
## [END] Rename-WACLGLocalGroup ##
function Set-WACLGLocalGroupProperties {
<#

.SYNOPSIS
Set local group properties.

.DESCRIPTION
Set local group properties. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $GroupName,

    [Parameter(Mandatory = $false)]
    [String]
    $Description
)

Set-StrictMode -Version 5.0

try {
    $group = [ADSI]("WinNT://localhost/$GroupName, group")

    if ($Description -ne $null) {
        $group.Description = $Description
    }
    
    $group.SetInfo()
}
catch [System.Management.Automation.RuntimeException]
{
     Write-Error $_.Exception.Message
}

return $true

}
## [END] Set-WACLGLocalGroupProperties ##
function Set-WACLGLocalUserPassword {
<#

.SYNOPSIS
Set local user password.

.DESCRIPTION
Set local user password. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,

    [Parameter(Mandatory = $false)]
    [String]
    $Password
)

Set-StrictMode -Version 5.0

if (-not $Password)
{
    $decryptedPassword = ""
}

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode($encryptedData) {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

try {
    $decryptedPassword = DecryptDataWithJWKOnNode $Password
    $user = [ADSI]("WinNT://localhost/$UserName, user")
    $user.psbase.invoke("SetPassword", "$decryptedPassword")
}
catch [System.InvalidOperationException] {
    Write-Error $_.Exception.Message
    return @{
        valid = $false
        reason = "Error"
        data = $_.Exception.Message
    }
}

}
## [END] Set-WACLGLocalUserPassword ##
function Set-WACLGLocalUserProperties {
<#

.SYNOPSIS
Set local user properties.

.DESCRIPTION
Set local user properties. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,

    [Parameter(Mandatory = $false)]
    [String]
    $FullName,

    [Parameter(Mandatory = $false)]
    [String]
    $Description
)

Set-StrictMode -Version 5.0

$user = [ADSI]("WinNT://localhost/$UserName, user")

if ($Description -ne $null) {
    $user.Description = $Description
}

if ($FullName -ne $null) {
    $user.FullName = $FullName
}

$user.SetInfo()

return $true

}
## [END] Set-WACLGLocalUserProperties ##
function Test-WACLGPasswordPolicy {
<#

.SYNOPSIS
Test given password.

.DESCRIPTION
Tests given password against system's password policies to see if it is valid.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $false)]
    [String]
    $UserName,

    [Parameter(Mandatory = $false)]
    [String]
    $FullName,

    [Parameter(Mandatory = $false)]
    [String]
    $Password
)

Set-StrictMode -Version 5.0

Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

###############################################################################
# Constants
###############################################################################
Set-Variable -Name LogName -Option Constant -Value "WindowsAdminCenter" -ErrorAction SilentlyContinue
Set-Variable -Name LogSource -Option Constant -Value "SMEScripts" -ErrorAction SilentlyContinue

function writeInfoLog($logMessage) {
    $message = "[Check-PasswordPolicy]: " + $logMessage
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
        -Message $message -ErrorAction SilentlyContinue
}

function writeErrorLog($errorMessage) {
    $message = "[Check-PasswordPolicy]: " + $logMessage
    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
        -Message $message -ErrorAction SilentlyContinue
}

function GetMinimumPasswordLength() {
    $CustomCode = @"
namespace SME
{
    using System;
    using System.Runtime.InteropServices;

    public static class UserModalsInfo
    {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        static extern uint NetUserModalsGet(
            string server,
            int level,
            out IntPtr BufPtr);

        [DllImport("netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_MODALS_INFO_0
        {
            public uint usrmod0_min_passwd_len;
            public uint usrmod0_max_passwd_age;
            public uint usrmod0_min_passwd_age;
            public uint usrmod0_force_logoff;
            public uint usrmod0_password_hist_len;
        };

        public static uint GetMinimumPasswordLength()
        {
            uint passwordLength = 0;
            USER_MODALS_INFO_0 objUserModalsInfo0 = new USER_MODALS_INFO_0();
            IntPtr bufPtr;
            uint exitCode = NetUserModalsGet("\\\\.", 0, out bufPtr);
            if (exitCode != 0)
            {
                throw new InvalidOperationException("Couldn't get MinimumPasswordLength.");
            }

            objUserModalsInfo0 = (USER_MODALS_INFO_0)Marshal.PtrToStructure(bufPtr, typeof(USER_MODALS_INFO_0));
            passwordLength = objUserModalsInfo0.usrmod0_min_passwd_len;
            NetApiBufferFree(bufPtr);
            bufPtr = IntPtr.Zero;

            return passwordLength;
        }
    }
}
"@

    try {
        Add-Type -TypeDefinition $CustomCode
        Remove-Variable CustomCode
        $minimumLength = [SME.UserModalsInfo]::GetMinimumPasswordLength()
    } catch [System.InvalidOperationException] {
        $err = $_.Exception.Message
        $message = "Error occured attempting to get minimum password length policy from system. Error: " + $err
        writeErrorLog $message

        return @{
            valid = $false
            reason = "Error"
            data = $err
        }
    }

    writeInfoLog "Successfully retrieved password policy of length " + $minimumLength + " from system."

    return $minimumLength
}

function CheckPasswordLength($password) {
    $minimumLength = GetMinimumPasswordLength

    if ($password.Length -lt $minimumLength) {
        return @{
            valid = $false
            reason = "LessThanMinimumLength"
            data = $minimumLength
        }
    }

    return @{
        valid = $true
        reason = "Valid"
    }
}

function InitializePositiveRegexes() {
    # Documentation on Windows Password Policy from which these regexes were derived:
    # https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy
    $lowerCaseRegex = "[a-z]"
    $upperCaseRegex = "[A-Z]"
    $numericalRegex = "[0-9]"
    $symbolsRegex = "[~!@#\$%\^&\*_\-\+=`\|\\\(\){}\[\]:;`"`'<>,\.?\/]"
    $remainingUnicodeRegex = "[^a-zA-Z0-9~!@#\$%\^&\*_\-\+=`\|\\\(\){}\[\]:;`"`'<>,\.?\/]"

    writeInfoLog "Initialized positive regexes."

    return @($lowerCaseRegex, $upperCaseRegex, $numericalRegex, $symbolsRegex, $remainingUnicodeRegex)
}

function BuildNegativeRegex($userName, $fullName) {
    $negativeRegex = $null
    if ($null -ne $userName -and $userName.Length -ge 3) {
        $negativeRegex = "(" + $userName + ")"
    } else {
        writeInfoLog "No user name provided or length is < 3 characters, not including in negative regex."
    }

    if ($null -ne $fullName) {
        $delimiterRegex = "[,\.\-_\s#]"
        $splitName = $fullName -split $delimiterRegex

        foreach ($name in $splitName) {
            if ($name.Length -ge 3) {
                if ($null -eq $negativeRegex) {
                    $negativeRegex = "(" + $name + ")"
                } else {
                    $negativeRegex = $negativeRegex + "|(" + $name + ")"
                }
            }
        }
    } else {
        writeInfoLog "No full name provided, not including in negative regex."
    }

    writeInfoLog "Built negative regex: $negativeRegex"

    return $negativeRegex
}

function CheckNegativeRegex($password, $negativeRegex) {
    if ($null -ne $negativeRegex -and $password -match $negativeRegex) {
        writeInfoLog "Password failed negative regex check."
        return @{
            valid = $false
            reason = "ContainsName"
        }
    }

    writeInfoLog "Password passed negative regex check."
    return @{
        valid = $true
        reason = "Valid"
    }
}

function CheckPositiveRegexes($password) {
    $positiveRegexes = InitializePositiveRegexes

    $count = 0
    foreach ($regex in $positiveRegexes) {
        if ($password -cmatch $regex) {
            $count = $count + 1
        }
    }

    if ($count -lt 3) {
        writeInfoLog "Password failed positive regex check."
        return @{
            valid = $false
            reason = "UnvariedCharacters"
        }
    }

    writeInfoLog "Password passed positive regex check."
    return @{
        valid = $true
        reason = "Valid"
    }
}

function CheckRegexes($password, $userName, $fullName) {
    $negativeRegex = BuildNegativeRegex $userName $fullName

    $negativeRegexResult = CheckNegativeRegex $password $negativeRegex
    if ($negativeRegexResult.valid -eq $false) {
        return $negativeRegexResult
    }

    $positiveRegexResult = CheckPositiveRegexes $password
    if ($positiveRegexResult.valid -eq $false) {
        return $positiveRegexResult
    }

    return @{
        valid = $true
        reason = "Valid"
    }
}

New-Variable -Name rsaProviderInstanceName -Value "RSA" -Option Constant

function DecryptDataWithJWKOnNode($encryptedData) {
  if(Get-Variable -Scope Global -Name $rsaProviderInstanceName -EA SilentlyContinue) {
    $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
    $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
  }
  throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
}

function Main($password, $userName, $fullName) {
    if ($null -eq $password) {
        writeInfoLog "Password was not provided, returning invalid."
        return @{
            valid = $false
            reason = "NotProvided"
        }
    }
    try {
        $decryptedPassword = DecryptDataWithJWKOnNode $password
        $minimumLengthResult = CheckPasswordLength $decryptedPassword
        if ($minimumLengthResult.valid -eq $false) {
            return $minimumLengthResult
        }

        return CheckRegexes $decryptedPassword $userName $fullName
    }
    catch [System.InvalidOperationException] {
        Write-Error $_.Exception.Message
        return @{
            valid = $false
            reason = "Error"
            data = $_.Exception.Message
        }
    }
}

###############################################################################
# Script execution starts here...
###############################################################################
if (-not ($env:pester)) {
    Microsoft.PowerShell.Management\New-EventLog -LogName $LogName -Source $LogSource -ErrorAction SilentlyContinue

    return Main $Password $UserName $FullName
}

}
## [END] Test-WACLGPasswordPolicy ##

# SIG # Begin signature block
# MIIoVQYJKoZIhvcNAQcCoIIoRjCCKEICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCaKWg9BGbgpN/8
# MPo5ISJRD/w6Y1sS/W+pSm5xW9KVaqCCDYUwggYDMIID66ADAgECAhMzAAAEhJji
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEOg
# 1bgcH0rf/mE2skS+Wyav1ugUegmEysMuEMlytH8QMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAEuw2wkDMSUUwRlkfbfwnt5qNdEclvi1e7Gb/
# a4AzBhjO+9qFEiEtxCQk2ICNOgC1L8r8ovTkUa4oAbxoHTAqpZhJ+VQc/sruFaPb
# JUANaSErIQLd39CG0sb6G8cNqyqB6NtWgUqF2cCgec2AkpEaVlxDJjzkmA/q1pMg
# 0sY7noBZ5vgihFka7ZHANFmgPf/EXJZSaBVhaCixwsl/uIR12C5arwByZb6JOnPe
# X9FkMSZbyqF+retI2ZC++hj9vq3yALuWpFBT6ag8vjNrMqeUyJUOuSYYctsonPla
# 6TuMscGDPKAqkVU6z2LVPHuGzag428eYIYen6aGha/TU0PejGKGCF7AwghesBgor
# BgEEAYI3AwMBMYIXnDCCF5gGCSqGSIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCH7AM2bo8ryWKzNaDOGincZkTqjcmL6D+i
# uDswIfKEWAIGaQKOSQGzGBMyMDI1MTExMDE3MTYyMS44NzhaMASAAgH0oIHZpIHW
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
# 9w0BCQQxIgQgAEcYu9SNhAplz2O6DJUVV/6t5HX1z5gT4lTyRoTP5dIwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCdeiHHrbtpKcwB20doVU89WHIOH8S7w37u
# aHcDmemK+zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAACGqmgHQagD0OqAAEAAAIaMCIEIKPNFLzj+7E9mXDA/zdHxTSaFDNlSt/bn9SH
# lqQLiN7nMA0GCSqGSIb3DQEBCwUABIICACvJT0TeLGQ9NBhl2V81BYCI850VdLCI
# IkEHHNod3LQ/uW9lUifZGmO7Adjki125Wf1r70P5c4f/I0va7W3eek+p3m3xvhbs
# HnBLLp4lkTnkGss7aPRhdtlInSDLEd0tmFkvofAzhmqXHUvwvYoWhVcK/CFWAIoX
# utfwSS42s7OQZ16t/uYGgFCXu5CjRX3GVCiY59kL5bHZVDxucClvDZE86Y4Sv2ow
# mhYZidXqT79wYrMogV+lCDlt93T7bG+UW1qfruGsGtHpTc3yjJN1z7rBWBPFHQDG
# li4EWZRkM4jg+C0Z7hX54xBIJok9G3ddyGNpDK8VX4tY/C7d3sEk3zw456OFnOjM
# OFV+twVkKLCQThXisS2FqAvJMaYmx2ILNePkCS+Vv6H2SjXlb9wBbAi45V+qiI4m
# Wo2UO7afkft5kvU9zReqKl50dRBhZNIwRk16Oux0Gzd4AVoAM9yXi7RML7YGV+bY
# ciaO/x1K1O42Dqi1u/mcNTMvG4PU9ineWiNmRFAf9OMEir6y4X72sjhJj2YJl1AY
# KPQrpcBNWJbtH7AnDtUrOHzOJAdCI33LVfwxiAnqTX7cNFYgpE4SdCoOodtINiKg
# VR0FsZ18asxPBx/Rk0Yh2KFszi6WGBQTRl8niuT4dAgWWs9Lkl/6WT8f/WBkAo9I
# KgHW/KBZp1O1
# SIG # End signature block
