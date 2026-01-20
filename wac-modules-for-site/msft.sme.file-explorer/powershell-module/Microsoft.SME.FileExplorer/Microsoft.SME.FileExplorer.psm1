function Add-WACFEFolderShare {
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
## [END] Add-WACFEFolderShare ##
function Add-WACFEFolderShareNameUser {
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
## [END] Add-WACFEFolderShareNameUser ##
function Add-WACFEFolderShareUser {
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
## [END] Add-WACFEFolderShareUser ##
function Compress-WACFEArchiveFileSystemEntity {
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
## [END] Compress-WACFEArchiveFileSystemEntity ##
function Disable-WACFEKdcProxy {
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
## [END] Disable-WACFEKdcProxy ##
function Disable-WACFESmbOverQuic {
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
## [END] Disable-WACFESmbOverQuic ##
function Edit-WACFEFolderShareInheritanceFlag {
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
## [END] Edit-WACFEFolderShareInheritanceFlag ##
function Edit-WACFEFolderShareUser {
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
## [END] Edit-WACFEFolderShareUser ##
function Edit-WACFESmbFileShare {
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
## [END] Edit-WACFESmbFileShare ##
function Edit-WACFESmbServerCertificateMapping {
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
## [END] Edit-WACFESmbServerCertificateMapping ##
function Enable-WACFESmbOverQuic {
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
## [END] Enable-WACFESmbOverQuic ##
function Expand-WACFEArchiveFileSystemEntity {
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
## [END] Expand-WACFEArchiveFileSystemEntity ##
function Get-WACFEBestHostNode {
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
## [END] Get-WACFEBestHostNode ##
function Get-WACFECertificates {
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
## [END] Get-WACFECertificates ##
function Get-WACFEComputerName {
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
## [END] Get-WACFEComputerName ##
function Get-WACFEFileNamesInPath {
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
## [END] Get-WACFEFileNamesInPath ##
function Get-WACFEFileSystemEntities {
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
## [END] Get-WACFEFileSystemEntities ##
function Get-WACFEFileSystemRoot {
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
## [END] Get-WACFEFileSystemRoot ##
function Get-WACFEFolderItemCount {
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
## [END] Get-WACFEFolderItemCount ##
function Get-WACFEFolderOwner {
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
## [END] Get-WACFEFolderOwner ##
function Get-WACFEFolderShareNames {
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
## [END] Get-WACFEFolderShareNames ##
function Get-WACFEFolderSharePath {
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
## [END] Get-WACFEFolderSharePath ##
function Get-WACFEFolderShareStatus {
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
## [END] Get-WACFEFolderShareStatus ##
function Get-WACFEFolderShareUsers {
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
## [END] Get-WACFEFolderShareUsers ##
function Get-WACFEIsAzureTurbineServer {
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
## [END] Get-WACFEIsAzureTurbineServer ##
function Get-WACFEItemProperties {
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
## [END] Get-WACFEItemProperties ##
function Get-WACFEItemType {
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
## [END] Get-WACFEItemType ##
function Get-WACFELocalGroups {
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
## [END] Get-WACFELocalGroups ##
function Get-WACFELocalUsers {
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
## [END] Get-WACFELocalUsers ##
function Get-WACFEOSDetails {
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
## [END] Get-WACFEOSDetails ##
function Get-WACFEShareEntities {
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
## [END] Get-WACFEShareEntities ##
function Get-WACFESmb1InstallationStatus {
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
## [END] Get-WACFESmb1InstallationStatus ##
function Get-WACFESmbFileShareDetails {
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
## [END] Get-WACFESmbFileShareDetails ##
function Get-WACFESmbOverQuicSettings {
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
## [END] Get-WACFESmbOverQuicSettings ##
function Get-WACFESmbServerCertificateHealth {
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
## [END] Get-WACFESmbServerCertificateHealth ##
function Get-WACFESmbServerCertificateMapping {
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
## [END] Get-WACFESmbServerCertificateMapping ##
function Get-WACFESmbServerCertificateValues {
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
## [END] Get-WACFESmbServerCertificateValues ##
function Get-WACFESmbServerSettings {

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
## [END] Get-WACFESmbServerSettings ##
function Get-WACFESmbShareAccess {
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
## [END] Get-WACFESmbShareAccess ##
function Get-WACFEStorageFileShare {
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
## [END] Get-WACFEStorageFileShare ##
function Get-WACFETempFolderPath {
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
## [END] Get-WACFETempFolderPath ##
function Move-WACFEFile {
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
## [END] Move-WACFEFile ##
function New-WACFEFile {
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
## [END] New-WACFEFile ##
function New-WACFEFolder {
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
## [END] New-WACFEFolder ##
function New-WACFESmbFileShare {
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
## [END] New-WACFESmbFileShare ##
function Remove-WACFEAllShareNames {
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
## [END] Remove-WACFEAllShareNames ##
function Remove-WACFEFileSystemEntity {
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
## [END] Remove-WACFEFileSystemEntity ##
function Remove-WACFEFolderShareUser {
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
## [END] Remove-WACFEFolderShareUser ##
function Remove-WACFESmbServerCertificateMapping {
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
## [END] Remove-WACFESmbServerCertificateMapping ##
function Remove-WACFESmbShare {
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
## [END] Remove-WACFESmbShare ##
function Rename-WACFEFileSystemEntity {
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
## [END] Rename-WACFEFileSystemEntity ##
function Restore-WACFEConfigureSmbServerCertificateMapping {
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
## [END] Restore-WACFEConfigureSmbServerCertificateMapping ##
function Set-WACFESmbOverQuicServerSettings {
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
## [END] Set-WACFESmbOverQuicServerSettings ##
function Set-WACFESmbServerCertificateMapping {
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
## [END] Set-WACFESmbServerCertificateMapping ##
function Set-WACFESmbServerSettings {
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
## [END] Set-WACFESmbServerSettings ##
function Test-WACFEFileSystemEntity {
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
## [END] Test-WACFEFileSystemEntity ##
function Uninstall-WACFESmb1 {
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
## [END] Uninstall-WACFESmb1 ##

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARwdOw4Kq0qtuW
# vnUT4rbq0m6HUZNt0mlFFA3zoZ96SqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINDkWjR+KIsPP5KApS5+C6nR
# yg11P9B+dlR5l2/8zA4hMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAqjQPyErfoHB4e321vZiXEMtPT07fhzZa7gvha+TyLu6HGhXqANvUNfcr
# c2j4LX188KFUp+x7d4tsPP61OGeNZ1wp6lxASO65x9UPsiZfQEqEvpEM5yrmC39k
# G3aXK16VOdfOBcwZ41ravnNNpjH5DSWZ4GKJNtpO/n6V4XtVjvTDksNMXdgS2HrN
# +v9VayeKL0eQBnMI7FUS26KDXABtvNnXbWbnQ0m5hemIaYyvM3kK3T9n8tpBt8ft
# L7lvmxzfi/RNQ+3DqUsNE/dr43/oUFXiQAzw8mxLz33TMpk7h2Qkf98tJQv3D4fT
# 1zno1zv2rGCpbIr1uJd57b2F8NhXBKGCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCC
# F34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCC9oTFQrrBWwR6WVBpmoHgeLaCvTTVHVGaexMamGdlOSQIGaO/mvuit
# GBMyMDI1MTExMDE3MTU0MC4wMzZaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# LwYJKoZIhvcNAQkEMSIEIGslchRjVDEtDhUudqGUZ3Ao7PONcdagapazmJVMjfMe
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1SjXtwUxk3jowjk18gCD1THl
# w7nEz2Ket7muK45nwi0wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAgy5ZOM1nOz0rgABAAACDDAiBCA0Ia2tCIEbcoajq/vTmYoWGbIM
# 7xAVq5WlhscRQ8YZpjANBgkqhkiG9w0BAQsFAASCAgATCOD3aGWDTG2d5tC/GG+j
# +0FqT9ykgGCuC+dKZ/8m0GA4V4+kaJvDFXysqQr6pTriTpv9A/AYFM43+Pkj/E5/
# 04l4/20L9lu7LDXtl0Iz/QmMR/JYjAfWl5YV/8ZZ6kPODRqM96GM+H15+iDgm/38
# tUISyN0BGbQRPer6bb8S3zSqf8qqO1gOfNnfYe5N5s1lZw5dIkiwTZWEzo89Uv/0
# Ie3KN5FF2zSSUQXQXNN7hQ0B6xFofxVqUc8KkUijpHRjA3Soqb6DjD2/7yonWUb2
# 95/+Ojero9zVcyTp8TWxD4DiXflCL6b46nd1bEX1XZS5qazm8z5X9OQmbxB6FkWQ
# CbQwmTQk/OFbaAxg24TdLThOh+CiHqhEQzd4cMlMSxXb8W6A+RljhTpC/ep/bFuY
# uO1ipbNUhBFyMRgMfyXDlmomR+HfBfiLGE+acCVWaoUAWfN1TWcspd1YYAZNFHGm
# hyZJR+qvAFxcE1SL+dxpmIhChBrOfcQiJvyLmH0YR1YVFNE7WzwoH3XMU6QNvew+
# VJw0Xq6nsrzCAL6ykPZbfHt4JFrv8By3fdR4D7OkH+U/bFSdqOFTg8/UOwnLsns5
# XfHkWr6vFE2MzdlhVu2EMYTXCKhVimX4IFPovy7f8C2NPkFlARK8ZfowawGWNouT
# vceBIXIjjgDuZa37rFJVag==
# SIG # End signature block
