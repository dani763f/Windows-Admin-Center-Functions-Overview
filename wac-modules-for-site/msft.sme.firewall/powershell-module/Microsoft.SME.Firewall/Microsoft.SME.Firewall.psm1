function Disable-WACFWFirewallRule {
<#

.SYNOPSIS
Disable Firewall Rule.

.DESCRIPTION
Disable Firewall Rule.

.ROLE
Administrators

#>
 param (
    [Parameter(Mandatory = $true)]
    [String]
    $instanceId,

    [Parameter(Mandatory = $true)]
    [String]
    $policyStore
)

Import-Module netsecurity

Disable-NetFirewallRule -PolicyStore $policyStore -Name $instanceId

}
## [END] Disable-WACFWFirewallRule ##
function Edit-WACFWFirewallRule {
<#

.SYNOPSIS
Edit a new firewall rule in the system.

.DESCRIPTION
Edit a new firewall rule in the system.

.ROLE
Administrators

#>

 param (
    [Parameter(Mandatory = $true)]
    [String]
    $instanceId,

    [Parameter(Mandatory = $false)]
    [String]
    $displayName,

    [Parameter(Mandatory = $false)]
    [int]
    $action,

    [Parameter(Mandatory = $false)]
    [String]
    $description,

    [Parameter(Mandatory = $false)]
    [int]
    $direction,

    [Parameter(Mandatory = $false)]
    [bool]
    $enabled,

    [Parameter(Mandatory = $false)]
    [String[]]
    $icmpType,

    [Parameter(Mandatory = $false)]
    [String[]]
    $localPort,

    [Parameter(Mandatory = $false)]
    [String]
    $profile,

    [Parameter(Mandatory = $false)]
    [String]
    $protocol,

    [Parameter(Mandatory = $false)]
    [String[]]
    $remotePort
)

Import-Module netsecurity

$command = 'Set-NetFirewallRule -Name $instanceId'
if ($displayName) {
    $command += ' -NewDisplayName $displayName';
}
if ($action) {
    $command += ' -Action ' + $action;
}
if ($description) {
    $command += ' -Description $description';
}
if ($direction) {
    $command += ' -Direction ' + $direction;
}
if ($PSBoundParameters.ContainsKey('enabled')) {
    $command += ' -Enabled ' + $enabled;
}
if ($icmpType) {
    $command += ' -IcmpType $icmpType';
}
if ($localPort) {
    $command += ' -LocalPort $localPort';
}
if ($profile) {
    $command += ' -Profile $profile';
}
if ($protocol) {
    $command += ' -Protocol $protocol';
}
if ($remotePort) {
    $command += ' -RemotePort $remotePort';
}

Invoke-Expression $command

}
## [END] Edit-WACFWFirewallRule ##
function Enable-WACFWFirewallRule {
<#

.SYNOPSIS
Enable Firewall Rule.

.DESCRIPTION
Enable Firewall Rule.

.ROLE
Administrators

#>

 param (
    [Parameter(Mandatory = $true)]
    [String]
    $instanceId,

    [Parameter(Mandatory = $true)]
    [String]
    $policyStore
)

Import-Module netsecurity

Enable-NetFirewallRule -PolicyStore $policyStore -Name $instanceId

}
## [END] Enable-WACFWFirewallRule ##
function Get-WACFWFirewallProfile {
<#

.SYNOPSIS
Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.

.DESCRIPTION
Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.

.ROLE
Readers

#>

Import-Module netsecurity

Get-NetFirewallProfile -PolicyStore ActiveStore | Microsoft.PowerShell.Utility\Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

}
## [END] Get-WACFWFirewallProfile ##
function Get-WACFWFirewallRules {
<#

.SYNOPSIS
Get Firewall Rules.

.DESCRIPTION
Get Firewall Rules.

.ROLE
Readers

#>

Import-Module netsecurity

$sidToPrincipalCache = @{};

function getPrincipalForSid($sid) {

  if ($sidToPrincipalCache.ContainsKey($sid)) {
    return $sidToPrincipalCache[$sid]
  }

  $propertyBag = @{}
  $propertyBag.userName = ""
  $propertyBag.domain = ""
  $propertyBag.principal = ""
  $propertyBag.ssid = $sid

  try{
	  $win32Sid = [WMI]"root\cimv2:win32_sid.sid='$sid'";
    $propertyBag.userName = $win32Sid.AccountName;
    $propertyBag.domain = $win32Sid.ReferencedDomainName

    try {
		$objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
      try{
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
        $propertyBag.principal = $objUser.Value;
      } catch [System.Management.Automation.MethodInvocationException]{
        # the sid couldn't be resolved
      }

    } catch [System.Management.Automation.MethodInvocationException]{
      # the sid is invalid
    }

  } catch [System.Management.Automation.RuntimeException] {
    # failed to get the user info, which is ok, maybe an old SID
  }

  $object = New-Object -TypeName PSObject -Prop $propertyBag
  $sidToPrincipalCache.Add($sid, $object)

	return $object
}

function fillUserPrincipalsFromSddl($sddl, $allowedPrincipals, $skippedPrincipals) {
  if ($sddl -eq $null -or $sddl.count -eq 0) {
    return;
  }

  $entries = $sddl.split(@("(", ")"));
  foreach ($entry in $entries) {
    $entryChunks = $entry.split(";");
    $sid = $entryChunks[$entryChunks.count - 1];
    if ($entryChunks[0] -eq "A") {
      $allowed = getPrincipalForSid($sid);
      $allowedPrincipals.Add($allowed) > $null;
    } elseif ($entryChunks[0] -eq "D") {
      $skipped = getPrincipalForSid($sid);
      $skippedPrincipals.Add($skipped) > $null;
    }
  }
}

$stores = @('PersistentStore','RSOP');
$allRules = @()
foreach ($store in $stores){
  $rules = (Get-NetFirewallRule -PolicyStore $store)

  $rulesHash = @{}
  $rules | foreach {
    $newRule = ($_ | Microsoft.PowerShell.Utility\Select-Object `
      instanceId, `
      name, `
      displayName, `
      description, `
      displayGroup, `
      group, `
      @{Name="enabled"; Expression={$_.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True}}, `
      profiles, `
      platform, `
      direction, `
      action, `
      edgeTraversalPolicy, `
      looseSourceMapping, `
      localOnlyMapping, `
      owner, `
      primaryStatus, `
      status, `
      enforcementStatus, `
      policyStoreSource, `
      policyStoreSourceType, `
      @{Name="policyStore"; Expression={$store}}, `
      @{Name="addressFilter"; Expression={""}}, `
      @{Name="applicationFilter"; Expression={""}}, `
      @{Name="interfaceFilter"; Expression={""}}, `
      @{Name="interfaceTypeFilter"; Expression={""}}, `
      @{Name="portFilter"; Expression={""}}, `
      @{Name="securityFilter"; Expression={""}}, `
      @{Name="serviceFilter"; Expression={""}})

      $rulesHash[$_.CreationClassName] = $newRule
      $allRules += $newRule  }

  $addressFilters = (Get-NetFirewallAddressFilter  -PolicyStore $store)
  $applicationFilters = (Get-NetFirewallApplicationFilter  -PolicyStore $store)
  $interfaceFilters = (Get-NetFirewallInterfaceFilter  -PolicyStore $store)
  $interfaceTypeFilters = (Get-NetFirewallInterfaceTypeFilter  -PolicyStore  $store)
  $portFilters = (Get-NetFirewallPortFilter  -PolicyStore $store)
  $securityFilters = (Get-NetFirewallSecurityFilter  -PolicyStore $store)
  $serviceFilters = (Get-NetFirewallServiceFilter  -PolicyStore $store)

  $addressFilters | ForEach-Object {
    $newAddressFilter = $_ | Microsoft.PowerShell.Utility\Select-Object localAddress, remoteAddress;
    $newAddressFilter.localAddress = @($newAddressFilter.localAddress)
    $newAddressFilter.remoteAddress = @($newAddressFilter.remoteAddress)
    $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
     $rule.addressFilter = $newAddressFilter
    }
  }

  $applicationFilters | ForEach-Object {
    $newApplicationFilter = $_ | Microsoft.PowerShell.Utility\Select-Object program, package;
      $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.applicationFilter = $newApplicationFilter
    }
  }

  $interfaceFilters | ForEach-Object {
    $newInterfaceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceAlias"; Expression={}};
    $newInterfaceFilter.interfaceAlias = @($_.interfaceAlias);
      $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.interfaceFilter = $newInterfaceFilter
    }
  }

  $interfaceTypeFilters | foreach {
    $newInterfaceTypeFilter  = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceType"; Expression={}};
    $newInterfaceTypeFilter.interfaceType = $_.PSbase.CimInstanceProperties["InterfaceType"].Value;
    $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.interfaceTypeFilter = $newInterfaceTypeFilter
    }
  }

  $portFilters | foreach {
    $newPortFilter = $_ | Microsoft.PowerShell.Utility\Select-Object dynamicTransport, icmpType, localPort, remotePort, protocol;
    $newPortFilter.localPort = @($newPortFilter.localPort);
    $newPortFilter.remotePort = @($newPortFilter.remotePort);
    $newPortFilter.icmpType = @($newPortFilter.icmpType);
    $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.portFilter = $newPortFilter
    }
  }

  $securityFilters | ForEach-Object {
    $allowedLocalUsers = New-Object System.Collections.ArrayList;
    $skippedLocalUsers = New-Object System.Collections.ArrayList;
    fillUserPrincipalsFromSddl -sddl $_.localUser -allowedprincipals $allowedLocalUsers -skippedPrincipals $skippedLocalUsers;

    $allowedRemoteMachines = New-Object System.Collections.ArrayList;
    $skippedRemoteMachines = New-Object System.Collections.ArrayList;
    fillUserPrincipalsFromSddl -sddl $_.remoteMachine -allowedprincipals $allowedRemoteMachines -skippedPrincipals $skippedRemoteMachines;

    $allowedRemoteUsers = New-Object System.Collections.ArrayList;
    $skippedRemoteUsers = New-Object System.Collections.ArrayList;
    fillUserPrincipalsFromSddl -sddl $_.remoteUser -allowedprincipals $allowedRemoteUsers -skippedPrincipals $skippedRemoteUsers;

  $newSecurityFilter = $_ | Microsoft.PowerShell.Utility\Select-Object authentication, `
    encryption, `
    overrideBlockRules, `
    @{Name="allowedLocalUsers"; Expression={}}, `
    @{Name="skippedLocalUsers"; Expression={}}, `
    @{Name="allowedRemoteMachines"; Expression={}}, `
    @{Name="skippedRemoteMachines"; Expression={}}, `
    @{Name="allowedRemoteUsers"; Expression={}}, `
    @{Name="skippedRemoteUsers"; Expression={}};

    $newSecurityFilter.allowedLocalUsers = $allowedLocalUsers.ToArray()
    $newSecurityFilter.skippedLocalUsers = $skippedLocalUsers.ToArray()
    $newSecurityFilter.allowedRemoteMachines = $allowedRemoteMachines.ToArray()
    $newSecurityFilter.skippedRemoteMachines = $skippedRemoteMachines.ToArray()
    $newSecurityFilter.allowedRemoteUsers = $allowedRemoteUsers.ToArray()
    $newSecurityFilter.skippedRemoteUsers = $skippedRemoteUsers.ToArray()

    $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.securityFilter = $newSecurityFilter
    }
  }

  $serviceFilters | ForEach-Object {
    $newServiceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object serviceName;
    $rule = $rulesHash[$_.CreationClassName];
    if ($rule){
      $rule.serviceFilter = $newServiceFilter
    }
  }
}

$allRules

}
## [END] Get-WACFWFirewallRules ##
function New-WACFWFirewallRule {
<#

.SYNOPSIS
Create a new Firewall Rule.

.DESCRIPTION
Create a new Firewall Rule.

.ROLE
Administrators

#>

 param (
    [Parameter(Mandatory = $true)]
    [String]
    $displayName,

    [Parameter(Mandatory = $false)]
    [int]
    $action,

    [Parameter(Mandatory = $false)]
    [String]
    $description,

    [Parameter(Mandatory = $false)]
    [int]
    $direction,

    [Parameter(Mandatory = $false)]
    [bool]
    $enabled,

    [Parameter(Mandatory = $false)]
    [String[]]
    $icmpType,

    [Parameter(Mandatory = $false)]
    [String[]]
    $localAddresses,

    [Parameter(Mandatory = $false)]
    [String[]]
    $localPort,

    [Parameter(Mandatory = $false)]
    [String]
    $profile,

    [Parameter(Mandatory = $false)]
    [String]
    $protocol,

    [Parameter(Mandatory = $false)]
    [String[]]
    $remoteAddresses,

    [Parameter(Mandatory = $false)]
    [String[]]
    $remotePort
)

Import-Module netsecurity

$command = 'New-NetFirewallRule -DisplayName $displayName'
if ($action) {
    $command += ' -Action ' + $action;
}
if ($description) {
    $command += ' -Description $description';
}
if ($direction) {
    $command += ' -Direction ' + $direction;
}
if ($PSBoundParameters.ContainsKey('enabled')) {
    $command += ' -Enabled ' + $enabled;
}
if ($icmpType) {
    $command += ' -IcmpType $icmpType';
}
if ($localAddresses) {
    $command += ' -LocalAddress $localAddresses';
}
if ($localPort) {
    $command += ' -LocalPort $localPort';
}
if ($profile) {
    $command += ' -Profile $profile';
}
if ($protocol) {
    $command += ' -Protocol $protocol';
}
if ($remoteAddresses) {
    $command += ' -RemoteAddress $remoteAddresses';
}
if ($remotePort) {
    $command += ' -RemotePort $remotePort';
}

Invoke-Expression $command

}
## [END] New-WACFWFirewallRule ##
function Remove-WACFWFirewallRule {
<#

.SYNOPSIS
Delete Firewall rule.

.DESCRIPTION
Delete Firewall rule.

.ROLE
Administrators

#>

 param (
    [Parameter(Mandatory = $true)]
    [String]
    $instanceId,

    [Parameter(Mandatory = $true)]
    [String]
    $policyStore
)

Import-Module netsecurity

Remove-NetFirewallRule -PolicyStore $policyStore -Name $instanceId

}
## [END] Remove-WACFWFirewallRule ##

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAqUqbRP+l/1Fyn
# g3I7dRNH5uBcHjugB4sNoYSQ2UaXLKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDL1AO0gVPc5MWIkJAmAY8cd
# ukZMyd0e0ma97/Afhq+JMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAF8tm8TU3Ld+HzpT11vB3Ewd9mwhim4Xx4yUz4HsLYKxp1H/MAgKJVUE0
# ad2IpDhMOK0b9EGDxh2l3F2MJAhPlRCAWCy/6vKwjKWEBGYfn1j2tn77r3NMpXfR
# 8p748hRj7T8ClaR/Vh8tb/8/1/FVMri9R10UMLJt8Aekihh3tWMyeTMP98A4hsUH
# wu8TFXF/bYL6hvL/R/9LDximKaEucYzJXH+2BOnSacWqrTH38+LB6UMVgESmVXye
# JIERJ77ktLtM9jWAz8yYQgtpNNB+T0cA4+ZFeR1Dh5xYOqDUqonc1iEDrvmo4qoF
# mE5mvyGLCSLvrVMcxjbbCAEWEE+0F6GCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCC
# F34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAGSrkhDvEIuwrjYfdXHGn4U0oH5OlyqHBXQjBLC518pAIGaO/YTsw4
# GBIyMDI1MTExMDE3MTcxOC44M1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAwLTA1
# RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# Ee0wggcgMIIFCKADAgECAhMzAAACAnlQdCEUfbihAAEAAAICMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI0
# NFoXDTI2MDQyMjE5NDI0NFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNDAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALd5Knpy5xQY6Rw+Di8pYol8RB6yErZkGxhTW0Na9C7o
# v2Wn52eqtqMh014fUc3ejPeKIagla43YdU1mRw63fxpYZ5szSBRQ60+O4uG47l3r
# tilCwcEkBaFy978xV2hA+PWeOICNKI6svzEVqsUsjjpEfw14OEA9dwmlafsAjMLI
# iNk5onYNYD7pDA3PCqMGAil/WFYXCoe88R53LSei1du1Z9P28JIv2x0Mror8cf0e
# xpjnAuZRQHtJ+4sajU5YSbownIbaOLGqL03JGjKl0Xx1HKNbEpGXYnHC9t62UNOK
# jrpeWJM5ySrZGAz5mhxkRvoSg5213RcqHcvPHb0CEfGWT7p4jBq+Udi44tkMqh08
# 5U3qPUgn1uuiVjqZluhDnU6p7mcQzmH9YlfbwYtmKgSQk3yo57k/k/ZjH0eg6ou6
# BfTSoLPGrgEObzEfzkcrG8oI7kqKSilpEYa1CVeMPK6wxaWsdzJK3noOEvh1xWef
# t0W8vnTO9CUVkyFWh6FZJCSRa5SUIKog6tN7tFuadt0miwf7uUL6fneCcrLg6hnO
# 5R6rMKdIHUk1c8qcmiM/cN7nHCymLm1S9AU1+V8ZOyNmBACAMF2D8M7RMaAtEMq9
# lAJnmoi5elBHKDfvJznV73nPxTabKxTRedKlZ6KAeqTI4C0N9wimrka/sdX51rZH
# AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU2ga5tQ+M/Z/yJ+Qgq/DLWuVIdNkwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBAIPzdoVBTE3fseQ6gkMzWZocVlVQZypNBw+c
# 4PpShhEyYMq/QZpseUTzYBiAs+5WW6Sfse0k8XbPSOdOAB9EyfbokUs8bs79dsor
# bmGsE8nfSUG7CMBNW3nxQDUFajuWyafKu6v/qHwAXOtfKte2W/NBippFhj2TRQVj
# kYz6f1hoQQrYPbrx75r4cOZZ761gvYf707hDUxAtqD5yI3AuSP/5CXGleJai70q8
# A/S0iT58fwXfDDlU5OL1pn36o+OzPDfUfid22K8FlofmzlugmYfYlu0y5/bLuFJ0
# l0TRRbYHQURk8siZ6aUqGyUk1WoQ7tE+CXtzzVC5VI7nx9+mZvC1LGFisRLdWw+C
# Vef04MXsOqY8wb8bKwHij9CSk1Sr7BLts5FM3Oocy0f6it3ZhKZr7VvJYGv+LMgq
# CA4J0TNpkN/KbXYYzprhL4jLoBQinv8oikCZ9Z9etwwrtXsQHPGh7OQtEQRYjhe0
# /CkQGe05rWgMfdn/51HGzEvS+DJruM1+s7uiLNMCWf/ZkFgH2KhR6huPkAYvjmba
# ZwpKTscTnNRF5WQgulgoFDn5f/yMU7X+lnKrNB4jX+gn9EuiJzVKJ4td8RP0RZkg
# GNkxnzjqYNunXKcr1Rs2IKNLCZMXnT1if0zjtVCzGy/WiVC7nWtVUeRI2b6tOsvA
# rW2+G/SZMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG
# 9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEy
# MDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
# MTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az
# /1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V2
# 9YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oa
# ezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkN
# yjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7K
# MtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRf
# NN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SU
# HDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoY
# WmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5
# C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8
# FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TAS
# BgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1
# Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUw
# UzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fO
# mhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
# a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggr
# BgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEz
# tTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJW
# AAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G
# 82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/Aye
# ixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI9
# 5ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1j
# dEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZ
# KCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xB
# Zj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuP
# Ntq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvp
# e784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA1Aw
# ggI4AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScw
# JQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTQwMC0wNUUwLUQ5NDcxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAEmJ
# SGkJYD/df+NnIjLTJ7pEnAvOoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDsvJp8MCIYDzIwMjUxMTEwMTcwODEy
# WhgPMjAyNTExMTExNzA4MTJaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOy8mnwC
# AQAwCgIBAAICKVQCAf8wBwIBAAICEgswCgIFAOy96/wCAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQsFAAOCAQEAGAvWE+fqLgybNLbR1U7ZYgF1AEfforscjnnfFzmiUCDE
# LdGd3evfvvRo3Fdyw+iS9CEiZ/IZK7f8D3uBOOAIDTk/dLGAfIj+fbU1Z4EDOKia
# F9FMDHCXOJ2vaeLPCqg0wYfEalWc6TixHV6a8t677BfYu1eB3OE6UjTtZnKYOIkc
# XohohVZ74Wo34ErnAX0OqD+AVZCYK/4pFgDxOe2AoRzLloyankMPr+0m6A7kfM8S
# ME4s4sdjllaLS5bPleuITGs3l/RAsupbIhheEaTgsz9b7j6gf9aUSwfqqnvMJHGy
# QOvlgp1k+cMJg22Ta21yUbkY3KpHBrhv30pEmbmD5DGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAACAnlQdCEUfbihAAEAAAIC
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIIQFOiQ4rBuRUsXRcmKCsl3qQyJOip4D9XlH2Gl4SzoY
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg843qARgHlsvNcta5SYvxl3zF
# cCypeSx50XKiV8yUX+wwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAgJ5UHQhFH24oQABAAACAjAiBCCVr4pxl4/c6A7A/MwdC+BwcDRx
# hdrcXQriIVnXBNIyrDANBgkqhkiG9w0BAQsFAASCAgCbYFKo3s+Ysab4QQrg4Y7l
# I8yo4D/ryZRXdRk8+OnyKXTcXy3uqk+NpUj+JlFKFBdrPVo6lvGDz2cboISvgJ7u
# H1yD11vLmm9z86r/i9dWmHowifCoNQHKW/B9/fscxJNw+Z2tQoHpzp18i3ylb4/b
# BSHKgF1rJwXGVMCULv4DLyJFdQn1ltLrEsgQ8LOlShsvzPDu4AqN9xlNGGfpx9Ek
# TAaNTD2yVzz+cPKFWEwiYrJr/hkZEVqtspOmbOCg4v7TV9xaqqqfOmknGtgNo/h3
# 4o/Er3NmxJfprs68/IpzeZQaCmhpDvCctzazFMLozJ5GFCAcVbPbUky6f8s1xf6e
# F3vWtBDjTtfPto2ZhbUU7vVExgxMu46ZGG/O+NPVgWvACGSIfSU1FTklUMeQzxIk
# 65VeQuGNd55gkH2cZkRQyByLpFL61tfUTbjZtEn4LuyWyjQyZC/LdSWla4ZwdmsO
# 1QqPAgnY3j0jjDvBJnad4GP+eWs8u/ngEluH/k858wUt6elDVLO5L8wMs2laANN/
# WHSt7SHNfV4KTY/05KQ99CqlHh8DRnlVKMSfWQb+xK1SqJVmJpDqDNwdnqlEwz1M
# vjZcSuokorJXTcW9gS86iMeq87mA19Z/dxc0O8v8/QZF/TptV+vcykZ3Qn/Chcaf
# mE/68bUTkwKhXYU1MPvLbQ==
# SIG # End signature block
