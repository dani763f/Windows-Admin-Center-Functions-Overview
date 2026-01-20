function Get-WACRFRoleAndFeatureDependencies {
<#

.SYNOPSIS
Retrieves all Feature/Role/Role Services, and their dependencies, to be installed on the target server. 

.DESCRIPTION
Retrieves all Feature/Role/Role Services, and their dependencies, to be installed on the target server. 

.PARAMETER FeatureName
Is a required parameter and is the name of the Role/Feature/Role Service to install

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>
param(
  [Parameter(Mandatory=$True)]
  [string[]]
  $FeatureName
)

Import-Module ServerManager

$output = @()

$feature = Get-WindowsFeature -Name $FeatureName

If ($feature -AND $feature.Where({$_.InstallState -eq 'Available'})) {
    Try {
        If ($feature.Name -eq 'Hyper-V') {
            $result = Install-WindowsFeature -Name 'Hyper-V' -IncludeAllSubFeature -IncludeManagementTools -WhatIf -ErrorAction SilentlyContinue -ErrorVariable +err

            # Handles the case of nested virtualization not being enabled. The error message representing this error (and the FullyQualifiedErrorId below) is:
            # Error: A prerequisite check for the Hyper-V feature failed. Hyper-V cannot be installed: The processor does not have required virtualization capabilities.
            If ($err -AND $feature.Name -eq 'Hyper-V' -AND $err[0].FullyQualifiedErrorId -eq 'Alteration_PrerequisiteCheck_Failed,Microsoft.Windows.ServerManager.Commands.AddWindowsFeatureCommand') {
                $output += 'Hyper-V'
                $FeatureName = $FeatureName | Where-Object {$_ -ne "Hyper-V"}                
            }
        }
        if ($FeatureName) {
            $result = Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature -IncludeManagementTools -WhatIf
            $output += $result.FeatureResult.DisplayName
        }
    }
    Catch {
        Throw
    }
}

$output

}
## [END] Get-WACRFRoleAndFeatureDependencies ##
function Get-WACRFRolesAndFeatures {
<#

.SYNOPSIS
Gets a list of Features / Roles / Role Services on the target server.

.DESCRIPTION
The data returned for each includes name, description, installstate, installed?... Can be called with a FeatureName or FeatureType both of which are optional.

.EXAMPLE
./GetFeaturesAndRoles.ps1
When called with no parameters, returns data for all roles, features and role services available on the server

.EXAMPLE
./GetFeaturesAndRoles.ps1 -FeatureName 'Web-Server'
When called with a FeatureName (e.g. Web-Server) returns details for the given feature if it is available

.EXAMPLE
./GetFeaturesAndRoles.ps1 -FeatureType 'Role'
When called with a FeatureType ('Role', 'Feature' or 'Role Service) returns details for all avilable features of that FeatureType

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Readers

#>

param(
  [Parameter(Mandatory=$False)]
  [string]
  $FeatureName = '',

  [Parameter(Mandatory=$False)]
  [ValidateSet('Role', 'Role Service', 'Feature', IgnoreCase=$False)]
  [string]
  $FeatureType = ''
)

Import-Module ServerManager

$result = $null

if ($FeatureName) {
  $result = Get-WindowsFeature -Name $FeatureName
} else {
  if ($FeatureType) {
    $result = Get-WindowsFeature | Where-Object { $_.FeatureType -EQ $FeatureType }
  } else {
    $result = Get-WindowsFeature
  }

}

$result

}
## [END] Get-WACRFRolesAndFeatures ##
function Install-WACRFRolesAndFeatures {
<#

.SYNOPSIS
Installs a Feature/Role/Role Service on the target server.

.DESCRIPTION
Installs a Feature/Role/Role Service on the target server, using Install-WindowsFeature PowerShell cmdlet. Returns a status object
that contains the following properties:
success - true/false depending on if the overall operation Succeeded
status - status message
result - response from Install-WindowsFeature call

.PARAMETER FeatureName
Is a required parameter and is the name of the Role/Feature/Role Service to install

.PARAMETER IncludeAllSubFeature
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.PARAMETER IncludeManagementTools
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.PARAMETER Restart
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'ManagementOData'
Installs the feature 'ManagementObject' without subfeature and management tools

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'Web-Server' -IncludeAllSubFeature -IncludeManagementTools
Installs the role 'Web-Server' with all dependencies and management tools

.EXAMPLE
./InstallRolesAndFeature.ps1 -FeatureName 'ManagementOData' -Restart
Installs the feature 'ManagementObject' without subfeature and management tools and reboots the server

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param(
  [Parameter(Mandatory=$True)]
  [string[]]
  $FeatureName,

  [Parameter(Mandatory=$False)]
  [Switch]
  $IncludeAllSubFeature,

  [Parameter(Mandatory=$False)]
  [Switch]
  $IncludeManagementTools,

  [Parameter(Mandatory=$False)]
  [Switch]
  $Restart
)

Import-Module ServerManager

Enum InstallStatus {
  Failed = 0
  Succeeded = 1
  NoSuchFeature = 2
  AlreadyInstalled = 3
  Pending = 4
}

$result  = $Null
$status = $Null
$success = $False

$ErrorActionPreference = "Stop"

$feature = Get-WindowsFeature -Name $FeatureName
If ($feature) {
  If ($feature.Where({$_.InstallState -eq 'Available'})) {
    Try {
      If ($feature.Where({$_.Name -eq 'Hyper-V'})) {
        $enableHyperVResult = Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V' -NoRestart
      }
      $result = Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature:$IncludeAllSubFeature -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart
      $success = $result -AND $result.Success
      $status = if ($success) { [InstallStatus]::Succeeded } Else { [InstallStatus]::Failed }
    }
    Catch {
      If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
        $status = [InstallStatus]::Pending
        $error.clear()
      } Else {
        Throw
      }
    }
    
  } Else {
    $success = $True
    $status = [InstallStatus]::AlreadyInstalled
  }
} Else {
  $success = $False
  $status = [InstallStatus]::NoSuchFeature
}

@{ 'success' = $success ; 'status' = $status ; 'result' = $result }

}
## [END] Install-WACRFRolesAndFeatures ##
function Uninstall-WACRFRolesAndFeatures {
<#
.SYNOPSIS
UnInstalls a Feature/Role/Role Service on the target server.

.DESCRIPTION
UnInstalls a Feature/Role/Role Service on the target server, using UnInstall-WindowsFeature PowerShell cmdlet. Returns a status object
that contains the following properties:
success - true/false depending on if the overall operation Succeeded
status - status message
result - response from UnInstall-WindowsFeature call

.PARAMETER FeatureName
Is a required parameter and is the name of the Role/Feature/Role Service to un-install

.PARAMETER IncludeManagementTools
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.PARAMETER Restart
Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature

.EXAMPLE
./UnInstallRolesAndFeature.ps1 -FeatureName 'ManagementOData'
Un-Installs the feature 'ManagementObject'

.EXAMPLE
./UnInstallRolesAndFeature.ps1 -FeatureName 'Web-Server' -IncludeManagementTools
Un-Installs the role 'Web-Server' and management tools

.EXAMPLE
./UnInstallRolesAndFeature.ps1 -FeatureName 'ManagementOData' -Restart
Un-Installs the feature 'ManagementObject' without management tools and reboots the server

.NOTES
The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

.ROLE
Administrators

#>

param(
  [Parameter(Mandatory=$True)]
  [string[]]
  $FeatureName,

  [Parameter(Mandatory=$False)]
  [Switch]
  $IncludeManagementTools,

  [Parameter(Mandatory=$False)]
  [Switch]
  $Restart,

  [Parameter(Mandatory=$False)]
  [Switch]
  $WhatIf
)

Import-Module ServerManager

Enum UnInstallStatus {
  Failed = 0
  Succeeded = 1
  NoSuchFeature = 2
  NotInstalled = 3
  Pending = 4
}

$result  = $Null
$status = $Null
$success = $False

$ErrorActionPreference = "Stop"

$feature = Get-WindowsFeature -Name $FeatureName
If ($feature) {
  If ($feature.Where({$_.InstallState -eq 'Installed'})) {
    Try {
      $result = UnInstall-WindowsFeature -Name $FeatureName -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart -WhatIf:$WhatIf
      $success = $result -AND $result.Success
      $status = if ($success) { [UnInstallStatus]::Succeeded } Else { [UnInstallStatus]::Failed }
    }
    Catch {
      If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
        $status = [UnInstallStatus]::Pending
        $error.clear()
      } Else {
        Throw
      }
    }
    
  } Else {
    $success = $True
    $status = [UnInstallStatus]::NotInstalled
  }
} Else {
  $success = $False
  $status = [UnInstallStatus]::NoSuchFeature
}

@{ 'success' = $success ; 'status' = $status ; 'result' = $result }

}
## [END] Uninstall-WACRFRolesAndFeatures ##

# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJ1FfvvwMBW3Bn
# ki7pRS/FoYgQO001SF/iFZ190QJW7qCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGsiuZJol51P2QaHOVh/Mwl9
# XQxH/IxU9PFm2IWGsWRNMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEASpiWgIKWzswR2Vyqoj+h7m+7zq6n+i6EkzHpPutGWcLzK2MpK2HmJj8Q
# vRx0iqM+Q28Z1kFGtEHSylmX5LtzY/kHsrTjA2sUFli6cuV1FRZcj499CFn21Et+
# 5PWmalKgLhkLna9/7EyXCWAD8TcQNVfRS9/6R3CI/zULlPzH8juY1wYu3Xnw4u/J
# zRERKJVl9tHZeEdjUAqIMgSojwIBunEuJDdjkkEPqQzV0g5Z95F17fjWdBXsPA5T
# BgGv7O9SdNghKbxCohsze4SK5Hh/USPqIPbppfo0nMUTo5BB5Bj5wekglzh5uJoj
# Kw1s//3FG5weJNSwgp8ad+qHMsMgZKGCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCC
# F34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCOzQuchoNqggTGwrocmYBiD9Humw+X7zcJlNCtiDxscQIGaO/mvu5I
# GBMyMDI1MTExMDE3MTcxNS4zMzRaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
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
# LwYJKoZIhvcNAQkEMSIEION/vkHphq2h4raFCaPj0gzWkklAP9zTfH9Malt24bRI
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1SjXtwUxk3jowjk18gCD1THl
# w7nEz2Ket7muK45nwi0wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAgy5ZOM1nOz0rgABAAACDDAiBCA0Ia2tCIEbcoajq/vTmYoWGbIM
# 7xAVq5WlhscRQ8YZpjANBgkqhkiG9w0BAQsFAASCAgCyxJcnwQRTgWrA2wRmLxQE
# eI5BPVESZpXFbBlqjHuGro8q4WwJ8T08q6vpqjWigrsaWN7dnsOzBXemQKCA5uzU
# uNC8FXCtYTTQhQ77wc29xCKQBOglTNKSeuM74T0s5SRXKNo8C4L1+9i3L0mNwH2B
# JbNCDt62xcD58cWSYbvqZYlqsVw1SKue1/ruqD6wyd44d14vkcAdWGbJ9VhT4NO+
# NCI8FwsBSq1gs/CxWEpoNK7sHAtexL7+JdfnbmQvQPLWDyBPe+8Ce/J13Y+lUsF0
# WeRwH+9gFOTUiUe816wrH/TxYXOkpb7Dt8b0pun3Cyr9Y6SZ8cxvXQr7Jq4xSqFM
# SaquyW4QQcjZFFHo04+1FBn9bgamkKAATHUCVDCYd+TC72jFZQhIep7IaZoeIqfI
# qVOaw6/hC3tvzUZ28mWEfMtHDMrI1TJpUeE/rXm0jE40TIut91n1GHAxwrdbmQI8
# gEVwedi4n1wcuJ5m/DZQkC4x687jg/P7KfIcMccwxB4sK/Vfycssqove5gMDd5V+
# oIttNOHKfFiuAEUvvQlDVAbdoMnHiZjHPrlTNdsi1AA411B+if/QTpJvZhxcUjcY
# eInA5FfruwPM2I+u3zgJJbbKRPXx4XosWRSntE2HPR1ZZLSTA0gAvwFCDfks3KAT
# X2b4NJA1ERH70sylvfejBQ==
# SIG # End signature block
