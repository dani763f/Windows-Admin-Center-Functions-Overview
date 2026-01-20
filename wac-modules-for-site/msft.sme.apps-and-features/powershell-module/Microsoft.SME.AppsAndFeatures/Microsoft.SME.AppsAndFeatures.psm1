function Disable-WACAFFeatures {
<#

.SYNOPSIS
Disables all features that are not already disabled in the selected list.

.DESCRIPTION
Disables all features that are not already disabled in the selected list.

.ROLE
Administrators

#>


Param([object[]] $Features)
Set-StrictMode -Version 5.0;

$SuccessfulDisables = New-Object System.Collections.ArrayList
$FailedDisables = New-Object System.Collections.ArrayList
$ErrorMessages = New-Object System.Collections.ArrayList

$DisableError = $null

# sometimes the user has not restarted their computer in a while and this script usually will not
# work until they restart and clean up whatever junk has been accumulated
$NeedRestart = $false;

foreach($Feature in $Features) {
  (Disable-WindowsOptionalFeature -Online -FeatureName $Feature.Name -NoRestart -ErrorVariable DisableError -ErrorAction SilentlyContinue) | Out-Null
  if ($DisableError) {
    $FailedDisables += $Feature.Name
    $ErrorMessages += $EnableFailure
  } else {
    $SuccessfulDisables += $Feature.Name

    # if the state has not changed, but the script did not throw an error, let the user know they should try restarting
    $VerifyEnable = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -eq $Feature.Name
    if ($VerifyEnable.State -eq "Enabled") {
      $NeedRestart = $true;
    }
  }
}

# TODO: update this when there is a standard method for localizing batch notifications from powershell
# at the moment this is a hack to return a mix of success/error messages in the event that at least one state change failed.
if ($FailedDisables.Count -gt 0) {
  $SuccessMessage = $SuccessfulDisables -join ", "
  $FailureMessage = $FailedDisables -join ", "
  $ReturnMessage = $SuccessMessage + "~" + $FailureMessage + ". " + $ErrorMessages -join ", "
  throw $ReturnMessage
}

# component class will check for this and return a special error message alerting the user to restart
$NeedRestart


}
## [END] Disable-WACAFFeatures ##
function Enable-WACAFFeatures {
<#

.SYNOPSIS
Enables all features that are not already enabled in the selected list.

.DESCRIPTION
Enables all features that are not already enabled in the selected list.

.ROLE
Administrators

#>



Param([object[]] $Features)
Set-StrictMode -Version 5.0;

$SuccessfulEnables = New-Object System.Collections.ArrayList
$FailedEnables = New-Object System.Collections.ArrayList
$ErrorMessages = New-Object System.Collections.ArrayList

$EnableFailure = $null

# sometimes the user has not restarted their computer in a while and this script usually will not
# work until they restart and clean up whatever junk has been accumulated
$NeedRestart = $false;

foreach($Feature in $Features) {

  (Enable-WindowsOptionalFeature -Online -FeatureName $Feature.Name -All -NoRestart -ErrorVariable EnableFailure -ErrorAction SilentlyContinue) | Out-Null
  if ($EnableFailure) {
    $FailedEnables += $Feature.Name
    $ErrorMessages += $EnableFailure
  } else {
    $SuccessfulEnables += $Feature.Name

    # if the state has not changed, but the script did not throw an error, let the user know they should try restarting
    $VerifyEnable = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -eq $Feature.Name
    if ($VerifyEnable.State -eq "Disabled") {
      $NeedRestart = $true;
    }
  }
}

# TODO: update this when there is a standard method for localizing batch notifications from powershell
# at the moment this is a hack to return a mix of success/error messages in the event that at least one state change failed.
if ($FailedEnables.Count -gt 0) {
  $SuccessMessage = $SuccessfulEnables -join ", "
  $FailureMessage = $FailedEnables -join ", "
  $ReturnMessage = $SuccessMessage + "~" + $FailureMessage + ". " + $ErrorMessages -join ", "
  throw $ReturnMessage
}

# component class will check for this and return a special error message alerting the user to restart
$NeedRestart


}
## [END] Enable-WACAFFeatures ##
function Get-WACAFAppListServer {
<#

.SYNOPSIS
Retrieves a list of software installed on this machine.

.DESCRIPTION
Retrieves a list of software installed on this machine. Servers cannot access the normal aeinv.dll library
so there is no way to replicate the Apps and Featurs page in the same way desktops can. Instead, we parse
the registry in 4 different uninstall folders and look for the property System Component. If this property
exists, this application is hidden from the user. If the property does not appear in a registry entry then
we DO return this application in the resultant list.

.ROLE
Readers

#>

$Roots = @("HKLM:", "HKCU:")
$Folders = @(
              "\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
              "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            )

$Result = @()
foreach($Root in $Roots) {
  foreach($Folder in $Folders) {
    $Path = $Root + "\" + $Folder
    Set-Location $Path -ErrorAction SilentlyContinue
    $Programs = Get-ChildItem $Path -ErrorAction SilentlyContinue

    foreach($Program in $Programs) {
      $App = New-Object PSObject
      $Hidden = $Program.GetValue("SystemComponent")
      if ($Hidden -eq $null) {
        # Name and version
        $Name = $Program.GetValue("DisplayName")
        $Version = $Program.GetValue("DisplayVersion")

        # Size
        $EstimatedSize = $Program.GetValue("EstimatedSize")
        if ($EstimatedSize -ne $null) {
          # size returned is in KB not B so we need to put it back to the right base to use the ByteConverter
          $EstimatedSize = $EstimatedSize * 1024
        }

        # InstallDate
        $InstallDate = $Program.GetValue("InstallDate")
        if ($InstallDate -ne $null) {
          try {
            $InstallDate = [datetime]::ParseExact($InstallDate,'yyyyMMdd', $null)
          }
          catch {
            $InstallDate = $null
          }
        }

        # Publisher
        $Publisher = $Program.GetValue("Publisher")

        # UninstallString and IsRemovable
        $UninstallString = $Program.GetValue("UninstallString")

        if ($UninstallString) {
          if ($UninstallString.ToLower().Contains("msiexec.exe")) {
            # If the UninstallString uses msiexec.exe, replace the /I with /X for uninstall
            if ($UninstallString.Contains("/I")) {
              $UninstallString = $UninstallString.Replace("/I", "/X");
            } elseif ($UninstallString.Contains("/i")) {
              $UninstallString = $UninstallString.Replace("/i", "/x");
            }
            $IsRemovable = $true
          } else {
            # If the UninstallString uses an uninstall exe, then mark this app as unremovable.
            $IsRemovable = $false
          }
        } else {
          $IsRemovable = $false
        }

        # ID
        if ($UninstallString -ne $null) {
          $Id = $UninstallString
        } else {
          $Id = $Name + $Version
        }

        $App | Add-Member -MemberType NoteProperty -Name "Name" -Value $Name
        $App | Add-Member -MemberType NoteProperty -Name "Version" -Value $Version
        $App | Add-Member -MemberType NoteProperty -Name "Size" -Value $EstimatedSize
        $App | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $InstallDate
        $App | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
        $App | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $Publisher
        $App | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $UninstallString
        $App | Add-Member -MemberType NoteProperty -Name "IsRemovable" -Value $IsRemovable
        $App | Add-Member -MemberType NoteProperty -Name "Id" -Value $Id

        $Result += $App
      }
    }
  }
}

$Result

}
## [END] Get-WACAFAppListServer ##
function Get-WACAFAppListWindowsPC {
<#

.SYNOPSIS
Retrieves a list of all classic applications and various properties including UninstallString
to remove the application.

.DESCRIPTION
Retrieves a list of all classic applications and various properties including UninstallString
to remove the application.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

$NativeCode = @"
namespace SME
{
    using System;
    using System.Runtime.InteropServices;

    // INTERNAL SOURCE CODE
    // CreateSoftwareInventory REF: https://microsoft.visualstudio.com/OS/_git/os?path=%2Fsdktools%2Fappcert%2Fsrc%2Ftasks%2FNativeMethods.cs&version=GBofficial%2Frsmaster
    // Flag parameters REF: https://microsoft.visualstudio.com/OS/_git/os?path=%2Fbase%2Fappcompat%2Fappraiser%2Fscripts%2FTools%2FDetailedInventory%2Fmain.cpp&version=GBofficial%2Frsmaster
    public static class AppInventory
    {
        [DllImport("aeinv.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int CreateSoftwareInventory(
            uint dwFlags,
            [MarshalAs(UnmanagedType.BStr)] ref string pbstrIntermediateXML,
            [MarshalAs(UnmanagedType.BStr)] ref string pbstrFinalXML);

        public static string GetSoftwareInventory()
        {
            var intermediateXml = string.Empty;
            var finalXml = string.Empty;
            var flags = 983057U; //  GAI_FLAG_SCAN_APPV | GAI_FLAG_SCAN_APPX | GAI_FLAG_SCAN_ARP | GAI_FLAG_SCAN_MISC | GAI_FLAG_APPLICATIONS | GAI_FLAG_APPLICATION_INFO
            var hresult = CreateSoftwareInventory(flags, ref intermediateXml, ref finalXml);

            Marshal.ThrowExceptionForHR(hresult);

            return finalXml;
        }
    }
}
"@

function ProcessModernApp ([object] $App) {
    $ModernApp = New-Object PSObject
    $HiddenArp = $App.HiddenArp

    # If the app is marked as hidden, do not return to viewable list
    if ($HiddenArp -eq $false) {
        # TODO: figure out some way to find size and install date for this source of apps
        $Name = $App.Name
        $Source = $App.Source
        $Version = $App.Version
        $Id = $App.Id

        # xml details
        # app has multiple root nodes so just add a temporary one to parse as XML object
        $XmlString = $App.InnerXml
        [xml] $Xml = "<tempRoot>$XmlString</tempRoot>"
        $XmlProperties = $Xml.tempRoot.Indicators.WindowsStoreAppManifestIndicators.PackageManifest

        # the package full name is used as the uninstall string for Remove-AppxPackage
        $UninstallString = $XmlProperties.PackageFullName
        $IsRemovable = $true
        $Publisher = $XmlProperties.Package.Properties.PublisherDisplayName
        # sometimes this field has been filled in and is more readable, sometimes it was left empty
        $DisplayName = $XmlProperties.Package.Properties.DisplayName

        $ModernApp | Add-Member -MemberType NoteProperty -Name "Name" -Value $Name
        $ModernApp | Add-Member -MemberType NoteProperty -Name "Version" -Value $Version
        $ModernApp | Add-Member -MemberType NoteProperty -Name "Size" -Value $null
        $ModernApp | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $null
        $ModernApp | Add-Member -MemberType NoteProperty -Name "Source" -Value $Source
        $ModernApp | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $Publisher
        $ModernApp | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $UninstallString
        $ModernApp | Add-Member -MemberType NoteProperty -Name "IsRemovable" -Value $IsRemovable
        $ModernApp | Add-Member -MemberType NoteProperty -Name "Id" -Value $Id
        $ModernApp | Add-Member -MemberType NoteProperty -Name "DisplayName" $DisplayName

        return $ModernApp
    }

    return $null;
}

function ProcessClassicApp ([object] $App) {
    $ClassicApp = New-Object PSObject
    $HiddenArp = $App.HiddenArp
    # If the app is marked as hidden, do not return to viewable list
    if ($HiddenArp -eq $false) {
        # base details
        $Name = $App.Name
        $Version = $App.Version
        $InstallDate = $App.InstallDate
        $Source = $App.Source
        $Publisher = $App.Publisher
        $Id = $App.Id;

        # xml details
        $MoreDetails = $App.Indicators.AddRemoveProgramIndicators.AddRemoveProgram
        $UninstallString = $MoreDetails.UninstallString
        if ($Source -eq 'Msi') {
            # /X is an msiexec parameter for uninstall instead of /I for install
            # /qn sets the UI level to none and /quiet insists on a silent uninstall so the user does not have to
            # click a button confirming the uninstall.
            if ($UninstallString.Contains("/I")) {
                $UninstallString = $UninstallString.Replace("/I", "/X");
            }
            elseif ($UninstallString.Contains("/i")) {
                $UninstallString = $UninstallString.Replace("/i", "/x");
            }
            $UninstallString += " /qn /quiet"
            $IsRemovable = $true
        }
        else {
            $IsRemovable = $false
        }

        # parsing remaning properties from registry
        $RegistryKeyPath = "Registry::" + $MoreDetails.RegistryKeyPath

        # square brackets in application name will result in an invalid
        # character pattern error, therefore, a literalpath is used instead
        $EstimatedSize = Get-ItemProperty -LiteralPath $RegistryKeyPath -Name EstimatedSize -ErrorAction SilentlyContinue
        if ($EstimatedSize -ne $null) {
            # size returned is in KB not B so we need to put it back to the right base to use the ByteConverter
            $EstimatedSize = $EstimatedSize.EstimatedSize * 1024
        }

        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Name" -Value $Name
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Version" -Value $Version
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Size" -Value $EstimatedSize
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $InstallDate
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Source" -Value $Source
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $Publisher
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $UninstallString
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "IsRemovable" -Value $IsRemovable
        $ClassicApp | Add-Member -MemberType NoteProperty -Name "Id" -Value $Id

        return $ClassicApp
    }
    return $null
}

###############################################################################
# main
###############################################################################
Add-Type -TypeDefinition $NativeCode

$Xml = [xml] ([SME.AppInventory]::GetSoftwareInventory())
$Applications = $Xml.Log.ProgramList.SelectNodes('Program')

# loop through all applications returned by this flag filtering.
# there are different parameters for modern and classic applications.
$Result = @()
foreach ($App in $Applications) {
    $AppObject = $null

    if ($App.source -eq 'AppxPackage') {
        $AppObject = ProcessModernApp($App)
    } else {
        $AppObject = ProcessClassicApp($App)
    }

    if ($AppObject -ne $null) {
        $Result += $AppObject
    }
}

$Result

}
## [END] Get-WACAFAppListWindowsPC ##
function Get-WACAFFeatureList {
<#

.SYNOPSIS
Retrieves a list of all features on this node.

.DESCRIPTION
Retrieves a list of all features on this node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0;

Get-WindowsOptionalFeature -Online | Sort-Object FeatureName



}
## [END] Get-WACAFFeatureList ##
function Remove-WACAFApps {
<#

.SYNOPSIS
Uninstalls all applications selected for removal. Uses either msiexec or remove appx-package
depending on the source of the application.

.DESCRIPTION
Uninstalls all applications selected for removal. Uses either msiexec or remove appx-package
depending on the source of the application.

.ROLE
Administrators

#>


Param([object[]] $Apps)

Set-StrictMode -Version 5.0;

$SuccessMessage = "Successfully removed '{0}'"
$RemoveSuccesses = New-Object System.Collections.ArrayList
$RemoveSuccessesMessage = ""

$FailureMessage = "We couldn't remove application(s) '{0}'. Error: {1}"
$RemoveFailures = New-Object System.Collections.ArrayList
$RemoveFailuresMessage = ""

foreach ($App in $Apps) {
  $Name = $App.Name
  $Source = $App.Source

  # modern app removal
  if ($Source -eq 'AppxPackage') {
    Remove-AppxPackage ($App.UninstallString) -ErrorVariable UninstallError -ErrorAction SilentlyContinue

    if ($UninstallError) {
      $ErrorMessage = $FailureMessage -f $Name, $UninstallError[0].Exception.Message
      $RemoveFailures += $ErrorMessage
    } else {
      $RemoveSuccesses += $Name
    }
  # classic app removal
  } else {
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $App.UninstallString, " /quiet /qn" -Wait -ErrorVariable UninstallError -ErrorAction SilentlyContinue

    if ($UninstallError) {
      $ErrorMessage = $FailureMessage -f $Name, $UninstallError[0].Exception.Message
      $RemoveFailures += $ErrorMessage
    } else {
      $RemoveSuccesses += $Name
    }
  }
}

if ($RemoveFailures.Count -gt 0) {
  $RemoveSuccessesMessage = $SuccessMessage -f ($RemoveSuccesses -join ", ")
  $RemoveFailuresMessage = $RemoveFailures -join ", "

  $ReturnMessage = $RemoveSuccessesMessage + ". " + $RemoveFailuresMessage
  throw $ReturnMessage
}

}
## [END] Remove-WACAFApps ##
function Restart-WACAFCimOperatingSystem {
<#

.SYNOPSIS
Reboot Windows Operating System by using Win32_OperatingSystem provider.

.DESCRIPTION
Reboot Windows Operating System by using Win32_OperatingSystem provider.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
)

import-module CimCmdlets

Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_OperatingSystem -MethodName Reboot

}
## [END] Restart-WACAFCimOperatingSystem ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDkovW9f5oCK+bb
# UesenCIpwP/TJw7dzvoWz2SaEhaE4KCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB+VoPdUAuVmrN6pM4eZwKTB
# 4MdiSVmq4t88eg3kKJkmMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdrcAPGqwJp4hCWLjTAZ5oc2jwfsKbNRYdDZY+Ki0JeIsosUbiSqezSB2
# 4wxIdMbvRQD502ShCgTrD3YQkA8YBTcLH4WBB5Dz0dLmGpxYw6avOqNMgHkxEH6K
# tNcnE9VBb4VQoxzdJLdE+/tocMlG3n9tonRN0alovLbT41+vdn/IZcfGrz86s49S
# CWrd1fTKL7Z9lvepoyKZ1J8R885e36Z9BPeyPHdHm/mbR+cfk08xz0Py/tErATeP
# zFX2Nj5ivBd17T5rOSfuDqXB2LVThB6Z6c7UvSAb0Z/zmh+y55QCelXMOWE0FWng
# WU+3jcUzrLlZz8vUzKlp2/W8PVkU5aGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCACrWOSJFwRC0DvKD9mXT7TNGBKCDrS3wkwvJxWbCHoAwIGaPCDIpZI
# GBMyMDI1MTExMDE3MTcwMS45NjlaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgpHshTZ7rKzDwABAAACCjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTdaFw0yNjA0MjIxOTQyNTdaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCy7NzwEpb7BpwAk9LJ00Xq30TcTjcwNZ80TxAtAbhS
# aJ2kwnJA1Au/Do9/fEBjAHv6Mmtt3fmPDeIJnQ7VBeIq8RcfjcjrbPIg3wA5v5MQ
# flPNSBNOvcXRP+fZnAy0ELDzfnJHnCkZNsQUZ7GF7LxULTKOYY2YJw4TrmcHohkY
# 6DjCZyxhqmGQwwdbjoPWRbYu/ozFem/yfJPyjVBql1068bcVh58A8c5CD6TWN/L3
# u+Ny+7O8+Dver6qBT44Ey7pfPZMZ1Hi7yvCLv5LGzSB6o2OD5GIZy7z4kh8UYHdz
# jn9Wx+QZ2233SJQKtZhpI7uHf3oMTg0zanQfz7mgudefmGBrQEg1ox3n+3Tizh0D
# 9zVmNQP9sFjsPQtNGZ9ID9H8A+kFInx4mrSxA2SyGMOQcxlGM30ktIKM3iqCuFEU
# 9CHVMpN94/1fl4T6PonJ+/oWJqFlatYuMKv2Z8uiprnFcAxCpOsDIVBO9K1vHeAM
# iQQUlcE9CD536I1YLnmO2qHagPPmXhdOGrHUnCUtop21elukHh75q/5zH+OnNekp
# 5udpjQNZCviYAZdHsLnkU0NfUAr6r1UqDcSq1yf5RiwimB8SjsdmHll4gPjmqVi0
# /rmnM1oAEQm3PyWcTQQibYLiuKN7Y4io5bJTVwm+vRRbpJ5UL/D33C//7qnHbeoW
# BQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFAKvF0EEj4AyPfY8W/qrsAvftZwkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCwk3PW0CyjOaqXCMOusTde7ep2CwP/xV1J
# 3o9KAiKSdq8a2UR5RCHYhnJseemweMUH2kNefpnAh2Bn8H2opDztDJkj8OYRd/KQ
# ysE12NwaY3KOwAW8Rg8OdXv5fUZIsOWgprkCQM0VoFHdXYExkJN3EzBbUCUw3yb4
# gAFPK56T+6cPpI8MJLJCQXHNMgti2QZhX9KkfRAffFYMFcpsbI+oziC5Brrk3361
# cJFHhgEJR0J42nqZTGSgUpDGHSZARGqNcAV5h+OQDLeF2p3URx/P6McUg1nJ2gMP
# YBsD+bwd9B0c/XIZ9Mt3ujlELPpkijjCdSZxhzu2M3SZWJr57uY+FC+LspvIOH1O
# pofanh3JGDosNcAEu9yUMWKsEBMngD6VWQSQYZ6X9F80zCoeZwTq0i9AujnYzzx5
# W2fEgZejRu6K1GCASmztNlYJlACjqafWRofTqkJhV/J2v97X3ruDvfpuOuQoUtVA
# wXrDsG2NOBuvVso5KdW54hBSsz/4+ORB4qLnq4/GNtajUHorKRKHGOgFo8DKaXG+
# UNANwhGNxHbILSa59PxExMgCjBRP3828yGKsquSEzzLNWnz5af9ZmeH4809fwItt
# I41JkuiY9X6hmMmLYv8OY34vvOK+zyxkS+9BULVAP6gt+yaHaBlrln8Gi4/dBr2y
# 6Srr/56g0DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjM3MDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDR
# AMVJlA6bKq93Vnu3UkJgm5HlYaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7Lvz3TAiGA8yMDI1MTExMDA1MTcx
# N1oYDzIwMjUxMTExMDUxNzE3WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsu/Pd
# AgEAMAoCAQACAkSWAgH/MAcCAQACAhINMAoCBQDsvUVdAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAJXajAutAHA9mPQ6smdRG/3VuwTOcpL2IrCu8urQlgrY
# FVOvJDfCeJ1QM6cdtYWUaDSkKaVtb4jYS4FCpmQ7G9mdlOMOuA9hZA4q6BgWeFL3
# oDbowt845w1fggf2VO/LlNBxHDtgm15cYYad0E6ne0s6dIwLjZx42LWyXZ9K3Xfr
# aakiUPLeehFCFXLe/7d2/IosTAwQS9WfP5VQp5qJ/JKpzX6uggO8DOLX5EGKhEBt
# MB9J5NwiQixx9O4rT4zbXRhc2s3bOclQrcDJANAdNyDMaKiievyzHRPx7N3wt3YI
# yB+P/QcH0EYn0JP3spx0/yRocM3WqDxTCUyrJmrApdcxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgpHshTZ7rKzDwABAAAC
# CjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCDaHAlYrkARXS9mCxSi+OmwqCjMqAOszjZGJoWGiCCs
# dzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIE2ay/y0epK/X3Z03KTcloqE
# 8u9IXRtdO7Mex0hw9+SaMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIKR7IU2e6ysw8AAQAAAgowIgQgl7M7lF6SJNEDfsIAyNIJMwba
# dk3UE3kNzaUgIEBT6kkwDQYJKoZIhvcNAQELBQAEggIAXZkwFNnh0CrF0/Eua/3V
# 9NKdxodJBuDOPAJt1gyMA3cazhDV6Tc0wvi10xGyPW1Nv1bRK5F950eLjEfDR+Uj
# cw69DLiQr5Tf5OJr5l8R7Ms7tOKzPiWdduFyfDqZF9JEosg2r24zM9Ru00MRF8cn
# VRQ7U9c5TVdbWO+YQUrzooNHDwZAwO0vGuIzY25rG8sExStO5GhQyEPok7vdgMEd
# ncndtJaepIpBCBpIg44PRv3sENkdKiOk+qGAY6vSYdwRbXCgca/3iQSUpkozr9uu
# DSp2tZvwT4yhKugTV/NLXRICXlsHL3tGtBr9l/uWbTM7EILkrXoWvFVaAEuWCnhO
# snX5HlENxuLIwvlT7SKJe9NL/0YuIXcFQw04nPGJykQioSYba17389RqBGSaUgnV
# KhbJfF6/w4hU1FdibvNtFox9mLI187nBrbR1qgeB8UhPnLk97DB7s1IFMxgpf7hE
# FDZWLVN64JsEm1MMijKX6cCNhWgJkJzr4ThJvzjoyDWqBcW+KgtcQlW89mlL4rxx
# HTAIPYFH4jjpoLaXz78allem78cXA3B94N2RT+GonqVjrxNVzMr7ZY1XR8mXFDFm
# w81cqcSkRuC2EcQPfXxl5hwM/DIIcCakIjEl46Egli6beB1Tep+S8l7rSvG61QdM
# bcNIFwn6cA66gWIEFL9v8EQ=
# SIG # End signature block
