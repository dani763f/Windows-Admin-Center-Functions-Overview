function Export-WACCMCertificate {
<#

.SYNOPSIS
Script that exports certificate.

.DESCRIPTION
Script that exports certificate.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $fromTaskScheduler,
    [Parameter(Mandatory = $true)]
    [String]
    $certPath,
    [Parameter(Mandatory = $true)]
    [String]
    $exportType,
    [String]
    $fileName,
    [String]
    $exportChain,
    [String]
    $exportProperties,
    [String]
    $usersAndGroups,
    [String]
    $password,
    [String]
    $tempPath,
    [String]
    $resultFile,
    [String]
    $errorFile
)

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name WaitTimeOut -Option ReadOnly -Value 30000 -Scope Script -ErrorAction SilentlyContinue        # 30 second timeout
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Export-Certificate.ps1" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name RsaProviderInstanceName -Option ReadOnly -Value "RSA" -Scope Script -ErrorAction SilentlyContinue
}
PROCESS {
    <#

    .SYNOPSIS
    Helper function to write the info logs to info stream.

    .DESCRIPTION
    Helper function to write the info logs to info stream.

    .PARAMETER logMessage
    log message

    #>

    function writeInfoLog($logMessage) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
            -Message $logMessage -ErrorAction SilentlyContinue
    }

    <#

    .SYNOPSIS
    Helper function to write the info logs to info stream.

    .DESCRIPTION
    Helper function to write the info logs to info stream.

    .PARAMETER logMessage
    log message

    #>

    function writeErrorLog($errorMessage) {
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message $errorMessage -ErrorAction SilentlyContinue
    }

    function exportCertificate() {
        param (
            [String]
            $certPath,
            [String]
            $tempPath,
            [String]
            $exportType,
            [String]
            $exportChain,
            [String]
            $exportProperties,
            [String]
            $usersAndGroups,
            [String]
            $password,
            [String]
            $resultFile,
            [String]
            $errorFile
        )
        try {
            Import-Module PKI
            if ($exportChain -eq "CertificateChain") {
                $chainOption = "BuildChain";
            }
            else {
                $chainOption = "EndEntityCertOnly";
            }

            $ExportPfxCertParams = @{ Cert = $certPath; FilePath = $tempPath; ChainOption = $chainOption }
            if ($exportProperties -ne "Extended") {
                $ExportPfxCertParams.NoProperties = $true
            }

            # Decrypt user encrypted password
            if ($password) {
                Add-Type -AssemblyName System.Security
                $encode = New-Object System.Text.UTF8Encoding
                $encrypted = [System.Convert]::FromBase64String($password)
                $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                $newPassword = $encode.GetString($decrypted)
                $securePassword = ConvertTo-SecureString -String $newPassword -Force -AsPlainText;
                $ExportPfxCertParams.Password = $securePassword
            }

            if ($usersAndGroups) {
                $ExportPfxCertParams.ProtectTo = $usersAndGroups
            }

            Export-PfxCertificate @ExportPfxCertParams | ConvertTo-Json -Depth 10 | Out-File $ResultFile
        }
        catch {
            $_.Exception.Message | ConvertTo-Json | Out-File $ErrorFile
        }
    }

    function CalculateFilePath {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $exportType,
            [Parameter(Mandatory = $true)]
            [String]
            $certPath
        )

        $extension = $exportType.ToLower();
        if ($exportType -ieq "cert") {
            $extension = "cer";
        }

        if (!$fileName) {
            try {
                $fileName = [IO.Path]::GetFileName($certPath);
            }
            catch {
                $err = $_.Exception.Message
                writeErrorLog "An error occured attempting to extract file name from certificate path. Exception: $err"
                throw $err
            }
        }

        try {
            $path = Join-Path $env:TEMP ([IO.Path]::ChangeExtension($filename, $extension))
        }
        catch {
            $err = $_.Exception.Message
            writeErrorLog "An error occured attempting to join file name to file extension. Exception: $err"
            throw $err
        }

        writeInfoLog "Calculated file name: $fileName."
        return $path
    }

    function DecryptPasswordWithJWKOnNode($encryptedJWKPassword) {
        if (Get-Variable -Scope Script -Name $RsaProviderInstanceName -ErrorAction SilentlyContinue) {
            $rsaProvider = (Get-Variable -Scope Script -Name $RsaProviderInstanceName).Value
            $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedJWKPassword), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)

            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }
        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Password decryption failed. RSACryptoServiceProvider Instance not found" -ErrorAction SilentlyContinue
        # TODO: Localize this message!
        throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
    }

    ###########################################################################
    # Script execution starts here
    ###########################################################################

    $tempPath = CalculateFilePath -exportType $exportType -certPath $certPath;
    if ($exportType -ne "Pfx") {
        Export-Certificate -Cert $certPath -FilePath $tempPath -Type $exportType -Force
        return;
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::new()

    function isSystemLockdownPolicyEnforced() {
        return [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -eq [System.Management.Automation.Security.SystemEnforcementMode]::Enforce
    }
    $isWdacEnforced = isSystemLockdownPolicyEnforced;

    # In WDAC environment script file will already be available on the machine
    # In WDAC mode the same script is executed - once normally and once through task Scheduler
    if ($isWdacEnforced) {
        if ($fromTaskScheduler) {
            exportCertificate $certPath $tempPath $exportType $exportChain $exportProperties $usersAndGroups $password $resultFile $errorFile;
            return;
        }
    }
    else {
        # In non-WDAC environment script file will not be available on the machine
        # Hence, a dynamic script is created which is executed through the task Scheduler
        $ScriptFile = $env:temp + "\export-certificate.ps1"
    }

    # PFX private key handlings
    if ($password) {
        $decryptedJWKPassword = DecryptPasswordWithJWKOnNode $password
        # encrypt password with current user.
        Add-Type -AssemblyName System.Security
        $encode = New-Object System.Text.UTF8Encoding
        $bytes = $encode.GetBytes($decryptedJWKPassword)
        $encrypt = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $userEncryptedPassword = [System.Convert]::ToBase64String($encrypt)
    }

    # Pass parameters to script and generate script file in temp folder
    $resultFile = $env:temp + "\export-certificate_result.json"
    $errorFile = $env:temp + "\export-certificate_error.json"
    if (Test-Path $errorFile) {
        Remove-Item $errorFile
    }

    if (Test-Path $resultFile) {
        Remove-Item $resultFile
    }

    # Create a scheduled task
    $TaskName = "SMEExportCertificate"
    $User = [Security.Principal.WindowsIdentity]::GetCurrent()

    $HashArguments = @{};
    if ($exportChain) {
        $HashArguments.Add("exportChain", $exportChain)
    }

    if ($exportProperties) {
        $HashArguments.Add("exportProperties", $exportProperties)
    }

    if ($usersAndGroups) {
        $HashArguments.Add("usersAndGroups", $usersAndGroups)
    }

    if ($userEncryptedPassword) {
        $HashArguments.Add("password", $userEncryptedPassword)
    }

    $tempArgs = ""
    foreach ($key in $HashArguments.Keys) {
        $value = $HashArguments[$key]
        $value = """$value"""
        $tempArgs += " -$key $value"
    }

    if ($isWdacEnforced) {
        $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.CertificateManager; Export-WACCMCertificate -fromTaskScheduler `$true -exportType $exportType $tempArgs -certPath $certPath -tempPath $tempPath -resultFile $resultFile -errorFile $errorFile}"""
    }
    else {
        (Get-Command exportCertificate).ScriptBlock | Set-Content -Path $ScriptFile
        $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile -certPath $certPath -exportType $exportType $tempArgs -tempPath $tempPath -resultFile $resultFile -errorFile $errorFile"
    }

    if ($null -eq (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
    }

    $Scheduler = New-Object -ComObject Schedule.Service

    # Try to connect to schedule service 3 time since it may fail the first time
    for ($i = 1; $i -le 3; $i++) {
        try {
            $Scheduler.Connect()
            Break
        }
        catch {
            if ($i -ge 3) {
                $message = $_.Exception.Message
                writeErrorLog $message
                Write-Error $message -ErrorAction Stop
            }
            else {
                Start-Sleep -s 1
            }
        }
    }

    $RootFolder = $Scheduler.GetFolder("\")
    # Delete existing task
    if ($RootFolder.GetTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
        Write-Debug("Deleting existing task" + $TaskName)
        $RootFolder.DeleteTask($TaskName, 0)
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

    # Tasks will be run with the highest privileges
    $Task.Principal.RunLevel = 1
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null

    # Wait for running task finished
    $stopWatch.Start()
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while ($Scheduler.GetRunningTasks(0) | Where-Object { $_.Name -eq $TaskName }) {
        Start-Sleep -s 2

        $now = $stopWatch.Elapsed.Milliseconds
        if ($now -ge $WaitTimeOut) {
            $message = 'Timed out waiting for the the scheduled task that exports the certificate to complete.'

            writeErrorLog $message
            throw $message
        }
    }

    # Clean up
    $RootFolder.DeleteTask($TaskName, 0)
    if (!$isWdacEnforced) {
        Remove-Item $ScriptFile
    }

    if (Test-Path $ErrorFile) {
        $result = Get-Content -Raw -Path $ErrorFile | ConvertFrom-Json
        Remove-Item $ErrorFile
        Remove-Item $ResultFile
        throw $result
    }

    # Return result
    if (Test-Path $ResultFile) {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }
}
END {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name WaitTimeOut -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name RsaProviderInstanceName -Scope Script -Force
}

}
## [END] Export-WACCMCertificate ##
function Get-WACCMCertificateOverview {
<#

.SYNOPSIS
Script that get the certificates overview (total, ex) in the system.

.DESCRIPTION
Script that get the certificates overview (total, ex) in the system.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $EventChannels,
    [String]
    $CertificatePath = "Cert:\",
    [int]
    $NearlyExpiredThresholdInDays = 60
)

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue

    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script -ErrorAction SilentlyContinue
}
PROCESS {
    # Notes: $channelList must be in this format:
    # "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*,
    # Microsoft-Windows-CertificateServices-Deployment*,
    # Microsoft-Windows-CertificateServicesClient-CredentialRoaming*,
    # Microsoft-Windows-CertificateServicesClient-Lifecycle-User*,
    # Microsoft-Windows-CAPI2*,Microsoft-Windows-CertPoleEng*"

    function Get-ChildLeafRecurse($psPath) {
        try {
            Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object NotAfter, PSIsContainer, Location, PSChildName | ForEach-Object {
                if (!$_.PSIsContainer) {
                    $_
                }
                else {
                    $location = "Cert:\$($_.Location)"

                    if ($_.psChildName -ne $_.Location) {
                        $location += "\$($_.PSChildName)"
                    }

                    Get-ChildLeafRecurse $location
                }
            } | Microsoft.PowerShell.Utility\Select-Object NotAfter
        }
        catch [System.ComponentModel.Win32Exception] {
            # When running this script remotely/non-elevated at least one store 'Cert:\CurrentUser\UserDS' cannot be
            # opened and traversed.  Logging an info record in case we ever need to investigate further.  An Error
            # record would be too chatty since this happens almost every time we run this script remotely/non-elevated.
            $message = "Error: '$_' for certificate store $location"
            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
                -Message $message -ErrorAction SilentlyContinue
        }
    }

    function main([String] $eventChannels, [String] $path, [int] $earlyExpiredThresholdInDays) {
        $stopwatch = [System.Diagnostics.Stopwatch]::new()

        $payload = New-Object -TypeName psobject

        $stopwatch.Start()
        $certs = Get-ChildLeafRecurse -pspath $path
        $stopwatch.Stop()
        $queryTime = $stopwatch.Elapsed.TotalMilliseconds

        $stopwatch.Restart()

        $expiredCount = @($certs | Where-Object { $_.NotAfter -lt [DateTime]::Now })
        $nearlyExpiredCount = @($certs | Where-Object { ($_.NotAfter -gt [DateTime]::Now ) -and ($_.NotAfter -lt [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays) ) })

        $channelList = @($eventChannels.split(","))
        $eventCount = 0
        Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object RecordCount | ForEach-Object {
            $eventCount += $_.RecordCount
        }

        $payload | add-member -Name "total" -Value $certs.length -MemberType NoteProperty
        $payload | add-member -Name "expired" -Value $expiredCount.length -MemberType NoteProperty
        $payload | add-member -Name "nearlyExpired" -Value $nearlyExpiredCount.length -MemberType NoteProperty
        $payload | add-member -Name "eventCount" -Value $eventCount -MemberType NoteProperty

        $stopwatch.Stop()
        $totalTime = $queryTime + $stopwatch.Elapsed.TotalMilliseconds

        $payload | add-member -Name "certQueryTime" -Value "$queryTime ms" -MemberType NoteProperty
        $payload | add-member -Name "totalTimeInScript" -Value "$totalTime ms" -MemberType NoteProperty

        return $payload
    }

    ###########################################################################
    # Script execution start here
    ###########################################################################

    return main $EventChannels $CertificatePath $NearlyExpiredThresholdInDays
}
END {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
}
}
## [END] Get-WACCMCertificateOverview ##
function Get-WACCMCertificateScopes {
<#

.SYNOPSIS
Script that enumerates all the certificate scopes/locations in the system.

.DESCRIPTION
Script that enumerates all the certificate scopes/locations in the system.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Get-ChildItem | Microsoft.PowerShell.Utility\Select-Object -Property @{name ="Name";expression= {$($_.LocationName)}}


}
## [END] Get-WACCMCertificateScopes ##
function Get-WACCMCertificateStores {
<#

.SYNOPSIS
Script that enumerates all the certificate stores in the system inside the scope/location.

.DESCRIPTION
Script that enumerates all the certificate stores in the system inside the scope/location.

.ROLE
Readers

#>

Param([string]$scope)

Set-StrictMode -Version 5.0

Get-ChildItem $('Cert:' + $scope) | Microsoft.PowerShell.Utility\Select-Object Name, @{name ="Path";expression= {$($_.Location.toString() + '\' + $_.Name)}}

}
## [END] Get-WACCMCertificateStores ##
function Get-WACCMCertificates {
<#

.SYNOPSIS
Script that enumerates all the certificates in the system.

.DESCRIPTION
Script that enumerates all the certificates in the system.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $path,
    [int]
    $nearlyExpiredThresholdInDays = 60
)

Set-StrictMode -Version 5.0

<#
.Synopsis
    Name: GetChildLeafRecurse
    Description: Recursively enumerates each scope and store in Cert:\ drive.

.Parameters
    $pspath: The initial pspath to use for creating whole path to certificate store.

.Returns
    The constructed ps-path object.
#>
function GetChildLeafRecurse {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $pspath
    )
    try {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue | ForEach-Object {
            if (!$_.PSIsContainer) {
                $_
            }
            else {
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location) {
                    $location += "\$($_.PSChildName)";
                }

                GetChildLeafRecurse $location
            }
        }
    }
    catch {}
}

<#
.Synopsis
    Name: ComputePublicKey
    Description: Computes public key algorithm and public key parameters

.Parameters
    $cert: The original certificate object.

.Returns
    A hashtable object of public key algorithm and public key parameters.
#>
function ComputePublicKey {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $publicKeyInfo = @{}

    $publicKeyInfo["PublicKeyAlgorithm"] = ""
    $publicKeyInfo["PublicKeyParameters"] = ""

    if ($cert.PublicKey) {
        $publicKeyInfo["PublicKeyAlgorithm"] = $cert.PublicKey.Oid.FriendlyName
        $publicKeyInfo["PublicKeyParameters"] = $cert.PublicKey.EncodedParameters.Format($true)
    }

    $publicKeyInfo
}

<#
.Synopsis
    Name: ComputeSignatureAlgorithm
    Description: Computes signature algorithm out of original certificate object.

.Parameters
    $cert: The original certificate object.

.Returns
    The signature algorithm friendly name.
#>
function ComputeSignatureAlgorithm {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $signatureAlgorithm = [System.String]::Empty

    if ($cert.SignatureAlgorithm) {
        $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
    }

    $signatureAlgorithm
}

<#
.Synopsis
    Name: ComputePrivateKeyStatus
    Description: Computes private key exportable status.
.Parameters
    $hasPrivateKey: A flag indicating certificate has a private key or not.
    $canExportPrivateKey: A flag indicating whether certificate can export a private key.

.Returns
    Enum values "Exported" or "NotExported"
#>
function ComputePrivateKeyStatus {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $hasPrivateKey,

        [Parameter(Mandatory = $true)]
        [bool]
        $canExportPrivateKey
    )

    if (-not ($hasPrivateKey)) {
        $privateKeystatus = "None"
    }
    else {
        if ($canExportPrivateKey) {
            $privateKeystatus = "Exportable"
        }
        else {
            $privateKeystatus = "NotExportable"
        }
    }

    $privateKeystatus
}

<#
.Synopsis
    Name: ComputeExpirationStatus
    Description: Computes expiration status based on notAfter date.
.Parameters
    $notAfter: A date object refering to certificate expiry date.

.Returns
    Enum values "Expired", "NearlyExpired" and "Healthy"
#>
function ComputeExpirationStatus {
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

<#
.Synopsis
    Name: ComputeArchivedStatus
    Description: Computes archived status of certificate.
.Parameters
    $archived: A flag to represent archived status.

.Returns
    Enum values "Archived" and "NotArchived"
#>
function ComputeArchivedStatus {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $archived
    )

    if ($archived) {
        $archivedStatus = "Archived"
    }
    else {
        $archivedStatus = "NotArchived"
    }

    $archivedStatus
}

<#
.Synopsis
    Name: ComputeIssuedTo
    Description: Computes issued to field out of the certificate subject.
.Parameters
    $subject: Full subject string of the certificate.

.Returns
    Issued To authority name.
#>
function ComputeIssuedTo {
    param (
        [String]
        $subject
    )

    $issuedTo = [String]::Empty

    $issuedToRegex = "CN=(?<issuedTo>[^,?]+)"
    $matched = $subject -match $issuedToRegex

    if ($matched -and $Matches) {
        $issuedTo = $Matches["issuedTo"]
    }

    $issuedTo
}

<#
.Synopsis
    Name: ComputeIssuerName
    Description: Computes issuer name of certificate.
.Parameters
    $cert: The original cert object.

.Returns
    The Issuer authority name.
#>
function ComputeIssuerName {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $issuerName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)

    $issuerName
}

<#
.Synopsis
    Name: ComputeCertificateName
    Description: Computes certificate name of certificate.
.Parameters
    $cert: The original cert object.

.Returns
    The certificate name.
#>
function ComputeCertificateName {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if (!$certificateName) {
        $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    }

    $certificateName
}

<#
.Synopsis
    Name: ComputeStore
    Description: Computes certificate store name.
.Parameters
    $pspath: The full certificate ps path of the certificate.

.Returns
    The certificate store name.
#>
function ComputeStore {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $pspath
    )

    $pspath.Split('\')[2]
}

<#
.Synopsis
    Name: ComputeScope
    Description: Computes certificate scope/location name.
.Parameters
    $pspath: The full certificate ps path of the certificate.

.Returns
    The certificate scope/location name.
#>
function ComputeScope {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $pspath
    )

    $pspath.Split('\')[1].Split(':')[2]
}

<#
.Synopsis
    Name: ComputePath
    Description: Computes certificate path. E.g. CurrentUser\My\<thumbprint>
.Parameters
    $pspath: The full certificate ps path of the certificate.

.Returns
    The certificate path.
#>
function ComputePath {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $pspath
    )

    $pspath.Split(':')[2]
}


<#
.Synopsis
    Name: EnhancedKeyUsageList
    Description: Enhanced KeyUsage
.Parameters
    $cert: The original cert object.

.Returns
    Enhanced Key Usage.
#>
function EnhancedKeyUsageList {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $usageString = ''
    foreach ( $usage in $cert.EnhancedKeyUsageList) {
        $usageString = $usageString + $usage.FriendlyName + ' ' + $usage.ObjectId + "`n"
    }

    $usageString
}

<#
.Synopsis
    Name: ComputeTemplate
    Description: Compute template infomation of a certificate
    $certObject: The original certificate object.

.Returns
    The certificate template if there is one otherwise empty string
#>
function ComputeTemplate {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    $template = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -match "Template" }
    if ($template) {
        $name = $template.Format(1).split('(')[0]
        if ($name) {
            $name -replace "Template="
        }
        else {
            ''
        }
    }
    else {
        ''
    }
}

<#
.Synopsis
    Name: ExtractCertInfo
    Description: Extracts certificate info by decoding different field and create a custom object.
.Parameters
    $certObject: The original certificate object.

.Returns
    The custom object for certificate.
#>
function ExtractCertInfo {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $certObject,
        [Parameter(Mandatory = $true)]
        [boolean]
        $hasPrivateKey,
        [Parameter(Mandatory = $true)]
        [boolean]
        $canExportPrivateKey
    )

    $publicKeyInfo = $(ComputePublicKey $certObject)
    return @{
        Archived            = $(ComputeArchivedStatus $certObject.Archived)
        CertificateName     = $(ComputeCertificateName $certObject)

        EnhancedKeyUsage    = $(EnhancedKeyUsageList $certObject)
        FriendlyName        = $certObject.FriendlyName
        IssuerName          = $(ComputeIssuerName $certObject)
        IssuedTo            = $(ComputeIssuedTo $certObject.Subject)
        Issuer              = $certObject.Issuer

        NotAfter            = $certObject.NotAfter
        NotBefore           = $certObject.NotBefore

        Path                = $(ComputePath  $certObject.PsPath)
        PrivateKey          = $(ComputePrivateKeyStatus -hasPrivateKey $hasPrivateKey -canExportPrivateKey  $canExportPrivateKey)
        PublicKey           = $publicKeyInfo.PublicKeyAlgorithm
        PublicKeyParameters = $publicKeyInfo.PublicKeyParameters

        Scope               = $(ComputeScope  $certObject.PsPath)
        Store               = $(ComputeStore  $certObject.PsPath)
        SerialNumber        = $certObject.SerialNumber
        Subject             = $certObject.Subject
        Status              = $(ComputeExpirationStatus $certObject.NotAfter)
        SignatureAlgorithm  = $(ComputeSignatureAlgorithm $certObject)

        Thumbprint          = $certObject.Thumbprint
        Version             = $certObject.Version

        Template            = $(ComputeTemplate $certObject)
    }
}

###############################################################################
# Script execution starts here
###############################################################################

GetChildLeafRecurse $path | ForEach-Object {
    $canExportPrivateKey = $false

    if ($_.HasPrivateKey) {
        [System.Security.Cryptography.CspParameters] $cspParams = new-object System.Security.Cryptography.CspParameters
        $contextField = $_.GetType().GetField("m_safeCertContext", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
        $privateKeyMethod = $_.GetType().GetMethod("GetPrivateKeyInfo", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)

        if ($contextField -and $privateKeyMethod) {
            $contextValue = $contextField.GetValue($_)
            $privateKeyInfoAvailable = $privateKeyMethod.Invoke($_, @($ContextValue, $cspParams))

            if ($privateKeyInfoAvailable) {
                $csp = new-object System.Security.Cryptography.CspKeyContainerInfo -ArgumentList @($cspParams)

                if ($csp.Exportable) {
                    $canExportPrivateKey = $true
                }
            }
        }
        else {
            $canExportPrivateKey = $true
        }
    }

    ExtractCertInfo $_ $_.HasPrivateKey $canExportPrivateKey
}

}
## [END] Get-WACCMCertificates ##
function Get-WACCMCertificatesForStore {
<#

.SYNOPSIS
Script that enumerates all the certificate scopes/locations in the system.

.DESCRIPTION
Script that enumerates all the certificate scopes/locations in the system.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $certificatesStorePath
)

Set-StrictMode -Version 5.0

$treeNodes = @()

$treeNodes = @(Get-ChildItem  $certificatesStorePath | `
    Microsoft.PowerShell.Utility\Select-Object Name, @{name="Path"; expression={$($_.Location.toString() + '\' + $_.Name)}})

$treeNodes

}
## [END] Get-WACCMCertificatesForStore ##
function Get-WACCMTempFolder {
<#

.SYNOPSIS
Script that gets temp folder based on the target node.

.DESCRIPTION
Script that gets temp folder based on the target node.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"}

}
## [END] Get-WACCMTempFolder ##
function Import-WACCMCertificate {
<#

.SYNOPSIS
Script that imports certificate.

.DESCRIPTION
Script that imports certificate.

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [boolean]
    $fromTaskScheduler,
    [Parameter(Mandatory = $true)]
    [String]
    $storePath,
    [Parameter(Mandatory = $true)]
    [String]
    $filePath,
    [string]
    $exportable,
    [String]
    $password,
    [String]
    $resultFile,
    [String]
    $errorFile
)

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

    Set-Variable -Name WaitTimeOut -Option ReadOnly -Value 30000 -Scope Script -ErrorAction SilentlyContinue        # 30 second timeout
    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Import-Certificate.ps1" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name RsaProviderInstanceName -Option ReadOnly -Value "RSA" -Scope Script -ErrorAction SilentlyContinue
}
PROCESS {
    function importCertificate() {
        param (
            [String]
            $storePath,
            [String]
            $filePath,
            [string]
            $exportable,
            [string]
            $password,
            [String]
            $resultFile,
            [String]
            $errorFile
        )

        try {
            Import-Module PKI
            $params = @{ CertStoreLocation = $storePath; FilePath = $filePath }
            if ($password) {
                Add-Type -AssemblyName System.Security
                $encode = New-Object System.Text.UTF8Encoding
                $encrypted = [System.Convert]::FromBase64String($password)
                $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                $newPassword = $encode.GetString($decrypted)
                $securePassword = ConvertTo-SecureString -String $newPassword -Force -AsPlainText
                $params.Password = $securePassword
            }

            if ($exportable -eq "Export") {
                $params.Exportable = $true;
            }

            Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Information `
                -Message "[$ScriptName]: Calling ImportPfx Certificate" -ErrorAction SilentlyContinue

            Import-PfxCertificate @params | ConvertTo-Json | Out-File $ResultFile
        }
        catch {
            $_.Exception.Message | ConvertTo-Json | Out-File $ErrorFile
        }
    }

    function DecryptPasswordWithJWKOnNode($encryptedJWKPassword) {
        if (Get-Variable -Scope Global -Name $RsaProviderInstanceName -ErrorAction SilentlyContinue) {
            $rsaProvider = (Get-Variable -Scope Global -Name $RsaProviderInstanceName).Value
            $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedJWKPassword), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)

            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Password decryption failed. RSACryptoServiceProvider Instance not found" -ErrorAction SilentlyContinue

        # TODO: Localize this message!
        throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
    }

    ###########################################################################
    # Script execution starts here
    ###########################################################################

    if ([System.IO.Path]::GetExtension($filePath) -ne ".pfx") {
        Import-Module PKI
        Import-Certificate -CertStoreLocation $storePath -FilePath $filePath
        return;
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::new()

    function isSystemLockdownPolicyEnforced() {
        return [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -eq [System.Management.Automation.Security.SystemEnforcementMode]::Enforce
    }
    $isWdacEnforced = isSystemLockdownPolicyEnforced;

    #In WDAC environment script file will already be available on the machine
    #In WDAC mode the same script is executed - once normally and once through task Scheduler
    if ($isWdacEnforced) {
        if ($fromTaskScheduler) {
            importCertificate $storePath $filePath $exportable $password $resultFile $errorFile;
            return;
        }
    }
    else {
        #In non-WDAC environment script file will not be available on the machine
        #Hence, a dynamic script is created which is executed through the task Scheduler
        $ScriptFile = $env:temp + "\import-certificate.ps1"
    }

    # PFX private key handlings
    if ($password) {
        $decryptedJWKPassword = DecryptPasswordWithJWKOnNode $password
        # encrypt password with current user.
        Add-Type -AssemblyName System.Security
        $encode = New-Object System.Text.UTF8Encoding
        $bytes = $encode.GetBytes($decryptedJWKPassword)
        $encrypt = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $userEncryptedPassword = [System.Convert]::ToBase64String($encrypt)
    }

    # Pass parameters to script and generate script file in temp folder
    $resultFile = $env:temp + "\import-certificate_result.json"
    $errorFile = $env:temp + "\import-certificate_error.json"
    if (Test-Path $errorFile) {
        Remove-Item $errorFile
    }

    if (Test-Path $resultFile) {
        Remove-Item $resultFile
    }

    # Create a scheduled task
    $TaskName = "SMEImportCertificate"

    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $HashArguments = @{};

    if ($exportable) {
        $HashArguments.Add("exportable", $exportable)
    }
    if ($userEncryptedPassword) {
        $HashArguments.Add("password", $userEncryptedPassword)
    }

    $tempArgs = ""
    foreach ($key in $HashArguments.Keys) {
        $value = $HashArguments[$key]
        $value = """$value"""
        $tempArgs += " -$key $value"
    }

    if ($isWdacEnforced) {
        $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -command ""&{Import-Module Microsoft.SME.CertificateManager; Import-WACCMCertificate -fromTaskScheduler `$true -storePath $storePath $tempArgs -filePath $filePath -resultFile $resultFile -errorFile $errorFile}"""
    }
    else {
    (Get-Command importCertificate).ScriptBlock | Set-Content -Path $ScriptFile
        $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile -storePath $storePath $tempArgs -filePath $filePath -resultFile $resultFile -errorFile $errorFile"
    }

    if ($null -eq (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
    }

    $Scheduler = New-Object -ComObject Schedule.Service

    #Try to connect to schedule service 3 time since it may fail the first time
    for ($i = 1; $i -le 3; $i++) {
        try {
            $Scheduler.Connect()
            Break
        }
        catch {
            if ($i -ge 3) {
                $message = $_.Exception.Message

                Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                    -Message "[$ScriptName]:Can't connect to Schedule service. Error: $message"  -ErrorAction SilentlyContinue
                Write-Error $message -ErrorAction Stop
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
        $RootFolder.DeleteTask($TaskName, 0)
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

    # Start the task with SYSTEM creds
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
    $RootFolder.DeleteTask($TaskName, 0)
    $stopWatch.Start()
    if (!$isWdacEnforced) {
        Remove-Item $ScriptFile
    }

    $now = $stopWatch.Elapsed.Milliseconds
    if ($now -ge $WaitTimeOut) {
        $message = 'Timed out waiting for the the scheduled task that exports the certificate to complete.'

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]:$message"  -ErrorAction SilentlyContinue

        throw $message
    }

    if (Test-Path $ErrorFile) {
        $result = Get-Content -Raw -Path $ErrorFile | ConvertFrom-Json
        Remove-Item $ErrorFile
        Remove-Item $ResultFile
        throw $result
    }

    #Return result
    if (Test-Path $ResultFile) {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }
}
END {
    Remove-Variable -Name WaitTimeOut -Scope Script -Force
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name ScriptName -Scope Script -Force
    Remove-Variable -Name RsaProviderInstanceName -Scope Script -Force
}

}
## [END] Import-WACCMCertificate ##
function Remove-WACCMCertificate {
 <#

.SYNOPSIS
Script that deletes certificate.

.DESCRIPTION
Script that deletes certificate.

.ROLE
Administrators

#>

 param (
    [Parameter(Mandatory = $true)]
    [string]
    $thumbprintPath
    )

Set-StrictMode -Version 5.0

Get-ChildItem $thumbprintPath | Remove-Item

}
## [END] Remove-WACCMCertificate ##
function Remove-WACCMItemByPath {
<#

.SYNOPSIS
Script that deletes certificate based on the path.

.DESCRIPTION
Script that deletes certificate based on the path.

.ROLE
Administrators

#>

 Param(
    [Parameter(Mandatory = $true)]
    [string]
    $path
    )

Set-StrictMode -Version 5.0

Remove-Item -Path $path;

}
## [END] Remove-WACCMItemByPath ##
function Update-WACCMCertificate {
<#

.SYNOPSIS
Renew Certificate

.DESCRIPTION
Renew Certificate

.ROLE
Administrators

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificatePath,
    [Parameter(Mandatory = $true)]
    [Boolean]
    $UseSameCertificateKey,
    [Parameter(Mandatory = $true)]
    [String]
    $UserName,
    [Parameter(Mandatory = $true)]
    [String]
    $Password
)

BEGIN {
    Set-StrictMode -Version 5.0

    Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

    Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name rsaProviderInstanceName -Option ReadOnly -Value "RSA" -Scope Script -ErrorAction SilentlyContinue
    Set-Variable -Name ScriptName -Option ReadOnly -Value "Update-Certificate.ps1" -Scope Script -ErrorAction SilentlyContinue
}
PROCESS {
    function DecryptDataWithJWKOnNode($encryptedData) {
        if (Get-Variable -Scope Global -Name $rsaProviderInstanceName -ErrorAction SilentlyContinue) {
            $rsaProvider = (Get-Variable -Scope Global -Name $rsaProviderInstanceName).Value
            $decryptedBytes = $rsaProvider.Decrypt([Convert]::FromBase64String($encryptedData), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)

            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }

        Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
            -Message "[$ScriptName]: Password decryption failed. RSACryptoServiceProvider Instance not found" -ErrorAction SilentlyContinue

        # TODO: Localize this message!
        throw [System.InvalidOperationException] "Password decryption failed. RSACryptoServiceProvider Instance not found"
    }

    ###############################################################################
    # Script execution starts here...
    ###############################################################################

    # TODO: Figure out if this script really needs alternate credentials!

    $decryptedPassword = DecryptDataWithJWKOnNode $Password
    $securePassword = ConvertTo-SecureString $decryptedPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($UserName, $securePassword)
    $thisComputer = [System.Net.DNS]::GetHostByName('').HostName

    Invoke-Command -ComputerName $thisComputer -ScriptBlock {
        param(
            [string]
            $CertificatePath,
            [boolean]
            $UseSameCertificateKey
        )

        BEGIN {
            Set-StrictMode -Version 5.0

            Import-Module -Name Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

            #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
            enum EncodingType {
                XCN_CRYPT_STRING_BASE64HEADER = 0
                XCN_CRYPT_STRING_BASE64 = 0x1
                XCN_CRYPT_STRING_BINARY = 0x2
                XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3
                XCN_CRYPT_STRING_HEX = 0x4
                XCN_CRYPT_STRING_HEXASCII = 0x5
                XCN_CRYPT_STRING_BASE64_ANY = 0x6
                XCN_CRYPT_STRING_ANY = 0x7
                XCN_CRYPT_STRING_HEX_ANY = 0x8
                XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9
                XCN_CRYPT_STRING_HEXADDR = 0xa
                XCN_CRYPT_STRING_HEXASCIIADDR = 0xb
                XCN_CRYPT_STRING_HEXRAW = 0xc
                XCN_CRYPT_STRING_NOCRLF = 0x40000000
                XCN_CRYPT_STRING_NOCR = 0x80000000
            }

            #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379399(v=vs.85).aspx
            enum X509CertificateEnrollmentContext {
                ContextUser = 0x1
                ContextMachine = 0x2
                ContextAdministratorForceMachine = 0x3
            }

            #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379430(v=vs.85).aspx
            enum X509RequestInheritOptions {
                InheritDefault = 0x00000000
                InheritNewDefaultKey = 0x00000001
                InheritNewSimilarKey = 0x00000002
                InheritPrivateKey = 0x00000003
                InheritPublicKey = 0x00000004
                InheritKeyMask = 0x0000000f
                InheritNone = 0x00000010
                InheritRenewalCertificateFlag = 0x00000020
                InheritTemplateFlag = 0x00000040
                InheritSubjectFlag = 0x00000080
                InheritExtensionsFlag = 0x00000100
                InheritSubjectAltNameFlag = 0x00000200
                InheritValidityPeriodFlag = 0x00000400
            }

            Set-Variable -Name LogName -Option ReadOnly -Value "WindowsAdminCenter" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name LogSource -Option ReadOnly -Value "SMEScripts" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ScriptName -Option ReadOnly -Value "Update-Certificate.ps1" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name LocalMachineStoreName -Option ReadOnly -Value "LocalMachine" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name CurrentUserStoreName -Option ReadOnly -Value "CurrentUser" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ResultPropertyName -Option ReadOnly -Value "Result" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ErrorPropertyName -Option ReadOnly -Value "Error" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ErrorMessagePropertyName -Option ReadOnly -Value "ErrorMessage" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name StatusPropertyName -Option ReadOnly -Value "Status" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name StatusError -Option ReadOnly -Value "Error" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name StatusSuccess -Option ReadOnly -Value "Success" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ErrorNoContext -Option ReadOnly -Value "NoContext" -Scope Script -ErrorAction SilentlyContinue
            Set-Variable -Name ErrorUpdateFailed -Option ReadOnly -Value "UpdateFailed" -Scope Script -ErrorAction SilentlyContinue
        }
        PROCESS {
            function main([String] $path, [Boolean] $useSameKey) {
                $global:result = ""

                $cert = Get-Item -Path $path

                if ($path -match $LocalMachineStoreName) {
                    $context = [X509CertificateEnrollmentContext]::ContextAdministratorForceMachine
                }

                if ($path -match $CurrentUserStoreName) {
                    $context = [X509CertificateEnrollmentContext]::ContextUser
                }

                if (!$context) {
                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]:The certificate store name in certificate path $path is not known."  -ErrorAction SilentlyContinue

                    $global:result = @{ $StatusPropertyName = $StatusError; $ResultPropertyName = ''; $ErrorMessagePropertyName = ''; $ErrorPropertyName = $ErrorNoContext; }
                    $global:result

                    return
                }

                $x509RequestInheritOptions = [X509RequestInheritOptions]::InheritTemplateFlag

                $x509RequestInheritOptions += [X509RequestInheritOptions]::InheritRenewalCertificateFlag

                if ($useSameKey) {
                    $x509RequestInheritOptions += [X509RequestInheritOptions]::InheritPrivateKey
                }

                try {
                    $encodingType = [EncodingType]::XCN_CRYPT_STRING_BASE64

                    $pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
                    $pkcs10.Silent = $true
                    $pkcs10.InitializeFromCertificate($context, [System.Convert]::ToBase64String($cert.RawData), $encodingType, $x509RequestInheritOptions)
                    $pkcs10.AlternateSignatureAlgorithm = $false
                    $pkcs10.SmimeCapabilities = $false
                    $pkcs10.SuppressDefaults = $true
                    $pkcs10.Encode()

                    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa377809(v=vs.85).aspx
                    $enrolledCert = New-Object -ComObject X509Enrollment.CX509Enrollment
                    $enrolledCert.InitializeFromRequest($pkcs10)

                    $enrolledCert.Enroll()

                    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import([System.Convert]::FromBase64String($enrolledCert.Certificate(1)))

                    $global:result = @{ $StatusPropertyName = $StatusSuccess; $ResultPropertyName = $cert.Thumbprint; $ErrorMessagePropertyName = ''; $ErrorPropertyName = ''; }
                } catch [System.Runtime.InteropServices.COMException] {
                    $exceptionMessage = $_.Exception.Message
                    $friendlyName = if ($cert.FriendlyName) { $cert.FriendlyName } else { $cert.Subject }
                    $global:result = @{ $StatusPropertyName = $StatusError; $ResultPropertyName = ''; $ErrorMessagePropertyName = $exceptionMessage; $ErrorPropertyName = $ErrorUpdateFailed; }

                    Microsoft.PowerShell.Management\Write-EventLog -LogName $LogName -Source $LogSource -EventId 0 -Category 0 -EntryType Error `
                        -Message "[$ScriptName]: Couldn't update certificate $friendlyName.  Error: $exceptionMessage ; Certificate path: $path"  -ErrorAction SilentlyContinue
                }

                $global:result
            }

            main $CertificatePath $UseSameCertificateKey
        }
        END {
            Remove-Variable -Name LogName -Scope Script -Force
            Remove-Variable -Name LogSource -Scope Script -Force
            Remove-Variable -Name ScriptName -Scope Script -Force
            Remove-Variable -Name LocalMachineStoreName -Scope Script -Force
            Remove-Variable -Name CurrentUserStoreName -Scope Script -Force
            Remove-Variable -Name ResultPropertyName -Scope Script -Force
            Remove-Variable -Name ErrorPropertyName -Scope Script -Force
            Remove-Variable -Name ErrorMessagePropertyName -Scope Script -Force
            Remove-Variable -Name StatusPropertyName -Scope Script -Force
            Remove-Variable -Name StatusError -Scope Script -Force
            Remove-Variable -Name StatusSuccess -Scope Script -Force
            Remove-Variable -Name ErrorNoContext -Scope Script -Force
            Remove-Variable -Name ErrorUpdateFailed -Scope Script -Force
        }

    } -Credential $credential -ArgumentList $CertificatePath, $UseSameCertificateKey
}
END {
    Remove-Variable -Name LogName -Scope Script -Force
    Remove-Variable -Name LogSource -Scope Script -Force
    Remove-Variable -Name rsaProviderInstanceName -Scope Script -Force
}

}
## [END] Update-WACCMCertificate ##
function Clear-WACCMEventLogChannel {
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
## [END] Clear-WACCMEventLogChannel ##
function Clear-WACCMEventLogChannelAfterExport {
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
## [END] Clear-WACCMEventLogChannelAfterExport ##
function Export-WACCMEventLogChannel {
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
## [END] Export-WACCMEventLogChannel ##
function Get-WACCMCimEventLogRecords {
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
## [END] Get-WACCMCimEventLogRecords ##
function Get-WACCMClusterEvents {
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
## [END] Get-WACCMClusterEvents ##
function Get-WACCMEventLogDisplayName {
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
## [END] Get-WACCMEventLogDisplayName ##
function Get-WACCMEventLogFilteredCount {
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
## [END] Get-WACCMEventLogFilteredCount ##
function Get-WACCMEventLogRecords {
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
## [END] Get-WACCMEventLogRecords ##
function Get-WACCMEventLogSummary {
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
## [END] Get-WACCMEventLogSummary ##
function Set-WACCMEventLogChannelStatus {
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
## [END] Set-WACCMEventLogChannelStatus ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAeBLUVSIOTIw+G
# +nsemHqK0X9e+vtMwrDgBGAeGzjHFqCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAMy7TDZEDL+Vt5/5o5DjULY
# SfV/GZabXAaBylGeyOvqMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdAa02Nyh53glfLhd2VEiVqR1JfM0aZeoZKz8KTNv4FxKjj1V6HHenplk
# 1h8cPX0i/49r0/QkBKs+gusEgGWx5CD5FhFk7HmVdOfwLaQTcnfP+aHtuyZDj56X
# ab7IWHRVWcrm1JfbZoJSo6mEHrzyTPBMmlIxlXVJ+2y7aZaoffe0XqwcWmUcgCH5
# 02xV/FEl6J3Hhy5n8UloZpM/wZjbPMAxDKK3a2mBzEI4yj2VLaFqx7YjkVLWzRai
# 1Rh4Hjz8lo1F3yVZyDL+9yB7fQghAmSYAMapyMs9lJ1CedbDgg+/xIp+zxXcWrTE
# iIeamuKJfhNH7fn7Y3ub6W4cWvrpEKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAeCoAq1MjxFkbnSAkJV3x9fJ3MSXKrwF5luOaKAOXSggIGaO/1UBd/
# GBMyMDI1MTExMDE3MTYxNS45MTNaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgkIB+D5XIzmVQABAAACCTANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTVaFw0yNjA0MjIxOTQyNTVaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDClEow9y4M3f1S9z1xtNEETwWL1vEiiw0oD7SXEdv4
# sdP0xsVyidv6I2rmEl8PYs9LcZjzsWOHI7dQkRL28GP3CXcvY0Zq6nWsHY2QamCZ
# FLF2IlRH6BHx2RkN7ZRDKms7BOo4IGBRlCMkUv9N9/twOzAkpWNsM3b/BQxcwhVg
# sQqtQ8NEPUuiR+GV5rdQHUT4pjihZTkJwraliz0ZbYpUTH5Oki3d3Bpx9qiPriB6
# hhNfGPjl0PIp23D579rpW6ZmPqPT8j12KX7ySZwNuxs3PYvF/w13GsRXkzIbIyLK
# EPzj9lzmmrF2wjvvUrx9AZw7GLSXk28Dn1XSf62hbkFuUGwPFLp3EbRqIVmBZ42w
# cz5mSIICy3Qs/hwhEYhUndnABgNpD5avALOV7sUfJrHDZXX6f9ggbjIA6j2nhSAS
# Iql8F5LsKBw0RPtDuy3j2CPxtTmZozbLK8TMtxDiMCgxTpfg5iYUvyhV4aqaDLwR
# BsoBRhO/+hwybKnYwXxKeeOrsOwQLnaOE5BmFJYWBOFz3d88LBK9QRBgdEH5CLVh
# 7wkgMIeh96cH5+H0xEvmg6t7uztlXX2SV7xdUYPxA3vjjV3EkV7abSHD5HHQZTrd
# 3FqsD/VOYACUVBPrxF+kUrZGXxYInZTprYMYEq6UIG1DT4pCVP9DcaCLGIOYEJ1g
# 0wIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFEmL6NHEXTjlvfAvQM21dzMWk8rSMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBcXnxvODwk4h/jbUBsnFlFtrSuBBZb7wSZ
# fa5lKRMTNfNlmaAC4bd7Wo0I5hMxsEJUyupHwh4kD5qkRZczIc0jIABQQ1xDUBa+
# WTxrp/UAqC17ijFCePZKYVjNrHf/Bmjz7FaOI41kxueRhwLNIcQ2gmBqDR5W4TS2
# htRJYyZAs7jfJmbDtTcUOMhEl1OWlx/FnvcQbot5VPzaUwiT6Nie8l6PZjoQsuxi
# asuSAmxKIQdsHnJ5QokqwdyqXi1FZDtETVvbXfDsofzTta4en2qf48hzEZwUvbkz
# 5smt890nVAK7kz2crrzN3hpnfFuftp/rXLWTvxPQcfWXiEuIUd2Gg7eR8QtyKtJD
# U8+PDwECkzoaJjbGCKqx9ESgFJzzrXNwhhX6Rc8g2EU/+63mmqWeCF/kJOFg2eJw
# 7au/abESgq3EazyD1VlL+HaX+MBHGzQmHtvOm3Ql4wVTN3Wq8X8bCR68qiF5rFas
# m4RxF6zajZeSHC/qS5336/4aMDqsV6O86RlPPCYGJOPtf2MbKO7XJJeL/UQN0c3u
# ix5RMTo66dbATxPUFEG5Ph4PHzGjUbEO7D35LuEBiiG8YrlMROkGl3fBQl9bWbgw
# 9CIUQbwq5cTaExlfEpMdSoydJolUTQD5ELKGz1TJahTidd20wlwi5Bk36XImzsH4
# Ys15iXRfAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
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
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjkyMDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQB8
# 762rPTQd7InDCQdb1kgFKQkCRKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LwOwjAiGA8yMDI1MTExMDA3MTIw
# MloYDzIwMjUxMTExMDcxMjAyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvA7C
# AgEAMAoCAQACAhWRAgH/MAcCAQACAhLHMAoCBQDsvWBCAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBABJVM6yZJMQJ0OgEgle+7FkS3adZc72zmR2t9DbhiwkM
# 0SJJqBey/gWbaqZL3pRY/AB3Fs6MGPWyjL3VnFcWZUaVlmaZZp+HLFr9Mhk6etqU
# VV8aqKHmsRX3ix/5vwUzvxeHEB8tJVrct/wIvOU0S/ySD4XROYnqEMjOZhFDkOYW
# ikktrZ0wB3nTdEhP95TfxkZyG93Bo3+0UEppIvYk9zwY7FOAPFw990DcwJr855Zn
# uX0+lViglh1wK9wVgQZbPUTqY8bqzz+AoFlXmbBIR539tbCfd5Lz+Y4KN08OyiOM
# y5ErDdF+19tM/ihCwW1au47vKhGa0KWDgsy5J0Ji1/wxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgkIB+D5XIzmVQABAAAC
# CTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCNHKwglM8JCSJJh9OnV+4dBfoYEDZMLbb4gCXoEA58
# szCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGgbLB7IvfQCLmUOUZhjdUqK
# 8bikfB6ZVVdoTjNwhRM+MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIJCAfg+VyM5lUAAQAAAgkwIgQgYevmSpE5N/hkJDG5Xm0q2UKS
# Cn9Nf4Fi0M0SQEldABEwDQYJKoZIhvcNAQELBQAEggIAH95t8Yn6yGAW3VAsj4cr
# GAlCytD7uI2EUekw+5z5igWLIEfrXba4CMqpw8OPrf/jmMsCK62tqxbIkJJkTCq5
# JVuj+PdOiycJMn9Iz9U464+90H5MLFH95cm/bTkVIkbkFNfIx/oh2OJEESaIDsvd
# AawoEPZ/7seJEuqFwPIijFcDtg4JKcDa0iDdQSFB+v+WNVZQtDPmJ98UridcBDto
# JcrhV6e+oS/z3zeK2C9erafKZ00GNwA036bQ5xgLjMJ+LcfS1fxSUCdLjbT/MZvP
# Yow8AmgOcB4vgEkYiFJ81WGsg3MXp3CV/uPquPeIfKARbicJ6ugFUB3ztK5/Nsbl
# OVla7cW/zw/g85Lqmh7rS43pK7t5eZzAYcki3cntf3A+db79viwwxG8BBTFisjqk
# bNHSW/82rhwI2UFK26tDnrUo7jhMT6hndM/EYaictUyr03oIcgohO5p5wv8RHDdW
# /UCbWhVDQWRVBSWw8443m8i7Azt1sdB9DmqPADyTb6stkmD2dxmDEqoO0FuRJ0y+
# rTEnCGU7H7aSPyq14ChO/V9JKVM+gf4ADtP8+EOghzvCxjJkufPS6OdUnrQ7lkKq
# Hwg8ILLKHatTc/8mFtKVWWuv5/wz04Uzfs9Y/Fy6R/5dF7yk9egFmqDL62/hyZeb
# wQGbIxAI8pDr7UXfgfOay9I=
# SIG # End signature block
