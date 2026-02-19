<#
.SYNOPSIS
    Evaluates a Windows workstation for CMMC 2.0 Level 2 compliance.

.DESCRIPTION
    This script assesses Windows workstation configuration against CMMC 2.0 Level 2
    (NIST SP 800-171) security controls and generates a detailed compliance report.

    Supports both traditional domain-joined and Azure AD joined / Intune-managed devices.

    The script evaluates:
    - Access Control (AC)
    - Audit and Accountability (AU)
    - Configuration Management (CM)
    - Identification and Authentication (IA)
    - System and Communications Protection (SC)
    - System and Information Integrity (SI)
    - Media Protection (MP)

.PARAMETER OutputPath
    Path where the HTML report will be saved. Defaults to desktop.

.PARAMETER ComputerName
    Remote computer name to assess. Defaults to local computer.

.EXAMPLE
    .\Invoke-CMMC2Assessment.ps1
    Runs assessment on local computer and saves report to desktop.

.EXAMPLE
    .\Invoke-CMMC2Assessment.ps1 -ComputerName "WORKSTATION01" -OutputPath "C:\Reports"
    Runs assessment on remote computer and saves to specified path.

.NOTES
    Author: PowerShell Security Assessment
    Version: 2.0
    Requires: PowerShell 5.1 or higher, Administrator privileges
    Changelog: v2.0 - Added Azure AD and Intune support
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = [Environment]::GetFolderPath("Desktop"),

    [Parameter(Mandatory = $false)]
    [switch]$ExportJSON,

    [Parameter(Mandatory = $false)]
    [string]$JSONOutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHTMLReport
)

#Requires -RunAsAdministrator

# Assessment Results Storage
$script:AssessmentResults = @()
$script:ComplianceScore = 0
$script:TotalChecks = 0
$script:ManagementInfo = @{}

#region Helper Functions

function Write-AssessmentLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Pass', 'Fail', 'Warning')]
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Warning' { 'Yellow' }
        default { 'White' }
    }

    $prefix = switch ($Level) {
        'Pass' { '[✓]' }
        'Fail' { '[✗]' }
        'Warning' { '[!]' }
        default { '[i]' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Add-AssessmentResult {
    param(
        [string]$ControlID,
        [string]$ControlName,
        [string]$Category,
        [ValidateSet('Compliant', 'Non-Compliant', 'Partial', 'Not Applicable', 'Error')]
        [string]$Status,
        [string]$Finding,
        [string]$Remediation,
        [string]$Reference
    )

    $script:TotalChecks++
    if ($Status -eq 'Compliant') {
        $script:ComplianceScore++
    }

    $result = [PSCustomObject]@{
        ControlID   = $ControlID
        ControlName = $ControlName
        Category    = $Category
        Status      = $Status
        Finding     = $Finding
        Remediation = $Remediation
        Reference   = $Reference
        Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $script:AssessmentResults += $result

    $logLevel = switch ($Status) {
        'Compliant' { 'Pass' }
        'Non-Compliant' { 'Fail' }
        'Partial' { 'Warning' }
        default { 'Info' }
    }

    Write-AssessmentLog -Message "$ControlID - $ControlName : $Status" -Level $logLevel
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $value.$Name
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-DeviceManagementStatus {
    Write-Host "`n=== DETECTING DEVICE MANAGEMENT STATUS ===" -ForegroundColor Cyan

    $mgmtInfo = @{
        IsAzureADJoined = $false
        IsHybridJoined = $false
        IsDomainJoined = $false
        IsIntuneEnrolled = $false
        IsIntuneCompliant = $null
        HasCompliancePolicies = $false
        TenantName = "N/A"
        TenantID = "N/A"
        DeviceID = "N/A"
        ManagementType = "Unknown"
        HasNinjaRMM = $false
        NinjaRMMVersion = "N/A"
        PatchManagement = "Unknown"
        HasBlackpointCyber = $false
        BlackpointVersion = "N/A"
        BlackpointStatus = "Unknown"
        HasDefenderForEndpoint = $false
        DefenderForEndpointOnboarded = $false
        DefenderForEndpointStatus = "Unknown"
        EDRPlatform = "Unknown"
    }

    # Check Azure AD Join Status
    try {
        $dsregStatus = dsregcmd /status

        # Parse Azure AD Join
        if ($dsregStatus -match "AzureAdJoined\s*:\s*YES") {
            $mgmtInfo.IsAzureADJoined = $true
        }

        # Parse Hybrid Join
        if ($dsregStatus -match "DomainJoined\s*:\s*YES" -and $mgmtInfo.IsAzureADJoined) {
            $mgmtInfo.IsHybridJoined = $true
        }

        # Parse Domain Join
        if ($dsregStatus -match "DomainJoined\s*:\s*YES") {
            $mgmtInfo.IsDomainJoined = $true
        }

        # Extract Tenant Name
        if ($dsregStatus -match "TenantName\s*:\s*(.+)") {
            $mgmtInfo.TenantName = $Matches[1].Trim()
        }

        # Extract Tenant ID
        if ($dsregStatus -match "TenantId\s*:\s*(.+)") {
            $mgmtInfo.TenantID = $Matches[1].Trim()
        }

        # Extract Device ID
        if ($dsregStatus -match "DeviceId\s*:\s*(.+)") {
            $mgmtInfo.DeviceID = $Matches[1].Trim()
        }
    }
    catch {
        Write-AssessmentLog -Message "Unable to query dsregcmd status" -Level Warning
    }

    # Check Intune Enrollment
    try {
        $intuneKey = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if (Test-Path $intuneKey) {
            $enrollments = Get-ChildItem -Path $intuneKey -ErrorAction SilentlyContinue
            foreach ($enrollment in $enrollments) {
                $upn = Get-RegistryValue -Path $enrollment.PSPath -Name "UPN"
                $providerID = Get-RegistryValue -Path $enrollment.PSPath -Name "ProviderID"

                # Check if it's an Intune enrollment (MS DM Server)
                if ($providerID -like "*MS DM Server*" -or $providerID -eq "MS DM Server") {
                    $mgmtInfo.IsIntuneEnrolled = $true

                    # Try to get compliance state - Method 1: Enrollment Key
                    $complianceState = Get-RegistryValue -Path $enrollment.PSPath -Name "DeviceComplianceState"
                    if ($complianceState -eq 1) {
                        $mgmtInfo.IsIntuneCompliant = $true
                    }
                    elseif ($null -ne $complianceState) {
                        $mgmtInfo.IsIntuneCompliant = $false
                    }

                    # Method 2: Check PolicyManager if primary method didn't find compliance
                    if ($null -eq $complianceState) {
                        $policyPaths = @(
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceStatus",
                            "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\*\Default\Device\DeviceStatus"
                        )

                        foreach ($policyPath in $policyPaths) {
                            if (Test-Path $policyPath) {
                                $deviceStatus = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
                                if ($deviceStatus) {
                                    # Look for compliance-related properties
                                    $complianceProps = $deviceStatus.PSObject.Properties | Where-Object { $_.Name -like "*Complian*" }
                                    foreach ($prop in $complianceProps) {
                                        if ($prop.Value -eq 1 -or $prop.Value -eq "Compliant") {
                                            $mgmtInfo.IsIntuneCompliant = $true
                                            break
                                        }
                                        elseif ($prop.Value -eq 0 -or $prop.Value -eq "NonCompliant") {
                                            $mgmtInfo.IsIntuneCompliant = $false
                                            break
                                        }
                                    }
                                }
                            }
                            if ($null -ne $mgmtInfo.IsIntuneCompliant) { break }
                        }
                    }

                    break
                }
            }
        }
    }
    catch {
        Write-AssessmentLog -Message "Unable to check Intune enrollment status" -Level Warning
    }

    # Check for NinjaRMM Agent
    try {
        # Check for NinjaRMM service
        $ninjaService = Get-Service -Name "NinjaRMMAgent" -ErrorAction SilentlyContinue
        if ($ninjaService) {
            $mgmtInfo.HasNinjaRMM = $true

            # Try to get version from registry
            $ninjaRegPaths = @(
                "HKLM:\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent",
                "HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent"
            )

            foreach ($path in $ninjaRegPaths) {
                if (Test-Path $path) {
                    $version = Get-RegistryValue -Path $path -Name "Version"
                    if ($version) {
                        $mgmtInfo.NinjaRMMVersion = $version
                        break
                    }
                }
            }

            # Check if NinjaRMM is configured for patching
            # NinjaRMM typically manages Windows Update via scheduled tasks or policies
            $ninjaTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Ninja*" -or $_.TaskPath -like "*NinjaRMM*" }
            $patchingTask = $ninjaTasks | Where-Object { $_.TaskName -like "*Update*" -or $_.TaskName -like "*Patch*" }

            if ($patchingTask -or $ninjaService.Status -eq "Running") {
                $mgmtInfo.PatchManagement = "NinjaRMM"
            }
        }
    }
    catch {
        Write-AssessmentLog -Message "Unable to check NinjaRMM status" -Level Warning
    }

    # Determine Patch Management
    if (-not $mgmtInfo.HasNinjaRMM) {
        if ($mgmtInfo.IsIntuneEnrolled) {
            $mgmtInfo.PatchManagement = "Intune (Windows Update for Business)"
        }
        elseif ($mgmtInfo.IsDomainJoined) {
            $mgmtInfo.PatchManagement = "WSUS/GPO (Traditional)"
        }
        else {
            $mgmtInfo.PatchManagement = "Windows Update (Direct)"
        }
    }

    # Check for Blackpoint Cyber EDR
    try {
        # Blackpoint Cyber uses multiple service names depending on version
        # SNAP is their primary agent service name
        $blackpointServices = @(
            "SNAP",
            "SNAPService",
            "BlackpointCyberServices",
            "Blackpoint",
            "BlackpointAgent"
        )

        foreach ($serviceName in $blackpointServices) {
            $bpService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($bpService) {
                $mgmtInfo.HasBlackpointCyber = $true
                $mgmtInfo.BlackpointStatus = $bpService.Status.ToString()

                # Try to get version from registry or file
                $bpRegPaths = @(
                    "HKLM:\SOFTWARE\Blackpoint Cyber",
                    "HKLM:\SOFTWARE\WOW6432Node\Blackpoint Cyber",
                    "HKLM:\SOFTWARE\SNAP",
                    "HKLM:\SOFTWARE\WOW6432Node\SNAP"
                )

                foreach ($path in $bpRegPaths) {
                    if (Test-Path $path) {
                        $version = Get-RegistryValue -Path $path -Name "Version"
                        if ($version) {
                            $mgmtInfo.BlackpointVersion = $version
                            break
                        }
                    }
                }

                # Try to get version from executable
                if ($mgmtInfo.BlackpointVersion -eq "N/A") {
                    $bpPaths = @(
                        "C:\Program Files\Blackpoint Cyber\*\*.exe",
                        "C:\Program Files (x86)\Blackpoint Cyber\*\*.exe",
                        "C:\Program Files\SNAP\*\*.exe",
                        "C:\Program Files (x86)\SNAP\*\*.exe"
                    )

                    foreach ($pattern in $bpPaths) {
                        $exePath = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($exePath) {
                            $fileVersion = (Get-Item $exePath.FullName).VersionInfo.FileVersion
                            if ($fileVersion) {
                                $mgmtInfo.BlackpointVersion = $fileVersion
                                break
                            }
                        }
                    }
                }

                break
            }
        }
    }
    catch {
        Write-AssessmentLog -Message "Unable to check Blackpoint Cyber status" -Level Warning
    }

    # Check for Microsoft Defender for Endpoint
    try {
        # Check if Sense service (MDE) is present and running
        $senseService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue

        if ($senseService) {
            $mgmtInfo.HasDefenderForEndpoint = $true
            $mgmtInfo.DefenderForEndpointStatus = $senseService.Status.ToString()

            # Check onboarding status
            $mdeOnboardingInfo = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState"
            if ($mdeOnboardingInfo -eq 1) {
                $mgmtInfo.DefenderForEndpointOnboarded = $true
            }

            # Alternative check for onboarding via registry
            if (-not $mgmtInfo.DefenderForEndpointOnboarded) {
                $orgId = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OrgId"
                if ($orgId) {
                    $mgmtInfo.DefenderForEndpointOnboarded = $true
                }
            }
        }
    }
    catch {
        Write-AssessmentLog -Message "Unable to check Microsoft Defender for Endpoint status" -Level Warning
    }

    # Determine EDR Platform
    if ($mgmtInfo.HasBlackpointCyber -and $mgmtInfo.HasDefenderForEndpoint) {
        $mgmtInfo.EDRPlatform = "Blackpoint Cyber + Microsoft Defender for Endpoint (Dual EDR)"
    }
    elseif ($mgmtInfo.HasBlackpointCyber) {
        $mgmtInfo.EDRPlatform = "Blackpoint Cyber"
    }
    elseif ($mgmtInfo.HasDefenderForEndpoint) {
        $mgmtInfo.EDRPlatform = "Microsoft Defender for Endpoint"
    }
    else {
        $mgmtInfo.EDRPlatform = "No EDR Detected"
    }

    # Determine Management Type
    if ($mgmtInfo.IsAzureADJoined -and $mgmtInfo.IsIntuneEnrolled -and -not $mgmtInfo.IsDomainJoined) {
        $mgmtInfo.ManagementType = "Cloud-Native (Azure AD + Intune)"
    }
    elseif ($mgmtInfo.IsHybridJoined -and $mgmtInfo.IsIntuneEnrolled) {
        $mgmtInfo.ManagementType = "Hybrid (Azure AD + On-Prem AD + Intune)"
    }
    elseif ($mgmtInfo.IsHybridJoined) {
        $mgmtInfo.ManagementType = "Hybrid (Azure AD + On-Prem AD)"
    }
    elseif ($mgmtInfo.IsDomainJoined) {
        $mgmtInfo.ManagementType = "Traditional (On-Premises Domain)"
    }
    elseif ($mgmtInfo.IsAzureADJoined) {
        $mgmtInfo.ManagementType = "Cloud-Native (Azure AD only)"
    }
    else {
        $mgmtInfo.ManagementType = "Workgroup (Unmanaged)"
    }

    # Log findings
    Write-AssessmentLog -Message "Management Type: $($mgmtInfo.ManagementType)" -Level Info
    Write-AssessmentLog -Message "Azure AD Joined: $($mgmtInfo.IsAzureADJoined)" -Level Info
    Write-AssessmentLog -Message "Intune Enrolled: $($mgmtInfo.IsIntuneEnrolled)" -Level Info
    if ($mgmtInfo.IsIntuneCompliant -ne $null) {
        Write-AssessmentLog -Message "Intune Compliant: $($mgmtInfo.IsIntuneCompliant)" -Level Info
    }
    Write-AssessmentLog -Message "NinjaRMM Agent: $($mgmtInfo.HasNinjaRMM)" -Level Info
    Write-AssessmentLog -Message "Patch Management: $($mgmtInfo.PatchManagement)" -Level Info
    Write-AssessmentLog -Message "EDR Platform: $($mgmtInfo.EDRPlatform)" -Level Info
    if ($mgmtInfo.HasBlackpointCyber) {
        Write-AssessmentLog -Message "Blackpoint Cyber: Active ($($mgmtInfo.BlackpointStatus))" -Level Info
    }
    if ($mgmtInfo.HasDefenderForEndpoint) {
        $mdeOnboardStatus = if ($mgmtInfo.DefenderForEndpointOnboarded) { "Onboarded" } else { "Installed but not onboarded" }
        Write-AssessmentLog -Message "Defender for Endpoint: $mdeOnboardStatus ($($mgmtInfo.DefenderForEndpointStatus))" -Level Info
    }

    return $mgmtInfo
}

function Get-RemediationGuidance {
    param(
        [string]$GPOPath,
        [string]$IntunePath,
        [string]$DirectFix
    )

    if ($script:ManagementInfo.IsIntuneEnrolled) {
        return "Configure via Intune: $IntunePath"
    }
    elseif ($script:ManagementInfo.IsDomainJoined) {
        return "Configure via GPO: $GPOPath"
    }
    else {
        return $DirectFix
    }
}

#endregion

#region Assessment Functions

function Test-AccessControl {
    Write-Host "`n=== ACCESS CONTROL (AC) ===" -ForegroundColor Cyan

    # AC.1.001 - Account Management
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminCount = $localAdmins.Count

        if ($adminCount -le 2) {
            Add-AssessmentResult -ControlID "AC.1.001" -ControlName "Limit Local Administrator Accounts" `
                -Category "Access Control" -Status "Compliant" `
                -Finding "Local Administrators group has $adminCount members (acceptable)" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.1.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Restricted Groups" `
                -IntunePath "Endpoint Security > Account Protection > Local Admin Password Solution (LAPS) and restrict local admin group membership" `
                -DirectFix "Remove unnecessary accounts from local Administrators group. Use standard user accounts with UAC elevation."

            Add-AssessmentResult -ControlID "AC.1.001" -ControlName "Limit Local Administrator Accounts" `
                -Category "Access Control" -Status "Non-Compliant" `
                -Finding "Local Administrators group has $adminCount members (excessive)" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.1.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AC.1.001" -ControlName "Limit Local Administrator Accounts" `
            -Category "Access Control" -Status "Error" `
            -Finding "Unable to enumerate local administrators: $($_.Exception.Message)" `
            -Remediation "Verify permissions and group existence" `
            -Reference "NIST SP 800-171 3.1.1"
    }

    # AC.1.002 - Guest Account Disabled
    try {
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if ($guestAccount.Enabled -eq $false) {
            Add-AssessmentResult -ControlID "AC.1.002" -ControlName "Guest Account Disabled" `
                -Category "Access Control" -Status "Compliant" `
                -Finding "Guest account is disabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.1.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Guest account status' = Disabled" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Local Policies Security Options > Accounts Guest Account Status = Disabled" `
                -DirectFix "net user guest /active:no"

            Add-AssessmentResult -ControlID "AC.1.002" -ControlName "Guest Account Disabled" `
                -Category "Access Control" -Status "Non-Compliant" `
                -Finding "Guest account is enabled" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.1.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AC.1.002" -ControlName "Guest Account Disabled" `
            -Category "Access Control" -Status "Error" `
            -Finding "Unable to check guest account status" `
            -Remediation "Manually verify guest account is disabled" `
            -Reference "NIST SP 800-171 3.1.1"
    }

    # AC.1.003 - Screen Lock Timeout
    $screenLockTimeout = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs"
    $screenSaverActive = Get-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive"
    $screenSaverTimeout = Get-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut"

    if (($screenLockTimeout -and $screenLockTimeout -le 900) -or ($screenSaverActive -eq 1 -and $screenSaverTimeout -le 900)) {
        Add-AssessmentResult -ControlID "AC.1.003" -ControlName "Screen Lock Timeout (15 minutes)" `
            -Category "Access Control" -Status "Compliant" `
            -Finding "Screen lock timeout is configured (≤15 minutes)" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.1.10"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Interactive logon: Machine inactivity limit' = 900 seconds" `
            -IntunePath "Devices > Configuration Profiles > Settings Catalog > Local Policies Security Options > Interactive Logon Machine Inactivity Limit = 900" `
            -DirectFix "Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs = 900"

        Add-AssessmentResult -ControlID "AC.1.003" -ControlName "Screen Lock Timeout (15 minutes)" `
            -Category "Access Control" -Status "Non-Compliant" `
            -Finding "Screen lock timeout not configured or exceeds 15 minutes" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.1.10"
    }

    # AC.1.004 - UAC Enabled
    $uacEnabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

    if ($uacEnabled -eq 1) {
        Add-AssessmentResult -ControlID "AC.1.004" -ControlName "User Account Control (UAC) Enabled" `
            -Category "Access Control" -Status "Compliant" `
            -Finding "UAC is enabled" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.1.7"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'User Account Control: Run all administrators in Admin Approval Mode' = Enabled" `
            -IntunePath "Devices > Configuration Profiles > Settings Catalog > Local Policies Security Options > User Account Control Run All Administrators In Admin Approval Mode = Enabled" `
            -DirectFix "Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA = 1"

        Add-AssessmentResult -ControlID "AC.1.004" -ControlName "User Account Control (UAC) Enabled" `
            -Category "Access Control" -Status "Non-Compliant" `
            -Finding "UAC is disabled or not configured" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.1.7"
    }

    # AC.1.005 - Account Lockout Policy
    # Note: For Azure AD accounts, this is managed in the cloud
    if ($script:ManagementInfo.IsAzureADJoined -and -not $script:ManagementInfo.IsDomainJoined) {
        Add-AssessmentResult -ControlID "AC.1.005" -ControlName "Account Lockout Policy" `
            -Category "Access Control" -Status "Partial" `
            -Finding "Azure AD joined device - Account lockout enforced by Entra ID (cloud-side)" `
            -Remediation "Verify Smart Lockout is enabled in Entra ID: Azure Portal > Entra ID > Security > Authentication Methods > Password Protection > Smart Lockout (10 failed attempts threshold recommended)" `
            -Reference "NIST SP 800-171 3.1.8"
    }
    else {
        try {
            $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
            $lockoutThreshold = ($secpolContent | Select-String "LockoutBadCount").ToString().Split('=')[1].Trim()
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

            if ([int]$lockoutThreshold -gt 0 -and [int]$lockoutThreshold -le 10) {
                Add-AssessmentResult -ControlID "AC.1.005" -ControlName "Account Lockout Policy" `
                    -Category "Access Control" -Status "Compliant" `
                    -Finding "Account lockout threshold is $lockoutThreshold attempts (acceptable)" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.1.8"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout threshold = 10" `
                    -IntunePath "Devices > Configuration Profiles > Settings Catalog > Account Policies Account Lockout > Account Lockout Threshold = 10" `
                    -DirectFix "Configure account lockout policy (requires domain or local security policy)"

                Add-AssessmentResult -ControlID "AC.1.005" -ControlName "Account Lockout Policy" `
                    -Category "Access Control" -Status "Non-Compliant" `
                    -Finding "Account lockout threshold is not configured or exceeds recommended limit" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.1.8"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "AC.1.005" -ControlName "Account Lockout Policy" `
                -Category "Access Control" -Status "Error" `
                -Finding "Unable to retrieve account lockout policy" `
                -Remediation "Manually verify account lockout policy is configured" `
                -Reference "NIST SP 800-171 3.1.8"
        }
    }
}

function Test-AuditAccountability {
    Write-Host "`n=== AUDIT AND ACCOUNTABILITY (AU) ===" -ForegroundColor Cyan

    # AU.1.001 - Security Event Log Size
    try {
        $securityLog = Get-WinEvent -ListLog Security
        $logSizeMB = $securityLog.MaximumSizeInBytes / 1MB

        if ($logSizeMB -ge 1024) {
            Add-AssessmentResult -ControlID "AU.1.001" -ControlName "Security Event Log Size" `
                -Category "Audit and Accountability" -Status "Compliant" `
                -Finding "Security log size is $logSizeMB MB (adequate)" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.3.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify maximum log file size = 1073741824 bytes" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Event Log Service Security > Maximum Log File Size = 1073741824" `
                -DirectFix "wevtutil sl Security /ms:1073741824"

            Add-AssessmentResult -ControlID "AU.1.001" -ControlName "Security Event Log Size" `
                -Category "Audit and Accountability" -Status "Partial" `
                -Finding "Security log size is $logSizeMB MB (consider increasing)" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.3.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AU.1.001" -ControlName "Security Event Log Size" `
            -Category "Audit and Accountability" -Status "Error" `
            -Finding "Unable to retrieve security log configuration" `
            -Remediation "Manually verify security log size" `
            -Reference "NIST SP 800-171 3.3.1"
    }

    # AU.1.002 - Audit Policy - Logon Events
    try {
        $auditPolicy = auditpol /get /category:"Logon/Logoff" 2>&1
        if ($auditPolicy -match "Success and Failure" -or ($auditPolicy -match "Success" -and $auditPolicy -match "Failure")) {
            Add-AssessmentResult -ControlID "AU.1.002" -ControlName "Audit Logon Events" `
                -Category "Audit and Accountability" -Status "Compliant" `
                -Finding "Logon/Logoff auditing is enabled for success and failure" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.3.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy > Logon/Logoff > Audit Logon (Success and Failure)" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Audit Policy Detailed Tracking > Audit Logon = Success and Failure" `
                -DirectFix "auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable"

            Add-AssessmentResult -ControlID "AU.1.002" -ControlName "Audit Logon Events" `
                -Category "Audit and Accountability" -Status "Non-Compliant" `
                -Finding "Logon/Logoff auditing is not properly configured" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.3.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AU.1.002" -ControlName "Audit Logon Events" `
            -Category "Audit and Accountability" -Status "Error" `
            -Finding "Unable to retrieve audit policy" `
            -Remediation "Manually verify audit policy configuration" `
            -Reference "NIST SP 800-171 3.3.1"
    }

    # AU.1.003 - Audit Policy - Account Management
    try {
        $auditPolicy = auditpol /get /category:"Account Management" 2>&1
        if ($auditPolicy -match "Success and Failure" -or ($auditPolicy -match "Success" -and $auditPolicy -match "Failure")) {
            Add-AssessmentResult -ControlID "AU.1.003" -ControlName "Audit Account Management" `
                -Category "Audit and Accountability" -Status "Compliant" `
                -Finding "Account Management auditing is enabled for success and failure" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.3.2"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy > Account Management (Success and Failure)" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Audit Policy Account Management > Audit Security Group Management = Success and Failure" `
                -DirectFix "auditpol /set /category:'Account Management' /success:enable /failure:enable"

            Add-AssessmentResult -ControlID "AU.1.003" -ControlName "Audit Account Management" `
                -Category "Audit and Accountability" -Status "Non-Compliant" `
                -Finding "Account Management auditing is not properly configured" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.3.2"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AU.1.003" -ControlName "Audit Account Management" `
            -Category "Audit and Accountability" -Status "Error" `
            -Finding "Unable to retrieve audit policy" `
            -Remediation "Manually verify audit policy configuration" `
            -Reference "NIST SP 800-171 3.3.2"
    }

    # AU.1.004 - Audit Policy - Object Access
    try {
        $auditPolicy = auditpol /get /category:"Object Access" 2>&1
        if ($auditPolicy -match "Failure" -or $auditPolicy -match "Success and Failure") {
            Add-AssessmentResult -ControlID "AU.1.004" -ControlName "Audit Object Access" `
                -Category "Audit and Accountability" -Status "Compliant" `
                -Finding "Object Access auditing is enabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.3.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy > Object Access" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Audit Policy Object Access > Audit File System = Failure" `
                -DirectFix "auditpol /set /subcategory:'File System' /failure:enable"

            Add-AssessmentResult -ControlID "AU.1.004" -ControlName "Audit Object Access" `
                -Category "Audit and Accountability" -Status "Partial" `
                -Finding "Object Access auditing may not be fully configured" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.3.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "AU.1.004" -ControlName "Audit Object Access" `
            -Category "Audit and Accountability" -Status "Error" `
            -Finding "Unable to retrieve audit policy" `
            -Remediation "Manually verify audit policy configuration" `
            -Reference "NIST SP 800-171 3.3.1"
    }
}

function Test-IdentificationAuthentication {
    Write-Host "`n=== IDENTIFICATION AND AUTHENTICATION (IA) ===" -ForegroundColor Cyan

    # Note: For Azure AD accounts, password policies are managed in the cloud
    $isCloudManaged = $script:ManagementInfo.IsAzureADJoined -and -not $script:ManagementInfo.IsDomainJoined

    # IA.1.001 - Password Complexity
    if ($isCloudManaged) {
        Add-AssessmentResult -ControlID "IA.1.001" -ControlName "Password Complexity Requirements" `
            -Category "Identification and Authentication" -Status "Partial" `
            -Finding "Azure AD joined device - Password complexity enforced by Entra ID (cloud-side)" `
            -Remediation "Verify password policy in Entra ID: Azure Portal > Entra ID > Security > Authentication Methods > Password Protection (complexity is enforced by default)" `
            -Reference "NIST SP 800-171 3.5.7"
    }
    else {
        try {
            $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
            $passwordComplexity = ($secpolContent | Select-String "PasswordComplexity").ToString().Split('=')[1].Trim()
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

            if ($passwordComplexity -eq "1") {
                Add-AssessmentResult -ControlID "IA.1.001" -ControlName "Password Complexity Requirements" `
                    -Category "Identification and Authentication" -Status "Compliant" `
                    -Finding "Password complexity is enabled" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.5.7"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > 'Password must meet complexity requirements' = Enabled" `
                    -IntunePath "Devices > Configuration Profiles > Settings Catalog > Account Policies Password Policy > Password Must Meet Complexity Requirements = Enabled" `
                    -DirectFix "Configure via local security policy: secpol.msc > Account Policies > Password Policy"

                Add-AssessmentResult -ControlID "IA.1.001" -ControlName "Password Complexity Requirements" `
                    -Category "Identification and Authentication" -Status "Non-Compliant" `
                    -Finding "Password complexity is not enabled" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.5.7"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "IA.1.001" -ControlName "Password Complexity Requirements" `
                -Category "Identification and Authentication" -Status "Error" `
                -Finding "Unable to retrieve password policy" `
                -Remediation "Manually verify password complexity is enabled" `
                -Reference "NIST SP 800-171 3.5.7"
        }
    }

    # IA.1.002 - Minimum Password Length
    if ($isCloudManaged) {
        Add-AssessmentResult -ControlID "IA.1.002" -ControlName "Minimum Password Length" `
            -Category "Identification and Authentication" -Status "Partial" `
            -Finding "Azure AD joined device - Minimum password length enforced by Entra ID (cloud-side, default 8 characters)" `
            -Remediation "Verify and increase if needed: Azure Portal > Entra ID > Security > Authentication Methods > Password Protection > Banned passwords (Custom list) and minimum length settings. For stronger security, enforce 14+ character passwords via custom policies." `
            -Reference "NIST SP 800-171 3.5.7"
    }
    else {
        try {
            $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
            $minPasswordLength = ($secpolContent | Select-String "MinimumPasswordLength").ToString().Split('=')[1].Trim()
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

            if ([int]$minPasswordLength -ge 14) {
                Add-AssessmentResult -ControlID "IA.1.002" -ControlName "Minimum Password Length" `
                    -Category "Identification and Authentication" -Status "Compliant" `
                    -Finding "Minimum password length is $minPasswordLength characters (meets requirement)" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.5.7"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > 'Minimum password length' = 14" `
                    -IntunePath "Devices > Configuration Profiles > Settings Catalog > Account Policies Password Policy > Minimum Password Length = 14" `
                    -DirectFix "Configure via local security policy: secpol.msc > Account Policies > Password Policy"

                Add-AssessmentResult -ControlID "IA.1.002" -ControlName "Minimum Password Length" `
                    -Category "Identification and Authentication" -Status "Non-Compliant" `
                    -Finding "Minimum password length is $minPasswordLength characters (should be 14+)" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.5.7"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "IA.1.002" -ControlName "Minimum Password Length" `
                -Category "Identification and Authentication" -Status "Error" `
                -Finding "Unable to retrieve minimum password length" `
                -Remediation "Manually verify minimum password length is 14+" `
                -Reference "NIST SP 800-171 3.5.7"
        }
    }

    # IA.1.003 - Maximum Password Age
    if ($isCloudManaged) {
        Add-AssessmentResult -ControlID "IA.1.003" -ControlName "Maximum Password Age" `
            -Category "Identification and Authentication" -Status "Partial" `
            -Finding "Azure AD joined device - Password expiration managed by Entra ID (default: passwords don't expire). For CMMC compliance, consider enabling expiration." `
            -Remediation "Enable password expiration if required: Azure Portal > Entra ID > Password reset > Password policy > Set password expiration to 60-90 days (Note: Microsoft recommends eliminating password expiration with MFA, but CMMC may require it)" `
            -Reference "NIST SP 800-171 3.5.8"
    }
    else {
        try {
            $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
            $maxPasswordAge = ($secpolContent | Select-String "MaximumPasswordAge").ToString().Split('=')[1].Trim()
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

            if ([int]$maxPasswordAge -le 60 -and [int]$maxPasswordAge -gt 0) {
                Add-AssessmentResult -ControlID "IA.1.003" -ControlName "Maximum Password Age" `
                    -Category "Identification and Authentication" -Status "Compliant" `
                    -Finding "Maximum password age is $maxPasswordAge days (acceptable)" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.5.8"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > 'Maximum password age' = 60" `
                    -IntunePath "Devices > Configuration Profiles > Settings Catalog > Account Policies Password Policy > Maximum Password Age = 60" `
                    -DirectFix "Configure via local security policy: secpol.msc > Account Policies > Password Policy"

                Add-AssessmentResult -ControlID "IA.1.003" -ControlName "Maximum Password Age" `
                    -Category "Identification and Authentication" -Status "Non-Compliant" `
                    -Finding "Maximum password age is $maxPasswordAge days (should be 60 or less)" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.5.8"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "IA.1.003" -ControlName "Maximum Password Age" `
                -Category "Identification and Authentication" -Status "Error" `
                -Finding "Unable to retrieve maximum password age" `
                -Remediation "Manually verify maximum password age is configured" `
                -Reference "NIST SP 800-171 3.5.8"
        }
    }

    # IA.1.004 - Password History
    if ($isCloudManaged) {
        Add-AssessmentResult -ControlID "IA.1.004" -ControlName "Password History" `
            -Category "Identification and Authentication" -Status "Compliant" `
            -Finding "Azure AD joined device - Password history enforced by Entra ID (prevents reuse of last 24 passwords by default)" `
            -Remediation "N/A - Enforced by Entra ID" `
            -Reference "NIST SP 800-171 3.5.8"
    }
    else {
        try {
            $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
            $passwordHistory = ($secpolContent | Select-String "PasswordHistorySize").ToString().Split('=')[1].Trim()
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

            if ([int]$passwordHistory -ge 24) {
                Add-AssessmentResult -ControlID "IA.1.004" -ControlName "Password History" `
                    -Category "Identification and Authentication" -Status "Compliant" `
                    -Finding "Password history remembers $passwordHistory passwords (meets requirement)" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.5.8"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > 'Enforce password history' = 24" `
                    -IntunePath "Devices > Configuration Profiles > Settings Catalog > Account Policies Password Policy > Enforce Password History = 24" `
                    -DirectFix "Configure via local security policy: secpol.msc > Account Policies > Password Policy"

                Add-AssessmentResult -ControlID "IA.1.004" -ControlName "Password History" `
                    -Category "Identification and Authentication" -Status "Non-Compliant" `
                    -Finding "Password history remembers $passwordHistory passwords (should be 24+)" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.5.8"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "IA.1.004" -ControlName "Password History" `
                -Category "Identification and Authentication" -Status "Error" `
                -Finding "Unable to retrieve password history setting" `
                -Remediation "Manually verify password history is configured" `
                -Reference "NIST SP 800-171 3.5.8"
        }
    }

    # IA.1.005 - Windows Hello / MFA
    $windowsHello = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled"
    $windowsHelloUser = Get-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\HelloForBusiness\State" -Name "EnvironmentState"

    if ($windowsHello -eq 1 -or $windowsHelloUser -eq 1) {
        Add-AssessmentResult -ControlID "IA.1.005" -ControlName "Multi-Factor Authentication (Windows Hello for Business)" `
            -Category "Identification and Authentication" -Status "Compliant" `
            -Finding "Windows Hello for Business (MFA) is enabled" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.5.3"
    } elseif ($script:ManagementInfo.IsAzureADJoined) {
        Add-AssessmentResult -ControlID "IA.1.005" -ControlName "Multi-Factor Authentication (Windows Hello for Business)" `
            -Category "Identification and Authentication" -Status "Partial" `
            -Finding "Windows Hello not detected locally. MFA may be enforced via Entra ID Conditional Access." `
            -Remediation "Enable Windows Hello for Business via Intune: Devices > Enrollment > Windows Enrollment > Windows Hello for Business = Enabled. Also verify Conditional Access policies require MFA." `
            -Reference "NIST SP 800-171 3.5.3"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Windows Hello for Business > Use Windows Hello for Business = Enabled" `
            -IntunePath "Devices > Enrollment > Windows Enrollment > Windows Hello for Business = Enabled" `
            -DirectFix "Enable Windows Hello for Business via Settings > Accounts > Sign-in options"

        Add-AssessmentResult -ControlID "IA.1.005" -ControlName "Multi-Factor Authentication (Windows Hello for Business)" `
            -Category "Identification and Authentication" -Status "Partial" `
            -Finding "Windows Hello not configured (MFA may be enforced at network/VPN level)" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.5.3"
    }
}

function Test-SystemCommunicationsProtection {
    Write-Host "`n=== SYSTEM AND COMMUNICATIONS PROTECTION (SC) ===" -ForegroundColor Cyan

    # SC.1.001 - Windows Firewall - Domain Profile
    try {
        $firewallDomain = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
        if ($firewallDomain.Enabled -eq $true) {
            Add-AssessmentResult -ControlID "SC.1.001" -ControlName "Firewall Enabled (Domain)" `
                -Category "System and Communications Protection" -Status "Compliant" `
                -Finding "Windows Firewall is enabled for Domain profile" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.13.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall > Domain Profile > Firewall state = On" `
                -IntunePath "Endpoint Security > Firewall > Windows Firewall > Domain Profile State = Enabled" `
                -DirectFix "Set-NetFirewallProfile -Profile Domain -Enabled True"

            Add-AssessmentResult -ControlID "SC.1.001" -ControlName "Firewall Enabled (Domain)" `
                -Category "System and Communications Protection" -Status "Non-Compliant" `
                -Finding "Windows Firewall is disabled for Domain profile" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.13.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SC.1.001" -ControlName "Firewall Enabled (Domain)" `
            -Category "System and Communications Protection" -Status "Error" `
            -Finding "Unable to retrieve firewall status" `
            -Remediation "Manually verify firewall is enabled" `
            -Reference "NIST SP 800-171 3.13.1"
    }

    # SC.1.002 - Windows Firewall - Private Profile
    try {
        $firewallPrivate = Get-NetFirewallProfile -Name Private -ErrorAction Stop
        if ($firewallPrivate.Enabled -eq $true) {
            Add-AssessmentResult -ControlID "SC.1.002" -ControlName "Firewall Enabled (Private)" `
                -Category "System and Communications Protection" -Status "Compliant" `
                -Finding "Windows Firewall is enabled for Private profile" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.13.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall > Private Profile > Firewall state = On" `
                -IntunePath "Endpoint Security > Firewall > Windows Firewall > Private Profile State = Enabled" `
                -DirectFix "Set-NetFirewallProfile -Profile Private -Enabled True"

            Add-AssessmentResult -ControlID "SC.1.002" -ControlName "Firewall Enabled (Private)" `
                -Category "System and Communications Protection" -Status "Non-Compliant" `
                -Finding "Windows Firewall is disabled for Private profile" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.13.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SC.1.002" -ControlName "Firewall Enabled (Private)" `
            -Category "System and Communications Protection" -Status "Error" `
            -Finding "Unable to retrieve firewall status" `
            -Remediation "Manually verify firewall is enabled" `
            -Reference "NIST SP 800-171 3.13.1"
    }

    # SC.1.003 - Windows Firewall - Public Profile
    try {
        $firewallPublic = Get-NetFirewallProfile -Name Public -ErrorAction Stop
        if ($firewallPublic.Enabled -eq $true) {
            Add-AssessmentResult -ControlID "SC.1.003" -ControlName "Firewall Enabled (Public)" `
                -Category "System and Communications Protection" -Status "Compliant" `
                -Finding "Windows Firewall is enabled for Public profile" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.13.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall > Public Profile > Firewall state = On" `
                -IntunePath "Endpoint Security > Firewall > Windows Firewall > Public Profile State = Enabled" `
                -DirectFix "Set-NetFirewallProfile -Profile Public -Enabled True"

            Add-AssessmentResult -ControlID "SC.1.003" -ControlName "Firewall Enabled (Public)" `
                -Category "System and Communications Protection" -Status "Non-Compliant" `
                -Finding "Windows Firewall is disabled for Public profile" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.13.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SC.1.003" -ControlName "Firewall Enabled (Public)" `
            -Category "System and Communications Protection" -Status "Error" `
            -Finding "Unable to retrieve firewall status" `
            -Remediation "Manually verify firewall is enabled" `
            -Reference "NIST SP 800-171 3.13.1"
    }

    # SC.1.004 - SMBv1 Disabled
    try {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($smbv1.State -eq "Disabled") {
            Add-AssessmentResult -ControlID "SC.1.004" -ControlName "SMBv1 Protocol Disabled" `
                -Category "System and Communications Protection" -Status "Compliant" `
                -Finding "SMBv1 protocol is disabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.13.8"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Administrative Templates > Network > Lanman Server > SMB 1.0 server = Disabled" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > SMB > SMB 1.0 Server = Disabled" `
                -DirectFix "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

            Add-AssessmentResult -ControlID "SC.1.004" -ControlName "SMBv1 Protocol Disabled" `
                -Category "System and Communications Protection" -Status "Non-Compliant" `
                -Finding "SMBv1 protocol is enabled (security risk)" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.13.8"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SC.1.004" -ControlName "SMBv1 Protocol Disabled" `
            -Category "System and Communications Protection" -Status "Error" `
            -Finding "Unable to check SMBv1 status" `
            -Remediation "Manually verify SMBv1 is disabled" `
            -Reference "NIST SP 800-171 3.13.8"
    }

    # SC.1.005 - Remote Desktop Configuration
    $rdpEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    $nlaRequired = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"

    if ($rdpEnabled -eq 1) {
        Add-AssessmentResult -ControlID "SC.1.005" -ControlName "Remote Desktop Security" `
            -Category "System and Communications Protection" -Status "Compliant" `
            -Finding "Remote Desktop is disabled (most secure)" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.13.8"
    }
    elseif ($rdpEnabled -eq 0 -and $nlaRequired -eq 1) {
        Add-AssessmentResult -ControlID "SC.1.005" -ControlName "Remote Desktop Security" `
            -Category "System and Communications Protection" -Status "Partial" `
            -Finding "Remote Desktop is enabled but requires NLA (Network Level Authentication)" `
            -Remediation "If RDP not needed, disable it. Otherwise ensure NLA remains enabled and use VPN/Azure Bastion/jumpbox for access." `
            -Reference "NIST SP 800-171 3.13.8"
    }
    else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections = Enabled" `
            -IntunePath "Devices > Configuration Profiles > Settings Catalog > Remote Desktop Services > Require User Authentication For Remote Connections = Enabled" `
            -DirectFix "Set HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1"

        Add-AssessmentResult -ControlID "SC.1.005" -ControlName "Remote Desktop Security" `
            -Category "System and Communications Protection" -Status "Non-Compliant" `
            -Finding "Remote Desktop is enabled without NLA (security risk)" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.13.8"
    }

    # SC.1.006 - TLS Version Configuration
    $tls10 = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled"
    $tls11 = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled"

    if ($tls10 -eq 0 -and $tls11 -eq 0) {
        Add-AssessmentResult -ControlID "SC.1.006" -ControlName "Insecure TLS Versions Disabled" `
            -Category "System and Communications Protection" -Status "Compliant" `
            -Finding "TLS 1.0 and 1.1 are disabled" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.13.8"
    }
    elseif ($tls10 -ne 1 -and $tls11 -ne 1) {
        Add-AssessmentResult -ControlID "SC.1.006" -ControlName "Insecure TLS Versions Disabled" `
            -Category "System and Communications Protection" -Status "Partial" `
            -Finding "TLS 1.0/1.1 configuration not explicitly set (may be disabled by default on Windows 11)" `
            -Remediation "Explicitly disable TLS 1.0 and 1.1 via Intune Settings Catalog or IIS Crypto tool" `
            -Reference "NIST SP 800-171 3.13.8"
    }
    else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > SSL Configuration Settings" `
            -IntunePath "Devices > Configuration Profiles > Settings Catalog > SCHANNEL > TLS 1.0/1.1 = Disabled (use PowerShell script deployment)" `
            -DirectFix "Use IIS Crypto tool or manually configure registry: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

        Add-AssessmentResult -ControlID "SC.1.006" -ControlName "Insecure TLS Versions Disabled" `
            -Category "System and Communications Protection" -Status "Non-Compliant" `
            -Finding "TLS 1.0 or 1.1 are enabled (security risk)" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.13.8"
    }

    # SC.1.007 - Bluetooth Configuration
    try {
        $bluetoothService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
        if ($bluetoothService.StartType -eq "Disabled") {
            Add-AssessmentResult -ControlID "SC.1.007" -ControlName "Bluetooth Service" `
                -Category "System and Communications Protection" -Status "Compliant" `
                -Finding "Bluetooth service is disabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.1.18"
        }
        elseif ($null -eq $bluetoothService) {
            Add-AssessmentResult -ControlID "SC.1.007" -ControlName "Bluetooth Service" `
                -Category "System and Communications Protection" -Status "Not Applicable" `
                -Finding "Bluetooth service not present on this system" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.1.18"
        }
        else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Windows Settings > Security Settings > System Services > Bluetooth Support Service = Disabled" `
                -IntunePath "Devices > Configuration Profiles > Settings Catalog > Bluetooth > Allow Bluetooth = Block" `
                -DirectFix "Set-Service bthserv -StartupType Disabled; Stop-Service bthserv"

            Add-AssessmentResult -ControlID "SC.1.007" -ControlName "Bluetooth Service" `
                -Category "System and Communications Protection" -Status "Partial" `
                -Finding "Bluetooth service is enabled (consider disabling if not required)" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.1.18"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SC.1.007" -ControlName "Bluetooth Service" `
            -Category "System and Communications Protection" -Status "Error" `
            -Finding "Unable to check Bluetooth service status" `
            -Remediation "Manually verify Bluetooth configuration" `
            -Reference "NIST SP 800-171 3.1.18"
    }
}

function Test-SystemInformationIntegrity {
    Write-Host "`n=== SYSTEM AND INFORMATION INTEGRITY (SI) ===" -ForegroundColor Cyan

    # SI.1.001 - Endpoint Protection (Antivirus/EDR)
    # Check for EDR solutions first (Blackpoint, MDE) as they may disable Defender AV
    if ($script:ManagementInfo.HasBlackpointCyber -or $script:ManagementInfo.HasDefenderForEndpoint) {
        $edrPlatforms = @()
        if ($script:ManagementInfo.HasBlackpointCyber) {
            $edrPlatforms += "Blackpoint Cyber EDR (Status: $($script:ManagementInfo.BlackpointStatus))"
        }
        if ($script:ManagementInfo.HasDefenderForEndpoint) {
            $mdeStatus = if ($script:ManagementInfo.DefenderForEndpointOnboarded) { "Onboarded" } else { "Not Onboarded" }
            $edrPlatforms += "Microsoft Defender for Endpoint ($mdeStatus, Service: $($script:ManagementInfo.DefenderForEndpointStatus))"
        }

        $edrFinding = "Enterprise EDR protection active: " + ($edrPlatforms -join " + ")

        # Check if all EDR platforms are operational
        $allEDROperational = $true
        if ($script:ManagementInfo.HasBlackpointCyber -and $script:ManagementInfo.BlackpointStatus -ne "Running") {
            $allEDROperational = $false
        }
        if ($script:ManagementInfo.HasDefenderForEndpoint) {
            if (-not $script:ManagementInfo.DefenderForEndpointOnboarded -or $script:ManagementInfo.DefenderForEndpointStatus -ne "Running") {
                $allEDROperational = $false
            }
        }

        if ($allEDROperational) {
            Add-AssessmentResult -ControlID "SI.1.001" -ControlName "Endpoint Protection (EDR/Antivirus)" `
                -Category "System and Information Integrity" -Status "Compliant" `
                -Finding $edrFinding `
                -Remediation "N/A - Enterprise EDR solutions provide advanced threat protection beyond traditional antivirus" `
                -Reference "NIST SP 800-171 3.14.1"
        } else {
            Add-AssessmentResult -ControlID "SI.1.001" -ControlName "Endpoint Protection (EDR/Antivirus)" `
                -Category "System and Information Integrity" -Status "Partial" `
                -Finding "$edrFinding - WARNING: One or more EDR platforms not fully operational" `
                -Remediation "Verify all EDR services are running. Check Blackpoint portal and/or MDE Security Center for device status." `
                -Reference "NIST SP 800-171 3.14.1"
        }
    }
    else {
        # Fallback to Windows Defender if no EDR detected
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop

            if ($defenderStatus.AntivirusEnabled -eq $true -and $defenderStatus.RealTimeProtectionEnabled -eq $true) {
                Add-AssessmentResult -ControlID "SI.1.001" -ControlName "Endpoint Protection (EDR/Antivirus)" `
                    -Category "System and Information Integrity" -Status "Compliant" `
                    -Finding "Windows Defender real-time protection is enabled" `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.14.1"
            } else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection > Turn on real-time protection = Enabled" `
                    -IntunePath "Endpoint Security > Antivirus > Microsoft Defender Antivirus > Real-time Protection = Enabled (or use Security Baseline)" `
                    -DirectFix "Set-MpPreference -DisableRealtimeMonitoring `$false"

                Add-AssessmentResult -ControlID "SI.1.001" -ControlName "Endpoint Protection (EDR/Antivirus)" `
                    -Category "System and Information Integrity" -Status "Non-Compliant" `
                    -Finding "Windows Defender real-time protection is disabled and no EDR solution detected" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.14.1"
            }
        }
        catch {
            Add-AssessmentResult -ControlID "SI.1.001" -ControlName "Endpoint Protection (EDR/Antivirus)" `
                -Category "System and Information Integrity" -Status "Error" `
                -Finding "Unable to retrieve Windows Defender status and no EDR solution detected" `
                -Remediation "Verify antivirus/EDR solution is installed and active. Install Blackpoint Cyber or enable Defender for Endpoint." `
                -Reference "NIST SP 800-171 3.14.1"
        }
    }

    # SI.1.002 - Antivirus Definition Updates
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated

        if ($signatureAge.Days -le 7) {
            Add-AssessmentResult -ControlID "SI.1.002" -ControlName "Antivirus Definition Currency" `
                -Category "System and Information Integrity" -Status "Compliant" `
                -Finding "Antivirus definitions updated $($signatureAge.Days) days ago (current)" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.14.1"
        } else {
            Add-AssessmentResult -ControlID "SI.1.002" -ControlName "Antivirus Definition Currency" `
                -Category "System and Information Integrity" -Status "Non-Compliant" `
                -Finding "Antivirus definitions last updated $($signatureAge.Days) days ago (outdated)" `
                -Remediation "Update definitions: Update-MpSignature. If Intune-managed, verify automatic updates are enabled in Endpoint Security > Antivirus policy." `
                -Reference "NIST SP 800-171 3.14.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SI.1.002" -ControlName "Antivirus Definition Currency" `
            -Category "System and Information Integrity" -Status "Error" `
            -Finding "Unable to retrieve antivirus signature status" `
            -Remediation "Manually verify antivirus definitions are current" `
            -Reference "NIST SP 800-171 3.14.1"
    }

    # SI.1.003 - Windows Update Configuration
    $autoUpdate = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"

    # Check if NinjaRMM is managing patches
    if ($script:ManagementInfo.HasNinjaRMM -and $script:ManagementInfo.PatchManagement -eq "NinjaRMM") {
        Add-AssessmentResult -ControlID "SI.1.003" -ControlName "Automatic Windows Updates" `
            -Category "System and Information Integrity" -Status "Compliant" `
            -Finding "Windows Update management delegated to NinjaRMM (RMM-managed patching detected)" `
            -Remediation "N/A - Verify patch policies are configured in NinjaRMM dashboard" `
            -Reference "NIST SP 800-171 3.14.1"
    }
    elseif ($autoUpdate -eq 0 -or $null -eq $autoUpdate) {
        Add-AssessmentResult -ControlID "SI.1.003" -ControlName "Automatic Windows Updates" `
            -Category "System and Information Integrity" -Status "Compliant" `
            -Finding "Automatic Windows Updates are enabled" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.14.1"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates = Enabled" `
            -IntunePath "Devices > Update Rings for Windows 10 and later > Create update ring with automatic updates enabled" `
            -DirectFix "Enable automatic updates via Settings > Update & Security > Windows Update"

        Add-AssessmentResult -ControlID "SI.1.003" -ControlName "Automatic Windows Updates" `
            -Category "System and Information Integrity" -Status "Non-Compliant" `
            -Finding "Automatic Windows Updates are disabled" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.14.1"
    }

    # SI.1.004 - Last Windows Update Install Date
    try {
        $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
        $updateAge = (Get-Date) - $lastUpdate.InstalledOn

        if ($updateAge.Days -le 35) {
            $finding = "Last update installed $($updateAge.Days) days ago (acceptable)"
            if ($script:ManagementInfo.HasNinjaRMM) {
                $finding += " - Managed via NinjaRMM"
            }

            Add-AssessmentResult -ControlID "SI.1.004" -ControlName "Recent Security Patches" `
                -Category "System and Information Integrity" -Status "Compliant" `
                -Finding $finding `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.14.1"
        } else {
            $remediation = "Install pending Windows updates immediately."

            if ($script:ManagementInfo.HasNinjaRMM) {
                $remediation = "System is $($updateAge.Days) days out of date. Verify patch policies in NinjaRMM dashboard and ensure device is checking in properly. Check NinjaRMM > Devices > [Device] > Patching tab."
            }
            elseif ($script:ManagementInfo.IsIntuneEnrolled) {
                $remediation = "Install pending Windows updates. Verify device is checking in to Intune and receiving update rings properly."
            }

            Add-AssessmentResult -ControlID "SI.1.004" -ControlName "Recent Security Patches" `
                -Category "System and Information Integrity" -Status "Non-Compliant" `
                -Finding "Last update installed $($updateAge.Days) days ago (outdated)" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.14.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SI.1.004" -ControlName "Recent Security Patches" `
            -Category "System and Information Integrity" -Status "Error" `
            -Finding "Unable to retrieve Windows update history" `
            -Remediation "Manually verify system is up to date" `
            -Reference "NIST SP 800-171 3.14.1"
    }

    # SI.1.005 - Windows Defender Exploit Protection
    try {
        $exploitProtection = Get-ProcessMitigation -System -ErrorAction Stop

        if ($exploitProtection.DEP.Enable -eq "ON" -or $exploitProtection.DEP.Enable -eq "NOTSET") {
            Add-AssessmentResult -ControlID "SI.1.005" -ControlName "Data Execution Prevention (DEP)" `
                -Category "System and Information Integrity" -Status "Compliant" `
                -Finding "Data Execution Prevention (DEP) is enabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.14.2"
        } else {
            Add-AssessmentResult -ControlID "SI.1.005" -ControlName "Data Execution Prevention (DEP)" `
                -Category "System and Information Integrity" -Status "Non-Compliant" `
                -Finding "Data Execution Prevention (DEP) is not enabled" `
                -Remediation "Enable DEP via system properties or bcdedit. If Intune-managed, configure via Endpoint Security > Attack Surface Reduction." `
                -Reference "NIST SP 800-171 3.14.2"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SI.1.005" -ControlName "Data Execution Prevention (DEP)" `
            -Category "System and Information Integrity" -Status "Error" `
            -Finding "Unable to retrieve exploit protection settings" `
            -Remediation "Manually verify DEP is enabled" `
            -Reference "NIST SP 800-171 3.14.2"
    }

    # SI.1.006 - Windows Defender Cloud Protection
    try {
        $cloudProtection = Get-MpPreference -ErrorAction Stop

        if ($cloudProtection.MAPSReporting -ne 0) {
            Add-AssessmentResult -ControlID "SI.1.006" -ControlName "Cloud-Delivered Protection" `
                -Category "System and Information Integrity" -Status "Compliant" `
                -Finding "Windows Defender cloud-delivered protection is enabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.14.1"
        } else {
            $remediation = Get-RemediationGuidance `
                -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > MAPS > Join Microsoft MAPS = Advanced MAPS" `
                -IntunePath "Endpoint Security > Antivirus > Microsoft Defender Antivirus > Cloud Protection Level = High (use Security Baseline)" `
                -DirectFix "Set-MpPreference -MAPSReporting Advanced"

            Add-AssessmentResult -ControlID "SI.1.006" -ControlName "Cloud-Delivered Protection" `
                -Category "System and Information Integrity" -Status "Partial" `
                -Finding "Windows Defender cloud-delivered protection is disabled" `
                -Remediation $remediation `
                -Reference "NIST SP 800-171 3.14.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "SI.1.006" -ControlName "Cloud-Delivered Protection" `
            -Category "System and Information Integrity" -Status "Error" `
            -Finding "Unable to retrieve cloud protection settings" `
            -Remediation "Manually verify cloud protection configuration" `
            -Reference "NIST SP 800-171 3.14.1"
    }
}

function Test-MediaProtection {
    Write-Host "`n=== MEDIA PROTECTION (MP) ===" -ForegroundColor Cyan

    # MP.1.001 - BitLocker Encryption Status
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq "OperatingSystem" }

        foreach ($volume in $volumes) {
            # Check if recovery key is backed up to Azure AD (for cloud-managed devices)
            $recoveryKeyBackedUp = $false
            if ($script:ManagementInfo.IsAzureADJoined) {
                try {
                    $bitlockerInfo = manage-bde -protectors -get $volume.MountPoint
                    if ($bitlockerInfo -match "AzureActiveDirectory") {
                        $recoveryKeyBackedUp = $true
                    }
                }
                catch { }
            }

            if ($volume.ProtectionStatus -eq "On" -and $volume.EncryptionPercentage -eq 100) {
                $finding = "BitLocker encryption is enabled and complete on $($volume.MountPoint)"
                if ($script:ManagementInfo.IsAzureADJoined -and $recoveryKeyBackedUp) {
                    $finding += " (Recovery key backed up to Azure AD)"
                }

                Add-AssessmentResult -ControlID "MP.1.001" -ControlName "Full Disk Encryption (BitLocker)" `
                    -Category "Media Protection" -Status "Compliant" `
                    -Finding $finding `
                    -Remediation "N/A" `
                    -Reference "NIST SP 800-171 3.8.9"
            }
            elseif ($volume.ProtectionStatus -eq "On" -and $volume.EncryptionPercentage -lt 100) {
                Add-AssessmentResult -ControlID "MP.1.001" -ControlName "Full Disk Encryption (BitLocker)" `
                    -Category "Media Protection" -Status "Partial" `
                    -Finding "BitLocker encryption in progress on $($volume.MountPoint) ($($volume.EncryptionPercentage)% complete)" `
                    -Remediation "Allow encryption to complete" `
                    -Reference "NIST SP 800-171 3.8.9"
            }
            else {
                $remediation = Get-RemediationGuidance `
                    -GPOPath "Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Operating System Drives > Require additional authentication at startup = Enabled" `
                    -IntunePath "Endpoint Security > Disk Encryption > BitLocker > Require Device Encryption = Yes (automatically backs up recovery key to Azure AD)" `
                    -DirectFix "Enable-BitLocker -MountPoint C: -RecoveryPasswordProtector"

                if ($script:ManagementInfo.IsAzureADJoined) {
                    $remediation = "Enable BitLocker via Intune: Endpoint Security > Disk Encryption > Create policy targeting Windows 10/11. Recovery keys will automatically backup to Azure AD."
                }

                Add-AssessmentResult -ControlID "MP.1.001" -ControlName "Full Disk Encryption (BitLocker)" `
                    -Category "Media Protection" -Status "Non-Compliant" `
                    -Finding "BitLocker encryption is not enabled on $($volume.MountPoint)" `
                    -Remediation $remediation `
                    -Reference "NIST SP 800-171 3.8.9"
            }
        }
    }
    catch {
        Add-AssessmentResult -ControlID "MP.1.001" -ControlName "Full Disk Encryption (BitLocker)" `
            -Category "Media Protection" -Status "Error" `
            -Finding "Unable to retrieve BitLocker status (may not be available on this edition)" `
            -Remediation "Verify BitLocker is available and enabled, or use alternative encryption" `
            -Reference "NIST SP 800-171 3.8.9"
    }

    # MP.1.002 - Removable Media Policy
    $removableMediaWrite = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_Write"

    if ($removableMediaWrite -eq 1) {
        Add-AssessmentResult -ControlID "MP.1.002" -ControlName "Removable Media Write Protection" `
            -Category "Media Protection" -Status "Compliant" `
            -Finding "Write access to removable media is restricted" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.8.7"
    }
    elseif ($null -eq $removableMediaWrite) {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > System > Removable Storage Access > All Removable Storage: Deny write access = Enabled" `
            -IntunePath "Endpoint Security > Attack Surface Reduction > Device Control > Removable Storage and USB devices policy" `
            -DirectFix "If CUI is handled, configure removable media restrictions"

        Add-AssessmentResult -ControlID "MP.1.002" -ControlName "Removable Media Write Protection" `
            -Category "Media Protection" -Status "Partial" `
            -Finding "Removable media policy not configured (consider implementing controls)" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.8.7"
    }
    else {
        Add-AssessmentResult -ControlID "MP.1.002" -ControlName "Removable Media Write Protection" `
            -Category "Media Protection" -Status "Partial" `
            -Finding "Removable media write access is allowed (ensure policies address CUI handling)" `
            -Remediation "Document removable media handling procedures for CUI" `
            -Reference "NIST SP 800-171 3.8.7"
    }
}

function Test-ConfigurationManagement {
    Write-Host "`n=== CONFIGURATION MANAGEMENT (CM) ===" -ForegroundColor Cyan

    # CM.1.001 - Secure Boot Status
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

        if ($secureBoot -eq $true) {
            Add-AssessmentResult -ControlID "CM.1.001" -ControlName "Secure Boot Enabled" `
                -Category "Configuration Management" -Status "Compliant" `
                -Finding "Secure Boot is enabled" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.4.8"
        } else {
            Add-AssessmentResult -ControlID "CM.1.001" -ControlName "Secure Boot Enabled" `
                -Category "Configuration Management" -Status "Non-Compliant" `
                -Finding "Secure Boot is disabled or not supported" `
                -Remediation "Enable Secure Boot in UEFI/BIOS settings (requires UEFI firmware). For Autopilot devices, Secure Boot should be enabled by default." `
                -Reference "NIST SP 800-171 3.4.8"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "CM.1.001" -ControlName "Secure Boot Enabled" `
            -Category "Configuration Management" -Status "Non-Compliant" `
            -Finding "Secure Boot not available (legacy BIOS mode)" `
            -Remediation "If possible, convert to UEFI and enable Secure Boot. Modern devices deployed via Autopilot should have UEFI/Secure Boot by default." `
            -Reference "NIST SP 800-171 3.4.8"
    }

    # CM.1.002 - Windows Version
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $buildNumber = [int]$osInfo.BuildNumber

        # Windows 10 22H2 (19045) or Windows 11 23H2 (22631) or newer
        if ($buildNumber -ge 19045) {
            Add-AssessmentResult -ControlID "CM.1.002" -ControlName "Supported Windows Version" `
                -Category "Configuration Management" -Status "Compliant" `
                -Finding "Running supported Windows version: $($osInfo.Caption) Build $buildNumber" `
                -Remediation "N/A" `
                -Reference "NIST SP 800-171 3.4.1"
        } else {
            Add-AssessmentResult -ControlID "CM.1.002" -ControlName "Supported Windows Version" `
                -Category "Configuration Management" -Status "Non-Compliant" `
                -Finding "Running unsupported/outdated Windows version: $($osInfo.Caption) Build $buildNumber" `
                -Remediation "Upgrade to Windows 10 22H2 or Windows 11. If Intune-managed, use Feature Update policies to orchestrate upgrades." `
                -Reference "NIST SP 800-171 3.4.1"
        }
    }
    catch {
        Add-AssessmentResult -ControlID "CM.1.002" -ControlName "Supported Windows Version" `
            -Category "Configuration Management" -Status "Error" `
            -Finding "Unable to retrieve Windows version information" `
            -Remediation "Manually verify Windows version is supported" `
            -Reference "NIST SP 800-171 3.4.1"
    }

    # CM.1.003 - Application Control / AppLocker
    $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

    if ($appLockerPolicy -and $appLockerPolicy.RuleCollections.Count -gt 0) {
        Add-AssessmentResult -ControlID "CM.1.003" -ControlName "Application Control Policy" `
            -Category "Configuration Management" -Status "Compliant" `
            -Finding "AppLocker or application control policy is configured" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.4.7"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker" `
            -IntunePath "Endpoint Security > Attack Surface Reduction > Application Control (deploy WDAC policy) or App Control for Business" `
            -DirectFix "Implement AppLocker or Windows Defender Application Control (WDAC) to restrict unauthorized software"

        Add-AssessmentResult -ControlID "CM.1.003" -ControlName "Application Control Policy" `
            -Category "Configuration Management" -Status "Partial" `
            -Finding "No AppLocker policy detected (consider implementing application control)" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.4.7"
    }

    # CM.1.004 - PowerShell Logging
    $psTranscription = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
    $psScriptBlockLogging = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"

    if ($psScriptBlockLogging -eq 1) {
        Add-AssessmentResult -ControlID "CM.1.004" -ControlName "PowerShell Logging" `
            -Category "Configuration Management" -Status "Compliant" `
            -Finding "PowerShell script block logging is enabled" `
            -Remediation "N/A" `
            -Reference "NIST SP 800-171 3.3.1"
    } else {
        $remediation = Get-RemediationGuidance `
            -GPOPath "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > 'Turn on PowerShell Script Block Logging' = Enabled" `
            -IntunePath "Devices > Configuration Profiles > Settings Catalog > Windows PowerShell > Turn On PowerShell Script Block Logging = Enabled" `
            -DirectFix "Set HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1"

        Add-AssessmentResult -ControlID "CM.1.004" -ControlName "PowerShell Logging" `
            -Category "Configuration Management" -Status "Non-Compliant" `
            -Finding "PowerShell script block logging is not enabled" `
            -Remediation $remediation `
            -Reference "NIST SP 800-171 3.3.1"
    }
}

#endregion

#region Report Generation

function New-HTMLReport {
    param(
        [array]$Results,
        [string]$OutputFile
    )

    $compliancePercentage = if ($script:TotalChecks -gt 0) {
        [math]::Round(($script:ComplianceScore / $script:TotalChecks) * 100, 2)
    } else { 0 }

    $compliantCount = ($Results | Where-Object { $_.Status -eq 'Compliant' }).Count
    $nonCompliantCount = ($Results | Where-Object { $_.Status -eq 'Non-Compliant' }).Count
    $partialCount = ($Results | Where-Object { $_.Status -eq 'Partial' }).Count
    $errorCount = ($Results | Where-Object { $_.Status -eq 'Error' }).Count
    $naCount = ($Results | Where-Object { $_.Status -eq 'Not Applicable' }).Count

    $statusColor = if ($compliancePercentage -ge 90) { '#28a745' }
                   elseif ($compliancePercentage -ge 70) { '#ffc107' }
                   else { '#dc3545' }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem

    # Management status badges
    $azureADBadge = if ($script:ManagementInfo.IsAzureADJoined) { '<span class="badge badge-success">Azure AD Joined</span>' } else { '<span class="badge badge-secondary">Not Azure AD Joined</span>' }
    $intuneBadge = if ($script:ManagementInfo.IsIntuneEnrolled) { '<span class="badge badge-success">Intune Enrolled</span>' } else { '<span class="badge badge-secondary">Not Intune Enrolled</span>' }
    $ninjaBadge = if ($script:ManagementInfo.HasNinjaRMM) { '<span class="badge badge-success">NinjaRMM Active</span>' } else { '<span class="badge badge-secondary">No RMM Detected</span>' }
    $blackpointBadge = if ($script:ManagementInfo.HasBlackpointCyber) {
        if ($script:ManagementInfo.BlackpointStatus -eq "Running") {
            '<span class="badge badge-success">Blackpoint Cyber Active</span>'
        } else {
            '<span class="badge badge-danger">Blackpoint Cyber (' + $script:ManagementInfo.BlackpointStatus + ')</span>'
        }
    } else {
        '<span class="badge badge-secondary">No Blackpoint</span>'
    }
    $mdeBadge = if ($script:ManagementInfo.HasDefenderForEndpoint) {
        if ($script:ManagementInfo.DefenderForEndpointOnboarded -and $script:ManagementInfo.DefenderForEndpointStatus -eq "Running") {
            '<span class="badge badge-success">MDE Onboarded</span>'
        } elseif ($script:ManagementInfo.DefenderForEndpointOnboarded) {
            '<span class="badge badge-warning">MDE Onboarded (Service: ' + $script:ManagementInfo.DefenderForEndpointStatus + ')</span>'
        } else {
            '<span class="badge badge-warning">MDE Not Onboarded</span>'
        }
    } else {
        '<span class="badge badge-secondary">No MDE</span>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMMC 2.0 Level 2 Assessment Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .management-status {
            background: white;
            margin: 20px 40px;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .management-status h2 {
            margin-bottom: 20px;
            color: #1e3c72;
        }
        .badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .badge-success {
            background: #28a745;
            color: white;
        }
        .badge-danger {
            background: #dc3545;
            color: white;
        }
        .badge-secondary {
            background: #6c757d;
            color: white;
        }
        .badge-info {
            background: #17a2b8;
            color: white;
        }
        .mgmt-detail {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .mgmt-detail strong {
            color: #666;
            display: inline-block;
            min-width: 150px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e3c72;
        }
        .compliance-score {
            background: white;
            margin: 20px 40px;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .compliance-score h2 {
            margin-bottom: 20px;
            color: #1e3c72;
        }
        .score-bar {
            height: 40px;
            background: #e9ecef;
            border-radius: 20px;
            overflow: hidden;
            position: relative;
        }
        .score-fill {
            height: 100%;
            background: $statusColor;
            transition: width 1s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.2em;
        }
        .system-info {
            background: white;
            margin: 20px 40px;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .system-info h2 {
            margin-bottom: 20px;
            color: #1e3c72;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        .info-item {
            display: flex;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .info-item strong {
            min-width: 150px;
            color: #666;
        }
        .results-section {
            margin: 20px 40px 40px 40px;
        }
        .category-section {
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .category-header {
            background: #1e3c72;
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .category-header:hover {
            background: #2a5298;
        }
        .category-content {
            padding: 20px;
        }
        .control-item {
            border-left: 4px solid #ddd;
            padding: 20px;
            margin-bottom: 15px;
            background: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }
        .control-item.compliant { border-left-color: #28a745; }
        .control-item.non-compliant { border-left-color: #dc3545; }
        .control-item.partial { border-left-color: #ffc107; }
        .control-item.error { border-left-color: #6c757d; }
        .control-item.na { border-left-color: #17a2b8; }
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .control-id {
            font-weight: bold;
            color: #1e3c72;
            font-size: 0.9em;
        }
        .control-name {
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
            flex-grow: 1;
            margin-left: 15px;
        }
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-badge.compliant { background: #28a745; color: white; }
        .status-badge.non-compliant { background: #dc3545; color: white; }
        .status-badge.partial { background: #ffc107; color: #333; }
        .status-badge.error { background: #6c757d; color: white; }
        .status-badge.na { background: #17a2b8; color: white; }
        .control-details {
            margin-top: 15px;
        }
        .detail-section {
            margin-bottom: 10px;
        }
        .detail-label {
            font-weight: bold;
            color: #666;
            display: inline-block;
            min-width: 120px;
        }
        .detail-value {
            color: #333;
        }
        .remediation {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 10px;
            border-radius: 0 5px 5px 0;
        }
        .remediation strong {
            color: #856404;
        }
        .reference {
            font-size: 0.85em;
            color: #666;
            font-style: italic;
            margin-top: 10px;
        }
        .footer {
            background: #1e3c72;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .category-content { display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CMMC 2.0 Level 2 Assessment Report</h1>
            <p>NIST SP 800-171 Rev 2 Compliance Evaluation</p>
            <p>Generated: $(Get-Date -Format "MMMM dd, yyyy HH:mm:ss")</p>
        </div>

        <div class="management-status">
            <h2>Device Management Status</h2>
            <div>
                $azureADBadge
                $intuneBadge
                <br>
                $ninjaBadge
                $blackpointBadge
                $mdeBadge
                <br>
                <span class="badge badge-info">$($script:ManagementInfo.ManagementType)</span>
            </div>
            <div class="mgmt-detail">
                <div><strong>Tenant Name:</strong> $($script:ManagementInfo.TenantName)</div>
                <div><strong>Tenant ID:</strong> $($script:ManagementInfo.TenantID)</div>
                <div><strong>Device ID:</strong> $($script:ManagementInfo.DeviceID)</div>
                <div><strong>Patch Management:</strong> $($script:ManagementInfo.PatchManagement)</div>
                <div><strong>EDR Platform:</strong> $($script:ManagementInfo.EDRPlatform)</div>
"@ + $(if ($script:ManagementInfo.HasNinjaRMM) { @"
                <div><strong>NinjaRMM Version:</strong> $($script:ManagementInfo.NinjaRMMVersion)</div>
"@ } else { "" }) + $(if ($script:ManagementInfo.HasBlackpointCyber) { @"
                <div><strong>Blackpoint Cyber:</strong> Version $($script:ManagementInfo.BlackpointVersion), Status: $($script:ManagementInfo.BlackpointStatus)</div>
"@ } else { "" }) + $(if ($script:ManagementInfo.HasDefenderForEndpoint) {
    $mdeOnboardText = if ($script:ManagementInfo.DefenderForEndpointOnboarded) { "Onboarded" } else { "Not Onboarded" }
    @"
                <div><strong>Defender for Endpoint:</strong> $mdeOnboardText, Service: $($script:ManagementInfo.DefenderForEndpointStatus)</div>
"@ } else { "" }) + @"
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Compliant</h3>
                <div class="value" style="color: #28a745;">$compliantCount</div>
            </div>
            <div class="summary-card">
                <h3>Non-Compliant</h3>
                <div class="value" style="color: #dc3545;">$nonCompliantCount</div>
            </div>
            <div class="summary-card">
                <h3>Partial/Warning</h3>
                <div class="value" style="color: #ffc107;">$partialCount</div>
            </div>
            <div class="summary-card">
                <h3>Total Checks</h3>
                <div class="value">$($script:TotalChecks)</div>
            </div>
        </div>

        <div class="compliance-score">
            <h2>Overall Compliance Score</h2>
            <div class="score-bar">
                <div class="score-fill" style="width: $compliancePercentage%; background: $statusColor;">
                    $compliancePercentage%
                </div>
            </div>
        </div>

        <div class="system-info">
            <h2>System Information</h2>
            <div class="info-grid">
                <div class="info-item"><strong>Computer Name:</strong> $($computerInfo.Name)</div>
                <div class="info-item"><strong>Operating System:</strong> $($osInfo.Caption)</div>
                <div class="info-item"><strong>OS Version:</strong> $($osInfo.Version)</div>
                <div class="info-item"><strong>Build Number:</strong> $($osInfo.BuildNumber)</div>
                <div class="info-item"><strong>Manufacturer:</strong> $($computerInfo.Manufacturer)</div>
                <div class="info-item"><strong>Model:</strong> $($computerInfo.Model)</div>
                <div class="info-item"><strong>Domain:</strong> $($computerInfo.Domain)</div>
                <div class="info-item"><strong>Assessment Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
            </div>
        </div>

        <div class="results-section">
            <h2 style="margin-bottom: 20px; color: #1e3c72;">Assessment Results by Category</h2>
"@

    # Group results by category
    $categories = $Results | Group-Object -Property Category | Sort-Object Name

    foreach ($category in $categories) {
        $categoryName = $category.Name
        $categoryResults = $category.Group

        $html += @"
            <div class="category-section">
                <div class="category-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                    <span>$categoryName</span>
                    <span>▼</span>
                </div>
                <div class="category-content">
"@

        foreach ($result in $categoryResults) {
            $statusClass = $result.Status.ToLower() -replace '\s', '-' -replace 'not-applicable', 'na'
            $statusDisplay = $result.Status -replace 'Not Applicable', 'N/A'

            $html += @"
                    <div class="control-item $statusClass">
                        <div class="control-header">
                            <span class="control-id">$($result.ControlID)</span>
                            <span class="control-name">$($result.ControlName)</span>
                            <span class="status-badge $statusClass">$statusDisplay</span>
                        </div>
                        <div class="control-details">
                            <div class="detail-section">
                                <span class="detail-label">Finding:</span>
                                <span class="detail-value">$($result.Finding)</span>
                            </div>
"@

            if ($result.Status -eq 'Non-Compliant' -or $result.Status -eq 'Partial' -or $result.Status -eq 'Error') {
                $html += @"
                            <div class="remediation">
                                <strong>Remediation:</strong> $($result.Remediation)
                            </div>
"@
            }

            $html += @"
                            <div class="reference">Reference: $($result.Reference)</div>
                        </div>
                    </div>
"@
        }

        $html += @"
                </div>
            </div>
"@
    }

    $html += @"
        </div>

        <div class="footer">
            <p><strong>CMMC 2.0 Level 2 Assessment Report (v2.0 - Cloud-Aware)</strong></p>
            <p>This assessment evaluates technical controls for both traditional and cloud-managed (Azure AD/Intune) devices.</p>
            <p>Administrative and procedural controls require manual verification.</p>
            <p>Consult with a Certified CMMC Professional (CCP) or Certified CMMC Assessor (CCA) for official certification.</p>
        </div>
    </div>

    <script>
        // Collapse all categories by default except first one
        document.addEventListener('DOMContentLoaded', function() {
            const categoryContents = document.querySelectorAll('.category-content');
            for (let i = 1; i < categoryContents.length; i++) {
                categoryContents[i].style.display = 'none';
            }
        });
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}

function Export-JSONReport {
    param(
        [array]$Results,
        [string]$OutputFile
    )

    $compliancePercentage = if ($script:TotalChecks -gt 0) {
        [math]::Round(($script:ComplianceScore / $script:TotalChecks) * 100, 2)
    } else { 0 }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem

    # Build JSON object
    $jsonObject = [PSCustomObject]@{
        AssessmentMetadata = [PSCustomObject]@{
            ComputerName = $computerInfo.Name
            AssessmentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            ScriptVersion = "2.1"
            Framework = "CMMC 2.0 Level 2 (NIST SP 800-171)"
        }
        ComplianceSummary = [PSCustomObject]@{
            OverallScore = $compliancePercentage
            TotalChecks = $script:TotalChecks
            CompliantCount = ($Results | Where-Object { $_.Status -eq 'Compliant' }).Count
            NonCompliantCount = ($Results | Where-Object { $_.Status -eq 'Non-Compliant' }).Count
            PartialCount = ($Results | Where-Object { $_.Status -eq 'Partial' }).Count
            ErrorCount = ($Results | Where-Object { $_.Status -eq 'Error' }).Count
            NotApplicableCount = ($Results | Where-Object { $_.Status -eq 'Not Applicable' }).Count
        }
        SystemInformation = [PSCustomObject]@{
            ComputerName = $computerInfo.Name
            OperatingSystem = $osInfo.Caption
            OSVersion = $osInfo.Version
            BuildNumber = $osInfo.BuildNumber
            Manufacturer = $computerInfo.Manufacturer
            Model = $computerInfo.Model
            Domain = $computerInfo.Domain
        }
        ManagementStatus = [PSCustomObject]@{
            ManagementType = $script:ManagementInfo.ManagementType
            IsAzureADJoined = $script:ManagementInfo.IsAzureADJoined
            IsIntuneEnrolled = $script:ManagementInfo.IsIntuneEnrolled
            TenantName = $script:ManagementInfo.TenantName
            TenantID = $script:ManagementInfo.TenantID
            DeviceID = $script:ManagementInfo.DeviceID
            PatchManagement = $script:ManagementInfo.PatchManagement
            HasNinjaRMM = $script:ManagementInfo.HasNinjaRMM
            NinjaRMMVersion = $script:ManagementInfo.NinjaRMMVersion
            EDRPlatform = $script:ManagementInfo.EDRPlatform
            HasBlackpointCyber = $script:ManagementInfo.HasBlackpointCyber
            BlackpointStatus = $script:ManagementInfo.BlackpointStatus
            HasDefenderForEndpoint = $script:ManagementInfo.HasDefenderForEndpoint
            DefenderForEndpointOnboarded = $script:ManagementInfo.DefenderForEndpointOnboarded
        }
        ControlResults = $Results | ForEach-Object {
            [PSCustomObject]@{
                ControlID = $_.ControlID
                ControlName = $_.ControlName
                Category = $_.Category
                Status = $_.Status
                Finding = $_.Finding
                Remediation = $_.Remediation
                Reference = $_.Reference
                Timestamp = $_.Timestamp
            }
        }
        CategorySummary = ($Results | Group-Object -Property Category | ForEach-Object {
            $categoryResults = $_.Group
            [PSCustomObject]@{
                Category = $_.Name
                TotalChecks = $categoryResults.Count
                Compliant = ($categoryResults | Where-Object { $_.Status -eq 'Compliant' }).Count
                NonCompliant = ($categoryResults | Where-Object { $_.Status -eq 'Non-Compliant' }).Count
                Partial = ($categoryResults | Where-Object { $_.Status -eq 'Partial' }).Count
                CompliancePercentage = if ($categoryResults.Count -gt 0) {
                    [math]::Round((($categoryResults | Where-Object { $_.Status -eq 'Compliant' }).Count / $categoryResults.Count) * 100, 2)
                } else { 0 }
            }
        })
    }

    # Export to JSON
    $jsonObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
}

#endregion

#region Main Execution

try {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     CMMC 2.0 LEVEL 2 COMPLIANCE ASSESSMENT TOOL  v2.0        ║" -ForegroundColor Cyan
    Write-Host "║     NIST SP 800-171 Rev 2 Technical Controls                 ║" -ForegroundColor Cyan
    Write-Host "║     Cloud-Aware (Azure AD + Intune Support)                  ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`nAssessing: $ComputerName" -ForegroundColor Yellow
    Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host ""

    # Detect device management status
    $script:ManagementInfo = Get-DeviceManagementStatus

    # Run all assessment functions
    Test-AccessControl
    Test-AuditAccountability
    Test-IdentificationAuthentication
    Test-SystemCommunicationsProtection
    Test-SystemInformationIntegrity
    Test-MediaProtection
    Test-ConfigurationManagement

    # Generate Reports
    Write-Host "`n" -NoNewline
    Write-Host "═" -NoNewline -ForegroundColor Cyan
    Write-Host "═" * 61 -ForegroundColor Cyan

    $reportFile = $null
    $jsonFile = $null

    # Generate HTML Report (unless skipped)
    if (-not $SkipHTMLReport) {
        $reportFile = Join-Path -Path $OutputPath -ChildPath "CMMC2_Assessment_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        Write-Host "`nGenerating HTML report..." -ForegroundColor Yellow
        New-HTMLReport -Results $script:AssessmentResults -OutputFile $reportFile
    }

    # Generate JSON Report (if requested)
    if ($ExportJSON) {
        if ($JSONOutputPath) {
            $jsonFile = $JSONOutputPath
        } else {
            $jsonFile = Join-Path -Path $OutputPath -ChildPath "CMMC2_Assessment_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        }
        Write-Host "`nGenerating JSON report..." -ForegroundColor Yellow
        Export-JSONReport -Results $script:AssessmentResults -OutputFile $jsonFile
    }

    # Summary
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    ASSESSMENT COMPLETE                        ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

    $compliancePercentage = [math]::Round(($script:ComplianceScore / $script:TotalChecks) * 100, 2)

    Write-Host "`nCompliance Score: " -NoNewline
    $scoreColor = if ($compliancePercentage -ge 90) { 'Green' }
                  elseif ($compliancePercentage -ge 70) { 'Yellow' }
                  else { 'Red' }
    Write-Host "$compliancePercentage%" -ForegroundColor $scoreColor

    Write-Host "`nResults Summary:"
    Write-Host "  Compliant:     " -NoNewline
    Write-Host "$script:ComplianceScore" -ForegroundColor Green
    Write-Host "  Non-Compliant: " -NoNewline
    Write-Host "$(($script:AssessmentResults | Where-Object { $_.Status -eq 'Non-Compliant' }).Count)" -ForegroundColor Red
    Write-Host "  Partial:       " -NoNewline
    Write-Host "$(($script:AssessmentResults | Where-Object { $_.Status -eq 'Partial' }).Count)" -ForegroundColor Yellow
    Write-Host "  Total Checks:  $script:TotalChecks"

    Write-Host "`nManagement Type: " -NoNewline
    Write-Host "$($script:ManagementInfo.ManagementType)" -ForegroundColor Cyan

    Write-Host "`nReport Location: " -NoNewline
    Write-Host $reportFile -ForegroundColor Cyan

    Write-Host "`nOpening report in default browser..." -ForegroundColor Yellow
    Start-Process $reportFile

    Write-Host "`nNote: This assessment evaluates technical controls for cloud-managed and traditional devices." -ForegroundColor Yellow
    Write-Host "Administrative, physical, and procedural controls require manual verification." -ForegroundColor Yellow
    Write-Host "Consult with a Certified CMMC Professional (CCP) for complete assessment.`n" -ForegroundColor Yellow
}
catch {
    Write-Host "`n[ERROR] Assessment failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion
