#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Diagnoses Intune enrollment and compliance status
.DESCRIPTION
    Checks multiple registry locations and methods to determine Intune compliance
#>

Write-Host "`n=== INTUNE ENROLLMENT & COMPLIANCE DIAGNOSTIC ===" -ForegroundColor Cyan

# Check 1: Enrollment Status
Write-Host "`n[1] Checking Intune Enrollment..." -ForegroundColor Yellow
$intuneKey = "HKLM:\SOFTWARE\Microsoft\Enrollments"
if (Test-Path $intuneKey) {
    $enrollments = Get-ChildItem -Path $intuneKey -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $upn = Get-ItemProperty -Path $enrollment.PSPath -Name "UPN" -ErrorAction SilentlyContinue
        $providerID = Get-ItemProperty -Path $enrollment.PSPath -Name "ProviderID" -ErrorAction SilentlyContinue

        if ($providerID.ProviderID -like "*MS DM Server*" -or $providerID.ProviderID -eq "MS DM Server") {
            Write-Host "  ✓ Found Intune Enrollment" -ForegroundColor Green
            Write-Host "    Enrollment GUID: $($enrollment.PSChildName)" -ForegroundColor Gray
            Write-Host "    UPN: $($upn.UPN)" -ForegroundColor Gray
            Write-Host "    Provider: $($providerID.ProviderID)" -ForegroundColor Gray

            $enrollmentPath = $enrollment.PSPath
        }
    }
} else {
    Write-Host "  ✗ No enrollments found" -ForegroundColor Red
}

# Check 2: Compliance State in Enrollment Key
Write-Host "`n[2] Checking Compliance State (Method 1 - Enrollment Key)..." -ForegroundColor Yellow
if ($enrollmentPath) {
    $complianceState = Get-ItemProperty -Path $enrollmentPath -Name "DeviceComplianceState" -ErrorAction SilentlyContinue
    if ($complianceState) {
        Write-Host "  ✓ DeviceComplianceState found: $($complianceState.DeviceComplianceState)" -ForegroundColor Green
        if ($complianceState.DeviceComplianceState -eq 1) {
            Write-Host "    Status: COMPLIANT" -ForegroundColor Green
        } else {
            Write-Host "    Status: NON-COMPLIANT" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⚠ DeviceComplianceState not found in enrollment key" -ForegroundColor Yellow
    }
}

# Check 3: Alternative Compliance Locations
Write-Host "`n[3] Checking Compliance State (Method 2 - PolicyManager)..." -ForegroundColor Yellow
$policyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceStatus",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\device\DeviceStatus"
)

foreach ($path in $policyPaths) {
    if (Test-Path $path) {
        Write-Host "  Found PolicyManager path: $path" -ForegroundColor Gray
        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -like "*Complian*" } | ForEach-Object {
                Write-Host "    $($_.Name) = $($_.Value)" -ForegroundColor Gray
            }
        }
    }
}

# Check 4: Device Compliance via WMI/CIM
Write-Host "`n[4] Checking via WMI (MDM_DevDetail_Ext01)..." -ForegroundColor Yellow
try {
    $mdmDevDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -ErrorAction Stop
    if ($mdmDevDetail) {
        Write-Host "  ✓ MDM Device Details found" -ForegroundColor Green
        Write-Host "    Device Name: $($mdmDevDetail.DeviceName)" -ForegroundColor Gray
        Write-Host "    Device ID: $($mdmDevDetail.DeviceHwData)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ⚠ Unable to query MDM WMI class" -ForegroundColor Yellow
}

# Check 5: Intune Management Extension (IME) Status
Write-Host "`n[5] Checking Intune Management Extension..." -ForegroundColor Yellow
$imeService = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
if ($imeService) {
    Write-Host "  ✓ Intune Management Extension: $($imeService.Status)" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Intune Management Extension service not found" -ForegroundColor Yellow
}

# Check 6: Last Sync Time
Write-Host "`n[6] Checking Last Sync with Intune..." -ForegroundColor Yellow
if ($enrollmentPath) {
    $lastSync = Get-ItemProperty -Path "$enrollmentPath\Poll" -Name "LastSuccessfulSync" -ErrorAction SilentlyContinue
    if ($lastSync) {
        $syncTime = [DateTime]::FromFileTime($lastSync.LastSuccessfulSync)
        $timeSince = (Get-Date) - $syncTime

        Write-Host "  ✓ Last successful sync: $syncTime" -ForegroundColor Green
        Write-Host "    Time since sync: $($timeSince.Hours) hours, $($timeSince.Minutes) minutes ago" -ForegroundColor Gray

        if ($timeSince.TotalHours -gt 24) {
            Write-Host "  ⚠ WARNING: Device hasn't synced in over 24 hours!" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ⚠ Unable to determine last sync time" -ForegroundColor Yellow
    }
}

# Check 7: Check for Compliance Policies
Write-Host "`n[7] Checking for Applied Compliance Policies..." -ForegroundColor Yellow
$compliancePolicyPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
if (Test-Path $compliancePolicyPath) {
    $policies = Get-ChildItem -Path $compliancePolicyPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*Compliance*" }

    if ($policies.Count -gt 0) {
        Write-Host "  ✓ Found $($policies.Count) compliance-related policy entries" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ No compliance policies found in registry" -ForegroundColor Yellow
    }
}

# Check 8: Task Scheduler - Intune Sync Tasks
Write-Host "`n[8] Checking Intune Scheduled Tasks..." -ForegroundColor Yellow
$intuneTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -like "*Microsoft*Intune*" -or
    $_.TaskName -like "*Intune*" -or
    $_.TaskPath -like "*Microsoft*Windows*EnterpriseMgmt*"
}

if ($intuneTasks) {
    Write-Host "  ✓ Found $($intuneTasks.Count) Intune-related tasks:" -ForegroundColor Green
    foreach ($task in $intuneTasks) {
        Write-Host "    - $($task.TaskName): $($task.State)" -ForegroundColor Gray
    }
} else {
    Write-Host "  ⚠ No Intune scheduled tasks found" -ForegroundColor Yellow
}

# Summary and Recommendations
Write-Host "`n=== SUMMARY & RECOMMENDATIONS ===" -ForegroundColor Cyan

if ($enrollmentPath -and $imeService.Status -eq "Running") {
    Write-Host "✓ Device appears to be properly enrolled in Intune" -ForegroundColor Green

    if (-not $complianceState) {
        Write-Host "`n⚠ Compliance state is not available in the expected registry location." -ForegroundColor Yellow
        Write-Host "  This could mean:" -ForegroundColor Yellow
        Write-Host "  1. Compliance evaluation hasn't run yet (wait 8-24 hours after enrollment)" -ForegroundColor Gray
        Write-Host "  2. No compliance policies are assigned to this device" -ForegroundColor Gray
        Write-Host "  3. Compliance data is stored in a different location" -ForegroundColor Gray
        Write-Host "`n  Recommended Actions:" -ForegroundColor Cyan
        Write-Host "  - Check Intune portal (endpoint.microsoft.com > Devices > All devices > [YourDevice] > Compliance)" -ForegroundColor Gray
        Write-Host "  - Force a sync: Settings > Accounts > Access work or school > [Account] > Info > Sync" -ForegroundColor Gray
        Write-Host "  - Wait 8-24 hours if device was recently enrolled" -ForegroundColor Gray
    }
} else {
    Write-Host "✗ Device does not appear to be properly enrolled in Intune" -ForegroundColor Red
}

Write-Host "`nTo force an Intune sync manually:" -ForegroundColor Yellow
Write-Host "  1. Open Settings > Accounts > Access work or school" -ForegroundColor Gray
Write-Host "  2. Click on your work account" -ForegroundColor Gray
Write-Host "  3. Click 'Info' button" -ForegroundColor Gray
Write-Host "  4. Scroll down and click 'Sync'" -ForegroundColor Gray
Write-Host "  5. Wait 5-10 minutes and run this diagnostic again" -ForegroundColor Gray

Write-Host "`nFor detailed compliance status, check the Intune portal:" -ForegroundColor Yellow
Write-Host "  https://endpoint.microsoft.com > Devices > All devices > [Search for your device]`n" -ForegroundColor Cyan
