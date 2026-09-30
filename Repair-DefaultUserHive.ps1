#requires -RunAsAdministrator
<#
.SYNOPSIS
    Releases an orphaned default-user registry hive that blocks creation of
    new virtual service account profiles.

.DESCRIPTION
    Symptom this fixes:
        - Service installs fail because the service can't reach Running.
        - Application log fills with Microsoft-Windows-User Profiles General
          event 1509: "Windows cannot copy file C:\Users\Default\NTUSER.DAT
          to location C:\Windows\ServiceProfiles\<svc>\NTUSER.DAT.
          The process cannot access the file because it is being used by
          another process."
        - Followed by 1511 ("logging on with a temporary profile") and SCM
          7000/7009 ("service did not respond ... in a timely fashion").
        - Common visible failure: Power BI on-premises data gateway install
          rolls back with MSI error 1920 / exit code 1603.

    Root cause:
        A prior script ran `reg load HKU\DefaultUser C:\Users\Default\NTUSER.DAT`
        to apply settings into the default profile, but never ran the matching
        `reg unload`. The kernel registry subsystem keeps an exclusive lock on
        the .DAT file - invisible to handle.exe / Process Explorer because it
        is not a user-mode file handle - so User Profile Service can no longer
        copy the default hive when initializing any new virtual service account
        profile.

    This script detects HKU\DefaultUser, unloads it, then verifies the lock on
    Default\NTUSER.DAT is released by attempting a copy.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$mount  = 'DefaultUser'
$source = 'C:\Users\Default\NTUSER.DAT'

$loaded = (reg query HKU) -match "^HKEY_USERS\\$mount\b"
if (-not $loaded) {
    Write-Host "HKU\$mount is not loaded - nothing to do." -ForegroundColor Green
    return
}

Write-Host "Unloading HKU\$mount ..." -ForegroundColor Yellow
& reg.exe unload "HKU\$mount"
if ($LASTEXITCODE -ne 0) { throw "reg unload HKU\$mount failed (exit $LASTEXITCODE)" }

$test = Join-Path $env:TEMP ([guid]::NewGuid().ToString() + '.dat')
try {
    Copy-Item $source $test -Force
    Remove-Item $test -Force
    Write-Host "Lock released - $source is now copyable. New service profiles will create normally." -ForegroundColor Green
} catch {
    Write-Warning "$source is still locked after unload. Another mountpoint or agent is holding it: $($_.Exception.Message)"
    Write-Host "Investigate with:  reg query HKU      and      handle.exe -a 'Default\NTUSER.DAT'"
}
