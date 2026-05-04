<#
.SYNOPSIS
Drain a Hyper-V failover cluster node, reboot it, and auto-resume the cluster after boot.

.DESCRIPTION
Pushed by NinjaOne (or run manually elevated). Phase=Drain runs preflight, drains the node
via Suspend-ClusterNode -Drain, persists state, registers an AtStartup scheduled task that
will run Phase=Resume after the reboot, then reboots. Phase=Resume (run by the scheduled
task at next boot) waits for the cluster service to be ready, runs Resume-ClusterNode
with the configured Failback policy, archives state, and unregisters its task.

Strict by default: if any VM owned by this node can't Live Migrate to its target node,
the script aborts before any cluster state changes. No fallback to SaveState/TurnOff
unless -SkipLiveMigrationCheck is supplied.

.PARAMETER Phase
Drain (default, what NinjaOne pushes) or Resume (what the boot task supplies).

.PARAMETER DrainTimeoutMinutes
Hard timeout on Suspend-ClusterNode -Drain. Range 5-480. Default 60.

.PARAMETER FailbackMode
Mapped to Resume-ClusterNode -Failback. Policy | Immediate | NoFailback. Default Policy.

.PARAMETER ResumeReadyTimeoutMinutes
How long the Resume phase waits for ClusSvc + Get-Cluster to be ready. Default 5.

.PARAMETER DryRun
Drain phase only. Runs preflight + LM eligibility checks, logs what would be drained,
exits 0 without calling Suspend or scheduling reboot.

.PARAMETER Force
Bypass idempotency checks. Cleans any stale state.json and any existing
\ClusterDrain\ResumeAfterReboot scheduled task before proceeding. Logged loudly.
Does not skip safety checks.

.PARAMETER SkipLiveMigrationCheck
Skip preflight Live Migration eligibility check. Use only if VMs are pre-validated
or non-LM transport (and the resulting downtime) is acceptable. Logged loudly.

.EXAMPLE
.\Invoke-ClusterNodeDrainReboot.ps1
Standard NinjaOne push. Drain -> reboot -> resume.

.EXAMPLE
.\Invoke-ClusterNodeDrainReboot.ps1 -DryRun
Smoke-test before a real maintenance window.

.EXAMPLE
.\Invoke-ClusterNodeDrainReboot.ps1 -Force
Recover from a stuck previous run.

.NOTES
Exit codes:
  0  Success
  1  Preflight failure (no reboot)
  2  Drain failed (rolled back, no reboot)
  3  State persistence or task registration failed (rolled back, no reboot)
  4  Drain timeout (rolled back, no reboot)
  5  Already in progress (state.json or task exists, no -Force)
  10 Cluster service not ready within timeout (Resume phase)
  11 State file missing or invalid (Resume phase)
  12 Resume-ClusterNode failed (Resume phase)
  13 Post-resume verification failed (Resume phase)
  99 Unhandled exception
#>

[CmdletBinding()]
param(
    [ValidateSet('Drain','Resume')]
    [string]$Phase = 'Drain',

    [ValidateRange(5, 480)]
    [int]$DrainTimeoutMinutes = 60,

    [ValidateSet('Policy','Immediate','NoFailback')]
    [string]$FailbackMode = 'Policy',

    [int]$ResumeReadyTimeoutMinutes = 5,

    [switch]$DryRun,
    [switch]$Force,
    [switch]$SkipLiveMigrationCheck
)

$ErrorActionPreference = 'Stop'

#region --- Constants ---
$script:StateDir     = Join-Path $env:ProgramData 'ClusterDrain'
$script:StatePath    = Join-Path $script:StateDir 'state.json'
$script:TaskFolder   = '\ClusterDrain\'
$script:TaskName     = 'ResumeAfterReboot'
$script:EventSource  = 'ClusterDrain'
$script:EventLogName = 'Application'
$script:LogRetentionDays = 30
$script:ResumeTaskBootDelaySeconds = 90
#endregion

#region --- Main ---
try {
    if ($Phase -eq 'Drain') {
        Write-Output 'Drain phase stub. Implementation pending.'
        exit 0
    }
    else {
        Write-Output 'Resume phase stub. Implementation pending.'
        exit 0
    }
}
catch {
    Write-Error "Unhandled exception: $_"
    exit 99
}
#endregion
