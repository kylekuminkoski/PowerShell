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

#region --- Logging ---
$script:LogPath = $null  # Set by Initialize-Transcript

function Format-LogLine {
    param(
        [Parameter(Mandatory)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[{0}] [{1}] {2}" -f $ts, $Level, $Message
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = Format-LogLine -Level $Level -Message $Message
    Write-Output $line
    if ($Level -eq 'ERROR') { Write-Error $Message -ErrorAction Continue }
    elseif ($Level -eq 'WARN') { Write-Warning $Message }
}

function Get-LogPath {
    param([Parameter(Mandatory)][ValidateSet('drain','resume')][string]$PhaseName)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    Join-Path $script:StateDir ("{0}-{1}.log" -f $PhaseName, $stamp)
}

function Initialize-Transcript {
    param([Parameter(Mandatory)][ValidateSet('drain','resume')][string]$PhaseName)
    if (-not (Test-Path $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }
    $script:LogPath = Get-LogPath -PhaseName $PhaseName
    Start-Transcript -Path $script:LogPath -Append | Out-Null
    Write-Log "Transcript started at $script:LogPath"
}

function Stop-ScriptTranscript {
    try { Stop-Transcript | Out-Null } catch { }
}

function Remove-OldLogs {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][int]$RetentionDays
    )
    if (-not (Test-Path $Directory)) { return }
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -Path $Directory -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
#endregion

#region --- Main ---
if ($MyInvocation.InvocationName -eq '.') { return }

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
