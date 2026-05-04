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

#region --- Path & State ---
function Initialize-StateDir {
    if (-not (Test-Path $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }
}

function Get-ScriptHash {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function New-StateObject {
    param(
        [Parameter(Mandatory)][string]$NodeName,
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][string]$DrainStartedAt,
        [Parameter(Mandatory)][string]$FailbackMode,
        [Parameter(Mandatory)][int]$DrainTimeoutMinutes,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ScriptHash,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$RolesAtDrainStart
    )
    [pscustomobject]@{
        schemaVersion       = 1
        nodeName            = $NodeName
        clusterName         = $ClusterName
        drainStartedAt      = $DrainStartedAt
        drainCompletedAt    = $null
        failbackMode        = $FailbackMode
        drainTimeoutMinutes = $DrainTimeoutMinutes
        scriptPath          = $ScriptPath
        scriptHash          = $ScriptHash
        rolesAtDrainStart   = $RolesAtDrainStart
        rebootRequestedAt   = $null
        resumeStartedAt     = $null
        resumeCompletedAt   = $null
    }
}

function Save-StateAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$State
    )
    $tmp = "$Path.tmp"
    $json = $State | ConvertTo-Json -Depth 10
    Set-Content -Path $tmp -Value $json -Encoding UTF8 -Force
    if (Test-Path $Path) { Remove-Item $Path -Force }
    Rename-Item -Path $tmp -NewName (Split-Path $Path -Leaf) -Force
}

function Read-State {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "State file not found: $Path" }
    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    $raw | ConvertFrom-Json -ErrorAction Stop
}

function Update-StateField {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Field,
        $Value
    )
    $state = Read-State -Path $Path
    if (-not ($state.PSObject.Properties.Name -contains $Field)) {
        throw "State schema has no field '$Field'"
    }
    $state.$Field = $Value
    Save-StateAtomic -Path $Path -State $state
}

function Get-CompleteStatePath {
    param([Parameter(Mandatory)][string]$DrainStartedAt)
    $dt = [datetime]::Parse(
        $DrainStartedAt,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )
    $stamp = $dt.ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    Join-Path $script:StateDir ("state-{0}.complete.json" -f $stamp)
}

function Move-StateToComplete {
    param([Parameter(Mandatory)][string]$Path)
    $state = Read-State -Path $Path
    $dest = Get-CompleteStatePath -DrainStartedAt $state.drainStartedAt
    Move-Item -Path $Path -Destination $dest -Force
    return $dest
}
#endregion

#region --- Event Log ---
function Initialize-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
            New-EventLog -LogName $script:EventLogName -Source $script:EventSource -ErrorAction Stop
            Write-Log "Created Event Log source '$script:EventSource' under '$script:EventLogName'"
        }
    }
    catch {
        Write-Log -Level WARN "Could not initialize Event Log source: $_"
    }
}

function Write-DrainEvent {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][ValidateSet('Information','Warning','Error')][string]$EntryType,
        [Parameter(Mandatory)][string]$Message
    )
    try {
        Write-EventLog -LogName $script:EventLogName -Source $script:EventSource -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
    }
    catch {
        Write-Log -Level WARN "Could not write Event Log entry ($EventId / $EntryType): $_"
    }
}
#endregion

#region --- Idempotency ---
function Test-StateFileExists {
    param([Parameter(Mandatory)][string]$Path)
    Test-Path -Path $Path -PathType Leaf
}

function Test-ResumeTaskExists {
    try {
        $existing = Get-ScheduledTask -TaskPath $script:TaskFolder -TaskName $script:TaskName -ErrorAction Stop
        return [bool]$existing
    }
    catch {
        return $false
    }
}

function Clear-StaleStateAndTask {
    Write-Log -Level WARN "Force mode: clearing any stale state and existing scheduled task."

    if (Test-Path $script:StatePath) {
        $archive = Join-Path $script:StateDir ("state-stale-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Move-Item -Path $script:StatePath -Destination $archive -Force
        Write-Log "Archived stale state.json to $archive"
    }

    if (Test-ResumeTaskExists) {
        Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskFolder -Confirm:$false
        Write-Log "Removed stale scheduled task ${script:TaskFolder}${script:TaskName}"
    }
}
#endregion

#region --- Cluster Context ---
function Test-ClusterModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name FailoverClusters)) {
        throw "FailoverClusters PowerShell module is not installed on this host."
    }
    Import-Module FailoverClusters -ErrorAction Stop
}

function Get-CurrentClusterContext {
    try {
        $cluster = Get-Cluster -ErrorAction Stop
    }
    catch {
        throw "Get-Cluster failed: $_. This host is not part of an active cluster, or the cluster service is not responsive."
    }
    return $cluster
}

function Get-ThisNode {
    Get-ClusterNode -Name $env:COMPUTERNAME -ErrorAction Stop
}

function Get-OtherNodes {
    Get-ClusterNode -ErrorAction Stop | Where-Object { $_.Name -ne $env:COMPUTERNAME }
}

function Get-PrimaryDrainTarget {
    # For a 2-node cluster: the other node. For 3+ nodes: the Up node with the most free memory
    # (rough heuristic; cluster service makes the actual decision at drain time, but Compare-VM
    # needs a concrete destination).
    $candidates = Get-OtherNodes | Where-Object State -eq 'Up'
    if (-not $candidates) {
        throw "No other Up cluster nodes found. Cannot drain - this is the only available node."
    }
    if ($candidates.Count -eq 1) { return $candidates[0] }

    # 3+ node case: pick the node with the most free memory.
    $best = $null
    $bestFree = -1
    foreach ($n in $candidates) {
        try {
            $hv = Get-VMHost -ComputerName $n.Name -ErrorAction Stop
            if ($hv.MemoryAvailableMB -gt $bestFree) {
                $bestFree = $hv.MemoryAvailableMB
                $best = $n
            }
        }
        catch {
            Write-Log -Level WARN "Could not query VMHost on $($n.Name): $_"
        }
    }
    if (-not $best) { return $candidates[0] }  # fallback
    return $best
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
