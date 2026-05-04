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

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Remove-OldLogs', Justification = 'Singular form less natural for collection operation; helper is script-internal')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Get-OtherNodes', Justification = 'Returns multiple nodes by definition; helper is script-internal')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Assert-NoFailedRoles', Justification = 'Predicate over a collection; helper is script-internal')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Get-BlockingIncompatibilities', Justification = 'Returns multiple incompatibilities; helper is script-internal')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Test-ResumeTaskExists', Justification = 'Predicate-style name; helper is script-internal')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Test-StateFileExists', Justification = 'Predicate-style name; helper is script-internal')]
[CmdletBinding()]
param(
    [ValidateSet('Drain','Resume')]
    [string]$Phase = 'Drain',

    [ValidateRange(5, 480)]
    [int]$DrainTimeoutMinutes = 60,

    [ValidateSet('Policy','Immediate','NoFailback')]
    [string]$FailbackMode = 'Policy',

    [ValidateRange(1, 60)]
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
$script:DrainAlreadyInProgressSentinel = 'DRAIN_ALREADY_IN_PROGRESS'
$script:DrainTimeoutSentinel           = 'DRAIN_TIMEOUT'
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
    param()
    try { Stop-Transcript | Out-Null }
    catch {
        # No transcript was running; nothing to stop. Intentional no-op.
        Write-Verbose "Stop-ScriptTranscript: no transcript was running ($_)."
    }
}

function Remove-OldLogs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
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
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Enumerate all tasks and filter in-process. Avoids the CIM "not found" exception
    # path entirely (Server 2025 raises a CimException whose FQEID does NOT match
    # "ObjectNotFound" patterns when a single task lookup misses), and avoids any
    # Write-Log calls that would pollute the function's success-stream return.
    # If the Task Scheduler service is genuinely broken, -ErrorAction SilentlyContinue
    # yields $null and we return $false; on a 2-node cluster this is the safer fallback
    # since drain wouldn't work anyway.
    $task = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -eq $script:TaskFolder -and $_.TaskName -eq $script:TaskName }
    return [bool]$task
}

function Clear-StaleStateAndTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
    param()
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

#region --- Preflight ---
function Test-IsElevated {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Elevated {
    if (-not (Test-IsElevated)) {
        throw "Script must run elevated (NinjaOne pushes as SYSTEM, which is elevated)."
    }
}

function Assert-ThisNodeIsUp {
    $node = Get-ThisNode
    if ($node.State -ne 'Up') {
        throw "This node ($env:COMPUTERNAME) is in state '$($node.State)', not 'Up'. Cannot drain."
    }
}

function Assert-OtherNodesAvailable {
    $up = Get-OtherNodes | Where-Object State -eq 'Up'
    if (-not $up) {
        throw "No other cluster nodes are 'Up'. Draining this node would have no failover target."
    }
}

function Assert-NoOtherNodePaused {
    $paused = Get-OtherNodes | Where-Object State -eq 'Paused'
    if ($paused) {
        $names = ($paused | ForEach-Object Name) -join ', '
        throw "Other cluster nodes are already Paused: $names. Refusing to drain - would stack VMs onto too few nodes."
    }
}

function Assert-CSVsHealthy {
    $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
    if (-not $csvs) {
        Write-Log -Level INFO "No Cluster Shared Volumes present (cluster may use SOFS or other storage)."
        return
    }
    foreach ($csv in $csvs) {
        if ($csv.State -ne 'Online') {
            throw "Cluster Shared Volume '$($csv.Name)' is in state '$($csv.State)', not 'Online'."
        }
        # SharedVolumeInfo[0].FaultState != NoFaults -> redirected access or fault
        $info = $csv.SharedVolumeInfo
        foreach ($svi in $info) {
            if ($svi.FaultState -ne 'NoFaults') {
                throw "Cluster Shared Volume '$($csv.Name)' has fault state '$($svi.FaultState)' (likely redirected access)."
            }
        }
    }
}

function Assert-NoFailedRoles {
    $bad = Get-ClusterGroup | Where-Object { $_.State -in @('Failed','Pending','PartialOnline') }
    if ($bad) {
        $names = ($bad | ForEach-Object { "$($_.Name) [$($_.State)]" }) -join ', '
        throw "Cluster groups in unhealthy state: $names. Refusing to drain."
    }
}

# Live Migration "blocking" MessageIds that force a non-LM transport at drain time.
# This list is best-effort, not exhaustive: there is no single Microsoft authoritative
# reference. Other IDs (shielded/TPM, GPU partition variants, version mismatches) may
# surface on real clusters and would silently slip through this filter. The Task 16
# live dry-run on COLONODE1 is intended to surface any such IDs in real-world output;
# extend this list when new blocking IDs are observed. Non-blocking incompatibilities
# are also logged at INFO level inside Assert-VMsLiveMigrationEligible for forensics.
$script:BlockingLMMessageIds = @(33000, 33002, 33012, 40010, 40011, 40012, 81005)

function Get-BlockingIncompatibilities {
    param([Parameter(Mandatory)]$CompatibilityReport)
    if (-not $CompatibilityReport.Incompatibilities) { return @() }
    @($CompatibilityReport.Incompatibilities | Where-Object {
        $script:BlockingLMMessageIds -contains $_.MessageId
    })
}

function Assert-VMsLiveMigrationEligible {
    param([switch]$SkipCheck)

    if ($SkipCheck) {
        Write-Log -Level WARN "SkipLiveMigrationCheck set; bypassing VM Live Migration eligibility preflight."
        return
    }

    $vmGroups = Get-ClusterGroup |
        Where-Object { $_.GroupType -eq 'VirtualMachine' -and $_.OwnerNode.Name -eq $env:COMPUTERNAME }

    if (-not $vmGroups) {
        Write-Log "No Hyper-V VMs currently owned by $env:COMPUTERNAME. Live Migration check trivially passes."
        return
    }

    $target = Get-PrimaryDrainTarget
    Write-Log ("Testing Live Migration eligibility of {0} VM(s) against target node '{1}'..." -f $vmGroups.Count, $target.Name)

    $blockers = @()
    foreach ($g in $vmGroups) {
        $vm = Get-VM -Name $g.Name -ErrorAction SilentlyContinue
        if (-not $vm) {
            Write-Log -Level WARN "Could not Get-VM for cluster group '$($g.Name)'; skipping LM check for it."
            continue
        }

        try {
            $report = Compare-VM -VM $vm -DestinationHost $target.Name -ErrorAction Stop
        }
        catch {
            $blockers += [pscustomobject]@{
                VM = $g.Name
                Reason = "Compare-VM raised: $_"
                MessageId = $null
            }
            continue
        }

        # Forensic log: emit every incompatibility (blocking and non-blocking) at INFO so
        # ops have a record if the blocking-ID filter misses something the cluster
        # treats as a blocker at drain time.
        if ($report.Incompatibilities) {
            foreach ($inc in $report.Incompatibilities) {
                $isBlocking = $script:BlockingLMMessageIds -contains $inc.MessageId
                Write-Log ("VM '{0}' Compare-VM incompatibility [{1}] (blocking={2}): {3}" -f $g.Name, $inc.MessageId, $isBlocking, $inc.Message)
            }
        }

        $bad = Get-BlockingIncompatibilities -CompatibilityReport $report
        foreach ($inc in $bad) {
            $blockers += [pscustomobject]@{
                VM = $g.Name
                Reason = $inc.Message
                MessageId = $inc.MessageId
            }
        }
    }

    if ($blockers) {
        Write-Log -Level ERROR "Live Migration preflight failed. The following VMs would force a non-LM transport:"
        foreach ($b in $blockers) {
            Write-Log -Level ERROR ("  - {0}: [{1}] {2}" -f $b.VM, $b.MessageId, $b.Reason)
        }
        throw "Live Migration eligibility check failed for $($blockers.Count) issue(s)."
    }

    Write-Log "All VMs cleared Live Migration preflight."
}

function Invoke-Preflight {
    param(
        [switch]$Force,
        [switch]$SkipLiveMigrationCheck
    )

    Write-Log "Starting preflight checks..."

    Assert-Elevated

    Test-ClusterModuleAvailable
    $cluster = Get-CurrentClusterContext
    Write-Log "Cluster context: $($cluster.Name)"

    # Idempotency checks (bypassable with -Force)
    $stateExists = Test-StateFileExists -Path $script:StatePath
    $taskExists = Test-ResumeTaskExists
    if ($stateExists -or $taskExists) {
        if ($Force) {
            Clear-StaleStateAndTask
        }
        else {
            $msg = "$script:DrainAlreadyInProgressSentinel`: state.json exists: $stateExists, resume task exists: $taskExists. Use -Force to clean up and retry."
            throw $msg
        }
    }

    Assert-ThisNodeIsUp
    Assert-OtherNodesAvailable
    Assert-NoOtherNodePaused
    Assert-CSVsHealthy
    Assert-NoFailedRoles
    Assert-VMsLiveMigrationEligible -SkipCheck:$SkipLiveMigrationCheck

    Write-Log "All preflight checks passed."
}
#endregion

#region --- Drain ---
function Get-CurrentRoleSnapshot {
    Get-ClusterGroup |
        Where-Object { $_.OwnerNode.Name -eq $env:COMPUTERNAME } |
        ForEach-Object {
            [pscustomobject]@{
                name          = $_.Name
                type          = $_.GroupType.ToString()
                originalOwner = $_.OwnerNode.Name
            }
        }
}

function Invoke-NodeDrain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = '$NodeName is bound via param() + -ArgumentList; using-scope is unnecessary and would error')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$TimeoutMinutes)

    Write-Log ("Calling Suspend-ClusterNode -Drain (timeout {0} min)..." -f $TimeoutMinutes)

    $job = Start-Job -ScriptBlock {
        param($NodeName)
        Import-Module FailoverClusters -ErrorAction Stop
        Suspend-ClusterNode -Name $NodeName -Drain -Wait -ErrorAction Stop
    } -ArgumentList $env:COMPUTERNAME

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ($job.State -eq 'Running' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
    }

    if ($job.State -eq 'Running') {
        Write-Log -Level ERROR "Drain timed out after $TimeoutMinutes minutes. Killing job."
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw $script:DrainTimeoutSentinel
    }

    if ($job.State -ne 'Completed') {
        $reason = $job.ChildJobs[0].JobStateInfo.Reason
        if (-not $reason) { $reason = ($job | Receive-Job -Keep -ErrorAction SilentlyContinue 2>&1) }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "Suspend-ClusterNode failed: $reason"
    }

    # Surface job output to log
    $output = Receive-Job -Job $job -ErrorAction SilentlyContinue
    if ($output) { $output | ForEach-Object { Write-Log "  drain-output: $_" } }
    Remove-Job -Job $job -ErrorAction SilentlyContinue

    Write-Log "Suspend-ClusterNode -Drain completed."
}

function Confirm-DrainComplete {
    $node = Get-ThisNode
    if ($node.State -ne 'Paused') {
        throw "Post-drain verification: node state is '$($node.State)', expected 'Paused'."
    }

    $stillOwned = Get-ClusterGroup | Where-Object { $_.OwnerNode.Name -eq $env:COMPUTERNAME }
    if ($stillOwned) {
        $names = ($stillOwned | ForEach-Object Name) -join ', '
        throw "Post-drain verification: this node still owns roles: $names"
    }

    Write-Log "Post-drain verification passed (state=Paused, owns 0 roles)."
}

function Invoke-DrainRollback {
    param([string]$Context = 'unspecified')
    Write-Log -Level WARN "Attempting drain rollback (context: $Context)..."
    try {
        Resume-ClusterNode -Name $env:COMPUTERNAME -Failback NoFailback -ErrorAction Stop
        Write-Log "Rollback Resume-ClusterNode succeeded."
    }
    catch {
        Write-Log -Level ERROR "Rollback Resume-ClusterNode failed: $_. MANUAL INTERVENTION REQUIRED - node is left Paused."
    }
}
#endregion

#region --- Resume Task Registration ---
function Register-ResumeTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScriptPath)

    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Phase Resume' -f $ScriptPath)

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT{0}S' -f $script:ResumeTaskBootDelaySeconds

    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    Register-ScheduledTask `
        -TaskName $script:TaskName `
        -TaskPath $script:TaskFolder `
        -InputObject $task `
        -Force | Out-Null

    Write-Log "Registered scheduled task '${script:TaskFolder}${script:TaskName}'."
}

function Unregister-ResumeTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Script-internal helper; -DryRun gate is at orchestrator level')]
    [CmdletBinding()]
    param()
    if (Test-ResumeTaskExists) {
        Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskFolder -Confirm:$false
        Write-Log "Unregistered scheduled task '${script:TaskFolder}${script:TaskName}'."
    }
}
#endregion

#region --- Drain Phase Orchestration ---
function Invoke-DrainPhase {
    param(
        [Parameter(Mandatory)][int]$DrainTimeoutMinutes,
        [Parameter(Mandatory)][string]$FailbackMode,
        [switch]$DryRun,
        [switch]$Force,
        [switch]$SkipLiveMigrationCheck
    )

    Initialize-StateDir
    Initialize-Transcript -PhaseName 'drain'
    Initialize-EventSource
    Remove-OldLogs -Directory $script:StateDir -RetentionDays $script:LogRetentionDays

    Write-Log "=== Drain phase starting on $env:COMPUTERNAME ==="
    Write-Log "Parameters: DrainTimeoutMinutes=$DrainTimeoutMinutes, FailbackMode=$FailbackMode, DryRun=$DryRun, Force=$Force, SkipLiveMigrationCheck=$SkipLiveMigrationCheck"

    try {
        Invoke-Preflight -Force:$Force -SkipLiveMigrationCheck:$SkipLiveMigrationCheck
    }
    catch {
        Write-Log -Level ERROR "Preflight failed: $_"
        Write-DrainEvent -EventId 1001 -EntryType Warning -Message "Drain preflight failed: $_"
        Stop-ScriptTranscript
        if ($_.Exception.Message -like "*$script:DrainAlreadyInProgressSentinel*") { exit 5 }
        exit 1
    }

    if ($DryRun) {
        Write-Log "DRY RUN: preflight passed; not draining or rebooting. Exiting 0."
        Stop-ScriptTranscript
        exit 0
    }

    $cluster = Get-CurrentClusterContext
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $roles = @(Get-CurrentRoleSnapshot)

    # Drain
    try {
        Invoke-NodeDrain -TimeoutMinutes $DrainTimeoutMinutes
        Confirm-DrainComplete
    }
    catch {
        Write-Log -Level ERROR "Drain failed: $_"
        if ($_.Exception.Message -eq $script:DrainTimeoutSentinel) {
            Invoke-DrainRollback -Context 'drain-timeout'
            Write-DrainEvent -EventId 1001 -EntryType Warning -Message "Drain timed out; rolled back."
            Stop-ScriptTranscript
            exit 4
        }
        Invoke-DrainRollback -Context 'drain-failed'
        Write-DrainEvent -EventId 1001 -EntryType Warning -Message "Drain failed and rolled back: $_"
        Stop-ScriptTranscript
        exit 2
    }

    $drainCompleted = (Get-Date).ToUniversalTime().ToString('o')

    # Persist state + register task. Wrap in try/catch - any failure here means rollback.
    try {
        $scriptPath = $MyInvocation.PSCommandPath
        $scriptHash = Get-ScriptHash -Path $scriptPath

        $state = New-StateObject `
            -NodeName $env:COMPUTERNAME `
            -ClusterName $cluster.Name `
            -DrainStartedAt $now `
            -FailbackMode $FailbackMode `
            -DrainTimeoutMinutes $DrainTimeoutMinutes `
            -ScriptPath $scriptPath `
            -ScriptHash $scriptHash `
            -RolesAtDrainStart $roles
        $state.drainCompletedAt = $drainCompleted

        Save-StateAtomic -Path $script:StatePath -State $state
        Write-Log "State persisted to $script:StatePath"

        Register-ResumeTask -ScriptPath $scriptPath
    }
    catch {
        Write-Log -Level ERROR "Failed to persist state or register resume task: $_"
        Invoke-DrainRollback -Context 'persist-or-schedule-failed'
        # Clean up partial state
        if (Test-Path $script:StatePath) { Remove-Item $script:StatePath -Force -ErrorAction SilentlyContinue }
        if (Test-ResumeTaskExists) { Unregister-ResumeTask }
        Write-DrainEvent -EventId 1001 -EntryType Warning -Message "Drain rolled back after persist/schedule failure: $_"
        Stop-ScriptTranscript
        exit 3
    }

    Update-StateField -Path $script:StatePath -Field 'rebootRequestedAt' -Value ((Get-Date).ToUniversalTime().ToString('o'))
    Write-Log "Reboot requested. NinjaOne will lose connection. Resume task registered."
    Write-DrainEvent -EventId 100 -EntryType Information -Message "Drain succeeded; rebooting $env:COMPUTERNAME. Resume task scheduled."

    Stop-ScriptTranscript

    try {
        Restart-Computer -Force -ErrorAction Stop
    }
    catch {
        # Reopen transcript for rollback log capture
        Initialize-Transcript -PhaseName 'drain'
        Write-Log -Level ERROR "Restart-Computer failed: $_. Rolling back drain to leave node recoverable."
        Invoke-DrainRollback -Context 'restart-computer-failed'
        if (Test-Path $script:StatePath) { Remove-Item $script:StatePath -Force -ErrorAction SilentlyContinue }
        if (Test-ResumeTaskExists) { Unregister-ResumeTask }
        Write-DrainEvent -EventId 1001 -EntryType Warning -Message "Restart-Computer failed; drain rolled back: $_"
        Stop-ScriptTranscript
        exit 3
    }
}
#endregion

#region --- Resume Phase Orchestration ---
function Wait-ClusterReady {
    param([Parameter(Mandatory)][int]$TimeoutMinutes)

    Write-Log "Waiting for cluster service readiness (timeout: $TimeoutMinutes min)..."
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)

    # Stage 1: ClusSvc running
    while ((Get-Date) -lt $deadline) {
        try {
            $svc = Get-Service -Name ClusSvc -ErrorAction Stop
            if ($svc.Status -eq 'Running') { break }
        }
        catch {
            # Service may not exist yet during early boot. Retry on next poll iteration.
            Write-Verbose "Wait-ClusterReady: ClusSvc not yet queryable ($_); will retry."
        }
        Start-Sleep -Seconds 10
    }
    if ((Get-Date) -ge $deadline) {
        throw "Timed out waiting for ClusSvc to reach Running."
    }
    Write-Log "ClusSvc is Running."

    # Stage 2: Get-Cluster responds
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Get-Cluster -ErrorAction Stop
            Write-Log "Get-Cluster responsive."
            return
        }
        catch {
            Start-Sleep -Seconds 10
        }
    }
    throw "Timed out waiting for Get-Cluster to respond."
}

function Invoke-ResumePhase {
    param([Parameter(Mandatory)][int]$ResumeReadyTimeoutMinutes)

    Initialize-StateDir
    Initialize-Transcript -PhaseName 'resume'
    Initialize-EventSource

    Write-Log "=== Resume phase starting on $env:COMPUTERNAME ==="

    # Step 1: cluster ready
    try {
        Test-ClusterModuleAvailable
        Wait-ClusterReady -TimeoutMinutes $ResumeReadyTimeoutMinutes
    }
    catch {
        Write-Log -Level ERROR "Cluster service not ready: $_"
        Write-DrainEvent -EventId 1010 -EntryType Error -Message "Resume phase: cluster not ready: $_"
        Stop-ScriptTranscript
        exit 10
    }

    # Step 2: validate state
    $state = $null
    try {
        if (-not (Test-Path $script:StatePath)) {
            throw "State file missing: $script:StatePath"
        }
        $state = Read-State -Path $script:StatePath

        if ($state.nodeName -ne $env:COMPUTERNAME) {
            throw "State file is for node '$($state.nodeName)', not '$env:COMPUTERNAME'."
        }

        if ($state.scriptPath -and (Test-Path $state.scriptPath)) {
            $currentHash = Get-ScriptHash -Path $state.scriptPath
            if ($currentHash -ne $state.scriptHash) {
                Write-Log -Level WARN "Script hash differs from drain-time hash. Continuing (admin may have legitimately updated the script)."
            }
        }
    }
    catch {
        Write-Log -Level ERROR "State validation failed: $_"
        Write-DrainEvent -EventId 1010 -EntryType Error -Message "Resume phase: invalid state: $_"
        try { Unregister-ResumeTask }
        catch {
            Write-Log -Level WARN "Could not unregister resume task during state-invalid cleanup: $_"
        }
        Stop-ScriptTranscript
        exit 11
    }

    # Step 3: confirm node is Paused (or already Up)
    $node = Get-ThisNode
    $skipResume = $false
    if ($node.State -eq 'Up') {
        Write-Log "Node already Up (someone manually resumed before this task ran). Skipping Resume-ClusterNode."
        $skipResume = $true
    }
    elseif ($node.State -ne 'Paused') {
        Write-Log -Level ERROR "Node state is '$($node.State)', expected 'Paused' or 'Up'."
        Write-DrainEvent -EventId 1010 -EntryType Error -Message "Resume phase: unexpected node state '$($node.State)'."
        Stop-ScriptTranscript
        exit 13
    }

    # Step 4: Resume
    if (-not $skipResume) {
        Update-StateField -Path $script:StatePath -Field 'resumeStartedAt' -Value ((Get-Date).ToUniversalTime().ToString('o'))
        try {
            Resume-ClusterNode -Name $env:COMPUTERNAME -Failback $state.failbackMode -ErrorAction Stop
            Write-Log "Resume-ClusterNode -Failback $($state.failbackMode) succeeded."
        }
        catch {
            Write-Log -Level ERROR "Resume-ClusterNode failed: $_"
            Write-DrainEvent -EventId 1010 -EntryType Error -Message "Resume-ClusterNode failed: $_"
            Stop-ScriptTranscript
            exit 12
        }

        # Step 4b: post-resume verification
        $node = Get-ThisNode
        if ($node.State -ne 'Up') {
            Write-Log -Level ERROR "Post-resume verification: node state is '$($node.State)', expected 'Up'."
            Write-DrainEvent -EventId 1010 -EntryType Error -Message "Post-resume verification failed: node is '$($node.State)'."
            Stop-ScriptTranscript
            exit 13
        }
        Write-Log "Post-resume verification passed (node is Up)."
    }

    # Step 5: cleanup
    Update-StateField -Path $script:StatePath -Field 'resumeCompletedAt' -Value ((Get-Date).ToUniversalTime().ToString('o'))
    $archived = Move-StateToComplete -Path $script:StatePath
    Write-Log "Archived state to $archived."

    Unregister-ResumeTask

    # Best-effort: remove the (now-empty) ClusterDrain task folder.
    try {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $folder = $svc.GetFolder('\')
        $folder.DeleteFolder('ClusterDrain', 0)
        Write-Log "Removed empty Task Scheduler folder \ClusterDrain\."
    }
    catch {
        # Folder may have other tasks or already be gone. Best-effort cleanup; not fatal.
        Write-Verbose "Could not delete \ClusterDrain task folder ($_); not fatal."
    }

    Write-Log "=== Resume phase complete ==="
    Write-DrainEvent -EventId 200 -EntryType Information -Message "Resume succeeded on $env:COMPUTERNAME."
    Stop-ScriptTranscript
    exit 0
}
#endregion

#region --- Main ---
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    if ($Phase -eq 'Drain') {
        Invoke-DrainPhase `
            -DrainTimeoutMinutes $DrainTimeoutMinutes `
            -FailbackMode $FailbackMode `
            -DryRun:$DryRun `
            -Force:$Force `
            -SkipLiveMigrationCheck:$SkipLiveMigrationCheck
    }
    else {
        Invoke-ResumePhase -ResumeReadyTimeoutMinutes $ResumeReadyTimeoutMinutes
    }
}
catch {
    Write-Error "Unhandled exception: $_"
    Stop-ScriptTranscript
    exit 99
}
#endregion
