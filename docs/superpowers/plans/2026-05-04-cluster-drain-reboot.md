# Cluster Node Drain & Reboot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single PowerShell script that NinjaOne can push to a Hyper-V cluster node, which drains the node, reboots it, and resumes normal cluster operations after the host returns — surviving the mid-flow reboot via a one-shot AtStartup scheduled task.

**Architecture:** Single `.ps1` file routed by a `-Phase` parameter (Drain or Resume). Drain phase runs preflight → snapshot → `Suspend-ClusterNode -Drain` → state file + scheduled task → reboot. Resume phase (fired by the scheduled task at next boot) waits for cluster service ready → `Resume-ClusterNode -Failback Policy` → cleanup. State persists across the reboot via JSON file in `C:\ProgramData\ClusterDrain\`. Strict by default — any VM that can't Live Migrate aborts the drain before any cluster state changes.

**Tech Stack:** Windows Server 2025, PowerShell 5.1+, FailoverClusters module, Hyper-V module, Pester 5 (for unit-testable pure helpers), PSScriptAnalyzer (static checks).

**Spec:** `docs/superpowers/specs/2026-05-04-cluster-drain-reboot-design.md`

**Target script path:** `C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1`

**Repo root for all relative paths:** `C:\Users\kkuminkoski\PowerShell\PowerShell\`

---

## Testing Approach

- **Pure helpers** (logging, state file, hash, path helpers): Pester 5 unit tests at `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`. These don't touch the cluster and run on the workstation.
- **Cluster-cmdlet helpers** (preflight checks, drain wrapper, resume wrapper): no unit tests per spec decision. Validated by PSScriptAnalyzer + parse-check during development, and by `-DryRun` against COLONODE1 in Task 17.
- **Integration**: `-DryRun` on the live cluster (Task 17), then real run during a maintenance window (separate, operator-driven, outside this plan's scope).

To run the Pester suite at any time:

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

If Pester 5 isn't present:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

---

## Script File Structure

The script is organized into named regions in this order. Tasks build it up region by region.

```
<help block>
[CmdletBinding()] param(...)
$ErrorActionPreference = 'Stop'

#region --- Constants ---
#region --- Logging ---
#region --- Path & State ---
#region --- Event Log ---
#region --- Idempotency ---
#region --- Cluster Context ---
#region --- Preflight ---
#region --- Drain ---
#region --- Resume Task Registration ---
#region --- Drain Phase Orchestration ---
#region --- Resume Phase Orchestration ---
#region --- Main ---
```

---

## Task 1: Skeleton — help block, parameters, constants, top-level dispatcher stub

**Files:**
- Create: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1`
- Create: `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`

- [ ] **Step 1: Write the failing parameter-validation test**

Create `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`:

```powershell
$script:ScriptPath = Join-Path $PSScriptRoot '..' 'NinjaOne Scripts' 'Invoke-ClusterNodeDrainReboot.ps1' | Resolve-Path | Select-Object -ExpandProperty Path

Describe 'Invoke-ClusterNodeDrainReboot — parameter binding' {
    It 'parses without error' {
        { [scriptblock]::Create((Get-Content -Raw $script:ScriptPath)) } | Should -Not -Throw
    }

    It 'accepts -Phase Drain' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters['Phase'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            ForEach-Object ValidValues |
            Should -Contain 'Drain'
    }

    It 'accepts -Phase Resume' {
        $cmd = Get-Command $script:ScriptPath
        $cmd.Parameters['Phase'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            ForEach-Object ValidValues |
            Should -Contain 'Resume'
    }

    It 'rejects DrainTimeoutMinutes below 5' {
        $cmd = Get-Command $script:ScriptPath
        $attr = $cmd.Parameters['DrainTimeoutMinutes'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
        $attr.MinRange | Should -Be 5
    }

    It 'rejects DrainTimeoutMinutes above 480' {
        $cmd = Get-Command $script:ScriptPath
        $attr = $cmd.Parameters['DrainTimeoutMinutes'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
        $attr.MaxRange | Should -Be 480
    }

    It 'has a comment-based help SYNOPSIS' {
        $help = Get-Help $script:ScriptPath -ErrorAction Stop
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match '^Invoke-ClusterNodeDrainReboot\.ps1$'
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail (script doesn't exist yet)**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: All tests FAIL because the script file doesn't exist.

- [ ] **Step 3: Create the script with help, params, constants, and a stub dispatcher**

Create `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1`:

```powershell
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
```

- [ ] **Step 4: Run the tests to verify they pass**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: All 6 tests in the parameter-binding describe block PASS.

- [ ] **Step 5: Run the script in both phase modes**

```powershell
& "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1"
```

Expected output: `Drain phase stub. Implementation pending.`

```powershell
& "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Phase Resume
```

Expected output: `Resume phase stub. Implementation pending.`

- [ ] **Step 6: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1" "tests/Invoke-ClusterNodeDrainReboot.Tests.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): script skeleton with help, params, dispatcher stub"
```

---

## Task 2: Logging helpers — Write-Log, transcript management, log pruning

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Logging ---`)
- Modify: `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`

- [ ] **Step 1: Write the failing tests for log format and pruning**

Append to `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`:

```powershell
Describe 'Logging helpers' {
    BeforeAll {
        # Dot-source the script with -Phase Drain but skip main by overriding $Phase before main runs.
        # Pattern: load script in a fresh runspace and extract the function definitions only.
        . $script:ScriptPath -Phase Drain -DryRun -ErrorAction SilentlyContinue *>$null
    }

    It 'Format-LogLine produces ISO-style timestamp + level + message' {
        $line = Format-LogLine -Level INFO -Message 'hello'
        $line | Should -Match '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[INFO\] hello$'
    }

    It 'Format-LogLine accepts WARN' {
        (Format-LogLine -Level WARN -Message 'x') | Should -Match '\[WARN\] x$'
    }

    It 'Format-LogLine accepts ERROR' {
        (Format-LogLine -Level ERROR -Message 'x') | Should -Match '\[ERROR\] x$'
    }

    It 'Get-LogPath returns a path under the state dir' {
        $p = Get-LogPath -PhaseName 'drain'
        $p | Should -Match 'ClusterDrain\\drain-\d{8}-\d{6}\.log$'
    }

    It 'Remove-OldLogs deletes files older than retention but keeps recent' {
        $tempDir = Join-Path $TestDrive 'logs'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $oldFile = Join-Path $tempDir 'drain-20200101-000000.log'
        $newFile = Join-Path $tempDir ('drain-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Set-Content -Path $oldFile -Value 'old'
        (Get-Item $oldFile).LastWriteTime = (Get-Date).AddDays(-60)
        Set-Content -Path $newFile -Value 'new'

        Remove-OldLogs -Directory $tempDir -RetentionDays 30

        Test-Path $oldFile | Should -BeFalse
        Test-Path $newFile | Should -BeTrue
    }
}
```

The dot-source pattern won't actually run main() because the stub's `try` returns/exits before executing logging. But during real implementation, main exits early; we need a way to load definitions without running main. Use this guard at the top of `#region --- Main ---` once functions exist:

```powershell
if ($MyInvocation.InvocationName -eq '.') { return }
```

When dot-sourced (test load), main is skipped; when invoked normally, it runs.

- [ ] **Step 2: Run the tests to verify they fail**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: All 5 logging tests FAIL — functions not defined.

- [ ] **Step 3: Add the dot-source guard at the top of the `Main` region**

In `Invoke-ClusterNodeDrainReboot.ps1`, change `#region --- Main ---` to start with:

```powershell
#region --- Main ---
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    ...existing dispatcher...
}
```

- [ ] **Step 4: Insert the Logging region after Constants**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` between `#region --- Constants ---` (closing) and `#region --- Main ---`:

```powershell
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
```

- [ ] **Step 5: Run the tests to verify they pass**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: All 11 tests (6 from Task 1 + 5 logging) PASS.

- [ ] **Step 6: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1" "tests/Invoke-ClusterNodeDrainReboot.Tests.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): logging helpers + transcript + log pruning"
```

---

## Task 3: State file management — atomic write, hash, schema, read

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Path & State ---`)
- Modify: `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`

- [ ] **Step 1: Write the failing state-file tests**

Append to `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`:

```powershell
Describe 'State file helpers' {
    BeforeAll {
        . $script:ScriptPath -Phase Drain -DryRun -ErrorAction SilentlyContinue *>$null
    }

    It 'Get-ScriptHash returns a 64-char SHA256 hex string for the script itself' {
        $h = Get-ScriptHash -Path $script:ScriptPath
        $h | Should -Match '^[A-F0-9]{64}$'
    }

    It 'Get-ScriptHash is stable across calls' {
        $h1 = Get-ScriptHash -Path $script:ScriptPath
        $h2 = Get-ScriptHash -Path $script:ScriptPath
        $h1 | Should -Be $h2
    }

    It 'New-StateObject populates required schema fields' {
        $obj = New-StateObject -NodeName 'NODE1' -ClusterName 'CL' -DrainStartedAt (Get-Date).ToString('o') -FailbackMode 'Policy' -DrainTimeoutMinutes 60 -ScriptPath 'C:\foo.ps1' -ScriptHash ('A' * 64) -RolesAtDrainStart @()
        $obj.schemaVersion | Should -Be 1
        $obj.nodeName | Should -Be 'NODE1'
        $obj.failbackMode | Should -Be 'Policy'
        $obj.PSObject.Properties.Name | Should -Contain 'rebootRequestedAt'
        $obj.PSObject.Properties.Name | Should -Contain 'resumeStartedAt'
        $obj.PSObject.Properties.Name | Should -Contain 'resumeCompletedAt'
    }

    It 'Save-StateAtomic + Read-State round-trip preserves data' {
        $tempDir = Join-Path $TestDrive 'state'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $statePath = Join-Path $tempDir 'state.json'

        $obj = New-StateObject -NodeName 'NODE1' -ClusterName 'CL' -DrainStartedAt '2026-05-04T14:00:00Z' -FailbackMode 'Policy' -DrainTimeoutMinutes 60 -ScriptPath 'C:\foo.ps1' -ScriptHash ('A' * 64) -RolesAtDrainStart @(@{ name='vm1'; type='VM'; originalOwner='NODE1' })

        Save-StateAtomic -Path $statePath -State $obj

        Test-Path $statePath | Should -BeTrue
        Test-Path "$statePath.tmp" | Should -BeFalse

        $loaded = Read-State -Path $statePath
        $loaded.nodeName | Should -Be 'NODE1'
        $loaded.rolesAtDrainStart[0].name | Should -Be 'vm1'
    }

    It 'Save-StateAtomic uses temp + rename (no half-written file under failure)' {
        $tempDir = Join-Path $TestDrive 'state2'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $statePath = Join-Path $tempDir 'state.json'

        $obj = New-StateObject -NodeName 'NODE1' -ClusterName 'CL' -DrainStartedAt '2026-05-04T14:00:00Z' -FailbackMode 'Policy' -DrainTimeoutMinutes 60 -ScriptPath 'C:\foo.ps1' -ScriptHash ('A' * 64) -RolesAtDrainStart @()
        Save-StateAtomic -Path $statePath -State $obj

        # Verify final file exists, tmp doesn't
        (Get-ChildItem $tempDir).Count | Should -Be 1
        (Get-ChildItem $tempDir).Name | Should -Be 'state.json'
    }

    It 'Read-State throws on missing file' {
        { Read-State -Path (Join-Path $TestDrive 'nope.json') } | Should -Throw
    }

    It 'Read-State throws on invalid JSON' {
        $tempDir = Join-Path $TestDrive 'state3'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $statePath = Join-Path $tempDir 'state.json'
        Set-Content -Path $statePath -Value 'not json'
        { Read-State -Path $statePath } | Should -Throw
    }

    It 'Update-StateField persists a single field change' {
        $tempDir = Join-Path $TestDrive 'state4'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $statePath = Join-Path $tempDir 'state.json'
        $obj = New-StateObject -NodeName 'NODE1' -ClusterName 'CL' -DrainStartedAt '2026-05-04T14:00:00Z' -FailbackMode 'Policy' -DrainTimeoutMinutes 60 -ScriptPath 'C:\foo.ps1' -ScriptHash ('A' * 64) -RolesAtDrainStart @()
        Save-StateAtomic -Path $statePath -State $obj

        Update-StateField -Path $statePath -Field 'rebootRequestedAt' -Value '2026-05-04T14:30:00Z'

        $loaded = Read-State -Path $statePath
        $loaded.rebootRequestedAt | Should -Be '2026-05-04T14:30:00Z'
        $loaded.nodeName | Should -Be 'NODE1'  # other fields preserved
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 8 state-file tests FAIL.

- [ ] **Step 3: Implement the Path & State region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Logging ---`:

```powershell
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
    $stamp = ([datetime]$DrainStartedAt).ToString('yyyyMMdd-HHmmss')
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
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: All 19 tests (11 prior + 8 new) PASS.

- [ ] **Step 5: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1" "tests/Invoke-ClusterNodeDrainReboot.Tests.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): atomic state file + schema + hash helpers"
```

---

## Task 4: Event Log helpers

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Event Log ---`)

No Pester tests — creating event sources requires elevation, and we don't want test runs to dirty the Application log. Validation: PSScriptAnalyzer + manual trigger during dry-run later.

- [ ] **Step 1: Implement Event Log region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Path & State ---`:

```powershell
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
```

- [ ] **Step 2: Run PSScriptAnalyzer to confirm clean**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: No warnings or errors.

- [ ] **Step 3: Run the existing Pester suite to confirm no regressions**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 19/19 PASS (no new tests added in this task).

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): event log source + Write-DrainEvent helper"
```

---

## Task 5: Idempotency helpers — detect and clean stale state and tasks

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Idempotency ---`)
- Modify: `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`

- [ ] **Step 1: Write the failing tests**

Append to `tests/Invoke-ClusterNodeDrainReboot.Tests.ps1`:

```powershell
Describe 'Idempotency helpers' {
    BeforeAll {
        . $script:ScriptPath -Phase Drain -DryRun -ErrorAction SilentlyContinue *>$null
    }

    It 'Test-StateFileExists returns true when file exists' {
        $tempDir = Join-Path $TestDrive 'idem1'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $p = Join-Path $tempDir 'state.json'
        Set-Content -Path $p -Value '{}'
        Test-StateFileExists -Path $p | Should -BeTrue
    }

    It 'Test-StateFileExists returns false when file missing' {
        Test-StateFileExists -Path (Join-Path $TestDrive 'nope.json') | Should -BeFalse
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 2 idempotency tests FAIL.

- [ ] **Step 3: Implement Idempotency region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Event Log ---`:

```powershell
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
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

`Test-ResumeTaskExists` and `Clear-StaleStateAndTask` aren't unit-tested (they touch real Task Scheduler). Both will be exercised in Task 17 dry-run.

- [ ] **Step 5: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1" "tests/Invoke-ClusterNodeDrainReboot.Tests.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): idempotency helpers + force-mode cleanup"
```

---

## Task 6: Cluster context helpers — module + node enumeration

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Cluster Context ---`)

These wrap cluster cmdlets; not Pester-tested. Validated by PSScriptAnalyzer and Task 17 dry-run.

- [ ] **Step 1: Implement Cluster Context region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Idempotency ---`:

```powershell
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
        throw "No other Up cluster nodes found. Cannot drain — this is the only available node."
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
```

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean (or only known acceptable suppressions).

- [ ] **Step 3: Run Pester suite for regressions**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): cluster context + drain target selection"
```

---

## Task 7: Preflight — non-LM checks (1-7, 9-12 from spec)

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Preflight ---`)

- [ ] **Step 1: Implement Preflight region (without #8 LM check yet)**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Cluster Context ---`:

```powershell
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
        throw "Other cluster nodes are already Paused: $names. Refusing to drain — would stack VMs onto too few nodes."
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
#endregion
```

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 3: Run Pester for regressions**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): preflight assertions for cluster + node + storage health"
```

---

## Task 8: Preflight — Live Migration eligibility check (#8)

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (extend `#region --- Preflight ---`)

The hardest preflight check: only count `Compare-VM` incompatibilities that would force a non-LM transport. Auto-resolvable incompatibilities (snapshot path differences, etc.) shouldn't fail the check.

`Compare-VM` returns a `VMCompatibilityReport` with an `Incompatibilities` collection. Each incompatibility has a `MessageId`. Live Migration prerequisite documentation lists which message IDs block LM:

- `33000` — VM has saved state.
- `33002` — VM has incompatible processor (CPU mismatch).
- `33012` — VM uses unsupported integration services.
- `40010` — VM has a virtual switch with no equivalent on destination.
- `40011` — VM uses physical resources (e.g., GPU partition / DDA) not present on destination.
- `40012` — VM has dynamic memory configured beyond destination capacity.
- `81005` — VM has an attached ISO on a path that doesn't exist on destination.

Many other IDs are auto-resolvable (path remapping, generation 1 differences, etc.). The implementation filters on the blocking set above.

- [ ] **Step 1: Append the LM eligibility helper to the Preflight region**

Add to `Invoke-ClusterNodeDrainReboot.ps1` inside `#region --- Preflight ---` (before the `#endregion`):

```powershell
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
```

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 3: Pester regression check**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): Live Migration eligibility preflight (Compare-VM)"
```

---

## Task 9: Preflight orchestrator — runs all checks in order

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (extend `#region --- Preflight ---`)

- [ ] **Step 1: Add the orchestrator at the end of the Preflight region**

Add to `Invoke-ClusterNodeDrainReboot.ps1` inside `#region --- Preflight ---` (before `#endregion`):

```powershell
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
            $msg = "Drain already in progress (state.json exists: $stateExists, resume task exists: $taskExists). Use -Force to clean up and retry."
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
```

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 3: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): preflight orchestrator with force + skip-LM gates"
```

---

## Task 10: Drain wrapper — Suspend-ClusterNode with timeout and rollback

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Drain ---`)

- [ ] **Step 1: Implement the Drain region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Preflight ---`:

```powershell
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
        throw "DRAIN_TIMEOUT"
    }

    if ($job.State -ne 'Completed') {
        $err = ($job.ChildJobs[0].JobStateInfo.Reason) ?? ($job | Receive-Job -Keep -ErrorAction SilentlyContinue 2>&1)
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "Suspend-ClusterNode failed: $err"
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
        Write-Log -Level ERROR "Rollback Resume-ClusterNode failed: $_. MANUAL INTERVENTION REQUIRED — node is left Paused."
    }
}
#endregion
```

Note on the `??` operator: PowerShell 7+ has null-coalescing. PSv5.1 doesn't. The `??` line should be replaced for PSv5.1 compatibility. Use this instead:

```powershell
        $reason = $job.ChildJobs[0].JobStateInfo.Reason
        if (-not $reason) { $reason = ($job | Receive-Job -Keep -ErrorAction SilentlyContinue 2>&1) }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "Suspend-ClusterNode failed: $reason"
```

Replace the `??` line accordingly when implementing.

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean. If `??` warning surfaces, apply the PSv5.1 replacement above and re-run.

- [ ] **Step 3: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): Suspend wrapper with timeout + rollback + verification"
```

---

## Task 11: Resume-task registration

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Resume Task Registration ---`)

- [ ] **Step 1: Implement the region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Drain ---`:

```powershell
#region --- Resume Task Registration ---
function Register-ResumeTask {
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
    if (Test-ResumeTaskExists) {
        Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath $script:TaskFolder -Confirm:$false
        Write-Log "Unregistered scheduled task '${script:TaskFolder}${script:TaskName}'."
    }
}
#endregion
```

- [ ] **Step 2: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 3: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): scheduled task registration for resume-after-reboot"
```

---

## Task 12: Drain phase orchestration

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Drain Phase Orchestration ---`)

This task wires preflight → drain → state persist → task register → reboot, with rollback on persist/schedule failure.

- [ ] **Step 1: Implement the region**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Resume Task Registration ---`:

```powershell
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
        if ($_.Exception.Message -like '*Drain already in progress*') { exit 5 }
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
        if ($_.Exception.Message -eq 'DRAIN_TIMEOUT') {
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

    # Persist state + register task. Wrap in try/catch — any failure here means rollback.
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
    Restart-Computer -Force -ErrorAction Stop
}
#endregion
```

- [ ] **Step 2: Wire it into Main**

In `Invoke-ClusterNodeDrainReboot.ps1`, replace the `try/else` body inside `#region --- Main ---`:

```powershell
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
        Write-Output 'Resume phase stub. Implementation pending.'
        exit 0
    }
}
catch {
    Write-Error "Unhandled exception: $_"
    Stop-ScriptTranscript
    exit 99
}
```

- [ ] **Step 3: Run PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 4: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 5: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): drain phase orchestration end-to-end with rollback"
```

---

## Task 13: Wait-ClusterReady helper

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (add `#region --- Resume Phase Orchestration ---` with this helper)

- [ ] **Step 1: Implement the helper**

Insert into `Invoke-ClusterNodeDrainReboot.ps1` after `#region --- Drain Phase Orchestration ---`:

```powershell
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
        catch { }
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
#endregion
```

(Note: the `#endregion` here will move when Task 14 adds more functions inside this region.)

- [ ] **Step 2: PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 3: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 4: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): wait-cluster-ready helper for resume phase"
```

---

## Task 14: Resume phase orchestration

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (extend `#region --- Resume Phase Orchestration ---`)

- [ ] **Step 1: Implement Invoke-ResumePhase**

Add to `Invoke-ClusterNodeDrainReboot.ps1` inside `#region --- Resume Phase Orchestration ---`, before the `#endregion`:

```powershell
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
        try { Unregister-ResumeTask } catch { }
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
        # Folder may have other tasks or already be gone. Not fatal.
    }

    Write-Log "=== Resume phase complete ==="
    Write-DrainEvent -EventId 200 -EntryType Information -Message "Resume succeeded on $env:COMPUTERNAME."
    Stop-ScriptTranscript
    exit 0
}
```

- [ ] **Step 2: Wire it into Main**

In `Invoke-ClusterNodeDrainReboot.ps1`, replace the resume stub in `#region --- Main ---`:

```powershell
    else {
        Invoke-ResumePhase -ResumeReadyTimeoutMinutes $ResumeReadyTimeoutMinutes
    }
```

- [ ] **Step 3: PSScriptAnalyzer**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: clean.

- [ ] **Step 4: Pester regression**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 5: Commit**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "feat(cluster-drain): resume phase orchestration with state validation + cleanup"
```

---

## Task 15: Final static review — script analyzer pass + help block

**Files:**
- Modify: `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` (only if issues surface)

- [ ] **Step 1: Run PSScriptAnalyzer with all rules**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Information,Warning,Error
```

Expected: zero Errors. Warnings should each have a justification (e.g., `PSAvoidUsingWriteHost` is acceptable; we use `Write-Output`/`Write-Error`).

- [ ] **Step 2: Verify help block completeness**

```powershell
Get-Help "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Full
```

Expected: SYNOPSIS, DESCRIPTION, all 7 PARAMETER blocks, 3 EXAMPLES, NOTES with exit-code table.

- [ ] **Step 3: Parse-check the script**

```powershell
$null = [scriptblock]::Create((Get-Content -Raw "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1"))
```

Expected: no exception.

- [ ] **Step 4: Run full Pester suite one more time**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 5: Fix any issues surfaced and commit if anything changed**

If PSScriptAnalyzer or help validation surfaced anything:

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "chore(cluster-drain): static review fixes"
```

If nothing changed, skip the commit.

---

## Task 16: Live-cluster dry-run smoke test on COLONODE1

This task **runs** the script against the real cluster with `-DryRun` to validate cluster cmdlets work end-to-end. No state changes occur. **Operator must run this on COLONODE1 directly** (or via NinjaOne ad-hoc execution). It is part of the implementation plan because the result feeds back into any final fixes.

- [ ] **Step 1: Copy the script to COLONODE1 if developing on a different host**

If the workstation isn't COLONODE1, push the script to COLONODE1 via NinjaOne or copy via `\\COLONODE1\C$\Path` once.

- [ ] **Step 2: Execute the dry-run on COLONODE1**

On COLONODE1, elevated:

```powershell
& "C:\Path\To\Invoke-ClusterNodeDrainReboot.ps1" -DryRun
```

Expected output (paraphrased):

```
[ts] [INFO] Transcript started at C:\ProgramData\ClusterDrain\drain-<ts>.log
[ts] [INFO] === Drain phase starting on COLONODE1 ===
[ts] [INFO] Parameters: DrainTimeoutMinutes=60, FailbackMode=Policy, DryRun=True, Force=False, SkipLiveMigrationCheck=False
[ts] [INFO] Starting preflight checks...
[ts] [INFO] Cluster context: <cluster name>
[ts] [INFO] Testing Live Migration eligibility of N VM(s) against target node 'COLONODE2'...
[ts] [INFO] All VMs cleared Live Migration preflight.
[ts] [INFO] All preflight checks passed.
[ts] [INFO] DRY RUN: preflight passed; not draining or rebooting. Exiting 0.
```

- [ ] **Step 3: Verify post-conditions**

```powershell
Get-ClusterNode                                                  # both nodes Up
Test-Path C:\ProgramData\ClusterDrain\state.json                # FALSE
Get-ScheduledTask -TaskPath '\ClusterDrain\' -ErrorAction Ignore # nothing
Get-ChildItem C:\ProgramData\ClusterDrain\*.log                  # transcript exists
```

Expected: both nodes Up, no state file, no scheduled task, transcript file exists.

- [ ] **Step 4: Negative test — pre-create stale state.json**

```powershell
'{}' | Set-Content C:\ProgramData\ClusterDrain\state.json
& "C:\Path\To\Invoke-ClusterNodeDrainReboot.ps1" -DryRun
$LASTEXITCODE  # expect 5
```

Expected: exit 5, message about "Drain already in progress".

- [ ] **Step 5: Negative test — same with -Force**

```powershell
'{}' | Set-Content C:\ProgramData\ClusterDrain\state.json
& "C:\Path\To\Invoke-ClusterNodeDrainReboot.ps1" -DryRun -Force
$LASTEXITCODE  # expect 0
```

Expected: exit 0, log shows "Force mode: clearing any stale state".

- [ ] **Step 6: Cleanup**

```powershell
Remove-Item C:\ProgramData\ClusterDrain\state.json -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\ClusterDrain\state-stale-*.json -ErrorAction SilentlyContinue
```

- [ ] **Step 7: If any step revealed bugs, fix and commit**

If smoke test reveals issues, fix them in the script. Commit after fixes:

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" add "NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1"
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" commit -m "fix(cluster-drain): smoke-test findings on COLONODE1"
```

If everything passed, no commit needed.

---

## Task 17: Final commit + handoff notes

**Files:**
- Modify: nothing (this is just verification + final tag)

- [ ] **Step 1: Final Pester sweep**

```powershell
Invoke-Pester -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\tests\Invoke-ClusterNodeDrainReboot.Tests.ps1" -Output Detailed
```

Expected: 21/21 PASS.

- [ ] **Step 2: Final PSScriptAnalyzer sweep**

```powershell
Invoke-ScriptAnalyzer -Path "C:\Users\kkuminkoski\PowerShell\PowerShell\NinjaOne Scripts\Invoke-ClusterNodeDrainReboot.ps1" -Severity Warning,Error
```

Expected: zero issues, or only pre-justified ones.

- [ ] **Step 3: Confirm git state is clean**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" status
```

Expected: working tree clean.

- [ ] **Step 4: Tag for traceability (optional)**

```powershell
git -C "C:\Users\kkuminkoski\PowerShell\PowerShell" tag -a cluster-drain-v1.0.0 -m "Initial Invoke-ClusterNodeDrainReboot.ps1"
```

- [ ] **Step 5: Note next steps for the operator**

Real-run validation (Layer 4 of spec testing) is **not** scripted. After this plan is complete, the operator should:

1. Pick a low-impact maintenance window.
2. Move all VMs except a low-stakes test VM to COLONODE2.
3. Execute the script via NinjaOne against COLONODE1 (no `-DryRun`).
4. Watch NinjaOne stdout, the cluster console, and the test VM behavior.
5. Verify post-run: `state-<ts>.complete.json` archived, no active state.json, no scheduled task remaining, Event Log entries (100 + 200), node Up, test VM placement matches its Failback policy.

If real-run reveals issues, file them and iterate (a follow-up plan, not part of this one).

---

## Self-Review

**1. Spec coverage check:**

| Spec section | Tasks |
|---|---|
| Architecture (5 phases) | 12 (drain), 13–14 (resume) |
| File layout | 1 (constants), 3 (state), 11 (scheduled task) |
| Preflight checks 1–7, 9–12 | 7, 9 |
| Preflight check 8 (LM eligibility) | 8 |
| Drain phase | 10, 12 |
| Persist + Schedule + Reboot | 11, 12 |
| Resume phase | 13, 14 |
| Parameters | 1 |
| Exit codes | 1 (help), 12 + 14 (implementation) |
| Logging | 2 |
| Error handling pattern | 1 (top-level `$ErrorActionPreference`), 12 + 14 (per-phase try/catch) |
| Event Log alerting hook | 4 (helpers), 12 + 14 (call sites) |
| Testing — static checks | 15, 17 |
| Testing — dry-run | 16 |
| Testing — real run | 17 (operator handoff, not scripted) |

All spec sections mapped. No gaps.

**2. Placeholder scan:**

No "TBD" / "TODO" / "implement later" / "add appropriate error handling". All steps either show the actual code or specify an exact verification command with expected output.

**3. Type & name consistency:**

- `script:StateDir`, `script:StatePath`, `script:TaskFolder`, `script:TaskName`, `script:EventSource`, `script:EventLogName`, `script:LogRetentionDays`, `script:ResumeTaskBootDelaySeconds`, `script:LogPath`, `script:BlockingLMMessageIds` — all defined in Task 1 (constants) or Task 2 (logging) and referenced consistently elsewhere.
- Function names match across tasks: `Test-StateFileExists` (T5, T9), `Test-ResumeTaskExists` (T5, T9, T11), `Clear-StaleStateAndTask` (T5, T9), `Get-ThisNode` (T6, T10, T14), `Get-OtherNodes` (T6, T7), `Get-PrimaryDrainTarget` (T6, T8), `Save-StateAtomic` (T3, T12), `Read-State` (T3, T14), `Update-StateField` (T3, T12, T14), `Get-ScriptHash` (T3, T12, T14), `Move-StateToComplete` (T3, T14), `Initialize-Transcript` (T2, T12, T14), `Stop-ScriptTranscript` (T2, T12, T14), `Initialize-EventSource` (T4, T12, T14), `Write-DrainEvent` (T4, T12, T14), `Register-ResumeTask` (T11, T12), `Unregister-ResumeTask` (T11, T14), `Wait-ClusterReady` (T13, T14), `Invoke-DrainPhase` (T12, dispatcher in T1/T12), `Invoke-ResumePhase` (T14, dispatcher T14).
- Parameter names match: `Phase`, `DrainTimeoutMinutes`, `FailbackMode`, `ResumeReadyTimeoutMinutes`, `DryRun`, `Force`, `SkipLiveMigrationCheck` — all defined in Task 1 and used identically in Task 12 / dispatcher.

No naming drift detected.
