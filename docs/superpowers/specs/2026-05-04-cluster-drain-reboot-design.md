---
title: Cluster Node Drain & Reboot Script — Design
date: 2026-05-04
status: Draft (awaiting user review)
script: NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1
target_environment: Server 2025 Hyper-V Failover Cluster (initial target: COLONODE1/COLONODE2)
---

# Cluster Node Drain & Reboot Script

## Purpose

A NinjaOne-pushable PowerShell script that safely drains a Hyper-V failover cluster node, reboots it, and resumes normal cluster operations after the host returns. Intended for routine maintenance (patching, firmware, planned reboots) on a small Hyper-V cluster (initially the two-node COLONODE cluster).

## Goals

1. Run end-to-end from a single NinjaOne push with no operator interaction after invocation.
2. Refuse to proceed if any cluster preflight check would result in VM downtime.
3. Survive the mid-flow reboot — drain runs synchronously, resume runs from a one-shot scheduled task at the next boot.
4. Honor each VM's configured Failback policy on resume; do not force a uniform failback decision across the cluster.
5. Roll back the drain if reboot scheduling fails. Never leave the node Paused with no automated path back to Up.
6. Surface failures via NinjaOne stdout/stderr **and** Windows Event Log so they can be alerted on.

## Non-goals

- Cluster patch orchestration. Cluster-Aware Updating already exists for that. This script is a single-node maintenance primitive.
- Non-Hyper-V cluster role types. The Live-Migration eligibility gate is Hyper-V-specific. File server / SQL FCI roles are out of scope for v1.
- Best-effort drain modes (SaveState/Shutdown fallback). Strict by default; an explicit `-SkipLiveMigrationCheck` switch exists as an escape hatch.
- Cross-platform compatibility. PowerShell 5.1+ on Windows Server 2025 only.

## Architecture

The script runs in two distinct invocations from the host's perspective:

1. **Drain invocation** — pushed by NinjaOne, runs synchronously through preflight, drain, state persistence, scheduled-task registration, and reboot.
2. **Resume invocation** — fires from a one-shot `AtStartup` scheduled task on the next boot, runs cluster-readiness wait + `Resume-ClusterNode`, and self-cleans.

The same script file handles both, routed by a `-Phase` parameter the boot task supplies.

### Phase summary

| Phase | Trigger | Reboot? | Exit codes |
|---|---|---|---|
| 1. Preflight | NinjaOne push | No | 1 (any check fails), 5 (already in progress) |
| 2. Drain | After preflight passes | No (yet) | 2 (drain failed), 4 (drain timeout) |
| 3. Persist + Schedule | After drain passes | No (yet) | 3 (persist or task registration failed → drain rolled back) |
| 4. Reboot | After persist + schedule succeed | Yes | n/a (process dies with reboot) |
| 5. Resume | Scheduled task at next boot | n/a | 10 (cluster not ready), 11 (state file missing/invalid), 12 (Resume-ClusterNode failed), 13 (post-resume verification failed) |

### File layout

| Path | Purpose |
|---|---|
| `<repo>/NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1` | The script itself |
| `C:\ProgramData\ClusterDrain\` | Runtime state and logs (created on first run) |
| `C:\ProgramData\ClusterDrain\state.json` | In-flight drain metadata (deleted on successful resume) |
| `C:\ProgramData\ClusterDrain\state-<ts>.complete.json` | Archived state file after successful resume |
| `C:\ProgramData\ClusterDrain\drain-<ts>.log` | Drain-phase transcript |
| `C:\ProgramData\ClusterDrain\resume-<ts>.log` | Resume-phase transcript |
| Task Scheduler `\ClusterDrain\ResumeAfterReboot` | One-shot task registered during Drain phase, unregistered after successful Resume |

## Preflight Checks

All preflight runs in the Drain phase only. Any failure exits non-zero with a clear message; no drain attempted, no reboot.

**Cluster + node state**

1. `FailoverClusters` PowerShell module loadable.
2. `Get-Cluster` succeeds — host is a member of an active cluster.
3. This node's `Get-ClusterNode` state is `Up` (not already `Paused` or `Down`).
4. At least one other cluster node is `Up`.
5. No other node is currently `Paused`.

**Storage + roles**

6. All `Get-ClusterSharedVolume` entries are `Online` and not in redirected-access mode.
7. No `Get-ClusterGroup` entry is in `Failed` or `Pending` state.

**Live-Migration eligibility (strict gate)**

8. Enumerate every Hyper-V VM clustered role currently owned by this node. For each, run `Compare-VM` against the partner node the cluster's drain logic would pick. If any VM reports an incompatibility that would force SaveState/TurnOff fallback, abort with the offending VM list and specific incompatibility reasons. No drain attempted.
   - Skipped if `-SkipLiveMigrationCheck` is supplied (logged loudly).
   - On clusters with three or more nodes, target the most-likely drain destination. For the initial COLONODE deployment (two nodes) this is simply the other node.

**Idempotency**

9. `C:\ProgramData\ClusterDrain\state.json` does not already exist.
10. Scheduled task `\ClusterDrain\ResumeAfterReboot` does not already exist.
11. Both #9 and #10 are bypassed by `-Force` (with a loud warning logged and stale state cleaned up before proceeding).

**Permissions**

12. Running elevated. NinjaOne pushes as SYSTEM (which is elevated), but the check is explicit.

## Drain Phase

Runs only after every preflight check passes.

1. Snapshot current cluster groups owned by this node (name, type, current owner) into `state.json`. Used for audit and to detect drift in resume.
2. Call `Suspend-ClusterNode -Name $env:COMPUTERNAME -Drain -Wait -ErrorAction Stop`, wrapped in a job + timeout (`-DrainTimeoutMinutes`, default 60). On timeout: kill the job, attempt `Resume-ClusterNode` to back out, exit 4. No reboot.
3. Verify final state:
   - `Get-ClusterNode $env:COMPUTERNAME` reports `Paused`.
   - `Get-ClusterGroup | Where-Object OwnerNode -eq $env:COMPUTERNAME` returns zero items.
4. If verification fails: attempt `Resume-ClusterNode` to back out, exit 2.
5. Inspect each migrated VM's final transport / `OperationalStatus`. If anything indicates a non-LM transport happened despite the eligibility preflight, log a warning (informational; the post-drain verification has already confirmed VMs are off the node).

Deliberately **not** done: manual `Move-ClusterVirtualMachineRole` loops or fallback transport selection. The cluster service decides distribution and respects anti-affinity rules.

## Persist + Schedule + Reboot

The most error-sensitive section. Between drain-success and reboot, any failure must roll back the drain (otherwise the node is Paused with no automated way back to Up).

### Step 1 — Write `state.json`

Atomic write: write to `state.json.tmp`, then rename. Avoids a half-written file on process kill.

```json
{
  "schemaVersion": 1,
  "nodeName": "COLONODE1",
  "clusterName": "<from Get-Cluster>",
  "drainStartedAt": "2026-05-04T14:22:11Z",
  "drainCompletedAt": "2026-05-04T14:24:33Z",
  "failbackMode": "Policy",
  "drainTimeoutMinutes": 60,
  "scriptPath": "<full path>",
  "scriptHash": "<SHA256 at run time>",
  "rolesAtDrainStart": [
    { "name": "...", "type": "...", "originalOwner": "..." }
  ],
  "rebootRequestedAt": null,
  "resumeStartedAt": null,
  "resumeCompletedAt": null
}
```

`scriptPath` and `scriptHash` are how the resume task knows which file to invoke and that it hasn't been swapped/tampered since drain.

### Step 2 — Register the on-boot scheduled task

- Name: `\ClusterDrain\ResumeAfterReboot`
- Principal: `SYSTEM`, `RunLevel = Highest`
- Trigger: `AtStartup` with a 90-second delay (lets `ClusSvc` initialize before the script polls).
- Action: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<scriptPath>" -Phase Resume`
- Settings: `StartWhenAvailable = true`, `MultipleInstances = IgnoreNew`, no time limit.
- Implementation: `Register-ScheduledTask` (PSv5+ cmdlets), not `schtasks.exe`.

### Step 3 — Rollback guard

If Step 1 or Step 2 fails: catch, log, call `Resume-ClusterNode -Failback NoFailback`, delete partial state file, delete partial scheduled task, exit 3. `NoFailback` is deliberate for the rollback path — we want a clean abort, not a cascade of failbacks during error handling.

### Step 4 — Final pre-reboot

- Update `state.json.rebootRequestedAt = <now>`.
- Flush logs.
- `Restart-Computer -Force -ErrorAction Stop`.

## Resume Phase

Triggered by the scheduled task firing 90 seconds after boot. Same script file, invoked with `-Phase Resume`.

### Step 1 — Wait for cluster service readiness

- Verify `ClusSvc` is `Running`. If not yet, poll every 10s up to `-ResumeReadyTimeoutMinutes` (default 5).
- Once running, poll `Get-Cluster -ErrorAction SilentlyContinue` until it returns successfully (cluster is responsive, not just the service started). Same outer timeout.
- On timeout: log + write Event Log error, exit 10. Leave the scheduled task and state file in place so a human can investigate or manually re-run `-Phase Resume`.

### Step 2 — Validate state file

- Read `state.json`. If missing → log error, unregister task, exit 11.
- Confirm `state.json.scriptPath` matches the running script path; verify `scriptHash` still matches the file. If hash differs, log a warning and continue (admin may have legitimately updated the script — refusing here would strand the node).
- Confirm `state.json.nodeName -eq $env:COMPUTERNAME`. If not, refuse and exit 11.

### Step 3 — Confirm node is Paused

- `Get-ClusterNode $env:COMPUTERNAME` should report `Paused`.
- If `Up` already (someone manually resumed before the boot task fired), log informational, skip Resume-ClusterNode, proceed to cleanup.
- If `Down`, exit 13 (cluster service is up but this node hasn't rejoined).

### Step 4 — Resume

- Update `state.json.resumeStartedAt = <now>`.
- `Resume-ClusterNode -Name $env:COMPUTERNAME -Failback Policy -ErrorAction Stop`.
- Verify `Get-ClusterNode $env:COMPUTERNAME` reports `Up`.

### Step 5 — Cleanup

- Update `state.json.resumeCompletedAt = <now>`.
- Rename `state.json` → `state-<drainStartedAt>.complete.json` (audit trail; not deleted).
- `Unregister-ScheduledTask -TaskName ResumeAfterReboot -TaskPath \ClusterDrain\ -Confirm:$false`.
- Remove `\ClusterDrain\` task folder if empty.
- Final log line, exit 0.

### Resume-phase failure handling

If Step 4 fails (`Resume-ClusterNode` raises): log the error, write Event Log error 1010, **leave** the scheduled task and state file in place, exit 12. The task is `MultipleInstances = IgnoreNew`, and only an explicit success unregisters it — so the operator can re-run `-Phase Resume` manually or wait for the next boot to retry.

## Parameters

```powershell
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
```

| Parameter | Purpose | Default |
|---|---|---|
| `-Phase` | Routing switch. Drain (NinjaOne push) or Resume (boot task). | `Drain` |
| `-DrainTimeoutMinutes` | Hard timeout on `Suspend-ClusterNode -Drain`. Range 5–480. | 60 |
| `-FailbackMode` | Mapped to `Resume-ClusterNode -Failback`. | `Policy` |
| `-ResumeReadyTimeoutMinutes` | How long Resume waits for `ClusSvc` + `Get-Cluster`. | 5 |
| `-DryRun` | Run preflight + LM eligibility checks only; no Suspend, no reboot. | off |
| `-Force` | Bypass idempotency checks (#9, #10). Cleans stale state first. Logged loudly. Does not skip safety checks. | off |
| `-SkipLiveMigrationCheck` | Skip preflight #8. For when VMs are pre-validated or non-LM transport is acceptable. | off |

### Invocation forms

```powershell
# Standard NinjaOne push (no params)
.\Invoke-ClusterNodeDrainReboot.ps1

# Smoke test before a real maintenance window
.\Invoke-ClusterNodeDrainReboot.ps1 -DryRun

# Recover from a stuck previous run
.\Invoke-ClusterNodeDrainReboot.ps1 -Force

# What the boot task runs (operator does not type this)
.\Invoke-ClusterNodeDrainReboot.ps1 -Phase Resume
```

## Exit Codes

| Code | Meaning | Phase | Reboot occurred |
|---|---|---|---|
| 0 | Success | Drain or Resume | Yes (Drain) / N/A (Resume) |
| 1 | Preflight failure | Drain | No |
| 2 | Drain failed (Suspend cmdlet error or post-drain verification) | Drain | No (rolled back) |
| 3 | State persistence or scheduled task registration failed | Drain | No (rolled back) |
| 4 | Drain timeout | Drain | No (rolled back) |
| 5 | Already in progress (state.json or task exists, no `-Force`) | Drain | No |
| 10 | Cluster service did not become ready within timeout | Resume | — |
| 11 | State file missing or invalid | Resume | — |
| 12 | Resume-ClusterNode failed | Resume | — |
| 13 | Post-resume verification failed (node not Up) | Resume | — |

## Logging

- `Start-Transcript` to `C:\ProgramData\ClusterDrain\drain-<yyyyMMdd-HHmmss>.log` (Drain phase) or `resume-<yyyyMMdd-HHmmss>.log` (Resume phase).
- All `Write-Log` calls also `Write-Output` so NinjaOne captures the full transcript live during the Drain phase.
- Format: `[yyyy-MM-dd HH:mm:ss] [LEVEL] message` (matches the existing `Invoke-HyperVRebootTasks.ps1` style).
- Levels: `INFO`, `WARN`, `ERROR`. Errors also `Write-Error` so they land in NinjaOne's stderr stream.
- Old logs: pruned past 30 days on Drain-phase entry.

## Error Handling Pattern

- `$ErrorActionPreference = 'Stop'` at the top.
- Top-level `try { Drain-Phase or Resume-Phase } catch { Log-Error; Rollback-If-Needed; exit <code> }`.
- Each phase function owns its own rollback. Drain phase rolls back drain on persist/schedule failure. Resume phase has no rollback; failures leave the task in place to retry.
- Every external call (`Suspend-ClusterNode`, `Register-ScheduledTask`, `Resume-ClusterNode`, etc.) wrapped to surface the underlying exception message into the log, not just a generic "command failed".

## Event Log Alerting Hook

- On first run, ensure event source `ClusterDrain` exists under the `Application` log (create if missing — requires admin, which we have).
- EventID 100 (Information) — drain started successfully.
- EventID 200 (Information) — resume completed successfully.
- EventID 1001 (Warning) — drain-phase failure (exit 1–5). No operational impact, but admin attention needed.
- EventID 1010 (Error) — resume-phase failure (exit 10–13). Cluster is degraded; page someone.

NinjaOne can be configured to alert on the `ClusterDrain` source.

## Testing & Validation

### Layer 1 — Static checks (always)

- `Invoke-ScriptAnalyzer` clean.
- Script parses (`$null = [scriptblock]::Create((Get-Content -Raw $path))`).
- Comment-based help block: synopsis, all parameters, examples, exit-code table.

### Layer 2 — Dry-run on the live cluster

`.\Invoke-ClusterNodeDrainReboot.ps1 -DryRun` against COLONODE1.

- Should: pass all preflight, report VMs that would migrate and their target, exit 0.
- Should: not write `state.json`, not register a task, not touch cluster state.
- Verify: both nodes still `Up`, no scheduled task in `\ClusterDrain\`.

### Layer 3 — Negative preflight tests on the live cluster

For each, run with `-DryRun` and confirm exit code + log message:

- Pre-create stale `state.json` → expect exit 5.
- Pre-create dummy `\ClusterDrain\ResumeAfterReboot` task → expect exit 5.
- Both above + `-Force` → expect exit 0 with cleanup logged.
- `Suspend-ClusterNode COLONODE2` first → expect exit 1 ("another node already paused").
- `Suspend-ClusterNode COLONODE1` first → expect exit 1 ("this node already paused").
- "No other Up node" test skipped on a 2-node cluster (would require taking the partner offline); covered by code review.

### Layer 4 — Real run with low-impact workload

- Pick a low-stakes window. Manually move all VMs except a single non-critical test VM to COLONODE2.
- Run `.\Invoke-ClusterNodeDrainReboot.ps1` on COLONODE1 from NinjaOne.
- Watch in real time:
  - NinjaOne stdout shows preflight pass, drain progress, scheduled task registered, reboot triggered.
  - Cluster console: COLONODE1 transitions Up → Paused → Down → Joining → Up.
  - Test VM Live Migrates to COLONODE2, then returns based on its Failback policy.
- Verify post-run:
  - `state-<timestamp>.complete.json` exists.
  - No active `state.json` remains.
  - Scheduled task is gone.
  - Resume log shows "Node Up", exit 0.
  - Event log: ID 100 (drain start), ID 200 (resume success).

### Layer 5 — Failure injection (optional, in a maintenance window)

- Briefly disable partner node networking during drain → expect Suspend to fail or time out, expect rollback, expect node returns to Up, no reboot. *(A fully partitioned 2-node cluster carries other risk — only do this in a maintenance window or skip.)*
- Edit script mid-drain (after preflight, before reboot) → expect resume phase to log hash mismatch warning but still proceed.

### Explicitly not tested automatically

- Pester unit tests of cluster cmdlet wrappers. Mocking `Suspend-ClusterNode` is more pain than value at this script size; dry-run + real-run testing on COLONODE provides stronger evidence.

## Open Questions / Future Work

- **Three-plus-node clusters:** The Live-Migration eligibility preflight assumes a single most-likely partner. On 3+ node clusters, the cluster's drain target selection isn't trivially predictable from outside. Future v2 could enumerate eligible targets and verify compatibility against all of them, or rely on the cluster's own pre-check via `Test-ClusterResourceFailure` / `Test-Cluster` if those expose the relevant data.
- **Non-Hyper-V roles:** File server / SQL FCI / generic services don't have an LM-eligibility analogue. Future v2 could classify by role type and skip the check for non-Hyper-V roles.
- **CAU integration:** If the user later adopts Cluster-Aware Updating, this script could be wrapped as a CAU pre-update / post-update script. Out of scope for v1.

## References

- `Suspend-ClusterNode` — https://learn.microsoft.com/powershell/module/failoverclusters/suspend-clusternode
- `Resume-ClusterNode` — https://learn.microsoft.com/powershell/module/failoverclusters/resume-clusternode
- `Compare-VM` — https://learn.microsoft.com/powershell/module/hyper-v/compare-vm
- Existing related script: `NinjaOne Scripts/Invoke-HyperVRebootTasks.ps1` (staggered host/VM reboot scheduler — different concern; the two scripts coexist).
