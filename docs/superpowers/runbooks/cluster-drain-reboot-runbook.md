# Cluster Drain & Reboot — Operator Runbook

**Script:** `NinjaOne Scripts/Invoke-ClusterNodeDrainReboot.ps1`
**Spec:** `docs/superpowers/specs/2026-05-04-cluster-drain-reboot-design.md`
**Plan:** `docs/superpowers/plans/2026-05-04-cluster-drain-reboot.md`

## What it does

Drains a Hyper-V failover cluster node, reboots it, and resumes cluster operations after the host returns. Survives the mid-flow reboot via a one-shot `AtStartup` scheduled task that re-invokes the script with `-Phase Resume`.

Strict by default: aborts before any cluster state changes if any owned VM can't Live Migrate. Configurable failback policy on resume (default: per-VM Failback Policy).

## Standard invocation

**NinjaOne push** (no parameters):

```powershell
.\Invoke-ClusterNodeDrainReboot.ps1
```

**Smoke-test before a real maintenance window** (no drain, no reboot):

```powershell
.\Invoke-ClusterNodeDrainReboot.ps1 -DryRun
```

**Recover from a stuck previous run** (clears stale `state.json` + scheduled task, then proceeds):

```powershell
.\Invoke-ClusterNodeDrainReboot.ps1 -Force
```

**Skip the Live Migration eligibility check** (only if VMs are pre-validated or non-LM transport downtime is acceptable):

```powershell
.\Invoke-ClusterNodeDrainReboot.ps1 -SkipLiveMigrationCheck
```

## What "good" looks like in NinjaOne stdout

Drain phase happy path:

```
[ts] [INFO] Transcript started at C:\ProgramData\ClusterDrain\drain-<ts>.log
[ts] [INFO] Created Event Log source 'ClusterDrain' under 'Application'  (first-run only)
[ts] [INFO] === Drain phase starting on <NODE> ===
[ts] [INFO] Parameters: DrainTimeoutMinutes=60, FailbackMode=Policy, DryRun=False, Force=False, SkipLiveMigrationCheck=False
[ts] [INFO] Starting preflight checks...
[ts] [INFO] Cluster context: <CLUSTER>
[ts] [INFO] Testing Live Migration eligibility of N VM(s) against target node '<PARTNER>'...
[ts] [INFO] All VMs cleared Live Migration preflight.
[ts] [INFO] All preflight checks passed.
[ts] [INFO] Calling Suspend-ClusterNode -Drain (timeout 60 min)...
[ts] [INFO] Suspend-ClusterNode -Drain completed.
[ts] [INFO] Post-drain verification passed (state=Paused, owns 0 roles).
[ts] [INFO] State persisted to C:\ProgramData\ClusterDrain\state.json
[ts] [INFO] Registered scheduled task '\ClusterDrain\ResumeAfterReboot'.
[ts] [INFO] Reboot requested. NinjaOne will lose connection. Resume task registered.
```

After the host comes back online, Resume phase runs from the scheduled task and writes its own log file at `C:\ProgramData\ClusterDrain\resume-<ts>.log`. End-state log lines:

```
[ts] [INFO] === Resume phase complete ===
```

## Exit codes — operator action

| Exit | Meaning | Reboot? | Operator action |
|------|---------|---------|-----------------|
| 0 | Success (drain phase queued reboot OR resume completed) | yes / n.a. | None |
| 1 | Preflight failure (cluster, node, storage, role health) | no | Read transcript log; fix the failed check; re-run |
| 2 | Drain failed (Suspend cmdlet error or post-drain verification) | no (rolled back) | Investigate cluster service / VM state; re-run |
| 3 | State persistence or task registration failed | no (rolled back) | Check disk space, permissions, Task Scheduler service; re-run |
| 4 | Drain timeout | no (rolled back) | Investigate slow VM migration; consider larger `-DrainTimeoutMinutes`; re-run |
| 5 | Already in progress (`state.json` or task exists) | no | Confirm node state; either wait for previous run, or re-run with `-Force` |
| 10 | Cluster service didn't become ready in time (resume phase) | n.a. | Manually run `-Phase Resume` once cluster service is up |
| 11 | State file missing or invalid (resume phase) | n.a. | Investigate state file contents; manual `Resume-ClusterNode` if needed |
| 12 | `Resume-ClusterNode` cmdlet failed | n.a. | Check cluster log / event viewer; manual `Resume-ClusterNode -Failback Policy` if needed |
| 13 | Post-resume verification failed (node didn't reach Up) | n.a. | Same as 12 |
| 99 | Unhandled exception | varies | Read top of transcript; if node is Paused, run `Resume-ClusterNode -Failback Policy` manually |

## File locations on the cluster node

| Path | Purpose |
|------|---------|
| `C:\ProgramData\ClusterDrain\drain-<yyyyMMdd-HHmmss>.log` | Drain-phase transcript |
| `C:\ProgramData\ClusterDrain\resume-<yyyyMMdd-HHmmss>.log` | Resume-phase transcript |
| `C:\ProgramData\ClusterDrain\state.json` | In-flight state (deleted on successful resume) |
| `C:\ProgramData\ClusterDrain\state-<ts>.complete.json` | Archived state after successful resume |
| `C:\ProgramData\ClusterDrain\state-stale-<ts>.json` | Archive of stale state cleared by `-Force` |
| Task Scheduler `\ClusterDrain\ResumeAfterReboot` | One-shot AtStartup task (self-unregisters on success) |
| Event Log: `Application` source `ClusterDrain` | Alerting events |

## NinjaOne alerting — Event Log watchlist

Configure NinjaOne's Event Log monitor on `Application` log, source `ClusterDrain`:

| EventID | Severity | When | Recommended NinjaOne action |
|---------|----------|------|-----------------------------|
| 100 | Information | Drain succeeded; reboot pending | Suppress / informational only |
| 200 | Information | Resume succeeded after reboot | Suppress / informational only |
| 1001 | Warning | Drain-phase failure (exit 1–5) | Page during business hours |
| 1010 | Error | Resume-phase failure (exit 10–13) | Page immediately — cluster degraded |

## Manual recovery commands

**Node stuck Paused after a script failure** (most common recovery scenario):

```powershell
Get-ClusterNode <NODE>     # confirm State is 'Paused'
Resume-ClusterNode -Name <NODE> -Failback Policy

# Then clean up any leftover artifacts
Remove-Item C:\ProgramData\ClusterDrain\state.json -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName ResumeAfterReboot -TaskPath '\ClusterDrain\' -Confirm:$false -ErrorAction SilentlyContinue
```

**Resume task didn't fire after reboot** (boot task delay or Schedule service hiccup):

```powershell
# Manually run the resume phase
& "C:\Path\To\Invoke-ClusterNodeDrainReboot.ps1" -Phase Resume
```

The script uses the persisted `state.json` to resume with the same `Failback` mode the drain phase chose.

**Investigating a failed run:** logs are in `C:\ProgramData\ClusterDrain\`. Each run writes a timestamped transcript. If reading remotely:

```powershell
# Latest drain transcript
Get-ChildItem C:\ProgramData\ClusterDrain\drain-*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
```

Event Log query:

```powershell
Get-WinEvent -ProviderName ClusterDrain -MaxEvents 20 |
    Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
```

## Pre-maintenance-window checklist

Before pushing the drain script to a node:

1. **Both nodes Up:** `Get-ClusterNode | Format-Table Name, State` — all `Up`.
2. **All VMs Online:** `Get-ClusterGroup | Where State -ne 'Online'` — empty.
3. **CSVs healthy:** `Get-ClusterSharedVolume | Where State -ne 'Online'` — empty.
4. **Failover capacity on partner:** confirm partner has enough free RAM and CSV space for the migrating VMs. The script's preflight checks LM eligibility, not capacity.
5. **No active backup or maintenance jobs** on the cluster (Veeam, Backup-VM, Update-ClusterFunctionalLevel).
6. **NinjaOne maintenance window** scheduled, alerts suppressed during the migration if desired.

## Parameters reference

| Parameter | Default | Range/Values |
|-----------|---------|--------------|
| `-Phase` | `Drain` | `Drain` (NinjaOne push) or `Resume` (boot task) |
| `-DrainTimeoutMinutes` | 60 | 5–480 |
| `-FailbackMode` | `Policy` | `Policy`, `Immediate`, `NoFailback` |
| `-ResumeReadyTimeoutMinutes` | 5 | 1–60 |
| `-DryRun` | off | switch — runs preflight, no drain/reboot |
| `-Force` | off | switch — bypass idempotency, clean stale state/task |
| `-SkipLiveMigrationCheck` | off | switch — skip per-VM LM eligibility preflight |

## Known limitations

- **`BlockingLMMessageIds` list is best-effort, not exhaustive.** The Compare-VM preflight may miss some IDs that the cluster service later treats as blocking at drain time. Forensic INFO logging records every incompatibility seen, so missed IDs can be added to the constant in `Invoke-ClusterNodeDrainReboot.ps1` (search for `BlockingLMMessageIds`).
- **Three-plus-node clusters use a memory-based heuristic** for `Get-PrimaryDrainTarget`. The script's LM check tests against one likely destination; the cluster service may pick a different one at drain time. For two-node clusters (COLONODE) this is N/A — there's only one possible target.
- **Resume phase is not unit-tested** (Pester suite covers helpers only). Validation is via dry-run + real-run.
