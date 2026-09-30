<# 
NinjaOne PowerShell Script: Staggered Reboot for Hyper-V Hosts and VMs (PS 5.1 compatible)

Behavior:
- VM guest: reboot around 01:00 (01:00–01:30)
- Hyper-V host: health-gated reboot around 02:00 (02:00–02:30)
- Neither host nor VM: reboot around 03:00 (03:00–03:30)

Run as: SYSTEM (recommended)

Note: This script schedules FORCED reboots and creates/deletes scheduled tasks.
Use -WhatIf to preview the actions without mutating system state, or -Confirm
to be prompted before each destructive action.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$VmBaseTime                 = "01:00",

    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$HostBaseTime               = "02:00",

    [ValidatePattern('^\d{1,2}:\d{2}$')]
    [string]$DefaultBaseTime            = "03:00",

    [ValidateRange(0, 1440)]
    [int]$VmMaxRandomOffsetMins         = 30,

    [ValidateRange(0, 1440)]
    [int]$HostMaxRandomOffsetMins       = 30,

    [ValidateRange(0, 1440)]
    [int]$DefaultMaxRandomOffsetMins    = 30,

    [ValidateRange(0, 1440)]
    [int]$HostHealthGateMaxDelayMins    = 120,

    [ValidateRange(1, 1440)]
    [int]$HostPostponeStepMins          = 15
)

# Top-level error handling: surface failures instead of leaving the machine
# in a partially-configured state during an unattended RMM run.
$ErrorActionPreference = 'Stop'

#region --- Config ---
$TaskFolder   = "\NinjaStagger\"
$VmTaskName   = "NinjaStaggerReboot-VM"
$HostTaskName = "NinjaStaggerReboot-HOST"
$DefTaskName  = "NinjaStaggerReboot-DEFAULT"

$WorkDir      = Join-Path $env:ProgramData "NinjaStagger"
#endregion

#region --- Logging / Helpers ---
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output ("[{0}] {1}" -f $ts, $Message)
}

function Ensure-WorkDir {
    if (-not (Test-Path $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
    }
}

function Get-NextOccurrence {
    param([string]$HHmm)

    $now = Get-Date
    $parts = $HHmm.Split(":")
    $h = [int]$parts[0]
    $m = [int]$parts[1]

    $target = Get-Date -Hour $h -Minute $m -Second 0
    if ($target -le $now) { $target = $target.AddDays(1) }
    return $target
}

function Write-RebootNowScript {
    Ensure-WorkDir
    $path = Join-Path $WorkDir "RebootNow.ps1"

    # Simple, no braces/complex quoting for schtasks
    $content = @"
`$ErrorActionPreference = 'Stop'
Restart-Computer -Force
"@

    Set-Content -Path $path -Value $content -Encoding UTF8 -Force
    return $path
}

function New-OneTimeTaskAsSystem {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][datetime]$RunAt,
        [Parameter(Mandatory=$true)][string]$CommandLine
    )

    Ensure-WorkDir

    $startTime = $RunAt.ToString("HH:mm")
    $startDate = $RunAt.ToString("MM/dd/yyyy")

    $fullTaskName = "$TaskFolder$TaskName"

    # Remove existing task if present
    if ($PSCmdlet.ShouldProcess($fullTaskName, "Delete existing scheduled task (if present)")) {
        schtasks.exe /Delete /TN $fullTaskName /F 2>$null | Out-Null
    }

    # IMPORTANT: /TR must be passed as ONE argument; so we wrap the whole command line in quotes
    $tr = '"' + $CommandLine.Replace('"','\"') + '"'

    if ($PSCmdlet.ShouldProcess($fullTaskName, ("Create SYSTEM scheduled task to forcibly reboot at {0}" -f $RunAt))) {
        $out = schtasks.exe /Create `
            /TN $fullTaskName `
            /SC ONCE `
            /SD $startDate `
            /ST $startTime `
            /RU "SYSTEM" `
            /RL HIGHEST `
            /TR $tr `
            /F

        if ($LASTEXITCODE -eq 0) {
            Write-Log ("Created scheduled task {0}{1} to run at {2}" -f $TaskFolder, $TaskName, $RunAt)
        } else {
            Write-Log ("ERROR: Failed creating task {0}{1}. Output: {2}" -f $TaskFolder, $TaskName, $out)
            throw "Failed to create scheduled task."
        }
    } else {
        Write-Log ("WhatIf/Skipped: would create scheduled task {0}{1} to run at {2}" -f $TaskFolder, $TaskName, $RunAt)
    }
}
#endregion

#region --- Role Detection (PS 5.1 safe) ---
function Test-IsVirtualMachine {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        $model = ""
        $mfg   = ""
        if ($null -ne $cs.Model) { $model = $cs.Model.ToString().ToLowerInvariant() }
        if ($null -ne $cs.Manufacturer) { $mfg = $cs.Manufacturer.ToString().ToLowerInvariant() }

        if ($model -match "virtual" -or
            $model -match "vmware" -or
            $model -match "kvm" -or
            $model -match "hvm" -or
            $model -match "virtual machine" -or
            ($mfg -match "microsoft corporation" -and $model -match "virtual")) {
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

function Test-IsHyperVHost {
    try {
        Get-Service -Name "vmms" -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}
#endregion

#region --- Host reboot wrapper creation (health-gated) ---
function Write-HostWrapperScript {
    param(
        [int]$MaxDelayMins,
        [int]$PostponeStepMins
    )

    Ensure-WorkDir
    $wrapperPath = Join-Path $WorkDir "HostReboot-HealthGate.ps1"

    $content = @"
`$ErrorActionPreference = 'Stop'

function Write-Log([string]`$Message) {
  `$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Output ("[{0}] {1}" -f `$ts, `$Message)
}

function Get-HeartbeatState([string]`$VmName) {
  try {
    `$hb = Get-VMIntegrationService -VMName `$VmName -Name "Heartbeat" -ErrorAction Stop
    if (`$hb -and `$hb.PrimaryStatusDescription) { return `$hb.PrimaryStatusDescription }
    if (`$hb -and `$hb.SecondaryStatusDescription) { return `$hb.SecondaryStatusDescription }
    return "Unknown"
  } catch {
    return "Unknown"
  }
}

function Test-AllVMsHealthy {
  `$vms = Get-VM -ErrorAction Stop
  if (-not `$vms) {
    Write-Log "No VMs found on host. Treating as healthy."
    return `$true
  }

  foreach (`$vm in `$vms) {
    if (`$vm.State -ne 'Running') {
      Write-Log ("VM '{0}' is not Running (State={1})." -f `$vm.Name, `$vm.State)
      return `$false
    }

    `$hb = Get-HeartbeatState -VmName `$vm.Name
    if (`$hb -match "No Contact|Lost|Error") {
      Write-Log ("VM '{0}' heartbeat looks unhealthy ({1})." -f `$vm.Name, `$hb)
      return `$false
    }
  }

  return `$true
}

`$maxDelayMins = $MaxDelayMins
`$postponeStepMins = $PostponeStepMins

Write-Log "Starting Hyper-V host health gate before reboot."
`$start = Get-Date

while (`$true) {
  if (Test-AllVMsHealthy) {
    Write-Log "All VMs appear healthy. Rebooting host now."
    Restart-Computer -Force
    exit 0
  }

  `$elapsed = (New-TimeSpan -Start `$start -End (Get-Date)).TotalMinutes
  if (`$elapsed -ge `$maxDelayMins) {
    Write-Log ("Health gate timed out after {0} mins. Proceeding with host reboot anyway." -f [int]`$elapsed)
    Restart-Computer -Force
    exit 1
  }

  Write-Log ("VMs not healthy yet. Waiting {0} mins before re-check." -f `$postponeStepMins)
  Start-Sleep -Seconds (`$postponeStepMins * 60)
}
"@

    Set-Content -Path $wrapperPath -Value $content -Encoding UTF8 -Force
    return $wrapperPath
}
#endregion

#region --- Main ---
try {
    $IsVM   = Test-IsVirtualMachine
    $IsHost = Test-IsHyperVHost

    # If it looks like both (rare), treat as host.
    if ($IsHost -and $IsVM) {
        Write-Log "Device appears to be both VM and host; treating as Hyper-V host."
        $IsVM = $false
    }

    $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    # Shared simple reboot script for VM + Default
    $rebootNow = Write-RebootNowScript

    if ($IsVM) {
        $base   = Get-NextOccurrence -HHmm $VmBaseTime
        $offset = Get-Random -Minimum 0 -Maximum ($VmMaxRandomOffsetMins + 1)
        $runAt  = $base.AddMinutes($offset)

        Write-Log ("Detected Virtual Machine. Scheduling reboot at {0} (base {1} + {2} mins)." -f $runAt, $VmBaseTime, $offset)

        $cmdLine = ('"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $psExe, $rebootNow)
        New-OneTimeTaskAsSystem -TaskName $VmTaskName -RunAt $runAt -CommandLine $cmdLine
        exit 0
    }

    if ($IsHost) {
        $base   = Get-NextOccurrence -HHmm $HostBaseTime
        $offset = Get-Random -Minimum 0 -Maximum ($HostMaxRandomOffsetMins + 1)
        $runAt  = $base.AddMinutes($offset)

        Write-Log ("Detected Hyper-V Host. Scheduling HEALTH-GATED reboot at {0} (base {1} + {2} mins)." -f $runAt, $HostBaseTime, $offset)
        Write-Log ("Host health gate can delay up to {0} mins in {1}-min steps." -f $HostHealthGateMaxDelayMins, $HostPostponeStepMins)

        $wrapper = Write-HostWrapperScript -MaxDelayMins $HostHealthGateMaxDelayMins -PostponeStepMins $HostPostponeStepMins

        $cmdLine = ('"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $psExe, $wrapper)
        New-OneTimeTaskAsSystem -TaskName $HostTaskName -RunAt $runAt -CommandLine $cmdLine
        exit 0
    }

    # Default path: neither VM nor host -> schedule reboot at 03:00 (staggered)
    $base   = Get-NextOccurrence -HHmm $DefaultBaseTime
    $offset = Get-Random -Minimum 0 -Maximum ($DefaultMaxRandomOffsetMins + 1)
    $runAt  = $base.AddMinutes($offset)

    Write-Log ("Device is neither Hyper-V host nor VM. Scheduling DEFAULT reboot at {0} (base {1} + {2} mins)." -f $runAt, $DefaultBaseTime, $offset)

    $cmdLine = ('"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $psExe, $rebootNow)
    New-OneTimeTaskAsSystem -TaskName $DefTaskName -RunAt $runAt -CommandLine $cmdLine
    exit 0
}
catch {
    Write-Log ("FATAL: Reboot task scheduling failed: {0}" -f $_.Exception.Message)
    Write-Log ($_.ScriptStackTrace)
    exit 1
}
#endregion