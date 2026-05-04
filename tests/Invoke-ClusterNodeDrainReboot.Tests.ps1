Describe 'Invoke-ClusterNodeDrainReboot — parameter binding' {
    BeforeAll {
        $script:ScriptPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'NinjaOne Scripts') 'Invoke-ClusterNodeDrainReboot.ps1' | Resolve-Path | Select-Object -ExpandProperty Path
    }

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

Describe 'Logging helpers' {
    BeforeAll {
        . $script:ScriptPath -ErrorAction SilentlyContinue *>$null
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

Describe 'State file helpers' {
    BeforeAll {
        . $script:ScriptPath -ErrorAction SilentlyContinue *>$null
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
        { Read-State -Path (Join-Path $TestDrive 'nope.json') } | Should -Throw -ExpectedMessage '*State file not found*'
    }

    It 'Read-State throws on invalid JSON' {
        $tempDir = Join-Path $TestDrive 'state3'
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $statePath = Join-Path $tempDir 'state.json'
        Set-Content -Path $statePath -Value 'not json'
        { Read-State -Path $statePath } | Should -Throw -ExpectedMessage '*Invalid*'
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

    It 'Get-CompleteStatePath preserves UTC time from a Z-suffixed ISO 8601 input' {
        # Save the script's current StateDir so we can stub it for the test
        $originalStateDir = $script:StateDir
        $script:StateDir = $TestDrive
        try {
            $result = Get-CompleteStatePath -DrainStartedAt '2026-05-04T14:00:00Z'
            $result | Should -Match 'state-20260504-140000\.complete\.json$'
        }
        finally {
            $script:StateDir = $originalStateDir
        }
    }
}

Describe 'Idempotency helpers' {
    BeforeAll {
        . $script:ScriptPath -ErrorAction SilentlyContinue *>$null
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
