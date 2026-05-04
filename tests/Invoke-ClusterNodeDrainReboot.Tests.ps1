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
