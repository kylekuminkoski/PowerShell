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
