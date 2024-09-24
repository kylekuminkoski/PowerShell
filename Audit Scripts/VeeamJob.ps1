# Import the Veeam Backup & Replication PowerShell module
Import-Module Veeam.Backup.PowerShell

Get-VBRJob | ?{ $_.JobType -eq "Backup" -or $_.JobType -eq 'BackupSync' } | %{
    
    $job = $_
    $JobName = $_.Name
    $Backup = Get-VBRBackup -Name $JobName
    $lastsession = $job.FindLastSession()
    $Session = $job.FindLastSession()
    
    foreach ($tasksession in $lastsession.GetTaskSessions()) {
        $PointsOnDisk = (Get-VBRBackup -Name $job.Name | Get-VBRRestorePoint -Name $tasksession.Name | Measure-Object).Count 
        $BackupTotalSize = [math]::round($Session.Info.Progress.TotalUsedSize / 1Gb, 2)
        $BackupSize = [math]::round($Session.Info.BackedUpSize / 1Gb, 2)
        $RepositoryPath = $Backup.Info.DirPath.ToString()
        $LastBackupStart = $Session.CreationTime
        $LastResult = $job.GetLastResult()
        $Retention = $Job.BackupStorageOptions.RetainCycles
        $AppAwareStatus = if ($job.Info.JobScript.AppAwareProcessing) { "Enabled" } else { "Disabled" }
    }
    
    $_ | Get-VBRJobObject | ?{ $_.Object.Type -eq "VM" } | Select @{ L = "Job"; E = { $JobName } }, 
                                                              Name, 
                                                              @{ L = "Size"; E = { $_.ApproxSizeString } }, 
                                                              @{ L = "PointsOnDisk"; E = { $PointsOnDisk } }, 
                                                              @{ L = "LastResult"; E = { $LastResult } }, 
                                                              @{ L = "LastBackupStart"; E = { $LastBackupStart } }, 
                                                              @{ L = "LastBackupTotalSize"; E = { $BackupTotalSize } }, 
                                                              @{ L = "LastBackupSize"; E = { $BackupSize } }, 
                                                              @{ L = "RepositoryPath"; E = { $RepositoryPath } }, 
                                                              @{ L = "RetentionPolicy"; E = { $Retention } }, 
                                                              @{ L = "AppAwareStatus"; E = { $AppAwareStatus } } | 
                                                              Sort-Object -Property Job, Name
}

Read-Host -Prompt "Press Enter to exit"
