[array]$arrSageSetKeys = @(
    'Active Setup Temp Folders',
    'BranchCache',
    'Compress System Disk',
    'Content Indexer Cleaner',
    'D3D Shader Cache',
    'Delivery Optimization Files',
    'Device Driver Packages',
    'Diagnostic Data Viewer database files',
    'Downloaded Program Files',
    'Internet Cache Files',
    'Offline Pages Files',
    'Old ChkDsk Files',
    'Previous Installations',
    'Recycle Bin',
    'RetailDemo Offline Content',
    'Service Pack Cleanup',
    'Setup Log Files',
    'System error memory dump files',
    'System error minidump files',
    'Temporary Files',
    'Temporary Setup Files',
    'Temporary Sync Files',
    'Thumbnail Cache',
    'Update Cleanup',
    'Upgrade Discarded Files',
    'User file versions',
    'Users Download Folder',
    'Windows Defender',
    'Windows Error Reporting Files',
    'Windows ESD installation files',
    'Windows Upgrade Log Files'
)

# Get current disk free space
[string]$strSystemDriveLetter = [System.Environment]::ExpandEnvironmentVariables("%systemdrive%") -replace (':', '')
$SystemDrive = Get-PSDrive -Name $strSystemDriveLetter
[double]$dblFreeSpace = $SystemDrive.Free

Write-Host "Cleaning Disk"

[string]$strRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
Foreach ($key in $arrSageSetKeys) {
    try {
        # Check if the path actually exists before trying to set the key (keys exisitng can depend on OS< patch level etc)
        If (Test-Path "$strRegPath\$key") {
            Write-Host "`nSetting $key"
            New-ItemProperty -Path "$strRegPath\$key" -Name 'StateFlags0066' -Value 2 -PropertyType DWORD -Force | Out-Null
        }
    }
    catch {
        Write-Warning "`nSAGESET registry keys for CLEANMGR could not be set."
    }
}

Start-Process cleanmgr.exe -NoNewWindow -ArgumentList '/SAGERUN:66' -Wait

#Clear out updates download folder
Write-Host "`nClearing out the Windows Updates download folder"

#Stop the Windows Updates service before clearing it out
$Wuauserv = Get-Service wuauserv
$Wuauserv | Stop-Service -Force

#Only delete the files if Windows Updates could be stopped
if ($Wuauserv.Status -eq "Stopped") {
    #Remove the files
    Get-ChildItem -Path "$env:WINDIR\SoftwareDistribution" -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
    #Start the Windows Updates service again
    $Wuauserv | Start-Service
}

Write-Host "`nDeleting any Hidden Windows Install Files"
Get-ChildItem -Path "$env:WINDIR" -Include `$NT* -File -Hidden | ForEach-Object { $_.Delete()}

Write-Host "`nDeleting Windows Prefetch files"
Get-ChildItem -Path "$env:WINDIR\Prefetch" -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}

Write-Host "`nDefragmenting Drive"
Start-Process Defrag.exe -NoNewWindow -ArgumentList "C: /U /V" -Wait

#Flush DNS
Write-Host "`nFlushing DNS cache"
Start-Process ipconfig.exe -NoNewWindow -ArgumentList "/flushdns" -Wait

#Clean Windows Component Store
Write-Host "`nCleaning Windows Component Store"
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /AnalyzeComponentStore" -Wait
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait

$SystemDrive = Get-PSDrive -Name $strSystemDriveLetter
[double]$dblNewFreeSpace = $SystemDrive.Free
[double]$dblSpaceFreed = [math]::Round((($dblNewFreeSpace - $dblFreeSpace) / 1MB), 2)

Write-Host "`n$dblSpaceFreed MB of disk space freed" -ForegroundColor Green