##################################################################################################
##                                                                                              ##
##                                                                                              ##
###################################  Reference Image Cleanup ####################################
#################################### Author: Kyle Kuminkoski #####################################
##                                                                                              ##
##                                                                                              ##
##################################################################################################

$ErrorActionPreference = 'Stop'

# Array of files to be cleaned
[array]$arrFilesToBeDeleted = @(
    '%SystemRoot%\memory.dmp',
    '%SystemRoot%\Minidump.dmp'
)

# Array of folders to be cleaned
[array]$arrFoldersToBeCleaned = @(
    '%systemroot%\Downloaded Program Files',
    '%systemroot%\Temp',
    '%systemdrive%\Windows.old',
    '%systemdrive%\Temp',
    '%systemdrive%\MSOCache\All Users',
    '%allusersprofile%\Adobe\Setup',
    '%allusersprofile%\Microsoft\Windows Defender\Definition Updates',
    '%allusersprofile%\Microsoft\Windows Defender\Scans',
    '%allusersprofile%\Microsoft\Windows\WER'
)

# Keys to set CLEANMGR to clean, remove unwanted entries
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

# Create counter to optionally record how many files could not be deleted. Not output by default
[long]$lngSkippedFileCount = 0

Function Feedback ($strFeedbackString) {
    # This function provides feedback in the console on errors or progress, and aborts if error has occured.
    If ($error.count -eq 0) {
        # Write content of feedback string
        Write-Host -Object $strFeedbackString -ForegroundColor 'Green'
    }
  
    # If an error occured report it, and exit the script with ErrorLevel 1
    Else {
        # Write content of feedback string but in red
        Write-Host -Object $strFeedbackString -ForegroundColor 'Red'
    
        # Display error details
        Write-Host 'Details: ' $error[0].Exception.Message -ForegroundColor 'Red'

        Exit 1
    }
}

Function Remove-AllFilesInFolder ($strFolder) {
    $ExpFolder = [System.Environment]::ExpandEnvironmentVariables("$strFolder")
    # Make sure folder exists, Get-Childitem -recurse can hang on folders that don't exist
    If ((Test-Path -Path "$ExpFolder") -eq $true) {
        $Files = Get-ChildItem -Path $ExpFolder -Recurse -File -Force

        # Call the function to remove the files
        Remove-FilesInArray $Files
    }
}
 
Function Remove-FilesInArray ($arrFiles) {
    Foreach ($File in $Files) {
        try {
            # Remove the file
            Remove-Item -Path $file.Fullname -Force
        }
        catch {
            $script:lngSkippedFileCount += 1
        }
    }
}


###End Initialization###

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
# Run CLEANMGR as a Job, so a time out can be used because cleanmgr sometimes hangs if run silently
try {
    # Set timeout 
    [int]$intTimeOut = 1800
    $CodeBlock = {
        Start-Process cleanmgr.exe -NoNewWindow -ArgumentList '/SAGERUN:66' -Wait
    }
    # Start the job
    $Job = Start-Job -ScriptBlock $CodeBlock

    # Wait for the job to complete
    Wait-Job $Job -Timeout $intTimeOut | Out-Null

    # Has the job completed?
    If ($Job.State -ne 'Completed') {
        Feedback "`nCLEANMGR did not complete in the specified time of $intTimeOut seconds. It may have run but failed to exit. Script will continue."
        Stop-Process -Name cleanmgr -Force
    }

    # Cleanup
    Stop-Job $Job
    Remove-Job $Job
}
catch {
    Write-Warning "`nCLEANMGR failed to run. This is not crucial so script will continue"
}

Write-Host "`nRemoving Files from User Documents and Downloads"
Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}

Write-Host "`nDeleting Shadow Copies"
Start-Process vssadmin.exe -NoNewWindow -ArgumentList "delete shadows /All /Quiet" -Wait

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


# Pass the folder array to function that gathers files
Foreach ($folder in $arrFoldersToBeCleaned) {
    Write-Host "Cleaning $folder"
    Remove-AllFilesInFolder $folder
}

# Delete the specified files
Foreach ($File in $arrFilesToBeDeleted) {
    Try {
        # Check if the file exists at all before trying to remove it, because default files may not exist on system
        $File = [System.Environment]::ExpandEnvironmentVariables("$File")
        If (Test-Path -Path $File) {
            Remove-Item -Path $File -Force
        }
    }
    catch {
        # File WAS FOUND but the file object could not be retreived, increase the Skipped File counter
        $lngSkippedFileCount += 1
    }
}

# Remove QuickBooks Update Cache Files
Get-ChildItem "C:\ProgramData\Intuit\QuickBooks 20*\Components\DownloadQB*\SPatch*.dat" -Force | Remove-Item -Recurse -Force
Get-ChildItem "C:\ProgramData\Intuit\QuickBooks 20*\Components\QBUpdateCache" -Force | Remove-Item -Recurse -Force

Write-Host "`nDefragmenting Drive"
Start-Process Defrag.exe -NoNewWindow -ArgumentList "C: /U /V" -Wait

#Flush DNS
Write-Host "`nFlushing DNS cache"
Start-Process ipconfig.exe -NoNewWindow -ArgumentList "/flushdns" -Wait

#Clean Windows Component Store
Write-Host "`nCleaning Windows Component Store"
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /AnalyzeComponentStore" -Wait
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait

#Scan for file corruption and restore image health with DISM. This is done twice because the two occasionally rely on eachothers component stores to work properly.
Write-Host "`nSystem File Checker (Pass 1)"
Start-Process sfc.exe -NoNewWindow -ArgumentList "/scannow" -Wait

Write-Host "`nDeployment Image Servicing and Management (Pass 1)"
Start-Sleep -Seconds 1

Write-Host "`nChecking Current Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /CheckHealth" -Wait

Write-Host "`nScanning Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait

Write-Host "`nRestoring Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait

Write-Host "`nSystem File Checker (Pass 2)"
Start-Process sfc.exe -NoNewWindow -ArgumentList "/scannow" -Wait

Write-Host "`nDeployment Image Servicing and Management (Pass 2)"
Start-Sleep -Seconds 1

Write-Host "`nChecking Current Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /CheckHealth" -Wait

Write-Host "`nScanning Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait

Write-Host "`nRestoring Health..."
Start-Process dism.exe -NoNewWindow -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait


#This function gets all event logs and loops through to clear them. A list of results is displayed on completion
Function Clear-AllEventLogs ($computerName="localhost")
{
    $logs = Get-EventLog -ComputerName $computername -List | ForEach-Object {$_.Log}

    $logs | ForEach-Object {
        Write-Host "Clearing $_"
        Clear-EventLog -ComputerName $computername -LogName $_ -ErrorAction continue } 
   
   Get-EventLog -ComputerName $computername -list
}

Write-Host "`nClearing Windows Logs"
Clear-AllEventLogs -ComputerName $env:COMPUTERNAME

Write-Host "`nClearing All logs"
Start-Process cmd.exe -ArgumentList {/c for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"} -Wait

# Write space gained to console
$SystemDrive = Get-PSDrive -Name $strSystemDriveLetter
[double]$dblNewFreeSpace = $SystemDrive.Free
[double]$dblSpaceFreed = [math]::Round((($dblNewFreeSpace - $dblFreeSpace) / 1MB), 2)

Write-Host "`n$dblSpaceFreed MB of disk space freed" -ForegroundColor Green

#Repair the image as a precaution
Write-Host "`nChecking the health of the running image"
$RepairResult = Repair-WindowsImage -Online -RestoreHealth -NoRestart

#Test that the image is healthy
if ($RepairResult.ImageHealthState -ne [Microsoft.Dism.Commands.ImageHealthState]::Healthy) {
    Write-Error "The image has been corrupted and should not be captured."
    exit
} else {
    Write-Host "Image is Healthy and ready to be captured." -ForegroundColor Green
}



