﻿# Define Parameters
$SiteURL = "https://occasionallymade.sharepoint.com/"
$FileRelativePath = "/Shared Documents/Product/Product Design/Internal/Moodboards/Moodboards 2024 Winter.pptx"
$VersionsToKeep = 50

# Connect to PnP Online
Connect-PnPOnline -Url $SiteURL -Interactive

# Get File Versions
$File = Get-PnPFile -Url $FileRelativePath
$Versions = Get-PnPProperty -ClientObject $File -Property versions

# Notification of file collected
Write-host -f Yellow "Scanning File:" $File.Name
$VersionsCount = $Versions.Count
write-host -f Cyan "`t Total Number of Versions of the File:" $VersionsCount

$VersionsToDelete = $VersionsCount - $VersionsToKeep
If ($VersionsToDelete -gt 0) {
    write-host -f Cyan "`t Total Number of Versions to be deleted:" $VersionsToDelete
    }