#Define Parameters
$ErrorActionPreference = 'Stop'
$SiteURL = "https://occasionallymade.sharepoint.com/"
$FileRelativePath = "/Shared Documents/Product/Product Design/Internal/Moodboards/Moodboards 2024 Winter.pptx"
$VersionsToKeep = 50

#Connect to PnP Online
try
{
    Connect-PnPOnline -Url $SiteURL -Interactive
}
catch
{
    Write-Error "Failed to connect to '$SiteURL': $($_.Exception.Message)"
    throw
}

#Get File Versions
try
{
    $File = Get-PnPFile -Url $FileRelativePath
    $Versions = Get-PnPProperty -ClientObject $File -Property versions
}
catch
{
    Write-Error "Failed to retrieve file or versions for '$FileRelativePath': $($_.Exception.Message)"
    throw
}

#Notification of file collected
Write-host -f Yellow "Scanning File:"$File.Name
$VersionsCount = $Versions.Count
write-host -f Cyan "`t Total Number of Versions of the File:" $VersionsCount

$VersionsToDelete = $VersionsCount - $VersionsToKeep
If($VersionsToDelete -gt 0)
{
    write-host -f Cyan "`t Total Number of Versions to be deleted:" $VersionsToDelete
    #Build the set of deletable (non-current) versions, oldest-first, and delete exactly $VersionsToDelete of them
    $DeletableVersions = @($Versions | Where-Object { -not $_.IsCurrentVersion })
    $TargetCount = [Math]::Min($VersionsToDelete, $DeletableVersions.Count)
    $Deleted = 0
    For($i=0; $i -lt $TargetCount; $i++)
    {
        $Version = $DeletableVersions[$i]
        try
        {
            write-host -f Cyan "`t Deleting Version:" $Version.VersionLabel
            Remove-PnPFileVersion -Url $FileRelativePath -Identity $Version.ID -Force
            $Deleted++
        }
        catch
        {
            Write-Error "Failed to delete version '$($Version.VersionLabel)' (ID $($Version.ID)): $($_.Exception.Message)"
        }
    }
    Write-Host -f Green "`t Version History is cleaned for the File:"$File.Name "($Deleted version(s) deleted)"
}
