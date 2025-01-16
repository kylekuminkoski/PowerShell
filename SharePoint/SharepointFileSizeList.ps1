#Set Variables - app ID: 65e90ea9-63b1-4ae9-b564-010d144ace3a
$SiteURL = "<site url here>"
$LibraryName = "Documents"
$CSVPath = "C:\Temp\SharepointFileSizeList.csv"
  
#Connect to SharePoint Online site
Connect-PnPOnline -Url $SiteURL -Interactive -Clientid "<app id here>"
 
$VersionHistoryData = @()
#Iterate through all files
Get-PnPListItem -List $LibraryName -PageSize 5000 | Where-Object {$_.FieldValues.FileLeafRef -like "*.*"} | ForEach-Object {
    Write-host "Getting Versioning Data of the File:"$_.FieldValues.FileRef
    #Get FileSize & version Size
    $FileSizeinKB = [Math]::Round(($_.FieldValues.File_x0020_Size/1KB),2)
    $File = Get-PnPProperty -ClientObject $_ -Property File
    $Versions = Get-PnPProperty -ClientObject $File -Property Versions
    $VersionSize = $Versions | Measure-Object -Property Size -Sum | Select-Object -expand Sum
    $VersionSizeinKB = [Math]::Round(($VersionSize/1KB),2)
    $TotalFileSizeKB = [Math]::Round(($FileSizeinKB + $VersionSizeinKB),2)
 
    #Extract Version History data
    $VersionHistoryData+=New-Object PSObject -Property  ([Ordered]@{
        "File Name"  = $_.FieldValues.FileLeafRef
        "File URL" = $_.FieldValues.FileRef
        "Versions" =  $Versions.Count
        "File Size (KB)"  = $FileSizeinKB
        "Version Size (KB)"   = $VersionSizeinKB
        "Total File Size (KB)" = $TotalFileSizeKB
    })
}
$VersionHistoryData | Format-table -AutoSize
$VersionHistoryData | Export-Csv -Path $CSVPath -NoTypeInformation