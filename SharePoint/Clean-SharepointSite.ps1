# Define Parameters
$siteUrl = "https://petersprofessionaleducation.sharepoint.com/sites/PetersProfessionalEducation"
$libraryName = "Documents"
$csvFilePath = "C:\Temp\VersionCleanupReport.csv"

# Initialize array to store operation details
$operationDetails = @()

# Connect to SharePoint Online site
Connect-PnPOnline -Url $SiteURL -Interactive -Clientid "65e90ea9-63b1-4ae9-b564-010d144ace3a"

# Get all files in the document library
$files = Get-PnPFolder -ListRootFolder $libraryName | Get-PnPFileInFolder -Recurse -ExcludeSystemFolders

# Iterate through each file
foreach ($file in $files) {
    # Attempt to delete all versions of the file
    try {
        Write-Host -ForegroundColor Yellow "Scanning file: $($file.ServerRelativeUrl)"

        # Get the file object without loading version properties
        $context = Get-PnPContext
        $fileObject = $context.Web.GetFileByServerRelativeUrl($file.ServerRelativeUrl)
        $context.Load($fileObject)
        $context.ExecuteQuery()

        # Check if the file has versions
        $versions = $fileObject.Versions
        $context.Load($versions)
        $context.ExecuteQuery()

        $versionsCount = $versions.Count

        if ($versionsCount -gt 0) {
            # Delete all versions of the file
            $fileObject.Versions.DeleteAll()
            $context.ExecuteQuery()

            Write-Host -ForegroundColor Green "Deleted $versionsCount versions of file: $($file.ServerRelativeUrl)"

            # Add operation details to the array
            $operationDetails += [PSCustomObject]@{
                "File" = $file.ServerRelativeUrl
                "Operation" = "Deleted all versions"
                "Timestamp" = Get-Date
            }
        } else {
            Write-Host -ForegroundColor DarkGray "No versions to delete for file: $($file.ServerRelativeUrl)"
        }
    } catch {
        Write-Host -ForegroundColor Red "Error processing file: $($file.ServerRelativeUrl) - $_"

        # Add error details to the array
        $operationDetails += [PSCustomObject]@{
            "File" = $file.ServerRelativeUrl
            "Operation" = "Error"
            "ErrorMessage" = $_.Exception.Message
            "Timestamp" = Get-Date
        }
    }
}

# Export operation details to CSV file
$operationDetails | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8

# Disconnect from SharePoint Online site
Disconnect-PnPOnline