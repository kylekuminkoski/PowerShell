if (-not (Get-Module -Name PnP.PowerShell)) {
    try {
        Import-Module PnP.PowerShell
        Get-Module -Name PnP.PowerShell
        Write-Host "PnP.PowerShell Module Successfully Imported" -ForegroundColor Green
    }
    catch {
        Write-Host "You need to install the PnP.PowerShell Module" -ForegroundColor Red
        exit
    }
}
else {
    Write-Host "PnP.PowerShell Module Found" -ForegroundColor Green
}

$TenantName = "occasionallymade"
$TenantUrl = "https://" + $TenantName + "-admin.sharepoint.com"
$ClientId = "98f5e5c4-795d-46a4-9db4-43f25a276b1c"



try {
    Connect-PnPOnline -Url $TenantUrl -ClientId $ClientId -Interactive
}
catch {
    Write-Host "ERROR: Could not connect to SharePoint Tenant. Please double check the Tenant Name, Application ID, and delegated permissions in Entra"
}


$Sites = Get-PnPTenantSite | Where-Object { $_.Template -like "*GROUP*" }

$Sites
# Loop through each site and store the connection to each site in a variable
$connections = @{}  # Create an empty hash table to store connections
$MasterTable = [ordered]@{}  # Create an empty ordered dictionary to store tables created during data processing
$Sites | ForEach-Object {
    $SiteUrl = $_.Url  # Get the site URL
    Write-Host "Connecting to site: $SiteUrl"

    # Connect to the site and store the connection object in the hash table
    $siteConnection = Connect-PnPOnline -Url $SiteUrl -ClientId $clientId -ReturnConnection -Interactive
    $connections[$SiteUrl] = $siteConnection  # Store the connection using the site URL as the key
    Write-Host "Connection to $SiteUrl has been stored" -ForegroundColor Green

}



$Sites | ForEach-Object {
    #Create a new empty ordered dictionary for the selected site's data processing. This will be stored in the master table after the site is done processing
    $VersionHistoryDataTable = [ordered]@{}

    $SiteUrl = $_.Url
    $LibraryName = "Documents"
    Write-Host "Connecting to site: $SiteUrl" -ForegroundColor Yellow

    try {
        #Connect to SharePoint Online site
        if ($connections.ContainsKey($SiteUrl)) {
            $connectionToUse = $connections[$SiteUrl]
            Write-Host "Connection Found in Hash Table" -ForegroundColor Green
            # Now you can perform any action on this specific site using its connection
        }

        #Iterate through all files
        Get-PnPListItem -Connection $connectionToUse -List $LibraryName -PageSize 5000 | Where-Object { $_.FieldValues.FileLeafRef -like "*.*" } | ForEach-Object {
            Write-host "Getting Versioning Data of the File:"$_.FieldValues.FileRef
            #Get FileSize & version Size
            $FileSizeinKB = [Math]::Round(($_.FieldValues.File_x0020_Size / 1KB), 2)
            $FileSizeinMB = [Math]::Round(($_.FieldValues.File_x0020_Size / 1MB), 2)
            $FileSizeinGB = [Math]::Round(($_.FieldValues.File_x0020_Size / 1GB), 2)
            $File = Get-PnPProperty -ClientObject $_ -Property File
            $Versions = Get-PnPProperty -ClientObject $File -Property Versions
            $VersionSize = $Versions | Measure-Object -Property Size -Sum | Select-Object -expand Sum
            $VersionSizeinKB = [Math]::Round(($VersionSize / 1KB), 2)
            $TotalFileSizeKB = [Math]::Round(($FileSizeinKB + $VersionSizeinKB), 2)
            $VersionSizeinMB = [Math]::Round(($VersionSize / 1MB), 2)
            $TotalFileSizeMB = [Math]::Round(($FileSizeinMB + $VersionSizeinMB), 2)
            $VersionSizeinGB = [Math]::Round(($VersionSize / 1GB), 2)
            $TotalFileSizeGB = [Math]::Round(($FileSizeinGB + $VersionSizeinGB), 2)
 
            #Extract Version History data
            $VersionHistoryData = [PSCustomObject]@{

                    "File Name"            = $_.FieldValues.FileLeafRef
                    "File URL"             = $_.FieldValues.FileRef
                    "Last Modified Date"   = $_.FieldValues.Modified
                    "Versions"             = $Versions.Count
                    "File Size (KB)"       = $FileSizeinKB
                    "Version Size (KB)"    = $VersionSizeinKB
                    "Total File Size (KB)" = $TotalFileSizeKB
                    "File Size (MB)"       = $FileSizeinMB
                    "Version Size (MB)"    = $VersionSizeinMB
                    "Total File Size (MB)" = $TotalFileSizeMB
                    "File Size (GB)"       = $FileSizeinGB
                    "Version Size (GB)"    = $VersionSizeinGB
                    "Total File Size (GB)" = $TotalFileSizeGB
                }

                if ( -not ($VersionHistoryDataTable.Contains($_.FieldValues.FileLeafRef))) {
                $VersionHistoryDataTable.Add($_.FieldValues.FileLeafRef, $VersionHistoryData)
                }

        }

            if (("" -ne $_.Title) -and ($VersionHistoryDataTable.Count -ne 0)) {
            $MasterTable[$_.Url.Split("/")[4]] = $VersionHistoryDataTable
            Write-Host "The table with Key: $($_.Url.Split("/")[4]) was added to the master table" -ForegroundColor Green
            }          


    }
    catch {
        Write-Host "Failed to connect or perform actions on site: $SiteUrl. Error: $_" -ForegroundColor Red
    }

}

# Data processing is now finished. We will now move on to report generation

try {
    #Check whether the module has been loaded
    if (-not (Get-Module PSExcel)) {
        Import-Module PSExcel -Force -ea Stop -Verbose:$false
    }
}
catch {
    Write-Error "Could not import the PsExcel module. Check that it is installed"
    Exit
}

$currentDate = Get-Date -Format "MM_dd_yyyy"
$WorkBookPath = "C:\Users\$($Env:USERNAME)\Documents\SharePointStorageReport_$currentDate.xlsx"
New-Excel -Path $WorkBookPath
#$MasterTable | ForEach-Object {$_.Values | Export-XLSX -Path $WorkBookPath -WorksheetName $_.Keys -Table -AutoFit -Force}

foreach ($Key in $MasterTable.Keys) {

    $Table = $MasterTable[$Key]

    if (($null -eq $Table.Values) -or ($null -eq $Table.Keys)){
        continue
    }

    $WorksheetName = $Key
    if ($Key.Contains(":")) {
        $WorksheetName = $Key.Split(":")[0]
    }

   $Table.Values | Export-XLSX -Path $WorkBookPath -WorksheetName $WorksheetName -Table -AutoFit

}

Write-Host "Done"