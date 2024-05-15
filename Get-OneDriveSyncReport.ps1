Function New-TableItem {
    Param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$Item,
        [System.Collections.Specialized.OrderedDictionary]$Table 
    )

        $Count = $Item.kfmFolderCount
        $KnownFolders = ""
        if ($Count -eq 3){
            $KnownFolders = "All"
        } elseif ($Count -eq 0) {
            $KnownFolders = "None"            
        } else {
            $KnownFolders = "Some"
        }

        $TableItem = [PSCustomObject]@{
            User = $Item.userName
            Device = $Item.deviceName
            OS = $Item.osName
            OneDriveVersion = $Item.oneDriveVersion
            Sync = $KnownFolders
            
        }

        $Table.add($TableItem.User, $TableItem)

}

$Session = Invoke-RestMethod -Method Get -Uri "https://clients.config.office.net/odbhealth/v1.0/synchealth/reports?top=50&orderby=UserName%20asc" `
-Headers @{
    "authority"="clients.config.office.net"
    "path"="/odbhealth/v1.0/synchealth/reports?top=50&orderby=UserName%20asc"
    "scheme"="https"
    "accept"="application/json"
    "accept-encoding"="gzip, deflate, br, zstd"
    "accept-language"="en-US,en;q=0.9"
    "authorization"="Bearer 123456"
    "origin"="https://config.office.com"
    "priority"="u=1, i"
    "referer"="https://config.office.com/"
    "sec-ch-ua"="`"Chromium`";v=`"124`", `"Google Chrome`";v=`"124`", `"Not-A.Brand`";v=`"99`""
    "sec-ch-ua-mobile"="?0"
    "sec-ch-ua-platform"="`"Windows`""
    "sec-fetch-dest"="empty"
    "sec-fetch-mode"="cors"
    "sec-fetch-site"="cross-site"
    "x-api-name"="onedriveReports"
    "x-correlationid"="9bf1bfb9-0195-4dc9-b630-aaaf5434bd3a"
    "x-manageoffice-client-sid"="bcd0d44b-448b-4af8-906a-0a893262e95b"
    "x-requested-with"="XMLHttpRequest"
    "x-start-time"="1715344908385"
}

$ResultsTable = [ordered]@{}

$Report = $Session | Select-Object -ExpandProperty reports | Select-Object -Property userName, deviceName, oneDriveVersion, osName, kfmFolderCount, kfmFolders

$Report | ForEach-Object { $_ | New-TableItem -Table $ResultsTable}

$ResultsTable.Values | Export-Csv -Path $env:USERPROFILE\Documents\Report.csv