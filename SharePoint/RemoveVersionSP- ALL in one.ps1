# Check if PnP.PowerShell module is installed
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    # Install PnP.PowerShell module if it is not installed
    Install-Module -Name PnP.PowerShell -Force -Scope CurrentUser
}

# Import the module
Import-Module PnP.PowerShell

#Config Variables
$TenantSiteURL = "https://petersprofessionaleducation-admin.sharepoint.com/"
$VersionsToKeep = 0

#Connect to Tenant Admin Site
Connect-PnPOnline -Url $TenantSiteURL -Interactive -Clientid "65e90ea9-63b1-4ae9-b564-010d144ace3a"

#Get All Site collections data
$Sites = Get-PnPTenantSite -Detailed 

foreach ($Site in $Sites) {
    #Config Parameters
    $SiteURL = $Site.Url

    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -Interactive -Clientid "65e90ea9-63b1-4ae9-b564-010d144ace3a"

        #Get the Context
        $Ctx = Get-PnPContext

        #Exclude certain libraries
        $ExcludedLists = @("Form Templates", "Preservation Hold Library", "Site Assets", "Pages", "Site Pages", "Images",
                            "Site Collection Documents", "Site Collection Images", "Style Library")

        #Get All document libraries
        $DocumentLibraries = Get-PnPList | Where-Object {$_.BaseType -eq "DocumentLibrary" -and $_.Title -notin $ExcludedLists -and $_.Hidden -eq $false}

        #Iterate through each document library
        ForEach($Library in $DocumentLibraries) {
            Write-host "Processing Document Library:" $Library.Title -f Magenta

            #Get All Items from the List - Exclude 'Folder' List Items
            $ListItems = Get-PnPListItem -List $Library -PageSize 2000 | Where {$_.FileSystemObjectType -eq "File"}

            #Loop through each file
            ForEach ($Item in $ListItems) {
                #Get File Versions
                $File = $Item.File
                $Versions = $File.Versions
                $Ctx.Load($File)
                $Ctx.Load($Versions)
                $Ctx.ExecuteQuery()

                Write-host -f Yellow "`tScanning File:" $File.Name
                $VersionsCount = $Versions.Count
                $VersionsToDelete = $VersionsCount - $VersionsToKeep
                If($VersionsToDelete -gt 0) {
                    write-host -f Cyan "`t Total Number of Versions of the File:" $VersionsCount
                    $VersionCounter = 0
                    #Delete versions
                    For($i = 0; $i -lt $VersionsToDelete; $i++) {
                        If($Versions[$VersionCounter].IsCurrentVersion) {
                           $VersionCounter++
                           Write-host -f Magenta "`t`t Retaining Current Major Version:" $Versions[$VersionCounter].VersionLabel
                           Continue
                        }
                        Write-host -f Cyan "`t Deleting Version:" $Versions[$VersionCounter].VersionLabel
                        $Versions[$VersionCounter].DeleteObject()
                    }
                    $Ctx.ExecuteQuery()
                    Write-Host -f Green "`t Version History is cleaned for the File:" $File.Name
                }
            }
        }
    }
    Catch {
        write-host -f Red "Error Cleaning up Version History!" $_.Exception.Message
    }
}
