[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]$TenantSiteURL,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [ValidateRange(1, 50000)]
    [int]$VersionsToKeep = 20
)

# Check if PnP.PowerShell module is installed
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    # Install PnP.PowerShell module if it is not installed
    Install-Module -Name PnP.PowerShell -Force -Scope CurrentUser
}

# Import the module
Import-Module PnP.PowerShell

#Connect to Tenant Admin Site
Connect-PnPOnline -Url $TenantSiteURL -Interactive -Clientid $ClientId

#Get All Site collections data
$Sites = Get-PnPTenantSite -Detailed 

foreach ($Site in $Sites) {
    #Config Parameters
    $SiteURL = $Site.Url

    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -Interactive -Clientid $ClientId

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
            $ListItems = Get-PnPListItem -List $Library -PageSize 2000 | Where-Object {$_.FileSystemObjectType -eq "File"}

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

                    #Snapshot the deletable versions (oldest first) by stable VersionLabel BEFORE mutating the
                    #live Versions collection. Never retain the current version; the live collection index
                    #shifts as items are deleted, so we must not delete by live index.
                    $DeletableVersions = $Versions | Where-Object { -not $_.IsCurrentVersion } | Select-Object -First $VersionsToDelete
                    $LabelsToDelete = @($DeletableVersions | ForEach-Object { $_.VersionLabel })

                    if ($LabelsToDelete.Count -gt 0 -and $PSCmdlet.ShouldProcess($File.Name, "Delete $($LabelsToDelete.Count) old version(s)")) {
                        foreach ($Label in $LabelsToDelete) {
                            #Re-resolve the version by stable label so live-collection re-indexing during deletes is irrelevant
                            $TargetVersion = $Versions | Where-Object { $_.VersionLabel -eq $Label } | Select-Object -First 1
                            if ($null -ne $TargetVersion) {
                                Write-host -f Cyan "`t Deleting Version:" $Label
                                $TargetVersion.DeleteObject()
                            }
                        }
                        $Ctx.ExecuteQuery()
                        Write-Host -f Green "`t Version History is cleaned for the File:" $File.Name
                    }
                }
            }
        }
    }
    Catch {
        write-host -f Red "Error Cleaning up Version History!" $_.Exception.Message
    }
}
