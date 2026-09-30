[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param()

$Sites = Import-Csv "C:\Users\mhollier\OneDrive - Bastionpoint Technology LLC (1)\Documents\Swig\AllSitesData2.csv"
foreach ($Site in $Sites) {
#Config Parameters
$SiteURL = $Site.Url
$VersionsToKeep = 100
 
Try {
    #Connect to PnP Online
    Connect-PnPOnline -Url $SiteURL -Interactive
 
    #Get the Context
    $Ctx= Get-PnPContext
 
    #Exclude certain libraries
    $ExcludedLists = @("Form Templates", "Preservation Hold Library","Site Assets", "Pages", "Site Pages", "Images",
                            "Site Collection Documents", "Site Collection Images","Style Library")
 
    #Get All document libraries
    $DocumentLibraries = Get-PnPList | Where-Object {$_.BaseType -eq "DocumentLibrary" -and $_.Title -notin $ExcludedLists -and $_.Hidden -eq $false}
 
    #Iterate through each document library
    ForEach($Library in $DocumentLibraries)
    {
        Write-host "Processing Document Library:"$Library.Title -f Magenta
 
        #Get All Items from the List - Exclude 'Folder' List Items
        $ListItems = Get-PnPListItem -List $Library -PageSize 2000 | Where {$_.FileSystemObjectType -eq "File"}
 
        #Loop through each file
        ForEach ($Item in $ListItems)
        {
            #Get File Versions
            $File = $Item.File
            $Versions = $File.Versions
            $Ctx.Load($File)
            $Ctx.Load($Versions)
            $Ctx.ExecuteQuery()
  
            Write-host -f Yellow "`tScanning File:"$File.Name
            $VersionsCount = $Versions.Count
            $VersionsToDelete = $VersionsCount - $VersionsToKeep
            If($VersionsToDelete -gt 0)
            {
                write-host -f Cyan "`t Total Number of Versions of the File:" $VersionsCount
                $DeletedCount = 0
                #Delete versions
                For($VersionCounter=0; $VersionCounter -lt $VersionsCount -and $DeletedCount -lt $VersionsToDelete; $VersionCounter++)
                {
                    If($Versions[$VersionCounter].IsCurrentVersion)
                    {
                       Write-host -f Magenta "`t`t Retaining Current Major Version:"$Versions[$VersionCounter].VersionLabel
                       Continue
                    }
                    $VersionLabel = $Versions[$VersionCounter].VersionLabel
                    If($PSCmdlet.ShouldProcess("$($File.Name) (version $VersionLabel)", "Delete version"))
                    {
                        Write-host -f Cyan "`t Deleting Version:" $VersionLabel
                        $Versions[$VersionCounter].DeleteObject()
                        $DeletedCount++
                    }
                }
                If($DeletedCount -gt 0)
                {
                    $Ctx.ExecuteQuery()
                    Write-Host -f Green "`t Version History is cleaned for the File:"$File.Name
                }
            }
        }
    }
}
Catch {
    write-host -f Red "Error Cleaning up Version History!" $_.Exception.Message
}
}

#Read more: https://www.sharepointdiary.com/2018/05/sharepoint-online-delete-version-history-using-pnp-powershell.html#ixzz8FqvCW6vg