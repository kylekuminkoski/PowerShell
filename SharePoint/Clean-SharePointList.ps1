$siteURL="https://petersprofessionaleducation.sharepoint.com/sites/PetersProfessionalEducation"    
$listName="Documents"     
    
# Connect to SharePoint Online site    
Connect-PnPOnline -Url $SiteURL -Interactive -Clientid "65e90ea9-63b1-4ae9-b564-010d144ace3a"    
    
# Get the list items    
$itemColl=Get-PnPListItem -List $listName   
# Get the context    
$context=Get-PnPContext    
    
# Loop through the items    
foreach($item in $itemColl)    
{       
    # Get the item Versions    
    $versionColl=$item.Versions;    
    $context.Load($versionColl);    
    $context.ExecuteQuery();    
 $Counter=$VersionColl.Count  
 If($Counter -gt 0)  
    {  
        for($i=1;$i -lt $Counter;$i++)  
 {  
 #Remove the oldest version  
 $VersionColl[1].DeleteObject()  
 $context.ExecuteQuery()  
 $context.Load($versionColl);    
 $context.ExecuteQuery();  

        } 
        Write-Host -ForegroundColor Green "Deleted $versionsCount versions of file: $($item.ServerRelativeUrl)"

        # Add operation details to the array
        $operationDetails += [PSCustomObject]@{
            "File" = $item.ServerRelativeUrl
            "Operation" = "Deleted all versions"
            "Timestamp" = Get-Date
        } 
    } else {
        Write-Host -ForegroundColor DarkGray "No versions to delete for file: $($file.ServerRelativeUrl)"
    }     

      
}