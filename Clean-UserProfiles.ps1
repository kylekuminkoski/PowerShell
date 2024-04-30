# This script queries all user profiles on the machine and deletes any that have not been modified in 365 days.
# The results are formatted in a table and the user is prompted to review and confirm the results before deletion.

$ErrorActionPreference = 'Continue'

# Table Creation
Function New-TableItem {
    Param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$QueryItem,
        [System.Collections.Specialized.OrderedDictionary]$Table 
    )

    $Path = "$env:SystemDrive\Users\$($QueryItem.Name)"

    $ProfileSize = [math]::Round(((Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB),2)

    $TableItem = [PSCustomObject]@{
        Username = $QueryItem.Name
        LastWriteTime = $QueryItem.LastWriteTime
        Size = $ProfileSize.ToString() + " MB"
    }

    # Results are appended to an ordered dictionary, so table will be in alphabetical order by username
    $Table.add($TableItem.Username, $TableItem)
}

#Removal Function
Function Remove-UserProfile {
    Param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$TableItem
    )
    $LocalPath = "$env:SystemDrive\Users\$($TableItem.Username)"

    # Removal line will prompt user to confirm deletion before each profile
    Remove-Item -Path $LocalPath -Recurse -Force -Confirm
}


$path = "$env:SystemDrive\Users"
$ExcludedUsers="default","defaultuser0","Administrator", "Public"
$UserTable = [ordered]@{}
$UserProfileQuery = Get-ChildItem -Path $path -Exclude $ExcludedUsers | Where-Object {$_.lastwritetime -lt (Get-Date).AddDays(-365)}

$UserProfileQuery | ForEach-Object { $_ | New-TableItem -Table $UserTable}

$UserTable.Values | Format-Table -AutoSize

$UserTable.Values | ForEach-Object { $_ | Remove-UserProfile}
