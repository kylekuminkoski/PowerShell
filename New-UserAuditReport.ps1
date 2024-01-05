Function Get-UserList {
    Param(
        [String]$SearchBase = "DC=hvhs,DC=org",

        [Switch]$DisabledUsers
    )
 

    if ($DisabledUsers) {
        Write-Host "Querying users at $SearchBase."
        $userObjects = Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' -SearchBase $SearchBase -Properties Name, DisplayName, Enabled, Description, LastLogonDate, PasswordLastSet, whenCreated
        Write-Host "Found $($userObjects.Count) users."
    }
    else {
        Write-Host "Querying all users at $SearchBase. Please wait..."
        $userObjects = Get-ADUser -LDAPFilter '(!userAccountControl:1.2.840.113556.1.4.803:=2)' -SearchBase $SearchBase -Properties Name, DisplayName, Enabled, Description, LastLogonDate, PasswordLastSet, whenCreated
        Write-Host "Found $($userObjects.Count) users."
    }


    $userObjects

# END of Get-UserList
}

Function New-ReportItem {
    Param (
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$User,
        [System.Collections.Specialized.OrderedDictionary]$Table,

        [Switch]$DisabledUsers
    )

        # Skip process if user is already included in the table
        if($Table.Contains($User.Name)) { return }

        # Calculate how long since user has checked in.
        $lastLogon = $User | Select-Object -ExpandProperty LastLogonDate
        $passLastSet = $User | Select-Object -ExpandProperty LastLogonDate
        $currentDate = Get-Date
    
        if ($null -ne $lastLogon) { $timeAway = $currentDate - $lastLogon } 
        if ($null -ne $passLastSet) {$timeSincePassChange = $currentDate - $passLastSet}

        # Get relevant OU
        $dn = [String] $User.DistinguishedName
        $OU = $dn.Split(',')[1].Split('=')[1]

        $ReportItem = [PSCustomObject]@{
            "User Name" = $User.Name
            "Display Name" = $User.DisplayName
            "Organizational Unit" = $OU
            Enabled = $User.Enabled
            Description = $User.Description
            "Last Logon" = $lastLogon | Get-Date -Format "MM/dd/yyyy"
            "Action (Disabled/Deleted)" = "None; User is active"
        }

        if ($null -eq $User.LastLogonDate) { 
            $creationDate = $User | Select-Object -ExpandProperty whenCreated | Get-Date -Format "MM/dd/yyyy"
            $ReportItem.'Last Logon' = "NEVER; Created: $creationDate"
        }
    
        # Mark user as stale if they haven't logged in within the past year; (Add disabling functionality here)
        if (($timeAway.TotalDays -gt 365) -or ($null -eq $User.LastLogonDate)){

            # Delete user if they've been disabled and password hasn't been changed for more than a year
            if ($DisabledUsers -and ($timeSincePassChange -gt 365)) {
                $ReportItem.'Action (Disabled/Deleted)' = "Deleted"
                Write-Host "$($User.Name) would be deleted"

            } else {
                $ReportItem.'Action (Disabled/Deleted)' = "Disabled"
                Write-Host "$($User.Name) would be disabled" 
            }



        }

        $Table.Add($User.Name, $ReportItem)
}

Function Format-AuditReport {
    Param (
        [System.Collections.Specialized.OrderedDictionary] $EnabledUsersTable,
        [System.Collections.Specialized.OrderedDictionary] $DisabledUsersTable
    )

    $currentDate = Get-Date -Format "MM_dd_yyyy"
    $WorkBookPath = "H:\Profile\Documents\$($Env:USERNAME)\My Documents\UserAuditReport_$currentDate.xlsx"

    $EnabledUsersTable.values | Sort-Object -Property Name | Export-XLSX -Path $WorkBookPath -WorksheetName "Enabled Users" -Table -AutoFit -Force

    $DisabledUsersTable.values | Sort-Object -Property Name | Export-XLSX -Path $WorkBookPath -WorksheetName "Disabled Users" -Table -AutoFit

}

$EnabledUsersTable = [ordered]@{}
$DisabledUsersTable = [ordered]@{}
$PSExcelPath = "\\hvhs-fs-04\GroupDrive\InformationTechnology\Software\Scripts_BatchFiles\PSExcel\1.0.2\PsExcel.psd1"

try {
    #Check whether the module has been loaded
    if (-not (Get-Module PSExcel)) {
        Import-Module $PSExcelPath -Force -ea Stop -Verbose:$false
    }
}
catch {
    Write-Error "Could not import the PsExcel module. Check the network and try again"
    Exit
}

Get-UserList -SearchBase "OU=Test,DC=hvhs,DC=org" | ForEach-Object { $_ | New-ReportItem -Table $EnabledUsersTable }
Get-UserList -SearchBase "OU=Test,DC=hvhs,DC=org" -DisabledUsers | ForEach-Object { $_ | New-ReportItem -Table $DisabledUsersTable -DisabledUsers }

Format-AuditReport -EnabledUsersTable $EnabledUsersTable -DisabledUsersTable $DisabledUsersTable