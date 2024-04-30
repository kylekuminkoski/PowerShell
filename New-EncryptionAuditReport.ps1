    <#
    .SYNOPSIS
    Builds a report for the Quarterly Encryption Audit Ticket
    .Description
    Get-EncryptionAuditReport generates an excel workbook with statistics on current Active Directory computer objects. The reports consist of 
    information pertaining to the computer's Bitlocker status, Current OU, and other useful information. 
    .PARAMETER
    Get-EncryptionAuditReport takes no parameters.

    .INPUTS
    None

    .OUTPUTS
   EncryptionAuditReport_CURRENTDATE.xlsx

    .EXAMPLE
    .\New-EncryptionAuditReport.ps1

    This command will save the encryption audit report to the current user's Documents directory within the HomeDrive
    #>
Function Get-ComputerList {
    Param(
        [String]$SearchBase = "DC=domain,DC=org",

        [Switch]$LaptopsOnly
    )
    $laptopFilter = "(&"
    $laptopFilter += "(name=*)"
    $laptopFilter += "(|"
    # Laptop naming conventions
    $laptopFilter += "(name=HVS*L*)(name=HVB*L*)(name=HVK*L*)(name=HVR*L*)(name=HVS*T*)(name=HVB*T*)(name=HVK*T*)(name=HVR*T*)(name=domain*)(name=*LAP*)"
    # end OR
    $laptopFilter += ")"
    # Filter disabled computers
    $laptopFilter += "(&(objectclass=computer)(!useraccountcontrol:1.2.840.113556.1.4.804:=2))"
    # end AND
    $laptopFilter += ")"

    if ($LaptopsOnly) {
        Write-Host "Querying laptops at $SearchBase."
        $computerObjects = Get-ADComputer -LDAPFilter $laptopFilter -SearchBase $SearchBase -Properties Name, DistinguishedName, Description, OperatingSystem, LastLogonDate, whenCreated
        Write-Host "Found $($computerObjects.Count) laptops."
    }
    else {
        Write-Host "Querying all computers at $SearchBase. Please wait..."
        $computerObjects = Get-ADComputer -LDAPFilter "(&(name=*)(&(objectclass=computer)(!useraccountcontrol:1.2.840.113556.1.4.804:=2)))" -SearchBase $SearchBase -Properties Name, DistinguishedName, Description, OperatingSystem, LastLogonDate, whenCreated
        Write-Host "Found $($computerObjects.Count) computers."
    }


    $computerObjects

# END of Get-ComputerList
}

Function New-StaleDeviceReportItem {
    Param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$Computer,
        [int] $TotalDaysAway,
        [System.Collections.Specialized.OrderedDictionary]$StaleTable
    )

    # Skip process if computer is already included in the report
    if($StaleTable.Contains($Computer.Name)) { return }

    $ReportItem = [PSCustomObject]@{
        Name = $Computer.Name
        "Operating System" = $Computer.OperatingSystem
        Description = $Computer.Description
        "Last Logon Date" = $lastLogon | Get-Date -Format "MM/dd/yyyy"
        "Total Days Away" = $TotalDaysAway
    }

    if ($null -eq $Computer.LastLogonDate) { 
        $creationDate = $Computer | Select-Object -ExpandProperty whenCreated | Get-Date -Format "MM/dd/yyyy"
        $ReportItem.'Last Logon Date' = "NEVER; Created: $creationDate"
        $ReportItem.'Total Days Away' = "N/A"
    }


    $StaleTable.Add($Computer.Name, $ReportItem)

}

Function New-ReportItem {
    Param (
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$Computer,
        [System.Collections.Specialized.OrderedDictionary]$MainTable,
        [System.Collections.Specialized.OrderedDictionary]$StaleTable
    )

    # Skip process if computer is already included in the table
    if($MainTable.Contains($Computer.Name)) { return }

    # Calculate how long since device has checked in.
    $lastLogon = $Computer | Select-Object -ExpandProperty LastLogonDate
    $currentDate = Get-Date

    if ($null -ne $lastLogon) { $timeAway = $currentDate - $lastLogon } 

    # Add item to stale device table and skip adding to main report
    if (($timeAway.TotalDays -gt 120) -or ($null -eq $Computer.LastLogonDate)){
        $Computer | New-StaleDeviceReportItem -TotalDaysAway $timeAway.TotalDays -StaleTable $StaleTable
        return
    }


    #Extract Bitlocker recovery key and computer OU from Distinguished Name
    $Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $Computer.DistinguishedName -Properties *
    $dn = [String] $Computer.DistinguishedName
    $OU = $dn.Split(',')[2].Split('=')[1]


    # Determining if computer has a Bitlocker key, is in the Medcart OU, both, or neither
    if ($null -ne $Bitlocker_Object.'msFVE-RecoveryPassword') {

        $BitlockerDate = $Bitlocker_Object.Created | Sort-Object -Descending | Select-Object -First 1 | Get-Date -Format "MM/dd/yyyy"
        $Bitlocker = "Enabled on " + $BitlockerDate

        if ($OU -eq "Medcarts") { $Encryption = "Bitlocker + MedcartOU" } else { $Encryption = "Bitlocker" }

    } else {

        $Bitlocker = "Disabled"

        if ($OU -eq "Medcarts") { $Encryption = "MedcartOU" } else { $Encryption = "None" }
    }

    # Object for each entry into final report
    $ReportItem = [PSCustomObject]@{
        Name = $Computer.Name
        "Operating System" = $Computer.OperatingSystem
        "Organizational Unit" = $OU
        Bitlocker = $Bitlocker
        Encryption = $Encryption
        Description = $Computer.Description
        "Last Logon Date" = $lastLogon | Get-Date -Format "MM/dd/yyyy"
    }


   $MainTable.Add($Computer.Name, $ReportItem)
}

Function Format-AuditReport {
    Param (
        [System.Collections.Specialized.OrderedDictionary] $MainTable,
        [System.Collections.Specialized.OrderedDictionary] $StaleTable
    )

    $currentDate = Get-Date -Format "MM_dd_yyyy"
    $WorkBookPath = "H:\Profile\Documents\$($Env:USERNAME)\My Documents\EncryptionAuditReport_$currentDate.xlsx"

    $EncryptionReportTable.values | Sort-Object -Property Name -Unique | Export-XLSX -Path $WorkBookPath -WorksheetName "Encryption Report" -Table -AutoFit -Force
    $StaleDevicesReportTable.values | Sort-Object -Property Name -Unique | Export-XLSX -Path $WorkBookPath -WorksheetName "Old Devices" -Table -AutoFit
    New-Excel -Path $WorkBookPath | Add-PivotTable -WorkSheetName "Encryption Report" -PivotTableWorksheetName "Summary" -PivotRows "Encryption" -PivotValues "Encryption" -ChartTitle "Summary of Encryption Audit" -ChartType "Pie3D" -ChartHeight 600 -ChartWidth 800 -Passthru | Save-Excel -Close
    Write-Host "Excel Workbook saved to $WorkBookPath"
}

$EncryptionReportTable = [ordered]@{}
$StaleDevicesReportTable = [ordered]@{}
$PSExcelPath = "$PSScriptRoot\PSExcel\1.0.2\PsExcel.psd1"

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

$medcartComputerList = Get-ComputerList -SearchBase "OU=MedCarts,OU=domain.Computers,DC=domain,DC=org"

$laptopList = Get-ComputerList -SearchBase "OU=domain.Computers,DC=domain,DC=org" -LaptopsOnly

$AllComputersList = $medcartComputerList + $laptopList

$AllComputersList | ForEach-Object { $_ | New-ReportItem -MainTable $EncryptionReportTable -StaleTable $StaleDevicesReportTable }

Format-AuditReport -MainTable $EncryptionReportTable -StaleTable $StaleDevicesReportTable