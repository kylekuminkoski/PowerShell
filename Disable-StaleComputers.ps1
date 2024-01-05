Function Get-OldComputers {
    $filter = "(&"
    $filter += "(name=*)"
    $filter += "(|"
    # Laptop naming conventions
    $filter += "(name=HVS*)(name=HVB*)(name=HVK*)(name=HVR*)(name=HVHS*)(name=INV*)"
    # end OR
    $filter += ")"
    # Filter disabled computers
    $filter += "(&(objectclass=computer)(!useraccountcontrol=2))"
    # end AND
    $filter += ")"

    $searchBase = "OU=HVHS Computer,OU=TechOps,OU=Test,DC=hvhs,DC=org"
    # $searchBaseTest = "OU=WSUS - Laptop Test,OU=Information Systems,OU=HVHS Computer,OU=TechOps,OU=Test,DC=hvhs,DC=org"
    
     $computers = Get-ADComputer -LDAPFilter $filter -SearchBase $searchBase -Properties Description, OperatingSystem, LastLogonDate, whenCreated |
     Where-Object { ($_.LastLogonDate -lt [datetime]"1/1/2023") -and ($_.Enabled -eq $true) } |
     Sort-Object Name
    
     if ($null -eq $computers) {
         Write-Host "No Old devices were found." -ForegroundColor Green
         Exit
     }

     $computers
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

        $dn = [String] $Computer.DistinguishedName
        $OU = $dn.Split(',')[2].Split('=')[1]
    
        $lastlogon = $Computer.LastLogonDate
        $ReportItem = [PSCustomObject]@{
            Name = $Computer.Name
            "Organizational Unit" = $OU
            "Autologon (Y/N)" = "N"
            "Operating System" = $Computer.OperatingSystem
            "Description" = $Computer.Description
            "Last Logon Date" = ""
        }

        if ( $null -ne $lastlogon) { 

          $ReportItem.'Last Logon Date' =  $lastlogon | Get-Date -Format "MM/dd/yyyy"
        } 
    
        if ($null -eq $Computer.LastLogonDate) { 
            $creationDate = $Computer | Select-Object -ExpandProperty whenCreated | Get-Date -Format "MM/dd/yyyy"
            $ReportItem.'Last Logon Date' = "NEVER; Created: $creationDate"
        }

        try {
            $user = Get-ADUser -Identity $Computer.Name -Properties Description -ErrorAction SilentlyContinue
            } catch {}
            
            if ($user){
                $ReportItem.'Autologon (Y/N)' = "Y"
                
            }
    
    
        $StaleTable.Add($Computer.Name, $ReportItem)
    
    }

    Function Disable-Computer {
        Param(
            [Parameter(ValueFromPipeline)]
            [PSCustomObject]$Computer
        )

        $currentDate = Get-Date -Format "MM/dd/yyyy"

        $description = "DISABLED $currentDate KRK " + $Computer.Description

        Set-ADComputer -Identity $Computer.DistinguishedName -Description $description
        Set-ADComputer -Identity $Computer.DistinguishedName -Enabled $false
        Move-ADObject -Identity $Computer.DistinguishedName -TargetPath "OU=Disabled,OU=HVHS.Computers,DC=hvhs,DC=org"

        try {
            $user = Get-ADUser -Identity $Computer.Name -Properties Description, LastLogonDate -ErrorAction SilentlyContinue
            } catch {}
            
            if ($user){

                if ($user.LastLogonDate -gt [datetime]"1/1/2023") {
                    Write-Host "User account $($user.Name) will not be disabled. Last Logon Date is $($user.LastLogonDate)"
                    return
                }
                $description = "DISABLED $currentDate KRK " + $user.Description

                Set-ADUser -Identity $user.DistinguishedName -Description $description
                Set-ADUser -Identity $user.DistinguishedName -Enabled $false 
                Move-ADObject -Identity $user.DistinguishedName -TargetPath "OU=Script_Disabled,OU=Disabled,OU=HVHS.Users,DC=hvhs,DC=org"

            }

    }
    
    Function Format-AuditReport {
        Param (
            [System.Collections.Specialized.OrderedDictionary] $StaleTable
        )
    
        $currentDate = Get-Date -Format "MM_dd_yyyy"
        $WorkBookPath = "H:\Profile\Documents\$($Env:USERNAME)\My Documents\StaleADDeviceReport_$currentDate.xlsx"

        $StaleTable.values | Sort-Object -Property Name -Unique | Export-XLSX -Path $WorkBookPath -WorksheetName "Old Devices" -Table -AutoFit -Force
        Write-Host "Excel Workbook saved to $WorkBookPath"
    }
    
    $StaleDevicesReportTable = [ordered]@{}
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

    $count = 1
    $computers = Get-OldComputers

     foreach ($computer in $computers) { 
         $count += 1
         $computer | New-StaleDeviceReportItem -StaleTable $StaleDevicesReportTable
         $computer | Disable-Computer

        #if ($count -gt 250) { break }
     }

    Format-AuditReport -StaleTable $StaleDevicesReportTable
    
