<#
.SYNOPSIS
Generate Bitlocker Reports
.DESCRIPTION
Get-EncryptionAuditReport will generate reports needed for Quarterly Encryption Audit. Three reports are created for stale devices, AD Bitlocker status, and local registry bitlocker status.
.PARAMETER SearchBase
The Distinguished Name of the OU to audit. This parameter is required or the script will not execute.
.INPUTS
System.String

Get-EncryptionAuditReport accepts System.String objects to the SearchBase parameter by value or property name
.OUTPUTS
Stale Devices Report, AD Bitlocker Report, Local Computer Bitlocker Report
#>
# Author: Kyle Kuminkoski
#
# Created on: July 3rd, 2023
#
# Example Usage:
# Get-EncryptionAuditReport -SearchBase "OU=HVHS Computer,OU=TechOps,OU=Test,DC=hvhs,DC=org"

[CmdletBinding()]

Param(
    [Parameter (Mandatory = $true)]
    [String]$SearchBase,

    [Switch]$LaptopOnly
)

try {
    if (-not (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory -Force -ea Stop -Verbose:$false }
}
catch {
    Write-Error "Could not import the Active Directory module. Check the network and try again."
    Exit-Command
}   

$volumeTypeTable = @{0 = "SYSTEM"; 1 = "FIXED DISK"; 2 = "REMOVABLE"; 3 = "N/A" }
$bitlockerStatusTable = @{0 = "FULLY DECRYPTED"; 1 = "FULLY ENCRYPTED"; 2 = "ENCRYPTION IN PROGRESS"; 3 = "DECRYPTION IN PROGRESS"; 4 = "ENCRYPTION PAUSED"; 5 = "DECRYPTION PAUSED"; 6 = "N/A" }
$encryptionMethodTable = @{0 = "NOT ENCRYPTED"; 1 = "AES 128 WITH DIFFUSER"; 2 = "AES 256 WITH DIFFUSER"; 3 = "AES 128"; 4 = "AES 256"; 5 = "HARDWARE ENCRYPTION"; 6 = "XTS-AES 128"; 7 = "XTS-AES 256 WITH DIFFUSER"; 8 = "N/A" }



# Get a list of Active Directory computer objects or laptops if the switch is present
if ($LaptopOnly) {
    Write-Host "Querying laptops at $SearchBase. Please wait..."
    $computerNames = Get-ADComputer -LDAPFilter "(&(name=*)(|(name=HVS*L*)(name=HVB*L*)(name=HVK*L*)(name=HVR*L*)(name=HVS*T*)(name=HVB*T*)(name=HVK*T*)(name=HVR*T*)(name=HVHSLAP*)(name=*LAP*)))" -SearchBase $SearchBase -Properties DistinguishedName, Name, LastLogonDate
}
else {
    Write-Host "Querying all computers at $SearchBase. Please wait..."
    $computerNames = Get-ADComputer -LDAPFilter "(name=*)" -SearchBase $SearchBase -Properties DistinguishedName, Name, LastLogonDate
}

# Empty ordered dictionary to store the results alphabetically by machine name
$localResults = [ordered]@{}
$ADResults = [ordered]@{}
$staleDevices = [ordered]@{}

# Iterate through each computer
$hostCount = $computerNames.Count
Write-Host "Found $hostCount Computers in $SearchBase OU. `nBeginning Scan..."
$scanCount = -1
foreach ($computerName in $computerNames) {

    #Background job to test if computer is pingable
    $pingTestJob = Start-Job -ArgumentList $computerName.Name -ScriptBlock {
        Test-Connection $args -Count 1 -BufferSize 16 -Quiet
    }

    $registryTestJob = Start-Job -ArgumentList $computerName.Name -ScriptBlock {
        if (Get-WmiObject -Class Win32_LogicalDisk -ComputerName $args -ErrorAction SilentlyContinue) {
            return $true
        } 
        else {
            return $false
        }
    }
    
    $scanCount++
    $progress = (($scanCount / $hostCount) * 100).ToString("F0")
    Write-Progress -Activity "Scan in Progress" -Status "Checking device $scanCount of $hostCount. In progress: $($computerName.Name)" -PercentComplete $progress
    # Calculate the total amount of time in days since a the computer has logged into AD.
    $lastLogon = $computerName | Select-Object -ExpandProperty LastLogonDate | Get-Date
    $presentDate = Get-Date
    $TotalDaysSinceLogon = ($presentDate - $lastLogon) | Select-Object -ExpandProperty Days

    # Checks for stale devices.
    #Skips Bitlocker check for any device that has not logged into Active Directory in the past 120 days.
    if ($TotalDaysSinceLogon -gt 120) {

        #Custom Object for separate report of devices considered no longer in use.
        $decomissionList = [PSCustomObject]@{
            ComputerName  = $computerName.Name
            LastLogonDate = $lastLogon
            TotalDaysAway = $TotalDaysSinceLogon.Days
        }

        #Add device to report and go to next computer in OU
        Write-Host "Stale Device found: $($computerName.Name). Last Logged in $($TotalDaysSinceLogon) Days ago."
        $staleDevices.Add($computerName.Name, $decomissionList)
        continue

    }

    #Create an object for the Bitlocker properties stored in Active Directory
    $Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $computerName.DistinguishedName -Properties 'msFVE-RecoveryPassword'

    if ($null -eq $Bitlocker_Object.'msFVE-RecoveryPassword') {
        # Computer does not have Bitlocker information stored in AD, assuming Bitlocker is disabled
        # Write this in AD report and skip the check on the computer locally
        $ADReportItem = [PSCustomObject]@{
            ComputerName     = $computerName.Name
            BitlockerEnabled = "False"
        }

        $ADResults.add($computerName.Name, $ADReportItem)
        Write-Host "No Bitlocker recovery key found in AD for $($computerName.Name). Skipping local check" -ForegroundColor "Yellow"
        continue
        
    } 
    else {
        # Write AD Bitlocker information to report and continue check with the device registry
        $ADReportItem = [PSCustomObject]@{
            ComputerName     = $computerName.Name
            BitlockerEnabled = "True"
        }

        $ADResults.add($computerName.Name, $ADReportItem)
        Write-Host "Found recovery key in Active Directory for $($computerName.Name)." -ForegroundColor "Green"
    }


    if (Receive-Job $pingTestJob -Wait) {
        Write-Host "Ping reply recieved from $($computerName.Name)"

        Write-Host "Accessing Registries on $($computerName.Name)"
        if (Receive-Job $registryTestJob -Wait) {
            # Retrieve drive information and BitLocker status from device registry
            try {
                $BitlockerRegistry = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -ComputerName $computerName.Name -ErrorAction Stop
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $computerName.Name -ErrorAction Stop
                $volumeType = $BitlockerRegistry | Select-Object -ExpandProperty VolumeType
                $bitlockerStatus = $BitlockerRegistry | Select-Object -ExpandProperty ConversionStatus
                $encryptionMethods = $BitlockerRegistry | Select-Object -ExpandProperty EncryptionMethod
                $status = "Success"
                Write-Host "Bitlocker status recieved from $($computerName.Name)" -ForegroundColor "Green"
            }
            catch [System.Runtime.InteropServices.COMException] {
                if ($_.Exception.ErrorCode -eq 0x800706BA) {
                    Write-Host "Could not connect to the remote registry of $($computerName.Name)" -ForegroundColor "Red"
                    $status = "RPC Server Unavailable"
                }
                else {
                    Write-Error -Message "A COMException Error Occured."
                    $status = "COMException Error"
                }
                $drives = " "
                $volumeType = 3
                $bitlockerStatus = 6
                $encryptionMethods = 8
           
            }
        }
        else {
            Write-Host "Registry could not be accessed." -ForegroundColor "Red"
            Receive-Job $registryTestJob -Wait
            $drives = " "
            $volumeType = 3
            $bitlockerStatus = 6
            $encryptionMethods = 8
        }
    }
    else {
        #if we cannot ping the computer then the registry checks do not happen and null is written to the report values
        $drives = " "
        $volumeType = 3
        $bitlockerStatus = 6
        $encryptionMethods = 8
        $status = "Host Unreachable"
        Write-Host "No reply recieved from $($computerName.Name). Skipping local check." -ForegroundColor "Yellow"
        Receive-Job $pingTestJob -Wait | Write-Host
    }

    # Iterate through each drive on the computer
    for ($i = 0; $i -le ($drives.length - 1); $i += 1) {
        # Create a custom object for BitLocker Audit Report
        $driveInfo = [PSCustomObject]@{
            ComputerName     = $computerName.Name
            DriveLetter      = $drives[$i].DeviceID
            VolumeType       = $volumeTypeTable[[int]$volumeType[$i]]
            BitLockerStatus  = $bitlockerStatusTable[[int]$bitlockerStatus[$i]]
            EncryptionMethod = $encryptionMethodTable[[int]$encryptionMethods[$i]]
            ScanResult       = $status
        }
        
        # Check if key already exists in the dictionary
        # If it does, add the drive path to the key name
        # Add the object to the results array
        if ($localResults.Contains($computerName.Name)) {
            $localResults.Add($computerName.Name + $i, $driveInfo)
        }
        else {
            $localResults.Add($computerName.Name, $driveInfo)
        }
    }
}

# Output the results as a table
$currentDate = Get-Date -Format "MM_dd_yyyy"
$scannedOU = Get-ADOrganizationalUnit -Identity $SearchBase -Properties * | Select-Object -ExpandProperty ou
If ($staleDevices.Count -eq 0) { Write-Host "No Stale Devices Found. `n " } else {
    $staleDevices.values | Export-Csv -Path "\\hvhs-fs-04\HomeDrive\$($Env:USERNAME)\staleDevicesReport_$($scannedOU)_$($currentDate).csv"
    Write-Host "Stale Devices Report successfully exported to HomeDrive.`n"
}

If ($ADResults.Count -eq 0) { Write-Host "No Bitlocker Devices Found in Active Directory. `n" } else {
    $ADResults.values | Export-Csv -Path "\\hvhs-fs-04\HomeDrive\$($Env:USERNAME)\ADBitlockerReport_$($scannedOU)_$($currentDate).csv"
    Write-Host "AD Bitlocker Report successfully exported to HomeDrive.`n"
}

If ($localResults.Count -eq 0) { Write-Host "No Bitlocker Information Found in Device Registries. `n" } else {
    $localResults.values | Export-Csv -Path "\\hvhs-fs-04\HomeDrive\$($Env:USERNAME)\LocalBitlockerReport_$($scannedOU)_$($currentDate).csv"
    Write-Host "Local Device Bitlocker Report successfully exported to HomeDrive. `n"
}

# Job Clean Up
Get-Job | Where-Object state -ne running | Remove-Job