
#Requires -Version 3.0

[CmdletBinding(SupportsShouldProcess = $true)]

Param(
    [Parameter(Position = 0)]
    [String]$MountPoint = $env:SystemDrive

)

#region Helper Functions

Function Test-AdminRights {
    #Get the current users Windows Principal
    $Principal = New-Object System.Security.Principal.WindowsPrincipal -Args ([Security.Principal.WindowsIdentity]::GetCurrent())
    #Test if the user is currently a local administrator
    $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Test-EncryptionStatus {

    try {
        if ( -not (Get-Module Bitlocker)) {
            Import-Module Bitlocker -Force -ea SilentlyContinue -Verbose:$false
        }
        
    }
    catch {
        return "Bitlocker Module Required"
    }

    #Get the BitLocker info for the specified drive
    $Bv = Get-BitLockerVolume -MountPoint $MountPoint

    #We consider a device to be encrypted if it is not fully decrypted and has not key protectors set
    if ($Bv.VolumeStatus -ne "FullyDecrypted" -and $bv.KeyProtector.Count) {
        $true
    }
    else { $false }
}

Function Test-IsLaptop {
    $IsLaptop = $false

    #These chassis types used to determine laptop status came from the reference for the Microsoft Deployment Toolkit
    #Specifically how MDT populates the IsLaptop variable
    $LaptopChassisTypes = 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32

    #Get the machines chassis types
    $ChassisTypes = (Get-WmiObject Win32_SystemEnclosure).ChassisTypes

    #The previous WMI call can return multiple values, we need to go through all of them for laptop chassis types
    #and return $true if any of them match
    foreach ($item in $ChassisTypes) {
        if ($item -in $LaptopChassisTypes) {
            $IsLaptop = $true
        }
    }

    if (Get-WmiObject -Class win32_battery) { $IsLaptop = $true }

    $IsLaptop
}

Function Test-RecoveryKeySync {

    try {
        if ( -not (Get-Module Bitlocker)) {
            Import-Module Bitlocker -Force -ea SilentlyContinue -Verbose:$false
        }
        
    }
    catch {
        return "Bitlocker Module Required"
    }

    #Get the BitLocker info for the specified drive
    $Bv = Get-BitLockerVolume -MountPoint $MountPoint

    #We consider a device to be encrypted if it is not fully decrypted and has not key protectors set
    if ($Bv.VolumeStatus -eq "FullyEncrypted") {
        $KeyProtector = $Bv.KeyProtector
        if ( -not ($RecoveryPasswordObject = $KeyProtector | Where-Object KeyProtectorType -EQ RecoveryPassword)) {
            return $false
        } 

        # Looks for Active Directory Module, if it exists, set variable identifier so that it is not removed at the end of the function
        $IsADModulePresent = $false
        try {
            if (-not (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory -Force -ea SilentlyContinue -Verbose:$false } else { $IsADModulePresent = $true }
        }
        catch {
            return $false
                
        } 

        # Extract most recent Recovery Password Key Protector ID Attribute from Active Directory
        $dn = Get-ADComputer $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
        $ADRecoveryPasswordObject = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $dn -Properties whenCreated | Sort-Object -Property whenCreated -Descending | Select-Object -First 1 -ExpandProperty Name
        $ADRecoveryKeyID = $ADRecoveryPasswordObject.Split('{')[1].Split('}')[0]

        $LocalRecoveryKeyID = $RecoveryPasswordObject.KeyProtectorId.Split('{')[1].Split('}')[0]

        # if recovery key ID mismatch found, return true
        if ($ADRecoveryKeyID -ne $LocalRecoveryKeyID) {
            $true
        }


    }
    else { $false }

    # Remove Active Directory Powershell Module if it was not present originally
    if (-not $IsADModulePresent) { Remove-Module ActiveDirectory -Force -ea SilentlyContinue -Verbose:$false }

}

#endregion

$IsLaptop = Test-IsLaptop

# Do nothing if the device is not a laptop or Bitlocker is already enabled
if (-not $IsLaptop) {
    exit
}

$LogPath = "C:\Windows\Logs\Bitlocker_Encyption_Status.txt"
$date = Get-Date -Format "MM/dd/yyyy HH:mm K"

if ( (Test-EncryptionStatus) ) {
    if (Test-RecoveryKeySync) {
        $RecoveryPasswordObject = Get-BitLockerVolume -MountPoint $MountPoint | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -EQ RecoveryPassword
        "`n$date : [INFO] Key Mismatch found: Backing up Recovery Password to Active Directory" | Tee-Object -FilePath $LogPath -Append
        $ADSync = Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $RecoveryPasswordObject.KeyProtectorId -WarningAction SilentlyContinue -Confirm:$false  
    }

    if ($ADSync) {
        "`n$date : [SUCCESS] Recovery Password Key synced to Active Directory." | Tee-Object -FilePath $LogPath -Append
    }
    exit
}

if (-not (Test-AdminRights)) {
    "`n$date : [FAILED] Administrator privilege is required to execute this command" | Tee-Object -FilePath $LogPath -Append
    exit
}

$Tpm = Get-Tpm

if (-not $Tpm.TpmPresent) { 
    "`n$date : [FAILED] This computer does not have a TPM, or it is disabled in the BIOS" | Tee-Object -FilePath $LogPath -Append
    exit
}

if (-not (Get-TpmSupportedFeature | Where-Object { $_ -eq "key attestation" })) {
    "`n$date : [FAILED] This computer's TPM does not support the necessary features. Check that the TPM is at least version 1.2 or that it has the correct driver." | Tee-Object -FilePath $LogPath -Append
    exit
}

if (-not $Tpm.TpmReady) {

    if ( $Tpm.AutoProvisioning -eq "Disabled") {
        Enable-TpmAutoProvisioning -WarningAction SilentlyContinue
    }

    $TpmStatus = Initialize-Tpm -AllowClear -AllowPhysicalPresence -WarningAction SilentlyContinue

    if ($TpmStatus.ClearRequired) {
        Clear-Tpm -WarningAction SilentlyContinue
        "`n$date : [INFO] Clear TPM required before TPM initialization. Physical presence may be required to perform this in the BIOS." | Tee-Object -FilePath $LogPath -Append
    } 

    if ($TpmStatus.RestartRequired) {
        "`n$date : [INFO] Restart required to initialize TPM. Bitlocker will enable after two reboots." | Tee-Object -FilePath $LogPath -Append
    }

    if($TpmStatus.PhysicalPresenceRequired){
        "`n$date : [FAILED] Physical Presence Required to initialize TPM" | Tee-Object -FilePath $LogPath -Append
    }

    exit
}

if ($PSCmdlet.ShouldProcess($MountPoint, "Add Recovery Password Key Protector`n")) {
    $BitLockerVolume = Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue -Confirm:$false
    "`n$date : [INFO] Adding Recovery Password Key Protector" | Tee-Object -FilePath $LogPath -Append
}
$KeyProtector = $BitLockerVolume.KeyProtector

if (-not ($RecoveryPasswordObject = $KeyProtector | Where-Object KeyProtectorType -EQ RecoveryPassword)) {
    "`n$date : [FAILED] A recovery password key protector was not able to be created" | Tee-Object -FilePath $LogPath -Append
    exit
}

if ($PSCmdlet.ShouldProcess("Recovery Password", "Syncing Recovery Key To Active Directory`n")) {
    "`n$date : [INFO] Backing up Recovery Password to Active Directory" | Tee-Object -FilePath $LogPath -Append
    $ADSync = Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $RecoveryPasswordObject.KeyProtectorId -WarningAction SilentlyContinue -Confirm:$false   
}

if ( -not $ADSync) {
    "`n$date : [FAILED] Could not backup Recovery Password to Active Directory. Bitlocker will not be enabled" | Tee-Object -FilePath $LogPath -Append
    Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $RecoveryPasswordObject.KeyProtectorId -Confirm:$false 
    exit
}

if ($PSCmdlet.ShouldProcess($MountPoint, "Enable BitLocker using the TPM and a recovery password protector")) {
    try {
    Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod XtsAes128 -UsedSpaceOnly -TpmProtector -WarningAction SilentlyContinue -Confirm:$false -InformationAction SilentlyContinue -ErrorAction Stop
    "`n$date : [SUCCESS] Bitlocker will be enabled after computer restarts." | Tee-Object -FilePath $LogPath -Append
    }
    catch {
        "`n$date : [FAILED] Please check that the TPM 1.2 or later is installed in Security Settings -> Device Security -> Security Proccessor Details" | Tee-Object -FilePath $LogPath -Append
        exit
    }
} 