try {
    if( -not (Get-Module Bitlocker)){
        Import-Module Bitlocker -Force -ea SilentlyContinue -Verbose:$false
    }
    
    }
    catch {
      return "Bitlocker Module Required"
    }
       
    #Get the BitLocker info for the specified drive
        $Bv = Get-BitLockerVolume -MountPoint $env:SYSTEMDRIVE
    
        #We consider a device to be encrypted if it is not fully decrypted and has key protectors set
        if ($Bv.VolumeStatus -eq "FullyEncrypted") {
            $KeyProtector = $Bv.KeyProtector
            if ( -not ($RecoveryPasswordObject = $KeyProtector | Where-Object KeyProtectorType -EQ RecoveryPassword)) {
                return "N/A"
            } 
    $LocalRecoveryKeyID = $RecoveryPasswordObject.KeyProtectorId.Split('{')[1].Split('}')[0]
    return $LocalRecoveryKeyID
    }
