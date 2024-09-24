#region script header
<#
.Synopsis


.DESCRIPTION


.PARAMETER


.NOTES


.EXAMPLE
  
     
#>
#endregion

Function Get-Manufacturer { # This function will return the host Manufacturer name

    $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

    if ($Manufacturer -eq "HP") {
        Get-iLoHealth
    } 
    elseif ($Manufacturer -eq "Dell Inc.") {
        Get-iDracHealth
    }
    else {
        Write-Host "Server Manufacturer is not HP or Dell. Manual auditing is required"
        exit
    }
}



Function Get-iLoHealth {
            # Check if HPEiLoCmdlets module is installed
            if (-not (Get-Module -ListAvailable -Name 'HPEiLoCmdlets')) {
                Write-Host "HPEiLoCmdlets module not found. Installing..."
                try {
                    Install-Module -Name 'HPEiLoCmdlets' -Force -Scope CurrentUser -Repository PSGallery
                    Write-Host "HPEiLoCmdlets module installed successfully."
                }
                catch {
                    Write-Host "Failed to install HPEiLoCmdlets module: $($_.Exception.Message)" -ForegroundColor Red
                    exit
                }
            }
            else {
                Write-Host "HPEiLoCmdlets module is already installed."
            }


}

Function Get-iDracHealth {
    

}