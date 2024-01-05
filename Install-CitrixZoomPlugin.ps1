
Function Test-AdminRights {
    #Get the current users Windows Principal
    $Principal = New-Object System.Security.Principal.WindowsPrincipal -Args ([Security.Principal.WindowsIdentity]::GetCurrent())
    #Test if the user is currently a local administrator
    $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Test-IsLaptop {
    $IsLaptop = $false

    #These chassis types used to determine laptop status came from the reference for the Microsoft Deployment Toolkit
    #Specifically how MDT populates the IsLaptop variable
    $LaptopChassisTypes = 8,9,10,11,12,14,18,21,30,31,32

    #Get the machines chassis types
    $ChassisTypes = (Get-WmiObject Win32_SystemEnclosure).ChassisTypes

    #The previous WMI call can return multiple values, we need to go through all of them for laptop chassis types
    #and return $true if any of them match
    foreach ($item in $ChassisTypes) {
        if ($item -in $LaptopChassisTypes) {
            $IsLaptop = $true
        }
    }

    $IsLaptop
}

Function Show-LaptopOverrideMenu {
    $title = "Laptop Not Detected"
    $message = "This computer was not detected as a laptop, so the Zoom Plugin for Citrix is not required. Would you like to install it anyways?"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes","Install it anyways"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&No","Do not install the plugin"
    $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no)

    $OverrideLaptopDetection = $host.UI.PromptForChoice($title, $message, $choices, 1)

    if ($OverrideLaptopDetection -eq 0) {
        $true
    }
    else { $false }
}

if (-not (Test-AdminRights)) {
    Write-Host "Administrator privilege is required to execute this command"
    exit
}

$IsLaptop = Test-IsLaptop

if (-not $IsLaptop) {
    $InstallCitrixPlugin = Show-LaptopOverrideMenu
}
else { $InstallCitrixPlugin = $IsLaptop }

if (-not $InstallCitrixPlugin) {
    Write-Host "The Zoom Citrix Plugin will not be installed"
    exit
}

$InstallPath = "\\hvhs-fs-04\GroupDrive\InformationTechnology\Software\zoom\ZoomCitrixHDXMediaPlugin.msi"
$LocalPath = Copy-Item $InstallPath -Destination "$env:PUBLIC\Downloads" -PassThru

Start-Process msiexec.exe -ArgumentList "/i $($LocalPath.FullName) /qn /norestart" -WorkingDirectory $LocalPath.DirectoryName -Wait

Remove-Item -Path $LocalPath.FullName

exit

