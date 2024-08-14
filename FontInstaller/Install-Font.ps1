# This script installs fonts from a given zip archive

[CmdletBinding()]
param(
    [Parameter (Mandatory = $true)]
    $ArchivePath
)

$FontsToInstallDirectory = "$PSScriptRoot\FontsToInstall"
if (Test-Path $ArchivePath) {
    $TempPath = "$PSScriptRoot\temp"
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $TempPath -Force
    Move-Item -Path "$TempPath\*" -Destination $FontsToInstallDirectory -Force
    Remove-Item -Path $TempPath -Recurse -Force

}
else {
    Write-Error "Archive at $ArchivePath does not exist. Please check file location and try again."
}

$FontsToInstall = Get-ChildItem $FontsToInstallDirectory -Recurse -Include '*.ttf', '*.ttc', '*.otf'

foreach ($Font in $FontsToInstall) {
    $Name = $Font.Name
    $InstalledFonts = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts"
    $RegKey = Get-Item $InstalledFonts
    If ($Font.Name -ne $RegKey.GetValue($Font.BaseName)) {
        Copy-Item $Font "C:\Windows\Fonts"
       $Reg = New-ItemProperty -Name $Font.BaseName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $Font.Name -Force 
        Write-Host "Installed Font $Name" -ForegroundColor Cyan
    }
    else {
        Write-Host "Font $Name is already installed" -ForegroundColor Green
    }
}

#Cleanup
Remove-Item "$PSScriptRoot\FontsToInstall" -Recurse -Force