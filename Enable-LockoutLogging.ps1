[CmdletBinding()]
$VerbosePreference = "Continue"

if ( -Not (Test-Path C:\Windows\Temp) ) {
    New-Item -Path "C:\Windows" -Name "Temp" -ItemType Directory

}

if (Test-Path C:\Windows\Temp\ALTools) {
    Remove-Item -Path C:\Windows\Temp\ALTools -Recurse -Force
}

New-Item -Path "C:\Windows\Temp" -Name "ALTools" -ItemType Directory
$RootPath = "C:\Windows\Temp\ALTools"
Invoke-WebRequest -Uri "https://download.microsoft.com/download/1/f/0/1f0e9569-3350-4329-b443-822976f29284/ALTools.exe" -OutFile "$RootPath\ALTools.exe"

if (Test-Path C:\Windows\Temp\ALTools\ALTools.exe){
    Start-Process -FilePath "$RootPath\ALTools.exe" -ArgumentList "/Q /T:$RootPath" -Wait
}

Expand-Archive -Path $RootPath\Alockout.zip -DestinationPath $RootPath\Alockout
Copy-Item $RootPath\Alockout\alockout.dll -Destination C:\Windows\System32\

if (Test-Path C:\Windows\System32\alockout.dll){
    try {
        Start-Process -FilePath "$RootPath\Alockout\appinit.reg" -Wait
        Write-Host "Account lockout events will now be logged at C:\Windows\debug\Alockout.LOG"
        Write-Verbose "A reboot is required for changes to take effect."
        Restart-Computer -Confirm
    }
    catch {
        Write-Error "An error occurred. No changes were made"
        exit
    }
}