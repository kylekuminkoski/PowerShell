[CmdletBinding()]

$VerbosePreference = "Continue"

if ( -Not (Test-Path C:\Temp) ) {
    New-Item -Path "C:\" -Name "Temp" -ItemType Directory
}

Invoke-WebRequest -Uri "https://download.microsoft.com/download/1/f/0/1f0e9569-3350-4329-b443-822976f29284/ALTools.exe" -OutFile "C:\Windows\Temp\ALTools.exe"
