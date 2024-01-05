# This script will run HP Image Assistant and install any applicable updates for the device

if (Test-Path C:\SWSetup\SP149392\HPImageAssistant.exe) {
     
Start-Process C:\SWSetup\SP149392\HPImageAssistant.exe -ArgumentList "/Operation:Analyze /Action:Install /SoftpaqDownloadFolder:C:\SWSetup /ReportFolder:C:\HPIA /Silent" -Wait

}