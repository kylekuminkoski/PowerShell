Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 5
Start-Process -FilePath "C:\Program Files\Google\Chrome\Application\chrome.exe" -WorkingDirectory "C:\Program Files\Google\Chrome\Application"