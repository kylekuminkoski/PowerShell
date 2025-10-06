# Define paths and names
$productName = "Smart Advocate Document Handler" # Replace with the actual product name
$certPath = "\\cpassc-serv\Plugins\SA_PubCert.cer"
$chromePolicyPath = "HKLM:\Software\Policies\Google\Chrome"
$extensionPolicyPath = "$chromePolicyPath\ExtensionInstallForcelist"
$extensionValue = "ofcdbngfnpdlmdligcclbkihfbahdnph;https://clients2.google.com/service/update2/crx"


# Function to check if the certificate is installed
function Is-CertificateInstalled {
    param (
        [string]$thumbprint
    )
    $cert = Get-ChildItem -Path Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq $thumbprint }
    return [bool]$cert
}

# Function to check if the registry keys are present
function Are-RegistryKeysPresent {
    param (
        [string]$chromePolicyPath,
        [string]$extensionPolicyPath,
        [string]$extensionValue
    )
    $chromePolicyExists = Test-Path -Path $chromePolicyPath
    $extensionPolicyExists = Test-Path -Path $extensionPolicyPath
    $extensionValueExists = (Get-ItemProperty -Path $extensionPolicyPath -Name "1" -ErrorAction SilentlyContinue)."1" -eq $extensionValue

    return $chromePolicyExists -and $extensionPolicyExists -and $extensionValueExists
}

# Function to check if the software is already installed
function Is-SoftwareInstalled {
    param (
        [string]$productName
    )
    # Check both 64-bit and 32-bit registry locations for installed software
    $installedSoftware = Get-ItemProperty -Path @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    ) -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*$productName*"
    }
    return [bool]$installedSoftware
}

# Check if the device "CPASSC-SERV" is reachable
$DeviceName = "CPASSC-SERV"
$PingResult = Test-Connection -ComputerName $DeviceName -Count 1 -Quiet

if (-not $PingResult) {
    Write-Host "Device '$DeviceName' is not reachable. Exiting script." -ForegroundColor Red
    exit 1
}

Write-Host "Device '$DeviceName' is reachable. Proceeding with script execution..." -ForegroundColor Green

# Main script logic
try {
    #enable .net 3.5 feature
    enable-WindowsOptionalFeature -online -FeatureName NetFx3 -norestart
    # Check if the certificate is installed
    $certThumbprint = (Get-PfxCertificate -FilePath $certPath).Thumbprint
    if (-not (Is-CertificateInstalled -thumbprint $certThumbprint)) {
        Write-Host "Certificate is not installed. Installing..."
     #   Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -ErrorAction Stop
        Write-Host "Certificate installed successfully."
    } else {
        Write-Host "Certificate is already installed. Skipping installation."
    }

    # Check if the registry keys are present
    if (-not (Are-RegistryKeysPresent -chromePolicyPath $chromePolicyPath -extensionPolicyPath $extensionPolicyPath -extensionValue $extensionValue)) {
        Write-Host "Registry keys are not configured. Configuring..."
        if (!(Test-Path -Path $chromePolicyPath)) {
            New-Item -Path $chromePolicyPath -Force | Out-Null
        }
        if (!(Test-Path -Path $extensionPolicyPath)) {
            New-Item -Path $extensionPolicyPath -Force | Out-Null
        }
        New-ItemProperty -Path $extensionPolicyPath -Name "1" -Value $extensionValue -PropertyType String -Force | Out-Null
        Write-Host "Registry keys configured successfully."
    } else {
        Write-Host "Registry keys are already configured. Skipping configuration."
    }

    # Check if the software is already installed
    if (-not (Is-SoftwareInstalled -productName $productName)) {
        Write-Host "$productName is not installed. Proceeding with installation..."

      # Verify the MSI file exists before proceeding
      $msiPath = "\\cpassc-serv\Plugins\ChromeSupport\SmartAdvocate Document Handler.msi"
      if (!(Test-Path $msiPath)) {
          Write-Host "MSI file not found at $msiPath. Exiting." -ForegroundColor Red
          exit 1
      }

      # Run the installer
      Write-Host "Starting installation of $productName..." -ForegroundColor Cyan
      
      $installArgs = "/i `"$msiPath`" SETUPEXEDIR=`"\\cpassc-serv\plugins\ChromeSupport`" SETUPEXENAME=`"SADocumentLauncher.exe`" /quiet /log `"$env:TEMP\SADocumentLauncher_install.log`""
      
      Write-Host "Executing: msiexec.exe $installArgs"
      
      # Start the installer and capture the exit code
      $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
      $exitCode = $process.ExitCode
      
      # Check if installation was successful
      if ($exitCode -eq 0) {
          Write-Host "Installation completed successfully." -ForegroundColor Green
      } else {
          Write-Host "Installation failed with exit code $exitCode." -ForegroundColor Red
          
          # Log more details about the error
          $logPath = "$env:TEMP\SADocumentLauncher_install.log"
          if (Test-Path $logPath) {
              Write-Host "Checking MSI log file: $logPath"
              Get-Content $logPath -Tail 20  # Display last 20 lines of the log for debugging
          } else {
              Write-Host "MSI log file not found. Check for permission or path issues." -ForegroundColor Yellow
          }
      
          exit $exitCode
      }
}
}catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}