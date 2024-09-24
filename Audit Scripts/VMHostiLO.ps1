# Install the HP iLO and Smart Array PowerShell modules
Install-Module -Name HPEiLOCmdlets
Install-Module -Name HPESmartArrayCmdlets

Import-Module HPEiLOCmdlets, HPESmartArrayCmdlets

# Variables
$Username = Read-Host -Prompt 'Input the iLo Admin Username'
$Password = Read-Host -Prompt 'Input the iLo Password'
$IPAddress = Read-Host -Prompt 'Input the iLo IP Address'
$iLOConnection = Connect-HPEiLO $IPAddress -Username $Username -Password $Password -DisableCertificateAuthentication
$SmartArray = Connect-HPESA -IP $IPAddress -Username $Username -Password $Password -DisableCertificateAuthentication

# Checks the HP iLO Status
Write-Host "`nDisplaying the iLO Serivce health and status.."
Get-HPEiLOHealthSummary $iLOConnection

# Checks the Smary Array service for drive health
Write-Host "`nDisplaying Physical drive information..`n"
Get-HPESAPhysicalDrive -Connection $SmartArray | Select-Object IP, PhysicalDrive, @{Name = "Health"; Expression= {$_.PhysicalDrive.Health}}
Write-Host "`nDisplaying Logical drive information.."
Get-HPESALogicalDrive -Connection $SmartArray | Select-Object IP, Status

# Disconnects from the iLO and Smart Array services
Write-Host "`nDisconnecting from the HP Services.."
Disconnect-HPEiLO -Connection $iLOConnection
Disconnect-HPESA -Connection $SmartArray

# Displays the current network configuration
Write-Host "`nDisplaying the current network configuration.."
Get-NetIPConfiguration | Select-Object InterfaceAlias, @{n='IPv4 Address';e={$_.IPv4Address.IPAddress}}, @{n='IPv4 Default Gateway';e={$_.IPv4DefaultGateway.NextHop}}, @{ n='DNSServer' ; e={$_.DNSServer.ServerAddresses -join "`n"}} | Format-List

# Displays the hard drive information
Write-Host "`nDisplaying the current drive information.."
Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'" | 
Select-Object -Property DeviceID, DriveType, VolumeName, 
@{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}},
@{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}