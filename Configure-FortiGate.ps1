$Configs = @{}

Function Initialize-Variables {
    $ApiToken = Read-Host "Enter API token generated on FortiGate"
    $Configs.add("ApiToken", $ApiToken)

    $LANIPAddress = Read-Host "Enter LAN Interface IP address (This should already be set for the script to connect to FortiGate.)"
    $Configs.add("LANIPAddress", $LANIPAddress)

    $WANIPAddress = Read-Host "Enter WAN Interface IP address (Enter 'DHCP' if this is the mode that should be used)"
    $Configs.add("WANIPAddress", $WANIPAddress)

    if ('DHCP' -ne $Configs.WANIPAddress) {
        $ISPIPAddress = Read-Host "Enter ISP router static IP address"
        $Configs.add("ISPIPAddress", $ISPIPAddress)
    }


}

$ErrorActionPreference = 'Stop'

Write-Host "Checking for PowerFGT module"
if ( -not (Get-Module PowerFGT)) {
    
    try {
        Import-Module PowerFGT
    }
    catch {
        Write-Host "Not found. Trying to install..." -ForegroundColor 'Yellow'
        Set-PSRepository PSGallery -InstallationPolicy Trusted
        Install-Module PowerFGT

        try {
            Import-Module PowerFGT
        }
        catch {
            Write-Error "Could not install the PowerFGT module. Check the network and try again."
            exit
        }
    }
}
else {
    Write-Host "PowerFGT module already installed. Continuing..." -ForegroundColor 'Green'
}

Initialize-Variables
# End Region

try {
    $FGTInfo = Connect-FGT $Configs.LANIPAddress -ApiToken $Configs.ApiToken -SkipCertificateCheck
}
catch {
    Write-Error "Could not connect to FortiGate using the provided API token. Check the token and try again."
    exit
}

# Set LAN interface values
#$LanInterface = Get-FGTSystemInterface lan | Set-FGTSystemInterface -role lan -allowaccess ping, https, ssh, fgfm -mode static -ip $Configs.LANIPAddress -netmask 255.255.255.0 -status up

# Set WAN interface values in DHCP or static addressing mode depending on user selection
if ('DHCP' -eq $Configs.WANIPAddress) {
    $WanInterface = Get-FGTSystemInterface wan | Set-FGTSystemInterface -role wan -allowaccess ping, fgfm -mode dhcp -status up
    Write-Host "Created WAN interface in DHCP Addressing Mode" -ForegroundColor 'Green'
}
else {
    $WanInterface = Get-FGTSystemInterface wan | Set-FGTSystemInterface -role wan -allowaccess ping, fgfm -mode static -ip $Configs.WANIPAddress -netmask 255.255.255.0 -status up
    Write-Host "Created WAN interface in Manual Addressing Mode with IP address $($Configs.WANIPAddress)" -ForegroundColor 'Green'
}

# if a static ISP router IP address was given, we create a default route on the WAN interface
if ($Configs.ContainsKey("ISPIPAddress")) {
    try {
        Get-FGTRouterStatic | Remove-FGTRouterStatic -Confirm:$false
        $DefaultRoute = Add-FGTRouterStatic -dst 0.0.0.0/0.0.0.0 -gateway $Configs.ISPIPAddress -device wan -distance 10
        Write-Host "Created default route 0.0.0.0/0.0.0.0 on wan port to $(Configs.ISPIPAddress)" -ForegroundColor 'Green'
    }
    catch {
        Write-Host "Static route already exists. Skipping route creation." -ForegroundColor 'Yellow'
    }

}

# if the dns server uses a Forinet SSL certificate, we assume that the FortiGate is using the FortiGuard servers
try {
    $FGTDNS = Get-FGTSystemDns -filter_attribute ssl-certificate -filter_value Fortinet -filter_type contains
    Write-Host "Confirmed system DNS is set to use FortiGuard servers." -ForegroundColor 'Green'
}
catch {
    Write-Host "FortiGate is not using FortiGuard DNS servers. Please go enable this on the GUI under Network > DNS" -ForegroundColor 'Yellow'
}

#Remove the default unnamed outbound policy, then create our own
Get-FGTFirewallPolicy | Remove-FGTFirewallPolicy -Confirm:$false
$OutboundPolicy = Add-FGTFirewallPolicy -name Outbound -srcintf lan -dstintf wan -srcaddr all -dstaddr all -schedule always -service ALL -action accept -inspectionmode flow -nat -sslsshprofile certificate-inspection -logtraffic all
Write-Host "Created Outbound Policy" -ForegroundColor 'Green'

$FGT = Get-FGTSystemGlobal
$Date = Get-Date -Format "MMddyyyy"

Write-Host "Backing up configuration to $PSScriptRoot. Please move file to client folder in Teams/OneDrive" -ForegroundColor 'Yellow'
Get-FGTMonitorSystemConfigBackup | Out-File -FilePath "$PSScriptRoot\$($FGT.hostname)_$($FGTInfo.version)_$($Date)_SIPALG-ENABLED.conf"

Write-Host "The default client setup for $($FGT.hostname) is complete. You may now login to the GUI and configure any client specific settings. Here is the information needed to create the CWM configuration: " -ForegroundColor 'Green'

$CWMConfig = [PSCustomObject]@{
    Name                  = $FGT.hostname
    Serial                = $FGTInfo.serial
    "WAN IP Address"      = $Configs.WANIPAddress
    "WAN Gateway Address" = $Configs.ISPIPAddress
    "DNS Server 1"        = $FGTDNS.primary
    "DNS Server 2"        = $FGTDNS.secondary
    "LAN IP Address"      = $Configs.LANIPAddress
}

$CWMConfig | Format-Table