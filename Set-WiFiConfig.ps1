Function Apply-PowerSettings
{
	(powercfg -list | select-string -pattern "Balanced") -match "(?i)([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})" | Out-Null
	$powerSchemeGUID = $matches[0]
	
	#Set sleep
	$sleepGUID = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
	powercfg -setacvalueindex $powerSchemeGUID $sleepGUID 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	powercfg -setdcvalueindex $powerSchemeGUID $sleepGUID 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	
	#Hibernate
	powercfg -setacvalueindex $powerSchemeGUID $sleepGUID 9d7815a6-7ee4-497e-8888-515a05f02364 0
	powercfg -setdcvalueindex $powerSchemeGUID $sleepGUID 9d7815a6-7ee4-497e-8888-515a05f02364 0
	
	#Lid
	$lidGUID = "4f971e89-eebd-4455-a8de-9e59040e7347"
	powercfg -setacvalueindex $powerSchemeGUID $lidGUID 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -setdcvalueindex $powerSchemeGUID $lidGUID 5ca83367-6e45-459f-a27b-476b1d01c936 0
	
	#Display
	$displayGUID = "7516b95f-f776-4464-8c53-06167f40cc99"
	powercfg -setacvalueindex $powerSchemeGUID $displayGUID 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 300
	#dim
	powercfg -setdcvalueindex $powerSchemeGUID $displayGUID 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 300
	#turn off
	powercfg -setacvalueindex $powerSchemeGUID $displayGUID 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 1200
	powercfg -setdcvalueindex $powerSchemeGUID $displayGUID 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 1200
	
	powercfg -setactive $powerSchemeGUID
    powercfg /H OFF
    #Set-NetAdapterAdvancedProperty -DisplayName 'Speed & Duplex' -DisplayValue '100 Mbps Full Duplex'
    Clear-Host
	echo "Applied power settings"
}

Function Set-WiFiRoamingAndBand {
    #Function to set a Wifi card's Roaming Aggressiveness to Highest and the Preferred Band to 5Ghz
    Write-Host "Checking to see if the computer has a WiFi adapter. If you know it has one, but it is not detected, contact TechOps to check the detection routines in this script."
    if (-not ($WiFi = Get-NetAdapter | Where-Object Name -Match 'Wi-?Fi|Wireless')) {
        Write-Host "No WiFi adapter detected"
        return
    }
    
    Function Set-DesiredWiFiAdapterProperty ($PropertyWildcard, $DesiredSettingRegex) {
        $AdvancedProperty = $WiFi | Get-NetAdapterAdvancedProperty -DisplayName $PropertyWildcard

        if ($AdvancedProperty) {
            foreach ($setting in $AdvancedProperty) {
                Write-Host "Found the setting $($setting.DisplayName) with a current setting of $($setting.DisplayValue)"

                $DesiredSetting = $setting | Select-Object -ExpandProperty ValidDisplayValues | Where-Object { $_ -match $DesiredSettingRegex }

                if ($DesiredSetting -and $DesiredSetting -ne $setting.DisplayValue) {
                    Write-Host "Found a setting of $DesiredSetting and applying it to $($setting.DisplayName)"
                    $setting | Set-NetAdapterAdvancedProperty -DisplayValue $DesiredSetting
                }
            }
        }
    }

    Write-Host "Attempting to set the roaming aggressiveness to its highest setting"
    Set-DesiredWiFiAdapterProperty -PropertyWildcard '*aggressive*' -DesiredSettingRegex '(?<!medium|m(?:e|i)d|medium(?:\s|-)|m(?:e|i)d(?:\s|-))high'

    Write-Host "Attempting to set the preferred band to 5Ghz"
    Set-DesiredWiFiAdapterProperty -PropertyWildcard '*band*' -DesiredSettingRegex '5[\s\d.]*Ghz'
}

Apply-PowerSettings
Set-WiFiRoamingAndBand