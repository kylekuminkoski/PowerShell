<#
.SYNOPSIS
.Removes bloat from a fresh Windows build
.DESCRIPTION
.Removes AppX Packages
.Disables Cortana
.Windows 10 and Windows 11 Compatible
.Creates default start layout
.Removes any unwanted installed applications
.Removes unwanted services and tasks
.Removes Edge Surf Game
.Configures registry for UAC and Secure Desktop
.Makes other registry changes to disable builtin windows bloat

.INPUTS
.OUTPUTS
C:\ProgramData\Debloat\Debloat.log
.NOTES
  Author:         Kyle Kuminkoski
  Creation Date:  10/31/2023

  *DISCLAIMER*
  If using this script for an image that is captured and 
  deployed using Microsoft Deployment Toolkit (MDT),
  verify that CopyProfile is set to TRUE within both Unattend.xml
  files of the Capture and Deployment task sequences. Without this, 
  any changes made to the user will not persist through and you will 
  only be left with changes made to HKLM.
#>

############################################################################################################
#                                         Initial Setup                                                    #
#                                                                                                          #
############################################################################################################

##Elevate if needed

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Write-Host "                                               3"
    Start-Sleep 1
    Write-Host "                                               2"
    Start-Sleep 1
    Write-Host "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'

#Create Folder
$DebloatFolder = "C:\ProgramData\Debloat"
If (Test-Path $DebloatFolder) {
    Write-Output "$DebloatFolder exists. Skipping."
}
Else {
    Write-Output "The folder '$DebloatFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$DebloatFolder" -ItemType Directory
    Write-Output "The folder $DebloatFolder was successfully created."
}

Start-Transcript -Path "C:\ProgramData\Debloat\Debloat.log"

$builtin = "Builtin"

############################################################################################################
#                                        Remove AppX Packages                                              #
#                                                                                                          #
############################################################################################################

    #Removes AppxPackages
    $WhitelistedApps = 'Microsoft.WindowsNotepad|Microsoft.CompanyPortal|Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|`
    |Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|.NET|Framework|`
    Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller|WindSynthBerry|MIDIBerry'
    #NonRemovable Apps that where getting attempted and the system would reject the uninstall, speeds up debloat and prevents 'initalizing' overlay when removing apps
    $NonRemovable = '1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|`
    Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.MicrosoftEdge|Microsoft.PPIProjection|Microsoft.Win32WebViewHost|Microsoft.Windows.Apprep.ChxApp|`
    Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|`
    Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|`
    Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|Windows.CBSPreview|windows.immersivecontrolpanel|Windows.PrintDialog|Microsoft.XboxGameCallableUI|Microsoft.VCLibs.140.00|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0|*Nvidia*'

    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} | Remove-AppxPackage
    Get-AppxPackage -allusers | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps -and $_.PackageName -NotMatch $NonRemovable} | Remove-AppxProvisionedPackage -Online


##Remove bloat
    $Bloatware = @(

        #Unnecessary Windows 10/11 AppX Apps
        "Microsoft.549981C3F5F10"
        "Microsoft.BingNews"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.MixedReality.Portal"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Office.Todo.List"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "MicrosoftTeams"
        "Microsoft.YourPhone"
        "Microsoft.XboxGamingOverlay_5.721.10202.0_neutral_~_8wekyb3d8bbwe"
        "Microsoft.GamingApp"
        "Microsoft.Todos"
        "Microsoft.PowerAutomateDesktop"
        "SpotifyAB.SpotifyMusic"
        "Disney.37853FC22B2CE"
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Office*"
        "*Disney*"
        "clipchamp.clipchamp"
        "*gaming*"
        "MicrosoftCorporationII.MicrosoftFamily"
        "MicrosoftCorporationII.QuickAssist"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        "*Microsoft.BingWeather*"
        "*Microsoft.MSPaint*"
        "*Microsoft.MicrosoftStickyNotes*"
        "*Microsoft.Windows.Photos*"

    )
    foreach ($Bloat in $Bloatware) {

        Get-AppxPackage -allusers -Name $Bloat| Remove-AppxPackage -AllUsers
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

############################################################################################################
#                                        Remove Registry Keys                                              #
#                                                                                                          #
############################################################################################################

#We need to grab all SIDs to remove at user level
$UserSIDs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Select-Object -ExpandProperty PSChildName

    #These are the registry keys that it will delete.
            
    $Keys = @(
            
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Host "Removing $Key from registry"
        Remove-Item $Key -Recurse
    }


    #Disables Windows Feedback Experience
    Write-Host "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"

    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0 
    }
            
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Host "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

    If (!(Test-Path $Search)) {
        New-Item $Search
    }
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0 

        #Disable Suggested Content in Windows Search
        Set-ItemProperty $Search EnableDynamicContentInWSB -Value 0
    }

    #Disables Web Search in Start Menu
    Write-Host "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1
    
    ##Loop through all user SIDs in the registry and disable Bing Search
    foreach ($sid in $UserSIDs) {
        $WebSearch = "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
        If (!(Test-Path $WebSearch)) {
            New-Item $WebSearch
        }
        Set-ItemProperty $WebSearch BingSearchEnabled -Value 0
    }
    
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 

    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Host "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

    ##Loop and do the same
    foreach ($sid in $UserSIDs) {
        $Period = "HKU:\$sid\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 
    }

    #Prevents bloatware applications from returning and removes Start Menu suggestions 
    
    Write-Host "Adding Registry key to disable push to install"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisablePushToInstall -Value 1

    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DontOfferThroughWUAU -Value 1

    Write-Host "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    Set-ItemProperty $registryOEM  FeatureManagementEnabled -Value 0 
    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  SoftLandingEnabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-310093Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-338388Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-338389Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-338393Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-353694Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContent-353696Enabled -Value 0
    Set-ItemProperty $registryOEM  SubscribedContentEnabled -Value 0
    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0 

    #Delete keys for suggestions and subscriptions
    Remove-ItemProperty $registryOEM Subscriptions
    Remove-ItemProperty $registryOEM SuggestedApps


    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $registryOEM = "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        If (!(Test-Path $registryOEM)) {
            New-Item $registryOEM
        }
        Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0
        Set-ItemProperty $registryOEM  FeatureManagementEnabled -Value 0 
        Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
        Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  SoftLandingEnabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-310093Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-338388Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-338389Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-338393Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-353694Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContent-353696Enabled -Value 0
        Set-ItemProperty $registryOEM  SubscribedContentEnabled -Value 0
        Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0 

        #Delete keys for suggestions and subscriptions
        Remove-ItemProperty $registryOEM Subscriptions
        Remove-ItemProperty $registryOEM SuggestedApps
    }

     #Preping mixed Reality Portal for removal    
     Write-Host "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
     $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
     If (Test-Path $Holo) {
         Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
     }   

    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Holo = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Holographic"    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
        }
    }

    #Disables Wi-fi Sense
    Write-Host "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
    #Disables live tiles
    Write-Host "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 

    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Live = "HKU:\$sid\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
        If (!(Test-Path $Live)) {      
            New-Item $Live
        }
        Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
    }

    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Host "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }



    #Disabling Location Tracking
    Write-Host "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0
  
    #Disables People icon on Taskbar

    Write-Host "Disabling Meet Now icon on Taskbar"
    $MeetNow = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    If (!(Test-Path $MeetNow)) { 
        New-Item $MeetNow
    }
    Set-ItemProperty $MeetNow HideSCAMeetNow -Value 1

    Write-Host "Disabling People icon on Taskbar"
    $People = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    If (!(Test-Path $People)) { 
        New-Item $People
    }
    Set-ItemProperty $People HidePeopleBar -Value 1

    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0
    }
    
    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $People = "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0
        }
    }
    
    Write-Host "Disabling Cortana"
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    If (!(Test-Path $Cortana1)) {
        New-Item $Cortana1
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
    If (!(Test-Path $Cortana2)) {
        New-Item $Cortana2
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
    If (!(Test-Path $Cortana3)) {
        New-Item $Cortana3
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0   

    ##Loop through users and do the same
    foreach ($sid in $UserSIDs) {
        $Cortana1 = "HKU:\$sid\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKU:\$sid\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKU:\$sid\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 0
    }


    #Removes 3D Objects from the 'My Computer' submenu in explorer
    Write-Host "Removing 3D Objects from explorer 'My Computer' submenu"
    $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (Test-Path $Objects32) {
        Remove-Item $Objects32 -Recurse 
    }
    If (Test-Path $Objects64) {
        Remove-Item $Objects64 -Recurse 
    }

    ##Removes the Microsoft Feeds from displaying
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
    $Name = "EnableFeeds"
    $value = "0"
    
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
    else {
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }

    ##Kill Cortana again
    Get-AppxPackage - allusers Microsoft.549981C3F5F10 | Remove AppxPackage

    
############################################################################################################
#                                        Remove Scheduled Tasks                                            #
#                                                                                                          #
############################################################################################################

    #Disables scheduled tasks that are considered unnecessary 
    Write-Host "Disabling scheduled tasks"
    $task1 = Get-ScheduledTask -TaskName XblGameSaveTaskLogon -ErrorAction SilentlyContinue
    if ($null -ne $task1) {
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    $task2 = Get-ScheduledTask -TaskName XblGameSaveTask -ErrorAction SilentlyContinue
    if ($null -ne $task2) {
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    $task3 = Get-ScheduledTask -TaskName Consolidator -ErrorAction SilentlyContinue
    if ($null -ne $task3) {
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    $task4 = Get-ScheduledTask -TaskName UsbCeip -ErrorAction SilentlyContinue
    if ($null -ne $task4) {
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    $task5 = Get-ScheduledTask -TaskName DmClient -ErrorAction SilentlyContinue
    if ($null -ne $task5) {
    Get-ScheduledTask  DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    $task6 = Get-ScheduledTask -TaskName DmClientOnScenarioDownload -ErrorAction SilentlyContinue
    if ($null -ne $task6) {
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }  


############################################################################################################
#                                             Disable Services                                             #
#                                                                                                          #
############################################################################################################
    Write-Host "Stopping and disabling Diagnostics Tracking Service"
    
    #Disabling the Diagnostics Tracking Service
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled

    Write-Output "Removing CloudStore from registry if it exists"

    #Removing the CloudStore
    $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
    If (Test-Path $CloudStore) {
        Stop-Process Explorer.exe -Force
        Remove-Item $CloudStore -Recurse -Force
        Start-Process Explorer.exe -Wait
    } 

############################################################################################################
#                                        Windows 11 Specific                                               #
#                                                                                                          #
############################################################################################################
    #Windows 11 Customisations
    write-host "Removing Windows 11 Customisations"
    #Remove XBox Game Bar
    
    Get-AppxPackage -allusers Microsoft.XboxGamingOverlay | Remove-AppxPackage
    write-host "Removed Xbox Gaming Overlay"
    Get-AppxPackage -allusers Microsoft.XboxGameCallableUI | Remove-AppxPackage
    write-host "Removed Xbox Game Callable UI"

    #Remove Cortana
    Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
    write-host "Removed Cortana"

    #Remove GetStarted
    Get-AppxPackage -allusers *getstarted* | Remove-AppxPackage
    write-host "Removed Get Started"

    #Remove Parental Controls
   Get-AppxPackage -allusers Microsoft.Windows.ParentalControls | Remove-AppxPackage 
   write-host "Removed Parental Controls"

#Remove Teams Chat
$MSTeams = "MicrosoftTeams"

$WinPackage = Get-AppxPackage -allusers | Where-Object {$_.Name -eq $MSTeams}
$ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $WinPackage }
If ($null -ne $WinPackage) 
{
    Remove-AppxPackage  -Package $WinPackage.PackageFullName -AllUsers
} 

If ($null -ne $ProvisionedPackage) 
{
    Remove-AppxProvisionedPackage -online -Packagename $ProvisionedPackage.Packagename -AllUsers
}

#Stop it from coming back
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath ConfigureChatAutoInstall -Value 0


#Unpin it
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath "ChatIcon" -Value 2
write-host "Removed Teams Chat"

############################################################################################################
#                                           Windows Backup App                                             #
#                                                                                                          #
############################################################################################################
    $version = Get-WMIObject win32_operatingsystem | Select-Object Caption
    if ($version.Caption -like "*Windows 10*") {
        write-host "Removing Windows Backup"
        $filepath = "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WindowsBackup\Assets"
    if (Test-Path $filepath) {
        Remove-WindowsPackage -Online -PackageName "Microsoft-Windows-UserExperience-Desktop-Package~31bf3856ad364e35~amd64~~10.0.19041.3393"
    }
    write-host "Removed"
    }

############################################################################################################
#                                             Clear Start Menu                                             #
#                                                                                                          #
############################################################################################################
write-host "Clearing Start Menu"
#Delete layout file if it already exists

##Check windows version
$version = Get-WMIObject win32_operatingsystem | Select-Object Caption
if ($version.Caption -like "*Windows 10*") {
    write-host "Windows 10 Detected"
    write-host "Removing Current Layout"
    If(Test-Path C:\Windows\StartLayout.xml)

    {
    
    Remove-Item C:\Windows\StartLayout.xml
    
    }
    write-host "Creating Default Layout"
    #Creates the blank layout file
    
    Write-Output "<LayoutModificationTemplate xmlns:defaultlayout=""http://schemas.microsoft.com/Start/2014/FullDefaultLayout"" xmlns:start=""http://schemas.microsoft.com/Start/2014/StartLayout"" Version=""1"" xmlns=""http://schemas.microsoft.com/Start/2014/LayoutModification"" xmlns:taskbar=""http://schemas.microsoft.com/Start/2014/TaskbarLayout"">" >> C:\Windows\StartLayout.xml
    
    Write-Output " <LayoutOptions StartTileGroupCellWidth=""6"" />" >> C:\Windows\StartLayout.xml
    
    Write-Output " <DefaultLayoutOverride>" >> C:\Windows\StartLayout.xml
    
    Write-Output " <StartLayoutCollection>" >> C:\Windows\StartLayout.xml
    
    Write-Output " <defaultlayout:StartLayout GroupCellWidth=""6"" />" >> C:\Windows\StartLayout.xml
    
    Write-Output " </StartLayoutCollection>" >> C:\Windows\StartLayout.xml
    
    Write-Output " </DefaultLayoutOverride>" >> C:\Windows\StartLayout.xml

    Write-Output " <CustomTaskbarLayoutCollection PinListPlacement=""Replace"">" >> C:\Windows\StartLayout.xml

    Write-Output "<defaultlayout:TaskbarLayout>" >> C:\Windows\StartLayout.xml

    Write-Output "<taskbar:TaskbarPinList>" >> C:\Windows\StartLayout.xml

    Write-Output "<taskbar:DesktopApp DesktopApplicationLinkPath=""%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk"" />" >> C:\Windows\StartLayout.xml

    Write-Output "<taskbar:DesktopApp DesktopApplicationLinkPath=""%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk"" />" >> C:\Windows\StartLayout.xml

    Write-Output "</taskbar:TaskbarPinList>" >> C:\Windows\StartLayout.xml

    Write-Output "</defaultlayout:TaskbarLayout>" >> C:\Windows\StartLayout.xml

    Write-Output "</CustomTaskbarLayoutCollection>" >> C:\Windows\StartLayout.xml
    
    Write-Output "</LayoutModificationTemplate>" >> C:\Windows\StartLayout.xml

    #Copy layout to default user profile layout modifications. (This is overwritten if CopyProfile is set to true. Added as a fallback)
    Copy-Item -Path C:\Windows\StartLayout.xml -Destination "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"

    #Copy layout to Administrator user profile (This is what will be used when CopyProfile is set to true)
    Copy-Item -Path C:\Windows\StartLayout.xml -Destination "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
}
if ($version.Caption -like "*Windows 11*") {
    write-host "Windows 11 Detected"
    write-host "Removing Current Layout"
    If(Test-Path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml")

    {
    
    Remove-Item "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
    
    }
    
$blankjson = @'
{ 
    "pinnedList": [ 
      { "desktopAppId": "Chrome" },  
      { "packagedAppId": "desktopAppId":"Microsoft.Windows.Explorer" } 
    ] 
  }
'@

$blankjson | Out-File "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Encoding utf8 -Force
$blankjson | Out-File "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Encoding utf8 -Force
}


############################################################################################################
#                                              Remove Xbox Gaming                                          #
#                                                                                                          #
############################################################################################################

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\xbgm" -Name "Start" -PropertyType DWORD -Value 4 -Force
Set-Service -Name XblAuthManager -StartupType Disabled
Set-Service -Name XblGameSave -StartupType Disabled
Set-Service -Name XboxGipSvc -StartupType Disabled
Set-Service -Name XboxNetApiSvc -StartupType Disabled
$task = Get-ScheduledTask -TaskName "Microsoft\XblGameSave\XblGameSaveTask" -ErrorAction SilentlyContinue
if ($null -ne $task) {
Set-ScheduledTask -TaskPath $task.TaskPath -Enabled $false
}

##Check if GamePresenceWriter.exe exists
if (Test-Path "$env:WinDir\System32\GameBarPresenceWriter.exe") {
    write-host "GamePresenceWriter.exe exists"

#Take-Ownership -Path "$env:WinDir\System32\GameBarPresenceWriter.exe"
$NewAcl = Get-Acl -Path "$env:WinDir\System32\GameBarPresenceWriter.exe"
# Set properties
$identity = "$builtin\Administrators"
$fileSystemRights = "FullControl"
$type = "Allow"
# Create new rule
$fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
$fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
# Apply new rule
$NewAcl.SetAccessRule($fileSystemAccessRule)
Set-Acl -Path "$env:WinDir\System32\GameBarPresenceWriter.exe" -AclObject $NewAcl
Stop-Process -Name "GameBarPresenceWriter.exe" -Force
Remove-Item "$env:WinDir\System32\GameBarPresenceWriter.exe" -Force -Confirm:$false

}
else {
    write-host "GamePresenceWriter.exe does not exist"
}

New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowgameDVR" -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -PropertyType String -Value "hide:gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking" -Force

############################################################################################################
#                                        Disable Edge Surf Game                                            #
#                                                                                                          #
############################################################################################################
$surf = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
If (!(Test-Path $surf)) {
    New-Item $surf
}
New-ItemProperty -Path $surf -Name 'AllowSurfGame' -Value 0 -PropertyType DWord

############################################################################################################
#                                         Configure Image Defaults                                         #
#                                                                                                          #
############################################################################################################

#Disable first logon animation
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath EnableFirstLogonAnimation -Value 0

#Configure lockscreen and UAC
Set-ItemProperty $registryPath dontdisplaylastusername -Value 0
Set-ItemProperty $registryPath DontDisplayUserName -Value 0
Set-ItemProperty $registryPath EnableLUA -Value 1
Set-ItemProperty $registryPath FilterAdministratorToken -Value 1
Set-ItemProperty $registryPath PromptOnSecureDesktop -Value 0
Set-ItemProperty $registryPath ConsentPromptBehaviorUser -Value 1
Set-ItemProperty $registryPath ConsentPromptBehaviorAdmin -Value 2
Set-ItemProperty $registryPath EnableInstallerDetection -Value 1

#Disable Remote UAC Restriction for PDQ
Set-ItemProperty $registryPath LocalAccountTokenFilterPolicy -Value 1

#Hide all Start Panel items except for the user profile folder on the desktop (0 to show / 1 to hide )
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath -Name "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Value 1
Set-ItemProperty $registryPath -Name "{208D2C60-3AEA-1069-A2D7-08002B30309D}" -Value 1
Set-ItemProperty $registryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 1
Set-ItemProperty $registryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 1
Set-ItemProperty $registryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value 0
Set-ItemProperty $registryPath -Name "{871C5380-42A0-1069-A2EA-08002B30309D}" -Value 1
Set-ItemProperty $registryPath -Name "{9343812e-1c37-4a49-a12e-4b2d810d956b}" -Value 1
Set-ItemProperty $registryPath -Name "{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}" -Value 1
Set-ItemProperty $registryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Value 1

#Hide OneDrive
Write-Host "Hiding OneDrive icon from the desktop"
$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"    
If (!(Test-Path $registryPath)) {      
    New-Item $registryPath
}
Set-ItemProperty $registryPath -Name "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Value 1
 

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $Live = "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"    
    If (!(Test-Path $registryPath)) {      
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath -Name "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Value 1
}

#Skip OOBE
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath SkipMachineOOBE -Value 1

#Disable Bing tips in search bar
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}

Set-ItemProperty $registryPath AllowOnlineTips -Value 0


write-host "Completed"

Stop-Transcript

Restart-Computer -Confirm