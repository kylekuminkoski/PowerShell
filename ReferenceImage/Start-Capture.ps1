<#
.SYNOPSIS
Starts an MDT capture task.
.DESCRIPTION
Start-Capture starts a Microsoft Deployment Toolkit task to cpature reference images. This script also performs some checks and cleanup before starting the capture task.
.PARAMETER DeployRoot
The UNC path of the root of the MDT Deployment Share. The server name should be a FQDN since reference images are not joined to a domain.

The default value is \WDS-HVB-02.hvhs.org\CaptureShare$
.PARAMETER Credential
The credential to use to connect to the Deployment Share.

If this parameter is not provided, the user will be prompted to enter one.
.INPUTS
None.

Start-Capture does not accept pipeline input.
.OUTPUTS
None.

Start-Capture does not produce any output.
.EXAMPLE
Start-Capture

This command will start an MDT capture task for reference images using the Deployment Share at \\WDS-HVB-01.hvhs.org\ProductionDeploymentShare$, and the user will prompt for the credentials to use to connect to the Deployment Share.
.EXAMPLE
#>

[CmdletBinding()]

Param(
    [String]$DeployRoot = "\\WDS-HVB-02.hvhs.org\CaptureShare$",

    [pscredential]$Credential
)

#Test for Administrator privileges.
Write-Host "`nTesting for Administrator privileges"
$IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "This command must be run as an administrator"
    exit
}

#Check that we're dealing with a correctly named reference image
if ($env:COMPUTERNAME -notmatch '^WIN1(?:0X(?:86|64)|1X64)-REF$') {
    Write-Error "This computer does not have a valid reference image name. MDT uses the name to determine which Capture Task Sequence to run. Either switch to a valid reference image, or rename the computer to the following format depending on the relevant Windows version and architecture: WIN<10|11><X86|X64>-REF"
    exit
}

#Prompt for credential if none was provided.
if (-not $Credential) { $Credential = Get-Credential -Message "You must provide a domain in the format of domain\username" }

#Get the Network Credential for use with LiteTouch arguments
$NetworkCred = $Credential.GetNetworkCredential()

#Test that a domain was given in the credential
if (-not $NetworkCred.Domain) {
    Write-Error "No domain was provided in the credential. Use the format of domain\username in the credential dialog"
    exit
}

#Uninstall the Adobe Customization Wizard
Write-Host "`nUninstalling the Adobe Customization Wizard"
try {
    $WizardUninstallProcess = Start-Process -FilePath (Get-Command msiexec.exe).Source `
        -Args '/x {AC76BA86-1033-0000-0000-0C15074E7B00} /qn /norestart' -PassThru -Wait
    
    if ($WizardUninstallProcess.ExitCode -notin @(3010,1605,0)) {
        throw "Exit code $($WizardUninstallProcess.ExitCode) was occurred"
    }
}
catch {
    Write-Error "There was an error while uninstalling the Adobe Customization Wizard: $_"
}

#Run Clean-WindowsImage.ps1
& $PSScriptRoot\Clean-WindowsImage.ps1


#Create a PSDrive for the Deployment Share

#Add a PSDrive to the drive letter
Write-Host "`nMounting MDT Deployment Share"
try {
    $Drive = New-PSDrive -Name Deploy -PSProvider FileSystem -Root $DeployRoot -Credential $Credential -ea Stop
}
catch { Write-Error "Could not mount the deployment share, check the network and try again"; exit }

#Run the LiteTouch Deployment
Write-Host "`nRunning the LiteTouch deployment to capture the image"
& (Get-Command cscript.exe).Source "$($Drive.Root)\Scripts\LiteTouch.vbs" "/UserID:$($NetworkCred.UserName)" "/UserDomain:$($NetworkCred.Domain)" "/UserPassword:$($NetworkCred.Password)"
