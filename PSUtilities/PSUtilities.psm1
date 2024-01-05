Function Copy-Repo {
    Param(
        [String] $RepoPath,
        [String] $LocalPath,

        [Switch]$Remove
    )

    $DefaultPath = "C:\TempRepo"

    if ($Remove) {
        if (-not ($LocalPath)){
            Write-Host "Error: No local path was specified. Checking for default path...`n" -ForegroundColor Yellow

            if ( -not (Test-Path $DefaultPath -ErrorAction SilentlyContinue )) {
                Write-Host "Could not find default path. Please provide the path to the correct location to remove. Exiting...`n" -ForegroundColor Red
                exit
            }
            $LocalPath = $DefaultPath
        }

        Write-Host "Deleting Directory at $LocalPath`n" -ForegroundColor Yellow
        try{
        Remove-Item -Path $LocalPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Host "The path cannot be removed because it does not exist.`n" -ForegroundColor Red
            exit
        }
        if (-not (Test-Path -Path $LocalPath -ErrorAction SilentlyContinue)) {
            Write-Host "$LocalPath has been removed.`n" -ForegroundColor Green
        } else {
            Write-Host "$LocalPath could not be removed. Please troubleshoot manually.`n" -ForegroundColor Red
            exit
        }
        return

    }

    if ( -not ($RepoPath)) {
        Write-Host "Please specify a Repository location to copy to the local machine`n" -ForegroundColor Red
        exit
    }

    if ( -not ($LocalPath)) {
        Write-Host "No local path was specified. Using default location C:\Repo`n" -ForegroundColor Yellow
        $LocalPath = $DefaultPath
    }

    try {
        if (Test-Path $LocalPath){
            $answer = Show-OverrideMenu -title "Directory Already Exists on Machine." -message "$LocalPath already exists on this machine. Would you like to overwrite its contents?"
            
            if ($answer){
                Write-Host "Overwriting existing directory" -ForegroundColor Yellow
                Copy-Repo -LocalPath $LocalPath -Remove
            } else {
                Write-Host "Skipping Copy" -ForegroundColor Yellow
                return
            }
        }
        $Object = Copy-Item -Path $RepoPath -Destination $LocalPath -Recurse -ErrorAction Stop
    } catch {
        Write-Host "An error occured while copying the Repo to the local machine.`n" -ForegroundColor Red
        exit
    }

    Write-Host "$RepoPath has been copied to $LocalPath`n" -ForegroundColor Green
    return $Object
}

Function Show-OverrideMenu {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $title,
        [Parameter(Mandatory = $true)]
        [String] $message
    )
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes","Continue"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList "&No","Skip"
    $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no)

    $OverrideDetection = $host.UI.PromptForChoice($title, $message, $choices, 1)

    if ($OverrideDetection -eq 0) {
        $true
    }
    else { $false }
}

Function Test-AdminRights {
    #Get the current users Windows Principal
    $Principal = New-Object System.Security.Principal.WindowsPrincipal -Args ([Security.Principal.WindowsIdentity]::GetCurrent())
    #Test if the user is currently a local administrator
    $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}