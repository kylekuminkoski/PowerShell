<#
.SYNOPSIS
    NinjaRMM wrapper script for deploying CMMC 2.0 Assessment across devices

.DESCRIPTION
    This script is designed to be deployed via NinjaRMM as a Scripted Action.
    It downloads the assessment script, runs it with JSON export, and uploads
    results to a central location (Rewst webhook, Azure Blob, or network share).

.PARAMETER WebhookURL
    Rewst webhook URL for receiving JSON assessment data

.PARAMETER UseNetworkShare
    Use a network share instead of webhook (for environments without direct internet access)

.PARAMETER NetworkSharePath
    UNC path to network share (e.g., \\server\share\CMMC-Reports)

.PARAMETER UseAzureBlob
    Use Azure Blob Storage for results (requires SAS token)

.PARAMETER AzureBlobURL
    Azure Blob Storage URL with SAS token

.PARAMETER ScriptSource
    Source location for the assessment script (URL or UNC path)
    Default: Local file path (assumes script is pre-deployed)

.EXAMPLE
    # Deploy via Rewst webhook
    .\Deploy-CMMC2Assessment.ps1 -WebhookURL "https://engine.rewst.io/webhooks/custom/your-webhook-id"

.EXAMPLE
    # Deploy via network share
    .\Deploy-CMMC2Assessment.ps1 -UseNetworkShare -NetworkSharePath "\\fileserver\compliance\CMMC-Reports"

.EXAMPLE
    # Deploy via Azure Blob
    .\Deploy-CMMC2Assessment.ps1 -UseAzureBlob -AzureBlobURL "https://storageaccount.blob.core.windows.net/cmmc?sp=racw&st=..."

.NOTES
    Author: Kyle Kuminkoski
    Version: 1.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$WebhookURL,

    [Parameter(Mandatory = $false)]
    [switch]$UseNetworkShare,

    [Parameter(Mandatory = $false)]
    [string]$NetworkSharePath,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzureBlob,

    [Parameter(Mandatory = $false)]
    [string]$AzureBlobURL,

    [Parameter(Mandatory = $false)]
    [string]$ScriptSource = "$PSScriptRoot\Invoke-CMMC2Assessment.ps1"
)

# Configuration
$script:ErrorActionPreference = 'Stop'
$TempPath = "$env:TEMP\CMMC2Assessment"
$LogFile = "$TempPath\deployment.log"
$AssessmentScript = "$TempPath\Invoke-CMMC2Assessment.ps1"
$JSONOutputFile = "$TempPath\CMMC2-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage

    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARN"  { Write-Warning $Message }
        default { Write-Host $Message }
    }
}

# Create temp directory
try {
    if (-not (Test-Path $TempPath)) {
        New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
    }
    Write-Log "Temporary directory created: $TempPath"
} catch {
    Write-Error "Failed to create temporary directory: $_"
    exit 1
}

# Download or copy assessment script
try {
    Write-Log "Retrieving assessment script from: $ScriptSource"

    if ($ScriptSource -like "http*") {
        # Download from URL
        Invoke-WebRequest -Uri $ScriptSource -OutFile $AssessmentScript -UseBasicParsing
        Write-Log "Assessment script downloaded successfully"
    } elseif ($ScriptSource -like "\\*") {
        # Copy from network share
        Copy-Item -Path $ScriptSource -Destination $AssessmentScript -Force
        Write-Log "Assessment script copied from network share"
    } elseif (Test-Path $ScriptSource) {
        # Copy from local path
        Copy-Item -Path $ScriptSource -Destination $AssessmentScript -Force
        Write-Log "Assessment script copied from local path"
    } else {
        throw "Script source not found: $ScriptSource"
    }
} catch {
    Write-Log "Failed to retrieve assessment script: $_" -Level "ERROR"
    exit 1
}

# Execute assessment
try {
    Write-Log "Starting CMMC 2.0 Assessment..."

    & $AssessmentScript -ExportJSON -JSONOutputPath $JSONOutputFile -SkipHTMLReport

    if (Test-Path $JSONOutputFile) {
        Write-Log "Assessment completed successfully. JSON output: $JSONOutputFile"
    } else {
        throw "Assessment script did not generate JSON output"
    }
} catch {
    Write-Log "Assessment execution failed: $_" -Level "ERROR"
    exit 1
}

# Upload results
try {
    Write-Log "Uploading assessment results..."

    if ($WebhookURL) {
        # Upload to Rewst webhook
        Write-Log "Uploading to Rewst webhook..."
        $JSONContent = Get-Content -Path $JSONOutputFile -Raw
        $Headers = @{
            "Content-Type" = "application/json"
        }

        $Response = Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $JSONContent -Headers $Headers
        Write-Log "Successfully uploaded to Rewst webhook. Response: $($Response | ConvertTo-Json -Compress)"

    } elseif ($UseNetworkShare -and $NetworkSharePath) {
        # Copy to network share
        Write-Log "Copying to network share: $NetworkSharePath"

        if (-not (Test-Path $NetworkSharePath)) {
            New-Item -Path $NetworkSharePath -ItemType Directory -Force | Out-Null
        }

        $DestinationFile = Join-Path -Path $NetworkSharePath -ChildPath (Split-Path -Leaf $JSONOutputFile)
        Copy-Item -Path $JSONOutputFile -Destination $DestinationFile -Force
        Write-Log "Successfully copied to network share: $DestinationFile"

    } elseif ($UseAzureBlob -and $AzureBlobURL) {
        # Upload to Azure Blob Storage
        Write-Log "Uploading to Azure Blob Storage..."

        $FileName = Split-Path -Leaf $JSONOutputFile
        $BlobURL = "$AzureBlobURL/$FileName"

        $Headers = @{
            "x-ms-blob-type" = "BlockBlob"
            "Content-Type" = "application/json"
        }

        $FileContent = Get-Content -Path $JSONOutputFile -Raw
        Invoke-RestMethod -Uri $BlobURL -Method Put -Headers $Headers -Body $FileContent
        Write-Log "Successfully uploaded to Azure Blob: $BlobURL"

    } else {
        Write-Log "No upload destination specified. JSON file saved locally: $JSONOutputFile" -Level "WARN"
    }

} catch {
    Write-Log "Failed to upload results: $_" -Level "ERROR"
    Write-Log "Results remain in local file: $JSONOutputFile" -Level "WARN"
    exit 1
}

# Cleanup (optional - comment out if you want to retain logs)
try {
    Write-Log "Cleaning up temporary files..."
    # Keep the log file but remove assessment script and JSON
    Remove-Item -Path $AssessmentScript -Force -ErrorAction SilentlyContinue
    # Uncomment next line to also remove JSON after successful upload
    # Remove-Item -Path $JSONOutputFile -Force -ErrorAction SilentlyContinue
    Write-Log "Cleanup completed"
} catch {
    Write-Log "Cleanup failed: $_" -Level "WARN"
}

Write-Log "CMMC 2.0 Assessment deployment completed successfully"
exit 0
