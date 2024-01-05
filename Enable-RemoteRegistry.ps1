# requires -RunAsAdministrator
# requires -Version 3.0
 
<#
.Synopsis
This will enable the remote registry service on local or remote computers.
      
.DESCRIPTION
This will enable the remote registry service on local or remote computers.     
     
.NOTES   
Name: Enable-RemoteRegistry
Author: Kyle Kuminkoski   
#>

    
        [CmdletBinding()]
        param(
            [Parameter(
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
     
            [string[]]  $ComputerName = $env:COMPUTERNAME
        )
     
     
        BEGIN {}
     
        PROCESS {
            Foreach ($Computer in $ComputerName) {
                try {
                    $RemoteRegistry = Get-WmiObject -Class Win32_Service -ComputerName $Computer -Filter 'Name = "RemoteRegistry"' -ErrorAction Stop
                    if ($RemoteRegistry.State -eq 'Running') {
                        Write-Output "$Computer is already Enabled"
                    }
     
                    if ($RemoteRegistry.StartMode -eq 'Disabled') {
                        Set-Service -Name RemoteRegistry -ComputerName $Computer -StartupType Manual -ErrorAction Stop
                        Write-Output "$Computer : Remote Registry has been Enabled"
                    }
     
                    if ($RemoteRegistry.State -eq 'Stopped') {
                        Start-Service -InputObject (Get-Service -Name RemoteRegistry -ComputerName $Computer) -ErrorAction Stop
                        Write-Output "$Computer : Remote Registry has been Started"
                    }
     
                } catch {
                    Write-Output $Computer + " Error: " + $_.Exception.Message
                         
                }
            }
        }
     
        END {}