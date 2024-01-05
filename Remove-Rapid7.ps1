[CmdletBinding()]
param(
    [Parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]

    [string]  $ComputerName = $env:COMPUTERNAME
)

Function Stop-Rapid7Processes {

   Enter-PSSession -ComputerName $ComputerName -Credential (Get-Credential)

      try{
    Get-Process -ComputerName $ComputerName | 
    Select-Object -Property ProcessName, Id | 
    Where-Object {$_.ProcessName -eq "ir_agent" -or $_.ProcessName -eq "rapid7_agentbroker"} | 
    Stop-Process  -Force -PassThru -ErrorAction Stop
      }
      catch {
          Exit-PSSession
          Write-Host "Processes could not be stopped." -ForegroundColor Red
          Exit
      }
 
      Write-Host "Successfully stopped all processes" -ForegroundColor Green

  $Processes
}

Stop-Rapid7Processes