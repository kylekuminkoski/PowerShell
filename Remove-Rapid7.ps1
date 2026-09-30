[CmdletBinding()]
param(
    [Parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]

    [string]  $ComputerName = $env:COMPUTERNAME
)

Function Stop-Rapid7Processes {

   $cred = Get-Credential

      try{
    $Processes = Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock {
        Get-Process |
        Where-Object {$_.ProcessName -eq "ir_agent" -or $_.ProcessName -eq "rapid7_agentbroker"} |
        Stop-Process -Force -PassThru -ErrorAction Stop |
        Select-Object -Property ProcessName, Id
    } -ErrorAction Stop
      }
      catch {
          Write-Host "Processes could not be stopped." -ForegroundColor Red
          Exit
      }

      Write-Host "Successfully stopped all processes" -ForegroundColor Green

  $Processes
}

Stop-Rapid7Processes