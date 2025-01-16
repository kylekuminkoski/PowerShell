Param(
    [Parameter(Position=0)]
        [String]$ComputerName = $Env:COMPUTERNAME,

        [String]$File

        
)

if ($File){
    $Computers = Import-Csv -Path $File | ForEach-Object { Get-ADComputer $_.Name -Properties Name, LastLogonDate, Description, OperatingSystem }
} else {
    $Computers = Get-ADComputer $ComputerName -Properties DistinguishedName, Name, LastLogonDate, Description, OperatingSystem

}

$resultsTable = [ordered]@{}

Write-Host "Scanning hostnames, please wait..." -ForegroundColor "Yellow"
foreach ($Computer in $Computers) {

    $pingTestJob = Start-Job -ArgumentList $Computer.Name -ScriptBlock {

        if (Test-Connection $args -Count 1 -BufferSize 16 -Quiet) {
             Test-Connection $args -Count 1 -BufferSize 16 | Select-Object -ExpandProperty IPV4Address | Select-Object -ExpandProperty IPAddressToString
        } else {
            $false
        }
    }

    # Calculate the total amount of time in days since a the computer has logged into AD.
    $lastLogon = $Computer | Select-Object -ExpandProperty LastLogonDate | Get-Date
    $presentDate = Get-Date
    $TotalDaysSinceLogon = ($presentDate - $lastLogon) | Select-Object -ExpandProperty Days

    # Checks for stale devices.
    if($TotalDaysSinceLogon -gt 120) {

        Write-Host "$($Computer.Name) is stale; Last Logon: $TotalDaysSinceLogon days ago" -ForegroundColor "Red"

    } else {

        Write-Host "$($Computer.Name) is active. Last Logon: $TotalDaysSinceLogon days ago" -ForegroundColor "Green"
    }
    
    $ip = "Unreachable"
    $pingResult = Receive-Job $pingTestJob -Wait
    if ($pingResult -ne $false) {
        $ip = $pingResult
    }

    $ComputerObject = [PSCustomObject]@{
        Name = $Computer.Name
        "Operating System" = $Computer.OperatingSystem
        Description = $Computer.Description
        "Last Logon Date" = $lastLogon | Get-Date -Format "MM/dd/yyyy"
        "Days Away" = $TotalDaysSinceLogon
        "IP Address" = $ip
    }

    if(!$resultsTable.Contains($ComputerObject.Name)) {
        $resultsTable.Add($ComputerObject.Name, $ComputerObject)
    }


}
$date = Get-Date -Format "MM_dd_yyyy"

$resultsTable.values | Export-Csv -Path "$PSScriptRoot\StaleDevicesReport_$date.csv"