$IPList = Import-Csv "$PSScriptRoot\WindowsXP_IPs.csv" | Select-Object -ExpandProperty 'IP Address'
$outputList = [ordered]@{}

$IPList.Count

foreach ($ip in $IPList) {
    Write-Host "Pinging" $ip
    $ComputerObject = [PSCustomObject]@{
        Name = ""
        IpAddress = $ip
        Caption = ""
        Architecture = ""
        Version = ""
        LastLogonDate = ""
        State = ""
        }
    if((Test-Connection $ip -BufferSize 16 -Count 1 -ea 0 -quiet)) {
        try {
                Write-Host "Reply Recieved from $ip. Trying Registries..." -ForegroundColor "Green"
                $ComputerInfo = Get-WmiObject -Computer $ip -Class Win32_OperatingSystem -ErrorAction Stop | Select-Object -Property *
        
                $ComputerObject.Name = $ComputerInfo.PSComputerName
                $ComputerObject.IpAddress = $ip
                $ComputerObject.Caption = $ComputerInfo.Caption
                $ComputerObject.Architecture = $ComputerInfo.OSArchitecture
                $ComputerObject.Version = $ComputerInfo.Version
                $ComputerObject.State = ""   
            } 
        catch
            {
                if($_.Exception.ErrorCode -eq 0x800706BA) {
                    Write-Host "Remote Registry Service Not Started." -ForegroundColor "Red"
                    $ComputerObject.State = "Remote Registry Service Not Started"
                } 
                elseif ($_.Exception.ErrorCode -eq 0x80070005) {
                     Write-Host "Remote Registry Access Denied." -ForegroundColor "Red"
                     $ComputerObject.State = "Registry Access Denied" 
                } else {
                    Write-Host "Unknown Registry Com Error Occured." -ForegroundColor "Red"
                    $ComputerObject.State = "Error Occured"
                }
                $ComputerObject.Name = "N/A"
                $ComputerObject.IpAddress = $ip
                $ComputerObject.Caption = "N/A"
                $ComputerObject.Architecture = "N/A"
                $ComputerObject.Version = "N/A"

                Write-Host "Trying DNS Lookup..." -ForegroundColor "Yellow"
                try {
                    $DnsName = Resolve-DnsName -Type PTR -Name $ip -ErrorAction Stop | Select-Object -ExpandProperty NameHost
                    $HostName = $DnsName.Substring(0, $DnsName.IndexOf('.'))
                    $ComputerObject.Name = $HostName
           
                } catch {
                    Write-Host "Host may not exist. Couldn't resolve hostname for $ip" -ForegroundColor "Red"
                    $ComputerObject.State = "No DNS records found"
                }

                if ($ComputerObject.Name -ne "N/A"){
                    Write-Host "Trying AD Lookup..." -ForegroundColor "Yellow"
                    try {
                        $LastLogonDate = Get-ADComputer $HostName -Properties LastLogonDate -ErrorAction Stop | Select-Object -ExpandProperty LastLogonDate
                        $ComputerObject.LastLogonDate = $LastLogonDate
                    } catch{
                        $ComputerObject.State = "Non-Domain Device"
                    }
                }
                
            }
        
    } else {
        $ComputerObject.Name = "N/A"
        $ComputerObject.IpAddress = $ip
        $ComputerObject.Caption = "N/A"
        $ComputerObject.Architecture = "N/A"
        $ComputerObject.Version = "N/A"
        $ComputerObject.State = "Unreachable"

        Write-Host "No reply from $ip. Trying DNS Lookup..." -ForegroundColor "Yellow"
        try {
            $DnsName = Resolve-DnsName -Type PTR -Name $ip -ErrorAction Stop | Select-Object -ExpandProperty NameHost
            $HostName = $DnsName.Substring(0, $DnsName.IndexOf('.'))
            $LastLogonDate = Get-ADComputer $HostName -Properties LastLogonDate -ErrorAction Stop | Select-Object -ExpandProperty LastLogonDate
            $ComputerObject.Name = $HostName
            $ComputerObject.LastLogonDate = $LastLogonDate
    
        } catch {
            Write-Host "Host may not exist. Couldn't resolve hostname for $ip" -ForegroundColor "Red"
            $ComputerObject.State = "No DNS records found"
        }

    }

    $outputList.Add($ip, $ComputerObject)
}

$currentDate = Get-Date -Format "MM_dd_yyyy"
$outputList.values | Export-Csv -Path "$PSScriptRoot\$($Env:USERNAME)\OS_Version_Report_$($currentDate).csv"