[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = 'Stop'

$ComputerName = "HVS000T50"

$TargetBaseOU = "InformationSystems"

try {
    $OU = Get-ADOrganizationalUnit -Filter {Name -like $TargetBaseOU} -SearchBase "OU=domain.Computers,DC=domain,DC=org" -SearchScope 1

    if ($null -eq $OU) {
        throw "Target OU '$TargetBaseOU' was not found under the specified SearchBase."
    }

    $Computer = Get-ADComputer $ComputerName

    if ($null -eq $Computer) {
        throw "Computer '$ComputerName' was not found in Active Directory."
    }

    $distName = $Computer | Select-Object -ExpandProperty DistinguishedName

    $distName

    $Base = $OU.DistinguishedName
    $WSUS = "WSUS-Monday"

    $randomNumber = 1,2,3,4,5 | Get-Random

    switch ($randomNumber) {
        1 { $WSUS = "WSUS-Monday" }
        2 { $WSUS = "WSUS-Tuesday" }
        3 { $WSUS = "WSUS-Wednesday" }
        4 { $WSUS = "WSUS-Thursday" }
        5 { $WSUS = "WSUS-Friday" }
        Default { $WSUS = "WSUS-Monday" }
    }

    $FullOU = "OU=" + $WSUS + "," + $Base

    $FullOU

    if ($PSCmdlet.ShouldProcess($distName, "Move-ADObject to '$FullOU'")) {
        Move-ADObject -Identity $distName -TargetPath $FullOU
    }
}
catch {
    Write-Error "Failed to move computer '$ComputerName': $($_.Exception.Message)"
    throw
}