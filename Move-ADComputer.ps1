$ComputerName = "HVS000T50"

$TargetBaseOU = "InformationSystems"
$OU = Get-ADOrganizationalUnit -Filter {Name -like $TargetBaseOU} -SearchBase "OU=HVHS.Computers,DC=hvhs,DC=org" -SearchScope 1

$Computer = Get-ADComputer $ComputerName

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

Move-ADObject -Identity $distName -TargetPath $FullOU