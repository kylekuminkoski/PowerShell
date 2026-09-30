#Enter a path to your import CSV file
$ADUsers = Import-csv C:\Scripts\PowerShell\Users\WillisNewUsers.csv

# Generates a strong random password at runtime so plaintext passwords are never
# stored in the import CSV or read from disk. Returns a SecureString.
function New-RandomSecurePassword
{
    param(
        [int]$Length = 20
    )

    # Character sets chosen to satisfy AD complexity requirements.
    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $lower   = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $digits  = '23456789'.ToCharArray()
    $special = '!@#$%^&*()-_=+[]{}'.ToCharArray()
    $all     = $upper + $lower + $digits + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try
    {
        $bytes = New-Object 'System.Byte[]' 1
        $pick = {
            param($set)
            do {
                $rng.GetBytes($bytes)
            } while ($bytes[0] -ge ([math]::Floor(256 / $set.Length) * $set.Length))
            $set[$bytes[0] % $set.Length]
        }

        # Guarantee at least one character from each required class.
        $chars = New-Object System.Collections.Generic.List[char]
        $chars.Add((& $pick $upper))
        $chars.Add((& $pick $lower))
        $chars.Add((& $pick $digits))
        $chars.Add((& $pick $special))
        for ($i = $chars.Count; $i -lt $Length; $i++)
        {
            $chars.Add((& $pick $all))
        }

        # Fisher-Yates shuffle so the guaranteed characters are not always first.
        for ($i = $chars.Count - 1; $i -gt 0; $i--)
        {
            do {
                $rng.GetBytes($bytes)
            } while ($bytes[0] -ge ([math]::Floor(256 / ($i + 1)) * ($i + 1)))
            $j = $bytes[0] % ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }

        $plain = -join $chars
        $secure = ConvertTo-SecureString $plain -AsPlainText -Force
        return $secure
    }
    finally
    {
        if ($rng) { $rng.Dispose() }
    }
}

# Collects generated passwords for out-of-band delivery (returned, never written to disk).
$GeneratedCredentials = @()

foreach ($User in $ADUsers)
{

       $Username    = $User.username
       $Firstname   = $User.firstname
       $Lastname    = $User.lastname
       $DisplayName = $User.displayname
       $UPN         = $User.upn
       $Department  = $User.department
       $OU          = $User.ou
       $Country     = 'US'
       $Company     = $User.Company
       $City        = $User.City
       $Street      = $User.StreetAddress
       $Title       = $User.Title
       $Office      = $User.Office

       #Check if the user account already exists in AD
       if (Get-ADUser -F {SamAccountName -eq $Username})
       {
               #If user does exist, output a warning message
               Write-Warning "A user account $Username already exists in Active Directory."
       }
       else
       {
              #If a user does not exist then create a new user account
          
        #Generate a strong random password at runtime instead of reading it from the CSV.
        $SecurePassword = New-RandomSecurePassword

        #Account will be created in the OU listed in the $OU variable in the CSV file;
        New-ADUser -Name "$Firstname $Lastname" `
           -SamAccountName $Username `
           -UserPrincipalName $UPN `
           -GivenName $Firstname `
           -Surname $Lastname `
           -DisplayName $DisplayName `
           -Department $Department `
           -Country $Country `
           -City $City `
           -Company $Company `
           -EmailAddres $UPN `
           -StreetAddress $Street `
           -Title $Title `
           -Office $Office `
           -Enabled $True `
           -ChangePasswordAtLogon $true `
           -Path $OU `
           -AccountPassword $SecurePassword

        #Return the generated password in an object for secure out-of-band delivery.
        #The plaintext is exposed only here in memory and is never written to disk.
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        try
        {
            $plainForDelivery = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            $GeneratedCredentials += [pscustomobject]@{
                Username          = $Username
                UserPrincipalName = $UPN
                InitialPassword   = $plainForDelivery
            }
        }
        finally
        {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
       }
}

# Emit the generated credentials so the operator can deliver them out-of-band
# (e.g. to a secure channel). They are intentionally NOT written to a file.
$GeneratedCredentials