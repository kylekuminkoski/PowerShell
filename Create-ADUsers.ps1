#Enter a path to your import CSV file
$ADUsers = Import-csv C:\Scripts\PowerShell\Users\WillisNewUsers.csv

foreach ($User in $ADUsers)
{

       $Username    = $User.username
       $Password    = $User.password
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
           -ChangePasswordAtLogon $false `
           -Path $OU `
           -AccountPassword (convertto-securestring $Password -AsPlainText -Force)
       }
}