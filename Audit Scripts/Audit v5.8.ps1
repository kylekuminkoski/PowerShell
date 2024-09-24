#V1.0 - Try 2, attempt 1
#v1.1 - Ignore employees with terminated status and increment log file in line with output - worked
#v1.2 - Output to Excel for easier parsing - worked
#v1.3 - Add mismatched items column - worked
#v1.4 - Freeze top row in output - worked
#v1.5 - Ignore capitalization when matching
#v1.6 - Null checks for manager 
#v1.7 - Add debugging for error about manager value and check for null manager in AD
#v1.8 - Remove debugging and add script name to log file
#v1.9 - Handle middle names in manager comparisons
#v2.0 - Ignore - does not exist. 
#v2.1 - Add filtering to the headers in the output
#v2.2 - Log to a variable instead of a file and output the variable at the end, changed terminated employee message to start with zz_, alphabetize log variable before writing to host
#v2.3 - Manually write script name to log file before sorted log messages, remove output to host
#v2.4 - Added nickname handling for manager comparison
#v2.5 - Consider no manager set in AD but manager listed in Excel as a mismatch and handle blank manager values
#v2.6 - Match users by name, handle agency nurses, output AD and Excel employee codes
#v2.7 - Move employee code columns to the 2nd and 3rd columns, ensuring employee codes are checked for match
#v2.8 - Update log to output user names instead of employee codes
#v2.9 - Handle duplicate employee names by checking employee code, log error for manual verification if still unresolved
#v3.0 - Improved duplicate handling, log unresolved duplicates for manual verification
#v3.1 - Enhance matching logic for agency nurses with middle names in Excel to ensure they are correctly matched with AD entries
#v3.2 - Handle matching for names with different capitalization and special characters
#v3.3 - Add fallback matching method for users if name does not return a result, change headers and column widths
#v3.4 - Fix fallback logic to correctly handle agency nurses by using modified first and last names
#v3.5 - Ensure fallback matched users have all necessary properties populated, update excel path
#v3.6 - Add new output files for terminated and not found employees, adjust logging accordingly, remove fallback matching and found x AD users from logfile
#v3.7 - Move status and mismatch items columns before code - ad and code - excel columns
#v3.8 - Add matching for names in addition to position, department, and manager, move status and mismatch items columns to end, set column width for "ou - ad" and "ou - excel" to 2, adjust column widths for specific columns
#v3.9 - Correct name matching and output modified agency nurse name for name - Excel -fallback users missing from report
#v4.0 - Add employee code matching
#v4.1 - Only output "No AD user found for" message when both standard and fallback matching fail
#v4.2 - Directly normalize strings to remove special characters and ensure lowercase matching
#v4.3 - Add special exemption for "Lawrence Caplin"
#v4.4 - Add special exemption for "Corinna Hearn"
#v4.5 - Keep running inventory of titles and departments
#v5.0 - Add remediation steps for mismatched items with user prompts and logging
#v5.1 - fix manager logic on remediation 
#v5.2 - final fix manager logic using prior defined functions and update nickname function to explicitly apaply to bob maxwell
#v5.3 - Disable confirmation prompt (comment lines: 540, 541, 548)
#v5.4 - Added error logging during remediation steps to a new log file "error_$i.txt" and fixed replace-nickname (must match full name)
#v5.5 - Added normalization for AD names when manager name fails to be found in remediation
#v5.6 - Add exemptions for both Ofoghs
#v5.7 - change from hardcoded file path to "select a file" pop up
#v5.8 - Select neweset file automatically

# Load necessary modules
Import-Module ActiveDirectory
Import-Module ImportExcel

# Configuration
$scriptName = "Audit v5.8.ps1"
$sheetName = "emp data"
$outputFolder = "C:\Users\Administrator.MEDIKOPC\Desktop\audit"
$dataFile = "$outputFolder\TitlesDepartments.json"
$logFile = "$outputFolder\TitlesDepartmentsChanges.log"

$folderPath = "C:\Users\Administrator.MEDIKOPC\Desktop\Weekly Reports"

# Get all files that match the naming pattern
$files = Get-ChildItem -Path $folderPath -Filter "HR EMPLOYEE DATA - Weekly Update - *.xlsx"

# Extract the date from each file name, convert it to a [DateTime] object, and find the newest one
$newestFile = $files | Sort-Object {
    $dateString = $_.BaseName -replace "HR EMPLOYEE DATA - Weekly Update - ", ""
    [datetime]::ParseExact($dateString, "M.d.yy", $null)
} -Descending | Select-Object -First 1

# Output the newest file
$excelPath = $newestFile.FullName
write-host $excelPath

# Helper function to log messages
$logMessages = @()
$debugMessages = @()
$terminatedMessages = @()
$notFoundMessages = @()
$changesMade = @()
$errorMessages = @()

function Get-NextFileNames {
    $i = 1
    while (Test-Path -Path "$outputFolder\output_$i.xlsx") {
        $i++
    }
    return @("$outputFolder\output_$i.xlsx", "$outputFolder\logfile_$i.txt", "$outputFolder\debug_$i.txt", "$outputFolder\terminated_$i.txt", "$outputFolder\not_found_$i.txt", "$outputFolder\changes_$i.txt", "$outputFolder\error_$i.txt")
}

function Log-Message {
    param (
        [string]$message
    )
    $script:logMessages += $message
}

function Log-Error {
    param (
        [string]$message
    )
    $script:logMessages += "ERROR: $message"
}

function Debug-Message {
    param (
        [string]$message
    )
    $script:debugMessages += $message
}

function Terminated-Message {
    param (
        [string]$message
    )
    $script:terminatedMessages += $message
}

function NotFound-Message {
    param (
        [string]$message
    )
    $script:notFoundMessages += $message
}

function Error-Message {
    param (
        [string]$message
    )
    $script:errorMessages += $message
    Write-Host "ERROR: $message" -ForegroundColor Red
}

function Convert-SupervisorName {
    param (
        [string]$name
    )
    if ($name -match '^(.*), (.*)$') {
        return "$($matches[2]) $($matches[1])"
    }
    return $name
}

function Get-FirstLastName {
    param (
        [string]$name
    )
    $names = $name -split ' '
    if ($names.Count -gt 1) {
        return "$($names[0]) $($names[-1])"
    }
    return $name
}

function Replace-Nickname {
    param (
        [string]$name
    )
    $nicknames = @{
        "Bob Maxwell" = "Robert Maxwell"
        "Angie Ward" = "Frances Ward"
        "Nettie Turner" = "Marie Turner"
        "Jamie Wheatley" = "Nicole Wheatley"
        "Lee Dillard-Johnson" = "Lee Ann Dillard-Johnson"
        "Jean Todd" = "Jeannie Todd"
        "Kiersten Hanover" = "Kiersten Davis"
        # Add more nickname pairs here if needed
    }
    if ($nicknames.ContainsKey($name)) {
        return $nicknames[$name]
    }
    return $name
}

function Normalize-Name {
    param (
        [string]$name
    )

    $name = $name -replace "[`'’]", "" 
    return $name
}

function Find-UserInAd {
    param (
        [string]$firstName,
        [string]$lastName
    )

    # Fetch all users from AD
    $allUsers2 = Get-ADUser -Filter * -Properties GivenName, Surname

    # Normalize names and find the matching user
    foreach ($user in $allUsers2) {
        $normFirstName = Normalize-Name -name $user.GivenName
        $normLastName = Normalize-Name -name $user.Surname

        if ($normFirstName -eq $firstName -and $normLastName -eq $lastName) {
            return $user
        }
    }

    return $null
}

function Get-ManagerName {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$adUser
    )
    $manager = "N/A"
    if ($null -ne $adUser.Manager) {
        $managerDN = if ($adUser.Manager -is [Array]) { $adUser.Manager[0] } else { $adUser.Manager }
        try {
            $managerObj = Get-ADUser -Identity $managerDN -Properties GivenName, Surname
            $manager = "$($managerObj.GivenName) $($managerObj.Surname)"

        } catch {
            Log-Error "Failed to fetch manager details for: $($adUser.GivenName) $($adUser.Surname)"
            $manager = "N/A"
        }
    }
    return $manager
}

function Get-MismatchedItems {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$adUser,
        [PSCustomObject]$employee,
        [string]$manager,
        [string]$supervisorName
    )
    $mismatchedItems = @()
    if ($employee.Legal_Lastname -like "AGENCY*") {
        $names = $employee.Legal_Firstname -split ' '
        $firstName = $names[0]
        $lastName = $names[-1]
    } else {
        $firstName = $employee.Legal_Firstname
        $lastName = $employee.Legal_Lastname
    }

    # Special exemptions
    if ($employee.Legal_Firstname -eq "LAWRENCE B CAPLIN" -and $employee.Legal_Lastname -eq "PC") {
        $firstName = "LAWRENCE"
        $lastName = "CAPLIN"
    } elseif ($employee.Legal_Firstname -eq "Hearn" -and $employee.Legal_Lastname -eq "CONSULTING LLC") {
        $firstName = "CORINNA"
        $lastName = "HEARN"
    }

    # Normalize names for comparison
    $normalizedADName = ($adUser.GivenName + $adUser.Surname) -replace '[^a-zA-Z0-9]', '' -replace ' ', '' | ForEach-Object { $_.ToLower() }
    $normalizedExcelName = ($firstName + $lastName) -replace '[^a-zA-Z0-9]', '' -replace ' ', '' | ForEach-Object { $_.ToLower() }

    Debug-Message "Comparing normalized names: AD Name - $normalizedADName, Excel Name - $normalizedExcelName"

    if ($normalizedADName -ne $normalizedExcelName) {
        $mismatchedItems += "Name"
    }

    if ($adUser.Title -and $employee.Position -and $adUser.Title.ToLower() -ne $employee.Position.ToLower()) {
        $mismatchedItems += "Title"
    }
    if ($adUser.Department -and $employee.Department_Desc -and $adUser.Department.ToLower() -ne $employee.Department_Desc.ToLower()) {
        $mismatchedItems += "Department"
    }
    if (($manager -eq "N/A" -and $supervisorName -ne $null) -or ($manager -ne "N/A" -and $supervisorName -eq $null)) {
        $mismatchedItems += "Manager"
    } elseif ($manager -ne "N/A" -and $supervisorName -ne $null -and (Get-FirstLastName -name $manager).ToLower() -ne $supervisorName.ToLower()) {
        $mismatchedItems += "Manager"
    }
    if ($adUser.Company -ne $employee.Employee_Code) {
        $mismatchedItems += "Employee Code"
    }
    if ($adUser.DistinguishedName -notlike "*$($employee.Department_Desc)*") {
        $mismatchedItems += "OU"
    }
    return $mismatchedItems
}

function Prepare-OutputObject {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$adUser,
        [PSCustomObject]$employee,
        [string]$manager,
        [array]$mismatchedItems
    )
    if ($employee.Legal_Lastname -like "AGENCY*") {
        $names = $employee.Legal_Firstname -split ' '
        $firstName = $names[0]
        $lastName = $names[-1]
    } else {
        $firstName = $employee.Legal_Firstname
        $lastName = $employee.Legal_Lastname
    }

    # Special exemptions
    if ($employee.Legal_Firstname -eq "LAWRENCE B CAPLIN" -and $employee.Legal_Lastname -eq "PC") {
        $firstName = "LAWRENCE"
        $lastName = "CAPLIN"
    } elseif ($employee.Legal_Firstname -eq "Hearn" -and $employee.Legal_Lastname -eq "CONSULTING LLC") {
        $firstName = "CORINNA"
        $lastName = "HEARN"
    }	
    [PSCustomObject]@{
        'Name - AD'         = "$($adUser.GivenName) $($adUser.Surname)"
        'Name - Excel'      = "$($firstName) $($lastName)"
        'Code - AD'         = $adUser.Company
        'Code - Excel'      = $employee.Employee_Code
        'Job Title - AD'    = $adUser.Title
        'Job Title - Excel' = $employee.Position
        'Department - AD'   = $adUser.Department
        'Department - Excel' = $employee.Department_Desc
        'Manager - AD'      = $manager
        'Manager - Excel'   = $employee.Supervisor_Primary
        'OU - AD'           = $adUser.DistinguishedName
        'OU - Excel'        = $employee.Department_Desc
        'Identity'          = $adUser.SamAccountName  # Added identity field for future remediation steps
        Status              = if ($mismatchedItems.Count -eq 0) {
            "Correct"
        } else {
            "Mismatch"
        }
        'Mismatched Items'  = if ($mismatchedItems.Count -eq 0) {
            ""
        } else {
            $mismatchedItems -join ", "
        }
    }
}

function Process-Employee {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$adUser,
        [PSCustomObject]$employee
    )
    # Fetch AD manager name
    $manager = Get-ManagerName -adUser $adUser

    # Convert Supervisor_Primary and extract first and last name
    $supervisorName = Get-FirstLastName -name (Convert-SupervisorName -name $employee.Supervisor_Primary)
    $supervisorName = Replace-Nickname -name $supervisorName
    $manager = Normalize-Name -name (Replace-Nickname -name $manager)

    # Prepare the mismatched items
    $mismatchedItems = Get-MismatchedItems -adUser $adUser -employee $employee -manager $manager -supervisorName $supervisorName

    # Prepare output object
    return Prepare-OutputObject -adUser $adUser -employee $employee -manager $manager -mismatchedItems $mismatchedItems
}

# Get the next available output, log, debug, and error file names
$fileNames = Get-NextFileNames
$outputFile = $fileNames[0]
$logFile = $fileNames[1]
$debugFile = $fileNames[2]
$terminatedFile = $fileNames[3]
$notFoundFile = $fileNames[4]
$changesFile = $fileNames[5]
$errorFile = $fileNames[6]

# Read Excel data
try {
    $employeeData = Import-Excel -Path $excelPath -WorksheetName $sheetName
    Debug-Message "Successfully read Excel file: $excelPath"
} catch {
    Log-Error "Failed to read Excel file: $_"
    $logMessages = $logMessages | Sort-Object
    Set-Content -Path $logFile -Value "Script Name: $scriptName"
    $logMessages | ForEach-Object { Add-Content -Path $logFile -Value $_ }
    exit 1
}

# Load existing titles and departments data
if (Test-Path $dataFile) {
    $storedData = Get-Content -Path $dataFile | ConvertFrom-Json
    $storedTitles = $storedData.Titles
    $storedDepartments = $storedData.Departments
} else {
    $storedTitles = @()
    $storedDepartments = @()
}

# Initialize current titles and departments
$currentTitles = @{}
$currentDepartments = @{}

# Perform the initial search and store the results
try {
    $allUsers = Get-ADUser -Filter * -Property GivenName, Surname, Company, Title, Department, Manager, DistinguishedName, SamAccountName
    Debug-Message "Successfully retrieved AD users"
} catch {
    Log-Error "Failed to retrieve AD users: $_"
    Debug-Message "Failed to retrieve AD users: $_"
    exit 1
}

# Function to find users by company (employee code) and achieve 2/3 match
function Find-UsersByCompany {
    param (
        [PSCustomObject]$employee,
        [string]$firstName,
        [string]$lastName
    )

    $companyCode = $employee.Employee_Code

    $filteredUsers = $allUsers | Where-Object { $_.Company -eq $companyCode }

    foreach ($user in $filteredUsers) {
        $matches = 0
        if ($user.GivenName -eq $firstName) {
            $matches++
        }
        if ($user.Surname -eq $lastName) {
            $matches++
        }
        if ($user.Company -eq $companyCode) {
            $matches++
        }

        Debug-Message "AD User Found in fallback: GivenName=$($user.GivenName), Surname=$($user.Surname), Company=$($user.Company), Matches=$matches"

        if ($matches -ge 2) {
            return $user
        }
    }
    return $null
}

# Initialize results array
$results = @()

# Process each employee
$results += foreach ($employee in $employeeData) {
    try {
        Debug-Message "Processing employee: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
                # Skip specific users
        if (($employee.Legal_Firstname -eq "KAVEH" -and $employee.Legal_Lastname -eq "OFOGH") -or 
            ($employee.Legal_Firstname -eq "NADEREH" -and $employee.Legal_Lastname -eq "OFOGH")) {
            Debug-Message "Skipped user: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            continue
        }
        # Skip if the employee status is "terminated"
        if ($employee.Employee_Status -eq "terminated") {
            Terminated-Message "Skipped terminated employee: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            continue
        }

        # Skip if any critical field is "BLANK"
        if ($employee.Legal_Firstname -eq "BLANK" -or $employee.Legal_Lastname -eq "BLANK") {
            Log-Error "Skipped entry with blank name: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            Debug-Message "Skipped entry with blank name: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            continue
        }

        # Handle "AGENCY-*" entries and extract first and last names, ignoring middle names
        if ($employee.Legal_Lastname -like "AGENCY*") {
            $names = $employee.Legal_Firstname -split ' '
            $firstName = $names[0]
            $lastName = $names[-1]
        } else {
            $firstName = $employee.Legal_Firstname
            $lastName = $employee.Legal_Lastname
        }

        # Special exemptions
        if ($employee.Legal_Firstname -eq "LAWRENCE B CAPLIN" -and $employee.Legal_Lastname -eq "PC") {
            $firstName = "LAWRENCE"
            $lastName = "CAPLIN"
        } elseif ($employee.Legal_Firstname -eq "Hearn" -and $employee.Legal_Lastname -eq "CONSULTING LLC") {
            $firstName = "CORINNA"
            $lastName = "HEARN"
        }

        # Normalize names for comparison
        $normalizedFirstName = ($firstName -replace '[^a-zA-Z0-9]', '' -replace ' ', '').ToLower()
        $normalizedLastName = ($lastName -replace '[^a-zA-Z0-9]', '' -replace ' ', '').ToLower()

        Debug-Message "Normalized Excel names: First Name - $normalizedFirstName, Last Name - $normalizedLastName"

        # Add titles and departments to current lists
        $currentTitles[$employee.Position] = $true
        $currentDepartments[$employee.Department_Desc] = $true

        # Fetch AD users
        $adUsers = @(Get-ADUser -Filter { GivenName -eq $firstName -and Surname -eq $lastName } -Properties GivenName, Surname, Title, Department, Manager, DistinguishedName, Company, SamAccountName)
        $adUserCount = ($adUsers | Measure-Object).Count
        Debug-Message "Found $adUserCount AD user(s) for $($employee.Legal_Firstname) $($employee.Legal_Lastname)"

        $adUser = $null
        if ($adUserCount -eq 0) {
			
            # Fallback matching for employee

            $adUser = Find-UsersByCompany -employee $employee -firstName $firstName -lastName $lastName

            if (-not $adUser) {
                NotFound-Message "No AD user found for: $($employee.Legal_Firstname) $($employee.Legal_Lastname) - Both Standard & Fallback attempted"
                Debug-Message "No AD user found for: $($employee.Legal_Firstname) $($employee.Legal_Lastname) - Both Standard & Fallback attempted"
            } else {
                # Process the fallback matched employee and return the result object
                Process-Employee -adUser $adUser -employee $employee
            }

            continue
        }

        # Output details of found AD users
        foreach ($user in $adUsers) {
            $userNormalizedFirstName = ($user.GivenName -replace '[^a-zA-Z0-9]', '' -replace ' ', '').ToLower()
            $userNormalizedLastName = ($user.Surname -replace '[^a-zA-Z0-9]', '' -replace ' ', '').ToLower()
            Debug-Message "Comparing normalized names: AD First Name - $userNormalizedFirstName, AD Last Name - $userNormalizedLastName, Excel First Name - $normalizedFirstName, Excel Last Name - $normalizedLastName"
            if ($userNormalizedFirstName -eq $normalizedFirstName -and $userNormalizedLastName -eq $normalizedLastName) {
                Debug-Message "Names match after normalization: AD Name - $($user.GivenName) $($user.Surname), Excel Name - $firstName $lastName, Normalized AD Name - $userNormalizedFirstName $userNormalizedLastName, Normalized Excel Name - $normalizedFirstName $normalizedLastName"
            } else {
                Debug-Message "Names do not match after normalization: AD Name - $($user.GivenName) $($user.Surname), Excel Name - $firstName $lastName, Normalized AD Name - $userNormalizedFirstName $userNormalizedLastName, Normalized Excel Name - $normalizedFirstName $normalizedLastName"
            }
        }

        if ($adUserCount -gt 1) {
            foreach ($user in $adUsers) {
                if ($userNormalizedFirstName -eq $normalizedFirstName -and $userNormalizedLastName -eq $normalizedLastName -and $user.Company -eq $employee.Employee_Code) {
                    $adUser = $user
                    break
                }
            }
            if (-not $adUser) {
                Log-Error "Duplicate employee found, manual verification needed: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
                Write-Host "ERROR: Duplicate employee found, manual verification needed: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
                Debug-Message "Duplicate employee found, manual verification needed: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
                continue
            }
        } elseif ($adUserCount -eq 1) {
            $adUser = $adUsers[0]
        } else {
            NotFound-Message "AD user not found for: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            Debug-Message "AD user not found for: $($employee.Legal_Firstname) $($employee.Legal_Lastname)"
            continue
        }

        # Process the employee and return the result object
        Process-Employee -adUser $adUser -employee $employee

    } catch {
        Log-Error "Error processing employee: $($_.Exception.Message)"
        Debug-Message "Error processing employee: $($_.Exception.Message)"
    }
}

# Remediation step
foreach ($result in $results) {
    if ($result.Status -eq "Mismatch") {
        # Split the 'Mismatched Items' to check if 'Name' is the only mismatch or part of multiple mismatches
        $mismatches = $result.'Mismatched Items' -split ',\s*'
        if (-not ($mismatches.Count -eq 1 -and $mismatches -contains "Name"))  {
            Write-Host "Mismatch detected for AD user: $($result.'Name - AD')"
            Write-Host "Current values:"
            Write-Host "------------------------------------"
            Write-Host "First Name: $($result.'Name - AD'.Split(' ')[0])"
            Write-Host "Last Name: $($result.'Name - AD'.Split(' ')[1])"
            Write-Host "Job Title: $($result.'Job Title - AD')"
            Write-Host "Department: $($result.'Department - AD')"
            Write-Host "Manager: $($result.'Manager - AD')"
            Write-Host "Code: $($result.'Code - AD')"
            Write-Host "------------------------------------"
            Write-Host "Field(s) needing change: " -NoNewline
            Write-Host $($result.'Mismatched Items') -ForegroundColor DarkRed -BackgroundColor Yellow
            Write-Host "Excel value(s) to be used:"
        
            $command = "Set-ADUser -Identity '$($result.Identity)' "
            $ouCommand = ""

            <#
            if ($result.'Mismatched Items' -match "Name") {
                Write-Host "First Name: $($result.'Name - Excel'.Split(' ')[0])"
                Write-Host "Last Name: $($result.'Name - Excel'.Split(' ')[1])"
                $command += "-GivenName '$($result.'Name - Excel'.Split(' ')[0])' -Surname '$($result.'Name - Excel'.Split(' ')[1])' "
            }
            #>
            if ($result.'Mismatched Items' -match "Title") {
                Write-Host "Job Title: $($result.'Job Title - Excel')"
                $command += "-Title '$($result.'Job Title - Excel')' "
            }
            if ($result.'Mismatched Items' -match "Department") {
                Write-Host "Department: $($result.'Department - Excel')"
                $command += "-Department '$($result.'Department - Excel')' "
            }
            if ($result.'Mismatched Items' -match "Manager") {
                $managerName = Get-FirstLastName -name (Convert-SupervisorName -name $result.'Manager - Excel')
                $managerName = Replace-Nickname -name $managerName
		        $managerFirstName = $managerName.Split(' ')[0].Trim()
                $managerLastName = $managerName.Split(' ')[1].Trim()
                $adManager = Get-ADUser -Filter "GivenName -eq '$managerFirstName' -and Surname -eq '$managerLastName'" -Properties DistinguishedName, ObjectGUID
		        if (-not $adManager) {
			        Write-Host "Standard check failed, attempting to find user with normalized names."
			        $adManager = Find-UserInAd -firstName $managerFirstName -lastName $managerLastName
		        }
		        if ($adManager) {
                    $managerDN = $adManager.ObjectGUID
                    Write-Host "Manager: $managerName"
                    $command += "-Manager '$managerDN' "
                } else {
			        Write-Host "No AD manager found for: $managerName"
		        }
	        }
            if ($result.'Mismatched Items' -match "Employee Code") {
                Write-Host "Code: $($result.'Code - Excel')"
                $command += "-Company '$($result.'Code - Excel')' "
            }
            if ($result.'Mismatched Items' -match "OU") {
                Write-Host "OU: $($result.'OU - Excel')"
                $ouDN = (Get-ADOrganizationalUnit -Filter "Name -eq '$($result.'OU - Excel')'").DistinguishedName
		        $result.Identity
                $guid = Get-Aduser -identity $result.Identity -Properties ObjectGUID
                $objectGuid = $guid.ObjectGUID
                $ouCommand = "Move-ADObject -Identity $objectGuid -TargetPath '$ouDN'"
            
            }

            if ($command -ne "Set-ADUser -Identity '$($result.Identity)' ") {
                Write-Host "Command to be executed: $command"
            }
            if ($ouCommand) {
                Write-Host "Command to move user to new OU: $ouCommand"
            }
            $confirmation = Read-Host "Do you want to apply these changes? (Y/N)"
            if ($confirmation -eq "Y") {
                try {
                    Invoke-Expression $command
                    $changesMade += "Changes applied for $($result.'Name - AD'): $command"
                    if ($ouCommand) {
                        Invoke-Expression $ouCommand
                        $changesMade += "User moved to new OU for $($result.'Name - AD'): $ouCommand"
                    }
                } catch {
                    $errorMessage = "`nError applying changes for $($result.'Name - AD'): $_"
                    $errorMessage += "`n- Code: $($result.'Code - Excel')"
                    $errorMessage += "`nRelevant Excel data:"
                    if ($result.'Mismatched Items' -match "Name") {
                        $errorMessage += "`n                     - Name: $($result.'Name - Excel')"
                    }
                    if ($result.'Mismatched Items' -match "Title") {
                        $errorMessage += "`n                     - Job Title: $($result.'Job Title - Excel')"
                    }
                    if ($result.'Mismatched Items' -match "Department") {
                        $errorMessage += "`n                     - Department: $($result.'Department - Excel')"
                    }
                    if ($result.'Mismatched Items' -match "Manager") {
                        $errorMessage += "`n                     - Manager: $($result.'Manager - Excel')"
                    }
                    if ($result.'Mismatched Items' -match "Employee Code") {
                        $errorMessage += "`n                     - Code: $($result.'Code - Excel')"
                    }
                    if ($result.'Mismatched Items' -match "OU") {
                        $errorMessage += "`n                     - OU: $($result.'OU - Excel')"
                    }
                    Error-Message $errorMessage
                }
            } else {
                $changesMade += "Changes skipped for $($result.'Name - AD')"
                }
                } 
    }
}
# Compare current and stored titles and departments
$newTitles = $currentTitles.Keys | Where-Object { $_ -notin $storedTitles }
$removedTitles = $storedTitles | Where-Object { $_ -notin $currentTitles.Keys }

$newDepartments = $currentDepartments.Keys | Where-Object { $_ -notin $storedDepartments }
$removedDepartments = $storedDepartments | Where-Object { $_ -notin $currentDepartments.Keys }

# Log changes
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
foreach ($title in $newTitles) {
    Add-Content -Path $logFile -Value "$timestamp - New Title Added: $title"
}
foreach ($title in $removedTitles) {
    Add-Content -Path $logFile -Value "$timestamp - Title Removed: $title"
}
foreach ($department in $newDepartments) {
    Add-Content -Path $logFile -Value "$timestamp - New Department Added: $department"
}
foreach ($department in $removedDepartments) {
    Add-Content -Path $logFile -Value "$timestamp - Department Removed: $department"
}

# Update persistent storage
$updatedData = @{
    Titles = $currentTitles.Keys
    Departments = $currentDepartments.Keys
}
$updatedData | ConvertTo-Json | Set-Content -Path $dataFile

# Output notification
if ($newTitles.Count -gt 0 -or $newDepartments.Count -gt 0) {
    $host.UI.RawUI.BackgroundColor = "Yellow"
    $host.UI.RawUI.ForegroundColor = "Red"
    Write-Host "===================="
    Write-Host "New Titles or Departments Found!"
    Write-Host "===================="
    foreach ($title in $newTitles) {
        Write-Host "New Title: $title"
    }
    foreach ($department in $newDepartments) {
        Write-Host "New Department: $department"
    }
    $host.UI.RawUI.BackgroundColor = "Black"
    $host.UI.RawUI.ForegroundColor = "White"
}

# Save results to an Excel file
$results | Export-Excel -Path $outputFile -AutoSize -WorksheetName "AuditResults" -FreezeTopRow -AutoFilter

# Set column width for specific columns
$excel = Open-ExcelPackage -Path $outputFile
$worksheet = $excel.Workbook.Worksheets["AuditResults"]
$worksheet.Column(1).Width = 24   # 'Name - AD'
$worksheet.Column(2).Width = 24   # 'Name - Excel'
$worksheet.Column(5).Width = 33   # 'Job Title - AD'
$worksheet.Column(6).Width = 33   # 'Job Title - Excel'
$worksheet.Column(7).Width = 30   # 'Department - AD'
$worksheet.Column(8).Width = 30   # 'Department - Excel'
$worksheet.Column(11).Width = 2    # 'OU - AD'
$worksheet.Column(12).Width = 2    # 'OU - Excel'
$worksheet.Column(13).Width = 20   # 'Identity'											   

Close-ExcelPackage -ExcelPackage $excel


# Log completion
Log-Message "Script completed successfully. Output saved to $outputFile."
$debugMessages += "Script completed successfully. Output saved to $outputFile."
$logMessages = $logMessages | Sort-Object
Set-Content -Path $logFile -Value "Script Name: $scriptName"
$logMessages | ForEach-Object { Add-Content -Path $logFile -Value $_ }

# Save debug logs
$debugMessages = $debugMessages | Sort-Object
Set-Content -Path $debugFile -Value "Script Name: $scriptName"
$debugMessages | ForEach-Object { Add-Content -Path $debugFile -Value $_ }

# Save terminated logs
$terminatedMessages = $terminatedMessages | Sort-Object
Set-Content -Path $terminatedFile -Value "Script Name: $scriptName"
$terminatedMessages | ForEach-Object { Add-Content -Path $terminatedFile -Value $_ }

# Save not found logs
$notFoundMessages = $notFoundMessages | Sort-Object
Set-Content -Path $notFoundFile -Value "Script Name: $scriptName"
$notFoundMessages | ForEach-Object { Add-Content -Path $notFoundFile -Value $_ }

# Save changes log
$changesMade = $changesMade | Sort-Object
Set-Content -Path $changesFile -Value "Script Name: $scriptName"
$changesMade | ForEach-Object { Add-Content -Path $changesFile -Value $_ }

# Save error logs
$errorMessages = $errorMessages | Sort-Object
Set-Content -Path $errorFile -Value "Script Name: $scriptName"
$errorMessages | ForEach-Object { Add-Content -Path $errorFile -Value $_ }
