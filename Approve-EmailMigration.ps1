# Save the start time
$startTime = Get-Date

# Define the duration to run the script (60 minutes)
$duration = New-TimeSpan -Minutes 60

# Initialize a counter for the loop iterations
$iteration = 0

Connect-ExchangeOnline

# Run the loop until the current time is less than start time + duration
while ((Get-Date) -lt $startTime.Add($duration)) {
    # Increase the counter
    $iteration += 1

    try {
        # Attempt to get migration users with status 'needsapproval'
        $users = Get-MigrationUser -Status needsapproval -ErrorAction Stop

        # Check if there are any users needing approval
        if ($users -and $users.Count -gt 0) {
            # Approve skipped items for users with status 'needsapproval'
            $users | Set-MigrationUser -ApproveSkippedItems -ErrorAction Stop

            # Report the number of users who were in 'needsapproval' status and processed
            Write-Host "Iteration ${iteration}: Approved skipped items for $($users.Count) users at $(Get-Date)."
        } else {
            # Report that no users are currently in the 'needsapproval' status
            Write-Host "Iteration ${iteration}: No users in 'needsapproval' status at $(Get-Date)."
        }
    } catch {
        Write-Host "An error occurred during iteration ${iteration}: $_. The script will continue to the next iteration."
    }

    # Wait 30 seconds before the next iteration
    Start-Sleep -Seconds 30
}

Write-Host "Script completed."