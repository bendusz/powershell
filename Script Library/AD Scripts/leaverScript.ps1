#Requires -Version 5.1
<#
.SYNOPSIS
    Active Directory User Offboarding/Leaver Processing Script.

.DESCRIPTION
    This script automates the process of offboarding users from Active Directory when they leave the organization.
    It performs the following actions:
    - Selects a user to process using Out-GridView
    - Disables the user account
    - Removes group memberships (with optional backup)
    - Moves the account to a Disabled Users OU
    - Handles direct reports reassignment (batch or individual)
    - Logs all actions for audit purposes
    
    Features:
    - Interactive user selection
    - Direct reports handling with new manager assignment
    - Comprehensive logging
    - Error handling

.PARAMETER LogPath
    Path where logs will be stored. Default is "C:\logs".

.PARAMETER DisabledOU
    Distinguished name of the OU where disabled accounts should be moved.
    Default is "OU=Disabled Users,DC=contoso,DC=com"

.PARAMETER BackupMemberships
    If specified, the script will save the user's group memberships before removing them.

.EXAMPLE
    .\leaverScript.ps1
    Runs the script with interactive prompts.

.EXAMPLE
    .\leaverScript.ps1 -DisabledOU "OU=Former Employees,DC=company,DC=local" -BackupMemberships
    Runs the script using a custom OU for disabled accounts and backs up group memberships.

.NOTES
    Version:        1.0
    Author:         Ben Vegh
    Creation Date:  01/04/2025
    Purpose:        Template for processing leavers in AD
    Requirements:   - PowerShell 5.1+
                    - Active Directory module
                    - Run as user with rights to modify users in AD
#>

param (
    [string]$LogPath = "C:\logs",
    [string]$DisabledOU = "OU=Disabled Users,DC=contoso,DC=com",
    [switch]$BackupMemberships
)

#region Functions

function Initialize-Environment {
    <#
    .SYNOPSIS
        Sets up the environment for script execution.
    .DESCRIPTION
        Validates prerequisites, loads required modules, and creates log directory.
    #>
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }
        catch {
            Write-Error "Failed to create log directory: $_"
            exit 1
        }
    }
    
    # Check if Active Directory module is available and load it
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Error "Active Directory module not available. Please install RSAT tools."
        exit 1
    }
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Verbose "Active Directory module loaded successfully"
    }
    catch {
        Write-Error "Failed to load Active Directory module: $_"
        exit 1
    }
    
    # Check if the disabled OU exists
    try {
        if (-not (Get-ADOrganizationalUnit -Identity $DisabledOU -ErrorAction SilentlyContinue)) {
            Write-Warning "The specified disabled OU does not exist: $DisabledOU"
            Write-Warning "You will need to specify a valid OU when prompted."
            $script:DisabledOUExists = $false
        }
        else {
            $script:DisabledOUExists = $true
        }
    }
    catch {
        Write-Warning "Error checking disabled OU: $_"
        $script:DisabledOUExists = $false
    }
    
    # Initialize log file with timestamp
    $script:LogFile = Join-Path -Path $LogPath -ChildPath "LeaverProcessing_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Log -Message "=== Leaver Processing Script Started ===" -Level "INFO"
    Write-Log -Message "Log file initialized at $($script:LogFile)" -Level "INFO"
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file.
    .DESCRIPTION
        Writes a timestamped message to the log file with a specified level.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        The level of the message (INFO, WARNING, ERROR, SUCCESS).
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
        
        # Also output to console with color based on level
        switch ($Level) {
            "INFO"    { Write-Verbose $Message -ForegroundColor Blue }
            "WARNING" { Write-Warning $Message -ForegroundColor Yellow }
            "ERROR"   { Write-Error $Message -ForegroundColor Red }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        }
    }
    catch {
        Write-Error "Failed to write to log file: $_"
    }
}

function Select-LeavingUser {
    <#
    .SYNOPSIS
        Selects the user that is leaving the organization.
    .DESCRIPTION
        Uses Out-GridView to select the user to process.
    .OUTPUTS
        Selected AD user object.
    #>
    
    Write-Log -Message "Beginning user selection" -Level "INFO"
    
    try {
        # Get all enabled users for selection
        $allUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties DisplayName, Title, Department, Manager, DistinguishedName |
            Sort-Object DisplayName
        
        if ($allUsers.Count -eq 0) {
            Write-Log -Message "No enabled users found in AD" -Level "WARNING"
            Write-Error "No enabled users found in AD. Exiting."
            exit 1
        }
        
        # Select user using Out-GridView
        $selectedUser = $allUsers | 
            Select-Object -Property DisplayName, SamAccountName, Title, Department, DistinguishedName |
            Out-GridView -Title "Select the user who is leaving" -OutputMode Single
        
        if (-not $selectedUser) {
            Write-Log -Message "No user selected. Exiting." -Level "WARNING"
            Write-Host "No user selected. Exiting." -ForegroundColor Yellow
            exit 0
        }
        
        # Get the full user object
        $fullUserObject = Get-ADUser -Identity $selectedUser.SamAccountName -Properties * -ErrorAction Stop
        
        Write-Log -Message "User selected: $($fullUserObject.DisplayName) ($($fullUserObject.SamAccountName))" -Level "INFO"
        
        return $fullUserObject
    }
    catch {
        Write-Log -Message "Error selecting user: $_" -Level "ERROR"
        Write-Error "Error selecting user: $_"
        exit 1
    }
}

function Backup-GroupMemberships {
    <#
    .SYNOPSIS
        Backs up a user's group memberships.
    .DESCRIPTION
        Saves the list of groups a user belongs to for future reference.
    .PARAMETER User
        The AD user object.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    if (-not $BackupMemberships) {
        return
    }
    
    Write-Log -Message "Backing up group memberships for $($User.SamAccountName)" -Level "INFO"
    
    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName |
            Where-Object { $_.Name -ne "Domain Users" } # Typically can't remove from Domain Users
        
        if ($groups.Count -eq 0) {
            Write-Log -Message "User $($User.SamAccountName) doesn't belong to any groups except default ones" -Level "INFO"
            return
        }
        
        # Create backup file
        $backupFile = Join-Path -Path $LogPath -ChildPath "GroupMemberships_$($User.SamAccountName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        # Export to CSV
        $groups | Select-Object Name, DistinguishedName | 
            Export-Csv -Path $backupFile -NoTypeInformation
        
        Write-Log -Message "Group memberships backed up to $backupFile" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Error backing up group memberships: $_" -Level "ERROR"
        Write-Warning "Failed to back up group memberships. Continuing with other operations."
    }
}

function Remove-GroupMemberships {
    <#
    .SYNOPSIS
        Removes a user from all groups except primary group.
    .DESCRIPTION
        Removes the user from all AD groups they belong to except their primary group.
    .PARAMETER User
        The AD user object.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    Write-Log -Message "Removing group memberships for $($User.SamAccountName)" -Level "INFO"
    
    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName |
            Where-Object { $_.Name -ne "Domain Users" } # Typically can't remove from Domain Users
        
        if ($groups.Count -eq 0) {
            Write-Log -Message "User $($User.SamAccountName) doesn't belong to any groups except default ones" -Level "INFO"
            return
        }
        
        foreach ($group in $groups) {
            try {
                Remove-ADGroupMember -Identity $group -Members $User.SamAccountName -Confirm:$false -ErrorAction Stop
                Write-Log -Message "Removed $($User.SamAccountName) from group '$($group.Name)'" -Level "SUCCESS"
            }
            catch {
                Write-Log -Message "Error removing $($User.SamAccountName) from group '$($group.Name)': $_" -Level "ERROR"
            }
        }
    }
    catch {
        Write-Log -Message "Error removing group memberships: $_" -Level "ERROR"
        Write-Warning "Failed to remove some group memberships."
    }
}

function Disable-LeavingUser {
    <#
    .SYNOPSIS
        Disables a user account.
    .DESCRIPTION
        Disables the user account and optionally adds a description.
    .PARAMETER User
        The AD user object.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    Write-Log -Message "Disabling account for $($User.SamAccountName)" -Level "INFO"
    
    try {
        # Get current date for the description
        $currentDate = Get-Date -Format "yyyy-MM-dd"
        $description = "Disabled on $currentDate - User left the organization"
        
        # Disable the account
        Disable-ADAccount -Identity $User.SamAccountName -ErrorAction Stop
        
        # Update description
        Set-ADUser -Identity $User.SamAccountName -Description $description -ErrorAction Stop
        
        Write-Log -Message "Account disabled successfully: $($User.SamAccountName)" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Error disabling account: $_" -Level "ERROR"
        Write-Error "Failed to disable the account: $_"
        return $false
    }
    
    return $true
}

function Move-ToDisabledOU {
    <#
    .SYNOPSIS
        Moves a user account to the disabled users OU.
    .DESCRIPTION
        Moves the disabled user account to the specified OU for disabled users.
    .PARAMETER User
        The AD user object.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    Write-Log -Message "Moving account to disabled users OU" -Level "INFO"
    
    # If the disabled OU doesn't exist, prompt for a valid one
    $targetOU = $DisabledOU
    if (-not $script:DisabledOUExists) {
        do {
            $promptedOU = Read-Host "Enter the distinguished name of the OU for disabled users (e.g., OU=Disabled Users,DC=contoso,DC=com)"
            
            try {
                if (Get-ADOrganizationalUnit -Identity $promptedOU -ErrorAction SilentlyContinue) {
                    $targetOU = $promptedOU
                    $validOU = $true
                    Write-Log -Message "Using custom OU for disabled users: $targetOU" -Level "INFO"
                }
                else {
                    Write-Warning "Invalid OU. Please enter a valid distinguished name."
                    $validOU = $false
                }
            }
            catch {
                Write-Warning "Error checking OU: $_"
                $validOU = $false
            }
        } while (-not $validOU)
    }
    
    try {
        # Move the user to the disabled OU
        Move-ADObject -Identity $User.DistinguishedName -TargetPath $targetOU -ErrorAction Stop
        Write-Log -Message "User $($User.SamAccountName) moved to disabled OU: $targetOU" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log -Message "Error moving user to disabled OU: $_" -Level "ERROR"
        Write-Error "Failed to move user to disabled OU: $_"
        return $false
    }
}

function Get-DirectReports {
    <#
    .SYNOPSIS
        Gets the direct reports of a user.
    .DESCRIPTION
        Retrieves the list of users who report directly to the specified user.
    .PARAMETER User
        The AD user object.
    .OUTPUTS
        Array of AD user objects who are direct reports.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    Write-Log -Message "Checking for direct reports of $($User.SamAccountName)" -Level "INFO"
    
    try {
        $directReports = Get-ADUser -Filter "Manager -eq '$($User.DistinguishedName)'" -Properties DisplayName, Title, Department, Manager
        
        if ($directReports) {
            Write-Log -Message "Found $($directReports.Count) direct reports for $($User.SamAccountName)" -Level "INFO"
            return $directReports
        }
        else {
            Write-Log -Message "No direct reports found for $($User.SamAccountName)" -Level "INFO"
            return $null
        }
    }
    catch {
        Write-Log -Message "Error checking direct reports: $_" -Level "ERROR"
        return $null
    }
}

function Select-NewManager {
    <#
    .SYNOPSIS
        Selects a new manager for direct reports.
    .DESCRIPTION
        Uses Out-GridView to select a new manager for reassignment.
    .OUTPUTS
        Selected AD user object to be the new manager.
    #>
    param (
        [string]$Title = "Select a new manager"
    )
    
    Write-Log -Message "Beginning new manager selection" -Level "INFO"
    
    try {
        # Get potential managers
        $potentialManagers = Get-ADUser -Filter {Enabled -eq $true} -Properties DisplayName, Title, Department |
            Where-Object { -not [string]::IsNullOrEmpty($_.DisplayName) } |
            Sort-Object DisplayName
        
        if ($potentialManagers.Count -eq 0) {
            Write-Log -Message "No potential managers found in AD" -Level "WARNING"
            return $null
        }
        
        # Select manager using Out-GridView
        $selectedManager = $potentialManagers | 
            Select-Object -Property DisplayName, SamAccountName, Title, Department |
            Out-GridView -Title $Title -OutputMode Single
        
        if ($selectedManager) {
            Write-Log -Message "New manager selected: $($selectedManager.DisplayName) ($($selectedManager.SamAccountName))" -Level "INFO"
            return $selectedManager
        }
        else {
            Write-Log -Message "No manager selected" -Level "WARNING"
            return $null
        }
    }
    catch {
        Write-Log -Message "Error selecting new manager: $_" -Level "ERROR"
        return $null
    }
}

function Update-DirectReports {
    <#
    .SYNOPSIS
        Updates the manager for direct reports.
    .DESCRIPTION
        Handles the reassignment of direct reports to new managers.
    .PARAMETER DirectReports
        Array of AD user objects who are direct reports.
    .PARAMETER LeavingUser
        The AD user object who is leaving (current manager).
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$DirectReports,
        
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$LeavingUser
    )
    
    if (-not $DirectReports -or $DirectReports.Count -eq 0) {
        Write-Log -Message "No direct reports to update" -Level "INFO"
        return
    }
    
    Write-Log -Message "Beginning direct reports update for $($DirectReports.Count) users" -Level "INFO"
    Write-Host "`nThe leaving user has $($DirectReports.Count) direct reports that need reassignment." -ForegroundColor Cyan
    
    # Ask how to handle direct reports
    $options = @(
        "Assign all direct reports to a single new manager"
        "Assign each direct report individually to different managers"
        "Skip manager reassignment (not recommended)"
    )
    
    Write-Host "`nHow would you like to handle direct reports?" -ForegroundColor Cyan
    for ($i = 0; $i -lt $options.Count; $i++) {
        Write-Host "[$($i+1)] $($options[$i])"
    }
    
    $valid = $false
    do {
        try {
            $choice = [int](Read-Host "`nEnter your choice (1-$($options.Count))")
            if ($choice -ge 1 -and $choice -le $options.Count) {
                $valid = $true
            }
            else {
                Write-Warning "Invalid option. Please enter a number between 1 and $($options.Count)"
            }
        }
        catch {
            Write-Warning "Please enter a valid number"
        }
    } while (-not $valid)
    
    Write-Log -Message "Selected option for direct reports: $($options[$choice-1])" -Level "INFO"
    
    switch ($choice) {
        1 {
            # Assign all to a single manager
            $newManager = Select-NewManager -Title "Select a new manager for ALL direct reports"
            
            if (-not $newManager) {
                Write-Log -Message "No new manager selected. Skipping direct reports update." -Level "WARNING"
                return
            }
            
            foreach ($report in $DirectReports) {
                try {
                    Set-ADUser -Identity $report -Manager $newManager.DistinguishedName -ErrorAction Stop
                    Write-Log -Message "Updated manager for $($report.SamAccountName) to $($newManager.DisplayName)" -Level "SUCCESS"
                }
                catch {
                    Write-Log -Message "Error updating manager for $($report.SamAccountName): $_" -Level "ERROR"
                }
            }
        }
        2 {
            # Assign individually
            foreach ($report in $DirectReports) {
                Write-Host "`nSelecting manager for: $($report.DisplayName) ($($report.SamAccountName))" -ForegroundColor Cyan
                
                $newManager = Select-NewManager -Title "Select a new manager for $($report.DisplayName)"
                
                if ($newManager) {
                    try {
                        Set-ADUser -Identity $report -Manager $newManager.DistinguishedName -ErrorAction Stop
                        Write-Log -Message "Updated manager for $($report.SamAccountName) to $($newManager.DisplayName)" -Level "SUCCESS"
                    }
                    catch {
                        Write-Log -Message "Error updating manager for $($report.SamAccountName): $_" -Level "ERROR"
                    }
                }
                else {
                    Write-Log -Message "No manager selected for $($report.SamAccountName). Skipping." -Level "WARNING"
                }
            }
        }
        3 {
            # Skip
            Write-Log -Message "Skipping direct reports update as requested" -Level "WARNING"
            Write-Warning "Direct reports will not have a valid manager after this user is disabled."
        }
    }
}

function Show-Summary {
    <#
    .SYNOPSIS
        Displays a summary of the actions performed.
    .DESCRIPTION
        Shows a summary of the offboarding process.
    .PARAMETER User
        The AD user object that was processed.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    Write-Host "`n====== Leaver Processing Summary ======" -ForegroundColor Cyan
    Write-Host "User:           $($User.DisplayName) ($($User.SamAccountName))"
    Write-Host "Account Status: Disabled"
    Write-Host "Groups:         Removed"
    if ($BackupMemberships) {
        Write-Host "Backup:         Group memberships backed up to log directory"
    }
    Write-Host "Location:       Moved to disabled users OU"
    Write-Host "Direct Reports: Processed"
    Write-Host "Log File:       $($script:LogFile)"
    Write-Host "========================================`n"
    
    Write-Log -Message "Leaver processing completed for $($User.SamAccountName)" -Level "SUCCESS"
}

#endregion Functions

#region Main Script

# Set up verbose output
$VerbosePreference = "Continue"

try {
    # Initialize environment and logging
    Initialize-Environment
    
    # Select the user who is leaving
    $leavingUser = Select-LeavingUser
    
    # Confirm processing
    Write-Host "`nReady to process leaver:" -ForegroundColor Cyan
    Write-Host "Name:       $($leavingUser.DisplayName)"
    Write-Host "Username:   $($leavingUser.SamAccountName)"
    if ($leavingUser.Department) {
        Write-Host "Department: $($leavingUser.Department)"
    }
    
    $confirmation = Read-Host "`nDo you want to process this leaver? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Log -Message "Leaver processing cancelled by administrator" -Level "INFO"
        Write-Host "Leaver processing cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    # Check for direct reports before making any changes
    $directReports = Get-DirectReports -User $leavingUser
    
    # Backup group memberships if requested
    if ($BackupMemberships) {
        Backup-GroupMemberships -User $leavingUser
    }
    
    # Remove group memberships
    Remove-GroupMemberships -User $leavingUser
    
    # Disable the account
    $disableSuccess = Disable-LeavingUser -User $leavingUser
    
    # Move to disabled OU
    if ($disableSuccess) {
        $moveSuccess = Move-ToDisabledOU -User $leavingUser
        
        # We only process direct reports if the account was successfully disabled
        if ($directReports -and $directReports.Count -gt 0) {
            Update-DirectReports -DirectReports $directReports -LeavingUser $leavingUser
        }
    }
    
    # Show summary
    Show-Summary -User $leavingUser
}
catch {
    Write-Log -Message "Critical error: $_" -Level "ERROR"
    Write-Error "An unexpected error occurred: $_"
    exit 1
}
finally {
    Write-Log -Message "=== Script execution completed ===" -Level "INFO"
}

#endregion Main Script 