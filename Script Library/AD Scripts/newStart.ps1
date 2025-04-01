#Requires -Version 5.1
<#
.SYNOPSIS
    New Employee AD Account Creation and Provisioning Script.

.DESCRIPTION
    This script automates the creation of Active Directory accounts for new employees.
    It collects user information, places them in the correct OU based on department,
    assigns group memberships, and links them to their manager.
    
    Features:
    - Interactive data collection with validation
    - Department-based OU placement
    - Department-based group membership assignment
    - Manager selection via Out-GridView
    - Comprehensive logging
    - Error handling

.PARAMETER LogPath
    Path where logs will be stored. Default is "C:\logs".

.EXAMPLE
    .\newStart.ps1
    Runs the script with interactive prompts.

.EXAMPLE
    .\newStart.ps1 -LogPath "D:\ADLogs"
    Runs the script with logs stored in D:\ADLogs.

.NOTES
    Version:        1.0
    Author:         Ben Vegh
    Creation Date:  01/04/2025
    Purpose:        Template for onboarding new employees in AD
    Requirements:   - PowerShell 5.1+
                    - Active Directory module
                    - Run as user with rights to create users in AD
#>

param (
    [string]$LogPath = "C:\logs"
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
    
    # Initialize log file with timestamp
    $script:LogFile = Join-Path -Path $LogPath -ChildPath "NewUserCreation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Log -Message "=== New User Creation Script Started ===" -Level "INFO"
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

function Get-UserInput {
    <#
    .SYNOPSIS
        Collects and validates user input for the new employee.
    .DESCRIPTION
        Prompts for first name, last name, display name, username, email, and validates the input.
    .OUTPUTS
        PSObject containing user details
    #>
    
    Write-Log -Message "Beginning user information collection" -Level "INFO"
    
    # Initialize user info object
    $userInfo = [PSCustomObject]@{
        FirstName  = ""
        LastName   = ""
        DisplayName = ""
        Username   = ""
        Email      = ""
        Department = ""
        Manager    = ""
        OU         = ""
        Groups     = @()
    }
    
    # First Name
    do {
        $userInfo.FirstName = Read-Host "Enter employee's first name"
        if ([string]::IsNullOrWhiteSpace($userInfo.FirstName)) {
            Write-Warning "First name cannot be empty"
        }
    } while ([string]::IsNullOrWhiteSpace($userInfo.FirstName))
    Write-Log -Message "First name entered: $($userInfo.FirstName)" -Level "INFO"
    
    # Last Name
    do {
        $userInfo.LastName = Read-Host "Enter employee's last name"
        if ([string]::IsNullOrWhiteSpace($userInfo.LastName)) {
            Write-Warning "Last name cannot be empty"
        }
    } while ([string]::IsNullOrWhiteSpace($userInfo.LastName))
    Write-Log -Message "Last name entered: $($userInfo.LastName)" -Level "INFO"
    
    # Display Name (with default)
    $defaultDisplayName = "$($userInfo.FirstName) $($userInfo.LastName)"
    $inputDisplayName = Read-Host "Enter display name [$defaultDisplayName]"
    $userInfo.DisplayName = if ([string]::IsNullOrWhiteSpace($inputDisplayName)) { $defaultDisplayName } else { $inputDisplayName }
    Write-Log -Message "Display name set to: $($userInfo.DisplayName)" -Level "INFO"
    
    # Username (with suggestion)
    $suggestedUsername = "$($userInfo.FirstName.Substring(0,1))$($userInfo.LastName)".ToLower()
    $suggestedUsername = $suggestedUsername -replace '[^a-zA-Z0-9]', '' # Remove special characters
    
    do {
        $inputUsername = Read-Host "Enter username [$suggestedUsername]"
        $userInfo.Username = if ([string]::IsNullOrWhiteSpace($inputUsername)) { $suggestedUsername } else { $inputUsername }
        
        # Check if username exists
        try {
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($userInfo.Username)'" -ErrorAction Stop
            if ($existingUser) {
                Write-Warning "Username '$($userInfo.Username)' already exists. Please choose a different username."
                $userInfo.Username = ""
            }
        }
        catch {
            # If error is not "user not found", log it
            if ($_.Exception.Message -notlike "*Cannot find an object with identity*") {
                Write-Log -Message "Error checking username: $_" -Level "ERROR"
            }
        }
    } while ([string]::IsNullOrWhiteSpace($userInfo.Username))
    Write-Log -Message "Username set to: $($userInfo.Username)" -Level "INFO"
    
    # Email (with suggestion)
    $domainName = (Get-ADDomain).DNSRoot
    $suggestedEmail = "$($userInfo.Username)@$domainName"
    
    $inputEmail = Read-Host "Enter email address [$suggestedEmail]"
    $userInfo.Email = if ([string]::IsNullOrWhiteSpace($inputEmail)) { $suggestedEmail } else { $inputEmail }
    Write-Log -Message "Email set to: $($userInfo.Email)" -Level "INFO"
    
    return $userInfo
}

function Select-Department {
    <#
    .SYNOPSIS
        Allows selection of a department from predefined options.
    .DESCRIPTION
        Presents a menu of department options and returns the selected department.
    .PARAMETER UserInfo
        User information object to update with department selection.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UserInfo
    )
    
    Write-Log -Message "Beginning department selection" -Level "INFO"
    
    # Define departments with their associated OUs and groups
    # This should be customized for each organization
    $departments = @{
        "IT" = @{
            OU = "OU=IT,OU=Departments,DC=contoso,DC=com"
            Groups = @(
                "IT Staff",
                "VPN Users",
                "Remote Desktop Users"
            )
        }
        "HR" = @{
            OU = "OU=HR,OU=Departments,DC=contoso,DC=com"
            Groups = @(
                "HR Staff",
                "Document Reviewers",
                "Policy Administrators"
            )
        }
        "Finance" = @{
            OU = "OU=Finance,OU=Departments,DC=contoso,DC=com"
            Groups = @(
                "Finance Team",
                "Budget Approvers",
                "SAP Users"
            )
        }
        "Marketing" = @{
            OU = "OU=Marketing,OU=Departments,DC=contoso,DC=com"
            Groups = @(
                "Marketing Team",
                "Social Media",
                "Creative Team"
            )
        }
        "Sales" = @{
            OU = "OU=Sales,OU=Departments,DC=contoso,DC=com"
            Groups = @(
                "Sales Team",
                "CRM Users",
                "Customer Service"
            )
        }
    }
    
    # Display department options
    Write-Host "`nAvailable Departments:" -ForegroundColor Cyan
    $i = 1
    $departmentList = @()
    
    foreach ($dept in $departments.Keys | Sort-Object) {
        Write-Host "[$i] $dept"
        $departmentList += $dept
        $i++
    }
    
    # Get valid selection
    do {
        try {
            $selection = [int](Read-Host "`nSelect department (1-$($departmentList.Count))")
            if ($selection -lt 1 -or $selection -gt $departmentList.Count) {
                Write-Warning "Invalid selection. Please enter a number between 1 and $($departmentList.Count)"
                $isValid = $false
            }
            else {
                $isValid = $true
            }
        }
        catch {
            Write-Warning "Please enter a valid number"
            $isValid = $false
        }
    } while (-not $isValid)
    
    # Update user info with department selection
    $selectedDept = $departmentList[$selection-1]
    $UserInfo.Department = $selectedDept
    $UserInfo.OU = $departments[$selectedDept].OU
    $UserInfo.Groups = $departments[$selectedDept].Groups
    
    Write-Log -Message "Department selected: $selectedDept" -Level "INFO"
    Write-Log -Message "OU set to: $($UserInfo.OU)" -Level "INFO"
    Write-Log -Message "Groups assigned: $($UserInfo.Groups -join ', ')" -Level "INFO"
    
    return $UserInfo
}

function Select-Manager {
    <#
    .SYNOPSIS
        Allows selection of a manager using Out-GridView.
    .DESCRIPTION
        Retrieves potential managers from AD and presents them in Out-GridView for selection.
    .PARAMETER UserInfo
        User information object to update with manager selection.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UserInfo
    )
    
    Write-Log -Message "Beginning manager selection" -Level "INFO"
    
    try {
        # Get list of potential managers
        # This filter gets all enabled user accounts
        $filterString = "(objectClass=user)(enabled=TRUE)"
        
        $potentialManagers = Get-ADUser -LDAPFilter "(&$filterString)" `
                             -Properties DisplayName, Department, Title | 
        Where-Object { 
            (-not [string]::IsNullOrEmpty($_.DisplayName))
        } | 
        Sort-Object DisplayName
        
        if ($potentialManagers.Count -eq 0) {
            Write-Warning "No potential managers found in AD"
            Write-Log -Message "No potential managers found in AD" -Level "WARNING"
            return $UserInfo
        }
        
        # Select manager using Out-GridView
        $selectedManager = $potentialManagers | 
            Select-Object -Property DisplayName, SamAccountName, Department, Title |
            Out-GridView -Title "Select a manager for $($UserInfo.DisplayName)" -OutputMode Single
        
        if ($selectedManager) {
            $UserInfo.Manager = $selectedManager.SamAccountName
            Write-Log -Message "Manager selected: $($selectedManager.DisplayName) ($($selectedManager.SamAccountName))" -Level "INFO"
        }
        else {
            Write-Log -Message "No manager selected" -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "Error during manager selection: $_" -Level "ERROR"
    }
    
    return $UserInfo
}

function New-ADUserAccount {
    <#
    .SYNOPSIS
        Creates a new AD user account.
    .DESCRIPTION
        Creates the AD user account with the specified properties in the correct OU.
    .PARAMETER UserInfo
        User information object containing all details for the new user.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UserInfo
    )
    
    Write-Log -Message "Beginning AD user account creation" -Level "INFO"
    
    # Generate a random password
    $passwordLength = 12
    $randomPassword = -join ((33..126) | Get-Random -Count $passwordLength | ForEach-Object { [char]$_ })
    $securePassword = ConvertTo-SecureString -String $randomPassword -AsPlainText -Force
    
    # Default properties for new user
    $userProperties = @{
        SamAccountName = $UserInfo.Username
        UserPrincipalName = $UserInfo.Email
        Name = $UserInfo.DisplayName
        GivenName = $UserInfo.FirstName
        Surname = $UserInfo.LastName
        DisplayName = $UserInfo.DisplayName
        EmailAddress = $UserInfo.Email
        Department = $UserInfo.Department
        Enabled = $true
        ChangePasswordAtLogon = $true
        AccountPassword = $securePassword
        Path = $UserInfo.OU
    }
    
    # Add manager if specified
    if (-not [string]::IsNullOrEmpty($UserInfo.Manager)) {
        $userProperties["Manager"] = (Get-ADUser -Identity $UserInfo.Manager).DistinguishedName
    }
    
    try {
        # Create the user account
        New-ADUser @userProperties -ErrorAction Stop
        Write-Log -Message "User account created successfully: $($UserInfo.Username)" -Level "SUCCESS"
        
        # Output the temporary password for the administrator
        Write-Host "`nUser account created successfully!" -ForegroundColor Green
        Write-Host "Temporary password: $randomPassword" -ForegroundColor Yellow
        Write-Host "IMPORTANT: Provide this password to the user securely." -ForegroundColor Yellow
        Write-Host "The user will be prompted to change it at first logon.`n" -ForegroundColor Yellow
        
        return $true
    }
    catch {
        Write-Log -Message "Failed to create AD user account: $_" -Level "ERROR"
        Write-Error "Failed to create AD user account: $_"
        return $false
    }
}

function Add-GroupMemberships {
    <#
    .SYNOPSIS
        Adds the user to specified AD groups.
    .DESCRIPTION
        Adds the new user to the department-specific AD groups defined in their profile.
    .PARAMETER Username
        The username (SamAccountName) of the user.
    .PARAMETER Groups
        Array of group names to add the user to.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string[]]$Groups
    )
    
    Write-Log -Message "Beginning group membership assignment for $Username" -Level "INFO"
    
    foreach ($group in $Groups) {
        try {
            # Check if the group exists
            $adGroup = Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction Stop
            
            if ($adGroup) {
                # Add user to the group
                Add-ADGroupMember -Identity $adGroup -Members $Username -ErrorAction Stop
                Write-Log -Message "Added $Username to group: $group" -Level "SUCCESS"
            }
            else {
                Write-Log -Message "Group not found: $group" -Level "WARNING"
            }
        }
        catch {
            Write-Log -Message "Error adding $Username to group '$group': $_" -Level "ERROR"
        }
    }
}

function Show-Summary {
    <#
    .SYNOPSIS
        Displays a summary of the actions performed.
    .DESCRIPTION
        Shows a summary of the user creation process, including account details and group memberships.
    .PARAMETER UserInfo
        User information object containing all details for the new user.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UserInfo
    )
    
    Write-Host "`n====== New User Account Summary ======" -ForegroundColor Cyan
    Write-Host "Name:       $($UserInfo.DisplayName)"
    Write-Host "Username:   $($UserInfo.Username)"
    Write-Host "Email:      $($UserInfo.Email)"
    Write-Host "Department: $($UserInfo.Department)"
    Write-Host "OU:         $($UserInfo.OU)"
    Write-Host "Manager:    $(if ($UserInfo.Manager) { $UserInfo.Manager } else { 'None' })"
    Write-Host "Groups:     $(if ($UserInfo.Groups) { $UserInfo.Groups -join ', ' } else { 'None' })"
    Write-Host "Log File:   $($script:LogFile)"
    Write-Host "=======================================`n"
    
    Write-Log -Message "User creation process completed for $($UserInfo.Username)" -Level "SUCCESS"
}

#endregion Functions

#region Main Script

# Set up verbose output
$VerbosePreference = "Continue"

try {
    # Initialize environment and logging
    Initialize-Environment
    
    # Collect user information
    $userInfo = Get-UserInput
    
    # Select department and associated OU/groups
    $userInfo = Select-Department -UserInfo $userInfo
    
    # Select manager
    $userInfo = Select-Manager -UserInfo $userInfo
    
    # Confirm creation
    Write-Host "`nReady to create user with the following details:" -ForegroundColor Cyan
    Write-Host "Name: $($userInfo.DisplayName)"
    Write-Host "Username: $($userInfo.Username)"
    Write-Host "Department: $($userInfo.Department)"
    
    $confirmation = Read-Host "`nDo you want to create this user? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Log -Message "User creation cancelled by administrator" -Level "INFO"
        Write-Host "User creation cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    # Create AD user account
    $success = New-ADUserAccount -UserInfo $userInfo
    
    if ($success) {
        # Add group memberships
        Add-GroupMemberships -Username $userInfo.Username -Groups $userInfo.Groups
        
        # Show summary
        Show-Summary -UserInfo $userInfo
    }
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
