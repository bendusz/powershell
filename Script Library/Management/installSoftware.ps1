#Requires -Version 5.1
<#
.SYNOPSIS
    Software Installation Script supporting multiple package managers.

.DESCRIPTION
    This script provides a unified interface for installing software using different package managers:
    - Windows Package Manager (winget) - Default
    - Microsoft Store (msstore)
    - Chocolatey (choco)

    The script will check if the selected package manager is installed and guide the user through
    the installation process.

.PARAMETER SoftwareName
    The name of the software to install. If not provided, the script will prompt for it.

.PARAMETER PackageManager
    The package manager to use for installation. Options are 'winget', 'msstore', or 'choco'.
    Default is 'winget'.

.PARAMETER LogPath
    The path where the log file will be created. Default is 'C:\logs'.

.EXAMPLE
    .\installSoftware.ps1
    Prompts for software name and uses winget to install it.

.EXAMPLE
    .\installSoftware.ps1 -SoftwareName "Visual Studio Code"
    Installs Visual Studio Code using winget.

.EXAMPLE
    .\installSoftware.ps1 -SoftwareName "Netflix" -PackageManager "msstore"
    Installs Netflix from the Microsoft Store.

.NOTES
    Version:        1.0
    Author:         Ben Vegh
    Creation Date:  01/04/2025
    Requirements:   - PowerShell 5.1+
                    - Admin rights for some installations
                    - Internet connection
#>

param (
    [string]$SoftwareName,
    [ValidateSet('winget', 'msstore', 'choco')]
    [string]$PackageManager = 'winget',
    [string]$LogPath = 'C:\logs'
)

#region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to both the console and a log file.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        The level of the log message (Info, Warning, Error).
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        'Info' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        }
        $logFile = Join-Path $LogPath "software_install_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage
    } catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Checks if the script is running with administrator privileges.
    .OUTPUTS
        Boolean indicating if script has admin privileges.
    #>
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Log -Message "Checking for administrator privileges: $isAdmin" -Level 'Info'
    return $isAdmin
}

function Test-CommandExists {
    <#
    .SYNOPSIS
        Checks if a command exists.
    .PARAMETER Command
        Name of the command to check.
    .OUTPUTS
        Boolean indicating if the command exists.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    $exists = $null -ne (Get-Command -Name $Command -ErrorAction SilentlyContinue)
    Write-Log -Message "Checking if command '$Command' exists: $exists" -Level 'Info'
    return $exists
}

function Install-Chocolatey {
    <#
    .SYNOPSIS
        Installs Chocolatey package manager if not already installed.
    .OUTPUTS
        Boolean indicating if Chocolatey is available.
    #>
    if (Test-CommandExists -Command 'choco') {
        Write-Log -Message "Chocolatey is already installed." -Level 'Info'
        return $true
    }
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log -Message "Administrator privileges are required to install Chocolatey." -Level 'Error'
        Write-Log -Message "Please restart the script as Administrator." -Level 'Warning'
        return $false
    }
    
    Write-Log -Message "Installing Chocolatey..." -Level 'Info'
    try {
        # Official Chocolatey installation command
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        if (Test-CommandExists -Command 'choco') {
            Write-Log -Message "Chocolatey installed successfully." -Level 'Info'
            return $true
        } else {
            Write-Log -Message "Failed to install Chocolatey." -Level 'Error'
            return $false
        }
    } catch {
        Write-Log -Message "Error installing Chocolatey: $_" -Level 'Error'
        return $false
    }
}

function Test-WinGet {
    <#
    .SYNOPSIS
        Checks if winget is available and provides installation guidance if not.
    .OUTPUTS
        Boolean indicating if winget is available.
    #>
    if (Test-CommandExists -Command 'winget') {
        Write-Log -Message "Windows Package Manager (winget) is available." -Level 'Info'
        return $true
    }
    
    Write-Log -Message "Windows Package Manager (winget) is not installed." -Level 'Warning'
    Write-Log -Message "To install winget, you need to:" -Level 'Info'
    Write-Log -Message "1. Install 'App Installer' from the Microsoft Store" -Level 'Info'
    Write-Log -Message "2. Or update to Windows 11 or Windows 10 with latest updates" -Level 'Info'
    
    $installFromStore = Read-Host "Would you like to open the Microsoft Store to install App Installer now? (Y/N)"
    if ($installFromStore -eq 'Y' -or $installFromStore -eq 'y') {
        Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"
        Write-Log -Message "Please rerun this script after installing App Installer." -Level 'Warning'
    }
    
    return $false
}

function Test-MicrosoftStore {
    <#
    .SYNOPSIS
        Checks if Microsoft Store is available.
    .OUTPUTS
        Boolean indicating if Microsoft Store is available.
    #>
    # Check if we're on Windows 10/11 which should have Microsoft Store
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $isWindows10OrNewer = [Environment]::OSVersion.Version.Major -ge 10
    
    if (-not $isWindows10OrNewer) {
        Write-Log -Message "Microsoft Store requires Windows 10 or newer." -Level 'Error'
        return $false
    }
    
    # Check if the Microsoft Store app is installed
    $storeApp = Get-AppxPackage -Name "Microsoft.WindowsStore"
    
    if ($null -eq $storeApp) {
        Write-Log -Message "Microsoft Store app is not installed on this system." -Level 'Error'
        return $false
    }
    
    Write-Log -Message "Microsoft Store is available." -Level 'Info'
    return $true
}

function Install-SoftwareWithWinget {
    <#
    .SYNOPSIS
        Installs software using winget.
    .PARAMETER SoftwareName
        Name of the software to install.
    .OUTPUTS
        Boolean indicating if installation was successful.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$SoftwareName
    )
    
    if (-not (Test-WinGet)) {
        return $false
    }
    
    Write-Log -Message "Searching for '$SoftwareName' in winget..." -Level 'Info'
    $searchResults = winget search $SoftwareName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Message "Error searching for software." -Level 'Error'
        return $false
    }
    
    Write-Log -Message "Installing '$SoftwareName' using winget..." -Level 'Info'
    winget install --id $SoftwareName --accept-package-agreements --accept-source-agreements
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log -Message "Successfully installed '$SoftwareName'." -Level 'Info'
        return $true
    } else {
        Write-Log -Message "Failed to install '$SoftwareName'. Exit code: $LASTEXITCODE" -Level 'Error'
        return $false
    }
}

function Install-SoftwareWithMSStore {
    <#
    .SYNOPSIS
        Installs software from Microsoft Store.
    .PARAMETER SoftwareName
        Name of the software to install.
    .OUTPUTS
        Boolean indicating if installation request was successful.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$SoftwareName
    )
    
    if (-not (Test-MicrosoftStore)) {
        return $false
    }
    
    Write-Log -Message "Attempting to open Microsoft Store for '$SoftwareName'..." -Level 'Info'
    
    # Try to search for the app in the Microsoft Store
    Start-Process "ms-windows-store://search/?query=$SoftwareName"
    
    Write-Log -Message "Microsoft Store search opened for '$SoftwareName'." -Level 'Info'
    Write-Log -Message "Please complete the installation manually through the Microsoft Store interface." -Level 'Warning'
    
    return $true
}

function Install-SoftwareWithChocolatey {
    <#
    .SYNOPSIS
        Installs software using Chocolatey.
    .PARAMETER SoftwareName
        Name of the software to install.
    .OUTPUTS
        Boolean indicating if installation was successful.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$SoftwareName
    )
    
    if (-not (Install-Chocolatey)) {
        return $false
    }
    
    if (-not (Test-AdminPrivileges)) {
        Write-Log -Message "Administrator privileges are required to install software with Chocolatey." -Level 'Error'
        Write-Log -Message "Please restart the script as Administrator." -Level 'Warning'
        return $false
    }
    
    Write-Log -Message "Searching for '$SoftwareName' in Chocolatey..." -Level 'Info'
    $searchResults = choco search $SoftwareName
    
    Write-Log -Message "Installing '$SoftwareName' using Chocolatey..." -Level 'Info'
    choco install $SoftwareName -y
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log -Message "Successfully installed '$SoftwareName'." -Level 'Info'
        return $true
    } else {
        Write-Log -Message "Failed to install '$SoftwareName'. Exit code: $LASTEXITCODE" -Level 'Error'
        return $false
    }
}

#endregion Functions

#region Main Script

# Title
Write-Log -Message "=== Software Installation Helper ===" -Level 'Info'
Write-Log -Message "Log file location: $LogPath" -Level 'Info'

# If software name not provided as parameter, prompt for it
if ([string]::IsNullOrWhiteSpace($SoftwareName)) {
    $SoftwareName = Read-Host "Enter the name of the software you want to install"
}

# If no software name provided, exit
if ([string]::IsNullOrWhiteSpace($SoftwareName)) {
    Write-Log -Message "No software name provided. Exiting." -Level 'Error'
    exit 1
}

# If package manager not explicitly specified, prompt for it
if ($PSBoundParameters.ContainsKey('PackageManager') -eq $false) {
    Write-Log -Message "Available package managers:" -Level 'Info'
    Write-Log -Message "1. Windows Package Manager (winget) [Default]" -Level 'Info'
    Write-Log -Message "2. Microsoft Store (msstore)" -Level 'Info'
    Write-Log -Message "3. Chocolatey (choco)" -Level 'Info'
    
    $selection = Read-Host "`nSelect package manager (1-3, default is 1)"
    
    # Default to winget if no selection made
    if ([string]::IsNullOrWhiteSpace($selection)) {
        $selection = "1"
    }
    
    switch ($selection) {
        "1" { $PackageManager = "winget" }
        "2" { $PackageManager = "msstore" }
        "3" { $PackageManager = "choco" }
        default {
            Write-Log -Message "Invalid selection. Using default (winget)." -Level 'Warning'
            $PackageManager = "winget"
        }
    }
}

# Display installation information
Write-Log -Message "Installation Details:" -Level 'Info'
Write-Log -Message "Software: '$SoftwareName'" -Level 'Info'
Write-Log -Message "Package Manager: '$PackageManager'" -Level 'Info'

# Perform installation based on selected package manager
$success = $false
switch ($PackageManager) {
    "winget" {
        $success = Install-SoftwareWithWinget -SoftwareName $SoftwareName
    }
    "msstore" {
        $success = Install-SoftwareWithMSStore -SoftwareName $SoftwareName
    }
    "choco" {
        $success = Install-SoftwareWithChocolatey -SoftwareName $SoftwareName
    }
}

# Final status message
if ($success) {
    if ($PackageManager -eq "msstore") {
        Write-Log -Message "Microsoft Store was opened for '$SoftwareName'. Please complete installation through the Store interface." -Level 'Info'
    } else {
        Write-Log -Message "Installation process for '$SoftwareName' completed successfully." -Level 'Info'
    }
} else {
    Write-Log -Message "Installation process for '$SoftwareName' was not completed." -Level 'Error'
    Write-Log -Message "Please check the error messages above for more information." -Level 'Warning'
}

#endregion Main Script
