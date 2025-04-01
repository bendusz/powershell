#Requires -Version 5
<#
.SYNOPSIS
    WindowsServer2025 Evaluation-to-OEM Conversion Script
    This script converts an evaluation system first to retail and then to OEM.
.DESCRIPTION
    Documentation: https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-conversion-options
.PARAMETER <Parameter_Name>
    None
.INPUTS
    None
.OUTPUTS
    Confirmation messages and errors.
.NOTES
  Version:        1.1
  Author:         Bendusz
  Creation Date:  19/02/2025
  Purpose/Change: Convert Windows Server 2025 Evaluation to OEM.
  
.EXAMPLE
    .\WindowsServer2025evalToOEM.ps1
#>

#--------[Script]---------------

function Convert-Edition {
    param (
        [Parameter(Mandatory=$true)]
        [string]$licensekey,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("ServerStandard", "ServerDatacenter")]
        [string]$serverEdition
    )
    
    Write-Host "Setting product key for $serverEdition..." -ForegroundColor Yellow

    try {
        $dismResult = dism.exe /Online /Set-Edition:$serverEdition /ProductKey:$licensekey /AcceptEula
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "DISM command failed with exit code $LASTEXITCODE" -ForegroundColor Red
            Write-Host $dismResult -ForegroundColor Red
            return $false
        }
        
        Write-Host "Please wait for the conversion to complete..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5

        Write-Host "Conversion successful. System needs to restart to complete the process." -ForegroundColor Green
        $restart = Read-Host "Restart now? (Y/N, default is Y)"
        
        if ($restart -eq "" -or $restart -eq "Y" -or $restart -eq "y") {
            Write-Host "Rebooting system in 10 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        } else {
            Write-Host "Please restart your system manually to complete the conversion." -ForegroundColor Yellow
        }
        
        return $true
    }
    catch {
        Write-Host "Error occurred during conversion: $_" -ForegroundColor Red
        return $false
    }
}

function Test-ProductKey {
    param (
        [string]$key
    )
    
    # Remove any spaces or dashes for consistency
    $cleanKey = $key -replace "[-\s]", ""
    
    # Check if the key is 25 characters
    if ($cleanKey.Length -ne 25) {
        Write-Host "Invalid product key length. Key must be 25 characters without spaces or dashes." -ForegroundColor Red
        return $null
    }
    
    # Check if key contains only alphanumeric characters
    if ($cleanKey -notmatch '^[A-Za-z0-9]{25}$') {
        Write-Host "Invalid product key. Key must contain only letters and numbers." -ForegroundColor Red
        return $null
    }
    
    # Format the key with dashes for display and DISM
    $formattedKey = $cleanKey.Substring(0,5) + "-" + 
                    $cleanKey.Substring(5,5) + "-" + 
                    $cleanKey.Substring(10,5) + "-" + 
                    $cleanKey.Substring(15,5) + "-" + 
                    $cleanKey.Substring(20,5)
    
    return $formattedKey
}

function Get-ProductKeyFromUser {
    $attempts = 0
    $maxAttempts = 3
    
    while ($attempts -lt $maxAttempts) {
        Write-Host "Please enter the 25-character OEM product key:" -ForegroundColor Yellow
        Write-Host "Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (or without dashes)" -ForegroundColor Yellow
        
        $inputKey = Read-Host "Enter product key"
        $formattedKey = Test-ProductKey -key $inputKey
        
        if ($null -ne $formattedKey) {
            Write-Host "Product key entered: $formattedKey" -ForegroundColor Cyan
            $confirm = Read-Host "Is this correct? (Y/N)"
            
            if ($confirm -eq "Y" -or $confirm -eq "y") {
                return $formattedKey
            }
        }
        
        $attempts++
        if ($attempts -lt $maxAttempts) {
            Write-Host "Let's try again. ($($maxAttempts - $attempts) attempts remaining)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "Maximum attempts reached. Exiting..." -ForegroundColor Red
    return $null
}

function Get-CurrentWindowsEdition {
    try {
        $osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        $currentEdition = $osInfo.EditionID
        Write-Host "Current Edition: $currentEdition" -ForegroundColor Cyan
        return $currentEdition
    }
    catch {
        Write-Error "Unable to retrieve OS edition: $_"
        return $null
    }
}

# Main script

# Define retail keys in a hashtable for better maintainability
$retailKeys = @{
    "ServerStandard" = "TVRH6-WHNXV-R9WG3-9XRFY-MY832"
    "ServerDatacenter" = "D764K-2NDRG-47T6Q-P8T8W-YP6DF"
}

# Get current Windows edition
$currentEdition = Get-CurrentWindowsEdition
if ($null -eq $currentEdition) {
    Read-Host "Press Enter to exit"
    exit 1
}

# Process based on current edition
if ($currentEdition -match "Eval") {
    Write-Host "Current edition is Evaluation." -ForegroundColor Cyan
    Write-Host "Converting from Evaluation to Retail..." -ForegroundColor Yellow
    
    $selection = Read-Host "Do you want to convert to Standard or Datacenter edition? (S/D)"
    
    if ($selection -eq "S" -or $selection -eq "s") {
        $targetEdition = "ServerStandard"
        Write-Host "Converting to Standard edition..." -ForegroundColor Yellow
    }
    elseif ($selection -eq "D" -or $selection -eq "d") {
        $targetEdition = "ServerDatacenter"
        Write-Host "Converting to Datacenter edition..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Invalid selection. Exiting..." -ForegroundColor Red
        Read-Host "Press Enter to exit and try again"
        exit 1
    }
    
    $success = Convert-Edition -licensekey $retailKeys[$targetEdition] -serverEdition $targetEdition
    
    if (-not $success) {
        Write-Host "Conversion failed. Please check the error messages above." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} 
elseif ($currentEdition -eq "ServerStandard" -or $currentEdition -eq "ServerDatacenter") {
    Write-Host "Current edition is Retail." -ForegroundColor Cyan
    Write-Host "Converting from Retail to OEM..." -ForegroundColor Yellow
    
    $oemKey = Get-ProductKeyFromUser
    
    if ($null -eq $oemKey) {
        Write-Host "No valid product key provided. Exiting..." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    $success = Convert-Edition -licensekey $oemKey -serverEdition $currentEdition
    
    if (-not $success) {
        Write-Host "Conversion failed. Please check the error messages above." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} 
else {
    Write-Host "Unexpected edition encountered: $currentEdition. No conversion action performed." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}