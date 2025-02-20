#Requires -Version 3
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
  Version:        1.0
  Author:         Bendusz
  Creation Date:  19/02/2025
  Purpose/Change: Convert Windows Server 2025 Evaluation to OEM.
  
.EXAMPLE
    .\WindowsServer2025evalToOEM.ps1
#>

#--------[Script]---------------
# Retrieve the current Windows edition from the registry.
$licensekey = ""
$currentEdition = ""

function Convert-Edition {
    param (
        [string]$licensekey,
        [string]$serverEdition

    )
    Write-Host "Setting product key..." -ForegroundColor Yellow

    dism.exe /Online /Set-Edition:$serverEdition /ProductKey:$licensekey /AcceptEula
    Write-Host "Please wait for the conversion to complete..." -ForegroundColor Yellow

    Start-Sleep -Seconds 5

    Write-Host "Rebooting system to complete conversion..." -ForegroundColor Green
    Restart-Computer -Force
    
}

function Ask-ProductKey {

        Write-Host "Please enter the 25-character OEM product key:" -ForegroundColor Yellow
        Write-Host "Example: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" -ForegroundColor Yellow
        $licensekey = Read-Host "Enter product key:"
        if ($licensekey -match "\s") {
            Write-Host "White spaces detected in product key, removing them..." -ForegroundColor Yellow
            $licensekey = $licensekey -replace "\s", ""
            Write-Host "Product key without spaces: $licensekey" -ForegroundColor Cyan
        }
        if ($licensekey -notmatch '^(?i)(?:[A-Z0-9]{5}-){4}[A-Z0-9]{5}$') {
            Write-Host "Invalid product key format. Please enter 25 alphanumeric characters (with dashes, e.g. XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)." -ForegroundColor Red
            return $false
        } else {
            Write-Host "Product key format is valid." -ForegroundColor Green
        }
        Write-Host "Product key entered: $licensekey" -ForegroundColor Cyan
        $ok = Read-Host "Is this correct? (Y/N)"

        if ($ok -eq "Y" -or $ok -eq "y") {
            return $true
        } else {
            return $false
        }
}

try {
    Write-Host "Retrieving OS edition..." -ForegroundColor Yellow
    $osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
    $currentEdition = $osInfo.EditionID
    Write-Host "Current Edition: $currentEdition" -ForegroundColor Cyan
}
catch {
    Write-Error "Unable to retrieve OS edition. Exiting..."
    Read-Host "Press Enter to exit."
    exit 1
}

if ($currentEdition -match "Eval") {
    Write-Host "Current edition is Evaluation." -ForegroundColor Cyan
    Write-Host "Converting from Evaluation to Retail..." -ForegroundColor Yellow
    $selection = Read-Host "Do you want to convert to Standard or Datacenter edition? (S/D)"
    if ($selection -eq "S" -or $selection -eq "s") {
        Write-Host "Converting to Standard edition..." -ForegroundColor Yellow
        $licensekey = "TVRH6-WHNXV-R9WG3-9XRFY-MY832"
        Convert-Edition -licensekey $licensekey -serverEdition ServerStandard
    }
    elseif ($selection -eq "D" -or $selection -eq "d") {
        Write-Host "Converting to Datacenter edition..." -ForegroundColor Yellow
        $licensekey = "D764K-2NDRG-47T6Q-P8T8W-YP6DF"
        Convert-Edition -licensekey $licensekey -serverEdition ServerDatacenter
    }
    else {
        Write-Host "Invalid selection. Exiting..."
        Read-Host "Press Enter to exit and try again."
        exit 1
    }
} elseif ($currentEdition -eq "ServerStandard" -or $currentEdition -eq "ServerDatacenter") {
    Write-Host "Current edition is Retail." -ForegroundColor Cyan
    Write-Host "Converting from Retail to OEM..." -ForegroundColor Yellow
    do {
        $go = Ask-ProductKey
    } while (!$go)
    Convert-Edition -licensekey $licensekey -serverEdition $currentEdition
} else {
    Write-Host "Unexpected edition encountered: $currentEdition. No conversion action performed."
}