#Requires -Version 5
<#
.SYNOPSIS
    This script is used to activate virtual machines running on a Hyper-V host using the Automatic Virtual Machine Activation (AVMA) key.
    The AVMA key is used to activate virtual machines running on a Hyper-V host without the need for individual keys.
    For more information on AVMA, refer to: https://docs.microsoft.com/en-us/windows-server/get-started/avma-overview
    Supported Windows Server versions: 2016, 2019, 2022, 2025 Standard and Datacenter editions.
    Note: This script requires administrative privileges to install the AVMA key and activate Windows.
.DESCRIPTION
    This script automates the activation process for virtual machines running on a Hyper-V host using the Automatic Virtual Machine Activation (AVMA) key.
    The script first checks the Windows edition of the virtual machine and then installs the appropriate AVMA key to activate Windows.
    The AVMA key is specific to the Windows Server version and edition, and it is used to activate virtual machines running on a Hyper-V host without the need for individual keys.
    The script supports Windows Server 2016, 2019, 2022 and 2025 Standard and Datacenter editions.
    Note: This script requires administrative privileges to install the AVMA key and activate Windows.
.PARAMETER <Parameter_Name>
    None
.INPUTS
    None
.OUTPUTS
    None
.NOTES
  Version:        1.1
  Author:         Bendusz
  Creation Date:  19/02/2025
  Purpose/Change: Streamlining the activation process using AVMA key.
  
.EXAMPLE
    .\AVMAScript.ps1
    This command will run the script to activate Virtual Machine using AVMA key running on Windows Server Datacenter Edition.
#>

# Self-Elevation: Restart as administrator if not already elevated.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Not running as administrator. Restarting with elevated privileges..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Function to check activation status using slmgr.vbs /xpr.
function Get-ActivationStatus {
    $statusOutput = cscript.exe //nologo "$env:windir\system32\slmgr.vbs" /xpr | Out-String
    return $statusOutput
}

# Pre-check: If already activated, exit.
Write-Host "Checking current activation status..."
$initialStatus = Get-ActivationStatus
if ($initialStatus -match "activated") {
    Write-Host "System is already activated. Exiting." -ForegroundColor Green
    exit 0 # Exit code 0 for success (already activated)
}

# Retrieve OS information.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$caption = $osInfo.Caption
Write-Host "Detected OS: $caption"

# Determine the appropriate AVMA key based on the OS version and edition using a switch statement.
$avmaKey = $null
switch -Wildcard ($caption) {
    "*2016*Standard*"   { $avmaKey = "BCR9J-3M3YR-9WYR8-RKQBV-3VQ8B" }
    "*2016*Datacenter*" { $avmaKey = "TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J" }
    "*2019*Standard*"   { $avmaKey = "N69G4-B89J2-4G8F4-WWYCC-J464C" }
    "*2019*Datacenter*" { $avmaKey = "WMDGN-G9PQG-XVVXX-R3X43-63DFG" }
    "*2022*Standard*"   { $avmaKey = "N2KJX-J94YW-TQVFB-DG9YT-724CC" }
    "*2022*Datacenter*" { $avmaKey = "B69WH-PRNHK-BXVK3-P9XF7-XD84C" }
    "*2025*Standard*"   { $avmaKey = "WWVGQ-PNHV9-B89P4-8GGM9-9HPQ4" }
    "*2025*Datacenter*" { $avmaKey = "YQB4H-NKHHJ-Q6K4R-4VMY6-VCH67" }
    default {
        Write-Host "Unsupported Windows Server version or edition: $caption. Exiting." -ForegroundColor Yellow
        exit 1 # Exit code 1 for failure (unsupported OS)
    }
}

# Check if a key was found (though 'default' in switch should handle this)
if ($null -eq $avmaKey) {
    Write-Host "Could not determine AVMA key for OS: $caption. Exiting." -ForegroundColor Red
    exit 1 # Exit code 1 for failure (logic error or unexpected caption)
}

Write-Host "Using AVMA key: $avmaKey"

# Set the AVMA key.
Write-Host "Setting the product key..."
$setKeyResult = cscript.exe //nologo "$env:windir\system32\slmgr.vbs" /ipk $avmaKey | Out-String
Write-Host $setKeyResult

# Attempt activation.
Write-Host "Attempting activation..."
$activationResult = cscript.exe //nologo "$env:windir\system32\slmgr.vbs" /ato | Out-String
Write-Host $activationResult

# Final check to verify activation.
Write-Host "Verifying activation status..."
$finalStatus = Get-ActivationStatus
Write-Host $finalStatus

if ($finalStatus -match "activated") {
    Write-Host "Activation successful!" -ForegroundColor Green
    exit 0 # Exit code 0 for success
} else {
    Write-Host "Activation failed. Please review the output above." -ForegroundColor Red
    exit 1 # Exit code 1 for failure
}