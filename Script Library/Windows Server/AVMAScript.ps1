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
    The script supports Windows Server 2016, 2019, 2022 and 2025 Standard andDatacenter editions.
    Note: This script requires administrative privileges to install the AVMA key and activate Windows.
.PARAMETER <Parameter_Name>
    None
.INPUTS
    None
.OUTPUTS
    None
.NOTES
  Version:        1.0
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
    exit
}

# Retrieve OS information.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$caption = $osInfo.Caption
Write-Host "Detected OS: $caption"

# Determine the appropriate AVMA key based on the OS version and edition.
$avmaKey = $null
if ($caption -match "2016" -and $caption -match "Standard") {
    $avmaKey = "BCR9J-3M3YR-9WYR8-RKQBV-3VQ8B"
} elseif ($caption -match "2016" -and $caption -match "Datacenter") {
    $avmaKey = "TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J"
} elseif ($caption -match "2019" -and $caption -match "Standard") {
    $avmaKey = "N69G4-B89J2-4G8F4-WWYCC-J464C"
} elseif ($caption -match "2019" -and $caption -match "Datacenter") {
    $avmaKey = "WMDGN-G9PQG-XVVXX-R3X43-63DFG"
} elseif ($caption -match "2022" -and $caption -match "Standard") {
    $avmaKey = "N2KJX-J94YW-TQVFB-DG9YT-724CC"
} elseif ($caption -match "2022" -and $caption -match "Datacenter") {
    $avmaKey = "B69WH-PRNHK-BXVK3-P9XF7-XD84C"
} elseif ($caption -match "2025" -and $caption -match "Standard") {
    $avmaKey = "WWVGQ-PNHV9-B89P4-8GGM9-9HPQ4"
} elseif ($caption -match "2025" -and $caption -match "Datacenter") {
    $avmaKey = "YQB4H-NKHHJ-Q6K4R-4VMY6-VCH67"
} else {
    Write-Host "Unsupported Windows Server version or edition. Exiting."
    exit
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
} else {
    Write-Host "Activation failed. Please review the output above." -ForegroundColor Red
}