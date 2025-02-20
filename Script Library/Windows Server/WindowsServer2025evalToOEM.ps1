#Requires -Version 3
<#
.SYNOPSIS
    WindowsServer2025 Evaluation-to-OEM Conversion Script
    This script converts an evaluation system first to retail and then to OEM.
    It registers itself as a startup task so that after each reboot it can check
    the current edition and proceed with the next conversion step.
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
# Define the name of the scheduled task.
$taskName = "WindowsServer2025_ConversionTask"

function Add-StartupTask {
    $scriptPath = $MyInvocation.MyCommand.Path
    Write-Host "Adding startup task to run this script on boot..."
    schtasks.exe /Create /SC ONSTART /TN $taskName /TR "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" /F | Out-Null
}

function Remove-StartupTask {
    Write-Host "Removing startup task..."
    schtasks.exe /Delete /TN $taskName /F | Out-Null
}

# Retrieve the current Windows edition from the registry.
try {
    $osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
    $currentEdition = $osInfo.EditionID
    Write-Host "Current Edition: $currentEdition"
}
catch {
    Write-Error "Unable to retrieve OS edition. Exiting..."
    exit 1
}

if ($currentEdition -match "Eval") {
    Write-Host "Converting from Evaluation to Retail..."
    dism.exe /Online /Set-Edition:ServerRetail /AcceptEula
    Add-StartupTask
    Write-Host "Rebooting system to complete conversion..."
    Restart-Computer -Force
}
elseif ($currentEdition -match "Retail") {
    Write-Host "Converting from Retail to OEM..."
    dism.exe /Online /Set-Edition:ServerOEM /AcceptEula
    Add-StartupTask
    Write-Host "Rebooting system to complete conversion..."
    Restart-Computer -Force
}
elseif ($currentEdition -match "OEM") {
    Write-Host "Conversion process complete. The system is now OEM licensed."
    Remove-StartupTask
}
else {
    Write-Host "Unexpected edition encountered: $currentEdition. No conversion action performed."
}