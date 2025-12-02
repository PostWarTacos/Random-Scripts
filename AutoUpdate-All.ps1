<#
.SYNOPSIS
    Automated system updater for Windows using package managers and Windows Update.

.DESCRIPTION
    Non-interactive script that updates applications, PowerShell modules, and Windows.
    Uses winget (primary) and chocolatey (fallback) package managers.
    Requires Administrator privileges.

.NOTES
    Author: PostWarTacos
    Runs non-interactively with automatic package agreement acceptance.
    Prompts for reboot if updates require it.
#>

#Requires -Version 5.0
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "C:\Temp\AutoUpdate-All.log"
    
    # Update Settings
    WingetAcceptAgreements    = $true
    ChocolateyYesFlag         = $true
    PSModuleUpdateForce       = $true
    
    # Reboot Settings
    RebootDelaySeconds        = 60
    AutoRebootEnabled         = $true  # Can be overridden by AUTOUPDATE_DISABLE_REBOOT env var
}

# --------------- Script Variables --------------- #
$script:UpdateResults = @{
    WingetSuccess = $false
    ChocolateySuccess = $false
    PSModulesSuccess = $false
    WindowsUpdateSuccess = $false
    RebootRequired = $false
}

$script:UpdateErrors = @()
$script:UpdateSummary = @()

# --------------- Helper Functions --------------- #

<#
.SYNOPSIS
    Writes formatted log messages with timestamps and color coding.
    
.DESCRIPTION
    Provides standardized logging output with different severity levels.
    Each message includes timestamp, level indicator, and appropriate console coloring.
    
.PARAMETER Level
    Severity level: Info, Warning, Error, or Success
    
.PARAMETER Message
    The message text to display and log
#>
Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Default")]
        [string]$Level,
        [string]$LogFile = $Config.LogFilePath
    )
    
    # Generate timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes for visual identification    
    if ($Level) {
        $prefix = switch ($Level) {
            "Info"    { "[*]" }     # Informational messages
            "Warning" { "[!]" }     # Warning messages  
            "Error"   { "[!!!]" }   # Error messages
            "Success" { "[+]" }     # Success messages
        }
    }
    else {
        $prefix = "[*]" # Default prefix for unspecified level
        $Level = "Default"
    }

    
    $logEntry = "[$timestamp] $prefix $Message"

    # Display console output with appropriate colors for each level (only when running interactively)
    switch ($Level) {
        "Default" { Write-Host $logEntry -ForegroundColor DarkGray }
        "Info"    { Write-Host $logEntry -ForegroundColor White }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Write to log file if specified
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -ErrorAction Stop
        } catch {
            # Use Write-Warning to avoid recursion when logging fails
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Run-IfExists {
    param(
        [string]$Command,
        [string[]]$Arguments = @(),
        [switch]$ContinueOnError
    )
    $exe = Get-Command $Command -ErrorAction SilentlyContinue
    if ($null -eq $exe) { return $false }
    Write-LogMessage -Level "Info" -Message "Running: $Command $($Arguments -join ' ')"
    try {
        & $Command @Arguments 2>&1 | ForEach-Object { Write-LogMessage -Level "Info" -Message $_ }
        return $true
    } catch {
        Write-LogMessage -Level "Warning" -Message "Command $Command failed: $_"
        if (-not $ContinueOnError) { throw $_ }
        return $false
    }
}

function Update-Winget {
    $wingetAvailable = $false
    $wingetUpdatedEverything = $false
    
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $wingetAvailable = $true
    } else {
        Write-LogMessage -Level "Info" -Message "winget not found. Attempting to install App Installer (includes winget)..."
        try {
            # Try to install App Installer from Microsoft Store
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
            Write-LogMessage -Level "Success" -Message "App Installer installed successfully"
            
            # Check if winget is now available
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                $wingetAvailable = $true
            } else {
                Write-LogMessage -Level "Warning" -Message "winget still not available after App Installer installation"
                $script:UpdateSummary += "Winget installation attempted but not available - skipped"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to install App Installer: $_"
            $script:UpdateSummary += "Winget not available and installation failed - skipped"
            $script:UpdateErrors += "Winget Installation: $_"
        }
    }
    
    if ($wingetAvailable) {
        Write-LogMessage -Level "Info" -Message "Checking for available winget updates..."
        try {
            # Check what updates are available
            $availableUpdates = & winget upgrade --accept-source-agreements 2>$null | Where-Object { $_ -match "^\S" -and $_ -notmatch "^Name|^-|^No applicable" }
            
            if ($availableUpdates -and $availableUpdates.Count -gt 0) {
                Write-LogMessage -Level "Info" -Message "Found $($availableUpdates.Count) updates available through winget. Updating..."
                
                # Run the actual updates
                $args = @('upgrade', '--all', '--silent')
                if ($Config.WingetAcceptAgreements) {
                    $args += @('--accept-source-agreements', '--accept-package-agreements')
                }
                $updateOutput = & winget @args 2>&1
                $updateOutput | ForEach-Object { Write-LogMessage -Level "Info" -Message $_ }
                
                # Check if all updates completed successfully
                $failedUpdates = $updateOutput | Where-Object { $_ -match "Failed|Error" }
                if (-not $failedUpdates) {
                    $wingetUpdatedEverything = $true
                    $script:UpdateResults.WingetSuccess = $true
                    $script:UpdateSummary += "Winget updates completed successfully - all packages updated"
                } else {
                    $script:UpdateResults.WingetSuccess = $false
                    $script:UpdateSummary += "Winget updates completed with some failures"
                    $script:UpdateErrors += "Winget: Some updates failed"
                }
            } else {
                Write-LogMessage -Level "Info" -Message "No updates available through winget"
                $wingetUpdatedEverything = $true  # Nothing to update means "everything" is updated
                $script:UpdateResults.WingetSuccess = $true
                $script:UpdateSummary += "Winget: No updates needed"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "winget upgrade encountered an error: $_"
            $script:UpdateErrors += "Winget: $_"
            $script:UpdateResults.WingetSuccess = $false
        }
    }
    
    return $wingetUpdatedEverything
}

function Update-Choco {
    param([bool]$RunOnlyIfNeeded = $false)
    
    if ($RunOnlyIfNeeded) {
        Write-LogMessage -Level "Info" -Message "Winget couldn't update everything, trying Chocolatey as fallback..."
    }
    
    $chocoAvailable = $false
    $chocoUpdatedEverything = $false
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $chocoAvailable = $true
    } else {
        Write-LogMessage -Level "Info" -Message "Chocolatey not found. Attempting to install Chocolatey..."
        try {
            # Install Chocolatey using the official installation script
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            # Check if choco is now available
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                $chocoAvailable = $true
                Write-LogMessage -Level "Success" -Message "Chocolatey installed successfully"
            } else {
                Write-LogMessage -Level "Warning" -Message "Chocolatey still not available after installation attempt"
                $script:UpdateSummary += "Chocolatey installation attempted but not available - skipped"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to install Chocolatey: $_"
            $script:UpdateSummary += "Chocolatey not available and installation failed - skipped"
            $script:UpdateErrors += "Chocolatey Installation: $_"
        }
    }
    
    if ($chocoAvailable) {
        Write-LogMessage -Level "Info" -Message "Checking for available Chocolatey updates..."
        try {
            # Check what updates are available
            $outdatedOutput = & choco outdated --limit-output 2>$null
            $outdatedPackages = $outdatedOutput | Where-Object { $_ -and $_ -notmatch "^Chocolatey" }
            
            if ($outdatedPackages -and $outdatedPackages.Count -gt 0) {
                Write-LogMessage -Level "Info" -Message "Found $($outdatedPackages.Count) packages to update with Chocolatey. Updating..."
                
                # Run the actual updates
                $args = @('upgrade', 'all', '--no-progress')
                if ($Config.ChocolateyYesFlag) {
                    $args += '-y'
                }
                $updateOutput = & choco @args 2>&1
                $updateOutput | ForEach-Object { Write-LogMessage -Level "Info" -Message $_ }
                
                # Check if all updates completed successfully
                $failedUpdates = $updateOutput | Where-Object { $_ -match "Failures|ERROR" }
                if (-not $failedUpdates) {
                    $chocoUpdatedEverything = $true
                    $script:UpdateResults.ChocolateySuccess = $true
                    $script:UpdateSummary += "Chocolatey updates completed successfully - all packages updated"
                } else {
                    $script:UpdateResults.ChocolateySuccess = $false
                    $script:UpdateSummary += "Chocolatey updates completed with some failures"
                    $script:UpdateErrors += "Chocolatey: Some updates failed"
                }
            } else {
                Write-LogMessage -Level "Info" -Message "No updates available through Chocolatey"
                $chocoUpdatedEverything = $true  # Nothing to update means "everything" is updated
                $script:UpdateResults.ChocolateySuccess = $true
                $script:UpdateSummary += "Chocolatey: No updates needed"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "choco upgrade failed: $_"
            $script:UpdateErrors += "Chocolatey: $_"
            $script:UpdateResults.ChocolateySuccess = $false
        }
    }
    
    return $chocoUpdatedEverything
}

function Update-PowerShellModules {
    Write-LogMessage -Level "Info" -Message "Updating installed PowerShell modules from PSGallery where possible..."
    try {
        if (-not (Get-Module -ListAvailable -Name PowerShellGet)) {
            Install-Module PowerShellGet -Force -Scope AllUsers -AllowClobber -ErrorAction SilentlyContinue
        }
        $modules = Get-InstalledModule -ErrorAction SilentlyContinue
        $updatedCount = 0
        foreach ($m in $modules) {
            try {
                Write-LogMessage -Level "Info" -Message "Updating module $($m.Name)"
                $updateArgs = @{
                    Name = $m.Name
                    ErrorAction = 'Stop'
                }
                if ($Config.PSModuleUpdateForce) {
                    $updateArgs['Force'] = $true
                }
                Update-Module @updateArgs
                $updatedCount++
            } catch {
                Write-LogMessage -Level "Warning" -Message "Could not update module $($m.Name): $_"
                $script:UpdateErrors += "PowerShell Module ($($m.Name)): $_"
            }
        }
        $script:UpdateResults.PSModulesSuccess = $true
        $script:UpdateSummary += "PowerShell modules: $updatedCount modules processed"
    } catch {
        Write-LogMessage -Level "Warning" -Message "PowerShell module update step failed: $_"
        $script:UpdateErrors += "PowerShell Modules: $_"
    }
}

function Install-And-Run-PSWindowsUpdate {
    Write-LogMessage -Level "Info" -Message "Ensuring PSWindowsUpdate module is installed..."
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to install or import PSWindowsUpdate: $_"
        $script:UpdateErrors += "PSWindowsUpdate Installation: $_"
        return $false
    }

    $driverUpdatesFound = $false
    
    # Run Windows Update including Microsoft Update (optional updates and drivers)
    try {
        Write-LogMessage -Level "Info" -Message "Running Windows Update (includes Microsoft Update catalog). This may take a long time..."
        # Install all available updates and include Microsoft Update catalog (3rd party driver updates).
        # IgnoreReboot so we can detect and reboot in our own controlled way below.
        $updates = Install-WindowsUpdate -AcceptAll -MicrosoftUpdate -IgnoreReboot -Verbose -ErrorAction Stop
        $updates | ForEach-Object { Write-LogMessage -Level "Info" -Message "Installed: $($_.Title)" }

        # Additionally try to install driver category specifically (some systems need explicit category)
        try {
            Write-LogMessage -Level "Info" -Message "Installing available Driver updates (category filter)..."
            $drv = Get-WindowsUpdate -Category Drivers -MicrosoftUpdate -AcceptALL -Verbose -ErrorAction SilentlyContinue
            if ($drv -and $drv.Count -gt 0) {
                $driverUpdates = Install-WindowsUpdate -Category Drivers -AcceptAll -MicrosoftUpdate -IgnoreReboot -Verbose
                $driverUpdates | ForEach-Object { Write-LogMessage -Level "Info" -Message "Driver installed: $($_.Title)" }
                $driverUpdatesFound = $true
                Write-LogMessage -Level "Success" -Message "Found and installed $($driverUpdates.Count) driver updates through Windows Update"
            } else {
                Write-LogMessage -Level "Info" -Message "No driver updates found through Windows Update"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "Driver-specific update attempt failed: $_"
            $script:UpdateErrors += "Driver Updates: $_"
        }
        
        $script:UpdateResults.WindowsUpdateSuccess = $true
        $script:UpdateSummary += "Windows Update completed successfully"
    } catch {
        Write-LogMessage -Level "Warning" -Message "Windows Update step failed: $_"
        $script:UpdateErrors += "Windows Update: $_"
    }
    
    return $driverUpdatesFound
}

function Test-PendingReboot {
    # Check common registry locations and pending file rename operations
    $pending = $false
    try {
        $cbs = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' -Name RebootInProgress -ErrorAction SilentlyContinue
        if ($cbs.RebootInProgress -eq 1) { $pending = $true }
    } catch {}
    try {
        $wu = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' -Name RebootRequired -ErrorAction SilentlyContinue
        if ($wu.RebootRequired) { $pending = $true }
    } catch {}
    try {
        $session = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($session.PendingFileRenameOperations) { $pending = $true }
    } catch {}
    return $pending
}

function Main {
    $startTime = Get-Date
    Write-LogMessage -Level "Info" -Message "AutoUpdate-All started at $startTime"

    # Update common package managers / apps (sequential fallback approach)
    Write-LogMessage -Level "Info" -Message "Starting package manager updates with sequential fallback approach..."
    
    # First try winget
    $wingetSuccess = Update-Winget
    
    # Only run Chocolatey if winget didn't update everything
    if (-not $wingetSuccess) {
        $chocoSuccess = Update-Choco -RunOnlyIfNeeded $true
        if (-not $chocoSuccess) {
            Write-LogMessage -Level "Warning" -Message "Both package managers had issues - some packages may not be updated"
        }
    } else {
        Write-LogMessage -Level "Info" -Message "Winget updated everything successfully - skipping Chocolatey"
        $script:UpdateSummary += "Chocolatey: Skipped (winget handled all updates)"
    }
    
    # Always update PowerShell modules (separate from package managers)
    Update-PowerShellModules

    # Windows Update & drivers
    Install-And-Run-PSWindowsUpdate

    # Generate summary report
    Write-LogMessage -Level "Success" -Message "=== UPDATE SUMMARY ==="
    foreach ($summary in $script:UpdateSummary) {
        Write-LogMessage -Level "Info" -Message "  $summary"
    }
    
    if ($script:UpdateErrors.Count -gt 0) {
        Write-LogMessage -Level "Warning" -Message "=== ERRORS ENCOUNTERED ==="
        foreach ($errorMsg in $script:UpdateErrors) {
            Write-LogMessage -Level "Error" -Message "  $errorMsg"
        }
    }

    # Post-check: pending reboot?
    $script:UpdateResults.RebootRequired = Test-PendingReboot
    if ($script:UpdateResults.RebootRequired) {
        Write-LogMessage -Level "Warning" -Message "A reboot is required to finish updates."
        
        # Show popup dialog asking user to reboot now or later
        Add-Type -AssemblyName PresentationFramework
        $result = [System.Windows.MessageBox]::Show(
            "Updates have been installed and require a restart to complete.`n`nWould you like to restart now?", 
            "Restart Required - AutoUpdate-All", 
            [System.Windows.MessageBoxButton]::YesNo, 
            [System.Windows.MessageBoxImage]::Question
        )
        
        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            Write-LogMessage -Level "Info" -Message "User chose to restart now. Restarting computer..."
            Restart-Computer -Force
        } else {
            Write-LogMessage -Level "Info" -Message "User chose to restart later. Please restart when convenient to complete the updates."
        }
    } else {
        Write-LogMessage -Level "Success" -Message "No reboot required."
    }

    $endTime = Get-Date
    $duration = [int](($endTime - $startTime).TotalMinutes)
    Write-LogMessage -Level "Success" -Message "AutoUpdate-All completed at $endTime (Duration: $duration minutes)"
}

try {
    Main
} catch {
    Write-LogMessage -Level "Error" -Message "Unhandled error: $_"
    exit 2
}
