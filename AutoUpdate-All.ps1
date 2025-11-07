<#
AutoUpdate-All.ps1

Purpose:
  - Run non-interactive, on-demand updates for applications and drivers on a Windows PC.
  - Use common package managers (winget, chocolatey, scoop) where available.
  - Run Windows Update (including drivers) via PSWindowsUpdate.
  - Attempt BIOS update if a vendor CLI/tool is present. If not present, the script logs vendor support URLs for manual action.

Notes / Safety:
  - The script requires Administrator privileges and will re-launch elevated if not run as admin.
  - It runs non-interactively and will accept package agreements where the package managers support the flags.
  - The script will perform an automatic reboot if updates require it (no input). Set the environment variable
    AUTOUPDATE_DISABLE_REBOOT=1 before running to prevent auto reboot.

Limitations:
  - There's no universal, safe way to download and flash BIOS across all vendors. This script only automates BIOS
    updates if the manufacturer's command-line tool is already installed on the system (example: Dell Command | Update).
  - For other vendors, the script will provide links and a short instruction so you can update manually.

Usage:
  - Run with Administrator privileges. E.g. right-click -> Run with PowerShell or just double-click the script.
  - The script runs with no interactive prompts.

#>

Set-StrictMode -Version Latest


# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "C:\Temp\AutoUpdate-All.log"
    
    # Update Settings
    WingetAcceptAgreements    = $true
    ChocolateyYesFlag         = $true
    ScoopUpdateAll            = $true
    PSModuleUpdateForce       = $true
    
    # Reboot Settings
    RebootDelaySeconds        = 60
    AutoRebootEnabled         = $true  # Can be overridden by AUTOUPDATE_DISABLE_REBOOT env var
}

# --------------- Script Variables --------------- #
$script:UpdateResults = @{
    WingetSuccess = $false
    ChocolateySuccess = $false
    ScoopSuccess = $false
    PSModulesSuccess = $false
    WindowsUpdateSuccess = $false
    RebootRequired = $false
}

$script:UpdateErrors = @()
$script:UpdateSummary = @()

# --------------- Helper Functions --------------- #

Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [string]$LogFile = $Config.LogFilePath 
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor White }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # File output
    if ($LogFile) {
        try {
            # Ensure log directory exists
            $logDir = Split-Path -Path $LogFile -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Ensure-RunningAsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-LogMessage -Level "Info" -Message "Not running as administrator — relaunching elevated..."
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Get-Process -Id $PID).Path
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $psi.Verb = "runas"
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            exit 0
        } catch {
            Write-LogMessage -Level "Error" -Message "Elevation cancelled or failed. Exiting. $_"
            exit 1
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
                $updateOutput = & winget upgrade --all --silent --accept-source-agreements --accept-package-agreements 2>&1
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
                $updateOutput = & choco upgrade all -y --no-progress 2>&1
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

function Update-Scoop {
    param([bool]$RunOnlyIfNeeded = $false)
    
    if ($RunOnlyIfNeeded) {
        Write-LogMessage -Level "Info" -Message "Previous package managers couldn't update everything, trying Scoop as final fallback..."
    }
    
    $scoopAvailable = $false
    $scoopUpdatedEverything = $false
    
    if (Test-Path "$env:USERPROFILE\scoop\shims\scoop.ps1" -PathType Leaf -ErrorAction SilentlyContinue -or (Get-Command scoop -ErrorAction SilentlyContinue)) {
        $scoopAvailable = $true
    } else {
        Write-LogMessage -Level "Info" -Message "Scoop not found. Attempting to install Scoop..."
        try {
            # Install Scoop using the official installation script
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Invoke-RestMethod get.scoop.sh | Invoke-Expression
            
            # Refresh environment variables and try again
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            # Check if scoop is now available
            if (Test-Path "$env:USERPROFILE\scoop\shims\scoop.ps1" -PathType Leaf -ErrorAction SilentlyContinue -or (Get-Command scoop -ErrorAction SilentlyContinue)) {
                $scoopAvailable = $true
                Write-LogMessage -Level "Success" -Message "Scoop installed successfully"
            } else {
                Write-LogMessage -Level "Warning" -Message "Scoop still not available after installation attempt"
                $script:UpdateSummary += "Scoop installation attempted but not available - skipped"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to install Scoop: $_"
            $script:UpdateSummary += "Scoop not available and installation failed - skipped"
            $script:UpdateErrors += "Scoop Installation: $_"
        }
    }
    
    if ($scoopAvailable) {
        Write-LogMessage -Level "Info" -Message "Checking for available Scoop updates..."
        try {
            # First, update scoop itself and check for outdated packages
            & scoop update 2>&1 | ForEach-Object { Write-LogMessage -Level "Info" -Message $_ }
            
            # Check what updates are available
            $statusOutput = & scoop status 2>$null
            $outdatedPackages = $statusOutput | Where-Object { $_ -match "outdated|newer version" -and $_ -notmatch "^Scoop" }
            
            if ($outdatedPackages -and $outdatedPackages.Count -gt 0) {
                Write-LogMessage -Level "Info" -Message "Found updates available through Scoop. Updating..."
                
                # Run the actual updates
                $updateOutput = & scoop update * 2>&1
                $updateOutput | ForEach-Object { Write-LogMessage -Level "Info" -Message $_ }
                
                # Check if all updates completed successfully
                $failedUpdates = $updateOutput | Where-Object { $_ -match "ERROR|WARN.*failed" }
                if (-not $failedUpdates) {
                    $scoopUpdatedEverything = $true
                    $script:UpdateResults.ScoopSuccess = $true
                    $script:UpdateSummary += "Scoop updates completed successfully - all packages updated"
                } else {
                    $script:UpdateResults.ScoopSuccess = $false
                    $script:UpdateSummary += "Scoop updates completed with some failures"
                    $script:UpdateErrors += "Scoop: Some updates failed"
                }
            } else {
                Write-LogMessage -Level "Info" -Message "No updates available through Scoop"
                $scoopUpdatedEverything = $true  # Nothing to update means "everything" is updated
                $script:UpdateResults.ScoopSuccess = $true
                $script:UpdateSummary += "Scoop: No updates needed"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "scoop update failed: $_"
            $script:UpdateErrors += "Scoop: $_"
            $script:UpdateResults.ScoopSuccess = $false
        }
    }
    
    return $scoopUpdatedEverything
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
                Update-Module -Name $m.Name -Force -ErrorAction Stop
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
    Ensure-RunningAsAdmin

    $startTime = Get-Date
    Write-LogMessage -Level "Info" -Message "AutoUpdate-All started at $startTime"

    # Update common package managers / apps (sequential fallback approach)
    Write-LogMessage -Level "Info" -Message "Starting package manager updates with sequential fallback approach..."
    
    # First try winget
    $wingetSuccess = Update-Winget
    
    # Only run Chocolatey if winget didn't update everything
    $chocoSuccess = $true  # Default to true so we don't run Scoop unnecessarily
    if (-not $wingetSuccess) {
        $chocoSuccess = Update-Choco -RunOnlyIfNeeded $true
    } else {
        Write-LogMessage -Level "Info" -Message "Winget updated everything successfully - skipping Chocolatey"
        $script:UpdateSummary += "Chocolatey: Skipped (winget handled all updates)"
    }
    
    # Only run Scoop if neither winget nor Chocolatey updated everything
    if (-not $wingetSuccess -and -not $chocoSuccess) {
        $scoopSuccess = Update-Scoop -RunOnlyIfNeeded $true
        if (-not $scoopSuccess) {
            Write-LogMessage -Level "Warning" -Message "All package managers had issues - some packages may not be updated"
        }
    } else {
        Write-LogMessage -Level "Info" -Message "Previous package managers handled all updates - skipping Scoop"
        $script:UpdateSummary += "Scoop: Skipped (previous package managers handled all updates)"
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
