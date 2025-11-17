<#
.SYNOPSIS
    Tests and displays security context information on local and remote computers.

.DESCRIPTION
    This script performs comprehensive security context analysis to help diagnose
    authentication and permission issues when running scripts against remote computers.
    It checks local security context, remote connectivity, and authentication flow
    to identify potential issues with network operations like file copying.
    
    The script provides detailed information about:
    - Current user identity and privileges
    - Process ownership and elevation status
    - Network authentication capabilities
    - Remote computer accessibility
    - File system permissions on network shares
    - Kerberos ticket information
    - Group memberships and security tokens

.PARAMETER ComputerName
    Specifies the target computer(s) to test security context against.
    Accepts a single computer name or an array of computer names.
    If not provided, only local security context will be analyzed.

.PARAMETER TestPaths
    Optional array of network paths to test access against.
    Useful for testing specific SCCM distribution points or file shares.
    
    Examples:
    - "\\server\share"
    - "\\scanz223\SMS_DDS\Client"
    - "\\slrcp223\SMS_PCI\Client"

.EXAMPLE
    .\Test-SecurityContext.ps1
    
    Analyzes local security context only.

.EXAMPLE
    .\Test-SecurityContext.ps1 -ComputerName "COMPUTER01"
    
    Tests security context against a single remote computer.

.EXAMPLE
    .\Test-SecurityContext.ps1 -ComputerName @("COMPUTER01", "COMPUTER02") -TestPaths @("\\scanz223\SMS_DDS\Client", "\\slrcp223\SMS_PCI\Client")
    
    Tests security context against multiple computers and specific network paths.

.NOTES
    Author: Matthew Wurtz
    Date: 17-Nov-25
    Version: 1.0
    
    Prerequisites:
    - Administrative privileges recommended for full analysis
    - PowerShell remoting enabled on target computers (if testing remote systems)
    - Network connectivity to target computers and test paths
    
    This script is designed to help diagnose issues with:
    - Copy-Item operations to network shares
    - PowerShell remoting authentication
    - Domain authentication and Kerberos tickets
    - Administrative access and privilege elevation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
    [Alias('Computer', 'Computers', 'CN')]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$TestPaths = @()
)

# -------------------- VARIABLES -------------------- #

# Create log file path on desktop with timestamp
$desktop = [Environment]::GetFolderPath('Desktop')
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $desktop "SecurityContext-$timestamp.log"

# -------------------- FUNCTIONS -------------------- #

<#
.SYNOPSIS
    Writes formatted log messages with timestamps and color coding.
#>
Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Default", "Info", "Warning", "Error", "Success", "Header")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes
    $prefix = switch ($Level) {
        "Default" { "[*]" }
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[!!!]" }
        "Success" { "[+]" }
        "Header"  { "[===]" }
    }
    
    # Build the log entry
    $logEntry = "[$timestamp] $prefix $Message"

    # Console output with colors
    switch ($Level) {
        "Default" { Write-Host $logEntry -ForegroundColor DarkGray }
        "Info"    { Write-Host $logEntry -ForegroundColor White }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Header"  { Write-Host $logEntry -ForegroundColor Cyan }
    }
    
    # Write to log file (without color codes)
    try {
        $logEntry | Out-File -FilePath $script:logFile -Append -Encoding UTF8
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

<#
.SYNOPSIS
    Analyzes local security context and user privileges.
#>
function Test-LocalSecurityContext {
    Write-LogMessage -Level Header -Message "LOCAL SECURITY CONTEXT ANALYSIS"
    Write-LogMessage -Level Header -Message "================================"
    
    try {
        # Get current Windows identity
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        Write-LogMessage -Level Info -Message "Current User: $($currentUser.Name)"
        Write-LogMessage -Level Info -Message "Authentication Type: $($currentUser.AuthenticationType)"
        Write-LogMessage -Level Info -Message "Is Authenticated: $($currentUser.IsAuthenticated)"
        Write-LogMessage -Level Info -Message "Is Anonymous: $($currentUser.IsAnonymous)"
        Write-LogMessage -Level Info -Message "Is Guest: $($currentUser.IsGuest)"
        Write-LogMessage -Level Info -Message "Is System: $($currentUser.IsSystem)"
        
        # Check elevation status
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-LogMessage -Level Info -Message "Is Elevated (Admin): $isElevated"
        
        # Get process information
        $process = Get-Process -Id $PID
        Write-LogMessage -Level Info -Message "Process ID: $PID"
        Write-LogMessage -Level Info -Message "Process Name: $($process.ProcessName)"
        
        # Get process owner
        try {
            $processOwner = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = $PID").GetOwner()
            if ($processOwner.Domain) {
                Write-LogMessage -Level Info -Message "Process Owner: $($processOwner.Domain)\$($processOwner.User)"
            } else {
                Write-LogMessage -Level Info -Message "Process Owner: $($processOwner.User)"
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Could not determine process owner: $_"
        }
        
        # Check security groups
        Write-LogMessage -Level Info -Message "Security Group Memberships:"
        $groups = $currentUser.Groups | ForEach-Object {
            try {
                $_.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $_.Value
            }
        }
        
        $importantGroups = $groups | Where-Object { 
            $_ -like "*Administrators*" -or 
            $_ -like "*Domain Admins*" -or 
            $_ -like "*Enterprise Admins*" -or
            $_ -like "*BUILTIN*" -or
            $_ -like "*Remote Desktop*" -or
            $_ -like "*Power Users*"
        }
        
        foreach ($group in $importantGroups) {
            Write-LogMessage -Level Success -Message "  - $group"
        }
        
        # Check user privileges
        Write-LogMessage -Level Info -Message "Current User Privileges:"
        try {
            $privileges = whoami /priv | Select-String "Se\w+" | ForEach-Object { $_.ToString().Trim() }
            $enabledPrivileges = $privileges | Where-Object { $_ -like "*Enabled*" }
            foreach ($priv in $enabledPrivileges) {
                Write-LogMessage -Level Success -Message "  - $priv"
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Could not enumerate privileges: $_"
        }
        
        return $true
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to analyze local security context: $_"
        return $false
    }
}

<#
.SYNOPSIS
    Tests network connectivity and authentication to remote computers.
#>
function Test-RemoteSecurityContext {
    param([string]$ComputerName)
    
    Write-LogMessage -Level Header -Message "REMOTE SECURITY CONTEXT: $ComputerName"
    Write-LogMessage -Level Header -Message "========================================"
    
    # Test basic network connectivity
    Write-LogMessage -Level Info -Message "Testing network connectivity..."
    try {
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
        if ($pingResult) {
            Write-LogMessage -Level Success -Message "Network connectivity: SUCCESS"
        } else {
            Write-LogMessage -Level Error -Message "Network connectivity: FAILED"
            return $false
        }
    } catch {
        Write-LogMessage -Level Error -Message "Network connectivity test failed: $_"
        return $false
    }
    
    # Test WMI connectivity
    Write-LogMessage -Level Info -Message "Testing WMI connectivity..."
    try {
        $wmiTest = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop
        Write-LogMessage -Level Success -Message "WMI connectivity: SUCCESS"
        Write-LogMessage -Level Info -Message "Remote OS: $($wmiTest.Caption) $($wmiTest.Version)"
    } catch {
        Write-LogMessage -Level Error -Message "WMI connectivity: FAILED - $_"
    }
    
    # Test PowerShell remoting
    Write-LogMessage -Level Info -Message "Testing PowerShell remoting..."
    try {
        $remotingTest = Invoke-Command -ComputerName $ComputerName -ScriptBlock { 
            $env:COMPUTERNAME 
        } -ErrorAction Stop
        Write-LogMessage -Level Success -Message "PowerShell remoting: SUCCESS"
        Write-LogMessage -Level Info -Message "Remote computer name: $remotingTest"
    } catch {
        Write-LogMessage -Level Error -Message "PowerShell remoting: FAILED - $_"
    }
    
    # Test administrative access
    Write-LogMessage -Level Info -Message "Testing administrative access..."
    try {
        $adminTest = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
            return @{
                UserName = $currentUser.Name
                IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                AuthType = $currentUser.AuthenticationType
            }
        } -ErrorAction Stop
        
        Write-LogMessage -Level Success -Message "Administrative access test: SUCCESS"
        Write-LogMessage -Level Info -Message "Remote identity: $($adminTest.UserName)"
        Write-LogMessage -Level Info -Message "Remote admin status: $($adminTest.IsAdmin)"
        Write-LogMessage -Level Info -Message "Remote auth type: $($adminTest.AuthType)"
    } catch {
        Write-LogMessage -Level Error -Message "Administrative access test: FAILED - $_"
    }
    
    # Test C$ administrative share permissions in detail
    Write-LogMessage -Level Info -Message "Testing C$ administrative share permissions..."
    Test-CSharePermissions -ComputerName $ComputerName
    
    return $true
}

<#
.SYNOPSIS
    Tests access to specific network paths.
#>
function Test-NetworkPathAccess {
    param([string[]]$Paths)
    
    if ($Paths.Count -eq 0) {
        return
    }
    
    Write-LogMessage -Level Header -Message "NETWORK PATH ACCESS TESTING"
    Write-LogMessage -Level Header -Message "============================"
    
    foreach ($path in $Paths) {
        Write-LogMessage -Level Info -Message "Testing path: $path"
        
        try {
            # Test basic path accessibility
            $pathExists = Test-Path $path -ErrorAction Stop
            if ($pathExists) {
                Write-LogMessage -Level Success -Message "  Path accessible: YES"
                
                # Try to list contents
                try {
                    $contents = Get-ChildItem $path -ErrorAction Stop | Select-Object -First 5
                    Write-LogMessage -Level Success -Message "  Contents readable: YES ($($contents.Count) items found)"
                    
                    # Show sample files
                    foreach ($item in $contents) {
                        Write-LogMessage -Level Info -Message "    - $($item.Name) ($($item.Length) bytes)"
                    }
                } catch {
                    Write-LogMessage -Level Warning -Message "  Contents readable: NO - $_"
                }
                
                # Test write access
                try {
                    $testFile = Join-Path $path "test_write_access.tmp"
                    "test" | Out-File -FilePath $testFile -ErrorAction Stop
                    Remove-Item $testFile -ErrorAction Stop
                    Write-LogMessage -Level Success -Message "  Write access: YES"
                } catch {
                    Write-LogMessage -Level Warning -Message "  Write access: NO - $_"
                }
                
            } else {
                Write-LogMessage -Level Error -Message "  Path accessible: NO"
            }
        } catch {
            Write-LogMessage -Level Error -Message "  Path test failed: $_"
        }
    }
}

<#
.SYNOPSIS
    Tests C$ administrative share permissions in detail including read/write access and write protection.
#>
function Test-CSharePermissions {
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    Write-LogMessage -Level Header -Message "C$ ADMINISTRATIVE SHARE PERMISSIONS: $ComputerName"
    Write-LogMessage -Level Header -Message "================================================"
    
    $adminSharePath = if ($ComputerName -eq $env:COMPUTERNAME) { "C:\" } else { "\\$ComputerName\c$" }
    
    try {
        # Test basic path accessibility
        Write-LogMessage -Level Info -Message "Testing basic access to: $adminSharePath"
        $pathExists = Test-Path $adminSharePath -ErrorAction Stop
        
        if (-not $pathExists) {
            Write-LogMessage -Level Error -Message "C$ administrative share is not accessible"
            return $false
        }
        
        Write-LogMessage -Level Success -Message "C$ administrative share is accessible"
        
        # Test read permissions
        Write-LogMessage -Level Info -Message "Testing read permissions..."
        try {
            $readTest = Get-ChildItem $adminSharePath -ErrorAction Stop | Select-Object -First 5
            Write-LogMessage -Level Success -Message "Read access: GRANTED (found $($readTest.Count) items)"
            
            # Show sample directory contents
            foreach ($item in $readTest) {
                $itemType = if ($item.PSIsContainer) { "Directory" } else { "File" }
                $size = if ($item.PSIsContainer) { "<DIR>" } else { "$($item.Length) bytes" }
                Write-LogMessage -Level Info -Message "  - [$itemType] $($item.Name) ($size)"
            }
        } catch {
            Write-LogMessage -Level Error -Message "Read access: DENIED - $_"
            return $false
        }
        
        # Test write permissions
        Write-LogMessage -Level Info -Message "Testing write permissions..."
        try {
            $testFileName = "PSSecurityTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"
            $testFilePath = Join-Path $adminSharePath $testFileName
            
            # Try to create a test file
            "Security context test file - $(Get-Date)" | Out-File -FilePath $testFilePath -ErrorAction Stop
            Write-LogMessage -Level Success -Message "Write access: GRANTED (test file created)"
            
            # Try to read the test file back
            $testContent = Get-Content $testFilePath -ErrorAction Stop
            Write-LogMessage -Level Success -Message "File read-back: SUCCESS"
            
            # Clean up test file
            Remove-Item $testFilePath -ErrorAction Stop
            Write-LogMessage -Level Success -Message "Test file cleanup: SUCCESS"
            
        } catch {
            Write-LogMessage -Level Error -Message "Write access: DENIED - $_"
            
            # Check if it's due to write protection
            if ($_.Exception.Message -match "readonly|write.*protect|access.*denied") {
                Write-LogMessage -Level Warning -Message "Drive may be write-protected or in read-only mode"
            }
        }
        
        # Test drive write protection status
        Write-LogMessage -Level Info -Message "Checking drive write protection status..."
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                # Local drive check
                $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
                $isReadOnly = $driveInfo.DriveType -eq 5 # CD-ROM drives are typically read-only
                
                if ($isReadOnly) {
                    Write-LogMessage -Level Warning -Message "Drive type indicates read-only media (DriveType: $($driveInfo.DriveType))"
                } else {
                    Write-LogMessage -Level Success -Message "Drive type allows read/write operations (DriveType: $($driveInfo.DriveType))"
                }
                
                Write-LogMessage -Level Info -Message "Drive details:"
                Write-LogMessage -Level Info -Message "  - File System: $($driveInfo.FileSystem)"
                Write-LogMessage -Level Info -Message "  - Size: $([math]::Round($driveInfo.Size/1GB, 2)) GB"
                Write-LogMessage -Level Info -Message "  - Free Space: $([math]::Round($driveInfo.FreeSpace/1GB, 2)) GB"
                Write-LogMessage -Level Info -Message "  - Volume Name: $($driveInfo.VolumeName)"
            } else {
                # Remote drive check via WMI
                $remoteDriveInfo = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
                
                if ($remoteDriveInfo.DriveType -eq 5) {
                    Write-LogMessage -Level Warning -Message "Remote drive type indicates read-only media"
                } else {
                    Write-LogMessage -Level Success -Message "Remote drive type allows read/write operations"
                }
                
                Write-LogMessage -Level Info -Message "Remote drive details:"
                Write-LogMessage -Level Info -Message "  - File System: $($remoteDriveInfo.FileSystem)"
                Write-LogMessage -Level Info -Message "  - Size: $([math]::Round($remoteDriveInfo.Size/1GB, 2)) GB"
                Write-LogMessage -Level Info -Message "  - Free Space: $([math]::Round($remoteDriveInfo.FreeSpace/1GB, 2)) GB"
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Could not determine drive write protection status: $_"
        }
        
        # Test specific directory permissions
        Write-LogMessage -Level Info -Message "Testing permissions on common system directories..."
        $testDirectories = @("Windows", "Program Files", "Users", "Temp")
        
        foreach ($dir in $testDirectories) {
            try {
                $dirPath = Join-Path $adminSharePath $dir
                if (Test-Path $dirPath) {
                    $dirContents = Get-ChildItem $dirPath -ErrorAction Stop | Select-Object -First 1
                    Write-LogMessage -Level Success -Message "  - $($dir): Read access OK"
                } else {
                    Write-LogMessage -Level Warning -Message "  - $($dir): Directory not found"
                }
            } catch {
                Write-LogMessage -Level Error -Message "  - $($dir): Access denied"
            }
        }
        
        # Get detailed ACL information if possible
        Write-LogMessage -Level Info -Message "Attempting to retrieve ACL information..."
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $acl = Get-Acl "C:\" -ErrorAction Stop
                Write-LogMessage -Level Success -Message "ACL retrieved successfully"
                Write-LogMessage -Level Info -Message "Owner: $($acl.Owner)"
                Write-LogMessage -Level Info -Message "Access rules count: $($acl.Access.Count)"
                
                # Show current user's effective rights
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $userRights = $acl.Access | Where-Object { $_.IdentityReference -like "*$($currentUser.Split('\\')[1])*" -or $_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "*Administrators*" }
                
                if ($userRights) {
                    Write-LogMessage -Level Info -Message "Relevant access rights:"
                    foreach ($right in $userRights) {
                        Write-LogMessage -Level Info -Message "  - $($right.IdentityReference): $($right.FileSystemRights) ($($right.AccessControlType))"
                    }
                }
            } else {
                Write-LogMessage -Level Info -Message "ACL check skipped for remote computer (requires different approach)"
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Could not retrieve ACL information: $_"
        }
        
        return $true
        
    } catch {
        Write-LogMessage -Level Error -Message "C$ permission test failed: $_"
        return $false
    }
}

<#
.SYNOPSIS
    Displays Kerberos ticket information for authentication troubleshooting.
#>
function Test-KerberosTickets {
    Write-LogMessage -Level Header -Message "KERBEROS TICKET ANALYSIS"
    Write-LogMessage -Level Header -Message "========================"
    
    try {
        # Run klist to show current tickets
        $klistOutput = & klist 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage -Level Success -Message "Kerberos tickets found:"
            
            # Parse and display relevant ticket information
            $ticketLines = $klistOutput | Where-Object { $_ -match "Server:|Client:|KerbTicket|Ticket Flags" }
            foreach ($line in $ticketLines) {
                Write-LogMessage -Level Info -Message "  $line"
            }
        } else {
            Write-LogMessage -Level Warning -Message "No Kerberos tickets found or klist failed"
        }
        
        # Try to get ticket granting ticket info
        try {
            $tgtOutput = & klist tgt 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage -Level Info -Message "Ticket Granting Ticket (TGT) information:"
                $tgtOutput | ForEach-Object {
                    if ($_ -match "Client:|Server:|KerbTicket|Start Time:|End Time:|Renew Time:") {
                        Write-LogMessage -Level Info -Message "  $_"
                    }
                }
            }
        } catch {
            Write-LogMessage -Level Warning -Message "Could not retrieve TGT information: $_"
        }
        
    } catch {
        Write-LogMessage -Level Warning -Message "Kerberos ticket analysis failed: $_"
    }
}

# -------------------- MAIN EXECUTION -------------------- #

# Initialize log file
Write-Host "Security Context Diagnostic Tool" -ForegroundColor Cyan
Write-Host "Log file: $logFile" -ForegroundColor Green
Write-Host ""

# Write initial log file header
"Security Context Diagnostic Tool" | Out-File -FilePath $logFile -Encoding UTF8
"=================================" | Out-File -FilePath $logFile -Append -Encoding UTF8
"Log started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $logFile -Append -Encoding UTF8
"" | Out-File -FilePath $logFile -Append -Encoding UTF8

Write-LogMessage -Level Header -Message "SECURITY CONTEXT DIAGNOSTIC TOOL"
Write-LogMessage -Level Header -Message "================================="
Write-LogMessage -Level Info -Message "Starting comprehensive security context analysis..."
Write-LogMessage -Level Info -Message "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-LogMessage -Level Info -Message "Log file location: $logFile"
Write-Host ""

# Test local security context
$localTestResult = Test-LocalSecurityContext
Write-Host ""

# Test local C$ permissions
Write-LogMessage -Level Info -Message "Testing local C$ drive permissions..."
$localCShareResult = Test-CSharePermissions
Write-Host ""

# Test Kerberos tickets
Test-KerberosTickets
Write-Host ""

# Test network paths if provided
if ($TestPaths.Count -gt 0) {
    Test-NetworkPathAccess -Paths $TestPaths
    Write-Host ""
}

# Test remote computers if provided
if ($ComputerName) {
    foreach ($computer in $ComputerName) {
        $remoteTestResult = Test-RemoteSecurityContext -ComputerName $computer
        Write-Host ""
    }
}

# Summary
Write-LogMessage -Level Header -Message "DIAGNOSTIC SUMMARY"
Write-LogMessage -Level Header -Message "=================="
Write-LogMessage -Level Info -Message "Local security context test: $(if($localTestResult){'PASSED'}else{'FAILED'})"
Write-LogMessage -Level Info -Message "Local C$ permissions test: $(if($localCShareResult){'PASSED'}else{'FAILED'})"

if ($ComputerName) {
    Write-LogMessage -Level Info -Message "Remote computers tested: $($ComputerName.Count)"
}

if ($TestPaths.Count -gt 0) {
    Write-LogMessage -Level Info -Message "Network paths tested: $($TestPaths.Count)"
}

Write-LogMessage -Level Success -Message "Security context analysis completed."
Write-LogMessage -Level Info -Message "Review the output above for any authentication or permission issues."
Write-LogMessage -Level Info -Message "Complete log saved to: $logFile"

# Write final timestamp to log file
"" | Out-File -FilePath $logFile -Append -Encoding UTF8
"Log completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $logFile -Append -Encoding UTF8

Write-Host ""
Write-Host "Complete diagnostic log saved to: $logFile" -ForegroundColor Green