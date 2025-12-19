<#
.SYNOPSIS
    Comprehensive computer inventory and health check script with CSV export.

.DESCRIPTION
    Combines connectivity testing, hardware inventory, OS details, network configuration,
    and Active Directory information. Outputs structured PSObjects for easy CSV export.

.PARAMETER ComputerListPath
    Path to text file containing computer names (one per line).

.PARAMETER OutputPath
    Directory where output CSV will be saved. Defaults to user's Desktop.

.PARAMETER IncludeShares
    Switch to include network share enumeration in the output.

.PARAMETER IncludeADInfo
    Switch to include Active Directory last logon information.

.EXAMPLE
    .\Get-ComputerInventory.ps1 -ComputerListPath "C:\computers.txt" -OutputPath "C:\Reports"

.EXAMPLE
    .\Get-ComputerInventory.ps1 -ComputerListPath "C:\computers.txt" -IncludeShares -IncludeADInfo | Export-Csv "C:\inventory.csv" -NoTypeInformation

.NOTES
    Author: Matthew T Wurtz
    Date: December 19, 2025
    Version: 2.0 (Combined from Test-ComputerHealth.ps1 and ComputerList.ps1)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$ComputerListPath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeShares,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeADInfo
)

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvFile = Join-Path $OutputPath "ComputerInventory_$timestamp.csv"

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Function to write log messages with timestamp and color coding
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)]
        [string]$Message,
        [Parameter(Position=1)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Default")]
        [string]$Level = "Info",
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LogFile
    )
    
    # Generate timestamp for log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes for visual identification
    $prefix = switch ($Level) {
        "Info"    { "[*]" }     # Informational messages
        "Warning" { "[!]" }     # Warning messages  
        "Error"   { "[!!!]" }   # Error messages
        "Success" { "[+]" }     # Success messages
        "Default" { "[*]" }     # Default prefix
    }
    
    $logEntry = "[$timestamp] $prefix $Message"

    # Display console output with appropriate colors
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
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

# Function to get network share information
function Get-SharesInfo {
    param([string]$ComputerName)
    
    try {
        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
            $shares = Get-SmbShare -CimSession $ComputerName -ErrorAction Stop | 
                Where-Object { $_.Name -notmatch '^(IPC\$|ADMIN\$|[A-Z]\$)$' }
            return ($shares | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join "; "
        } else {
            $shares = Get-CimInstance -ClassName Win32_Share -ComputerName $ComputerName -ErrorAction Stop |
                Where-Object { $_.Name -notmatch '^(IPC\$|ADMIN\$|[A-Z]\$)$' }
            return ($shares | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join "; "
        }
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

# Function to get AD last logon
function Get-ADLastLogon {
    param([string]$ComputerName)
    
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $computer = Get-ADComputer -Identity $ComputerName -Properties LastLogonTimeStamp -ErrorAction Stop
            if ($computer.LastLogonTimeStamp) {
                return [DateTime]::FromFileTime($computer.LastLogonTimeStamp)
            } else {
                return "Never"
            }
        } else {
            # Fallback to ADSI
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(name=$ComputerName))"
            $searcher.PropertiesToLoad.Add("lastLogonTimeStamp") | Out-Null
            
            $result = $searcher.FindOne()
            if ($result -and $result.Properties["lastLogonTimeStamp"][0]) {
                return [DateTime]::FromFileTime($result.Properties["lastLogonTimeStamp"][0])
            } else {
                return "Never"
            }
        }
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

# Function to get currently logged on user (active session only)
function Get-CurrentUser {
    param([string]$ComputerName)
    
    try {
        # Try using Get-CimInstance for logged on user
        $loggedOnUser = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
        
        if ($loggedOnUser.UserName) {
            $username = $loggedOnUser.UserName.Split('\\')[-1]
            
            # Try to get AD user info
            try {
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                    $adUser = Get-ADUser $username -ErrorAction SilentlyContinue
                    if ($adUser) {
                        return "$($adUser.Name) ($username)"
                    }
                }
            } catch {}
            
            return $username
        } else {
            return "None"
        }
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

# Function to get last logged on user
function Get-LastLoggedOnUser {
    param([string]$ComputerName)
    
    try {
        $userDir = Get-ChildItem "\\$ComputerName\c$\Users" -ErrorAction Stop |
            Where-Object {
                $_.PSIsContainer -and 
                $_.Name -notmatch '^(Public|Default|Default User|All Users|Admin|Administrator)$'
            } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        
        if ($userDir) {
            # Try to get AD user info
            try {
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                    $adUser = Get-ADUser $userDir.Name -ErrorAction SilentlyContinue
                    if ($adUser) {
                        return "$($adUser.Name) ($($userDir.Name))"
                    }
                }
            } catch {}
            
            return $userDir.Name
        } else {
            return "Unknown"
        }
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

# Function to get primary user (most frequently used profile)
function Get-PrimaryUser {
    param([string]$ComputerName)
    
    try {
        $userDirs = Get-ChildItem "\\$ComputerName\c$\Users" -ErrorAction Stop |
            Where-Object {
                $_.PSIsContainer -and 
                $_.Name -notmatch '^(Public|Default|Default User|All Users|Admin|Administrator)$'
            }
        
        if ($userDirs) {
            # Calculate profile size for each user as indicator of primary user
            $userStats = foreach ($userDir in $userDirs) {
                try {
                    $size = (Get-ChildItem $userDir.FullName -Recurse -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    
                    [PSCustomObject]@{
                        UserName = $userDir.Name
                        ProfileSize = $size
                        LastAccess = $userDir.LastWriteTime
                    }
                } catch {
                    # Skip users we can't access
                }
            }
            
            # Primary user is the one with largest profile (most data/activity)
            $primaryUser = $userStats | Sort-Object ProfileSize -Descending | Select-Object -First 1
            
            if ($primaryUser) {
                # Try to get AD user info
                try {
                    if (Get-Module -ListAvailable -Name ActiveDirectory) {
                        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                        $adUser = Get-ADUser $primaryUser.UserName -ErrorAction SilentlyContinue
                        if ($adUser) {
                            return "$($adUser.Name) ($($primaryUser.UserName))"
                        }
                    }
                } catch {}
                
                return $primaryUser.UserName
            } else {
                return "Unknown"
            }
        } else {
            return "No Users"
        }
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

# Function to get drive space
function Get-DriveSpace {
    param([string]$ComputerName)
    
    try {
        $drive = Get-CimInstance -ClassName Win32_Volume -ComputerName $ComputerName -Filter "drivetype = 3" -ErrorAction Stop |
            Where-Object { $_.DriveLetter -eq 'C:' } |
            Select-Object -First 1
        
        if ($drive) {
            $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $totalGB = [math]::Round($drive.Capacity / 1GB, 2)
            $percentFree = [math]::Round(($drive.FreeSpace / $drive.Capacity) * 100, 1)
            return "$freeGB GB free of $totalGB GB ($percentFree%)"
        }
        return "N/A"
    } catch {
        return "ERROR"
    }
}

# Main script execution
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Computer Inventory & Health Check" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Read computer list
$computers = Get-Content $ComputerListPath | Where-Object { $_.Trim() -ne "" }
Write-LogMessage "Found $($computers.Count) computers to process" -Level Info
Write-LogMessage "Results will be saved to: $csvFile" -Level Info

# Check if host is domain-joined (for AD queries)
$isDomainJoined = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

# Initialize counters
$processedCount = 0
$onlineCount = 0
$offlineCount = 0

# Process each computer
$results = foreach ($computer in $computers) {
    $computerName = $computer.Trim()
    $processedCount++
    
    Write-Host "`n[$processedCount/$($computers.Count)] Processing: $computerName" -ForegroundColor White
    
    # Initialize result object with defaults
    $result = [PSCustomObject]@{
        ComputerName = $computerName.ToUpper()
        Status = "Offline"
        PingResponse = "No"
        IPAddress = "N/A"
        MACAddress = "N/A"
        Manufacturer = "N/A"
        Model = "N/A"
        SystemType = "N/A"
        SerialNumber = "N/A"
        OperatingSystem = "N/A"
        OSBuildVersion = "N/A"
        TotalMemoryGB = "N/A"
        CPUName = "N/A"
        DiskSpace = "N/A"
        LastBootTime = "N/A"
        CurrentUser = "N/A"
        LastLoggedOnUser = "N/A"
        PrimaryUser = "N/A"
        ADLastLogon = "N/A"
        Shares = "N/A"
        ErrorDetails = ""
    }
    
    # Test connectivity
    try {
        $pingResult = Test-Connection -ComputerName $computerName -Count 2 -Quiet -ErrorAction Stop
        
        if ($pingResult) {
            Write-LogMessage "  $computerName is ONLINE" -Level Success
            $result.Status = "Online"
            $result.PingResponse = "Yes"
            $onlineCount++
            
            try {
                # Get hardware and OS information
                $bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $computerName -ErrorAction Stop
                $hardware = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computerName -ErrorAction Stop
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computerName -ErrorAction Stop
                $cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $computerName -ErrorAction Stop | Select-Object -First 1
                $networks = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $computerName -ErrorAction Stop |
                    Where-Object { $_.IPEnabled }
                
                # Populate result object
                $result.SerialNumber = $bios.SerialNumber
                $result.Manufacturer = $hardware.Manufacturer
                $result.Model = $hardware.Model
                $result.SystemType = $hardware.SystemType
                $result.OperatingSystem = $os.Caption
                $result.OSBuildVersion = $os.Version
                $result.TotalMemoryGB = [math]::Round($hardware.TotalPhysicalMemory / 1GB, 2)
                $result.CPUName = $cpu.Name
                $result.LastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
                
                if ($networks) {
                    $result.IPAddress = $networks[0].IPAddress[0]
                    $result.MACAddress = $networks[0].MACAddress
                }
                
                # Get additional information
                $result.DiskSpace = Get-DriveSpace -ComputerName $computerName
                $result.CurrentUser = Get-CurrentUser -ComputerName $computerName
                $result.LastLoggedOnUser = Get-LastLoggedOnUser -ComputerName $computerName
                $result.PrimaryUser = Get-PrimaryUser -ComputerName $computerName
                
                # Optional: Get shares
                if ($IncludeShares) {
                    Write-LogMessage "  Enumerating shares..." -Level Info
                    $result.Shares = Get-SharesInfo -ComputerName $computerName
                }
                
                # Optional: Get AD info
                if ($IncludeADInfo -and $isDomainJoined) {
                    Write-LogMessage "  Retrieving AD information..." -Level Info
                    $result.ADLastLogon = Get-ADLastLogon -ComputerName $computerName
                }
                
            } catch {
                $result.ErrorDetails = "Data collection error: $($_.Exception.Message)"
                Write-LogMessage "  ERROR: $($_.Exception.Message)" -Level Error
            }
            
        } else {
            Write-LogMessage "  $computerName is OFFLINE (no ping response)" -Level Warning
            $offlineCount++
        }
        
    } catch {
        Write-LogMessage "  $computerName is OFFLINE (connection failed)" -Level Warning
        $result.ErrorDetails = "Connectivity error: $($_.Exception.Message)"
        $offlineCount++
    }
    
    # Output the result object (will be collected in $results array)
    $result
}

# Export to CSV
Write-Host "`n========================================" -ForegroundColor Cyan
Write-LogMessage "Exporting results to CSV..." -Level Info
$results | Export-Csv -Path $csvFile -NoTypeInformation -Force

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Computers:  $processedCount" -ForegroundColor White
Write-Host "Online:           $onlineCount" -ForegroundColor Green
Write-Host "Offline:          $offlineCount" -ForegroundColor Yellow
Write-Host "`nResults exported to:" -ForegroundColor White
Write-Host "$csvFile" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Return the results for pipeline use
return $results
