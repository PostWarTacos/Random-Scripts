[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerListPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$env:USERPROFILE\Desktop"
)

# Initialize output file with timestamp (single .txt file as requested)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFile = Join-Path $LogPath "ComputerHealth_$timestamp.txt"

# Ensure output directory exists
if (-not (Test-Path -Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

# Function to write to log with timestamp
function Write-LogEntry {
    param(
        [string]$Message,
        [string]$LogFile,
        [string]$Level = "INFO"
    )

    if (-not $LogFile) { $LogFile = $OutFile }

    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    Write-Host $logEntry
}

# Function to test computer connectivity
function Test-ComputerConnectivity {
    param([string]$ComputerName)
    
    try {
        $result = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop
        if ($result) {
            Write-LogEntry -Message "$ComputerName - PASS" -LogFile $connectivityLogPath -Level "SUCCESS"
            return $true
        } else {
            Write-LogEntry -Message "$ComputerName - FAIL (No response)" -LogFile $connectivityLogPath -Level "FAIL"
            return $false
        }
    } catch {
        Write-LogEntry -Message "$ComputerName - FAIL (Error: $($_.Exception.Message))" -LogFile $connectivityLogPath -Level "ERROR"
        return $false
    }
}

# Function to get network shares
function Get-ComputerShares {
    param([string]$ComputerName)
    
    try {
        Write-LogEntry -Message "Enumerating shares on $ComputerName" -LogFile $sharesLogPath
        
        # Try modern approach first (PowerShell 3.0+)
        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
            $shares = Get-SmbShare -CimSession $ComputerName -ErrorAction Stop
            foreach ($share in $shares) {
                $shareInfo = "Share: $($share.Name) | Path: $($share.Path) | Description: $($share.Description)"
                Write-LogEntry -Message "$ComputerName - $shareInfo" -LogFile $sharesLogPath
            }
        } else {
            # Fallback to WMI
            $shares = Get-WmiObject -Class Win32_Share -ComputerName $ComputerName -ErrorAction Stop
            foreach ($share in $shares) {
                $shareInfo = "Share: $($share.Name) | Path: $($share.Path) | Description: $($share.Description)"
                Write-LogEntry -Message "$ComputerName - $shareInfo" -LogFile $sharesLogPath
            }
        }
    } catch {
        Write-LogEntry -Message "$ComputerName - ERROR: Unable to enumerate shares ($($_.Exception.Message))" -LogFile $sharesLogPath -Level "ERROR"
    }
}

# Function to get AD last seen timestamp
function Get-ADLastSeen {
    param([string]$ComputerName)
    
    try {
        # Try using ActiveDirectory module first
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $computer = Get-ADComputer -Identity $ComputerName -Properties LastLogonTimeStamp -ErrorAction Stop
            $lastSeen = [DateTime]::FromFileTime($computer.LastLogonTimeStamp)
            Write-LogEntry -Message "$ComputerName - Last Seen: $lastSeen" -LogFile $adTimestampLogPath
        } else {
            # Fallback to ADSI
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(name=$ComputerName))"
            $searcher.PropertiesToLoad.Add("lastLogonTimeStamp") | Out-Null
            
            $result = $searcher.FindOne()
            if ($result) {
                $lastLogonTS = $result.Properties["lastLogonTimeStamp"][0]
                if ($lastLogonTS) {
                    $lastSeen = [DateTime]::FromFileTime($lastLogonTS)
                    Write-LogEntry -Message "$ComputerName - Last Seen: $lastSeen (via ADSI)" -LogFile $adTimestampLogPath
                } else {
                    Write-LogEntry -Message "$ComputerName - Last Seen: Never or timestamp not available" -LogFile $adTimestampLogPath -Level "WARN"
                }
            } else {
                Write-LogEntry -Message "$ComputerName - Not found in Active Directory" -LogFile $adTimestampLogPath -Level "WARN"
            }
        }
    } catch {
        Write-LogEntry -Message "$ComputerName - ERROR: Unable to retrieve AD timestamp ($($_.Exception.Message))" -LogFile $adTimestampLogPath -Level "ERROR"
    }
}

# Main script execution
Write-Host "Computer Health Test Script Starting..." -ForegroundColor Green
Write-Host "Results will be saved to: $OutFile" -ForegroundColor Yellow

# Validate input file
if (-not (Test-Path $ComputerListPath)) {
    Write-Error "Computer list file not found: $ComputerListPath"
    exit 1
}

# Initialize single output file with a header
Write-LogEntry -Message "=== Computer Health Test Started ==="

# Read computer names from file
$computers = Get-Content $ComputerListPath | Where-Object { $_.Trim() -ne "" }
Write-Host "Found $($computers.Count) computers to test" -ForegroundColor Cyan

# Process each computer
$successCount = 0
foreach ($computer in $computers) {
    $computerName = $computer.Trim()
    Write-Host "`nProcessing: $computerName" -ForegroundColor White

    # Write a clear separator/header for this computer's results
    Write-LogEntry -Message "================================================================" -Level "INFO"
    Write-LogEntry -Message "COMPUTER: $computerName  --  START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-LogEntry -Message "----------------------------------------------------------------" -Level "INFO"

    # Test connectivity
    $isOnline = Test-ComputerConnectivity -ComputerName $computerName

    if ($isOnline) {
        $successCount++
        
        # Get shares if computer is online
        Get-ComputerShares -ComputerName $computerName
    }
    
    # Always try to get AD timestamp (even if offline)
    Get-ADLastSeen -ComputerName $computerName

    # End separator for this computer
    Write-LogEntry -Message "COMPUTER: $computerName  --  END: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-LogEntry -Message "" -Level "INFO"
}

# Summary
Write-LogEntry -Message "=== Summary: $successCount of $($computers.Count) computers were reachable ==="
Write-LogEntry -Message "=== Computer Health Test Completed ==="

Write-Host "`nScript completed successfully!" -ForegroundColor Green
Write-Host "Results saved to: $OutFile" -ForegroundColor Yellow