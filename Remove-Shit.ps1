<#
#   Intent: Removes old and/or temporary files/folders to save potentially 30GB of space. 
#   Date 25-Feb-25
#>>

#requires administrator

param(
    [switch]$resetBase  # Optional switch to include /resetbase in DISM cleanup
)

# Ensure the script is run with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please re-run with elevated privileges."
    exit
}

# Clear Temp Files
Write-Host "Deleting Temporary Files..." -ForegroundColor Yellow
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# Clear Windows Update Cache
Write-Host "Cleaning Windows Update Cache..." -ForegroundColor Yellow
Stop-Service wuauserv -Force
Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service wuauserv

# Empty Recycle Bin
Write-Host "Emptying Recycle Bin..." -ForegroundColor Yellow
$shell = New-Object -ComObject Shell.Application
$shell.Namespace(10).Items() | ForEach-Object { $_.InvokeVerb("Delete") }

# Delete Prefetch Files
Write-Host "Cleaning Prefetch Files..." -ForegroundColor Yellow
Get-ChildItem "C:\Windows\Prefetch\*" -Recurse | Where-Object CreationTime -lt (get-date).AddDays(-30) |
    Remove-Item -Force

# Delete Thumbnails
Write-Host "Clearing Thumbnails Cache..." -ForegroundColor Yellow
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue

# Delete old Windows Error Reports
Write-Host "Removing Old Windows Error Reports..." -ForegroundColor Yellow
Get-ChildItem "C:\ProgramData\Microsoft\Windows\WER\*" -Recurse | Where-Object LastWriteTime -lt (get-date).AddDays(-180) |
    Remove-Item -Force

# Delete Windows.old if it exists
if (Test-Path "C:\Windows.old") {
    Write-Host "Removing Windows.old (Old Windows Installation)..." -ForegroundColor Yellow
    Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "No Windows.old found, skipping..." -ForegroundColor Green
}

# Clear Old Driver Packages
 Write-Host "Removing Old Driver Packages...(UNDER CONSTRUCTION)" -ForegroundColor Yellow
<#
 pnputil /enum-drivers | ForEach-Object {
    if ($_ -match "Published Name : (oem\d+\.inf)") {
        pnputil /delete-driver $matches[1] /uninstall /force
    }
}
#>

# Search for large files that may need manual cleanup across all user profiles
Write-Host "Searching for large files (>1GB, >500MB, docs/images >50MB) in all user profiles..." -ForegroundColor Cyan
$docExtensions = @('.doc', '.docx', '.pdf', '.txt', '.xlsx', '.xls', '.ppt', '.pptx', '.odt', '.rtf')
$imageExtensions = @('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.svg', '.webp', '.ico', '.raw', '.psd')
$videoExtensions = @('.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg')
$usersPath = "C:\Users"

try {
    $allLargeFiles = @()
    $userProfiles = Get-ChildItem -Path $usersPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    
    foreach ($userProfile in $userProfiles) {
        Write-Host "Scanning $($userProfile.Name)..." -ForegroundColor Gray
        $largeFiles = Get-ChildItem -Path $userProfile.FullName -File -Recurse -ErrorAction SilentlyContinue | Where-Object {
            ($_.Length -gt 1GB) -or 
            ($_.Length -gt 500MB -and $videoExtensions -notcontains $_.Extension.ToLower()) -or
            (($docExtensions -contains $_.Extension.ToLower() -or $imageExtensions -contains $_.Extension.ToLower()) -and $_.Length -gt 50MB)
        }
        $allLargeFiles += $largeFiles
    }
    
    if ($allLargeFiles) {
        Write-Host "Large files found:" -ForegroundColor Yellow
        $allLargeFiles | Select-Object @{Name='Size(MB)';Expression={[math]::Round($_.Length/1MB, 2)}}, 
                                       @{Name='Size(GB)';Expression={[math]::Round($_.Length/1GB, 2)}}, 
                                       FullName, 
                                       Extension | 
            Sort-Object -Property {$_.PSObject.Properties['Size(MB)'].Value} -Descending | 
            Format-Table -AutoSize
        
        $totalSize = ($allLargeFiles | Measure-Object -Property Length -Sum).Sum
        Write-Host "Total size of large files: $([math]::Round($totalSize/1GB, 2)) GB" -ForegroundColor Cyan
    } else {
        Write-Host "No large files found matching the criteria." -ForegroundColor Green
    }
} catch {
    Write-Host "Error searching for large files: $_" -ForegroundColor Red
}

# Run Disk Cleanup silently for System Files
Write-Host "Running Disk Cleanup..." -ForegroundColor Yellow
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/verylowdisk" -NoNewWindow -Wait

# Run DISM for Windows Component Cleanup
Write-Host "Running DISM Cleanup..." -ForegroundColor Cyan
if ($resetBase) {
    Write-Host "Including /resetbase (Permanent Cleanup)" -ForegroundColor Yellow
    dism /online /cleanup-image /startcomponentcleanup /resetbase
} else {
    Write-Host "Skipping /resetbase (Retaining Rollback Option)" -ForegroundColor Green
    dism /online /cleanup-image /startcomponentcleanup
}

Write-Host "Cleanup Completed!" -ForegroundColor Green

# Displaying DISM features that can be manually removed.
Write-host
Write-host "Running DISM Features Cleanup."
DISM /online /get-features | more
Write-Host "Select the features to remove and run the following command:" -ForegroundColor Cyan
Write-Host "DISM /online /disable-feature /featurename:<featurename> /remove" -ForegroundColor Cyan

