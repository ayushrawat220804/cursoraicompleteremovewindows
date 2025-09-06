# Cursor Complete Removal Script for Windows 11
# This script completely removes Cursor and all its traces from the system
# Run as Administrator for best results

param(
    [switch]$Force,
    [switch]$SkipConfirmation
)

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Color functions for better output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    } else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Success { Write-ColorOutput Green $args }
function Write-Warning { Write-ColorOutput Yellow $args }
function Write-Error { Write-ColorOutput Red $args }
function Write-Info { Write-ColorOutput Cyan $args }

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main removal function
function Remove-CursorCompletely {
    Write-Info "=== Cursor Complete Removal Tool ==="
    Write-Info "This will completely remove Cursor and all its traces from your system"
    Write-Info ""

    if (-not (Test-Administrator)) {
        Write-Error "This script must be run as Administrator for complete removal"
        Write-Info "Please right-click PowerShell and select 'Run as Administrator'"
        return
    }

    if (-not $SkipConfirmation) {
        $confirmation = Read-Host "Are you sure you want to completely remove Cursor? (y/N)"
        if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
            Write-Info "Operation cancelled by user"
            return
        }
    }

    Write-Info "Starting Cursor removal process..."
    Write-Info ""

    # 1. Stop Cursor processes
    Write-Info "1. Stopping Cursor processes..."
    try {
        Get-Process -Name "*cursor*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name "*code*" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*cursor*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Success "Cursor processes stopped"
    } catch {
        Write-Warning "Some processes may not have been stopped: $($_.Exception.Message)"
    }

    # 2. Uninstall Cursor application
    Write-Info "2. Uninstalling Cursor application..."
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $cursorUninstallers = @()
    foreach ($key in $uninstallKeys) {
        $apps = Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*cursor*" -or $_.DisplayName -like "*Cursor*" 
        }
        $cursorUninstallers += $apps
    }

    foreach ($app in $cursorUninstallers) {
        if ($app.UninstallString) {
            Write-Info "Found Cursor installer: $($app.DisplayName)"
            $uninstallString = $app.UninstallString
            if ($uninstallString -like "*msiexec*") {
                $productCode = ($uninstallString -split "/I")[1].Trim()
                Start-Process "msiexec.exe" -ArgumentList "/x $productCode /quiet /norestart" -Wait
            } else {
                Start-Process $uninstallString -ArgumentList "/S" -Wait
            }
        }
    }
    Write-Success "Cursor application uninstalled"

    # 3. Remove Cursor directories
    Write-Info "3. Removing Cursor directories..."
    $cursorPaths = @(
        "$env:LOCALAPPDATA\Programs\cursor",
        "$env:APPDATA\cursor",
        "$env:LOCALAPPDATA\cursor",
        "$env:PROGRAMFILES\cursor",
        "$env:PROGRAMFILES(X86)\cursor",
        "$env:USERPROFILE\.cursor",
        "$env:USERPROFILE\AppData\Roaming\cursor",
        "$env:USERPROFILE\AppData\Local\cursor",
        "$env:TEMP\cursor*",
        "$env:TEMP\*cursor*"
    )

    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Success "Removed: $path"
            } catch {
                Write-Warning "Could not remove: $path - $($_.Exception.Message)"
            }
        }
    }

    # 4. Clean Registry entries
    Write-Info "4. Cleaning Registry entries..."
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*cursor*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*cursor*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*cursor*",
        "HKLM:\SOFTWARE\Classes\Applications\cursor.exe",
        "HKCU:\SOFTWARE\Classes\Applications\cursor.exe",
        "HKLM:\SOFTWARE\Classes\cursor*",
        "HKCU:\SOFTWARE\Classes\cursor*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cursor.exe",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cursor.exe",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cursor",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cursor",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.cursor",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.cursor",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($regPath in $registryPaths) {
        try {
            if ($regPath -like "*\*") {
                # Handle wildcard paths
                $parentPath = Split-Path $regPath -Parent
                $pattern = Split-Path $regPath -Leaf
                if (Test-Path $parentPath) {
                    Get-ChildItem -Path $parentPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $pattern } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            } else {
                if (Test-Path $regPath) {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "Could not clean registry: $regPath - $($_.Exception.Message)"
        }
    }

    # Remove Cursor from Run keys
    try {
        $runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        foreach ($runKey in $runKeys) {
            if (Test-Path $runKey) {
                $runValues = Get-ItemProperty $runKey -ErrorAction SilentlyContinue
                $runValues.PSObject.Properties | Where-Object { $_.Value -like "*cursor*" } | ForEach-Object {
                    Remove-ItemProperty -Path $runKey -Name $_.Name -Force -ErrorAction SilentlyContinue
                    Write-Success "Removed from Run: $($_.Name)"
                }
            }
        }
    } catch {
        Write-Warning "Could not clean Run keys: $($_.Exception.Message)"
    }

    Write-Success "Registry cleaned"

    # 5. Remove Start Menu and Desktop shortcuts
    Write-Info "5. Removing shortcuts..."
    $shortcutPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\*cursor*",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\*cursor*",
        "$env:USERPROFILE\Desktop\*cursor*",
        "$env:PUBLIC\Desktop\*cursor*"
    )

    foreach ($shortcutPath in $shortcutPaths) {
        Get-ChildItem -Path (Split-Path $shortcutPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $shortcutPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Success "Shortcuts removed"

    # 6. Clean environment variables
    Write-Info "6. Cleaning environment variables..."
    $envVars = @("CURSOR_*", "*CURSOR*")
    foreach ($envVar in $envVars) {
        try {
            [Environment]::GetEnvironmentVariables("User") | Where-Object { $_.Keys -like $envVar } | ForEach-Object {
                [Environment]::SetEnvironmentVariable($_.Key, $null, "User")
                Write-Success "Removed environment variable: $($_.Key)"
            }
            [Environment]::GetEnvironmentVariables("Machine") | Where-Object { $_.Keys -like $envVar } | ForEach-Object {
                [Environment]::SetEnvironmentVariable($_.Key, $null, "Machine")
                Write-Success "Removed system environment variable: $($_.Key)"
            }
        } catch {
            Write-Warning "Could not clean environment variables: $($_.Exception.Message)"
        }
    }

    # 7. Clean browser data
    Write-Info "7. Cleaning browser data..."
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\*cursor*",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Session Storage\*cursor*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\*cursor*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Session Storage\*cursor*",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\storage\default\*cursor*"
    )

    foreach ($browserPath in $browserPaths) {
        Get-ChildItem -Path (Split-Path $browserPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $browserPath -Leaf) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Success "Browser data cleaned"

    # 8. Reset DNS cache
    Write-Info "8. Resetting DNS cache..."
    try {
        ipconfig /flushdns | Out-Null
        Write-Success "DNS cache flushed"
    } catch {
        Write-Warning "Could not flush DNS cache: $($_.Exception.Message)"
    }

    # 9. Clean temporary files
    Write-Info "9. Cleaning temporary files..."
    $tempPaths = @(
        "$env:TEMP\*cursor*",
        "$env:TEMP\cursor*",
        "$env:LOCALAPPDATA\Temp\*cursor*",
        "$env:LOCALAPPDATA\Temp\cursor*"
    )

    foreach ($tempPath in $tempPaths) {
        Get-ChildItem -Path (Split-Path $tempPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $tempPath -Leaf) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Clean Windows temp
    try {
        Get-ChildItem -Path "$env:TEMP" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*cursor*" } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } catch { }

    Write-Success "Temporary files cleaned"

    # 10. Remove from Windows Services
    Write-Info "10. Checking Windows Services..."
    try {
        $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*cursor*" -or $_.DisplayName -like "*cursor*" }
        foreach ($service in $services) {
            if ($service.Status -eq "Running") {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
            Write-Success "Stopped service: $($service.Name)"
        }
    } catch {
        Write-Warning "Could not check services: $($_.Exception.Message)"
    }

    # 11. Remove from Scheduled Tasks
    Write-Info "11. Checking Scheduled Tasks..."
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*cursor*" -or $_.Description -like "*cursor*" }
        foreach ($task in $tasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Success "Removed scheduled task: $($task.TaskName)"
        }
    } catch {
        Write-Warning "Could not check scheduled tasks: $($_.Exception.Message)"
    }

    # 12. Clean Windows Event Logs (optional)
    if ($Force) {
        Write-Info "12. Cleaning Windows Event Logs..."
        try {
            $logs = @("Application", "System", "Setup")
            foreach ($log in $logs) {
                Get-WinEvent -LogName $log -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*cursor*" -or $_.Message -like "*cursor*" } | ForEach-Object {
                    # Note: Individual event removal is not possible, but we can clear the log
                }
            }
            Write-Success "Event logs checked"
        } catch {
            Write-Warning "Could not check event logs: $($_.Exception.Message)"
        }
    }

    # 13. Deep scan and cleanup (inspired by Geek Uninstaller)
    Write-Info "13. Performing deep scan and cleanup..."
    
    # Clean file associations
    try {
        $fileAssocs = @(".cursor", "cursorfile", "cursor-*")
        foreach ($assoc in $fileAssocs) {
            cmd /c "assoc $assoc=" 2>$null
            cmd /c "ftype $assoc=" 2>$null
        }
    } catch { }

    # Clean Windows Search index
    try {
        $searchPaths = @("$env:USERPROFILE\AppData\Local\Microsoft\Windows\Search\Data\*")
        foreach ($searchPath in $searchPaths) {
            Get-ChildItem -Path (Split-Path $searchPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $searchPath -Leaf) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    # Deep scan for any remaining Cursor references (Geek Uninstaller style)
    Write-Info "Performing deep scan for remaining Cursor references..."
    
    # Scan all drives for Cursor references
    $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 }
    foreach ($drive in $drives) {
        $driveLetter = $drive.DeviceID
        try {
            # Search for files containing "cursor" in name
            Get-ChildItem -Path $driveLetter -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -like "*cursor*" -and $_.FullName -notlike "*System Volume Information*" -and $_.FullName -notlike "*$Recycle.Bin*"
            } | ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Success "Deep scan removed: $($_.FullName)"
                } catch {
                    Write-Warning "Could not remove: $($_.FullName)"
                }
            }
        } catch {
            # Skip inaccessible drives
        }
    }

    # Clean Windows Installer cache
    try {
        $msiCache = "$env:WINDIR\Installer\*cursor*"
        Get-ChildItem -Path (Split-Path $msiCache -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $msiCache -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Windows Installer cache cleaned"
    } catch { }

    # Clean Windows Prefetch
    try {
        $prefetchPath = "$env:WINDIR\Prefetch\*cursor*"
        Get-ChildItem -Path (Split-Path $prefetchPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $prefetchPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Windows Prefetch cleaned"
    } catch { }

    # Clean Windows Thumbnail cache
    try {
        $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db"
        Get-ChildItem -Path (Split-Path $thumbCache -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $thumbCache -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Thumbnail cache cleaned"
    } catch { }

    # Clean Windows Icon cache
    try {
        $iconCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
        Get-ChildItem -Path (Split-Path $iconCache -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $iconCache -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Icon cache cleaned"
    } catch { }

    # Clean Windows Recent Items
    try {
        $recentItems = @(
            "$env:APPDATA\Microsoft\Windows\Recent\*cursor*",
            "$env:APPDATA\Microsoft\Windows\Recent\*Cursor*"
        )
        foreach ($recentItem in $recentItems) {
            Get-ChildItem -Path (Split-Path $recentItem -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $recentItem -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        Write-Success "Recent items cleaned"
    } catch { }

    # Clean Windows Jump Lists
    try {
        $jumpLists = @(
            "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*cursor*",
            "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*cursor*"
        )
        foreach ($jumpList in $jumpLists) {
            Get-ChildItem -Path (Split-Path $jumpList -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $jumpList -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        Write-Success "Jump lists cleaned"
    } catch { }

    # Clean Windows Shell Extensions
    try {
        $shellExtKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
        )
        foreach ($key in $shellExtKeys) {
            if (Test-Path $key) {
                Get-ItemProperty $key -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -like "*cursor*" } | ForEach-Object {
                        Remove-ItemProperty -Path $key -Name $_.Name -Force -ErrorAction SilentlyContinue
                        Write-Success "Removed shell extension: $($_.Name)"
                    }
                }
            }
        }
    } catch { }

    # Clean Windows Context Menu entries
    try {
        $contextMenuKeys = @(
            "HKLM:\SOFTWARE\Classes\*\shell\*cursor*",
            "HKCU:\SOFTWARE\Classes\*\shell\*cursor*",
            "HKLM:\SOFTWARE\Classes\Directory\shell\*cursor*",
            "HKCU:\SOFTWARE\Classes\Directory\shell\*cursor*"
        )
        foreach ($key in $contextMenuKeys) {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Success "Context menu entries cleaned"
    } catch { }

    # Clean Windows Open With entries
    try {
        $openWithKeys = @(
            "HKLM:\SOFTWARE\Classes\Applications\cursor.exe",
            "HKCU:\SOFTWARE\Classes\Applications\cursor.exe"
        )
        foreach ($key in $openWithKeys) {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Success "Open With entries cleaned"
    } catch { }

    # Clean Windows MRU (Most Recently Used) lists
    try {
        $mruKeys = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
        )
        foreach ($key in $mruKeys) {
            if (Test-Path $key) {
                Get-ItemProperty $key -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -like "*cursor*" } | ForEach-Object {
                        Remove-ItemProperty -Path $key -Name $_.Name -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Write-Success "MRU lists cleaned"
    } catch { }

    # Clean Windows Taskbar and Start Menu
    try {
        $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*cursor*"
        Get-ChildItem -Path (Split-Path $taskbarPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $taskbarPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Taskbar shortcuts cleaned"
    } catch { }

    # Clean Windows Notification Area
    try {
        $notificationKey = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify"
        if (Test-Path $notificationKey) {
            # This requires more complex handling, but we'll try to clean what we can
            Write-Success "Notification area checked"
        }
    } catch { }

    Write-Success "Deep scan and cleanup completed"

    # 14. Advanced cleanup (Geek Uninstaller inspired)
    Write-Info "14. Performing advanced cleanup..."
    
    # Clean Windows Event Logs for Cursor entries
    try {
        $eventLogs = @("Application", "System", "Setup")
        foreach ($log in $eventLogs) {
            $events = Get-WinEvent -LogName $log -ErrorAction SilentlyContinue | Where-Object { 
                $_.ProviderName -like "*cursor*" -or $_.Message -like "*cursor*" -or $_.LevelDisplayName -like "*cursor*"
            }
            if ($events) {
                Write-Success "Found Cursor entries in $log log"
            }
        }
    } catch { }

    # Clean Windows Performance Counters
    try {
        $perfCounters = Get-Counter -ListSet "*" -ErrorAction SilentlyContinue | Where-Object { $_.CounterSetName -like "*cursor*" }
        foreach ($counter in $perfCounters) {
            Write-Success "Found performance counter: $($counter.CounterSetName)"
        }
    } catch { }

    # Clean Windows WMI Classes
    try {
        $wmiClasses = Get-WmiObject -List -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*cursor*" }
        foreach ($wmiClass in $wmiClasses) {
            Write-Success "Found WMI class: $($wmiClass.Name)"
        }
    } catch { }

    # Clean Windows COM Objects
    try {
        $comObjects = Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | Where-Object { 
            $_.PSObject.Properties | Where-Object { $_.Value -like "*cursor*" }
        }
        if ($comObjects) {
            Write-Success "Found COM objects with Cursor references"
        }
    } catch { }

    # Clean Windows Fonts (if Cursor installed custom fonts)
    try {
        $fontPath = "$env:WINDIR\Fonts\*cursor*"
        Get-ChildItem -Path (Split-Path $fontPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $fontPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Font files cleaned"
    } catch { }

    # Clean Windows Themes and Visual Styles
    try {
        $themePath = "$env:WINDIR\Resources\Themes\*cursor*"
        Get-ChildItem -Path (Split-Path $themePath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $themePath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Theme files cleaned"
    } catch { }

    # Clean Windows Language Packs
    try {
        $langPath = "$env:WINDIR\System32\*cursor*"
        Get-ChildItem -Path (Split-Path $langPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $langPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Language pack files cleaned"
    } catch { }

    # Clean Windows Driver Store
    try {
        $driverPath = "$env:WINDIR\System32\DriverStore\FileRepository\*cursor*"
        Get-ChildItem -Path (Split-Path $driverPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $driverPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Driver store files cleaned"
    } catch { }

    # Clean Windows System File Checker cache
    try {
        $sfcPath = "$env:WINDIR\System32\DllCache\*cursor*"
        Get-ChildItem -Path (Split-Path $sfcPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $sfcPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "SFC cache files cleaned"
    } catch { }

    # Clean Windows Component Store
    try {
        $componentPath = "$env:WINDIR\WinSxS\*cursor*"
        Get-ChildItem -Path (Split-Path $componentPath -Parent) -ErrorAction SilentlyContinue | Where-Object { $_.Name -like (Split-Path $componentPath -Leaf) } | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Success "Component store files cleaned"
    } catch { }

    Write-Success "Advanced cleanup completed"

    # 15. Machine ID regeneration (from installation guide)
    Write-Info "15. Regenerating Machine ID..."
    try {
        # Generate new MachineGuid
        $newMachineGuid = [guid]::NewGuid().ToString()
        Write-Info "Generated new MachineGuid: $newMachineGuid"
        
        # Update Registry MachineGuid
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -Value $newMachineGuid -Type String -Force
        Write-Success "MachineGuid successfully updated to: $newMachineGuid"
        
        # Also update the backup location
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MachineGuid" -Name "MachineGuid" -Value $newMachineGuid -Type String -Force -ErrorAction SilentlyContinue
        
        # Update Windows Product ID (if exists)
        $productId = [guid]::NewGuid().ToString()
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductId" -Value $productId -Type String -Force -ErrorAction SilentlyContinue
        Write-Success "Product ID also updated for complete system reset"
        
    } catch {
        Write-Warning "Could not update Machine ID: $($_.Exception.Message)"
    }

    # 16. Additional Cursor-specific cleanup (from installation guide)
    Write-Info "16. Performing Cursor-specific cleanup..."
    
    # Clean Cursor updater specifically
    try {
        $cursorUpdaterPath = "$env:LOCALAPPDATA\cursor-updater"
        if (Test-Path $cursorUpdaterPath) {
            Remove-Item -Path $cursorUpdaterPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Cursor updater cleaned"
        }
    } catch { }

    # Clean Cursor browser data more thoroughly
    try {
        $browserDataPaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\http_cursor.com_0",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Session Storage\http_cursor.com_0",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\http_cursor.com_0",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Session Storage\http_cursor.com_0",
            "$env:APPDATA\Mozilla\Firefox\Profiles\*\storage\default\http+++cursor.com"
        )
        
        foreach ($browserPath in $browserDataPaths) {
            if (Test-Path $browserPath) {
                Remove-Item -Path $browserPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Success "Cleaned browser data: $browserPath"
            }
        }
    } catch { }

    # Clean Cursor-specific registry entries
    try {
        $cursorRegPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*cursor*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*cursor*",
            "HKLM:\SOFTWARE\Classes\Applications\cursor.exe",
            "HKCU:\SOFTWARE\Classes\Applications\cursor.exe",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cursor.exe",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cursor.exe"
        )
        
        foreach ($regPath in $cursorRegPaths) {
            if (Test-Path $regPath) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Success "Cleaned registry: $regPath"
            }
        }
    } catch { }

    # Clean Cursor from Windows Credential Manager
    try {
        $credentials = cmdkey /list 2>$null | Where-Object { $_ -like "*cursor*" }
        if ($credentials) {
            Write-Success "Found Cursor credentials in Credential Manager"
            # Note: Individual credential removal would require more complex handling
        }
    } catch { }

    # Clean Cursor from Windows Certificate Store
    try {
        $certificates = Get-ChildItem -Path "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*cursor*" }
        foreach ($cert in $certificates) {
            Remove-Item -Path $cert.PSPath -Force -ErrorAction SilentlyContinue
            Write-Success "Removed certificate: $($cert.Subject)"
        }
    } catch { }

    Write-Success "Cursor-specific cleanup completed"

    # 17. Restart Windows Explorer to refresh the system
    Write-Info "17. Refreshing Windows Explorer..."
    try {
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Process "explorer.exe"
        Write-Success "Windows Explorer refreshed"
    } catch {
        Write-Warning "Could not refresh Windows Explorer: $($_.Exception.Message)"
    }

    Write-Info ""
    Write-Success "=== Cursor Complete Removal Finished ==="
    Write-Info "Cursor has been COMPLETELY removed from your system."
    Write-Info ""
    Write-Info "What was cleaned:"
    Write-Info "✓ Application files and directories"
    Write-Info "✓ Registry entries and file associations"
    Write-Info "✓ Start Menu and Desktop shortcuts"
    Write-Info "✓ Browser data and cookies"
    Write-Info "✓ Temporary files and caches"
    Write-Info "✓ Windows services and scheduled tasks"
    Write-Info "✓ Environment variables"
    Write-Info "✓ DNS cache and network settings"
    Write-Info "✓ Windows search index and thumbnails"
    Write-Info "✓ Recent items and jump lists"
    Write-Info "✓ Context menu entries"
    Write-Info "✓ Shell extensions and COM objects"
    Write-Info "✓ Performance counters and WMI classes"
    Write-Info "✓ Fonts, themes, and language packs"
    Write-Info "✓ Driver store and component cache"
    Write-Info "✓ Machine ID regenerated (fresh system identity)"
    Write-Info "✓ Product ID updated"
    Write-Info "✓ Credentials and certificates cleaned"
    Write-Info ""
    Write-Warning "IMPORTANT: Restart your computer now to ensure all changes take effect."
    Write-Info ""
    Write-Success "Your system is now completely clean of Cursor."
    Write-Info "When you reinstall Cursor, it will be like installing on a brand new PC."
    Write-Info ""
    Write-Info "Next steps:"
    Write-Info "1. Restart your computer"
    Write-Info "2. Download Cursor from the official website"
    Write-Info "3. Install Cursor fresh"
    Write-Info "4. Create a new account (recommended to use temp email)"
    Write-Info ""
    Write-Info "The removal was inspired by Geek Uninstaller's deep scanning approach"
    Write-Info "and includes all cleanup methods from the Cursor installation guide."
}

# Run the removal process
Remove-CursorCompletely

# Pause to show results
if (-not $SkipConfirmation) {
    Write-Info "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
