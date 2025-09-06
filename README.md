# Cursor Complete Removal Tool

This tool completely removes Cursor from your Windows 11 system, ensuring a fresh installation when you reinstall it.

## What This Tool Does

This enhanced removal tool combines the deep scanning approach of [Geek Uninstaller](https://geekuninstaller.com/) with Cursor-specific cleanup methods. The removal process includes:

### 1. Application Uninstallation
- Stops all running Cursor processes
- Uninstalls Cursor application using Windows uninstaller
- Removes installation files and updater

### 2. File System Cleanup
- Removes all Cursor directories from:
  - `%LOCALAPPDATA%\Programs\cursor`
  - `%APPDATA%\cursor`
  - `%LOCALAPPDATA%\cursor`
  - `%LOCALAPPDATA%\cursor-updater`
  - `%PROGRAMFILES%\cursor`
  - `%PROGRAMFILES(X86)%\cursor`
  - `%USERPROFILE%\.cursor`
  - All temporary directories

### 3. Registry Deep Clean
- Removes all Cursor-related registry entries
- Cleans uninstaller entries
- Removes file associations
- Cleans Windows Run keys
- Removes application paths
- Cleans shell extensions and COM objects
- Removes context menu entries

### 4. System Integration Cleanup
- Removes Start Menu shortcuts
- Removes Desktop shortcuts
- Cleans environment variables
- Removes from Windows Services
- Removes from Scheduled Tasks
- Cleans Windows MRU lists
- Removes taskbar pins

### 5. Advanced Data Cleanup
- Clears browser data and cookies (Chrome, Edge, Firefox)
- Removes temporary files and caches
- Cleans Windows Search index
- Flushes DNS cache
- Cleans thumbnail and icon caches
- Removes recent items and jump lists

### 6. Deep System Cleanup (Geek Uninstaller Style)
- Scans all drives for remaining Cursor references
- Cleans Windows Installer cache
- Cleans Windows Prefetch
- Removes fonts, themes, and language packs
- Cleans driver store and component cache
- Removes performance counters and WMI classes

### 7. Machine Identity Reset
- **Regenerates Machine ID** (crucial for fresh installation)
- Updates Windows Product ID
- Ensures system appears completely new to Cursor

### 8. Security Cleanup
- Removes credentials from Windows Credential Manager
- Cleans certificates from Windows Certificate Store
- Removes authentication tokens

### 9. System Refresh
- Refreshes Windows Explorer
- Ensures all changes take effect

## How to Use

### Method 1: Easy Execution (Recommended)
1. Right-click on `RemoveCursor.bat`
2. Select "Run as administrator"
3. Follow the prompts

### Method 2: PowerShell Direct
1. Right-click on PowerShell
2. Select "Run as administrator"
3. Navigate to the script directory
4. Run: `.\CursorCompleteRemoval.ps1`

## Command Line Options

```powershell
# Run with confirmation (default)
.\CursorCompleteRemoval.ps1

# Run without confirmation prompts
.\CursorCompleteRemoval.ps1 -SkipConfirmation

# Run with force mode (includes additional cleanup)
.\CursorCompleteRemoval.ps1 -Force

# Run with both options
.\CursorCompleteRemoval.ps1 -SkipConfirmation -Force
```

## Requirements

- Windows 11 (also works on Windows 10)
- Administrator privileges
- PowerShell execution policy (handled automatically)

## Safety Features

- Confirmation prompts before removal
- Detailed logging of all operations
- Color-coded output for easy reading
- Error handling for safe operation
- Backup recommendations

## After Removal

1. **Restart your computer** (highly recommended)
2. Your system will be completely clean of Cursor
3. You can now install Cursor fresh as if it's a new system
4. All previous settings, tokens, and data will be gone

## Troubleshooting

### If you get execution policy errors:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### If some files can't be deleted:
- Make sure Cursor is completely closed
- Run the script as Administrator
- Restart your computer and try again

### If registry cleaning fails:
- The script will continue with other cleanup tasks
- Manual registry cleaning may be needed for stubborn entries

## Files Included

- `CursorCompleteRemoval.ps1` - Main PowerShell removal script
- `RemoveCursor.bat` - Batch file wrapper for easy execution
- `README.md` - This documentation

## Important Notes

- This tool is designed for complete removal
- All Cursor data will be permanently deleted
- Make sure to backup any important Cursor settings before running
- The tool is safe and only targets Cursor-related files and settings
- After running, your system will be as if Cursor was never installed

## Support

If you encounter any issues:
1. Make sure you're running as Administrator
2. Check that Cursor is completely closed
3. Try restarting your computer first
4. Run the script again if needed

The tool is designed to be safe and thorough, ensuring complete removal of Cursor from your system.
