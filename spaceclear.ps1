<#
.SYNOPSIS
    Safe cache cleanup across all connected Windows drives.

.DESCRIPTION
    Scans all connected fixed and removable drives for:
    - Microsoft Flight Simulator ROLLINGCACHE.CCC files
    - Standard Windows and user temporary files
    - DirectX shader cache
    - Windows Error Reporting cache
    - Recycle Bin contents, when approved

    The script does not delete:
    - WindowsApps
    - WpSystem
    - Program Files
    - Games
    - Documents
    - Downloads
    - Save-game folders

.PARAMETER AutoConfirm
    Deletes discovered rolling-cache files and empties recycle bins without
    asking for individual confirmation.

.PARAMETER ReportOnly
    Reports discovered files and cache sizes without deleting anything.
#>

[CmdletBinding()]
param(
    [switch]$AutoConfirm,
    [switch]$ReportOnly
)

$ErrorActionPreference = "Continue"

function Get-SizeGB {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    try {
        $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

        if (-not $Item.PSIsContainer) {
            return [math]::Round($Item.Length / 1GB, 2)
        }

        $Bytes = (
            Get-ChildItem -LiteralPath $Path `
                -File `
                -Force `
                -Recurse `
                -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum
        ).Sum

        return [math]::Round(($Bytes / 1GB), 2)
    }
    catch {
        return 0
    }
}

function Remove-FolderContents {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $SizeGB = Get-SizeGB -Path $Path

    Write-Host ""
    Write-Host "$Description"
    Write-Host "  Path: $Path"
    Write-Host "  Size: approximately $SizeGB GB"

    if ($ReportOnly) {
        Write-Host "  [REPORT ONLY] Nothing removed."
        return
    }

    try {
        Get-ChildItem -LiteralPath $Path `
            -Force `
            -ErrorAction SilentlyContinue |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

        Write-Host "  [CLEANED]"
    }
    catch {
        Write-Warning "Unable to completely clean $Path"
        Write-Warning $_.Exception.Message
    }
}

function Confirm-Deletion {
    param(
        [Parameter(Mandatory)]
        [string]$Prompt
    )

    if ($ReportOnly) {
        return $false
    }

    if ($AutoConfirm) {
        return $true
    }

    $Answer = Read-Host "$Prompt Type YES to continue"
    return $Answer -eq "YES"
}

# Get all connected local fixed and removable file-system drives.
# DriveType 2 = removable
# DriveType 3 = local fixed disk

$ConnectedDrives = Get-CimInstance Win32_LogicalDisk |
    Where-Object {
        $_.DriveType -in @(2, 3) -and
        $_.DeviceID
    } |
    Sort-Object DeviceID

if (-not $ConnectedDrives) {
    Write-Warning "No connected local drives were detected."
    exit 1
}

Write-Host ""
Write-Host "Connected drives that will be inspected:" -ForegroundColor Cyan

$ConnectedDrives |
    Select-Object @{
        Name = "Drive"
        Expression = { $_.DeviceID }
    }, @{
        Name = "Type"
        Expression = {
            switch ($_.DriveType) {
                2 { "Removable" }
                3 { "Fixed" }
            }
        }
    }, @{
        Name = "SizeGB"
        Expression = {
            if ($_.Size) {
                [math]::Round($_.Size / 1GB, 2)
            }
        }
    }, @{
        Name = "FreeGB"
        Expression = {
            if ($_.FreeSpace) {
                [math]::Round($_.FreeSpace / 1GB, 2)
            }
        }
    }, VolumeName |
    Format-Table -AutoSize

Write-Host "Close Microsoft Flight Simulator, Xbox, Microsoft Store,"
Write-Host "and other games before continuing."
Write-Host ""

# Refuse to clean while Flight Simulator is running.

$FlightSimulatorProcesses = Get-Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProcessName -match `
            "FlightSimulator|FlightSimulator2024"
    }

if ($FlightSimulatorProcesses) {
    Write-Warning "Microsoft Flight Simulator appears to be running."
    Write-Warning "Close it before deleting ROLLINGCACHE.CCC."
    exit 1
}

# Search every connected drive for Flight Simulator rolling caches.

$RollingCaches = [System.Collections.Generic.List[object]]::new()

foreach ($Drive in $ConnectedDrives) {
    $DriveRoot = "$($Drive.DeviceID)\"
    $WpSystemPath = Join-Path $DriveRoot "WpSystem"

    if (-not (Test-Path -LiteralPath $WpSystemPath)) {
        continue
    }

    Write-Host "Searching $WpSystemPath for Flight Simulator caches..."

    try {
        $FoundCaches = Get-ChildItem `
            -LiteralPath $WpSystemPath `
            -Filter "ROLLINGCACHE.CCC" `
            -File `
            -Force `
            -Recurse `
            -ErrorAction SilentlyContinue

        foreach ($Cache in $FoundCaches) {
            $RollingCaches.Add($Cache)
        }
    }
    catch {
        Write-Warning "Unable to fully scan $WpSystemPath"
    }
}

if ($RollingCaches.Count -eq 0) {
    Write-Host ""
    Write-Host "No ROLLINGCACHE.CCC files were found."
}
else {
    Write-Host ""
    Write-Host "Flight Simulator rolling-cache files found:" `
        -ForegroundColor Cyan

    $RollingCaches |
        Select-Object FullName, @{
            Name = "SizeGB"
            Expression = {
                [math]::Round($_.Length / 1GB, 2)
            }
        }, LastWriteTime |
        Format-Table -AutoSize -Wrap

    foreach ($Cache in $RollingCaches) {
        $SizeGB = [math]::Round($Cache.Length / 1GB, 2)

        Write-Host ""
        Write-Host "Cache file:"
        Write-Host "  $($Cache.FullName)"
        Write-Host "  Size: $SizeGB GB"

        if ($ReportOnly) {
            Write-Host "  [REPORT ONLY] Nothing removed."
            continue
        }

        $Delete = Confirm-Deletion `
            -Prompt "Delete this rolling-cache file?"

        if ($Delete) {
            try {
                Remove-Item -LiteralPath $Cache.FullName `
                    -Force `
                    -ErrorAction Stop

                Write-Host "  [REMOVED] Recovered approximately $SizeGB GB."
            }
            catch {
                Write-Warning "Could not delete $($Cache.FullName)"
                Write-Warning $_.Exception.Message
            }
        }
        else {
            Write-Host "  [SKIPPED]"
        }
    }
}

# Clean standard temporary locations.
# These are Windows/profile locations rather than arbitrary folders
# on every drive.

Write-Host ""
Write-Host "Inspecting standard temporary locations..." `
    -ForegroundColor Cyan

$TemporaryLocations = @(
    @{
        Path        = $env:TEMP
        Description = "Current-user temporary files"
    },
    @{
        Path        = "$env:SystemRoot\Temp"
        Description = "Windows temporary files"
    },
    @{
        Path        = "$env:LOCALAPPDATA\D3DSCache"
        Description = "DirectX shader cache"
    },
    @{
        Path        = "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
        Description = "Archived Windows Error Reporting files"
    },
    @{
        Path        = "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
        Description = "Queued Windows Error Reporting files"
    },
    @{
        Path        = "$env:LOCALAPPDATA\Microsoft\Windows\WER"
        Description = "User Windows Error Reporting cache"
    }
)

foreach ($Location in $TemporaryLocations) {
    Remove-FolderContents `
        -Path $Location.Path `
        -Description $Location.Description
}

# Ask whether to empty recycle bins for all connected drives.

Write-Host ""
Write-Host "Recycle Bin review:" -ForegroundColor Cyan

foreach ($Drive in $ConnectedDrives) {
    $DriveLetter = $Drive.DeviceID.TrimEnd(":")

    if ($ReportOnly) {
        Write-Host "  [REPORT ONLY] Recycle Bin on $($Drive.DeviceID) not emptied."
        continue
    }

    $EmptyBin = Confirm-Deletion `
        -Prompt "Empty the Recycle Bin on $($Drive.DeviceID)?"

    if (-not $EmptyBin) {
        Write-Host "  [SKIPPED] Recycle Bin on $($Drive.DeviceID)"
        continue
    }

    try {
        Clear-RecycleBin `
            -DriveLetter $DriveLetter `
            -Force `
            -ErrorAction Stop

        Write-Host "  [CLEANED] Recycle Bin on $($Drive.DeviceID)"
    }
    catch {
        Write-Host "  Recycle Bin on $($Drive.DeviceID) was empty or inaccessible."
    }
}

Write-Host ""
Write-Host "Cleanup complete." -ForegroundColor Green
Write-Host "The script did not remove WindowsApps, WpSystem, or game folders."