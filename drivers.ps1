<#
.SYNOPSIS
    Audits installed Windows drivers and checks Windows Update
    for available driver updates.

.DESCRIPTION
    This script:
      1. Collects installed Plug and Play driver information.
      2. Identifies devices reporting errors.
      3. Flags drivers older than a configurable age.
      4. Searches Windows Update for available driver updates.
      5. Exports the results to CSV and TXT files.

    It does NOT install, remove, or modify drivers.

.NOTES
    Recommended: Run in Windows PowerShell 5.1 as Administrator.
#>

[CmdletBinding()]
param(
    # Drivers older than this many years will be marked for review.
    [ValidateRange(1, 20)]
    [int]$OldDriverThresholdYears = 5,

    # Folder where reports will be saved.
    [string]$OutputFolder = "$env:USERPROFILE\Desktop\DriverAudit_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Title)

    Write-Host ""
    Write-Host ("=" * 75) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 75) -ForegroundColor Cyan
}

function Convert-DriverDate {
    param($DriverDate)

    if (-not $DriverDate) {
        return $null
    }

    try {
        if ($DriverDate -is [datetime]) {
            return $DriverDate
        }

        # CIM/WMI dates may use DMTF format.
        if ([string]$DriverDate -match '^\d{14}\.') {
            return [Management.ManagementDateTimeConverter]::ToDateTime(
                [string]$DriverDate
            )
        }

        return [datetime]$DriverDate
    }
    catch {
        return $null
    }
}

function Get-AvailableDriverUpdates {
    Write-Section "Searching Windows Update for driver updates"

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # IsInstalled=0: updates that are not installed.
        # Type='Driver': driver-class updates only.
        $searchResult = $updateSearcher.Search(
            "IsInstalled=0 and Type='Driver'"
        )

        $results = foreach ($update in $searchResult.Updates) {
            $categories = @(
                foreach ($category in $update.Categories) {
                    $category.Name
                }
            ) -join "; "

            $kbNumbers = @(
                foreach ($kb in $update.KBArticleIDs) {
                    "KB$kb"
                }
            ) -join "; "

            [pscustomobject]@{
                Title             = $update.Title
                DriverManufacturer = $update.DriverManufacturer
                DriverModel       = $update.DriverModel
                DriverClass       = $update.DriverClass
                DriverVerDate     = $update.DriverVerDate
                Description       = $update.Description
                Categories        = $categories
                KBArticles        = $kbNumbers
                IsDownloaded      = $update.IsDownloaded
                RebootRequired    = $update.RebootRequired
                UpdateID          = $update.Identity.UpdateID
            }
        }

        return @($results)
    }
    catch {
        Write-Warning "Windows Update driver search failed: $($_.Exception.Message)"
        Write-Warning "This can happen when Windows Update is disabled, managed by your organization, or awaiting a reboot."
        return @()
    }
}

try {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null

    $computerInfo = Get-CimInstance Win32_ComputerSystem
    $operatingSystem = Get-CimInstance Win32_OperatingSystem

    Write-Section "Computer information"

    $systemSummary = [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        Manufacturer     = $computerInfo.Manufacturer
        Model            = $computerInfo.Model
        WindowsEdition   = $operatingSystem.Caption
        WindowsVersion   = $operatingSystem.Version
        WindowsBuild     = $operatingSystem.BuildNumber
        LastBootTime     = $operatingSystem.LastBootUpTime
        AuditTime        = Get-Date
        OldDriverCutoff  = (Get-Date).AddYears(-$OldDriverThresholdYears)
    }

    $systemSummary | Format-List

    Write-Section "Collecting installed driver information"

    $cutoffDate = (Get-Date).AddYears(-$OldDriverThresholdYears)

    $signedDrivers = Get-CimInstance Win32_PnPSignedDriver

    $installedDrivers = foreach ($driver in $signedDrivers) {
        $convertedDate = Convert-DriverDate -DriverDate $driver.DriverDate

        $ageYears = $null
        if ($convertedDate) {
            $ageYears = [math]::Round(
                ((Get-Date) - $convertedDate).TotalDays / 365.25,
                1
            )
        }

        $reviewReasons = [System.Collections.Generic.List[string]]::new()

        if (-not $driver.DriverProviderName) {
            $reviewReasons.Add("Missing driver provider")
        }

        if (-not $driver.DriverVersion) {
            $reviewReasons.Add("Missing driver version")
        }

        if ($convertedDate -and $convertedDate -lt $cutoffDate) {
            $reviewReasons.Add(
                "Driver is more than $OldDriverThresholdYears years old"
            )
        }

        if ($driver.IsSigned -eq $false) {
            $reviewReasons.Add("Driver is not digitally signed")
        }

        [pscustomobject]@{
            DeviceName        = $driver.DeviceName
            DeviceClass       = $driver.DeviceClass
            Manufacturer      = $driver.Manufacturer
            DriverProvider    = $driver.DriverProviderName
            DriverVersion     = $driver.DriverVersion
            DriverDate        = $convertedDate
            DriverAgeYears    = $ageYears
            IsSigned          = $driver.IsSigned
            InfName           = $driver.InfName
            DeviceID          = $driver.DeviceID
            Status            = $driver.Status
            NeedsReview       = ($reviewReasons.Count -gt 0)
            ReviewReason      = $reviewReasons -join "; "
        }
    }

    $installedDrivers = @(
        $installedDrivers |
            Sort-Object DeviceClass, DeviceName
    )

    Write-Section "Checking for devices reporting errors"

    $problemDevices = @(
        Get-CimInstance Win32_PnPEntity |
            Where-Object {
                $null -ne $_.ConfigManagerErrorCode -and
                $_.ConfigManagerErrorCode -ne 0
            } |
            Select-Object `
                Name,
                Manufacturer,
                PNPClass,
                DeviceID,
                Status,
                ConfigManagerErrorCode,
                @{
                    Name = "ErrorDescription"
                    Expression = {
                        switch ($_.ConfigManagerErrorCode) {
                            1  { "Device is not configured correctly" }
                            3  { "Driver may be corrupted" }
                            10 { "Device cannot start" }
                            12 { "Insufficient resources" }
                            14 { "Restart required" }
                            18 { "Reinstall the drivers" }
                            19 { "Registry configuration problem" }
                            21 { "Windows is removing the device" }
                            22 { "Device is disabled" }
                            24 { "Device is missing or not working" }
                            28 { "Drivers are not installed" }
                            31 { "Windows cannot load the required drivers" }
                            32 { "Driver service is disabled" }
                            37 { "Windows cannot initialize the driver" }
                            39 { "Driver is corrupted or missing" }
                            43 { "Windows stopped the device after an error" }
                            45 { "Device is not currently connected" }
                            48 { "Driver is blocked" }
                            52 { "Driver signature cannot be verified" }
                            default {
                                "Device Manager error code $($_.ConfigManagerErrorCode)"
                            }
                        }
                    }
                }
    )

    $availableUpdates = Get-AvailableDriverUpdates

    Write-Section "Exporting reports"

    $installedDriverPath = Join-Path $OutputFolder "InstalledDrivers.csv"
    $reviewDriverPath = Join-Path $OutputFolder "DriversNeedingReview.csv"
    $problemDevicePath = Join-Path $OutputFolder "ProblemDevices.csv"
    $availableUpdatePath = Join-Path $OutputFolder "AvailableDriverUpdates.csv"
    $summaryPath = Join-Path $OutputFolder "DriverAuditSummary.txt"

    $installedDrivers |
        Export-Csv -Path $installedDriverPath -NoTypeInformation -Encoding UTF8

    $driversNeedingReview = @(
        $installedDrivers |
            Where-Object { $_.NeedsReview }
    )

    $driversNeedingReview |
        Export-Csv -Path $reviewDriverPath -NoTypeInformation -Encoding UTF8

    $problemDevices |
        Export-Csv -Path $problemDevicePath -NoTypeInformation -Encoding UTF8

    $availableUpdates |
        Export-Csv -Path $availableUpdatePath -NoTypeInformation -Encoding UTF8

    $summary = @"
DRIVER AUDIT SUMMARY
====================

Audit time:                $(Get-Date)
Computer:                  $($systemSummary.ComputerName)
Manufacturer:              $($systemSummary.Manufacturer)
Model:                     $($systemSummary.Model)
Windows:                   $($systemSummary.WindowsEdition)
Windows build:             $($systemSummary.WindowsBuild)

Installed driver records:  $($installedDrivers.Count)
Drivers needing review:    $($driversNeedingReview.Count)
Problem devices:           $($problemDevices.Count)
Available driver updates:  $($availableUpdates.Count)

IMPORTANT
---------
A driver's age alone does not prove it needs an update. Some Microsoft,
chipset, storage, monitor, and system-device drivers remain valid for years.

The strongest indicators that an update is needed are:
1. Windows Update offers a newer driver.
2. Device Manager reports an error.
3. The computer or component manufacturer recommends a newer version.
4. You are troubleshooting a device-specific problem.

REPORT FILES
------------
$installedDriverPath
$reviewDriverPath
$problemDevicePath
$availableUpdatePath
"@

    $summary | Set-Content -Path $summaryPath -Encoding UTF8

    Write-Section "Results"

    Write-Host "Installed driver records: " -NoNewline
    Write-Host $installedDrivers.Count -ForegroundColor White

    Write-Host "Drivers flagged for review: " -NoNewline
    Write-Host $driversNeedingReview.Count -ForegroundColor Yellow

    Write-Host "Devices reporting errors: " -NoNewline
    if ($problemDevices.Count -gt 0) {
        Write-Host $problemDevices.Count -ForegroundColor Red
    }
    else {
        Write-Host "0" -ForegroundColor Green
    }

    Write-Host "Driver updates offered by Windows Update: " -NoNewline
    if ($availableUpdates.Count -gt 0) {
        Write-Host $availableUpdates.Count -ForegroundColor Yellow
    }
    else {
        Write-Host "0" -ForegroundColor Green
    }

    if ($availableUpdates.Count -gt 0) {
        Write-Section "Available driver updates"

        $availableUpdates |
            Select-Object `
                Title,
                DriverManufacturer,
                DriverModel,
                DriverClass,
                DriverVerDate |
            Format-Table -AutoSize -Wrap
    }

    if ($problemDevices.Count -gt 0) {
        Write-Section "Problem devices"

        $problemDevices |
            Select-Object `
                Name,
                PNPClass,
                ConfigManagerErrorCode,
                ErrorDescription |
            Format-Table -AutoSize -Wrap
    }

    Write-Host ""
    Write-Host "Reports saved to:" -ForegroundColor Green
    Write-Host $OutputFolder -ForegroundColor White

    # Open the report folder.
    Start-Process explorer.exe -ArgumentList "`"$OutputFolder`""
}
catch {
    Write-Host ""
    Write-Error "Driver audit failed: $($_.Exception.Message)"
    exit 1
}