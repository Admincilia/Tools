<#
.SYNOPSIS
    Lenovo Legion T5 26IAB7 System Health Check

.DESCRIPTION
    Performs a mostly read-only health assessment of a Windows computer.

    Recommended:
    - Run from Windows PowerShell 5.1 or PowerShell 7 as Administrator.
    - Close games and demanding applications before running.
    - The DISM and SFC checks may take several minutes.

    Reports are saved to:
    C:\LegionHealthReports

.PARAMETER OutputDirectory
    Directory where reports are written.

.PARAMETER SkipWindowsIntegrityChecks
    Skips DISM /ScanHealth and SFC /VerifyOnly.

.PARAMETER EventLogDays
    Number of days of Windows event logs to inspect.

.EXAMPLE
    .\Test-LegionHealth.ps1

.EXAMPLE
    .\Test-LegionHealth.ps1 -SkipWindowsIntegrityChecks

.EXAMPLE
    .\Test-LegionHealth.ps1 -EventLogDays 14
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "C:\LegionHealthReports",

    [switch]$SkipWindowsIntegrityChecks,

    [ValidateRange(1, 90)]
    [int]$EventLogDays = 7
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

$TimeStamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$TextReport = Join-Path $OutputDirectory "Legion_T5_Health_$TimeStamp.txt"
$HtmlReport = Join-Path $OutputDirectory "Legion_T5_Health_$TimeStamp.html"

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Sections = [System.Collections.Generic.List[string]]::new()

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Add-Finding {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("PASS", "INFO", "WARNING", "FAIL")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Finding,

        [string]$Recommendation = ""
    )

    $script:Findings.Add([pscustomobject]@{
        Status         = $Status
        Category       = $Category
        Finding        = $Finding
        Recommendation = $Recommendation
    })
}

function Add-TextSection {
    param(
        [string]$Title,
        [object]$Content
    )

    $text = @()
    $text += ""
    $text += ("=" * 78)
    $text += $Title
    $text += ("=" * 78)

    if ($null -eq $Content) {
        $text += "No information available."
    }
    elseif ($Content -is [string]) {
        $text += $Content
    }
    else {
        $text += ($Content | Out-String -Width 220).TrimEnd()
    }

    $script:Sections.Add(($text -join [Environment]::NewLine))
}

function Convert-WmiDate {
    param([object]$Value)

    if (-not $Value) {
        return $null
    }

    try {
        return [Management.ManagementDateTimeConverter]::ToDateTime(
            [string]$Value
        )
    }
    catch {
        try {
            return [datetime]$Value
        }
        catch {
            return $null
        }
    }
}

function Get-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

try {
    New-Item -Path $OutputDirectory -ItemType Directory -Force |
        Out-Null
}
catch {
    throw "Unable to create output directory '$OutputDirectory': $($_.Exception.Message)"
}

$IsAdmin = Test-IsAdministrator

if ($IsAdmin) {
    Add-Finding -Status PASS -Category "Execution" `
        -Finding "PowerShell is running with administrative rights."
}
else {
    Add-Finding -Status WARNING -Category "Execution" `
        -Finding "PowerShell is not running as Administrator." `
        -Recommendation "Run PowerShell as Administrator for complete disk, security, DISM, SFC, and event-log results."
}

# ---------------------------------------------------------------------------
# Computer and Lenovo identity
# ---------------------------------------------------------------------------

try {
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    $ComputerProduct = Get-CimInstance Win32_ComputerSystemProduct
    $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    $BIOS = Get-CimInstance Win32_BIOS
    $Baseboard = Get-CimInstance Win32_BaseBoard

    $BIOSDate = Convert-WmiDate $BIOS.ReleaseDate
    $Uptime = (Get-Date) - $OperatingSystem.LastBootUpTime

    $SystemInfo = [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        Manufacturer   = $ComputerSystem.Manufacturer
        Model          = $ComputerSystem.Model
        SystemFamily   = $ComputerSystem.SystemFamily
        SerialNumber   = $BIOS.SerialNumber
        ProductVersion = $ComputerProduct.Version
        UUID           = $ComputerProduct.UUID
        Motherboard    = "$($Baseboard.Manufacturer) $($Baseboard.Product)"
        BIOSVersion    = $BIOS.SMBIOSBIOSVersion
        BIOSDate       = $BIOSDate
        Windows        = $OperatingSystem.Caption
        WindowsVersion = $OperatingSystem.Version
        BuildNumber    = $OperatingSystem.BuildNumber
        LastBoot       = $OperatingSystem.LastBootUpTime
        Uptime         = "{0} days, {1} hours, {2} minutes" -f `
            [math]::Floor($Uptime.TotalDays),
            $Uptime.Hours,
            $Uptime.Minutes
    }

    Add-TextSection -Title "SYSTEM IDENTITY" -Content $SystemInfo

    if ($ComputerSystem.Manufacturer -match "LENOVO") {
        Add-Finding -Status PASS -Category "Lenovo" `
            -Finding "System manufacturer is Lenovo."
    }
    else {
        Add-Finding -Status WARNING -Category "Lenovo" `
            -Finding "Reported manufacturer is '$($ComputerSystem.Manufacturer)', not Lenovo."
    }

    if (
        $ComputerSystem.Model -match "26IAB7" -or
        $ComputerProduct.Version -match "26IAB7"
    ) {
        Add-Finding -Status PASS -Category "Lenovo" `
            -Finding "System identifies as a Legion T5 26IAB7 family computer."
    }
    else {
        Add-Finding -Status INFO -Category "Lenovo" `
            -Finding "The exact 26IAB7 designation was not found in the reported model fields. Reported model: $($ComputerSystem.Model)."
    }

    if ($BIOSDate) {
        $BIOSAgeDays = ((Get-Date) - $BIOSDate).Days

        if ($BIOSAgeDays -gt 1095) {
            Add-Finding -Status WARNING -Category "BIOS" `
                -Finding "BIOS release date is $($BIOSDate.ToString('yyyy-MM-dd')), more than three years old." `
                -Recommendation "Compare the installed BIOS with the BIOS offered for the exact Lenovo machine type and serial number. Do not flash BIOS during unstable power."
        }
        else {
            Add-Finding -Status INFO -Category "BIOS" `
                -Finding "Installed BIOS is $($BIOS.SMBIOSBIOSVersion), dated $($BIOSDate.ToString('yyyy-MM-dd'))."
        }
    }
}
catch {
    Add-Finding -Status FAIL -Category "System" `
        -Finding "Unable to collect system identity information: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Processor
# ---------------------------------------------------------------------------

try {
    $Processors = Get-CimInstance Win32_Processor | ForEach-Object {
        [pscustomobject]@{
            Name                  = $_.Name.Trim()
            Cores                 = $_.NumberOfCores
            LogicalProcessors     = $_.NumberOfLogicalProcessors
            CurrentClockMHz       = $_.CurrentClockSpeed
            MaximumClockMHz       = $_.MaxClockSpeed
            LoadPercentage        = $_.LoadPercentage
            VirtualizationEnabled = $_.VirtualizationFirmwareEnabled
            Status                = $_.Status
        }
    }

    Add-TextSection -Title "PROCESSOR" -Content $Processors

    foreach ($Processor in $Processors) {
        if ($Processor.Status -eq "OK") {
            Add-Finding -Status PASS -Category "CPU" `
                -Finding "$($Processor.Name) reports status OK."
        }
        else {
            Add-Finding -Status WARNING -Category "CPU" `
                -Finding "$($Processor.Name) reports status '$($Processor.Status)'."
        }
    }
}
catch {
    Add-Finding -Status WARNING -Category "CPU" `
        -Finding "Unable to collect CPU information: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

try {
    $MemoryModules = Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{
            Bank            = $_.BankLabel
            DeviceLocator   = $_.DeviceLocator
            CapacityGB      = [math]::Round($_.Capacity / 1GB, 2)
            ConfiguredMHz   = $_.ConfiguredClockSpeed
            Manufacturer    = $_.Manufacturer
            PartNumber      = ([string]$_.PartNumber).Trim()
            SerialNumber    = ([string]$_.SerialNumber).Trim()
        }
    }

    $TotalPhysicalGB = [math]::Round(
        $ComputerSystem.TotalPhysicalMemory / 1GB,
        2
    )

    $AvailableMemoryGB = [math]::Round(
        $OperatingSystem.FreePhysicalMemory / 1MB,
        2
    )

    $AvailablePercent = if ($TotalPhysicalGB -gt 0) {
        [math]::Round(($AvailableMemoryGB / $TotalPhysicalGB) * 100, 1)
    }
    else {
        0
    }

    $MemorySummary = [pscustomobject]@{
        InstalledGB      = $TotalPhysicalGB
        AvailableGB      = $AvailableMemoryGB
        AvailablePercent = $AvailablePercent
        InstalledModules = $MemoryModules.Count
    }

    Add-TextSection -Title "MEMORY SUMMARY" -Content $MemorySummary
    Add-TextSection -Title "MEMORY MODULES" -Content $MemoryModules

    if ($AvailablePercent -lt 10) {
        Add-Finding -Status WARNING -Category "Memory" `
            -Finding "Only $AvailablePercent% of physical memory is currently available." `
            -Recommendation "Close unnecessary applications and use Task Manager to identify high-memory processes."
    }
    else {
        Add-Finding -Status PASS -Category "Memory" `
            -Finding "$AvailablePercent% of installed memory is currently available."
    }

    $MemorySpeeds = $MemoryModules.ConfiguredMHz |
        Where-Object { $_ } |
        Select-Object -Unique

    if ($MemorySpeeds.Count -gt 1) {
        Add-Finding -Status WARNING -Category "Memory" `
            -Finding "Installed memory modules report different configured speeds: $($MemorySpeeds -join ', ') MHz." `
            -Recommendation "Verify that the memory modules are compatible and installed in the recommended paired slots."
    }
}
catch {
    Add-Finding -Status WARNING -Category "Memory" `
        -Finding "Unable to collect memory information: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Video adapters and NVIDIA health
# ---------------------------------------------------------------------------

try {
    $VideoControllers = Get-CimInstance Win32_VideoController |
        ForEach-Object {
            [pscustomobject]@{
                Name          = $_.Name
                DriverVersion = $_.DriverVersion
                DriverDate    = Convert-WmiDate $_.DriverDate
                Resolution    = if ($_.CurrentHorizontalResolution) {
                    "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"
                }
                else {
                    "Not reported"
                }
                Status        = $_.Status
            }
        }

    Add-TextSection -Title "VIDEO ADAPTERS" -Content $VideoControllers

    foreach ($GPU in $VideoControllers) {
        if ($GPU.Status -eq "OK") {
            Add-Finding -Status PASS -Category "GPU" `
                -Finding "$($GPU.Name) reports status OK."
        }
        else {
            Add-Finding -Status WARNING -Category "GPU" `
                -Finding "$($GPU.Name) reports status '$($GPU.Status)'."
        }
    }
}
catch {
    Add-Finding -Status WARNING -Category "GPU" `
        -Finding "Unable to collect video adapter information: $($_.Exception.Message)"
}

try {
    $NvidiaSmiCandidates = @(
        "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        "$env:SystemRoot\System32\nvidia-smi.exe"
    )

    $NvidiaSmi = $NvidiaSmiCandidates |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1

    if (-not $NvidiaSmi) {
        $NvidiaCommand = Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue

        if ($NvidiaCommand) {
            $NvidiaSmi = $NvidiaCommand.Source
        }
    }

    if ($NvidiaSmi) {
        $NvidiaRaw = & $NvidiaSmi `
            --query-gpu=name,driver_version,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,power.limit `
            --format=csv,noheader,nounits 2>$null

        $NvidiaData = foreach ($Line in $NvidiaRaw) {
            $Fields = $Line -split ",\s*"

            if ($Fields.Count -ge 8) {
                [pscustomobject]@{
                    Name               = $Fields[0]
                    DriverVersion      = $Fields[1]
                    TemperatureC       = [int]$Fields[2]
                    GPUUtilizationPct  = [int]$Fields[3]
                    MemoryUsedMB       = [int]$Fields[4]
                    MemoryTotalMB      = [int]$Fields[5]
                    PowerDrawWatts     = $Fields[6]
                    PowerLimitWatts    = $Fields[7]
                }
            }
        }

        Add-TextSection -Title "NVIDIA LIVE HEALTH" -Content $NvidiaData

        foreach ($GPU in $NvidiaData) {
            if ($GPU.TemperatureC -ge 90) {
                Add-Finding -Status FAIL -Category "GPU Temperature" `
                    -Finding "$($GPU.Name) is currently $($GPU.TemperatureC)°C." `
                    -Recommendation "Stop demanding workloads. Inspect airflow, dust accumulation, fan operation, and GPU cooling."
            }
            elseif ($GPU.TemperatureC -ge 83) {
                Add-Finding -Status WARNING -Category "GPU Temperature" `
                    -Finding "$($GPU.Name) is currently $($GPU.TemperatureC)°C." `
                    -Recommendation "Check whether a game or GPU workload is running. Inspect airflow and cooling if this occurs at idle."
            }
            else {
                Add-Finding -Status PASS -Category "GPU Temperature" `
                    -Finding "$($GPU.Name) is currently $($GPU.TemperatureC)°C."
            }
        }
    }
    else {
        Add-Finding -Status INFO -Category "GPU Temperature" `
            -Finding "nvidia-smi was not found. Live NVIDIA temperature and utilization data could not be collected." `
            -Recommendation "Install or repair the NVIDIA graphics driver if the computer has an NVIDIA GPU."
    }
}
catch {
    Add-Finding -Status WARNING -Category "GPU Temperature" `
        -Finding "Unable to query NVIDIA health information: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Logical volumes and disk space
# ---------------------------------------------------------------------------

try {
    $Volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" |
        ForEach-Object {
            $FreePercent = if ($_.Size -gt 0) {
                [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
            }
            else {
                0
            }

            [pscustomobject]@{
                Drive       = $_.DeviceID
                Label       = $_.VolumeName
                FileSystem  = $_.FileSystem
                SizeGB      = [math]::Round($_.Size / 1GB, 2)
                FreeGB      = [math]::Round($_.FreeSpace / 1GB, 2)
                FreePercent = $FreePercent
            }
        }

    Add-TextSection -Title "DISK SPACE" -Content $Volumes

    foreach ($Volume in $Volumes) {
        if ($Volume.FreePercent -lt 5) {
            Add-Finding -Status FAIL -Category "Disk Space" `
                -Finding "$($Volume.Drive) has only $($Volume.FreeGB) GB free ($($Volume.FreePercent)%)." `
                -Recommendation "Free disk space immediately. Windows, updates, games, and the page file may malfunction when space is critically low."
        }
        elseif ($Volume.FreePercent -lt 15) {
            Add-Finding -Status WARNING -Category "Disk Space" `
                -Finding "$($Volume.Drive) has $($Volume.FreeGB) GB free ($($Volume.FreePercent)%)." `
                -Recommendation "Remove or relocate unnecessary files and games."
        }
        else {
            Add-Finding -Status PASS -Category "Disk Space" `
                -Finding "$($Volume.Drive) has $($Volume.FreeGB) GB free ($($Volume.FreePercent)%)."
        }
    }
}
catch {
    Add-Finding -Status WARNING -Category "Disk Space" `
        -Finding "Unable to collect volume information: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Physical disks and SMART
# ---------------------------------------------------------------------------

try {
    $PhysicalDisks = Get-PhysicalDisk -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject]@{
                FriendlyName        = $_.FriendlyName
                MediaType           = $_.MediaType
                BusType             = $_.BusType
                SizeGB              = [math]::Round($_.Size / 1GB, 2)
                HealthStatus        = $_.HealthStatus
                OperationalStatus   = ($_.OperationalStatus -join ", ")
                FirmwareVersion     = $_.FirmwareVersion
                CannotPoolReason    = ($_.CannotPoolReason -join ", ")
            }
        }

    Add-TextSection -Title "PHYSICAL DISKS" -Content $PhysicalDisks

    foreach ($Disk in $PhysicalDisks) {
        if (
            $Disk.HealthStatus -eq "Healthy" -and
            $Disk.OperationalStatus -match "OK"
        ) {
            Add-Finding -Status PASS -Category "Storage" `
                -Finding "$($Disk.FriendlyName) reports Healthy/OK."
        }
        else {
            Add-Finding -Status FAIL -Category "Storage" `
                -Finding "$($Disk.FriendlyName) reports health '$($Disk.HealthStatus)' and operational status '$($Disk.OperationalStatus)'." `
                -Recommendation "Back up important data immediately and run the drive manufacturer's diagnostic utility."
        }
    }
}
catch {
    Add-Finding -Status WARNING -Category "Storage" `
        -Finding "Get-PhysicalDisk could not return health information: $($_.Exception.Message)"
}

try {
    $SmartStatus = Get-CimInstance `
        -Namespace root\wmi `
        -ClassName MSStorageDriver_FailurePredictStatus `
        -ErrorAction Stop |
        Select-Object InstanceName, PredictFailure, Reason

    Add-TextSection -Title "SMART FAILURE PREDICTION" -Content $SmartStatus

    foreach ($DiskStatus in $SmartStatus) {
        if ($DiskStatus.PredictFailure) {
            Add-Finding -Status FAIL -Category "SMART" `
                -Finding "A storage device predicts failure: $($DiskStatus.InstanceName)." `
                -Recommendation "Back up important files immediately and replace or thoroughly diagnose the affected drive."
        }
        else {
            Add-Finding -Status PASS -Category "SMART" `
                -Finding "No predicted failure reported for $($DiskStatus.InstanceName)."
        }
    }
}
catch {
    Add-Finding -Status INFO -Category "SMART" `
        -Finding "Legacy SMART failure-prediction data was unavailable. NVMe devices often do not expose data through this interface."
}

# ---------------------------------------------------------------------------
# File-system scan
# ---------------------------------------------------------------------------

try {
    $ChkdskOutput = cmd.exe /c "chkdsk C: /scan" 2>&1
    Add-TextSection -Title "CHKDSK ONLINE SCAN" `
        -Content ($ChkdskOutput -join [Environment]::NewLine)

    if (
        $ChkdskOutput -match "found no problems" -or
        $ChkdskOutput -match "Windows has scanned the file system and found no problems"
    ) {
        Add-Finding -Status PASS -Category "File System" `
            -Finding "CHKDSK did not detect file-system problems on C:."
    }
    elseif ($LASTEXITCODE -ne 0) {
        Add-Finding -Status WARNING -Category "File System" `
            -Finding "CHKDSK completed with exit code $LASTEXITCODE or reported a condition requiring review." `
            -Recommendation "Review the CHKDSK section in the report. Schedule an offline repair only if errors were detected."
    }
    else {
        Add-Finding -Status INFO -Category "File System" `
            -Finding "CHKDSK completed. Review its detailed output in the report."
    }
}
catch {
    Add-Finding -Status WARNING -Category "File System" `
        -Finding "Unable to run CHKDSK online scan: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Device Manager and drivers
# ---------------------------------------------------------------------------

try {
    $ProblemDevices = Get-CimInstance Win32_PnPEntity |
        Where-Object {
            $null -ne $_.ConfigManagerErrorCode -and
            $_.ConfigManagerErrorCode -ne 0
        } |
        Select-Object Name, PNPDeviceID, ConfigManagerErrorCode, Status

    Add-TextSection -Title "DEVICES WITH ERRORS" -Content $ProblemDevices

    if ($ProblemDevices.Count -eq 0) {
        Add-Finding -Status PASS -Category "Device Manager" `
            -Finding "No Plug and Play devices report a Device Manager error code."
    }
    else {
        foreach ($Device in $ProblemDevices) {
            Add-Finding -Status WARNING -Category "Device Manager" `
                -Finding "$($Device.Name) reports Device Manager error code $($Device.ConfigManagerErrorCode)." `
                -Recommendation "Open Device Manager, inspect the device status, and install the correct Lenovo, Intel, Realtek, or NVIDIA driver."
        }
    }
}
catch {
    Add-Finding -Status WARNING -Category "Device Manager" `
        -Finding "Unable to query device errors: $($_.Exception.Message)"
}

try {
    $DriverCutoff = (Get-Date).AddYears(-3)

    $Drivers = Get-CimInstance Win32_PnPSignedDriver |
        Where-Object {
            $_.DeviceName -and
            $_.DriverVersion
        } |
        ForEach-Object {
            $DriverDate = Convert-WmiDate $_.DriverDate

            [pscustomobject]@{
                DeviceName       = $_.DeviceName
                Manufacturer     = $_.Manufacturer
                DriverProvider   = $_.DriverProviderName
                DriverVersion    = $_.DriverVersion
                DriverDate       = $DriverDate
                Signed           = $_.IsSigned
                OlderThan3Years  = if ($DriverDate) {
                    $DriverDate -lt $DriverCutoff
                }
                else {
                    $false
                }
            }
        }

    $UnsignedDrivers = $Drivers |
        Where-Object { $_.Signed -eq $false }

    $OldRelevantDrivers = $Drivers |
        Where-Object {
            $_.OlderThan3Years -and
            $_.DeviceName -match "NVIDIA|Intel|Realtek|Bluetooth|Wireless|Wi-Fi|Ethernet|Storage|Chipset|USB"
        } |
        Sort-Object DriverDate

    Add-TextSection -Title "UNSIGNED DRIVERS" -Content $UnsignedDrivers
    Add-TextSection -Title "OLDER RELEVANT DRIVERS" -Content $OldRelevantDrivers

    if ($UnsignedDrivers.Count -gt 0) {
        Add-Finding -Status WARNING -Category "Drivers" `
            -Finding "$($UnsignedDrivers.Count) installed driver entries report that they are unsigned." `
            -Recommendation "Review the unsigned-driver section. Replace unknown third-party drivers with trusted signed versions."
    }
    else {
        Add-Finding -Status PASS -Category "Drivers" `
            -Finding "No unsigned driver entries were detected."
    }

    if ($OldRelevantDrivers.Count -gt 0) {
        Add-Finding -Status INFO -Category "Drivers" `
            -Finding "$($OldRelevantDrivers.Count) relevant driver entries are more than three years old." `
            -Recommendation "Age alone does not prove that a driver is outdated. Compare chipset, network, audio, storage, and graphics drivers against Lenovo Vantage, Lenovo Support, Windows Update, and the GPU vendor."
    }
}
catch {
    Add-Finding -Status WARNING -Category "Drivers" `
        -Finding "Unable to inspect installed drivers: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Security features
# ---------------------------------------------------------------------------

try {
    $TPM = Get-Tpm -ErrorAction Stop

    Add-TextSection -Title "TPM" -Content $TPM

    if ($TPM.TpmPresent -and $TPM.TpmReady) {
        Add-Finding -Status PASS -Category "Security" `
            -Finding "TPM is present and ready."
    }
    else {
        Add-Finding -Status WARNING -Category "Security" `
            -Finding "TPM present: $($TPM.TpmPresent); TPM ready: $($TPM.TpmReady)." `
            -Recommendation "Review BIOS security settings if Windows 11, BitLocker, or TPM-backed security features require TPM."
    }
}
catch {
    Add-Finding -Status INFO -Category "Security" `
        -Finding "TPM status could not be queried: $($_.Exception.Message)"
}

try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

    if ($SecureBoot) {
        Add-Finding -Status PASS -Category "Security" `
            -Finding "Secure Boot is enabled."
    }
    else {
        Add-Finding -Status WARNING -Category "Security" `
            -Finding "Secure Boot is disabled." `
            -Recommendation "Enable Secure Boot only after confirming Windows was installed in UEFI mode and all required hardware and software support it."
    }
}
catch {
    Add-Finding -Status INFO -Category "Security" `
        -Finding "Secure Boot status could not be determined. The system may not be running in UEFI mode, or administrative access may be required."
}

try {
    $BitLocker = Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod

    Add-TextSection -Title "BITLOCKER" -Content $BitLocker
}
catch {
    Add-Finding -Status INFO -Category "Security" `
        -Finding "BitLocker information was unavailable."
}

try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop

    $DefenderSummary = [pscustomobject]@{
        AntivirusEnabled           = $Defender.AntivirusEnabled
        RealTimeProtectionEnabled  = $Defender.RealTimeProtectionEnabled
        BehaviorMonitorEnabled     = $Defender.BehaviorMonitorEnabled
        AntivirusSignatureVersion  = $Defender.AntivirusSignatureVersion
        AntivirusSignatureAgeDays  = $Defender.AntivirusSignatureAge
        QuickScanAgeDays           = $Defender.QuickScanAge
        FullScanAgeDays            = $Defender.FullScanAge
    }

    Add-TextSection -Title "MICROSOFT DEFENDER" -Content $DefenderSummary

    if (
        $Defender.AntivirusEnabled -and
        $Defender.RealTimeProtectionEnabled
    ) {
        Add-Finding -Status PASS -Category "Defender" `
            -Finding "Microsoft Defender antivirus and real-time protection are enabled."
    }
    elseif (-not $Defender.AntivirusEnabled) {
        Add-Finding -Status INFO -Category "Defender" `
            -Finding "Microsoft Defender antivirus is not active. A third-party antivirus product may be installed."
    }
    else {
        Add-Finding -Status WARNING -Category "Defender" `
            -Finding "Microsoft Defender is present, but real-time protection is not enabled." `
            -Recommendation "Check Windows Security and confirm that a functioning antivirus product is active."
    }

    if ($Defender.AntivirusSignatureAge -gt 3) {
        Add-Finding -Status WARNING -Category "Defender" `
            -Finding "Defender signatures are $($Defender.AntivirusSignatureAge) days old." `
            -Recommendation "Run Windows Update or Update-MpSignature."
    }
}
catch {
    Add-Finding -Status INFO -Category "Defender" `
        -Finding "Microsoft Defender status was unavailable. A third-party antivirus product may be controlling security."
}

# ---------------------------------------------------------------------------
# Pending reboot and Windows Update history
# ---------------------------------------------------------------------------

$PendingRebootChecks = [ordered]@{
    ComponentBasedServicing = Test-Path `
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

    WindowsUpdate = Test-Path `
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

    PendingFileRename = $null -ne (
        Get-RegistryValueSafe `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
            -Name "PendingFileRenameOperations"
    )
}

$PendingReboot = $PendingRebootChecks.Values -contains $true

Add-TextSection -Title "PENDING REBOOT CHECK" `
    -Content ([pscustomobject]$PendingRebootChecks)

if ($PendingReboot) {
    Add-Finding -Status WARNING -Category "Windows" `
        -Finding "Windows reports that a restart is pending." `
        -Recommendation "Save your work and restart the computer before evaluating unresolved update or driver issues."
}
else {
    Add-Finding -Status PASS -Category "Windows" `
        -Finding "No common pending-restart indicators were detected."
}

try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
    $HistoryLimit = [math]::Min($HistoryCount, 25)

    if ($HistoryLimit -gt 0) {
        $UpdateHistory = $UpdateSearcher.QueryHistory(0, $HistoryLimit) |
            ForEach-Object {
                [pscustomobject]@{
                    Date       = $_.Date
                    Title      = $_.Title
                    ResultCode = switch ($_.ResultCode) {
                        0 { "Not Started" }
                        1 { "In Progress" }
                        2 { "Succeeded" }
                        3 { "Succeeded With Errors" }
                        4 { "Failed" }
                        5 { "Aborted" }
                        default { [string]$_.ResultCode }
                    }
                }
            }

        Add-TextSection -Title "RECENT WINDOWS UPDATE HISTORY" `
            -Content $UpdateHistory

        $FailedUpdates = $UpdateHistory |
            Where-Object {
                $_.ResultCode -in @(
                    "Failed",
                    "Succeeded With Errors"
                )
            }

        if ($FailedUpdates.Count -gt 0) {
            Add-Finding -Status WARNING -Category "Windows Update" `
                -Finding "$($FailedUpdates.Count) of the most recent update-history entries failed or succeeded with errors." `
                -Recommendation "Open Settings > Windows Update > Update history and investigate recurring failures."
        }
        else {
            Add-Finding -Status PASS -Category "Windows Update" `
                -Finding "No failures were found in the last $HistoryLimit Windows Update history entries."
        }
    }
}
catch {
    Add-Finding -Status INFO -Category "Windows Update" `
        -Finding "Windows Update history could not be queried: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Event logs
# ---------------------------------------------------------------------------

$StartTime = (Get-Date).AddDays(-$EventLogDays)

function Get-EventsSafe {
    param(
        [hashtable]$Filter,
        [int]$MaximumEvents = 100
    )

    try {
        return Get-WinEvent -FilterHashtable $Filter `
            -MaxEvents $MaximumEvents `
            -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    }
    catch {
        return @()
    }
}

$UnexpectedShutdowns = Get-EventsSafe -Filter @{
    LogName   = "System"
    Id        = 41, 6008
    StartTime = $StartTime
}

$WheaEvents = Get-EventsSafe -Filter @{
    LogName      = "System"
    ProviderName = "Microsoft-Windows-WHEA-Logger"
    StartTime    = $StartTime
}

$StorageEvents = Get-EventsSafe -Filter @{
    LogName   = "System"
    Id        = 7, 11, 15, 51, 55, 129, 153, 157
    StartTime = $StartTime
}

$BugChecks = Get-EventsSafe -Filter @{
    LogName   = "System"
    Id        = 1001
    StartTime = $StartTime
}

$CriticalSystemEvents = Get-EventsSafe -Filter @{
    LogName   = "System"
    Level     = 1
    StartTime = $StartTime
}

Add-TextSection -Title "UNEXPECTED SHUTDOWNS — LAST $EventLogDays DAYS" `
    -Content $UnexpectedShutdowns

Add-TextSection -Title "WHEA HARDWARE EVENTS — LAST $EventLogDays DAYS" `
    -Content $WheaEvents

Add-TextSection -Title "STORAGE EVENTS — LAST $EventLogDays DAYS" `
    -Content $StorageEvents

Add-TextSection -Title "BUGCHECK EVENTS — LAST $EventLogDays DAYS" `
    -Content $BugChecks

Add-TextSection -Title "CRITICAL SYSTEM EVENTS — LAST $EventLogDays DAYS" `
    -Content $CriticalSystemEvents

if ($UnexpectedShutdowns.Count -gt 0) {
    Add-Finding -Status WARNING -Category "Stability" `
        -Finding "$($UnexpectedShutdowns.Count) unexpected shutdown or Kernel-Power events occurred during the last $EventLogDays days." `
        -Recommendation "Correlate the timestamps with power loss, crashes, overheating, BIOS changes, or gaming workloads. Kernel-Power 41 records an improper shutdown but does not by itself identify the cause."
}
else {
    Add-Finding -Status PASS -Category "Stability" `
        -Finding "No unexpected shutdown events were found during the last $EventLogDays days."
}

if ($WheaEvents.Count -gt 0) {
    Add-Finding -Status FAIL -Category "Hardware Errors" `
        -Finding "$($WheaEvents.Count) WHEA hardware-error events occurred during the last $EventLogDays days." `
        -Recommendation "Review the WHEA event details. Common sources include CPU instability, memory, PCIe devices, GPU, motherboard, BIOS, overclocking, undervolting, or power delivery."
}
else {
    Add-Finding -Status PASS -Category "Hardware Errors" `
        -Finding "No WHEA hardware-error events were found during the last $EventLogDays days."
}

if ($StorageEvents.Count -gt 0) {
    Add-Finding -Status WARNING -Category "Storage Events" `
        -Finding "$($StorageEvents.Count) potentially significant storage events occurred during the last $EventLogDays days." `
        -Recommendation "Review event IDs, timestamps, device names, SMART status, cabling where applicable, NVMe firmware, and storage-controller drivers."
}
else {
    Add-Finding -Status PASS -Category "Storage Events" `
        -Finding "No selected disk, NTFS, or storage-reset events were found during the last $EventLogDays days."
}

if ($BugChecks.Count -gt 0) {
    Add-Finding -Status WARNING -Category "Blue Screens" `
        -Finding "$($BugChecks.Count) bugcheck-related events occurred during the last $EventLogDays days." `
        -Recommendation "Review C:\Windows\Minidump using WinDbg and correlate the crash time with driver, memory, GPU, or hardware events."
}
else {
    Add-Finding -Status PASS -Category "Blue Screens" `
        -Finding "No selected bugcheck events were found during the last $EventLogDays days."
}

# ---------------------------------------------------------------------------
# Network adapters
# ---------------------------------------------------------------------------

try {
    $NetworkAdapters = Get-NetAdapter -ErrorAction Stop |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

    Add-TextSection -Title "NETWORK ADAPTERS" -Content $NetworkAdapters

    $ActiveAdapters = $NetworkAdapters |
        Where-Object { $_.Status -eq "Up" }

    if ($ActiveAdapters.Count -gt 0) {
        Add-Finding -Status PASS -Category "Network" `
            -Finding "$($ActiveAdapters.Count) network adapter(s) currently report status Up."
    }
    else {
        Add-Finding -Status WARNING -Category "Network" `
            -Finding "No network adapter currently reports status Up."
    }
}
catch {
    Add-Finding -Status INFO -Category "Network" `
        -Finding "Network adapter status could not be collected."
}

# ---------------------------------------------------------------------------
# Windows integrity checks
# ---------------------------------------------------------------------------

if ($SkipWindowsIntegrityChecks) {
    Add-Finding -Status INFO -Category "Windows Integrity" `
        -Finding "DISM and SFC checks were skipped by request."
}
elseif (-not $IsAdmin) {
    Add-Finding -Status WARNING -Category "Windows Integrity" `
        -Finding "DISM and SFC were not run because the session is not elevated." `
        -Recommendation "Run the script from PowerShell as Administrator."
}
else {
    try {
        Write-Host "Running DISM component-store scan..." -ForegroundColor Cyan

        $DismOutput = & dism.exe /Online /Cleanup-Image /ScanHealth 2>&1
        $DismExitCode = $LASTEXITCODE

        Add-TextSection -Title "DISM COMPONENT STORE SCAN" `
            -Content ($DismOutput -join [Environment]::NewLine)

        if (
            $DismExitCode -eq 0 -and
            $DismOutput -match "No component store corruption detected"
        ) {
            Add-Finding -Status PASS -Category "Windows Integrity" `
                -Finding "DISM did not detect component-store corruption."
        }
        elseif ($DismOutput -match "component store is repairable") {
            Add-Finding -Status WARNING -Category "Windows Integrity" `
                -Finding "DISM reports that the Windows component store is repairable." `
                -Recommendation "Run DISM /Online /Cleanup-Image /RestoreHealth from an elevated terminal, then run SFC /Scannow."
        }
        elseif ($DismExitCode -ne 0) {
            Add-Finding -Status WARNING -Category "Windows Integrity" `
                -Finding "DISM completed with exit code $DismExitCode." `
                -Recommendation "Review the DISM output and C:\Windows\Logs\DISM\dism.log."
        }
        else {
            Add-Finding -Status INFO -Category "Windows Integrity" `
                -Finding "DISM completed. Review its detailed output in the report."
        }
    }
    catch {
        Add-Finding -Status WARNING -Category "Windows Integrity" `
            -Finding "DISM could not be completed: $($_.Exception.Message)"
    }

    try {
        Write-Host "Running SFC verification..." -ForegroundColor Cyan

        $SfcOutput = & sfc.exe /VerifyOnly 2>&1
        $SfcExitCode = $LASTEXITCODE

        Add-TextSection -Title "SYSTEM FILE CHECKER VERIFICATION" `
            -Content ($SfcOutput -join [Environment]::NewLine)

        if ($SfcOutput -match "did not find any integrity violations") {
            Add-Finding -Status PASS -Category "Windows Integrity" `
                -Finding "SFC did not find protected system-file integrity violations."
        }
        elseif ($SfcOutput -match "found integrity violations") {
            Add-Finding -Status WARNING -Category "Windows Integrity" `
                -Finding "SFC found protected system-file integrity violations." `
                -Recommendation "Run DISM /Online /Cleanup-Image /RestoreHealth, restart Windows, and then run SFC /Scannow."
        }
        elseif ($SfcExitCode -ne 0) {
            Add-Finding -Status WARNING -Category "Windows Integrity" `
                -Finding "SFC completed with exit code $SfcExitCode." `
                -Recommendation "Review the SFC output and C:\Windows\Logs\CBS\CBS.log."
        }
        else {
            Add-Finding -Status INFO -Category "Windows Integrity" `
                -Finding "SFC completed. Review its detailed output in the report."
        }
    }
    catch {
        Add-Finding -Status WARNING -Category "Windows Integrity" `
            -Finding "SFC verification could not be completed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Overall result
# ---------------------------------------------------------------------------

$FailCount = @($script:Findings | Where-Object Status -eq "FAIL").Count
$WarningCount = @($script:Findings | Where-Object Status -eq "WARNING").Count
$PassCount = @($script:Findings | Where-Object Status -eq "PASS").Count
$InfoCount = @($script:Findings | Where-Object Status -eq "INFO").Count

$OverallStatus = if ($FailCount -gt 0) {
    "FAIL — Immediate review recommended"
}
elseif ($WarningCount -gt 0) {
    "WARNING — Review detected concerns"
}
else {
    "PASS — No significant concerns detected"
}

$Summary = [pscustomobject]@{
    Computer       = $env:COMPUTERNAME
    ScanTime       = Get-Date
    OverallStatus  = $OverallStatus
    Passes         = $PassCount
    Informational  = $InfoCount
    Warnings       = $WarningCount
    Failures       = $FailCount
    EventLogPeriod = "$EventLogDays days"
}

# ---------------------------------------------------------------------------
# Write text report
# ---------------------------------------------------------------------------

$TextOutput = @()
$TextOutput += "LENOVO LEGION T5 SYSTEM HEALTH REPORT"
$TextOutput += "Generated: $(Get-Date)"
$TextOutput += "Computer: $env:COMPUTERNAME"
$TextOutput += "Overall result: $OverallStatus"
$TextOutput += ""
$TextOutput += "SUMMARY"
$TextOutput += ($Summary | Format-List | Out-String -Width 220).TrimEnd()
$TextOutput += ""
$TextOutput += "FINDINGS"
$TextOutput += (
    $script:Findings |
        Sort-Object @{
            Expression = {
                switch ($_.Status) {
                    "FAIL"    { 1 }
                    "WARNING" { 2 }
                    "INFO"    { 3 }
                    "PASS"    { 4 }
                }
            }
        }, Category |
        Format-Table -AutoSize -Wrap |
        Out-String -Width 220
).TrimEnd()

$TextOutput += $script:Sections

$TextOutput -join [Environment]::NewLine |
    Set-Content -Path $TextReport -Encoding UTF8

# ---------------------------------------------------------------------------
# Write HTML report
# ---------------------------------------------------------------------------

$Css = @"
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    margin: 24px;
    background: #f4f5f7;
    color: #202124;
}
h1, h2 {
    color: #243447;
}
.summary {
    background: white;
    border-left: 6px solid #4b6b8a;
    padding: 16px;
    margin-bottom: 20px;
}
table {
    border-collapse: collapse;
    width: 100%;
    background: white;
    margin-bottom: 24px;
}
th {
    background: #243447;
    color: white;
    text-align: left;
}
th, td {
    border: 1px solid #d5d9dd;
    padding: 8px;
    vertical-align: top;
}
tr:nth-child(even) {
    background: #f1f3f5;
}
.PASS {
    background: #d9ead3;
}
.INFO {
    background: #d9eaf7;
}
.WARNING {
    background: #fff2cc;
}
.FAIL {
    background: #f4cccc;
    font-weight: bold;
}
pre {
    white-space: pre-wrap;
    background: white;
    border: 1px solid #d5d9dd;
    padding: 12px;
}
</style>
"@

$FindingRows = foreach ($Finding in (
    $script:Findings |
        Sort-Object @{
            Expression = {
                switch ($_.Status) {
                    "FAIL"    { 1 }
                    "WARNING" { 2 }
                    "INFO"    { 3 }
                    "PASS"    { 4 }
                }
            }
        }, Category
)) {
    $SafeStatus = [System.Net.WebUtility]::HtmlEncode($Finding.Status)
    $SafeCategory = [System.Net.WebUtility]::HtmlEncode($Finding.Category)
    $SafeFinding = [System.Net.WebUtility]::HtmlEncode($Finding.Finding)
    $SafeRecommendation = [System.Net.WebUtility]::HtmlEncode(
        $Finding.Recommendation
    )

    @"
<tr class="$SafeStatus">
    <td>$SafeStatus</td>
    <td>$SafeCategory</td>
    <td>$SafeFinding</td>
    <td>$SafeRecommendation</td>
</tr>
"@
}

$DetailedHtml = foreach ($Section in $script:Sections) {
    $SafeSection = [System.Net.WebUtility]::HtmlEncode($Section)
    "<pre>$SafeSection</pre>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Lenovo Legion T5 Health Report</title>
$Css
</head>
<body>
<h1>Lenovo Legion T5 System Health Report</h1>

<div class="summary">
<strong>Computer:</strong> $env:COMPUTERNAME<br>
<strong>Generated:</strong> $(Get-Date)<br>
<strong>Overall status:</strong> $OverallStatus<br>
<strong>Pass:</strong> $PassCount |
<strong>Info:</strong> $InfoCount |
<strong>Warnings:</strong> $WarningCount |
<strong>Failures:</strong> $FailCount
</div>

<h2>Findings</h2>
<table>
<thead>
<tr>
    <th>Status</th>
    <th>Category</th>
    <th>Finding</th>
    <th>Recommendation</th>
</tr>
</thead>
<tbody>
$($FindingRows -join [Environment]::NewLine)
</tbody>
</table>

<h2>Detailed Results</h2>
$($DetailedHtml -join [Environment]::NewLine)

</body>
</html>
"@

$Html | Set-Content -Path $HtmlReport -Encoding UTF8

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Lenovo Legion T5 Health Check Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Overall result : $OverallStatus"
Write-Host "Passes         : $PassCount" -ForegroundColor Green
Write-Host "Information    : $InfoCount" -ForegroundColor Cyan
Write-Host "Warnings       : $WarningCount" -ForegroundColor Yellow
Write-Host "Failures       : $FailCount" -ForegroundColor Red
Write-Host ""
Write-Host "Text report : $TextReport"
Write-Host "HTML report : $HtmlReport"
Write-Host ""

$script:Findings |
    Where-Object { $_.Status -in @("FAIL", "WARNING") } |
    Format-Table Status, Category, Finding -AutoSize -Wrap

try {
    Start-Process $HtmlReport
}
catch {
    Write-Host "Open the HTML report manually: $HtmlReport"
}