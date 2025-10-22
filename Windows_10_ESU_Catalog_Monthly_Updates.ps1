# ====================================================================================================================================================
# SCRIPT NAME:  Windows_10_ESU_Catalog_Monthly_Updates.ps1
# SUPPORTED OS: Windows 10 Version 22H2 x64 and x86 (and ARM64 partially), ESU phase
# AUTHOR:       ardap86
# DATE:         [2025-10-22]
# VERSION:      1.0
# DESCRIPTION:  See README.txt
# ====================================================================================================================================================

$TargetDirectory = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })

# Mapping of MSU installation exit codes
$positiveExitCodeMessages = @{
    "0"       = "SUCCESS - The update was installed successfully."
    "3010"    = "SUCCESS_REBOOT_REQUIRED - Installation succeeded, but a reboot is required."
    "2359301" = "WU_S_REBOOT_REQUIRED - A reboot is required."
    "2359302" = "WU_S_ALREADY_INSTALLED - The update was already installed."
    "2359303" = "WU_S_DOES_NOT_APPLY - The update is not applicable to the system."
}

$negativeExitCodeMessages = @{
    "1"          = "ERROR_INVALID_FUNCTION - Incorrect function (generic failure)."
    "2"          = "ERROR_FILE_NOT_FOUND - The specified update package could not be found."
    "3"          = "ERROR_PATH_NOT_FOUND - The specified path could not be found."
    "5"          = "ERROR_ACCESS_DENIED - Access denied (insufficient privileges)."
    "13"         = "ERROR_INVALID_DATA - Corrupted setup file, delete and download MSU file again."
    "87"         = "ERROR_INVALID_PARAMETER - Invalid command-line argument or parameter."
    "1618"       = "ERROR_INSTALL_ALREADY_RUNNING - Wusa.exe is already running. Only one instance allowed."
    "2145124313" = "WU_E_MISSING_FILE - The update is missing required files or prerequisites."
    "2145124318" = "WU_E_INVALID_UPDATE - The update is not valid or corrupted."
    "2145124320" = "WU_E_DOWNLOADED_FILE_CORRUPT - The downloaded update file is corrupted."
    "2145124329" = "WU_E_NOT_APPLICABLE - The update is not applicable to the system."
    "2147942402" = "ERROR_FILE_NOT_FOUND - File not found (HRESULT form)."
    "2147942487" = "ERROR_INVALID_PARAMETER - Invalid parameter (HRESULT form)."
    "2147943457" = "ERROR_INTERNAL_ERROR - Internal error during installation."
    "2147943860" = "ERROR_INSTALL_ALREADY_RUNNING - Another installation is in progress."
    "2147943869" = "ERROR_UNKNOWN_PRODUCT - The update could not find the product it applies to."
    "2147944001" = "ERROR_INSTALL_SERVICE_FAILURE - Windows Installer service failure."
    "2149842967" = "WU_E_NOT_APPLICABLE - Installation wasn't performed because this is not an applicable update for this system."
}


# BEGIN OF FUNCTIONS

# ====================================================================================================================================================
# FUNCTION: Check for pending restart
# ====================================================================================================================================================
function Confirm-PendingRestart {
    param (
        [switch]$PromptUser = $false
    )
	
    $wuReboot = $null -ne (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue)
    $cbReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $msiReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress"
    $pfRename = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations

    $pfSystemRenames = @()
    if ($pfRename) {
        $pfSystemRenames = $pfRename | Where-Object {
            $_ -match '^(?:\\\?\?\\)?(C:\\Windows|C:\\ProgramData|C:\\Program Files\\Windows|C:\\Program Files \(x86\)\\Windows|C:\\Drivers)' -and
            ($_ -notmatch '\\Temp\\' -and $_ -notmatch '\\scoped_dir' -and $_ -notmatch '\\Microsoft\\Edge\\')
        }
    }

    $pfReboot = ($pfSystemRenames.Count -gt 0)
    $rebootPending = $wuReboot -or $cbReboot -or $msiReboot -or $pfReboot
    
    if ($rebootPending) {
        Write-Host "[WARNING] A restart is pending." -ForegroundColor Yellow
        if ($PromptUser) {
            $response = Read-Host "Do you want to restart now? (y/n)"
            if ($response.Trim() -ieq 'y') {
                Stop-Transcript -ErrorAction SilentlyContinue
                Write-Host "[INFO] Restarting now..." -ForegroundColor Cyan
                Start-Sleep -Milliseconds 500
                Restart-Computer -Force
            }
            else {
                Write-Host "[INFO] Please restart later. Exiting script." -ForegroundColor Yellow
            }
        }
        return $true
    }
    else {
        Write-Host "[SUCCESS] No pending restart detected." -ForegroundColor Green
        return $false
    }
}

# ====================================================================================================================================================
# FUNCTION: Get download dialog response from Microsoft Update Catalog
# ====================================================================================================================================================
function Get-UpdateCatalogResponse {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UpdateId
    )

    # Prepare POST payload
    $postUrl = "https://catalog.update.microsoft.com/DownloadDialog.aspx"
    $payload = "updateIDs=[{""size"":0,""updateID"":""$UpdateId"",""uidInfo"":""$UpdateId""}]"
    $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }

    try {
        $response = Invoke-WebRequest -Uri $postUrl -Method POST -Body $payload -Headers $headers
        $responseText = $response.Content
        Write-Host "[SUCCESS] Download dialog response retrieved for Update ID $UpdateId" -ForegroundColor Green
        return $responseText
    }
    catch {
        Write-Host "[ERROR] Failed to get download link(s) for Update ID {$UpdateId}: $_" -ForegroundColor White -BackgroundColor Red
        return $null
    }
}

# ====================================================================================================================================================
# FUNCTION: Extract MSU links from HTML response
# ====================================================================================================================================================
function Get-MSUUrlsFromResponse {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResponseHtml,
        [string]$type
    )

    $patternCatalogMsu = ""

    if ($type -eq "NET") {
        $patternCatalogMsu = "https://catalog\.s\.download\.windowsupdate\.com/.*ndp481_.*\.msu"
    }
    elseif ($type -eq "Security") {
        $patternCatalogMsu = "https://catalog\.s\.download\.windowsupdate\.com/.*\.msu"
    }

    $match = [regex]::Match($ResponseHtml, $patternCatalogMsu)

    if ($match.Success) {
        $msuUrl = $match.Value
        Write-Host "[SUCCESS] Found MSU update file: $msuUrl" -ForegroundColor Green
        return $msuUrl
    }
    else {
        Write-Host "[WARNING] No valid MSU download links found in the HTML response." -ForegroundColor Yellow
        return $null
    }
}

# ====================================================================================================================================================
# FUNCTION: Download and install MSU update
# ====================================================================================================================================================
function Install-MSUUpdate {
    param (
        [Parameter(Mandatory = $true)][string]$msuUrl
    )

    $msuFile = [System.IO.Path]::GetFileName($msuUrl)
    $msuPath = Join-Path -Path $TargetDirectory -ChildPath $msuFile

    # -------------------------------
    # Step 1: Check if update was already installed
    # -------------------------------
    $kbMatch = [regex]::Match($msuFile, "kb\d{7}", "IgnoreCase")
    $kbNumberId = $null

    if ($kbMatch.Success) {
        $kbNumber = $kbMatch.Value.ToUpper()
        $kbNumberId = [regex]::Match($kbNumber, "\d{7}").Value
        $installed = Get-HotFix -Id $kbNumber -ErrorAction SilentlyContinue

        if (-not $installed) {
            $installed = dism /online /get-packages | Out-String | Select-String $kbNumber
        }

        if ($installed) {
            Write-Host "[SUCCESS] Update $kbNumber was already installed, skipping..." -ForegroundColor White -BackgroundColor DarkGreen
            Write-Host "[INFO] Support information about this update: https://support.microsoft.com/help/$kbNumberId" -ForegroundColor Magenta
            return $null
        }
    }

    # -------------------------------
    # Step 2: Download MSU if missing
    # -------------------------------
    if (-not (Test-Path $msuPath)) {
        Write-Host ""
        Write-Host "[INFO] Downloading MSU file, please wait..." -ForegroundColor Cyan
        try {
            $bitsService = Get-Service -Name BITS -ErrorAction SilentlyContinue

            if ($bitsService) {
                try {
                    Start-BitsTransfer -Source $msuUrl -Destination $msuPath -ErrorAction Stop -DisplayName "Downloading $msuPath"
                } 
                catch [System.Runtime.InteropServices.COMException] {
                    Write-Host "[ERROR] BITS transfer failed due to a COM error: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
                    Write-Host "[INFO] Check internet connection and run script again." -ForegroundColor Cyan
                }
                catch {
                    Write-Host "[ERROR] An unexpected error occurred during BITS transfer: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
                    Write-Host "[INFO] Check internet connection and run script again." -ForegroundColor Cyan
                }
            }
            else {
                Write-Host "[INFO] BITS service not running or cannot start. Using Invoke-WebRequest..." -ForegroundColor Yellow
                Invoke-WebRequest -Uri $msuUrl -OutFile $msuPath
            }

            Write-Host "[SUCCESS] Download completed: $msuPath" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to download {$msuPath}: $_" -ForegroundColor White -BackgroundColor Red
            return $null
        }
    }
    else {
        Write-Host "[INFO] File already exists, skipping download of $msuFile" -ForegroundColor Cyan
    }

    # -------------------------------
    # Step 3: Install MSU
    # -------------------------------
    try {
        Write-Host ""
        Write-Host "[INFO] Installing update $msuFile - This can take several minutes, please wait..." -ForegroundColor Cyan

        $installProcess = Start-Process -FilePath "wusa.exe" -ArgumentList "/quiet", "/norestart", $msuPath -Wait -PassThru
        $exitCode = $installProcess.ExitCode

        $normalizedCode = if ($exitCode -lt 0) { [uint32]($exitCode + 0x100000000) } else { $exitCode }
        $hexCode = ('0x{0:X8}' -f $normalizedCode)
        $normalizedKey = $normalizedCode.ToString()

        if ($positiveExitCodeMessages.ContainsKey($normalizedKey)) {
            Write-Host "[SUCCESS] Exit code $normalizedCode ($hexCode): $($positiveExitCodeMessages[$normalizedKey])" -ForegroundColor White -BackgroundColor DarkGreen
            Remove-Item -Path $msuPath -Force -ErrorAction SilentlyContinue
        }
        elseif ($negativeExitCodeMessages.ContainsKey($normalizedKey)) {
            Write-Host "[ERROR] Exit code $normalizedCode ($hexCode): $($negativeExitCodeMessages[$normalizedKey])" -ForegroundColor White -BackgroundColor Red

            # Delete corrupt MSU to avoid repeated failures
            if ($normalizedKey -eq "2145124320") {
                Write-Host "[INFO] Deleting corrupted MSU file: $msuPath" -ForegroundColor Yellow
                Remove-Item -Path $msuPath -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-Host "[INFO] Exit code $normalizedCode ($hexCode): Unknown exit code" -ForegroundColor Yellow
        }
    }
    catch [System.InvalidOperationException] {
        Write-Host "[WARNING] Installation was cancelled or blocked by UAC (User Account Control) pop-up window." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[ERROR] Unexpected error during installation: $_" -ForegroundColor White -BackgroundColor Red
    }

    if ($kbNumberId) {
        Write-Host "[INFO] Support information about this update: https://support.microsoft.com/help/$kbNumberId" -ForegroundColor Magenta
    }
}
# END OF FUNCTIONS


# ---------------------------
# BEGIN SCRIPT LOGGING
# ---------------------------
$logDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$logFile = Join-Path -Path $logDir -ChildPath "UpdateLog.txt"
Start-Transcript -Path "$logFile" -Append

Write-Host "`n=======================================================================================================================`n" -ForegroundColor Gray
Write-Host "`nWindows update catalog - Automated download and installation script - Only for Windows 10 22H2 x64, x86 and ARM64 (ESU)`n" -ForegroundColor Gray
Write-Host "`n=======================================================================================================================`n" -ForegroundColor Gray

try {
    # ====================================================================================================================================================
    # PRE-PRE-CHECK: Checking architecture and windows build version 
    # ====================================================================================================================================================
    $supportedUpdateArchNET = "x86", "x64"                # .NET Framework updates supported only for x86 and x64
    $supportedUpdateArchSecurity = "x86", "x64", "ARM64"  # Security updates additionally supported for ARM64

    if ([Environment]::Is64BitOperatingSystem) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }

        switch ($arch.ToLower()) {
            "amd64" { $updateArch = "x64" }
            "arm64" { $updateArch = "ARM64" }
            default { $updateArch = "Unknown" }
        }
    }
    else {
        $updateArch = "x86"
    }

    # Check if the system architecture is supported by the script
    if ($updateArch -notin $supportedUpdateArchSecurity) {
        Write-Host "[WARNING] This script supports only Windows 10 running on 32-bit (x86), 64-bit (x64), or ARM64." -ForegroundColor Yellow
    }

    $build = [System.Environment]::OSVersion.Version.Build

    switch ($build) {
        19045 { 
            Write-Host "[INFO] Detected: Windows 10 22H2 $updateArch (Build 19045), continuing..." -ForegroundColor Green
            break
        }

        7600 { Write-Host "[INFO] Detected: Windows 7 $updateArch (Build 7600)" -ForegroundColor Cyan; break }
        7601 { Write-Host "[INFO] Detected: Windows 7 SP1 $updateArch (Build 7601)" -ForegroundColor Cyan; break }
        9200 { Write-Host "[INFO] Detected: Windows 8 $updateArch (Build 9200)" -ForegroundColor Cyan; break }
        9600 { Write-Host "[INFO] Detected: Windows 8.1 $updateArch (Build 9600)" -ForegroundColor Cyan; break }
        10240 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1507 (Build 10240)" -ForegroundColor Cyan; break }
        10586 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1511 (Build 10586)" -ForegroundColor Cyan; break }
        14393 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1607 (Build 14393)" -ForegroundColor Cyan; break }
        15063 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1703 (Build 15063)" -ForegroundColor Cyan; break }
        16299 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1709 (Build 16299)" -ForegroundColor Cyan; break }
        17134 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1803 (Build 17134)" -ForegroundColor Cyan; break }
        17763 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1809 (Build 17763)" -ForegroundColor Cyan; break }
        18362 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1903 (Build 18362)" -ForegroundColor Cyan; break }
        18363 { Write-Host "[INFO] Detected: Windows 10 $updateArch 1909 (Build 18363)" -ForegroundColor Cyan; break }
        19041 { Write-Host "[INFO] Detected: Windows 10 $updateArch 2004 (Build 19041)" -ForegroundColor Cyan; break }
        19042 { Write-Host "[INFO] Detected: Windows 10 $updateArch 20H2 (Build 19042)" -ForegroundColor Cyan; break }
        19043 { Write-Host "[INFO] Detected: Windows 10 $updateArch 21H1 (Build 19043)" -ForegroundColor Cyan; break }
        19044 { Write-Host "[INFO] Detected: Windows 10 $updateArch 21H2 (Build 19044)" -ForegroundColor Cyan; break }
        22000 { Write-Host "[INFO] Detected: Windows 11 $updateArch 21H2 (Build 22000)" -ForegroundColor Cyan; break }
        22621 { Write-Host "[INFO] Detected: Windows 11 $updateArch 22H2 (Build 22621)" -ForegroundColor Cyan; break }
        22631 { Write-Host "[INFO] Detected: Windows 11 $updateArch 23H2 (Build 22631)" -ForegroundColor Cyan; break }
        26100 { Write-Host "[INFO] Detected: Windows 11 $updateArch 24H2 (Build 26100)" -ForegroundColor Cyan; break }
        26200 { Write-Host "[INFO] Detected: Windows 11 $updateArch 25H2 (Build 26200)" -ForegroundColor Cyan; break }

        Default {
            Write-Host "[WARNING] Unknown or unsupported Windows version detected (Build $build) $updateArch." -ForegroundColor Yellow
            exit
        }
    }

    # Exit early if not Windows 10 22H2 (Build 19045)
    if ($build -ne 19045) {
        # Info regarding required enablement package update from 21H2 to 22H2 (not available in Windows update catalog)
        if ($build -eq 19044) {
            Write-Host "[INFO] Please manually download and install windows10.0-kb5015684-$updateArch.msu to update from version 21H2 to 22H2." -ForegroundColor Yellow
            Write-Host "[INFO] Support information about this update: https://support.microsoft.com/help/5015684" -ForegroundColor Magenta
        }
        Write-Host "[WARNING] Only Windows 10 22H2 (Build 19045) is supported, exiting script." -ForegroundColor Yellow
        exit
    }

    # ====================================================================================================================================================
    # PRE-CHECK: Pending Restart and check for KB5011048 as pre-requisite for subsequent .NET Framework 4.8.1 updates
    # ====================================================================================================================================================
    Write-Host "`n[PRE-CHECK] Checking if a system restart is pending..." -ForegroundColor Gray

    $restartPending = Confirm-PendingRestart -PromptUser

    if ($restartPending) { 
        exit
    }

    # .NET Framework updates are not done/available for ARM64 and therefore skipped
    if ($updateArch -in $supportedUpdateArchNET) {
        $KB5011048 = "KB5011048" # This is the update from 4.8 to 4.8.1
        $installed = Get-HotFix -Id $KB5011048 -ErrorAction SilentlyContinue

        if (-not $installed) {
            $installed = dism /online /get-packages | Out-String | Select-String $KB5011048
        }

        if (-not $installed) {

            $release = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue).Release

            if ($release -and $release -lt 533000) {
                if ($updateArch -eq "x64") {
                    $msuUrlNet481 = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/ftpk/2023/09/windows10.0-$KB5011048-x64_411d40ab5705c99f2bdb576ad3dc3e6ec0f3902e.msu"
                }
                else {
                    $msuUrlNet481 = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/ftpk/2023/09/windows10.0-$KB5011048-x86_74a24b713a0af00a9d437c06904e2f5237fd96c9.msu"
                }

                $msuFileNet481 = [System.IO.Path]::GetFileName($msuUrlNet481)
                $msuPathNet481 = Join-Path -Path $TargetDirectory -ChildPath $msuFileNet481


                if (-not (Test-Path $msuPathNet481)) {
                    Write-Host ""
                    Write-Host "[INFO] Missing $KB5011048 (.NET Framework update from v4.8 to v4.8.1) as pre-requisite for future updates will be checked first..." -ForegroundColor Cyan
                    Write-Host "[INFO] MSU file located at $msuUrlNet481" -ForegroundColor Cyan
                    Write-Host "[INFO] Downloading MSU file, please wait..." -ForegroundColor Cyan

                    try {
                        $bitsService = Get-Service -Name BITS -ErrorAction SilentlyContinue

                        if ($bitsService) {
                            try {
                                Start-BitsTransfer -Source $msuUrlNet481 -Destination $msuPathNet481 -ErrorAction Stop -DisplayName "Downloading $msuPathNet481"
                            } 
                            catch [System.Runtime.InteropServices.COMException] {
                                Write-Host "[ERROR] BITS transfer failed due to a COM error: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
                                Write-Host "[INFO] Check internet connection and run script again." -ForegroundColor Cyan
                            }
                            catch {
                                Write-Host "[ERROR] An unexpected error occurred during BITS transfer: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
                                Write-Host "[INFO] Check internet connection and run script again." -ForegroundColor Cyan
                            }
                        } 
                        else {
                            Write-Host "[INFO] BITS service not running or cannot start. Using Invoke-WebRequest..." -ForegroundColor Yellow
                            Invoke-WebRequest -Uri $msuUrlNet481 -OutFile $msuPathNet481
                        }

                        Write-Host "[SUCCESS] Download completed: $msuPathNet481" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[ERROR] Failed to download {$msuPathNet481}: $_" -ForegroundColor White -BackgroundColor Red
                        return $null
                    }
                } 
                else {
                    Write-Host "[INFO] File already exists, skipping download of $msuFileNet481" -ForegroundColor Cyan
                }


                try {
                    Write-Host "[INFO] Installing update $msuFileNet481 - This can take several minutes, please wait..." -ForegroundColor Cyan

                    $installProcess = Start-Process -FilePath "wusa.exe" -ArgumentList "/quiet", "/norestart", $msuPathNet481 -Wait -PassThru
                    $exitCode = $installProcess.ExitCode

                    $normalizedCode = if ($exitCode -lt 0) { [uint32]($exitCode + 0x100000000) } else { $exitCode }
                    $hexCode = ('0x{0:X8}' -f $normalizedCode)
                    $normalizedKey = $normalizedCode.ToString()

                    if ($positiveExitCodeMessages.ContainsKey($normalizedKey)) {
                        Write-Host "[SUCCESS] Exit code $normalizedCode ($hexCode): $($positiveExitCodeMessages[$normalizedKey])" -ForegroundColor White -BackgroundColor DarkGreen
                        Remove-Item -Path $msuPathNet481 -Force -ErrorAction SilentlyContinue
                    }
                    elseif ($negativeExitCodeMessages.ContainsKey($normalizedKey)) {
                        Write-Host "[ERROR] Exit code $normalizedCode ($hexCode): $($negativeExitCodeMessages[$normalizedKey])" -ForegroundColor White -BackgroundColor Red

                        # Delete corrupt MSU to avoid repeated failures
                        if ($normalizedKey -eq "2145124320") {
                            Write-Host "[INFO] Deleting corrupted MSU file: $msuPathNet481" -ForegroundColor Yellow
                            Remove-Item -Path $msuPathNet481 -Force -ErrorAction SilentlyContinue
                        }
                    }
                    else {
                        Write-Host "[INFO] Exit code $normalizedCode ($hexCode): Unknown exit code" -ForegroundColor Yellow
                    }
                }
                catch [System.InvalidOperationException] {
                    Write-Host "[WARNING] Installation was cancelled or blocked by UAC (User Account Control) pop-up window." -ForegroundColor Yellow
                }
                catch {
                    Write-Host "[ERROR] Unexpected error during installation: $_" -ForegroundColor White -BackgroundColor Red
                }

            }
        }

        # ====================================================================================================================================================
        # Step 1: Set search URL for .NET Framework updates and get HTML data
        # ====================================================================================================================================================
        Write-Host "`n[STEP 1/6] Getting HTML data about available .NET Framework security updates for Windows 10 22H2 $updateArch..." -ForegroundColor Gray

        if ($updateArch -eq "x64") {
            $searchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=%22cumulative%20update%20for%20.net%20framework%203.5%2C%204.8%20and%204.8.1%20for%20windows%2010%20version%2022h2%20for%20x64%22"
        }
        else {
            $searchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=-x64%22cumulative%20update%20for%20.net%20framework%203.5%2C%204.8%20and%204.8.1%20for%20windows%2010%20version%2022h2%22"
        }

        Write-Host "[INFO] Using following search URL to find latest monthly .NET Framework security update: $searchUrl" -ForegroundColor Cyan

        try {
            $searchResponse = Invoke-WebRequest -Uri $searchUrl
            $searchHtml = $searchResponse.Content
            Write-Host "[SUCCESS] Search page retrieved." -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve search page: $_" -ForegroundColor White -BackgroundColor Red
            exit
        }

        # ====================================================================================================================================================
        # Step 2: Extract latest (i.e. first/topmost) .NET Framework update ID
        # ====================================================================================================================================================
        Write-Host "`n[STEP 2/6] Extracting latest .NET Framework security update ID..." -ForegroundColor Gray

        $updateId = $null
        $rowPattern = '<input[^>]+id="(?<GUID>[0-9a-fA-F-]{36})"[^>]+class="flatBlueButtonDownload\s+focus-only"'
        $match = [regex]::Match($searchHtml, $rowPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

        if ($match.Success) {
            $updateId = $match.Groups["GUID"].Value.Trim()
            Write-Host "[SUCCESS] The latest .NET Framework security update ID is: $updateId" -ForegroundColor Green
        }
        else {
            Write-Host "[ERROR] Failed to extract update ID." -ForegroundColor White -BackgroundColor Red
            exit
        }

        # ====================================================================================================================================================
        # Step 3: Prepare and send POST request to get download links and install MSU files if available
        # ====================================================================================================================================================
        if (-not $updateId) {
            Write-Host "[ERROR] No security update ID found. Exiting." -ForegroundColor White -BackgroundColor Red
            exit
        } 
        else {
            Write-Host "`n[STEP 3/6] Retrieving download link, downloading and installing update..." -ForegroundColor Gray
            $responseHtml = Get-UpdateCatalogResponse -UpdateId $updateId

            if ($responseHtml) {
                $msuUrl = Get-MSUUrlsFromResponse -ResponseHtml $responseHtml -type "NET"
                if ($msuUrl) {
                    Install-MSUUpdate -msuUrl $msuUrl
                }
                else {
                    Write-Host "[ERROR] Could not find MSU download link for .NET Framework 4.8.1. Continuing with monthly cumulative security update..." -ForegroundColor White -BackgroundColor Red
                }
            }
        }
    }
    else {
        Write-Host "[INFO] .NET Framework updates are not available for ARM64, skipping STEP[1-3/6]..." -ForegroundColor Cyan
    }

    # ====================================================================================================================================================
    # Step 4: Set search URL and get HTML data from monthly cumulative security update
    # ====================================================================================================================================================
    Write-Host "`n[STEP 4/6] Getting HTML data about available monthly cumulative security updates for Windows 10 22H2 $updateArch..." -ForegroundColor Gray

    if ($updateArch -eq "x64") {
        $searchUrl = "https://catalog.update.microsoft.com/Search.aspx?q=-dynamic%20%22cumulative%20update%20for%20windows%2010%20version%2022h2%20for%20x64-based%20systems%22"
    }
    elseif ($updateArch -eq "x86") {
        $searchUrl = "https://catalog.update.microsoft.com/Search.aspx?q=-dynamic%20%22cumulative%20update%20for%20windows%2010%20version%2022h2%20for%20x86-based%20systems%22"
    }
    else {
        $searchUrl = "https://catalog.update.microsoft.com/Search.aspx?q=-dynamic%20%22cumulative%20update%20for%20windows%2010%20version%2022h2%20for%20ARM64-based%20systems%22"
    }

    Write-Host "[INFO] Using following search URL to find latest monthly cumulative security update: $searchUrl" -ForegroundColor Cyan

    try {
        $searchResponse = Invoke-WebRequest -Uri $searchUrl
        $searchHtml = $searchResponse.Content
        Write-Host "[SUCCESS] Search page retrieved." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve search page: $_" -ForegroundColor White -BackgroundColor Red
        exit
    }

    # ====================================================================================================================================================
    # Step 5: Extract latest (i.e. first/topmost) monthly cumulative security update ID
    # ====================================================================================================================================================
    Write-Host "`n[STEP 5/6] Extracting latest monthly cumulative security update ID..." -ForegroundColor Gray

    $updateId = $null
    $rowPattern = '<tr[^>]*id="(?<RowID>[^"]+)"[^>]*>.*?<td[^>]*id="[^"]+_C3_[^"]*"[^>]*>\s*(?<Classification>[^<]+)\s*</td>.*?<input\s+id="(?<GUID>[0-9a-fA-F-]+)"[^>]*value=''.+?'''
    $regexMatches = [regex]::Matches($searchHtml, $rowPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    foreach ($idMatch in $regexMatches) {
        $classification = $idMatch.Groups["Classification"].Value.Trim()
        if ($classification -match "security") {
            $updateId = $idMatch.Groups["GUID"].Value.Trim()
            Write-Host "[SUCCESS] The latest monthly cumulative security update ID is: $updateId" -ForegroundColor Green
            break
        }
    }

    # ====================================================================================================================================================
    # Step 6: Prepare and send POST request to get download links and install MSU files if available
    # ====================================================================================================================================================
    if (-not $updateId) {
        Write-Host "[ERROR] No security update ID found. Exiting." -ForegroundColor White -BackgroundColor Red
        exit
    } 
    else {
        Write-Host "`n[STEP 6/6] Retrieving download link, downloading and installing update..." -ForegroundColor Gray
        $responseHtml = Get-UpdateCatalogResponse -UpdateId $updateId

        if ($responseHtml) {
            $msuUrl = Get-MSUUrlsFromResponse -ResponseHtml $responseHtml -type "Security"
            if ($msuUrl) {
                Install-MSUUpdate -msuUrl $msuUrl
            }
            else {
                Write-Host "[ERROR] Could not find MSU download link for security update. Exiting." -ForegroundColor White -BackgroundColor Red
                exit
            }
        }
    }

    # ====================================================================================================================================================
    # POST-CHECK: Check reboot requirement
    # ====================================================================================================================================================
    Write-Host "`n[POST-CHECK] Checking if a system restart is required..." -ForegroundColor Gray

    $restartPending = Confirm-PendingRestart -PromptUser

    Write-Host ""

    if ($restartPending) { 
        exit
    }
}
finally {
    # ---------------------------
    # END SCRIPT LOGGING
    # ---------------------------
    Stop-Transcript -ErrorAction SilentlyContinue
}
