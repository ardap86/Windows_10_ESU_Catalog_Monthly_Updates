SCRIPT NAME:  Windows_10_ESU_Catalog_Monthly_Updates.ps1
SUPPORTED OS: Windows 10 Version 22H2 x64 and x86 (and ARM64 partially), ESU phase
AUTHOR:       ardap86
DATE:         [2025-10-22]
VERSION:      1.0

DESCRIPTION:
  Automates the retrieval, download, and installation of the latest available monthly cumulative security and .NET Framework updates (.msu files) 
  from the official Windows update catalog for Windows 10 22H2 during the ESU (Extended Security Updates) phase for any language

HOW TO USE:
 • Extract Windows_10_ESU_Catalog_Monthly_Updates_v1.0.zip to any folder on any drive
 • Execute run_Windows_10_ESU_Catalog_Monthly_Updates.cmd

FEATURES:
  • Aborts if run on unsupported Windows version
  • Retrieves and installs latest final .NET Framework 4.8.1 update (ignores previews)
    • This applies only to x64 and x86. ARM64 will skip these updates
    • If version 4.8 is still installed, it will be automatically updated to 4.8.1 first
    • Note that not every month a new final .NET Framework update is released
  • Retrieves and installs latest final monthly cumulative security update (ignores previews and out-of-band releases)
    • This applies to x64, x86 and ARM64
  • Malicious Software Removal Tool and Defender Definitions still should be downloaded automatically using Windows Update without ESU license
  • Checks if the updates are already installed (via WMI and DISM) before download
  • Avoids re-downloading of updates that were not installed yet and which are already available in the same directory 
  • Automatically deletes the downloaded .msu file after successful installation
  • Asks user for confirmation in case a reboot is required
  • Creates/Extends UpdateLog.txt file in current directory including the script output. Can be deleted if not needed
  • Works for all account types, including standard/local users (no Microsoft account and WSUS required)
  • No licensing changes are done, it does not require the ESU license

NOTES:
  • Requires PowerShell 5.1+ (i.e. default on Windows 10 22H2)
  • Requires internet access for downloading update metadata and .msu packages
  • Administrative privileges are optional (but if applied, then potential UAC dialog during installation are avoided)
  • There is no progress indicator during update installation in the terminal window
    • But potentially monitor running process TiWorker.exe (TrustedInstaller Worker) in the task manager
    • But potentially monitor and refresh installer log at "C:\Windows\Logs\CBS\CBS.log" to see progress
  • Inspecting the installed updates in the windows update history will not display the package type ('cumulative monthly' or '.NET') and date
    • This is normal, as this information is not available inside the .msu files
  • Script expected to remain functional until at least October 2028 and maybe until January 2032 if the LTSC updates will be applicable then
  • Run this script every second Wednesday of the month or later to get the latest monthly updates

DISCLAIMER:
  Use at your own risk. This script is provided "as is" without warranty of any kind - Always test in a controlled environment before deployment
