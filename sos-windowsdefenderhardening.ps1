# Continue on error
$ErrorActionPreference = 'silentlycontinue'

# Require elevation for script run
Write-Output "Elevating privileges for this process"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"")
    exit
}

# Set Directory to PSScriptRoot
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "Enabling Windows Defender Protections and Features" -ForegroundColor Green -BackgroundColor Black

Write-Host "Copying Files to Supported Directories"
# Windows Defender Configuration Files
$destinationDir = "C:\temp\Windows Defender"
mkdir $destinationDir -Force | Out-Null
Copy-Item -Path "$scriptPath\Files\Windows Defender Configuration Files\*" -Destination $destinationDir -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Enabling Windows Defender Exploit Protections..."
# Enable Windows Defender Exploit Protection
$policyFilePath = Join-Path $destinationDir "DOD_EP_V3.xml"
Set-ProcessMitigation -PolicyFilePath $policyFilePath

$policyPath = Join-Path $destinationDir "CIP\WDAC_V1_Recommended_Audit\*.cip"
# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
$refreshPolicyTool = "$scriptPath\Files\EXECUTABLES\RefreshPolicy(AMD64).exe"
Get-ChildItem -Recurse $policyPath | ForEach-Object {
    $policyBinary = $_.FullName
    $destinationFolder = "$env:windir\System32\CodeIntegrity\CIPolicies\Active\"
    Copy-Item -Path $policyBinary -Destination $destinationFolder -Force
    & $refreshPolicyTool
}

Write-Host "Enabling Windows Defender Features..."
#https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
#https://social.technet.microsoft.com/wiki/contents/articles/52251.manage-windows-defender-using-powershell.aspx
#https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
# Enable Windows Defender features
$mpPreference = Get-MpPreference
$mpPreference.DisableRealtimeMonitoring = $false
$mpPreference.MAPSReporting = "Advanced"
$mpPreference.SubmitSamplesConsent = "Always"
$mpPreference.CheckForSignaturesBeforeRunningScan = 1
$mpPreference.DisableBehaviorMonitoring = $false
$mpPreference.DisableIOAVProtection = $false
$mpPreference.DisableScriptScanning = $false
$mpPreference.DisableRemovableDriveScanning = $false
$mpPreference.DisableBlockAtFirstSeen = $false
$mpPreference.PUAProtection = 1
$mpPreference.DisableArchiveScanning = $false
$mpPreference.DisableEmailScanning = $false
$mpPreference.EnableFileHashComputation = $true
$mpPreference.DisableIntrusionPreventionSystem = $false
$mpPreference.DisableSshParsing = $false
$mpPreference.DisableDnsParsing = $false
$mpPreference.DisableDnsOverTcpParsing = $false
$mpPreference.EnableDnsSinkhole = $true
$mpPreference.EnableControlledFolderAccess = "Enabled"
$mpPreference.EnableNetworkProtection = "Enabled"
$mpPreference.MP_FORCE_USE_SANDBOX = 1
$mpPreference.CloudBlockLevel = "High"
$mpPreference.CloudExtendedTimeout = 50
$mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false
$mpPreference.DisableArchiveScanningAlternateDataStream = $false
$mpPreference.DisableBehaviorMonitoringAlternateDataStream = $false
$mpPreference.ScanArchiveFilesWithPassword = $true
$mpPreference.ScanDownloads = 2
$mpPreference.ScanNetworkFiles = 2
$mpPreference.ScanIncomingMail = 2
$mpPreference.ScanMappedNetworkDrivesDuringFullScan = $true
$mpPreference.ScanRemovableDrivesDuringFullScan = $true
$mpPreference.ScanScriptsLoadedInInternetExplorer = $true
$mpPreference.ScanScriptsLoadedInOfficeApplications = $true
$mpPreference.ScanSubDirectoriesDuringQuickScan = $true
$mpPreference.ScanRemovableDrivesDuringQuickScan = $true
$mpPreference.ScanMappedNetworkDrivesDuringQuickScan = $true
$mpPreference.DisableBehaviorMonitoringMemoryDoubleFree = $false
$mpPreference.DisableBehaviorMonitoringNonSystemSigned = $false
$mpPreference.DisableBehaviorMonitoringUnsigned = $false
$mpPreference.DisableBehaviorMonitoringPowershellScripts = $false
$mpPreference.DisableBehaviorMonitoringNonMsSigned = $false
$mpPreference.DisableBehaviorMonitoringNonMsSystem = $false
$mpPreference.DisableBehaviorMonitoringNonMsSystemProtected = $false
$mpPreference.EnableControlledFolderAccessMemoryProtection = $true
$mpPreference.EnableControlledFolderAccessNonScriptableDlls = $true
$mpPreference.EnableControlledFolderAccessNonMsSigned = $true
$mpPreference.EnableControlledFolderAccessNonMsSystem = $true
$mpPreference.EnableControlledFolderAccessNonMsSystemProtected = $true
$mpPreference.ScanRemovableDriveDuringFullScan = $true
$mpPreference.ScanNetworkFilesDuringFullScan = $true
$mpPreference.ScanNetworkFilesDuringQuickScan = $true
$mpPreference.EnableNetworkProtectionRealtimeInspection = $true
$mpPreference.EnableNetworkProtectionExploitInspection = $true
$mpPreference.EnableNetworkProtectionControlledFolderAccessInspection = $true
$mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false
$mpPreference.SignatureDisableUpdateOnStartupWithoutEngine = $false

Set-MpPreference -PreferenceObject $mpPreference

Write-Host "Windows Defender Protections and Features have been enabled successfully!" -ForegroundColor Green

Write-Host "Disabling Account Prompts"
$accountProtectionKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State\AccountProtection_MicrosoftAccount_Disconnected"
if (!(Test-Path -Path $accountProtectionKeyPath)) {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType DWORD -Value 1 -Force
} else {
    Set-ItemProperty -Path $accountProtectionKeyPath -Name "AccountProtection_MicrosoftAccount_Disconnected" -Value 1
}

Write-Host "Enabling Cloud-delivered Protections"
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Write-Host "Enabling Windows Defender Attack Surface Reduction Rules"
$asrRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    #Still technically in beta
    #"33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
    #"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
    #"a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
}


foreach ($ruleId in $asrRules.Keys) {
    Write-Host " - $($asrRules[$ruleId])"
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
}

Write-Host "Enabling Windows Defender Group Policy Settings"
Start-Process -NoNewWindow -FilePath ".\Files\LGPO\LGPO.exe" -ArgumentList "/g .\Files\GPO\" -Wait

Write-Host "Updating Signatures..."
Update-MpSignature -UpdateSource MicrosoftUpdateServer
Update-MpSignature -UpdateSource MMPC

Write-Host "Printing Current Windows Defender Configuration"
Get-MpComputerStatus
Get-MpPreference
Get-MpThreat
Get-MpThreatDetection

Write-Host "Starting Full Scan and removing any known threats..."
Start-MpScan -ScanType FullScan

Write-Host "Removing Active Threats From System"
Remove-MpThreat
