# Windows-Defender-Hardening

This script is for Windows Defender security configurations and feature enabling. It begins by elevating privileges and setting the directory to the script's root. The script then copies necessary files to the supported directories and sets process mitigations. It enables various Windows Defender features such as real-time monitoring, cloud-delivered protection, sample submission, behavior monitoring, script scanning, removable drive scanning, and others. The script also sets preferences for various protection mechanisms and parsings. The script outputs status messages for each step, ensuring the user is aware of what actions are being taken.

## What does this script do?
- Enables Cloud-delivered Protections
- Enables Controlled Folder Access
- Enables Network Protections
- Enables Intrusion Prevention System
- [Enables Windows Defender Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control)
- [Enables Windows Defender Attack Surface Reduction Rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
- [Enables Windows Defender Exploit Protections](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide#powershell)
- Implements all requirements listed in the [Windows Defender Antivirus STIG V2R1](https://dl.cyber.mil/stigs/zip/U_MS_Windows_Defender_Antivirus_V2R1_STIG.zip)

## Requirements:
- [x] Windows 10 Enterprise (**Preferred**) or Windows 10 Professional
  - Windows 10 Home does not allow for GPO configurations or [ASR](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction). 
Though most of these configurations will still apply. 
  - Windows 10 "N" Editions are not tested.

## Recommended reading:
- [Microsoft - WDSI Defender Updates](https://www.microsoft.com/en-us/wdsi/defenderupdates)

## Download the required files:

Download the required files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Defender-STIG-Script)

## How to run the script:

**The script may be lauched from the extracted GitHub download like this:**
```
.\sos-windowsdefenderhardening.ps1
```
