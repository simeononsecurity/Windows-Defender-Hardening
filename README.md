# Windows-Defender-Hardening

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

## Download the required files:

Download the required files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Defender-STIG-Script)

## How to run the script:

**The script may be lauched from the extracted GitHub download like this:**
```
.\sos-windowsdefenderhardening.ps1
```
