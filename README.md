# Windows Defender Hardening

Apply supported Microsoft Defender preferences and attack surface reduction (ASR) rules, verify effective settings, and retain a recovery snapshot.

## Requirements

- Windows with Microsoft Defender and the Defender PowerShell module available.
- Elevated Windows PowerShell 5.1 or PowerShell 7 with access to Defender commands.
- Test on a disposable Windows system matching your target build before deployment.
- Domain policy, MDM, and tamper protection might prevent changes. A failed verification returns a nonzero exit code. Review the saved backup before recovery.

## Apply

Extract the repository and run from an elevated PowerShell window:

```powershell
.\sos-windowsdefenderhardening.ps1 -WhatIf
.\sos-windowsdefenderhardening.ps1 -BackupPath C:\Recovery\defender-before.json
```

The default applies antivirus preferences and puts network protection, controlled folder access, and the supplied ASR rules into audit mode. Existing ASR rules outside this collection remain in the desired configuration.

Use block mode after reviewing audit events and application compatibility:

```powershell
.\sos-windowsdefenderhardening.ps1 -ProtectionMode Block -BackupPath C:\Recovery\defender-before-block.json
```

Each application requires a new backup path. Existing backups are never overwritten. The default location is a timestamped JSON file under `%ProgramData%\SoS-Defender`.

Settings unavailable in the installed command or preference object are reported and skipped. ASR command support is required. The script verifies every requested supported setting and the resulting ASR rule set before reporting completion.

## Export and restore

```powershell
.\sos-windowsdefenderhardening.ps1 -Mode Export -BackupPath C:\Recovery\defender-export.json
.\sos-windowsdefenderhardening.ps1 -Mode Restore -BackupPath C:\Recovery\defender-before.json -WhatIf
.\sos-windowsdefenderhardening.ps1 -Mode Restore -BackupPath C:\Recovery\defender-before.json
```

Export reads configuration without changing Defender. Restore reapplies the saved managed preferences and the complete saved ASR list, including an originally empty list. Changes to those settings after the snapshot are replaced. Other Defender preferences are outside the restore scope. Keep backups local to the source machine and review before restoring.

A partial application failure retains the snapshot. Fix the blocking policy or capability problem, then restore from the recorded path. Restoration also verifies effective settings and reports failures.

## Migration and scope

This version replaces unsupported `Set-MpPreference -PreferenceObject` calls with capability-checked named parameters. It removes automatic full scans, threat removal, account-prompt registry changes, and implicit imports of bundled LGPO, exploit-protection, and WDAC policies from the default operation. Those operations lacked complete snapshot and recovery coverage and are separate from verified Defender preferences. Existing files remain available for manual review.

Earlier executions have no recovery snapshot from this version. Export records the current state, not the state before an older script ran. Do not describe a fresh export as an undo file for an earlier installation.

Review cloud reporting and sample submission before use. The configuration enables advanced cloud reporting and sends all samples, including potentially sensitive files, to Microsoft.

## Validation

```powershell
pwsh -NoProfile -File tests/Regression.ps1
```

Tests replace Defender commands with in-memory fixtures. They cover supported and unsupported settings, audit and block modes, export, restoration, an empty original ASR list, existing backups, WhatIf, and ignored writes. CI runs these checks on Windows PowerShell 5.1 and PowerShell 7. They do not certify real Windows build compatibility or override managed policy.

Before release, use a disposable Windows VM to record `Get-MpPreference`, apply, reboot, compare effective settings, restore, reboot, and compare against the original snapshot.

Reference: [Microsoft Set-MpPreference documentation](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference).
