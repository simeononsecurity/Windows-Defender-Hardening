#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Apply','Export','Restore')][string]$Mode = 'Apply',
    [ValidateSet('Audit','Block')][string]$ProtectionMode = 'Audit',
    [string]$BackupPath = (Join-Path $env:ProgramData ('SoS-Defender\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.json'))
)
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'DefenderHardening.psm1') -Force
    $confirmation = @{}
    if ($PSBoundParameters.ContainsKey('Confirm')) { $confirmation['Confirm'] = $PSBoundParameters['Confirm'] }
    Invoke-DefenderConfiguration -Mode $Mode -ProtectionMode $ProtectionMode -BackupPath $BackupPath -WhatIf:$WhatIfPreference @confirmation
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
