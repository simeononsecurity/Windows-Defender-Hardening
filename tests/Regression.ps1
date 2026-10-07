$ErrorActionPreference = 'Stop'
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Throws([scriptblock]$Action) { $failed=$false; try { & $Action } catch { $failed=$true }; Assert $failed 'Expected failure' }
$global:state = [pscustomobject]@{
    DisableRealtimeMonitoring=$true; MAPSReporting=0; SubmitSamplesConsent=1
    EnableNetworkProtection=0; EnableControlledFolderAccess=0
    AttackSurfaceReductionRules_Ids=@('00000000-0000-0000-0000-000000000001')
    AttackSurfaceReductionRules_Actions=@(1)
}
$global:ignoreWrites = $false
$global:writes = 0
function global:Get-MpPreference { [CmdletBinding()]param(); return $global:state }
function global:Set-MpPreference {
    [CmdletBinding()]param([bool]$DisableRealtimeMonitoring,[int]$MAPSReporting,[int]$SubmitSamplesConsent,
        [int]$EnableNetworkProtection,[int]$EnableControlledFolderAccess,
        [string[]]$AttackSurfaceReductionRules_Ids,[int[]]$AttackSurfaceReductionRules_Actions)
    $global:writes++
    if ($global:ignoreWrites) { return }
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne 'ErrorAction') { $global:state.$key = $PSBoundParameters[$key] }
    }
}
function global:Remove-MpPreference {
    [CmdletBinding()]param([string[]]$AttackSurfaceReductionRules_Ids)
    $global:state.AttackSurfaceReductionRules_Ids=@()
    $global:state.AttackSurfaceReductionRules_Actions=@()
}
Import-Module (Join-Path $PSScriptRoot '../DefenderHardening.psm1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$null=New-Item -ItemType Directory $root
try {
    $backup=Join-Path $root 'original.json'
    Invoke-DefenderConfiguration -BackupPath $backup -WhatIf
    Assert ($global:writes -eq 0 -and -not (Test-Path $backup)) 'WhatIf changed configuration'
    Invoke-DefenderConfiguration -BackupPath $backup -Mode Export
    Assert ($global:writes -eq 0) 'Export changed configuration'
    Remove-Item $backup
    Invoke-DefenderConfiguration -BackupPath $backup
    Assert ($global:state.DisableRealtimeMonitoring -eq $false) 'Protection was not applied'
    Assert ($global:state.EnableNetworkProtection -eq 2) 'Default should use audit'
    Assert ($global:state.AttackSurfaceReductionRules_Ids.Count -eq 17) 'Existing ASR rule was not preserved'
    $calls=$global:writes
    Throws { Invoke-DefenderConfiguration -BackupPath $backup }
    Assert ($global:writes -eq $calls) 'Existing backup allowed mutations'
    Invoke-DefenderConfiguration -BackupPath $backup -Mode Restore
    Assert ($global:state.DisableRealtimeMonitoring -eq $true) 'Preference did not restore'
    Assert ($global:state.AttackSurfaceReductionRules_Ids.Count -eq 1) 'ASR snapshot did not restore'
    $global:state.AttackSurfaceReductionRules_Ids=@()
    $global:state.AttackSurfaceReductionRules_Actions=@()
    $emptyBackup=Join-Path $root 'empty.json'
    Invoke-DefenderConfiguration -BackupPath $emptyBackup -ProtectionMode Block
    Assert ($global:state.EnableNetworkProtection -eq 1) 'Explicit block mode failed'
    Invoke-DefenderConfiguration -BackupPath $emptyBackup -Mode Restore
    Assert ($global:state.AttackSurfaceReductionRules_Ids.Count -eq 0) 'Empty ASR snapshot did not restore'
    $global:ignoreWrites=$true
    Throws { Invoke-DefenderConfiguration -BackupPath (Join-Path $root 'failed.json') }
    Assert (Test-Path (Join-Path $root 'failed.json')) 'Failure lost recovery snapshot'
    Write-Output 'PASS: supported parameters, unsupported settings, apply, audit/block, export, restore, WhatIf and ignored writes'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
    Remove-Module DefenderHardening
    Remove-Item Function:\Get-MpPreference,Function:\Set-MpPreference,Function:\Remove-MpPreference
}
