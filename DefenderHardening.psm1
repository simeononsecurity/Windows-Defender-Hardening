Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-HardeningPlan {
    $desired = [ordered]@{
        DisableRealtimeMonitoring = $false
        MAPSReporting = 2
        SubmitSamplesConsent = 3
        DisableBehaviorMonitoring = $false
        DisableIOAVProtection = $false
        DisableScriptScanning = $false
        DisableRemovableDriveScanning = $false
        DisableBlockAtFirstSeen = $false
        PUAProtection = 1
        DisableArchiveScanning = $false
        DisableEmailScanning = $false
        EnableFileHashComputation = $true
        EnableNetworkProtection = 2
        EnableControlledFolderAccess = 2
        CloudBlockLevel = 2
        CloudExtendedTimeout = 50
    }
    return $desired
}

function Get-HardeningRules {
    @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
      '3B576869-A4EC-4529-8536-B80A7769E899','75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
      'D3E037E1-3EB8-44C8-A917-57927947596D','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
      '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B','01443614-CD74-433A-B99E-2ECDC07BFC25',
      '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2','E6DB77E5-3DF2-4CF1-B95A-636979351E5B',
      'D1E49AAC-8F56-4280-B9BA-993A6D77406C','B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4',
      '26190899-1602-49E8-8B27-EB1D0A1CE869','7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C',
      '56A863A9-875E-4185-98A7-B882C64B5CE5','C1DB55AB-C21A-4637-BB3F-A12568109D35')
}

function Get-RuleMap($Preference) {
    $map = @{}
    $ids = @($Preference.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -gt 0 -and $ids.Count -ne $actions.Count) { throw 'Invalid ASR arrays.' }
    for ($i = 0; $i -lt $ids.Count; $i++) { $map[[string]$ids[$i]] = [int]$actions[$i] }
    return $map
}

function Assert-Preferences($Expected, $Rules) {
    $actual = Get-MpPreference -ErrorAction Stop
    foreach ($name in $Expected.Keys) {
        if ([string]$actual.$name -ne [string]$Expected[$name]) {
            throw "Verification failed for $name. Check policy management and tamper protection."
        }
    }
    $actualRules = Get-RuleMap $actual
    if ($actualRules.Count -ne $Rules.Count) { throw 'ASR rule count verification failed.' }
    foreach ($id in $Rules.Keys) {
        if (-not $actualRules.ContainsKey($id) -or $actualRules[$id] -ne $Rules[$id]) {
            throw "ASR verification failed for $id."
        }
    }
}

function Invoke-DefenderConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Apply','Export','Restore')][string]$Mode = 'Apply',
        [ValidateSet('Audit','Block')][string]$ProtectionMode = 'Audit',
        [Parameter(Mandatory)][string]$BackupPath
    )
    $current = Get-MpPreference -ErrorAction Stop
    $command = Get-Command Set-MpPreference -ErrorAction Stop
    $desired = Get-HardeningPlan
    $supported = @{}
    $before = @{}
    foreach ($name in $desired.Keys) {
        if ($command.Parameters.ContainsKey($name) -and $null -ne $current.PSObject.Properties[$name]) {
            $supported[$name] = $desired[$name]
            $before[$name] = $current.$name
        } else { Write-Warning "Unsupported setting skipped: $name" }
    }
    if ($supported.Count -eq 0) { throw 'No supported Defender settings found.' }
    foreach ($name in @('AttackSurfaceReductionRules_Ids','AttackSurfaceReductionRules_Actions')) {
        if (-not $command.Parameters.ContainsKey($name)) { throw "Required ASR capability unavailable: $name" }
    }
    $rules = Get-RuleMap $current
    if ($Mode -eq 'Restore') {
        $saved = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
        if ($saved.Version -ne 1 -or $null -eq $saved.Preferences -or $null -eq $saved.Rules) {
            throw 'Invalid backup format.'
        }
        $supported = @{}
        foreach ($property in $saved.Preferences.PSObject.Properties) {
            if (-not $desired.Contains($property.Name) -or -not $command.Parameters.ContainsKey($property.Name)) {
                throw "Unsupported backup setting: $($property.Name)"
            }
            $supported[$property.Name] = $property.Value
        }
        if ($supported.Count -eq 0) { throw 'Empty backup.' }
        $rules = @{}
        foreach ($property in $saved.Rules.PSObject.Properties) {
            $null = [guid]::Parse($property.Name)
            $rules[$property.Name] = [int]$property.Value
        }
    } else {
        if (Test-Path -LiteralPath $BackupPath) { throw 'Backup already exists. Choose a new path to preserve the original.' }
        if (-not $PSCmdlet.ShouldProcess($BackupPath, 'Export original managed preferences and all ASR rules')) { return }
            $parent = Split-Path -Parent ([IO.Path]::GetFullPath($BackupPath))
            $null = New-Item -ItemType Directory -Path $parent -Force
            @{ Version = 1; Preferences = $before; Rules = $rules } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $BackupPath -Encoding UTF8
        if ($Mode -eq 'Export') { return }
        $action = 2
        if ($ProtectionMode -eq 'Block') { $action = 1 }
        $supported['EnableNetworkProtection'] = $action
        $supported['EnableControlledFolderAccess'] = $action
        foreach ($name in @('EnableNetworkProtection','EnableControlledFolderAccess')) {
            if (-not $before.ContainsKey($name)) { $supported.Remove($name) }
        }
        foreach ($id in Get-HardeningRules) { $rules[$id] = $action }
    }
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', "$Mode managed configuration ($ProtectionMode)")) {
        Set-MpPreference @supported -ErrorAction Stop
        $ids = @($rules.Keys | Sort-Object)
        if ($ids.Count) {
            $actions = @($ids | ForEach-Object { $rules[$_] })
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
        } else {
            $existing = @((Get-RuleMap (Get-MpPreference)).Keys)
            if ($existing.Count) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $existing -ErrorAction Stop }
        }
        Assert-Preferences $supported $rules
        Write-Output "$Mode completed and effective settings verified. Backup: $BackupPath"
    }
}
Export-ModuleMember -Function Invoke-DefenderConfiguration
