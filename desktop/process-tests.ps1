# Deterministic process regression tests. Mock all process/service/signature providers.
param([Parameter(Mandatory = $true)][string]$SourcePath)
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Backend syntax is invalid.' }
foreach ($name in @('Convert-ProcessStartedAt', 'Limit-ProcessText', 'Convert-ProcessPath', 'Get-ProcessRows', 'Get-ProcessServiceRows',
    'Convert-ProcessEntry', 'Get-HostedService', 'Get-NativeProcessSnapshot', 'Assert-ProcessIdentity', 'Get-VerifiedProcess',
    'Get-InspectionModules', 'Get-InspectionFile', 'Get-NativeProcessInspection')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false)
    if (-not $definition) { throw "Missing process helper: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function New-Row([long]$ProcessId, [long]$ParentId = 1, [long]$Time = 1700000000000) {
    [pscustomobject]@{ ProcessId = $ProcessId; ParentProcessId = $ParentId; Name = 'fixture.exe'; ExecutablePath = 'C:\fixture.exe'; CreationDate = [DateTimeOffset]::FromUnixTimeMilliseconds($Time).UtcDateTime }
}
$script:rows = @((New-Row 42), (New-Row 42), (New-Row 1 0 1699999990000), (New-Row 43 42 1700000001000), (New-Row 44 42 1699999999000))
$script:reads = 0
$script:reuseAfterRead = $false
$script:servicesFail = $false
function Get-ProcessRows {
    $script:reads++
    if ($script:reuseAfterRead -and $script:reads -gt 1) { return @((New-Row 42 1 1700000005000)) }
    return $script:rows
}
function Get-ProcessServiceRows {
    if ($script:servicesFail) { throw 'Fixture denied' }
    return @([pscustomobject]@{ Name = 'svc-one'; DisplayName = 'Service One'; State = 'Running'; ProcessId = 42 },
        [pscustomobject]@{ Name = 'svc-one'; DisplayName = 'Duplicate'; State = 'Running'; ProcessId = 42 })
}
function Get-HostedService($Row) { return [ordered]@{ name = $Row.Name; displayName = $Row.DisplayName; state = $Row.State; serviceDll = 'C:\fixture.dll' } }
$inventory = Get-NativeProcessSnapshot
Assert ($inventory.available -and $inventory.processes.Count -eq 4) 'Inventory must deduplicate process IDs.'
$entry = @($inventory.processes | Where-Object { $_.pid -eq 42 })[0]
Assert ($entry.services.Count -eq 1 -and $entry.services[0].serviceDll -eq 'C:\fixture.dll') 'Hosted service names must deduplicate and retain configured DLL metadata.'
Assert ($entry.startedAt -eq 1700000000000 -and $entry.parentPid -eq 1) 'Process identity and parent PID must come from explicit Windows fields.'
$script:servicesFail = $true
$partial = Get-NativeProcessSnapshot
Assert ($partial.available -and $partial.processes.Count -eq 4 -and $partial.errors.Count -gt 0) 'A service access failure must preserve process observations and report the failure.'
$script:servicesFail = $false
$script:reads = 0; $script:reuseAfterRead = $true
$changed = Get-NativeProcessSnapshot
$changedEntry = @($changed.processes | Where-Object { $_.pid -eq 42 })[0]
Assert ($changedEntry.services.Count -eq 0 -and $changedEntry.errors.Count -gt 0) 'A reused PID must never inherit hosted services from the old process instance.'
$script:reuseAfterRead = $false
$script:verifyReads = 0
$script:changeDuringInspection = $false
function Get-Process {
    $script:verifyReads++
    $start = 1700000000000
    if ($script:changeDuringInspection -and $script:verifyReads -ge 3) { $start++ }
    $process = [pscustomobject]@{ Id = 42; StartTime = [DateTimeOffset]::FromUnixTimeMilliseconds($start).UtcDateTime; Modules = @(
        [pscustomobject]@{ FileName = 'C:\fixture.exe'; ModuleName = 'fixture.exe' }, [pscustomobject]@{ FileName = 'C:\fixture.dll'; ModuleName = 'fixture.dll' }) }
    $process | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    return $process
}
function Get-InspectionFile($Program) { return @{ sha256 = ('a' * 64); signature = @{ status = 'unsigned'; nativeStatus = 'NotSigned' }; errors = @() } }
$identity = [pscustomobject]@{ pid = 42; startedAt = 1700000000000 }
$inspection = Get-NativeProcessInspection $identity
Assert ($inspection.available -and $inspection.modules.Count -eq 2 -and $inspection.sha256) 'Inspection must read modules and file metadata for a verified identity.'
Assert ($inspection.parent.pid -eq 1 -and $inspection.children.Count -eq 1 -and $inspection.children[0].pid -eq 43) 'Parent and child relationships must reject creation times belonging to a reused PID.'
$wrong = Get-NativeProcessInspection ([pscustomobject]@{ pid = 42; startedAt = 1700000000001 })
Assert (-not $wrong.available -and -not $wrong.sha256 -and $wrong.modules.Count -eq 0) 'A requested identity mismatch must not reveal another instance metadata.'
$script:verifyReads = 0; $script:changeDuringInspection = $true
$raced = Get-NativeProcessInspection $identity
Assert (-not $raced.available -and -not $raced.sha256 -and $raced.modules.Count -eq 0 -and -not $raced.process) 'A process that exits or is reused during inspection must discard all slow-read metadata.'
$many = [pscustomobject]@{ Modules = @(1..300 | ForEach-Object { [pscustomobject]@{ FileName = "C:\module$_.dll"; ModuleName = "module$_.dll" } }) }
$bounded = Get-InspectionModules $many
Assert ($bounded.modules.Count -eq 256 -and $bounded.truncated) 'Module output must be bounded and explicitly truncated.'
$denied = [pscustomobject]@{}
$denied | Add-Member -MemberType ScriptProperty -Name Modules -Value { throw 'Access denied' }
$partialModules = Get-InspectionModules $denied
Assert ($partialModules.errors.Count -gt 0 -and $partialModules.modules.Count -eq 0) 'Module access denial must be explicit, never a clean empty inventory.'
foreach ($bad in @([pscustomobject]@{ pid = 42; startedAt = $true }, [pscustomobject]@{ pid = 42; startedAt = 1; path = 'C:\secret' })) {
    $rejected = $false
    try { Assert-ProcessIdentity $bad } catch { $rejected = $true }
    Assert $rejected 'Native identity validation must independently reject unsupported requests.'
}
foreach ($badPath in @('\\server\secret.dll', '\\?\C:\secret.dll', 'C:\file.dll:secret', 'relative.dll')) {
    Assert (-not (Convert-ProcessPath $badPath)) 'Process paths must not become arbitrary remote or device reads.'
}
[Console]::Out.WriteLine('Native process regression cases passed.')
