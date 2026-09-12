param([Parameter(Mandatory = $true)][string]$SourcePath, [Parameter(Mandatory = $true)][string]$NodePath)
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Backend PowerShell syntax is invalid.' }
foreach ($name in @('Assert-Rule', 'Test-SameProgramPath', 'Assert-MatchingRule')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false)
    if ($null -eq $definition) { throw "Missing helper: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('Limen-path-regression-' + [guid]::NewGuid().ToString())
try {
    $null = New-Item -ItemType Directory -Path $directory
    $fixture = Join-Path $directory 'long-program-name.exe'
    [IO.File]::WriteAllBytes($fixture, [byte[]]@(77, 90))
    $filesystem = New-Object -ComObject Scripting.FileSystemObject
    $aliasChecked = $false
    foreach ($candidate in @($NodePath, $fixture)) {
        $longPath = (Get-Item -LiteralPath $candidate).FullName
        $shortPath = $filesystem.GetFile($candidate).ShortPath
        if ($shortPath -ieq $longPath) { continue }
        $expected = [pscustomobject]@{ program = $shortPath; action = 'block'; direction = 'out'; protocol = 'TCP' }
        $validated = Assert-Rule $expected
        $actual = [pscustomobject]@{ program = $validated; action = 'block'; direction = 'out'; protocol = 'TCP'; enabled = $true }
        Assert-MatchingRule $actual $expected $true
        if (-not (Test-SameProgramPath $longPath $shortPath)) { throw 'The actual DOS alias did not match its long filename.' }
        $aliasChecked = $true
    }
    if (Test-SameProgramPath $NodePath $fixture) { throw 'Different executable paths must never compare equal.' }
    if (Test-SameProgramPath '\\untrusted\program.exe' $NodePath) { throw 'UNC path comparison must be rejected.' }
    $expected = [pscustomobject]@{ program = $NodePath; action = 'block'; direction = 'out'; protocol = 'TCP'; remotePort = 443 }
    $actual = [pscustomobject]@{ program = $fixture; action = 'allow'; direction = 'in'; protocol = 'UDP'; remotePort = 80; enabled = $false }
    try { Assert-MatchingRule $actual $expected $true; throw 'Expected mismatch was accepted.' }
    catch {
        $message = $_.Exception.Message
        foreach ($field in @('program path', 'action', 'direction', 'protocol', 'enabled', 'remotePort')) {
            if (-not $message.Contains($field)) { throw "Verification error did not identify $field." }
        }
        if ($message.Contains($fixture) -or $message.Contains($NodePath)) { throw 'Verification error leaked a full executable path.' }
    }
    [Console]::Out.WriteLine((ConvertTo-Json -Compress @{ aliasChecked = $aliasChecked; fieldDiagnosticsChecked = $true }))
} finally {
    $resolved = [IO.Path]::GetFullPath($directory)
    $root = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved).StartsWith('Limen-path-regression-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
    } else { throw 'Temporary fixture path containment check failed.' }
}
