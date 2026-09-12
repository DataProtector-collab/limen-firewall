# Pure helper regression: load only this function definition, never the bridge entrypoint.
param([Parameter(Mandatory = $true)][string]$SourcePath)
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Backend PowerShell syntax is invalid.' }
$definition = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-ActiveRuleStatus'
}, $false)
if ($null -eq $definition) { throw 'Active status mapper is missing.' }
. ([scriptblock]::Create($definition.Extent.Text))
$stored = [pscustomobject]@{ id = 'fixture'; primaryStatus = 'OK'; enforcementStatus = @('NotApplicable') }
$active = [pscustomobject]@{ PrimaryStatus = 'Inactive'; EnforcementStatus = @('CategoryDisabled') }
$mapped = Add-ActiveRuleStatus $stored $active
if ($mapped.primaryStatus -cne 'Inactive' -or $mapped.enforcementStatus.Count -ne 1 -or $mapped.enforcementStatus[0] -cne 'CategoryDisabled') {
    throw 'Persistent store status incorrectly masked an inactive runtime rule.'
}
$missing = Add-ActiveRuleStatus ([pscustomobject]@{ id = 'missing' }) $null
if ($missing.primaryStatus -cne 'NotPresent' -or $missing.enforcementStatus[0] -cne 'NotPresent') { throw 'Missing ActiveStore rules must be explicit.' }
$unknown = Add-ActiveRuleStatus ([pscustomobject]@{ id = 'unknown' }) ([pscustomobject]@{})
if ($unknown.primaryStatus -cne 'Unknown' -or $unknown.enforcementStatus[0] -cne 'Unknown') { throw 'Missing runtime status must stay unknown.' }
[Console]::Out.WriteLine('ActiveStore status mapping passed.')
