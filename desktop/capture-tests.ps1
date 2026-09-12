# Pure capture regression tests. Load only helper definitions and mock all OS reads.
param([Parameter(Mandatory = $true)][string]$SourcePath)
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Backend syntax is invalid.' }
foreach ($name in @('Get-DotNetNetworkInterfaces', 'Get-DotNetTrafficAdapters', 'Convert-TrafficCounters', 'Get-NativeTraffic', 'Convert-ProcessStartedAt', 'Get-NativeSnapshot')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false)
    if (-not $definition) { throw "Missing capture helper: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function New-Interface([string]$Id, [string]$Status = 'Up', [string]$Type = 'Ethernet', [bool]$Configured = $true, [long]$Rx = 1234, [long]$Tx = 5678) {
    $interface = [pscustomobject]@{ Id = $Id; Name = $Id; OperationalStatus = [Net.NetworkInformation.OperationalStatus]$Status
        NetworkInterfaceType = [Net.NetworkInformation.NetworkInterfaceType]$Type; Configured = $Configured; Rx = $Rx; Tx = $Tx }
    $interface | Add-Member -MemberType ScriptMethod -Name GetIPProperties -Value {
        $addresses = if ($this.Configured) { @([pscustomobject]@{ Address = [Net.IPAddress]::Parse('192.0.2.5') }) } else { @() }
        [pscustomobject]@{ UnicastAddresses = $addresses }
    }
    $interface | Add-Member -MemberType ScriptMethod -Name GetIPStatistics -Value {
        $script:statisticsReads++
        [pscustomobject]@{ BytesReceived = $this.Rx; BytesSent = $this.Tx }
    }
    return $interface
}
$script:cimAdapters = @()
$script:cimFails = $false
$script:statisticsReads = 0
$script:interfaces = @(New-Interface 'nic-a')
$script:counterDelay = 0
$script:lastCounterRead = 0
function Get-NetAdapterStatistics {
    if ($script:counterDelay) { Start-Sleep -Milliseconds $script:counterDelay }
    $script:lastCounterRead = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    if ($script:cimFails) { throw 'Fixture CIM failure' }
    return $script:cimAdapters
}
function Get-DotNetNetworkInterfaces { return $script:interfaces }
function Get-NetTCPConnection {
    [pscustomobject]@{ LocalAddress = '192.0.2.5'; LocalPort = 50000; RemoteAddress = '198.51.100.8'; RemotePort = 443; OwningProcess = 42; State = 'Established' }
}
function Get-NetUDPEndpoint { return @() }
function Get-Process { [pscustomobject]@{ Id = 42; ProcessName = 'Fixture'; Path = 'C:\Fixture.exe' } }

$fallback = Get-NativeTraffic
Assert ($fallback.trafficAvailable -and $fallback.rxBytes -eq 1234 -and $fallback.txBytes -eq 5678) 'Empty successful CIM output must use actual fallback counters, not zero.'
Assert ($fallback.counterSource -like 'windows-networkinterface:*') 'Fallback counter source must identify the provider.'
$script:cimFails = $true
Assert ((Get-NativeTraffic).trafficAvailable) 'A failing CIM provider must also permit the supported fallback.'
$script:cimFails = $false
$script:cimAdapters = @([pscustomobject]@{ InstanceID = 'cim-a'; ReceivedBytes = $null; SentBytes = 2 })
Assert ((Get-NativeTraffic).rxBytes -eq 1234) 'Missing counter fields must not be coerced to measured zero.'
$script:cimAdapters = @([pscustomobject]@{ InstanceID = 'cim-a'; ReceivedBytes = 0; SentBytes = 0 })
$beforeReads = $script:statisticsReads
$quiet = Get-NativeTraffic
Assert ($quiet.trafficAvailable -and $quiet.rxBytes -eq 0 -and $quiet.txBytes -eq 0) 'Measured zeros must remain valid counters.'
Assert ($script:statisticsReads -eq $beforeReads) 'Providers must not be mixed or double-counted.'
Assert ($quiet.counterSource -cne $fallback.counterSource) 'Provider changes must reset the consumer rate baseline.'
$script:cimAdapters = @()
$script:interfaces = @((New-Interface 'nic-a'), (New-Interface 'nic-a'), (New-Interface 'down' 'Down'),
    (New-Interface 'loopback' 'Up' 'Loopback'), (New-Interface 'tunnel' 'Up' 'Tunnel'), (New-Interface 'pseudo' 'Up' 'Ethernet' $false))
$filtered = Get-NativeTraffic
Assert ($filtered.rxBytes -eq 1234 -and $filtered.txBytes -eq 5678) 'Loopback, tunnel, down, duplicate and unconfigured interfaces must not add traffic.'
$script:interfaces = @(New-Interface 'nic-b')
Assert ((Get-NativeTraffic).counterSource -cne $fallback.counterSource) 'A changed interface set must reset the consumer baseline.'
$script:interfaces = @()
$unavailable = Get-NativeSnapshot
Assert ($unavailable.available -and $unavailable.sockets.Count -eq 1 -and $unavailable.capture -ceq 'windows') 'Counter failure must preserve valid sockets.'
Assert (-not $unavailable.trafficAvailable -and $unavailable.trafficError) 'Unavailable traffic must be explicit rather than an idle rate.'
$script:cimAdapters = @([pscustomobject]@{ InstanceID = 'cim-a'; ReceivedBytes = 10; SentBytes = 20 })
$script:counterDelay = 80
$snapshot = Get-NativeSnapshot
Assert ($snapshot.at -ge $script:lastCounterRead -and $snapshot.captureDurationMs -ge 70) 'Snapshot time must correspond to counters after slow enumeration.'
Assert ($snapshot.trafficAvailable -and $snapshot.rxBytes -eq 10 -and $snapshot.sockets[0].direction -ceq 'unknown') 'Capture metadata must retain real counter values and unknown direction.'
[Console]::Out.WriteLine('Native capture regression cases passed.')
