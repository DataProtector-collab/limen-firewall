# Fixed-operation Windows Firewall bridge. Request values enter only through JSON stdin.
# Windows PowerShell 5.1 compatible. This script never evaluates caller-supplied code.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$LimenGroup = 'Limen Firewall'
$LimenIdPattern = '^Limen-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Elevated {
    if (-not (Test-Elevated)) { throw 'Administrator permission is required. Close Limen and start the desktop application as administrator, then retry.' }
}

function Assert-Id($Id) {
    if ($Id -isnot [string] -or $Id -notmatch $LimenIdPattern) { throw 'Invalid Limen rule ID.' }
}

function Assert-Rule($Rule) {
    if ($null -eq $Rule -or $Rule -isnot [pscustomobject]) { throw 'A rule object is required.' }
    $allowed = @('program', 'action', 'direction', 'protocol', 'remoteAddress', 'localPort', 'remotePort')
    foreach ($property in $Rule.PSObject.Properties.Name) {
        if ($property -cnotin $allowed) { throw 'Unsupported rule property.' }
    }
    $program = $Rule.program
    if ($program -isnot [string] -or $program.Length -gt 32700 -or $program -notmatch '^[a-zA-Z]:\\' -or
        $program -match '[\x00-\x1f<>"|?*/%]' -or $program.Substring(2).Contains(':') -or
        $program -match '(^|\\)\.\.?($|\\)' -or [IO.Path]::GetExtension($program) -ine '.exe') {
        throw 'Select a full local Windows .exe path.'
    }
    $item = Get-Item -LiteralPath $program -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item -isnot [IO.FileInfo]) { throw 'The program must be an existing .exe file.' }
    # Reject remote mapped drives as well as UNC paths and filesystem links/reparse points.
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($item.FullName))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { throw 'The executable must be on a local disk.' }
    $ancestor = $item
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Executables reached through filesystem links are not supported. Select the original local file.' }
        if ($ancestor -is [IO.FileInfo]) { $ancestor = $ancestor.Directory } else { $ancestor = $ancestor.Parent }
    }
    if ($Rule.action -cnotin @('allow', 'block')) { throw 'Action must be allow or block.' }
    if ($Rule.direction -cnotin @('in', 'out')) { throw 'Direction must be in or out.' }
    if ($Rule.protocol -cnotin @('TCP', 'UDP', 'ANY')) { throw 'Protocol must be TCP, UDP or ANY.' }
    if ($null -ne $Rule.remoteAddress) {
        $parsed = $null
        if ($Rule.remoteAddress -isnot [string] -or $Rule.remoteAddress.Contains('%') -or
            -not [Net.IPAddress]::TryParse($Rule.remoteAddress, [ref]$parsed)) { throw 'Remote address must be a literal IP address.' }
        # .NET accepts abbreviated and numeric IPv4 forms; require four decimal octets.
        if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $Rule.remoteAddress -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') { throw 'Use a standard dotted IPv4 address.' }
    }
    foreach ($port in @('remotePort', 'localPort')) {
        $value = $Rule.$port
        if ($null -ne $value -and ($Rule.protocol -eq 'ANY' -or $value -isnot [ValueType] -or $value -is [bool] -or
            [double]$value -ne [Math]::Floor([double]$value) -or $value -lt 1 -or $value -gt 65535)) {
            throw 'Ports must be integers from 1 to 65535 and require TCP or UDP.'
        }
    }
    return $item.FullName
}

function Get-OwnedRules([string]$Store = 'PersistentStore') {
    # Query errors must propagate: an inaccessible policy store is not an empty rule list.
    return @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object {
        $_.Group -ceq $LimenGroup -and $_.Name -match $LimenIdPattern
    })
}

function Get-OwnedRule($Id, [string]$Store = 'PersistentStore') {
    Assert-Id $Id
    $matches = @(Get-OwnedRules $Store | Where-Object { $_.Name -ceq $Id })
    if ($matches.Count -ne 1) { throw "The Limen rule was not found in $Store. Refresh the rule list." }
    return $matches[0]
}

function Convert-Rule($Rule) {
    $application = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $address = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $protocol = switch ([string]$port.Protocol) { '6' { 'TCP' } 'TCP' { 'TCP' } '17' { 'UDP' } 'UDP' { 'UDP' } '256' { 'ANY' } 'Any' { 'ANY' } default { throw 'A Limen rule has an unsupported protocol. Inspect it in Windows Defender Firewall.' } }
    if ([string]$application.Program -eq 'Any' -or [string]$Rule.Action -notin @('Allow', 'Block') -or [string]$Rule.Direction -notin @('Inbound', 'Outbound')) {
        throw 'A Limen rule was changed outside Limen to an unsupported scope. Inspect it in Windows Defender Firewall.'
    }
    $createdAt = 0L
    if ($Rule.Description -match '^Limen v1; createdAt=([0-9]+)$') { $createdAt = [long]$Matches[1] }
    $result = [ordered]@{
        id = [string]$Rule.Name; program = [string]$application.Program
        action = ([string]$Rule.Action).ToLowerInvariant()
        direction = $(if ([string]$Rule.Direction -eq 'Inbound') { 'in' } else { 'out' })
        protocol = $protocol; enabled = ([string]$Rule.Enabled -eq 'True'); createdAt = $createdAt
    }
    if (@($address.RemoteAddress).Count -ne 1) { throw 'A Limen rule has multiple remote addresses. Inspect it in Windows Defender Firewall.' }
    if ([string]$address.RemoteAddress -ne 'Any') { $result.remoteAddress = [string]$address.RemoteAddress }
    foreach ($entry in @(@('LocalPort', 'localPort'), @('RemotePort', 'remotePort'))) {
        $value = @($port.($entry[0]))
        if ($value.Count -ne 1) { throw 'A Limen rule has multiple ports. Inspect it in Windows Defender Firewall.' }
        if ([string]$value[0] -ne 'Any') {
            if ([string]$value[0] -notmatch '^[0-9]+$') { throw 'A Limen rule has a port range. Inspect it in Windows Defender Firewall.' }
            $result[$entry[1]] = [int]$value[0]
        }
    }
    return [pscustomobject]$result
}

function Add-ActiveRuleStatus($Converted, $ActiveRule) {
    # PersistentStore reports parsing/storage status, not runtime enforcement.
    # Always use ActiveStore for these fields, including explicit missing/unknown states.
    $primary = 'NotPresent'
    $enforcement = @('NotPresent')
    if ($null -ne $ActiveRule) {
        $primary = [string]$ActiveRule.PrimaryStatus
        if (-not $primary) { $primary = 'Unknown' }
        $enforcement = @($ActiveRule.EnforcementStatus | ForEach-Object { [string]$_ } | Where-Object { $_ })
        if ($enforcement.Count -eq 0) { $enforcement = @('Unknown') }
    }
    $Converted | Add-Member -NotePropertyName primaryStatus -NotePropertyValue $primary -Force
    $Converted | Add-Member -NotePropertyName enforcementStatus -NotePropertyValue $enforcement -Force
    return $Converted
}

function Test-SameProgramPath($Actual, $Expected) {
    if ($Actual -isnot [string] -or $Expected -isnot [string]) { return $false }
    if ($Actual -ieq $Expected) { return $true }
    # Windows expands DOS 8.3 aliases when storing program filters. Resolve only
    # existing drive-qualified files, never URLs, UNC paths or command text.
    if ($Actual -notmatch '^[a-zA-Z]:\\' -or $Expected -notmatch '^[a-zA-Z]:\\') { return $false }
    try {
        $actualFile = Get-Item -LiteralPath $Actual -Force -ErrorAction Stop
        $expectedFile = Get-Item -LiteralPath $Expected -Force -ErrorAction Stop
        return ($actualFile -is [IO.FileInfo] -and $expectedFile -is [IO.FileInfo] -and $actualFile.FullName -ieq $expectedFile.FullName)
    } catch { return $false }
}

function Assert-MatchingRule($Actual, $Expected, [bool]$Enabled) {
    $mismatches = [Collections.Generic.List[string]]::new()
    if (-not (Test-SameProgramPath $Actual.program $Expected.program)) { $mismatches.Add('program path') }
    if ($Actual.action -cne $Expected.action) { $mismatches.Add('action') }
    if ($Actual.direction -cne $Expected.direction) { $mismatches.Add('direction') }
    if ($Actual.protocol -cne $Expected.protocol) { $mismatches.Add('protocol') }
    if ($Actual.enabled -ne $Enabled) { $mismatches.Add('enabled') }
    foreach ($port in @('localPort', 'remotePort')) {
        if ([string]$Actual.$port -cne [string]$Expected.$port) { $mismatches.Add($port) }
    }
    if ($null -ne $Expected.remoteAddress) {
        try {
            if ($null -eq $Actual.remoteAddress -or -not [Net.IPAddress]::Parse($Actual.remoteAddress).Equals([Net.IPAddress]::Parse($Expected.remoteAddress))) {
                $mismatches.Add('remoteAddress')
            }
        } catch { $mismatches.Add('remoteAddress') }
    } elseif ($null -ne $Actual.remoteAddress) { $mismatches.Add('remoteAddress') }
    if ($mismatches.Count -gt 0) {
        # Report field names without copying private executable paths or endpoints.
        throw "Windows rule verification failed. Mismatched field(s): $($mismatches -join ', '). Refresh and inspect the rule."
    }
}

function Get-NativeStatus {
    $elevated = Test-Elevated
    try {
        Import-Module NetSecurity -ErrorAction Stop
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True')
                defaultInboundAction = [string]$_.DefaultInboundAction; defaultOutboundAction = [string]$_.DefaultOutboundAction }
        })
        if ($profiles.Count -eq 0) { throw 'Windows returned no firewall profiles.' }
        $enabled = @($profiles | Where-Object { -not $_.enabled }).Count -eq 0
        $warnings = [Collections.Generic.List[string]]::new()
        if (-not $enabled) { $warnings.Add('One or more Windows Firewall profiles are disabled. Limen does not change global profile settings.') }
        if (-not $elevated) { $warnings.Add('Connection monitoring is available. Start Limen as administrator to read and change firewall rules.') }
        $result = [ordered]@{ platform = 'win32'; available = $true; elevated = $elevated; firewallEnabled = $enabled
            backend = 'windows-firewall'; reason = $null; profiles = $profiles }
        try {
            $providers = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop |
                Where-Object { $_.displayName -and $_.displayName -notmatch '^(Windows (Defender )?Firewall|Microsoft Defender Firewall)$' } |
                ForEach-Object { [string]$_.displayName } | Sort-Object -Unique)
            $result.externalFirewallProviders = $providers
            if ($providers.Count -gt 0) {
                $warnings.Add("Another firewall provider is registered: $($providers -join ', '). Limen manages Windows Firewall rules; enforcement by another provider is not verified.")
            }
        } catch {
            # Windows Server may not expose SecurityCenter2. Omission means unknown,
            # never an assertion that no other firewall is present.
        }
        if ($warnings.Count -gt 0) { $result.reason = $warnings -join ' ' }
        return $result
    } catch {
        return [ordered]@{ platform = 'win32'; available = $false; elevated = $elevated; firewallEnabled = $false
            backend = 'none'; reason = $_.Exception.Message; profiles = @() }
    }
}

function Get-RuleDiagnostic($Rule) {
    $application = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    return [ordered]@{
        id = [string]$Rule.Name; enabled = [string]$Rule.Enabled; action = [string]$Rule.Action; direction = [string]$Rule.Direction
        primaryStatus = [string]$Rule.PrimaryStatus; enforcementStatus = @($Rule.EnforcementStatus | ForEach-Object { [string]$_ })
        status = [string]$Rule.Status; policyStoreSourceType = [string]$Rule.PolicyStoreSourceType; policyStoreSource = [string]$Rule.PolicyStoreSource
        program = [string]$application.Program; protocol = [string]$port.Protocol
        localPort = @($port.LocalPort | ForEach-Object { [string]$_ }); remotePort = @($port.RemotePort | ForEach-Object { [string]$_ })
        localAddress = @($address.LocalAddress | ForEach-Object { [string]$_ }); remoteAddress = @($address.RemoteAddress | ForEach-Object { [string]$_ })
    }
}

function Get-DotNetNetworkInterfaces {
    return @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
}

function Get-DotNetTrafficAdapters {
    # The CIM statistics provider can return an empty successful result on valid
    # Windows NIC drivers. Read the supported .NET interface API as an alternative.
    # Exclude loopback, tunnel and unconfigured filter/pseudo interfaces: otherwise
    # the same traffic can be counted again through inactive protocol bindings.
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($adapter in @(Get-DotNetNetworkInterfaces)) {
        if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up -or
            $adapter.NetworkInterfaceType -in @([Net.NetworkInformation.NetworkInterfaceType]::Loopback, [Net.NetworkInformation.NetworkInterfaceType]::Tunnel)) { continue }
        $addresses = @($adapter.GetIPProperties().UnicastAddresses | Where-Object {
            -not [Net.IPAddress]::IsLoopback($_.Address) -and -not $_.Address.Equals([Net.IPAddress]::Any) -and -not $_.Address.Equals([Net.IPAddress]::IPv6Any)
        })
        if ($addresses.Count -eq 0) { continue }
        $identity = [string]$adapter.Id
        if (-not $identity) { throw 'An active network interface has no stable counter identity.' }
        if (-not $seen.Add($identity)) { continue }
        $statistics = $adapter.GetIPStatistics()
        [pscustomobject]@{ InstanceID = $identity; Name = [string]$adapter.Name
            ReceivedBytes = $statistics.BytesReceived; SentBytes = $statistics.BytesSent }
    }
}

function Convert-TrafficCounters($Adapters, [string]$Source) {
        if (@($Adapters).Count -eq 0) { throw 'Windows returned no usable network adapter counters.' }
        $received = 0L; $sent = 0L
        $identities = [Collections.Generic.List[string]]::new()
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($adapter in $Adapters) {
            $identity = [string]$adapter.InstanceID
            if (-not $identity) { $identity = [string]$adapter.Name }
            if (-not $identity) { throw 'Windows returned an adapter without a stable counter identity.' }
            if (-not $seen.Add($identity)) { continue }
            foreach ($field in @('ReceivedBytes', 'SentBytes')) {
                $value = $adapter.$field
                if ($null -eq $value -or $value -isnot [ValueType] -or $value -is [bool] -or
                    [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value) -or
                    [double]$value -lt 0 -or [double]$value -gt 9007199254740991 -or [double]$value -ne [Math]::Floor([double]$value)) {
                    throw 'Windows returned missing or invalid adapter byte counters.'
                }
            }
            $received += [long]$adapter.ReceivedBytes; $sent += [long]$adapter.SentBytes
            if ($received -gt 9007199254740991 -or $sent -gt 9007199254740991) { throw 'Adapter byte totals exceeded the supported numeric range.' }
            $identities.Add($identity)
        }
        return [ordered]@{ rxBytes = $received; txBytes = $sent; trafficAvailable = $true
            counterSource = $Source + ':' + (ConvertTo-Json -InputObject @($identities | Sort-Object -Unique) -Compress) }
}

function Get-NativeTraffic {
    try {
        return Convert-TrafficCounters @(Get-NetAdapterStatistics -ErrorAction Stop) 'windows-netadapter'
    } catch {
        $primaryError = $_.Exception.Message
    }
    try {
        # Never combine the two providers. Source and interface-set changes reset
        # the UI's rate baseline before another measured rate is displayed.
        return Convert-TrafficCounters @(Get-DotNetTrafficAdapters) 'windows-networkinterface'
    } catch {
        return [ordered]@{ rxBytes = 0; txBytes = 0; trafficAvailable = $false
            trafficError = "Adapter counters unavailable. CIM: $primaryError . Network interfaces: $($_.Exception.Message)" }
    }
}

function Convert-ProcessStartedAt($Value) {
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -isnot [DateTime] -and $Value -isnot [DateTimeOffset]) { return $null }
        $milliseconds = ([DateTimeOffset]$Value).ToUniversalTime().ToUnixTimeMilliseconds()
        if ($milliseconds -gt 0) { return $milliseconds }
    } catch { }
    return $null
}

function Get-NativeSnapshot {
    $captureTimer = [Diagnostics.Stopwatch]::StartNew()
    $captureStartedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $processes = @{}
        $ownerPids = [Collections.Generic.HashSet[int]]::new()
        foreach ($socket in @($tcp) + @($udp)) { $null = $ownerPids.Add([int]$socket.OwningProcess) }
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            $exe = ''
            try { $exe = [string]$process.Path } catch { }
            $startedAt = $null
            if ($exe -and $ownerPids.Contains([int]$process.Id)) {
                try { $startedAt = Convert-ProcessStartedAt $process.StartTime } catch { }
            }
            # A process created after enumeration began cannot own an earlier socket
            # observation. Withhold the identity instead of joining a reused PID.
            if ($null -ne $startedAt -and $startedAt -gt $captureStartedAt) { $startedAt = $null; $exe = '' }
            $processes[[int]$process.Id] = @{ name = [string]$process.ProcessName; exe = $exe; startedAt = $startedAt }
        }
        $sockets = [Collections.Generic.List[object]]::new()
        foreach ($socket in $tcp) {
            $owner = $processes[[int]$socket.OwningProcess]
            $entry = [ordered]@{
                id = "TCP|$($socket.LocalAddress)|$($socket.LocalPort)|$($socket.RemoteAddress)|$($socket.RemotePort)|$($socket.OwningProcess)"
                proto = 'TCP'; family = $(if ($socket.LocalAddress.Contains(':')) { 6 } else { 4 })
                localIp = [string]$socket.LocalAddress; localPort = [int]$socket.LocalPort
                remoteIp = [string]$socket.RemoteAddress; remotePort = [int]$socket.RemotePort
                state = ([string]$socket.State).ToUpperInvariant(); inode = ''; pid = [int]$socket.OwningProcess
                comm = $(if ($owner) { $owner.name } else { 'Unknown process' }); exe = $(if ($owner) { $owner.exe } else { '' })
                uid = -1; direction = 'unknown'
            }
            if ($owner -and $null -ne $owner.startedAt) { $entry.processStartedAt = $owner.startedAt }
            $sockets.Add($entry)
        }
        foreach ($socket in $udp) {
            $owner = $processes[[int]$socket.OwningProcess]
            $entry = [ordered]@{
                id = "UDP|$($socket.LocalAddress)|$($socket.LocalPort)|$($socket.OwningProcess)"
                proto = 'UDP'; family = $(if ($socket.LocalAddress.Contains(':')) { 6 } else { 4 })
                localIp = [string]$socket.LocalAddress; localPort = [int]$socket.LocalPort
                remoteIp = ''; remotePort = 0; state = 'BOUND'; inode = ''; pid = [int]$socket.OwningProcess
                comm = $(if ($owner) { $owner.name } else { 'Unknown process' }); exe = $(if ($owner) { $owner.exe } else { '' })
                uid = -1; direction = 'unknown'
            }
            if ($owner -and $null -ne $owner.startedAt) { $entry.processStartedAt = $owner.startedAt }
            $sockets.Add($entry)
        }
        $traffic = Get-NativeTraffic
        # Timestamp the measured counters rather than the beginning of a slow
        # process/CIM enumeration. A counter failure must not erase valid sockets.
        $snapshot = [ordered]@{ at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); sockets = @($sockets.ToArray())
            rxBytes = $traffic.rxBytes; txBytes = $traffic.txBytes; trafficAvailable = $traffic.trafficAvailable
            tcpInuse = $tcp.Count; udpInuse = $udp.Count; capture = 'windows'; available = $true; platform = 'win32'
            captureDurationMs = $captureTimer.ElapsedMilliseconds }
        if ($traffic.counterSource) { $snapshot.counterSource = $traffic.counterSource }
        if ($traffic.trafficError) { $snapshot.trafficError = $traffic.trafficError }
        return $snapshot
    } catch {
        return [ordered]@{ at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); sockets = @(); rxBytes = 0; txBytes = 0; tcpInuse = 0; udpInuse = 0
            capture = 'unavailable'; available = $false; platform = 'win32'; error = $_.Exception.Message
            trafficAvailable = $false; trafficError = $_.Exception.Message; captureDurationMs = $captureTimer.ElapsedMilliseconds }
    }
}

function Limit-ProcessText($Value, [int]$Maximum = 512) {
    $text = [string]$Value
    if ($text.Length -gt $Maximum) { return $text.Substring(0, $Maximum) }
    return $text
}

function Convert-ProcessPath($Value) {
    $text = [string]$Value
    if (-not $text -or $text.Length -gt 32700 -or $text -notmatch '^[a-zA-Z]:\\' -or
        $text -match '[\x00-\x1f<>"|?*]' -or $text.Substring(2).Contains(':')) { return '' }
    try { return [IO.Path]::GetFullPath($text) } catch { return '' }
}

function Get-ProcessRows {
    # Select only these properties at the provider; CommandLine is never collected.
    return @(Get-CimInstance -Query 'SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate FROM Win32_Process' -OperationTimeoutSec 10 -ErrorAction Stop)
}

function Get-ProcessServiceRows {
    return @(Get-CimInstance -Query 'SELECT Name,DisplayName,State,ProcessId FROM Win32_Service WHERE ProcessId > 0' -OperationTimeoutSec 10 -ErrorAction Stop)
}

function Convert-ProcessEntry($Row) {
    $issues = [Collections.Generic.List[string]]::new()
    $startedAt = Convert-ProcessStartedAt $Row.CreationDate
    $exe = Convert-ProcessPath $Row.ExecutablePath
    if ($null -eq $startedAt) { $issues.Add('Process start time is unavailable; identity cannot be verified.') }
    if (-not $exe) { $issues.Add('Executable path is unavailable or is not a supported local path.') }
    return [ordered]@{ pid = [long]$Row.ProcessId; name = (Limit-ProcessText $Row.Name 260); exe = $exe
        parentPid = $(if ($null -ne $Row.ParentProcessId) { [long]$Row.ParentProcessId } else { $null })
        startedAt = $startedAt; services = @(); errors = @($issues.ToArray()) }
}

function Get-HostedService($Row) {
    $issues = [Collections.Generic.List[string]]::new()
    $service = [ordered]@{ name = (Limit-ProcessText $Row.Name 256); displayName = (Limit-ProcessText $Row.DisplayName 512); state = (Limit-ProcessText $Row.State 64) }
    # Service names come from Windows, never caller-controlled registry paths.
    # OpenSubKey returns null for a missing Parameters key, which is normal for EXE services.
    $key = $null
    try {
        if ([string]$Row.Name -match '[\\/\x00-\x1f]' -or ([string]$Row.Name).Length -gt 256) { throw 'Unsupported service name.' }
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\' + [string]$Row.Name + '\Parameters', $false)
        if ($key) {
            $rawDll = $key.GetValue('ServiceDll', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($rawDll -is [string] -and $rawDll) {
                $dll = Convert-ProcessPath ([Environment]::ExpandEnvironmentVariables($rawDll))
                if ($dll) { $service.serviceDll = $dll } else { $issues.Add('Configured ServiceDll is not a supported local path.') }
            }
        }
    } catch { $issues.Add('ServiceDll configuration is not accessible.') }
    finally { if ($key) { $key.Dispose() } }
    if ($issues.Count) { $service.errors = @($issues.ToArray()) }
    return $service
}

function Get-NativeProcessSnapshot {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $errors = [Collections.Generic.List[string]]::new()
    $result = [ordered]@{ at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); available = $false; processes = @(); errors = @(); truncated = $false; captureDurationMs = 0 }
    try {
        $rows = @(Get-ProcessRows)
        if ($rows.Count -gt 4096) { $result.truncated = $true; $rows = @($rows | Select-Object -First 4096); $errors.Add('Process inventory was limited to 4096 entries.') }
        $entries = [Collections.Generic.List[object]]::new()
        $byPid = @{}
        foreach ($row in $rows) {
            $entry = Convert-ProcessEntry $row
            if ($byPid.ContainsKey($entry.pid)) { continue }
            $byPid[$entry.pid] = $entry
            $entries.Add($entry)
        }
        $serviceRows = @()
        $servicesAvailable = $true
        try {
            $serviceRows = @(Get-ProcessServiceRows)
            if ($serviceRows.Count -gt 16384) { $result.truncated = $true; $serviceRows = @($serviceRows | Select-Object -First 16384); $errors.Add('Service inventory was limited to 16384 entries.') }
        } catch { $servicesAvailable = $false; $errors.Add('Windows service inventory is unavailable; empty service lists do not establish the absence of hosted services.') }
        if ($servicesAvailable) {
            $after = @{}
            try {
                foreach ($row in @(Get-ProcessRows)) { $after[[long]$row.ProcessId] = Convert-ProcessStartedAt $row.CreationDate }
            } catch { $errors.Add('Process identities could not be rechecked; service associations were withheld.') }
            $servicesSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($serviceRow in $serviceRows) {
                $entry = $byPid[[long]$serviceRow.ProcessId]
                if (-not $entry) { continue }
                if ($null -eq $entry.startedAt -or -not $after.ContainsKey($entry.pid) -or $after[$entry.pid] -ne $entry.startedAt) {
                    if ($entry.errors -notcontains 'Service association withheld: process identity changed or became unavailable.') {
                        $entry.errors += 'Service association withheld: process identity changed or became unavailable.'
                    }
                    continue
                }
                if (-not $servicesSeen.Add([string]$serviceRow.Name)) { continue }
                if ($entry.services.Count -ge 128) {
                    if ($entry.errors -notcontains 'Hosted service list was limited to 128 entries.') { $entry.errors += 'Hosted service list was limited to 128 entries.' }
                    $result.truncated = $true
                    continue
                }
                $entry.services += Get-HostedService $serviceRow
            }
        }
        $result.processes = @($entries.ToArray())
        $result.available = $true
    } catch { $errors.Add('Windows process inventory could not be read.') }
    $result.at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $result.captureDurationMs = $timer.ElapsedMilliseconds
    $result.errors = @($errors.ToArray())
    return $result
}

function Assert-ProcessIdentity($Identity) {
    if ($Identity -isnot [pscustomobject] -or @($Identity.PSObject.Properties.Name | Where-Object { $_ -cnotin @('pid', 'startedAt') }).Count) { throw 'An exact process ID and start time are required.' }
    foreach ($field in @('pid', 'startedAt')) {
        $value = $Identity.$field
        if ($value -isnot [ValueType] -or $value -is [bool] -or [double]::IsNaN([double]$value) -or
            [double]::IsInfinity([double]$value) -or [double]$value -ne [Math]::Floor([double]$value) -or $value -lt 1) { throw 'An exact process ID and start time are required.' }
    }
    if ($Identity.pid -gt 4294967295 -or $Identity.startedAt -gt 8640000000000000) { throw 'Process identity is outside the supported range.' }
}

function Get-VerifiedProcess($Identity) {
    $process = Get-Process -Id $Identity.pid -ErrorAction Stop
    $startedAt = Convert-ProcessStartedAt $process.StartTime
    if ($null -eq $startedAt -or $startedAt -ne $Identity.startedAt) { $process.Dispose(); throw 'Process identity changed or became unavailable. Refresh the process list.' }
    return $process
}

function Get-InspectionModules($Process) {
    # Enumerate OS module records only. Do not open modules or execute their code.
    $modules = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $truncated = $false
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $nativeModules = $Process.Modules
        # PowerShell can suppress property-getter failures into null, even under
        # ErrorActionPreference Stop. Null is not an observed empty module list.
        if ($null -eq $nativeModules) { throw 'Module enumeration was unavailable.' }
        foreach ($module in $nativeModules) {
            if ($modules.Count -ge 256) { $truncated = $true; break }
            $modulePath = Convert-ProcessPath $module.FileName
            if (-not $modulePath) { if ($errors.Count -eq 0) { $errors.Add('One or more loaded module paths were unavailable or unsupported.') }; continue }
            if ($seen.Add($modulePath)) { $modules.Add([ordered]@{ name = (Limit-ProcessText $module.ModuleName 260); path = $modulePath }) }
        }
    } catch { $errors.Add('Loaded modules are partially or wholly unavailable; Windows may protect this process.') }
    return @{ modules = @($modules.ToArray()); truncated = $truncated; errors = @($errors.ToArray()) }
}

function Get-InspectionFile($Program) {
    $errors = [Collections.Generic.List[string]]::new()
    $result = @{ signature = @{ status = 'unknown' }; errors = @() }
    $stream = $null
    try {
        $canonical = Convert-ProcessPath $Program
        if (-not $canonical) { throw 'Executable path is unavailable.' }
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($canonical))
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { throw 'Remote executable inspection is not supported.' }
        # Check each component before following it, including links to remote disks.
        $componentPath = [IO.Path]::GetPathRoot($canonical)
        $file = $null
        foreach ($component in $canonical.Substring($componentPath.Length).Split('\')) {
            $componentPath = [IO.Path]::Combine($componentPath, $component)
            $file = Get-Item -LiteralPath $componentPath -Force -ErrorAction Stop
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Executable inspection through filesystem links is not supported.' }
        }
        if ($file -isnot [IO.FileInfo] -or $file.PSIsContainer) { throw 'The executable is not a regular file.' }
        # Hold a read lock through hashing and signature verification. A replacement
        # or writable file cannot yield a hash from one binary and signature from another.
        $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -gt 536870912) { throw 'Executable exceeds the 512 MiB inspection limit.' }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $result.sha256 = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        try {
            Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
            $status = switch ([string]$signature.Status) {
                'Valid' { 'valid' } 'NotSigned' { 'unsigned' }
                'HashMismatch' { 'invalid' } 'NotTrusted' { 'invalid' }
                default { 'unknown' }
            }
            $result.signature = @{ status = $status; nativeStatus = (Limit-ProcessText $signature.Status 64) }
            if ($signature.SignerCertificate) { $result.signature.publisher = Limit-ProcessText $signature.SignerCertificate.Subject 512 }
        } catch { $errors.Add('Authenticode verification could not complete.') }
    } catch { $errors.Add('Executable hash/signature unavailable: ' + (Limit-ProcessText $_.Exception.Message 256)) }
    finally { if ($stream) { $stream.Dispose() } }
    $result.errors = @($errors.ToArray())
    return $result
}

function Get-NativeProcessInspection($Identity) {
    Assert-ProcessIdentity $Identity
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $errors = [Collections.Generic.List[string]]::new()
    $result = [ordered]@{ at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); available = $false; identity = $Identity
        children = @(); modules = @(); modulesTruncated = $false; signature = @{ status = 'unknown' }; errors = @(); captureDurationMs = 0 }
    $process = $null
    try {
        $process = Get-VerifiedProcess $Identity
        $inventory = Get-NativeProcessSnapshot
        if (-not $inventory.available) { throw 'Windows process inventory could not be read.' }
        foreach ($message in $inventory.errors) { $errors.Add($message) }
        $entry = @($inventory.processes | Where-Object { $_.pid -eq $Identity.pid -and $null -ne $_.startedAt -and $_.startedAt -eq $Identity.startedAt })
        if ($entry.Count -ne 1) { throw 'Process exited or its identity changed. Refresh the process list.' }
        $entry = $entry[0]
        $check = Get-VerifiedProcess $Identity
        $check.Dispose()
        $moduleResult = Get-InspectionModules $process
        $fileResult = Get-InspectionFile $entry.exe
        # Slow metadata reads must not attach their results to a newly reused PID.
        $check = Get-VerifiedProcess $Identity
        $check.Dispose()
        $parent = @($inventory.processes | Where-Object { $_.pid -ne $entry.pid -and $_.pid -eq $entry.parentPid -and $null -ne $_.startedAt -and $_.startedAt -le $entry.startedAt })
        if ($parent.Count -eq 1) { $result.parent = $parent[0] }
        elseif ($entry.parentPid -gt 0) { $errors.Add('Parent identity is unavailable; the original parent may have exited or its PID may have been reused.') }
        $children = @($inventory.processes | Where-Object { $_.pid -ne $entry.pid -and $_.parentPid -eq $entry.pid -and $null -ne $_.startedAt -and $_.startedAt -ge $entry.startedAt })
        if ($children.Count -gt 256) { $errors.Add('Child process list was limited to 256 entries.'); $children = @($children | Select-Object -First 256) }
        $result.process = $entry
        $result.children = $children
        $result.modules = $moduleResult.modules
        $result.modulesTruncated = $moduleResult.truncated
        $result.signature = $fileResult.signature
        if ($fileResult.sha256) { $result.sha256 = $fileResult.sha256 }
        foreach ($message in @($moduleResult.errors) + @($fileResult.errors)) { $errors.Add($message) }
        $result.available = $true
    } catch { $errors.Add('Process inspection unavailable: ' + (Limit-ProcessText $_.Exception.Message 256)) }
    finally { if ($process) { $process.Dispose() } }
    $result.at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $result.errors = @($errors.ToArray())
    $result.captureDurationMs = $timer.ElapsedMilliseconds
    return $result
}

try {
    $raw = [Console]::In.ReadToEnd()
    if ($raw.Length -gt 65536) { throw 'Native request is too large.' }
    $request = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    if ($request -isnot [pscustomobject] -or @($request.PSObject.Properties.Name | Where-Object { $_ -cnotin @('operation', 'data') }).Count -gt 0) {
        throw 'Invalid native request.'
    }
    $result = switch -CaseSensitive ($request.operation) {
        'status' { Get-NativeStatus }
        'snapshot' { Get-NativeSnapshot }
        'processes' {
            if ($null -ne $request.data) { throw 'This operation takes no arguments.' }
            Get-NativeProcessSnapshot
        }
        'process-inspect' { Get-NativeProcessInspection $request.data }
        'list' {
            Import-Module NetSecurity -ErrorAction Stop
            $persistentRules = @(Get-OwnedRules)
            $activeRules = @{}
            foreach ($activeRule in @(Get-OwnedRules 'ActiveStore')) { $activeRules[[string]$activeRule.Name] = $activeRule }
            ,@($persistentRules | ForEach-Object { Add-ActiveRuleStatus (Convert-Rule $_) $activeRules[[string]$_.Name] })
        }
        'inspect' {
            # Available only to the explicit test CLI, never exposed through renderer IPC.
            Assert-Id $request.data.id
            Import-Module NetSecurity -ErrorAction Stop
            $persistent = Get-OwnedRule $request.data.id
            $active = Get-OwnedRule $request.data.id 'ActiveStore'
            [ordered]@{
                persistent = Get-RuleDiagnostic $persistent
                active = Get-RuleDiagnostic $active
                profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True')
                        allowLocalFirewallRules = $(switch ([string]$_.AllowLocalFirewallRules) { 'True' { $true } 'False' { $false } default { $null } })
                        disabledInterfaceAliases = @($_.DisabledInterfaceAliases | ForEach-Object { [string]$_ }) }
                })
            }
        }
        'apply' {
            Assert-Elevated
            $program = Assert-Rule $request.data
            Import-Module NetSecurity -ErrorAction Stop
            $id = 'Limen-' + [guid]::NewGuid().ToString()
            $createdAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            $arguments = @{
                Name = $id; DisplayName = "Limen: $($request.data.action) $($request.data.direction) - $([IO.Path]::GetFileName($program))"
                Group = $LimenGroup; Description = "Limen v1; createdAt=$createdAt"
                Program = $program; Direction = $(if ($request.data.direction -eq 'in') { 'Inbound' } else { 'Outbound' })
                Action = $(if ($request.data.action -eq 'allow') { 'Allow' } else { 'Block' })
                Protocol = $(if ($request.data.protocol -eq 'ANY') { 'Any' } else { $request.data.protocol })
                Profile = 'Any'; Enabled = 'True'; PolicyStore = 'PersistentStore'; ErrorAction = 'Stop'
            }
            if ($null -ne $request.data.remoteAddress) { $arguments.RemoteAddress = $request.data.remoteAddress }
            if ($null -ne $request.data.remotePort) { $arguments.RemotePort = [int]$request.data.remotePort }
            if ($null -ne $request.data.localPort) { $arguments.LocalPort = [int]$request.data.localPort }
            try {
                $null = New-NetFirewallRule @arguments
                $stored = Convert-Rule (Get-OwnedRule $id)
                Assert-MatchingRule $stored $request.data $true
                $activeRule = Get-OwnedRule $id 'ActiveStore'
                $active = Convert-Rule $activeRule
                Assert-MatchingRule $active $request.data $true
                Add-ActiveRuleStatus $stored $activeRule
            } catch {
                $failure = $_.Exception.Message
                # Roll back only the fresh exact ID, never an existing or foreign rule.
                try {
                    $own = @(Get-OwnedRules | Where-Object { $_.Name -ceq $id })
                    if ($own.Count -eq 1) { $own[0] | Remove-NetFirewallRule -ErrorAction Stop }
                } catch { $failure += " Cleanup failed for $id; inspect Windows Defender Firewall." }
                throw $failure
            }
        }
        'remove' {
            Assert-Elevated
            Assert-Id $request.data.id
            Import-Module NetSecurity -ErrorAction Stop
            $rule = Get-OwnedRule $request.data.id
            $rule | Remove-NetFirewallRule -ErrorAction Stop
            if (@(Get-OwnedRules | Where-Object { $_.Name -ceq $request.data.id }).Count -ne 0 -or
                @(Get-OwnedRules 'ActiveStore' | Where-Object { $_.Name -ceq $request.data.id }).Count -ne 0) {
                throw 'Windows has not confirmed rule removal. Refresh and inspect the rule.'
            }
            [ordered]@{ id = $request.data.id; removed = $true }
        }
        'enabled' {
            Assert-Elevated
            Assert-Id $request.data.id
            if ($request.data.enabled -isnot [bool]) { throw 'Enabled must be a boolean.' }
            Import-Module NetSecurity -ErrorAction Stop
            $rule = Get-OwnedRule $request.data.id
            $expected = Convert-Rule $rule
            try {
                $rule | Set-NetFirewallRule -Enabled $(if ($request.data.enabled) { 'True' } else { 'False' }) -ErrorAction Stop
                $stored = Convert-Rule (Get-OwnedRule $request.data.id)
                Assert-MatchingRule $stored $expected $request.data.enabled
                $activeRule = Get-OwnedRule $request.data.id 'ActiveStore'
                $active = Convert-Rule $activeRule
                Assert-MatchingRule $active $expected $request.data.enabled
                Add-ActiveRuleStatus $stored $activeRule
            } catch {
                $failure = $_.Exception.Message
                try {
                    $original = Get-OwnedRule $request.data.id
                    $original | Set-NetFirewallRule -Enabled $(if ($expected.enabled) { 'True' } else { 'False' }) -ErrorAction Stop
                    $restored = Convert-Rule (Get-OwnedRule $request.data.id)
                    Assert-MatchingRule $restored $expected $expected.enabled
                    $restoredActive = Convert-Rule (Get-OwnedRule $request.data.id 'ActiveStore')
                    Assert-MatchingRule $restoredActive $expected $expected.enabled
                    $failure += ' The previous enabled state was restored and verified.'
                } catch {
                    $failure += " The previous state could not be restored or verified for $($request.data.id). Its enabled state may have changed; refresh and inspect Windows Defender Firewall."
                }
                throw $failure
            }
        }
        default { throw 'Unsupported native operation.' }
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ ok = $true; data = $result } -Depth 12 -Compress))
    exit 0
} catch {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Depth 4 -Compress))
    exit 1
}
