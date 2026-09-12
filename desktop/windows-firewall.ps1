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

function Assert-MatchingRule($Actual, $Expected, [bool]$Enabled) {
    if ($Actual.program -ine $Expected.program -or $Actual.action -cne $Expected.action -or
        $Actual.direction -cne $Expected.direction -or $Actual.protocol -cne $Expected.protocol -or $Actual.enabled -ne $Enabled) {
        throw 'Windows returned a different rule configuration. Refresh and inspect the rule.'
    }
    foreach ($port in @('localPort', 'remotePort')) {
        if ([string]$Actual.$port -cne [string]$Expected.$port) { throw 'Windows returned different port restrictions. Refresh and inspect the rule.' }
    }
    if ($null -ne $Expected.remoteAddress) {
        if ($null -eq $Actual.remoteAddress -or -not [Net.IPAddress]::Parse($Actual.remoteAddress).Equals([Net.IPAddress]::Parse($Expected.remoteAddress))) {
            throw 'Windows returned a different remote address. Refresh and inspect the rule.'
        }
    } elseif ($null -ne $Actual.remoteAddress) { throw 'Windows returned a different remote address scope.' }
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

function Get-NativeSnapshot {
    $at = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $processes = @{}
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            $exe = ''
            try { $exe = [string]$process.Path } catch { }
            $processes[[int]$process.Id] = @{ name = [string]$process.ProcessName; exe = $exe }
        }
        $sockets = [Collections.Generic.List[object]]::new()
        foreach ($socket in $tcp) {
            $owner = $processes[[int]$socket.OwningProcess]
            $sockets.Add([ordered]@{
                id = "TCP|$($socket.LocalAddress)|$($socket.LocalPort)|$($socket.RemoteAddress)|$($socket.RemotePort)|$($socket.OwningProcess)"
                proto = 'TCP'; family = $(if ($socket.LocalAddress.Contains(':')) { 6 } else { 4 })
                localIp = [string]$socket.LocalAddress; localPort = [int]$socket.LocalPort
                remoteIp = [string]$socket.RemoteAddress; remotePort = [int]$socket.RemotePort
                state = ([string]$socket.State).ToUpperInvariant(); inode = ''; pid = [int]$socket.OwningProcess
                comm = $(if ($owner) { $owner.name } else { 'Unknown process' }); exe = $(if ($owner) { $owner.exe } else { '' })
                uid = -1; direction = 'unknown'
            })
        }
        foreach ($socket in $udp) {
            $owner = $processes[[int]$socket.OwningProcess]
            $sockets.Add([ordered]@{
                id = "UDP|$($socket.LocalAddress)|$($socket.LocalPort)|$($socket.OwningProcess)"
                proto = 'UDP'; family = $(if ($socket.LocalAddress.Contains(':')) { 6 } else { 4 })
                localIp = [string]$socket.LocalAddress; localPort = [int]$socket.LocalPort
                remoteIp = ''; remotePort = 0; state = 'BOUND'; inode = ''; pid = [int]$socket.OwningProcess
                comm = $(if ($owner) { $owner.name } else { 'Unknown process' }); exe = $(if ($owner) { $owner.exe } else { '' })
                uid = -1; direction = 'unknown'
            })
        }
        # Host adapter totals only. Windows endpoint tables do not provide per-process bytes.
        $adapters = @(Get-NetAdapterStatistics -ErrorAction Stop)
        $received = 0L; $sent = 0L
        foreach ($adapter in $adapters) { $received += [long]$adapter.ReceivedBytes; $sent += [long]$adapter.SentBytes }
        return [ordered]@{ at = $at; sockets = @($sockets.ToArray()); rxBytes = $received; txBytes = $sent
            tcpInuse = $tcp.Count; udpInuse = $udp.Count; capture = 'windows'; available = $true; platform = 'win32' }
    } catch {
        return [ordered]@{ at = $at; sockets = @(); rxBytes = 0; txBytes = 0; tcpInuse = 0; udpInuse = 0
            capture = 'unavailable'; available = $false; platform = 'win32'; error = $_.Exception.Message }
    }
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
