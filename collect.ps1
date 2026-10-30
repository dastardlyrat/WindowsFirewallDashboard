$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$issues = [System.Collections.Generic.List[string]]::new()
function Read-Section([string]$name, [scriptblock]$action) {
    try { & $action } catch { $issues.Add("${name}: $($_.Exception.Message)") }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$profiles = @(Read-Section 'Profiles' { Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,LogAllowed,LogBlocked,LogIgnored,LogFileName,LogMaxSizeKilobytes | ForEach-Object {
    [pscustomobject]@{Name=[string]$_.Name;Enabled=[string]$_.Enabled;Inbound=[string]$_.DefaultInboundAction;Outbound=[string]$_.DefaultOutboundAction;LocalRules=[string]$_.AllowLocalFirewallRules;LogAllowed=[bool]$_.LogAllowed;LogBlocked=[bool]$_.LogBlocked;LogIgnored=[bool]$_.LogIgnored;LogPath=$_.LogFileName;LogSizeKB=$_.LogMaxSizeKilobytes}
} })
$networks = @(Read-Section 'Networks' { Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,@{n='Category';e={[string]$_.NetworkCategory}},@{n='IPv4';e={[string]$_.IPv4Connectivity}},@{n='IPv6';e={[string]$_.IPv6Connectivity}} })
$rawRules = @(Read-Section 'Rules' { Get-NetFirewallRule -PolicyStore ActiveStore })
$maps = @{}
$commands = @{Port='Get-NetFirewallPortFilter';Address='Get-NetFirewallAddressFilter';Application='Get-NetFirewallApplicationFilter';Service='Get-NetFirewallServiceFilter';Interface='Get-NetFirewallInterfaceFilter';Security='Get-NetFirewallSecurityFilter'}
foreach ($kind in $commands.Keys) {
    $maps[$kind] = @{}
    $command = $commands[$kind]
    Read-Section "$kind filters" { $rawRules | & $command | ForEach-Object { $maps[$kind][$_.InstanceID] = $_ } }
}
$rules = @(foreach ($r in $rawRules) {
    $p=$maps.Port[$r.InstanceID];$a=$maps.Address[$r.InstanceID];$x=$maps.Application[$r.InstanceID];$s=$maps.Service[$r.InstanceID];$i=$maps.Interface[$r.InstanceID];$q=$maps.Security[$r.InstanceID]
    [pscustomobject]@{Id=$r.Name;Name=$r.DisplayName;Group=$r.DisplayGroup;Enabled=([string]$r.Enabled -eq 'True');Direction=[string]$r.Direction;Action=[string]$r.Action;Profile=[string]$r.Profile;Protocol=[string]$p.Protocol;LocalPort=@($p.LocalPort);RemotePort=@($p.RemotePort);IcmpType=@($p.IcmpType);LocalAddress=@($a.LocalAddress);RemoteAddress=@($a.RemoteAddress);Application=$x.Program;Package=$x.Package;Service=$s.Service;Interface=@($i.InterfaceAlias);DynamicTarget=[string]$p.DynamicTarget;LocalUser=$q.LocalUser;RemoteUser=$q.RemoteUser;RemoteMachine=$q.RemoteMachine;Authentication=[string]$q.Authentication;Encryption=[string]$q.Encryption;Edge=[string]$r.EdgeTraversalPolicy;Source=[string]$r.PolicyStoreSourceType;Store=$r.PolicyStoreSource;Status=[string]$r.EnforcementStatus}
})
$processes=@{}; Read-Section 'Process names' { Get-Process | ForEach-Object { $processes[[int]$_.Id]=$_.ProcessName } }
$listeners=@(Read-Section 'TCP listeners' { Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{Protocol='TCP';Address=$_.LocalAddress;Port=$_.LocalPort;PID=$_.OwningProcess;Process=$processes[[int]$_.OwningProcess]} } }; Read-Section 'UDP endpoints' { Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{Protocol='UDP';Address=$_.LocalAddress;Port=$_.LocalPort;PID=$_.OwningProcess;Process=$processes[[int]$_.OwningProcess]} } })
$services=@(Read-Section 'Firewall services' { Get-Service MpsSvc,BFE | Select-Object Name,@{n='Status';e={[string]$_.Status}},@{n='Startup';e={[string]$_.StartType}} })
$dependencyMap=@{}
Read-Section 'Service dependencies' {
    Get-Service | ForEach-Object {
        try { $dependencyMap[$_.Name]=[pscustomobject]@{Requires=@($_.ServicesDependedOn | ForEach-Object Name | Where-Object { $_ })} }
        catch { $issues.Add("Dependencies for $($_.Name): $($_.Exception.Message)") }
    }
}
$inventory=@(Read-Section 'All services' {
    Get-CimInstance Win32_Service | ForEach-Object {
        $dep=$dependencyMap[$_.Name]
        [pscustomobject]@{Name=$_.Name;DisplayName=$_.DisplayName;Description=$_.Description;State=$_.State;Startup=$_.StartMode;DelayedAutoStart=$_.DelayedAutoStart;Account=$_.StartName;Path=$_.PathName;PID=$_.ProcessId;Requires=@($dep.Requires | Where-Object { $_ });Dependents=@();DependenciesAvailable=($null -ne $dep)}
    }
})
foreach ($entry in $inventory) {
    $entry.Dependents=@($inventory | Where-Object { $_.Requires -contains $entry.Name } | ForEach-Object Name)
}
$adapters=@(Read-Section 'Adapters' { Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,Status,ifIndex })
$providers=@(Read-Section 'Firewall providers' { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | Select-Object displayName,productState })
$ipsec=@(Read-Section 'IPsec rules' { Get-NetIPsecRule -PolicyStore ActiveStore | Select-Object DisplayName,@{n='Enabled';e={[string]$_.Enabled}},@{n='Profile';e={[string]$_.Profile}} })
[pscustomobject]@{CollectedAt=[DateTimeOffset]::Now.ToString('o');Elevated=$elevated;Profiles=$profiles;Networks=$networks;Rules=$rules;Listeners=$listeners;Services=$services;ServiceInventory=$inventory;WindowsDirectory=$env:windir;Adapters=$adapters;Providers=$providers;IPsec=$ipsec;Issues=@($issues)} | ConvertTo-Json -Depth 8 -Compress
