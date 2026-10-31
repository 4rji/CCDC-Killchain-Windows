<#
.SYNOPSIS
  CCDC Windows baseline enumeration (blue team). Run as Administrator.
  Writes CSV/TXT output to C:\CCDC\enum_<HOST>_<timestamp>\ plus a readable
  summary.html report, so you can re-run later and diff against the first baseline.

.USAGE
  Full run:
    powershell -ExecutionPolicy Bypass -File .\ccdc-win-enum.ps1
  Rebuild the report for a folder you already have:
    powershell -ExecutionPolicy Bypass -File .\ccdc-win-enum.ps1 -ReportOnly C:\CCDC\enum_DC01_20261031_132600
  Compare two runs:
    Compare-Object (Import-Csv old\services.csv) (Import-Csv new\services.csv) -Property Name,PathName,StartMode
#>
param([string]$ReportOnly)

# =====================================================================
#  Readable HTML report built from the CSV files in an output folder
# =====================================================================
function New-CcdcReport {
    param([string]$Dir)

    function Load($name) {
        $f = Join-Path $Dir "$name.csv"
        if (Test-Path $f) { @(Import-Csv $f) } else { @() }
    }
    function Enc($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    function Table($rows) {
        if (-not $rows -or $rows.Count -eq 0) { return '<p class="none">No results</p>' }
        (($rows | ConvertTo-Html -Fragment) -join "`n")
    }

    $checks = New-Object System.Collections.ArrayList
    function Check($level, $text) { [void]$checks.Add([pscustomobject]@{ Level = $level; Text = $text }) }

    # ---------- Quick checks (plain-English findings) ----------
    $users = Load local_users
    $guest = $users | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled -eq 'True' }
    if ($guest) { Check 'BAD' 'Local Guest account is enabled.' }
    $noPw = $users | Where-Object { $_.Enabled -eq 'True' -and $_.PasswordRequired -eq 'False' }
    if ($noPw) { Check 'BAD' ("Enabled local accounts that don't require a password: " + (($noPw.Name) -join ', ')) }

    $admins = Load local_group_members | Where-Object { $_.Group -eq 'Administrators' }
    if ($admins) { Check 'INFO' ("Local Administrators members (verify each): " + (($admins.Name) -join ', ')) }

    $da = Load ad_priv_groups | Where-Object { $_.Group -eq 'Domain Admins' }
    if ($da) { Check 'INFO' ("Domain Admins members (verify each): " + (($da.SamAccountName) -join ', ')) }

    $asrep = Load flag_asrep_roastable
    if ($asrep) { Check 'BAD' ("Accounts without Kerberos pre-auth (AS-REP roastable): " + (($asrep.SamAccountName) -join ', ')) }
    $kerb = Load flag_kerberoastable | Where-Object { $_.SamAccountName -ne 'krbtgt' }
    if ($kerb) { Check 'WARN' ("User accounts with SPNs (Kerberoastable - use long passwords): " + (($kerb.SamAccountName) -join ', ')) }
    $pnr = Load flag_passwd_not_required
    if ($pnr) { Check 'BAD' ("AD accounts flagged PasswordNotRequired: " + (($pnr.SamAccountName) -join ', ')) }

    $sec = Load security_settings | Select-Object -First 1
    if ($sec) {
        if ($sec.RDP_Disabled -eq '0' -and $sec.RDP_NLA -ne '1') { Check 'BAD' 'RDP is enabled without Network Level Authentication.' }
        if ($sec.WDigest_UseLogonCredential -eq '1') { Check 'BAD' 'WDigest is caching cleartext passwords in memory (UseLogonCredential = 1).' }
        if ($sec.LSA_RunAsPPL -ne '1') { Check 'WARN' 'LSA protection (RunAsPPL) is off - credential dumping is easier.' }
    }

    $smb = Load smb_config | Select-Object -First 1
    if ($smb) {
        if ($smb.EnableSMB1Protocol -eq 'True') { Check 'BAD' 'SMBv1 is enabled.' }
        if ($smb.RequireSecuritySignature -ne 'True') { Check 'WARN' 'SMB signing is not required.' }
    }

    foreach ($p in (Load firewall_profiles)) {
        if ($p.Enabled -ne 'True') { Check 'BAD' "Windows Firewall $($p.Name) profile is OFF." }
        elseif ($p.DefaultInboundAction -eq 'Allow') { Check 'BAD' "Windows Firewall $($p.Name) profile allows inbound by default." }
    }

    $def = Load defender_status | Select-Object -First 1
    if (-not $def) { Check 'WARN' 'Could not read Defender status (removed, disabled, or replaced by another AV?).' }
    elseif ($def.RealTimeProtectionEnabled -ne 'True') { Check 'BAD' 'Defender real-time protection is OFF.' }
    $excl = Load flag_defender_exclusions
    if ($excl) { Check 'BAD' 'Defender has exclusions configured - attackers use these to hide tools.' }

    $ifeo = Load flag_ifeo_debuggers
    if ($ifeo) { Check 'BAD' ("Debugger hijack set on: " + (($ifeo.Image) -join ', ') + " (sethc/utilman = sticky-keys backdoor).") }
    $wl = Load winlogon | Select-Object -First 1
    if ($wl -and ($wl.Shell -notmatch '^explorer\.exe,?$' -or $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$')) {
        Check 'BAD' "Winlogon Shell/Userinit changed from default: Shell='$($wl.Shell)' Userinit='$($wl.Userinit)'"
    }
    if (Load wmi_consumers) { Check 'BAD' 'WMI command-line event consumers exist (common persistence) - review the WMI section.' }

    $tasks = Load scheduled_tasks_nonms
    if ($tasks) { Check 'INFO' "$($tasks.Count) non-Microsoft scheduled task(s) - review each one." }
    $runs = Load run_keys
    if ($runs) { Check 'INFO' "$($runs.Count) Run/RunOnce registry entr(ies) - review each one." }
    $svcs = Load flag_services_nonwindows
    if ($svcs) { Check 'INFO' "$($svcs.Count) service(s) running from outside C:\Windows - review each one." }
    $unq = Load flag_unquoted_service_paths
    if ($unq) { Check 'WARN' "$($unq.Count) service(s) with unquoted paths containing spaces (privilege escalation risk)." }
    $recent = Load flag_recent_executables
    if ($recent) { Check 'WARN' "$($recent.Count) script/executable file(s) recently written to temp, public, or web folders." }

    $listen = Load tcp_listening
    if ($listen) {
        $ports = ($listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object { [int]$_ }) -join ', '
        Check 'INFO' "Listening TCP ports: $ports"
    }
    if ($checks.Count -eq 0) { Check 'OK' 'No issues detected by the quick checks.' }

    # ---------- Build HTML ----------
    $order = @{ 'BAD' = 0; 'WARN' = 1; 'INFO' = 2; 'OK' = 3 }
    $checkRows = ($checks | Sort-Object { $order[$_.Level] } | ForEach-Object {
        "<tr class='$($_.Level.ToLower())'><td class='lvl'>$($_.Level)</td><td>$(Enc $_.Text)</td></tr>"
    }) -join "`n"
    $nBad  = @($checks | Where-Object Level -eq 'BAD').Count
    $nWarn = @($checks | Where-Object Level -eq 'WARN').Count

    # title, csv name, open by default?
    $sections = @(
        @{ H = 'Red flags (details)'; Items = @(
            @('AS-REP roastable accounts','flag_asrep_roastable',$true),
            @('Kerberoastable accounts (krbtgt is normal)','flag_kerberoastable',$true),
            @('Password not required','flag_passwd_not_required',$true),
            @('Debugger (IFEO) hijacks','flag_ifeo_debuggers',$true),
            @('Defender exclusions','flag_defender_exclusions',$true),
            @('Unquoted service paths','flag_unquoted_service_paths',$true),
            @('Recent executables in drop folders','flag_recent_executables',$true)) },
        @{ H = 'Accounts'; Items = @(
            @('Local users','local_users',$true),
            @('Local privileged group members','local_group_members',$true),
            @('AD privileged group members','ad_priv_groups',$true),
            @('All AD users','ad_users',$false)) },
        @{ H = 'Persistence'; Items = @(
            @('Non-Microsoft scheduled tasks','scheduled_tasks_nonms',$true),
            @('Services outside C:\Windows','flag_services_nonwindows',$true),
            @('Run / RunOnce keys','run_keys',$true),
            @('Startup folders','startup_folders',$true),
            @('Winlogon','winlogon',$true),
            @('WMI event filters','wmi_filters',$true),
            @('WMI command-line consumers','wmi_consumers',$true),
            @('WMI bindings','wmi_bindings',$false)) },
        @{ H = 'Network'; Items = @(
            @('Listening TCP ports','tcp_listening',$true),
            @('Established TCP connections','tcp_established',$true),
            @('SMB shares','smb_shares',$true),
            @('SMB configuration','smb_config',$true),
            @('Firewall profiles','firewall_profiles',$true),
            @('Inbound allow rules','firewall_inbound_allow',$false),
            @('UDP endpoints','udp_listening',$false),
            @('DNS cache','dns_cache',$false)) },
        @{ H = 'Security settings'; Items = @(
            @('Security settings','security_settings',$true),
            @('Defender status','defender_status',$true)) },
        @{ H = 'Inventory'; Items = @(
            @('Installed roles/features','roles_features',$false),
            @('Installed software','installed_software',$false),
            @('Hotfixes','hotfixes',$false),
            @('AD computers','ad_computers',$false),
            @('Group Policy objects','gpos',$false),
            @('All services','services',$false),
            @('Running processes','processes',$false)) }
    )

    $body = New-Object System.Text.StringBuilder
    foreach ($s in $sections) {
        [void]$body.AppendLine("<h2>$(Enc $s.H)</h2>")
        foreach ($i in $s.Items) {
            $rows = Load $i[1]
            $open = if ($i[2] -and $rows.Count -gt 0) { ' open' } else { '' }
            [void]$body.AppendLine("<details$open><summary>$(Enc $i[0]) <span class='count'>($($rows.Count))</span></summary>")
            [void]$body.AppendLine((Table $rows))
            [void]$body.AppendLine('</details>')
        }
    }

    $machine = (Split-Path $Dir -Leaf) -replace '^enum_', ''
    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CCDC enum - $(Enc $machine)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fafafa}
 h1{margin:0 0 4px} .sub{color:#555;margin-bottom:16px}
 h2{border-bottom:2px solid #ccc;padding-bottom:4px;margin-top:32px}
 .pill{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-weight:600;margin-right:6px}
 .pbad{background:#c62828} .pwarn{background:#ef8f00}
 table{border-collapse:collapse;margin:8px 0 16px;font-size:13px;background:#fff}
 th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top;max-width:700px;word-break:break-word}
 th{background:#eee}
 #checks td.lvl{font-weight:700;width:60px}
 tr.bad td.lvl{color:#c62828} tr.warn td.lvl{color:#ef8f00} tr.info td.lvl{color:#1565c0} tr.ok td.lvl{color:#2e7d32}
 tr.bad{background:#fdecea} tr.warn{background:#fff4e0}
 details{margin:6px 0} summary{cursor:pointer;font-weight:600;padding:3px 0}
 .count{color:#777;font-weight:400} .none{color:#888;font-style:italic;margin:4px 0 8px 16px}
</style></head><body>
<h1>CCDC enumeration report</h1>
<div class="sub">$(Enc $machine) &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; folder: $(Enc $Dir)</div>
<span class="pill pbad">$nBad problems</span><span class="pill pwarn">$nWarn warnings</span>
<h2>Quick checks</h2>
<table id="checks">$checkRows</table>
<p class="sub">Text files in the folder (not shown here): systeminfo, ipconfig, arp, routes, auditpol, password_policy, errors.</p>
$($body.ToString())
</body></html>
"@
    $report = Join-Path $Dir 'summary.html'
    $html | Out-File $report -Encoding UTF8
    return $report
}

# ---------- Report-only mode ----------
if ($ReportOnly) {
    if (-not (Test-Path $ReportOnly)) { Write-Host "[!] Folder not found: $ReportOnly" -ForegroundColor Red; exit 1 }
    $r = New-CcdcReport -Dir (Resolve-Path $ReportOnly).Path
    Write-Host "[*] Report written: $r" -ForegroundColor Green
    Invoke-Item $r
    exit 0
}

# =====================================================================
#  Enumeration
# =====================================================================
Write-Host "=== CCDC enumeration starting on $env:COMPUTERNAME ===" -ForegroundColor Green

# Warn (don't stop) if not elevated - many checks return nothing without admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] NOT running as Administrator. Right-click PowerShell > 'Run as administrator' and run again." -ForegroundColor Red
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out   = "C:\CCDC\enum_$($env:COMPUTERNAME)_$stamp"
try {
    New-Item -ItemType Directory -Path $out -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Host "[!] Could not create $out : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host "[*] Output folder: $out" -ForegroundColor Green

# Individual checks fail quietly so one missing cmdlet doesn't stop the run;
# every error is still recorded in errors.txt at the end.
$ErrorActionPreference = 'SilentlyContinue'
$Error.Clear()

function Save {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$name)
    begin   { $items = New-Object System.Collections.ArrayList }
    process { if ($null -ne $InputObject) { [void]$items.Add($InputObject) } }
    end     { if ($items.Count) { $items | Export-Csv "$out\$name.csv" -NoTypeInformation -Encoding UTF8 }
              else { "No results" | Out-File "$out\$name.EMPTY.txt" } }
}
function Note($text) { Write-Host "[*] $text" -ForegroundColor Cyan }

# ---------- System ----------
Note 'System info'
systeminfo | Out-File "$out\systeminfo.txt"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Save -name hotfixes
if (Get-Command Get-WindowsFeature) {
    Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName | Save -name roles_features
}

# ---------- Local accounts ----------
Note 'Local users and groups'
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires, Description | Save -name local_users
foreach ($g in 'Administrators','Remote Desktop Users','Remote Management Users','Backup Operators') {
    Get-LocalGroupMember -Group $g | Select-Object @{n='Group';e={$g}}, Name, ObjectClass, PrincipalSource |
        Export-Csv "$out\local_group_members.csv" -Append -NoTypeInformation
}

# ---------- Active Directory (only if on a DC / RSAT present) ----------
if (Get-Module -ListAvailable ActiveDirectory) {
    Import-Module ActiveDirectory
    Note 'Active Directory'
    Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,whenCreated,adminCount,DoesNotRequirePreAuth,ServicePrincipalName |
        Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, whenCreated, adminCount, DoesNotRequirePreAuth,
                      @{n='SPNs';e={$_.ServicePrincipalName -join ';'}} | Save -name ad_users

    foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','DnsAdmins','Group Policy Creator Owners') {
        Get-ADGroupMember -Identity $g -Recursive | Select-Object @{n='Group';e={$g}}, SamAccountName, objectClass |
            Export-Csv "$out\ad_priv_groups.csv" -Append -NoTypeInformation
    }

    # Quick red flags
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object SamAccountName | Save -name flag_asrep_roastable
    Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName |
        Select-Object SamAccountName, @{n='SPNs';e={$_.ServicePrincipalName -join ';'}} | Save -name flag_kerberoastable
    Get-ADUser -Filter {PasswordNotRequired -eq $true} | Select-Object SamAccountName | Save -name flag_passwd_not_required
    Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, IPv4Address | Select-Object Name, OperatingSystem, IPv4Address, LastLogonDate | Save -name ad_computers
    Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime | Save -name gpos
}

# ---------- Services ----------
Note 'Services'
$svc = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
$svc | Save -name services
# Non-Windows binaries and unquoted paths with spaces (classic persistence / privesc)
$svc | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\' } | Save -name flag_services_nonwindows
$svc | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '(?i)^C:\\Windows\\' } | Save -name flag_unquoted_service_paths

# ---------- Scheduled tasks ----------
Note 'Scheduled tasks'
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    [pscustomobject]@{
        TaskName = $_.TaskName; Path = $_.TaskPath; State = $_.State; RunAs = $_.Principal.UserId
        Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    }
} | Save -name scheduled_tasks_nonms

# ---------- Autoruns / persistence ----------
Note 'Run keys, startup folders, WMI subscriptions'
$runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$runKeys | ForEach-Object {
    $k = $_
    (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } }
} | Save -name run_keys
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp','C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -Force |
    Where-Object { $_.Name -ne 'desktop.ini' } | Select-Object FullName, LastWriteTime | Save -name startup_folders
# Winlogon tampering (Userinit / Shell)
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Userinit, Shell | Save -name winlogon
# Accessibility backdoors (sethc / utilman debugger hijack)
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
    ForEach-Object { $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { [pscustomobject]@{ Image = $_.PSChildName; Debugger = $d } } } |
    Save -name flag_ifeo_debuggers
# WMI persistence
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter            | Select-Object Name, Query               | Save -name wmi_filters
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate | Save -name wmi_consumers
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object @{n='Filter';e={$_.Filter.Name}}, @{n='Consumer';e={$_.Consumer.Name}} | Save -name wmi_bindings

# ---------- Network ----------
Note 'Network: listeners, connections, shares, firewall'
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={$procs[[int]$_.OwningProcess]}} |
    Sort-Object { [int]$_.LocalPort } | Save -name tcp_listening
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={$procs[[int]$_.OwningProcess]}} | Save -name udp_listening
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{n='Process';e={$procs[[int]$_.OwningProcess]}} | Save -name tcp_established
Get-SmbShare | Select-Object Name, Path, Description | Save -name smb_shares
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | Save -name smb_config
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName | Save -name firewall_profiles
Note '  firewall rules (can take a minute on a DC)'
# Pull all port filters ONCE and look them up by rule ID. Piping each rule into
# Get-NetFirewallPortFilter separately takes many minutes on servers with hundreds of rules.
$portFilters = @{}
Get-NetFirewallPortFilter -All | ForEach-Object { $portFilters[$_.InstanceID] = $_ }
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | ForEach-Object {
    $p = $portFilters[$_.InstanceID]
    [pscustomobject]@{ Name = $_.DisplayName; Profile = $_.Profile; Protocol = $p.Protocol; LocalPort = ($p.LocalPort -join ',') }
} | Save -name firewall_inbound_allow
Note '  DNS cache, ipconfig, ARP, routes'
Get-DnsClientCache | Select-Object Entry, Data | Save -name dns_cache
ipconfig /all | Out-File "$out\ipconfig.txt"
arp -a      | Out-File "$out\arp.txt"
route print | Out-File "$out\routes.txt"

# ---------- Processes & software ----------
Note 'Processes and installed software'
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | Save -name processes
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Save -name installed_software

# ---------- Security settings ----------
Note 'Security posture'
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Save -name defender_status
$mp = Get-MpPreference
if ($mp -and ($mp.ExclusionPath -or $mp.ExclusionProcess -or $mp.ExclusionExtension)) {
    [pscustomobject]@{
        ExclusionPath      = $mp.ExclusionPath -join '; '
        ExclusionProcess   = $mp.ExclusionProcess -join '; '
        ExclusionExtension = $mp.ExclusionExtension -join '; '
    } | Save -name flag_defender_exclusions
}
[pscustomobject]@{
    RDP_Disabled = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    RDP_NLA      = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    WDigest_UseLogonCredential = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
    LSA_RunAsPPL = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa').RunAsPPL
    WinRM_Running = [string](Get-Service WinRM).Status
} | Save -name security_settings
auditpol /get /category:* | Out-File "$out\auditpol.txt"
net accounts | Out-File "$out\password_policy.txt"

# ---------- Recently modified files in common drop locations ----------
Note 'Recent files in temp/public/web roots (last 7 days)'
$paths = 'C:\Windows\Temp','C:\Users\Public','C:\ProgramData','C:\inetpub\wwwroot','C:\Users\*\AppData\Local\Temp'
Get-ChildItem $paths -Recurse -Depth 4 -File -Force |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match '\.(exe|dll|ps1|bat|vbs|js|aspx?|php|hta)$' } |
    Select-Object FullName, Length, LastWriteTime | Save -name flag_recent_executables

# ---------- Summary ----------
$errCount = $Error.Count
$Error | ForEach-Object { "$($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" } | Out-File "$out\errors.txt"

Note 'Building summary.html'
$ErrorActionPreference = 'Continue'
$report = New-CcdcReport -Dir $out

$files = Get-ChildItem $out -File
$withData = ($files | Where-Object { $_.Name -notlike '*.EMPTY.txt' -and $_.Name -notin 'errors.txt','summary.html' }).Count
$flags = $files | Where-Object { $_.Name -like 'flag_*.csv' }

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "Output folder : $out"
Write-Host "Report        : $report"
Write-Host "Files written : $($files.Count)  (with data: $withData)"
Write-Host "Errors logged : $errCount  (see errors.txt)"
if ($flags) {
    Write-Host "Red flags to review first:" -ForegroundColor Yellow
    $flags | ForEach-Object { "  {0}  ({1} rows)" -f $_.Name, (@(Import-Csv $_.FullName)).Count } | Write-Host
} else {
    Write-Host "No flag_* findings." -ForegroundColor Green
}

# Open the readable report in the default browser
Invoke-Item $report
