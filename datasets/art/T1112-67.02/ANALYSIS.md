# T1112-67: Modify Registry — Enable Proxy Settings

## Technique Context

T1112 (Modify Registry) is used here to enable the system proxy by setting `ProxyEnable` to `1` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`. This is the registry key that governs the Internet Explorer / WinINet proxy configuration, which a wide range of Windows applications and system components honor when making HTTP/HTTPS connections.

Adversaries enable proxy settings as a post-exploitation step to route outbound traffic through attacker-controlled infrastructure. This serves several purposes: it intercepts traffic from applications that use WinINet (including many enterprise tools and some browsers), it allows the attacker to observe or modify that traffic, and it can redirect C2 communications to a proxy that provides persistence if the original C2 endpoint is blocked. This behavior is associated with post-compromise lateral movement preparation and exfiltration staging. It is distinct from—but complementary to—techniques that configure the `ProxyServer` value, which specifies the actual proxy address. Enabling the proxy with `ProxyEnable=1` without also setting a `ProxyServer` value would cause connections to fail for applications that respect this setting, making it useful as a denial-of-service against specific application traffic or as the first step before configuring the proxy address.

## What This Dataset Contains

This dataset captures the ProxyEnable registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. The modification occurs at approximately 2026-03-14T23:53:42Z, in the same continuous PowerShell session that ran T1112-63 through T1112-66.

The execution chain is PowerShell (SYSTEM) → cmd.exe → reg.exe. Sysmon EID 1 captures both child processes:

- `cmd.exe` (PID 7016, ProcessGuid `{9dc7570a-f506-69b5-f212-000000000600}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 1112, ProcessGuid `{9dc7570a-f506-69b5-f412-000000000600}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f`

Both run from `C:\Windows\Temp\` at System integrity level. Security EID 4688 independently records the process chain with identical command-line content.

The Sysmon EID breakdown (7: 9, 1: 4, 10: 3, 17: 1) is again structurally consistent with the other tests in this session. PowerShell channel: 36 EID 4104 events, including the cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 67 -Cleanup`.

The `HKCU` target hive is consistent with T1112-66: both tests write to the current user's hive rather than HKLM. Executed as SYSTEM, this targets the SYSTEM account's registry hive, which affects system services and processes running under that account.

## What This Dataset Does Not Contain

No `ProxyServer` value modification is captured—this test sets only `ProxyEnable`. Without a proxy server address, enabling the proxy has no functional network effect in isolation. Any actual traffic redirection would require a separate `ProxyServer` write that is not present in this dataset.

No network-level proxy traffic, connection attempts, or WinINet activity resulting from the proxy configuration appears. The test is confined to the registry write itself.

Security EID 4657/4663 (registry object auditing) events are absent—no SACL on the Internet Settings key by default.

## Assessment

The undefended dataset (Sysmon: 17, Security: 4, PowerShell: 36) versus the defended variant (Sysmon: 27, Security: 13, PowerShell: 34) shows the same pattern as neighboring tests: Defender's absence reduces the Security channel from 13 to 4 events and reduces Sysmon from 27 to 17 events by eliminating the defensive inspection overhead. The PowerShell channel remains comparable (36 vs. 34).

The proxy enable pattern is particularly interesting from a detection perspective because `ProxyEnable=1` is also set legitimately by browsers, VPN clients, and enterprise management tools. The distinguishing factor here is not the registry value itself but the process that writes it: `reg.exe` invoked from a PowerShell-spawned cmd.exe running as SYSTEM from `C:\Windows\Temp\` is not a legitimate path for proxy configuration. Browsers and management tools write this value from their own process context, not via the `reg.exe` command-line tool.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The full command line targeting `HKCU\...\Internet Settings\ProxyEnable` via `reg.exe` is captured in both channels. The combination of `ProxyEnable` modification via `reg.exe` (rather than a browser or configuration manager process) is the key detection signal.

**Registry value set (Sysmon EID 13):** The direct write event to the Internet Settings key is present in the full dataset. Monitoring for writes to `ProxyEnable` or `ProxyServer` from non-browser, non-management-tool processes covers this behavior.

**HKCU vs. HKLM coverage:** This test writes to `HKCU`. System-wide proxy changes go to `HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings`. Detection coverage should address both paths, as adversaries may target either depending on the execution context they have established.

**Process lineage and working directory (Sysmon EID 1):** `reg.exe` executing from `C:\Windows\Temp\` under PowerShell → cmd.exe at SYSTEM integrity is the consistent process ancestry indicator shared across this entire T1112 cluster.
