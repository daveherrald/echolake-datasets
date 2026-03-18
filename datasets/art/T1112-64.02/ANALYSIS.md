# T1112-64: Modify Registry — Disable Remote Desktop Anti-Alias Setting Through Registry

## Technique Context

T1112 (Modify Registry) is used by adversaries to alter Windows behavior, disable security features, and facilitate remote access. This test modifies a Remote Desktop Services policy key: `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\DisableRemoteDesktopAntiAlias`. Setting this value to `1` disables anti-aliasing rendering for RDP sessions.

While disabling anti-aliasing is not inherently a security control bypass, it is a recognized technique used by attackers and ransomware operators who have established RDP access to a target. Degrading rendering quality can improve session responsiveness over low-bandwidth connections, which matters during interactive post-exploitation activity. More importantly, modifying Terminal Services policy keys is a behavior pattern shared with other, more aggressive RDP manipulations—such as disabling NLA (Network Level Authentication) or removing the requirement for encryption—making this key path worth monitoring as a category.

## What This Dataset Contains

This dataset captures the complete execution of the DisableRemoteDesktopAntiAlias registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. All events occur within an approximately 11-second window (2026-03-14T23:52:52Z to 23:53:03Z).

The attack executes as `NT AUTHORITY\SYSTEM` via the standard PowerShell → cmd.exe → reg.exe chain. Sysmon EID 1 captures both child process creations:

- `cmd.exe` (PID 6364, ProcessGuid `{9dc7570a-f4df-69b5-c412-000000000600}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableRemoteDesktopAntiAlias" /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 672, ProcessGuid `{9dc7570a-f4df-69b5-c612-000000000600}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableRemoteDesktopAntiAlias" /t REG_DWORD /d 1 /f`

Both run from `CurrentDirectory: C:\Windows\Temp\` at System integrity level. Security EID 4688 independently records the same process creations, confirming the parent-child relationship: PowerShell spawns cmd.exe, which spawns reg.exe.

The Sysmon EID breakdown (7: 9 image loads, 1: 4 process creates, 10: 3 process accesses, 17: 1 pipe create) accounts for 17 events total. EID 10 events capture PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.

The PowerShell channel (36 EID 4104 events) contains test framework boilerplate script blocks and the cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 64 -Cleanup`. The actual test command is executed as a command-line argument to `powershell.exe` rather than as a file, so the core script block containing the `cmd.exe` invocation is not present in the captured sample set.

## What This Dataset Does Not Contain

Security EID 4657 or 4663 (registry object auditing) events are absent. The `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` key does not have a SACL configured by default, so the Security channel captures process creation only, not the registry write.

There is no Sysmon EID 12 (registry key create) event. The key path already existed; the operation is a value write, not a key creation. The EID 13 (registry value set) exists in the full dataset but is not in the sample window shown here.

No evidence of RDP session activity, connection attempts, or subsequent exploitation of the modified setting appears in this dataset. This test is scoped to the isolated registry write step.

## Assessment

The undefended variant (Sysmon: 17, Security: 4, PowerShell: 36) is significantly smaller than the defended variant (Sysmon: 27, Security: 12, PowerShell: 34). The defended dataset's higher Security event count reflects Defender's process inspection activity around the Terminal Services registry modification. With Defender disabled, only the four direct process creation events are recorded in the Security channel.

The technique evidence itself is identical in quality between the two variants. The full command line, the target registry path, the value name `DisableRemoteDesktopAntiAlias`, and the data value `1` all appear in both Sysmon EID 1 and Security EID 4688 records. The undefended dataset strips away the Defender telemetry overhead while preserving the complete attack artifact chain.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The command line `reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableRemoteDesktopAntiAlias" /t REG_DWORD /d 1 /f` is fully captured. The Terminal Services policy key path combined with `reg.exe` as the writing process is a meaningful signal.

**Process chain from TEMP directory (Sysmon EID 1):** `reg.exe` executing from `C:\Windows\Temp\` under a PowerShell → cmd.exe parent is atypical for legitimate administrative tooling and distinguishable from Group Policy application (which would use `csrss.exe` or `svchost.exe` as the process context).

**Registry value set (Sysmon EID 13):** The full dataset contains a direct registry write event to the Terminal Services key, providing a second independent detection path that does not require process argument logging.

**Correlated process access (Sysmon EID 10):** PowerShell's process access events against its child processes (with `0x1FFFFF` access) can be used to reconstruct the full execution context when correlating across the session window.
