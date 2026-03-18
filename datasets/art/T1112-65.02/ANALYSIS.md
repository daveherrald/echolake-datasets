# T1112-65: Modify Registry — Disable Remote Desktop Security Settings Through Registry

## Technique Context

T1112 (Modify Registry) enables adversaries to modify system behavior by writing to Windows registry keys. This test targets `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\DisableSecuritySettings`, setting it to `1`. The `DisableSecuritySettings` value removes the Security tab from the RDP client experience—specifically the lock screen, disconnect, and logoff controls—affecting the session interface presented to users on a compromised host.

The security relevance here extends beyond cosmetic changes. Attackers operating interactively over RDP may disable this setting to reduce the visibility of their session to local users or to modify the behavior of RDP security negotiation. More broadly, modification of Terminal Services policy keys—whether targeting anti-aliasing, security settings, or NLA—is a recognizable cluster of adversary behavior. Groups conducting ransomware pre-staging or interactive intrusions over RDP routinely touch this key namespace. Defenders benefit from treating modifications to `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` as a family of related behaviors rather than evaluating each value in isolation.

## What This Dataset Contains

This dataset captures the DisableSecuritySettings registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. Events span approximately 21 seconds (2026-03-14T23:52:53Z to 23:53:14Z), reflecting the sequential execution of multiple T1112 subtests in the same session.

The execution follows the consistent PowerShell → cmd.exe → reg.exe chain, running as `NT AUTHORITY\SYSTEM`. Sysmon EID 1 records both child processes:

- `cmd.exe` (PID 764, ProcessGuid `{9dc7570a-f4ea-69b5-d312-000000000600}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 5480, ProcessGuid `{9dc7570a-f4ea-69b5-d512-000000000600}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f`

Both execute from `C:\Windows\Temp\` at System integrity level. Security EID 4688 independently captures the same process creation chain with full command-line details.

The Sysmon EID breakdown (7: 9 image loads, 1: 4 process creates, 10: 3 process accesses, 17: 1 pipe create) mirrors the structure seen in T1112-64, which ran in the same PowerShell session seconds earlier. The PowerShell channel (36 EID 4104 events) contains the cleanup wrapper for `Invoke-AtomicTest T1112 -TestNumbers 65` and standard runtime boilerplate; the execution command was passed as a command-line argument rather than a script file.

## What This Dataset Does Not Contain

Security EID 4657/4663 events are absent—no SACL is configured on the Terminal Services policy key by default. Sysmon EID 12 (registry key create) is also absent since the key already existed. The single EID 13 event is in the full dataset but not represented in the sample subset.

No evidence of active RDP connections, session establishment, or downstream exploitation of the modified setting appears. The test is a point-in-time registry write without follow-on activity.

## Assessment

The undefended dataset (Sysmon: 17, Security: 4, PowerShell: 36) is again significantly smaller than its defended counterpart (Sysmon: 27, Security: 13, PowerShell: 35). The pattern holds across T1112-64 and T1112-65: Defender generates additional Security channel events when active, while the undefended run captures only the core process creation chain.

The key observation for this specific test versus T1112-64 is that both target the same parent registry path (`HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services`) but write to different values (`DisableRemoteDesktopAntiAlias` vs `DisableSecuritySettings`). A detection tuned to the parent key path would catch both behaviors simultaneously.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The full command line with `DisableSecuritySettings` and the Terminal Services policy path is captured in both sources. The value name is distinctive and does not appear in normal administrative operations.

**Terminal Services key namespace (Sysmon EID 13):** The full dataset's registry value set event directly names the key and value. Monitoring `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` for any write from non-Group Policy sources (i.e., not `svchost.exe` or `csrss.exe`) covers both T1112-64 and T1112-65 behavior with a single rule.

**Process chain context (Sysmon EID 1):** `reg.exe` running from `C:\Windows\Temp\` under a PowerShell-spawned cmd.exe at SYSTEM integrity is the shared indicator across this entire T1112 test cluster. This process ancestry pattern is a reliable differentiator from legitimate administrative registry operations.
