# T1087.001-9: Local Account — Enumerate all accounts via PowerShell (Local)

## Technique Context

T1087.001 Local Account Discovery involves adversaries enumerating local user accounts on a system to understand available targets and privilege levels. This is a fundamental reconnaissance activity that occurs early in attack chains, helping attackers identify high-value targets like local administrators or service accounts. Attackers commonly use built-in Windows utilities like `net user`, PowerShell cmdlets (`Get-LocalUser`, `Get-LocalGroup`), or WMI queries to gather this information. Detection engineers focus on monitoring for enumeration patterns involving multiple account discovery commands executed in sequence, especially when performed by non-administrative users or in unusual contexts.

## What This Dataset Contains

This dataset captures a comprehensive PowerShell-based local account enumeration sequence executed as SYSTEM. The core technique appears in Security event 4688 showing the PowerShell command line: `"powershell.exe" & {net user; get-localuser; get-localgroupmember -group Users; cmdkey.exe /list; ls C:/Users; get-childitem C:\Users\; dir C:\Users\; get-localgroup; net localgroup}`.

Key telemetry includes:
- Sysmon EID 1 events capturing process creation for enumeration tools: `whoami.exe`, `net.exe user`, `net1.exe user`, `cmdkey.exe /list`, `net.exe localgroup`, and `net1.exe localgroup`
- Security EID 4688/4689 events showing the same process chain with full command lines
- PowerShell EID 4103/4104 events capturing cmdlet invocations including `Get-LocalUser`, `Get-LocalGroupMember -group Users`, `Get-ChildItem C:/Users`, and `Get-LocalGroup`
- Sysmon EID 10 process access events showing PowerShell accessing spawned enumeration processes
- Multiple PowerShell processes with GUIDs {9dc7570a-614c-69b4-403c-000000001000}, {9dc7570a-614d-69b4-453c-000000001000}, and {9dc7570a-614f-69b4-4e3c-000000001000}

The PowerShell channel contains detailed command invocations showing parameter binding for `Get-LocalGroupMember` with `name="Group"; value="Users"` and `Get-ChildItem` with multiple path variations targeting the Users directory.

## What This Dataset Does Not Contain

The dataset lacks any blocking or prevention telemetry — all enumeration commands executed successfully with exit status 0x0, indicating Windows Defender did not prevent this reconnaissance activity. There are no registry access events (Security 4656/4658) that might occur with WMI-based enumeration approaches. The PowerShell script block logging primarily shows test framework boilerplate rather than the actual enumeration script content, and there are no network-based enumeration attempts or domain controller queries that might accompany this technique in domain environments.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based local account enumeration. The combination of Security 4688 command-line logging and PowerShell 4103/4104 cmdlet logging creates multiple detection opportunities. Sysmon ProcessCreate events capture several enumeration utilities, though some expected processes may be filtered by the include-mode configuration. The process access events (EID 10) add another dimension showing PowerShell's interaction with spawned enumeration tools. The primary strength is the clear command-line evidence and cmdlet parameter binding details that make this technique highly detectable through multiple complementary data sources.

## Detection Opportunities Present in This Data

1. **PowerShell cmdlet sequence detection** - Monitor for rapid succession of `Get-LocalUser`, `Get-LocalGroup`, and `Get-LocalGroupMember` cmdlets (PowerShell EID 4103)

2. **Command-line enumeration pattern** - Detect PowerShell scripts containing multiple account discovery commands like `net user`, `get-localuser`, and `cmdkey.exe /list` in a single execution (Security EID 4688)

3. **Process tree analysis** - Alert on PowerShell spawning multiple enumeration utilities (`net.exe`, `cmdkey.exe`, `whoami.exe`) within a short timeframe (Sysmon EID 1)

4. **File system enumeration correlation** - Detect PowerShell accessing Users directory with `Get-ChildItem` or `dir` commands combined with account enumeration (PowerShell EID 4103)

5. **Process access patterns** - Monitor for PowerShell processes accessing multiple system utilities with high privileges (0x1FFFFF) during enumeration phases (Sysmon EID 10)

6. **Credential manager enumeration** - Alert on `cmdkey.exe /list` execution, especially when combined with other account discovery activities (Security EID 4688, Sysmon EID 1)

7. **Multi-method enumeration** - Detect scripts using both PowerShell cmdlets and legacy NET commands for account discovery redundancy (cross-channel correlation)
