# T1087.002-8: Domain Account — Adfind - Enumerate Active Directory Exchange AD Objects

## Technique Context

T1087.002 (Account Discovery: Domain Account) covers adversary enumeration of Active Directory objects. This test targets Exchange-related AD objects via AdFind's built-in shortcut command (`-sc exchaddresses`), which retrieves mail-enabled objects and their email address attributes from the Exchange address book container.

Exchange AD objects are a high-value enumeration target. A full list of Exchange recipients provides an attacker with: valid email addresses for phishing campaigns, organizational structure insights, identification of high-privilege mail-enabled accounts (service accounts, shared mailboxes with broad access, Exchange admin accounts), and potential targets for email-based lateral movement. In environments where Exchange permissions are tied to AD groups and delegation, this reconnaissance step often precedes attempts to compromise Exchange-privileged accounts or abuse mail flow rules.

AdFind's `-sc exchaddresses` shortcut is well-documented in threat intelligence reports against organizations with on-premises Exchange or Exchange hybrid environments. The detection community watches for this specific query pattern as a precursor to Business Email Compromise (BEC) escalation and Exchange server abuse.

## What This Dataset Contains

The dataset spans approximately four seconds (2026-03-14T23:35:14Z–23:35:18Z) on ACME-WS06.acme.local and contains 112 events across three channels.

**The core AdFind command** is captured in Sysmon EID 1 (PID 4340) and Security EID 4688 (PID 0x10F4):

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -sc exchaddresses
```

This spawns from `powershell.exe` (PID 5232) running as `NT AUTHORITY\SYSTEM`. The `-sc exchaddresses` argument invokes AdFind's built-in Exchange address shortcut, which internally constructs an LDAP query against the Exchange address book container for all mail-enabled objects.

**Sysmon EID 1** captures two process creations: `whoami.exe` (PID 4324, rule `T1033`, parent powershell.exe PID 5232) and `cmd.exe` (PID 4340, rule `T1059.003`, parent powershell.exe PID 5232). The cmd.exe hash `SHA256=423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB` matches the standard Windows Command Processor across all tests on this host.

**Security EID 4688** records three process creations: `whoami.exe` (0x10E4), `cmd.exe` (0x10F4) with the AdFind command line, and a second `whoami.exe` (0x700) from the cleanup phase. All execute as `S-1-5-18` (SYSTEM) with `TokenElevationTypeDefault` and Mandatory Label `S-1-16-16384` (System integrity level).

**Sysmon EID 10** (3 events) records process access events from PowerShell (PID 5232) against its child processes with full access rights (0x1FFFFF), consistent with the test framework monitoring child execution.

**Sysmon EID 7** (9 events) documents DLL loads for PowerShell: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, and `System.Management.Automation.ni.dll` (rule `T1059.001`).

**Sysmon EID 17** (1 event) records a named pipe creation from PowerShell.

**PowerShell EID 4104** (93 events) captures script block fragments. Key blocks include the ART test framework invocation (`Invoke-AtomicTest T1087.002 -TestNumbers 8 -Cleanup -Confirm:$false`), module import, and the standard runtime closures.

## What This Dataset Does Not Contain

As with other AdFind tests in this series, the AdFind.exe process itself does not appear as a process creation event. Sysmon's include-mode ProcessCreate filter does not cover AdFind, so only the `cmd.exe` wrapper is captured — not the actual query tool binary.

No LDAP network traffic is captured. In an environment with no on-premises Exchange deployment (or in the lab environment where ACME-WS06 is a member of `acme.local` without Exchange), the `-sc exchaddresses` query would return empty results or fail gracefully; that outcome is not reflected in any event.

No DNS resolution events appear, and no network connection events (Sysmon EID 3) are present in the dataset.

## Assessment

This test executed without interference from Defender and produced complete command-line telemetry in both Security and Sysmon channels. The AdFind `-sc exchaddresses` query is clearly captured in the process creation events.

Comparing with the defended variant (26 Sysmon, 10 Security, 34 PowerShell), the undefended dataset is structurally similar but somewhat larger (16 Sysmon, 3 Security, 93 PowerShell). The dramatic difference in Security event count (3 vs. 10) and Sysmon count (16 vs. 26) in the defended run suggests the extra events come from Defender's own process activity in response to the AdFind execution — those inspection processes are absent here because Defender is disabled.

The core detection data — `cmd.exe` executing `AdFind.exe -sc exchaddresses` under SYSTEM from a PowerShell parent — is identical between defended and undefended variants. The undefended dataset is cleaner in the sense that the surrounding events are purely OS activity and test framework artifacts, without Defender-generated telemetry mixed in.

## Detection Opportunities Present in This Data

**Process creation with `-sc exchaddresses` in command line**: Both Security EID 4688 and Sysmon EID 1 preserve the complete command line. The string `exchaddresses` (or `-sc exchaddresses`) in any process argument is a specific, rarely-seen signal that warrants immediate investigation. There is no common reason for a workstation process to query Exchange address book objects.

**cmd.exe spawned by PowerShell running AdFind**: The parent-child chain (powershell.exe → cmd.exe → AdFind.exe) under SYSTEM context is consistent across AdFind-based attacks. Behavioral correlation across the two process creation events strengthens confidence relative to either event in isolation.

**SYSTEM-context AD enumeration from workstation**: All execution runs under `NT AUTHORITY\SYSTEM`. A SYSTEM-context process performing LDAP queries against a domain controller is unusual for a standard workstation, particularly when the query tool is a third-party binary not native to Windows.

**Hash-based detection of AdFind.exe**: While not captured as a process event here, the binary at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` would be loaded by cmd.exe. Any endpoint that captures child process hashes or has file hash telemetry for AdFind (a well-known tool with stable public hashes) can correlate the tool's presence regardless of the process event gap.
