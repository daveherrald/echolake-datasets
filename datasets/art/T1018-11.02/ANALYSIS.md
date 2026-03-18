# T1018-11: Remote System Discovery — Adfind - Enumerate Active Directory Domain Controller Objects

## Technique Context

T1018 Remote System Discovery covers a range of methods for identifying hosts and services within a network. AdFind is a free, standalone Windows command-line tool originally written for legitimate AD administration that has become one of the most reliably documented pre-ransomware reconnaissance tools. Threat actors use it to enumerate Active Directory objects — domain controllers, users, groups, computers, and trust relationships — using a single binary that requires no installation and leaves a minimal footprint. The `-sc dclist` shortcut specifically dumps the domain controller list, which attackers use to identify high-value targets for Kerberoasting, DCSync, or GPO manipulation.

Security teams and detection engineers treat any AdFind execution as a high-priority signal because it has essentially no legitimate administrative use case that cannot be replaced by built-in tools (such as `nltest /dclist` or PowerShell AD cmdlets). The tool's presence and execution almost always indicates adversary activity. LDAP queries from AdFind to domain controllers are visible in network captures, but process creation telemetry remains the most reliable host-based detection point.

The test in this dataset invokes AdFind with the pre-staged binary at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` and the argument `-sc dclist`, wrapped in `cmd.exe /c` launched by PowerShell as SYSTEM.

## What This Dataset Contains

With Defender disabled, the process chain executes and is captured fully. The dataset covers a roughly 4-second window (22:58:25–22:58:29 UTC on 2026-03-14) with 186 total events.

The critical evidence is in Sysmon EID 1. PowerShell (PID 1588) spawns `cmd.exe` (PID 6540) with the full command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe"  -sc dclist`. This event is tagged with `RuleName: technique_id=T1059.003,technique_name=Windows Command Shell`. The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` resolves to `C:\AtomicRedTeam\ExternalPayloads\AdFind.exe`, and the double space before `-sc` reflects how ART constructs the command line. The cleanup phase creates a second `cmd.exe` (PID 5528) with a blank argument — the cleanup command for this test has nothing to delete.

Security EID 4688 records the same `cmd.exe` creation, capturing the command line in the `Process Command Line` field with the full AdFind invocation.

The key difference from the defended version is significant: in the defended dataset, the cmd.exe exited with status 0x1 and no AdFind.exe ProcessCreate was recorded, indicating Defender blocked it. In this undefended dataset, the cmd.exe creates successfully and — critically — there is no second `cmd.exe` exit failure. The absence of a Sysmon EID 1 for `AdFind.exe` itself suggests the binary either was not present in the ExternalPayloads directory at test time, or the `cmd.exe /c` wrapper completed its scope without spawning the child (possible if the path resolution via `..` failed). The 73 EID 4664 hard-link events in the Security channel are concurrent OS servicing activity unrelated to this technique.

Compared to the defended run (26 Sysmon events, 11 Security), this dataset has 13 Sysmon events and 78 Security events. The Security channel increase is due to the same background servicing pattern.

## What This Dataset Does Not Contain

There is no Sysmon EID 1 for `AdFind.exe` itself. Without a ProcessCreate for the tool, there are no associated network connection events (LDAP queries to port 389 or 3268 on domain controllers), no file creation events for any output file, and no DNS queries to resolve domain controller names. Whether the binary was absent from the expected path or failed to launch for another reason, this dataset captures the staging and invocation command without the actual AD enumeration activity. Sysmon EID 3 network events for LDAP would be the most operationally valuable additions missing here.

## Assessment

This dataset is primarily useful as a process-creation detection dataset for the AdFind invocation pattern. The full command line — including the binary path, the `..` traversal in the path, and the `-sc dclist` argument — is present and searchable in both Sysmon EID 1 and Security EID 4688. Even without the AdFind.exe ProcessCreate itself, the `cmd.exe` wrapping the AdFind call is a valid detection target. Detection teams building rules for AdFind abuse will find this dataset useful for developing and testing the initial spawning pattern, particularly when combined with other T1018 datasets that capture downstream LDAP activity.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — binary name in command line**: The string `AdFind.exe` in any process command line is a near-zero-false-positive detection opportunity. Both Sysmon and Security process creation events contain the full path.

2. **Sysmon EID 1 / EID 4688 — AdFind argument matching**: The argument `-sc dclist` alongside the binary name is a specific indicator for domain controller enumeration intent, useful for alert triage prioritization.

3. **Sysmon EID 1 — path traversal pattern**: The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` contains a `..` traversal in a command line, which is unusual for normal application launches and could be a supplementary filter to catch tool staging patterns.

4. **Sysmon EID 1 — cmd.exe from TEMP with specific argument**: `cmd.exe /c` with a path to `ExternalPayloads\AdFind.exe` launched from `C:\Windows\TEMP\` as SYSTEM is a highly specific behavioral pattern detectable before the tool binary itself is tagged.

5. **Sysmon EID 1 — parent-child chain**: PowerShell spawning `cmd.exe` with an AdFind invocation as SYSTEM is the same parent-child pattern seen in T1018-1. Detecting powershell.exe → cmd.exe chains where the cmd.exe command line contains third-party AD tools rather than built-in commands is a higher-fidelity approach than binary-name matching alone.
