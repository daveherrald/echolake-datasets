# T1134.001-5: Token Impersonation/Theft — Juicy Potato

## Technique Context

Token impersonation/theft (T1134.001) allows attackers to gain elevated privileges by duplicating and using access tokens from other processes running with higher privileges. Juicy Potato is a well-known privilege escalation tool that exploits Windows COM service impersonation to escalate from NETWORK SERVICE or LOCAL SERVICE to SYSTEM privileges. It works by creating a malicious COM server, tricking the system into connecting with SYSTEM privileges, then impersonating that token.

The detection community focuses on monitoring for token manipulation APIs (DuplicateToken, SetThreadToken), COM object instantiation patterns, and process creation chains showing privilege escalation. Juicy Potato specifically creates characteristic network listeners and spawns processes under elevated contexts that weren't originally available to the calling process.

## What This Dataset Contains

This dataset captures a failed Juicy Potato execution attempt. The key telemetry shows:

**Process execution chain** captured in Security 4688 events:
- Initial PowerShell process (PID 5044): `powershell.exe & {cmd /c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\JuicyPotato.exe' -l '7777' -t * -p '$env:windir\system32\notepad.exe' -c '{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}'}`
- Child cmd.exe process (PID 36200) with command line: `"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\JuicyPotato.exe -l 7777 -t * -p $env:windir\system32\notepad.exe -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}`
- Exit status 0x1 for cmd.exe indicating failure

**PowerShell script block logging** in event 4104 shows the exact command:
`& {cmd /c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\JuicyPotato.exe' -l '7777' -t * -p '$env:windir\system32\notepad.exe' -c '{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}'}`

**Sysmon process creation events** (EID 1) captured the suspicious process chain with full command lines and parent-child relationships.

**Security token events** show privilege adjustment in event 4703, where the PowerShell process enabled multiple high-privilege rights including `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, and `SeTakeOwnershipPrivilege`.

**Process access events** (Sysmon EID 10) show PowerShell processes accessing other processes with full access rights (0x1FFFFF), typical of token manipulation attempts.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful token impersonation because the Juicy Potato execution failed (cmd.exe exit code 0x1). We don't see:
- The actual JuicyPotato.exe process creation (would have been captured by Sysmon if it launched successfully)
- Network connection events showing the COM listener on port 7777
- Successful notepad.exe spawn under an impersonated SYSTEM token
- Registry or file system access showing successful privilege escalation
- Any COM-related events that would indicate successful COM object manipulation

The sysmon-modular configuration's include-mode filtering for ProcessCreate means we only see known-suspicious processes (PowerShell, cmd.exe, whoami.exe) but would miss the actual JuicyPotato.exe execution if it occurred.

## Assessment

This dataset provides excellent visibility into attempted token impersonation attacks, even when they fail. The combination of Security 4688 with command-line auditing, PowerShell script block logging, and Sysmon process access monitoring creates multiple detection vectors. The Security 4703 token privilege adjustment event is particularly valuable as it captures the enabling of privileges commonly required for token impersonation.

While the technique attempt failed, the telemetry demonstrates how defensive tooling can capture the attack lifecycle up to the point of failure. The process execution chain, command-line arguments, and privilege escalation attempts are all clearly visible, providing detection engineers with concrete indicators to hunt for similar attacks.

## Detection Opportunities Present in This Data

1. **Monitor Security 4703 events for suspicious privilege adjustments** - Multiple high-impact privileges enabled simultaneously (SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, SeTakeOwnershipPrivilege)

2. **Detect Juicy Potato tool usage via command-line patterns** - Command lines containing "JuicyPotato.exe" with characteristic parameters (-l, -t, -p, -c flags)

3. **Hunt for COM CLSID abuse patterns** - CLSID {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} in command lines (DCOM-enabled Windows Media Player Network Sharing Service)

4. **Monitor Sysmon EID 10 process access events** - PowerShell processes accessing other processes with full rights (GrantedAccess 0x1FFFFF)

5. **Alert on PowerShell script block content** - Scripts invoking external privilege escalation tools or COM manipulation commands

6. **Track process chains indicating privilege escalation attempts** - PowerShell spawning cmd.exe with suspicious external executables in non-standard paths

7. **Correlate failed process executions** - cmd.exe processes with exit code 0x1 following suspicious command patterns may indicate blocked privilege escalation attempts
