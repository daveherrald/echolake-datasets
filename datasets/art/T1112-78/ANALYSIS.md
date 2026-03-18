# T1112-78: Modify Registry — Modify UseTPM Registry entry

## Technique Context

T1112 (Modify Registry) is a fundamental technique where adversaries modify Windows registry keys and values to achieve persistence, privilege escalation, or defense evasion. The registry serves as a central configuration database for Windows, making it an attractive target for attackers seeking to modify system behavior, disable security controls, or establish persistence mechanisms.

This specific test targets the UseTPM registry entry under `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Full Volume Encryption), which controls Trusted Platform Module (TPM) usage for BitLocker encryption. By setting UseTPM to 2, an attacker could potentially disable TPM requirements for BitLocker, weakening disk encryption protections. The detection community typically focuses on monitoring registry modifications to security-relevant keys, especially those affecting encryption, authentication, and system security policies.

## What This Dataset Contains

The dataset captures a straightforward registry modification executed through PowerShell calling cmd.exe, which then invokes reg.exe. The core attack sequence is visible in Security event 4688 process creation logs:

- PowerShell (PID 33504) launches cmd.exe with command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPM /t REG_DWORD /d 2 /f`
- cmd.exe (PID 25240) spawns reg.exe with: `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPM /t REG_DWORD /d 2 /f`

Sysmon captures the process creation chain with EID 1 events showing the same command lines, along with process GUIDs, hashes, and parent-child relationships. The technique executes successfully with exit status 0x0 for all processes.

Additional telemetry includes PowerShell module loading (Sysmon EID 7), process access events (Sysmon EID 10), and Security privilege adjustment (EID 4703) showing PowerShell gaining elevated privileges including `SeBackupPrivilege` and `SeRestorePrivilege`.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification event. Windows typically generates Security event 4657 (registry value modified) or System event 1 when registry changes occur, but neither appears in this capture. This absence suggests either the audit policy doesn't include object access for registry monitoring, or the specific registry path wasn't audited.

The dataset also doesn't contain Sysmon EID 13 (RegistryEvent - Value Set), indicating the sysmon-modular configuration may not monitor this particular registry location or may filter out FVE policy changes. Without these registry-specific events, detection engineers cannot see the actual registry modification that constitutes the core of this technique.

## Assessment

This dataset provides excellent process execution telemetry but falls short on the primary technique evidence. The process creation events offer strong detection opportunities for the command-line patterns and tool usage, but the missing registry modification events significantly limit its value for detecting the actual T1112 behavior.

The data sources are strong for behavioral detection (suspicious process chains, LOLBin usage) but inadequate for detecting the registry changes themselves. A complete T1112 dataset would require either Security audit policy configuration for object access on the target registry keys or Sysmon registry monitoring rules.

## Detection Opportunities Present in This Data

1. **Suspicious reg.exe command line patterns** - Detection on `reg add` operations targeting `HKLM\SOFTWARE\Policies\Microsoft\FVE` with UseTPM modifications

2. **PowerShell spawning cmd.exe for registry operations** - Process chain of powershell.exe → cmd.exe → reg.exe, especially when targeting security-relevant registry paths

3. **BitLocker policy tampering** - Command lines containing `SOFTWARE\Policies\Microsoft\FVE` and `UseTPM` parameters, indicating potential encryption policy manipulation

4. **Privilege escalation correlation** - Security EID 4703 showing privilege adjustment immediately before registry modification attempts

5. **LOLBin process creation** - Sysmon EID 1 capturing reg.exe execution with suspicious command line arguments targeting encryption policies

6. **Process access anomalies** - Sysmon EID 10 showing PowerShell accessing spawned processes with full access rights (0x1FFFFF), potentially indicating process injection techniques alongside registry modification
