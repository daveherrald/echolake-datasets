# T1112-81: Modify Registry — Modify UseTPMKeyPIN Registry entry

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers for both defense evasion and persistence. Registry modifications can disable security controls, establish persistence mechanisms, hide malicious activity, or alter system behavior to facilitate further attack operations. The detection community focuses on monitoring registry modifications to sensitive keys, unusual processes performing registry operations, and specific value changes that indicate known attack patterns.

This particular test modifies the UseTPMKeyPIN registry entry under `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Full Volume Encryption), which controls BitLocker TPM PIN policy. Attackers might target BitLocker settings to weaken disk encryption, facilitate data access, or prepare for credential harvesting scenarios.

## What This Dataset Contains

The dataset captures a PowerShell-initiated registry modification through the following process chain: `powershell.exe` → `cmd.exe` → `reg.exe`. The core technique evidence appears in Security event 4688 showing reg.exe execution with the command line `reg  add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 2 /f`.

Sysmon captures the complete process creation chain with ProcessCreate events (EID 1) for whoami.exe, cmd.exe, and reg.exe. The cmd.exe process shows the full command: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 2 /f`. Sysmon EID 10 (ProcessAccess) events show PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF).

Security events provide comprehensive process tracking with 4688 events for all three child processes and corresponding 4689 termination events, along with a 4703 token rights adjustment for PowerShell showing elevated privileges including SeBackupPrivilege and SeRestorePrivilege.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode scriptblocks) without capturing the actual registry modification commands.

## What This Dataset Does Not Contain

The dataset lacks Sysmon EID 13 (RegistryEvent - Value Set) events that would directly capture the registry modification itself. This absence suggests either the sysmon-modular configuration filters registry events for this particular key, or the registry change wasn't completed successfully.

No Sysmon ProcessCreate events exist for the parent PowerShell process, indicating it doesn't match the include-mode filtering rules for suspicious process patterns. The PowerShell script block logging doesn't capture the actual Invoke-AtomicRedTeam execution or the registry modification commands, showing only framework initialization.

Windows Defender real-time protection was active but apparently didn't block this registry modification, as evidenced by the successful process executions and normal exit codes (0x0).

## Assessment

This dataset provides excellent telemetry for detecting the process execution chain and command-line artifacts of registry modifications via reg.exe, but incomplete coverage of the actual registry changes. The Security 4688 events with command-line logging offer the most reliable detection opportunities, while Sysmon ProcessCreate events provide additional context and parent-child relationships.

The absence of registry modification events (Sysmon EID 13) significantly limits the dataset's utility for detecting the core technique behavior versus just the execution method. However, the process-level telemetry is comprehensive and representative of what most environments would capture.

## Detection Opportunities Present in This Data

1. **Registry Tool Execution with BitLocker Paths** - Monitor Security EID 4688 for reg.exe execution with command lines containing `HKLM\SOFTWARE\Policies\Microsoft\FVE` or other encryption policy paths

2. **PowerShell Spawning Registry Tools** - Detect Sysmon EID 1 showing reg.exe or cmd.exe spawned by PowerShell processes, especially with registry-related command lines

3. **Sequential Process Chain Analysis** - Monitor the execution sequence of PowerShell → cmd.exe → reg.exe within short time windows (2-5 seconds in this dataset)

4. **Registry Policy Modification Commands** - Alert on command lines containing registry add/modify operations against `HKLM\SOFTWARE\Policies` with encryption-related values like UseTPMKeyPIN

5. **Privileged Registry Access** - Correlate Security EID 4703 token adjustment events showing registry-related privileges (SeBackupPrivilege, SeRestorePrivilege) with subsequent registry tool execution

6. **Process Access to Registry Tools** - Monitor Sysmon EID 10 showing processes accessing cmd.exe or reg.exe with high privilege levels (0x1FFFFF) as potential injection or manipulation attempts
