# T1112-74: Modify Registry — Disable Windows Remote Desktop Protocol

## Technique Context

T1112 (Modify Registry) is used here to disable RDP by setting `fDenyTSConnections` to `1` in `HKLM\System\CurrentControlSet\Control\Terminal Server`. This is the canonical registry value that controls whether the Terminal Services (Remote Desktop) service accepts incoming connections. Setting it to `1` prevents any new RDP sessions from being established.

Disabling RDP mid-attack is a tactic used primarily by ransomware operators during active deployment. After achieving domain-level compromise and staging the ransomware payload, actors frequently block RDP access before triggering encryption to prevent defenders and administrators from remoting in to halt the attack. Organizations whose incident response depends on RDP access to affected systems find themselves locked out exactly when response speed is most critical. This technique is documented in operational reporting on BlackMatter, LockBit, BlackByte, and several other ransomware families. The `fDenyTSConnections` key path is one of the most reliably observable pre-encryption staging indicators.

## What This Dataset Contains

This dataset captures the `fDenyTSConnections` registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. Events occur at approximately 2026-03-17T16:34:52Z to 16:34:55Z—notably a different session date from T1112-63 through T1112-67, indicating this test was run in a separate execution session.

The attack chain is PowerShell (SYSTEM) → cmd.exe → reg.exe. Sysmon EID 1 captures both child processes:

- `cmd.exe` (PID 17232, ProcessGuid `{9dc7570a-82ae-69b9-c039-000000000900}`, RuleName `technique_id=T1083`) with command line: `"cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`
- `reg.exe` (PID 14572, ProcessGuid `{9dc7570a-82ae-69b9-c239-000000000900}`, RuleName `technique_id=T1083`) with command line: `reg  add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`

Both run from `C:\Windows\TEMP\` as `NT AUTHORITY\SYSTEM` at `LogonId: 0x3E7`. Security EID 4688 independently records the same process chain.

The Sysmon EID breakdown (7: 9, 1: 4, 10: 3, 17: 1, 13: 1) is structurally consistent with other tests in this batch. The EID 13 event in the full dataset records the write to `fDenyTSConnections`. The `whoami.exe` process (EID 1, RuleName `technique_id=T1033`) at 16:34:52 is the test framework pre-execution context check.

The PowerShell channel contains 97 EID 4104 events—significantly elevated relative to the 36-event baseline seen in T1112-63 through T1112-67. This larger script block count reflects the different session context: more PowerShell modules and initialization fragments were logged in this session. The cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 74 -Cleanup` is visible in the samples. The single EID 4103 (module logging) event in the PowerShell channel provides additional execution context.

## What This Dataset Does Not Contain

This dataset does not capture the effect of the registry change—no Terminal Services service state change, no `netsh` firewall modifications, and no evidence of RDP connections being refused after the change. The test is the registry write alone.

No Sysmon EID 13 appears in the sample subset, though one exists in the full dataset. The `HKLM\System\CurrentControlSet\Control\Terminal Server` key path does not have a default SACL, so Security EID 4657/4663 are absent.

The high PowerShell event count (97) reflects session initialization and module loading rather than additional technique-related content. The substantive PowerShell content is limited to the test framework wrapper.

## Assessment

The undefended dataset (Sysmon: 18, Security: 4, PowerShell: 97) compared to the defended variant (Sysmon: 38, Security: 12, PowerShell: 40) shows a substantial Sysmon reduction (38 → 18) and a Security reduction (12 → 4). Notably, the PowerShell channel is much larger in the undefended run (97 vs. 40). This inversion—where one channel grows while others shrink—reflects the session context difference: the defended run had more controlled PowerShell initialization, while the undefended session generated more script block fragments due to the different execution environment.

The core technique evidence is identical in quality: the full command line with `fDenyTSConnections` and value `1` appears in both Sysmon and Security channels. The `fDenyTSConnections` key path is among the most detection-rule-covered registry paths in the industry; this dataset provides concrete, real-system telemetry to validate those detections.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The complete command line `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f` appears in both sources. This key path and value combination is a well-known indicator; this dataset provides real telemetry for tuning.

**Registry value set (Sysmon EID 13):** The full dataset contains the direct write event. `fDenyTSConnections` modified to `1` via any mechanism (not just `reg.exe`) represents the disabling of RDP.

**Process ancestry from TEMP (Sysmon EID 1):** `reg.exe` launched from `C:\Windows\TEMP\` via a PowerShell-spawned cmd.exe running as SYSTEM is anomalous. This indicator has excellent specificity: legitimate RDP configuration changes occur through `services.exe`, Group Policy service contexts, or administrative tools—not this process chain.

**Temporal clustering with other T1112 tests:** This dataset was captured in the same session as T1112-75, T1112-79, T1112-8, T1112-81, and T1112-83. In a real intrusion, multiple registry modifications in rapid succession using the same tool chain within a short time window is itself a detection signal worth alerting on, independent of the individual key paths targeted.
