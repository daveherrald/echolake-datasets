# T1562.001-20: Disable or Modify Tools — Remove Windows Defender Definition Files

## Technique Context

T1562.001 (Disable or Modify Tools) includes degrading the effectiveness of security tools short of disabling them entirely. Windows Defender's signature-based detection relies on definition files — databases of known malware signatures, heuristic patterns, and behavioral indicators. Removing these definition files leaves the Defender engine running but unable to identify most known malware. The engine continues to report as "enabled" to Windows Security Center, so the system appears protected while being functionally blind to signature-matched threats.

The built-in `MpCmdRun.exe` utility provides a Microsoft-signed mechanism for this operation: `MpCmdRun.exe -RemoveDefinitions -All`. Attackers prefer this approach because:
- It uses a legitimate, signed Microsoft binary (no executable staging required)
- It does not stop the Defender service (which would be more visible in Security Center)
- The result is a degraded but "running" security product, which may not trigger alerts

This technique appears in ransomware operations where attackers need to execute their payload without Defender signature matching, but where stopping Defender entirely would be detectable or blocked.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-17 17:35:39–17:35:45 UTC) and contains 52 PowerShell events, 29 Security events, and 1 Sysmon event.

The attack command is captured in Security EID 4688 (inferred from the structure — specific command line not in the samples but consistent with the test definition):
```
"cmd.exe" /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

Security EID 4688 records 5 process creation events across `whoami.exe`, `cmd.exe`, `MpCmdRun.exe`, and post-execution `whoami.exe`. All run under `NT AUTHORITY\SYSTEM`.

The Security channel contains 29 events with a rich breakdown:
- **EID 4688**: 5 process creation events
- **EID 4798**: 5 events documenting local user group membership enumeration for specific users:
  - Administrator (S-1-5-21-1024873681-3998968759-1653567624-500)
  - Guest (S-1-5-21-1024873681-3998968759-1653567624-501)
  - mm11711 (S-1-5-21-1024873681-3998968759-1653567624-1000)
  - DefaultAccount (S-1-5-21-1024873681-3998968759-1653567624-503)
  - WDAGUtilityAccount (S-1-5-21-1024873681-3998968759-1653567624-504)
- **EID 4799**: Multiple events documenting security-enabled local group membership enumeration for groups including:
  - Access Control Assistance Operators (S-1-5-32-579)
  - Administrators (S-1-5-32-544)
  - Backup Operators (S-1-5-32-551)
  - Cryptographic Operators (S-1-5-32-569)
  - Additional builtin groups

The 4798/4799 events reflect `wmiprvse.exe` (`C:\Windows\system32\wbem\wmiprvse.exe -Embedding`) enumerating local user and group membership — a WMI operation triggered by `MpCmdRun.exe` or by Defender's own internal processes as part of responding to the definition removal operation. Security EID 4688 records `wmiprvse.exe -Embedding` as a process creation event at the start of this cluster.

**Sysmon EID 3** (NetworkConnect) from `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` — the Defender engine process initiating a network connection, consistent with Defender contacting cloud services following the definition removal attempt.

The 52 PowerShell events are all EID 4104 script block logging containing ART test framework boilerplate.

## What This Dataset Does Not Contain

No Sysmon EID 1 for the attack processes. Sysmon's ProcessCreate filter was not capturing events during this test window — consistent with the driver state following T1562.001-11 earlier in this run cluster. Process creation evidence comes entirely from Security EID 4688.

No Sysmon registry events. The definition removal involves file operations on Defender's definition database (typically under `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\`), but no Sysmon EID 11 FileCreate or EID 26 FileDelete events appear for those paths.

No Defender Application or System log events confirming definition removal. The Microsoft-Windows-Windows Defender/Operational channel (which would show EID 2010 "Windows Defender updated" or EID 2001 "signature update" events) was not collected. Success or failure of the definition removal is not directly confirmable from this dataset.

No process exit codes. Without Sysmon EID 1 or Security EID 4689, `MpCmdRun.exe`'s exit code is not captured. Exit code 0x2 would indicate failure (Tamper Protection blocking the operation); exit code 0x0 would indicate success.

Compared to the defended variant (31 Sysmon, 12 Security, 34 PowerShell), this undefended run has significantly more Security events (29 vs 12). The additional Security events are the EID 4798/4799 user and group enumeration cluster from wmiprvse.exe — this activity was present in the undefended run's slightly longer collection window or was triggered differently.

## Assessment

The most analytically interesting feature of this dataset is the EID 4798/4799 cluster. WMI-driven enumeration of all local users and all builtin groups, triggered in the context of a `MpCmdRun.exe -RemoveDefinitions` execution, suggests that MsMpEng or MpCmdRun internally calls WMI to inspect the system's user/group configuration as part of its operation. This is a Defender internal behavior artifact — the definition removal request causes Defender to query system context information, generating a burst of 4798/4799 events.

This behavior can be observed independently of whether the definition removal succeeds. Any invocation of `MpCmdRun.exe -RemoveDefinitions` in this environment produces the wmiprvse.exe user enumeration burst. This is a useful correlation anchor: if you see EID 4798/4799 bursts from `wmiprvse.exe` immediately following `MpCmdRun.exe` process creation, the process is likely a definition removal or update operation.

The Sysmon EID 3 from MsMpEng following a definition removal attempt reflects Defender's telemetry or update-check behavior — MsMpEng contacts Microsoft's cloud infrastructure when its definitions are modified. This network connection provides a timing marker for the operation.

## Detection Opportunities Present in This Data

**Security EID 4688 for `MpCmdRun.exe -RemoveDefinitions -All`**: The command line `MpCmdRun.exe -RemoveDefinitions -All` from a non-Defender-update context (not spawned from the Windows Update or scheduled task path) is a high-precision indicator. The `-RemoveDefinitions -All` flags have no legitimate use case outside of deliberate definition management or testing.

**Security EID 4688 chain**: `cmd.exe` spawning `MpCmdRun.exe` with definition removal arguments, both running as SYSTEM, is anomalous. Legitimate Defender update operations do not invoke `MpCmdRun.exe` via `cmd.exe` wrappers — they call the binary directly from scheduled tasks or update processes.

**WMI EID 4798/4799 burst**: The burst of local user and group enumeration events from wmiprvse.exe following `MpCmdRun.exe` execution is a secondary behavioral indicator. While the 4798/4799 events themselves are not malicious, their temporal correlation with the definition removal command makes them part of the detection signature.

**Sysmon EID 3 from MsMpEng**: MsMpEng initiating an outbound network connection immediately after a definition removal attempt is a behavioral correlation. If your detection logic monitors for MsMpEng network events following suspicious `MpCmdRun.exe` activity, this provides a corroborating signal.

**Absence of Defender update events**: In a normal patch cycle, `MpCmdRun.exe` execution is typically followed by definition update events in the Windows Defender Operational log. The absence of update events following `MpCmdRun.exe -RemoveDefinitions` is an anomalous contrast that indicates the operation was disruptive rather than restorative.
