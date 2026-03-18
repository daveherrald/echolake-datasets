# T1070.005-4: Network Share Connection Removal — Disable Administrative Share Creation at Startup

## Technique Context

T1070.005 Network Share Connection Removal encompasses methods adversaries use to remove evidence of network shares they've created or accessed during an intrusion. Administrative shares (C$, ADMIN$, IPC$) are automatically created by Windows at startup and provide administrative-level access to system resources. Disabling their automatic creation is a defensive technique that reduces attack surface, but when performed by adversaries, it can serve as an anti-forensics measure to complicate incident response efforts.

The detection community focuses on registry modifications to LanmanServer parameters, particularly AutoShareServer and AutoShareWks values that control administrative share creation. These modifications require elevated privileges and represent a significant configuration change that deviates from default Windows behavior.

## What This Dataset Contains

This dataset captures the complete execution chain of disabling administrative share creation through registry modification. The Security channel shows the full process tree in events 4688: PowerShell (PID 40776) spawning cmd.exe (PID 16164) with command line `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f`, which then spawns two reg.exe processes (PIDs 39100 and 42164) to perform the actual registry writes.

Sysmon provides complementary process creation events (EID 1) for cmd.exe and both reg.exe executions, along with the critical registry modification evidence in events EID 13: `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer` and `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks` both set to DWORD value 0x00000000.

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script block logging, indicating the test used direct command execution rather than PowerShell scripting.

## What This Dataset Does Not Contain

This dataset does not capture the immediate effect of the registry changes, as administrative shares are created at system startup, not dynamically when the registry values are modified. There are no network events showing existing shares being removed or subsequent startup events showing shares not being created. The dataset also lacks any Service Control Manager events that might indicate attempts to restart the LanmanServer service to apply changes immediately.

Windows Defender did not block this technique (all processes exit with status 0x0), as modifying these specific registry keys is considered legitimate system administration and doesn't trigger behavioral detection.

## Assessment

This dataset provides excellent telemetry for detecting administrative share disabling through registry modification. The combination of Security 4688 command-line logging and Sysmon EID 13 registry monitoring creates multiple detection points that are difficult for adversaries to evade. The process chain is fully captured, showing the execution context and parent-child relationships clearly.

The registry modification events are particularly valuable as they capture the exact keys and values being modified, which is the definitive indicator of this technique. The command-line evidence in Security logs provides additional context about how the modification was performed and can help distinguish between legitimate administration and malicious activity.

## Detection Opportunities Present in This Data

1. **Registry Key Modification Detection** - Monitor Sysmon EID 13 for modifications to `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer` or `AutoShareWks` values being set to 0, which directly indicates administrative share disabling.

2. **Command Line Pattern Detection** - Alert on Security EID 4688 process creation events with command lines containing both "LanmanServer\Parameters" and "AutoShare" registry paths, particularly when setting values to 0.

3. **Process Chain Analysis** - Detect cmd.exe spawning reg.exe with arguments targeting LanmanServer registry keys, especially when the parent process is PowerShell or other scripting engines commonly used by attackers.

4. **Bulk Registry Modification Detection** - Monitor for rapid succession of registry modifications to multiple AutoShare-related values within a short timeframe, which may indicate automated tooling.

5. **Privilege Escalation Context** - Correlate these registry modifications with recent privilege escalation events (Security EID 4703 token right adjustments) to identify potential malicious context versus legitimate administration.

6. **Administrative Share Enumeration Correlation** - Look for network enumeration activities (net share, PowerShell Get-SmbShare) preceding these registry modifications, which may indicate reconnaissance followed by anti-forensics measures.
