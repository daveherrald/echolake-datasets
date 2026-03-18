# T1112-65: Modify Registry — Disable Remote Desktop Security Settings Through Registry

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to establish persistence, evade defenses, and modify system behavior by directly manipulating Windows registry keys. This specific test (T1112-65) focuses on disabling Remote Desktop security settings through the registry, which weakens authentication requirements and security controls for RDP connections. Attackers commonly target RDP configurations to enable easier lateral movement and persistent remote access to compromised systems.

The detection community focuses heavily on monitoring registry modifications, particularly those affecting security controls, authentication mechanisms, and remote access services. Registry changes to Terminal Services/RDP configurations are especially significant as they can enable attackers to bypass security measures and maintain covert access channels.

## What This Dataset Contains

This dataset captures a PowerShell-driven registry modification that disables Remote Desktop security settings. The key evidence is found in Security event 4688, which shows the command-line execution:

`"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f`

The process chain is clearly visible: PowerShell (PID 36436) spawns cmd.exe (PID 42920), which then executes reg.exe (PID 18740) to perform the registry modification. All Security 4688 events show successful process creation with exit status 0x0 in the corresponding 4689 events.

Sysmon provides complementary telemetry with ProcessCreate events for the spawned processes. The whoami.exe execution (captured in Sysmon EID 1) appears to be a discovery command run as part of the test setup. Sysmon also captures process access events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe processes.

The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no script blocks containing the actual attack technique.

## What This Dataset Does Not Contain

The dataset lacks direct registry modification telemetry. There are no Sysmon EID 13 (Registry value set) events, which would normally capture the actual registry change. This absence suggests either the sysmon-modular configuration doesn't monitor this specific registry path, or the events were filtered out.

The dataset also lacks any Windows Defender alerts or blocking actions, despite the endpoint protection being active. This indicates the registry modification technique successfully executed without triggering behavioral detection rules.

No network-related events are present, which is expected since this is a local registry modification technique.

## Assessment

This dataset provides solid process execution telemetry for detecting the technique through command-line analysis and process chain monitoring. The Security audit logs with command-line logging offer comprehensive coverage of the process creation events, making this an excellent dataset for building detections based on command-line patterns and parent-child process relationships.

However, the absence of registry modification events limits the dataset's utility for building registry-focused detections. The technique evidence is indirect (through process execution) rather than direct (through registry monitoring), which may miss more sophisticated registry modification methods that don't use reg.exe.

The execution context (NT AUTHORITY\SYSTEM) and the specific registry path make this dataset particularly valuable for detecting privilege escalation attempts and RDP security bypasses.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection**: Monitor for `reg.exe` executions with `add` operations targeting `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services` with `DisableSecuritySettings` value

2. **Process chain analysis**: Detect PowerShell spawning cmd.exe which then spawns reg.exe, particularly when modifying Terminal Services registry keys

3. **Registry path monitoring**: Alert on any modifications to `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` regardless of the tool used

4. **RDP security policy changes**: Monitor for registry modifications that weaken Remote Desktop authentication or security controls

5. **Privileged registry modifications**: Detect SYSTEM-level processes making changes to security-related registry policies

6. **LOLBin usage**: Monitor reg.exe usage for adding DWORD values to system policy locations, especially when spawned by scripting engines

7. **Terminal Services policy tampering**: Build specific rules for detecting changes to RDP/Terminal Services configuration that could enable unauthorized access
