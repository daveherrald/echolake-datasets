# T1218-13: System Binary Proxy Execution — LOLBAS CustomShellHost to Spawn Process

## Technique Context

T1218 (System Binary Proxy Execution) involves adversaries leveraging trusted system binaries to execute malicious payloads, bypassing application whitelisting and security controls. CustomShellHost.exe is a lesser-known Windows binary that can be abused as a Living Off The Land Binary (LOLBin) to spawn arbitrary processes. This technique allows attackers to use a legitimate, signed Microsoft binary to execute code while appearing benign to security tools that focus on unsigned or suspicious binaries.

CustomShellHost.exe is designed to act as a shell host for custom shell implementations in Windows. When executed, it automatically attempts to launch "explorer.exe" from its current directory with the "/NoShellRegistrationCheck" parameter. Attackers exploit this behavior by placing a malicious executable renamed as "explorer.exe" in the same directory as CustomShellHost.exe, effectively using the legitimate binary as a proxy to execute their payload.

The detection community focuses on monitoring for unusual parent-child process relationships, execution of binaries from non-standard locations, and the specific command-line pattern associated with CustomShellHost's automatic explorer.exe spawning behavior.

## What This Dataset Contains

This dataset captures a complete execution chain of the CustomShellHost.exe LOLBin technique. The PowerShell script block logging shows the setup commands: creating a `C:\test` directory, copying `customshellhost.exe` from System32, and copying `calc.exe` as a renamed `explorer.exe` to establish the proxy execution scenario.

Security event 4688 shows the key process creation events:
- PowerShell (PID 43096) with the full command line containing the setup and execution commands
- `C:\test\customshellhost.exe` (PID 9304) launched from the copied location
- `C:\test\explorer.exe` (PID 12084) spawned by customshellhost.exe with command line `explorer.exe /NoShellRegistrationCheck`

Sysmon provides rich additional context with events showing:
- File creation events (EID 11) for both copied binaries at `C:\test\customshellhost.exe` and `C:\test\explorer.exe`
- File executable detection events (EID 29) with full hash information for both copied files
- Process access events (EID 10) showing PowerShell accessing the spawned processes
- Image load events (EID 7) showing DLL loading in the malicious `explorer.exe` process

The parent-child relationship clearly shows: PowerShell → customshellhost.exe → explorer.exe (actually calc.exe), demonstrating the proxy execution chain.

## What This Dataset Does Not Contain

The dataset lacks network connections that might occur if a real payload established persistence or command-and-control communications. Since calc.exe was used as the payload, there are no additional malicious behaviors beyond the initial process spawning.

There are no Sysmon ProcessCreate events (EID 1) for the customshellhost.exe execution itself, likely because the sysmon-modular configuration's include-mode filtering doesn't classify customshellhost.exe as a suspicious LOLBin requiring monitoring. However, the Security channel 4688 events provide complete coverage of all process creations.

Registry modifications or additional file system changes that a real attacker might perform post-execution are not present in this controlled demonstration.

## Assessment

This dataset provides excellent coverage for detecting the CustomShellHost.exe LOLBin technique. The combination of Security 4688 events and Sysmon telemetry captures all the critical detection points. The PowerShell script block logging reveals the attacker's methodology, while the process creation events show the execution chain clearly.

The file creation and executable detection events provide opportunities to detect the staging behavior, and the distinctive command line pattern "/NoShellRegistrationCheck" serves as a strong signature for this technique. The hash information allows for both known-bad detection and behavioral analysis of unexpected executables in custom locations.

The process access telemetry demonstrates how PowerShell maintains relationships with the spawned processes, providing additional context for correlation and investigation.

## Detection Opportunities Present in This Data

1. **CustomShellHost.exe execution from non-standard locations** - Monitor for customshellhost.exe running from directories other than System32, indicating potential abuse.

2. **Explorer.exe with /NoShellRegistrationCheck parameter** - This specific command line is highly indicative of CustomShellHost.exe proxy execution and rarely appears in legitimate scenarios.

3. **File staging behavior** - Detect copying of customshellhost.exe to user-writable directories, especially when combined with placement of renamed executables.

4. **Unusual parent-child process relationships** - CustomShellHost.exe spawning explorer.exe from non-standard locations should trigger investigation.

5. **PowerShell Copy-Item operations targeting customshellhost.exe** - Script block logging can reveal the setup phase of this technique through file copy operations.

6. **Hash-based detection of renamed legitimate binaries** - Files named explorer.exe with hashes matching calc.exe or other system utilities indicate masquerading.

7. **Process tree anomalies** - Three-tier process chains (PowerShell → CustomShellHost → renamed executable) represent suspicious execution patterns.

8. **File creation events in temporary directories** - Monitor for executable file creation in directories like C:\test, C:\temp, or user profiles, especially when followed by CustomShellHost execution.
