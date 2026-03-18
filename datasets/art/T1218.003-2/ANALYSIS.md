# T1218.003-2: CMSTP — CMSTP Executing UAC Bypass

## Technique Context

CMSTP (Connection Manager Service Profile Installer) is a legitimate Microsoft signed binary used to install Connection Manager service profiles. Attackers abuse CMSTP to bypass User Account Control (UAC) and execute malicious code with elevated privileges by crafting malicious .inf files that exploit CMSTP's auto-elevation behavior. This technique is particularly valuable because CMSTP is a trusted Microsoft binary that can bypass application whitelisting and UAC without user interaction.

The detection community focuses on monitoring CMSTP execution with suspicious command-line parameters, particularly the `/s` (silent) and `/au` (auto-unattended) flags, process spawning from CMSTP, and the loading of malicious .inf files. CMSTP UAC bypasses typically involve the creation of elevated processes through COM object instantiation or other privilege escalation mechanisms.

## What This Dataset Contains

This dataset captures a CMSTP UAC bypass attempt that demonstrates both successful process creation and subsequent failure. The key evidence includes:

**Process Chain**: PowerShell → cmd.exe → cmstp.exe → dllhost.exe → cmd.exe, showing the complete attack execution path through Security 4688 events.

**CMSTP Invocation**: Security 4688 shows `cmstp.exe /s "C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003_uacbypass.inf" /au` with the classic UAC bypass parameters.

**Elevated Process Spawning**: Security 4688 captures dllhost.exe spawning with the CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` and subsequently launching an elevated cmd.exe with the command line `c:\windows\system32\cmd.exe`.

**Process Failures**: Multiple Security 4689 events show cmd.exe processes exiting with status 0x1 (general failure), indicating the UAC bypass attempt failed despite initial process creation.

**Sysmon Process Creation**: Sysmon EID 1 captures the whoami.exe execution, cmd.exe spawning with the full CMSTP command line, and the final elevated cmd.exe creation from dllhost.exe, providing additional process telemetry with parent-child relationships and integrity levels.

**System Service Changes**: System EID 7040 shows the Background Intelligent Transfer Service changing from demand start to auto start, possibly related to the UAC bypass mechanism.

## What This Dataset Does Not Contain

**Missing CMSTP Process Creation**: No Sysmon EID 1 for cmstp.exe itself, as the sysmon-modular config filters out many standard Windows binaries not explicitly marked as suspicious.

**Missing Dllhost Process Creation**: No Sysmon EID 1 for the critical dllhost.exe process that performs the COM-based privilege escalation, limiting visibility into this key component of the bypass.

**No INF File Analysis**: The dataset doesn't contain file creation events for the malicious .inf file or evidence of its parsing by CMSTP.

**Limited PowerShell Content**: The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual test execution commands.

**No Success Telemetry**: While the processes are created, the exit codes indicate failure, so the dataset shows an attempted but unsuccessful UAC bypass rather than a fully successful one.

## Assessment

This dataset provides moderate utility for CMSTP UAC bypass detection engineering. The Security 4688 events comprehensively capture the process execution chain and command lines, making them the primary detection source. The presence of both the CMSTP invocation with bypass parameters and the subsequent dllhost.exe/cmd.exe spawning provides clear evidence of the attack pattern.

However, the filtered Sysmon configuration significantly limits process visibility, particularly missing the CMSTP and dllhost.exe process creation events that would provide valuable parent-child relationship context and integrity level information. The dataset would be stronger with full process creation logging and file system events showing INF file operations.

## Detection Opportunities Present in This Data

1. **CMSTP with UAC Bypass Parameters** - Security 4688 showing `cmstp.exe` with `/s` and `/au` flags, particularly when combined with custom .inf files outside standard system directories.

2. **Suspicious Process Chain** - Security 4688 events showing cmd.exe → cmstp.exe → dllhost.exe → cmd.exe execution sequence, especially when originating from scripting engines.

3. **Dllhost with Specific CLSID** - Security 4688 showing `dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` which is associated with CMSTP UAC bypass techniques.

4. **Elevated Process from Dllhost** - Security 4688 showing cmd.exe or other shells spawned by dllhost.exe, indicating potential privilege escalation success.

5. **Process Access from PowerShell** - Sysmon EID 10 showing PowerShell accessing spawned processes with full access rights (0x1FFFFF), indicating potential injection or manipulation.

6. **CMSTP INF File Path Anomalies** - Command line analysis showing CMSTP loading .inf files from non-standard locations like user directories or temporary paths.

7. **Service Configuration Changes** - System EID 7040 showing unexpected service startup type changes concurrent with CMSTP execution, potentially indicating privilege escalation side effects.
