# T1055-3: Process Injection — Section View Injection

## Technique Context

Process injection is a defense evasion and privilege escalation technique where adversaries inject code into the address space of another process to evade process-based defenses and potentially escalate privileges. Section view injection (T1055.008) is a specific variant that uses Windows section objects to map memory between processes, leveraging APIs like `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection`. This technique allows attackers to inject shellcode or DLLs into target processes while potentially bypassing some endpoint detection mechanisms that focus on more common injection methods like `CreateRemoteThread` or manual DLL injection.

The detection community focuses on process access events with suspicious access rights (particularly `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`), unusual cross-process memory operations, and the loading of unsigned or suspicious modules. Section view injection often generates telemetry through process access events and may be detectable through memory forensics or behavioral analysis of injected processes.

## What This Dataset Contains

This dataset captures a failed attempt at section view injection using the Atomic Red Team test. The key evidence shows:

**Process Chain**: The test creates a PowerShell process (PID 40376) that attempts to launch both `notepad.exe` and `InjectView.exe` via the command line `"powershell.exe" & {$notepad = Start-Process notepad -passthru; Start-Process \"C:\AtomicRedTeam\atomics\T1055\bin\x64\InjectView.exe\"}`.

**Process Access Events**: Sysmon EID 10 captures two critical process access events from the PowerShell process (PID 40168) accessing both `whoami.exe` (PID 40336) and another PowerShell instance (PID 40376) with `GrantedAccess: 0x1FFFFF` (full access rights). The call traces show .NET System.Management.Automation assemblies, indicating PowerShell's `Start-Process` cmdlet behavior.

**File System Evidence**: Security EID 4688 shows successful creation of `notepad.exe` with command line `"C:\Windows\system32\notepad.exe"`, and Sysmon EID 7 shows notepad.exe loading `urlmon.dll`.

**Failure Indicators**: PowerShell EID 4100 shows an error: "This command cannot be run due to the error: The system cannot find the file specified" when attempting to start `InjectView.exe`, indicating the injection tool was not found at the specified path.

## What This Dataset Does Not Contain

The dataset lacks the actual section view injection execution because the `InjectView.exe` binary was missing from the expected path `C:\AtomicRedTeam\atomics\T1055\bin\x64\InjectView.exe`. This means we don't see:

- The section object creation and mapping APIs (`NtCreateSection`, `NtMapViewOfSection`)
- Injection of code into the notepad.exe process
- Behavioral changes in the target process post-injection
- Network connections or additional process spawning from injected code
- Memory allocation events in the target process

The Sysmon configuration's include-mode filtering for ProcessCreate (EID 1) means we only see processes that match suspicious patterns - we capture `whoami.exe` and PowerShell instances but might miss other processes that don't match the filter criteria.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating the process access patterns and command-line artifacts associated with process injection attempts. The Sysmon EID 10 events with full process access rights (`0x1FFFFF`) from PowerShell to other processes represent the most valuable detection signal. However, the failed execution limits its utility for understanding the complete attack chain and post-injection behaviors. The Security event logs with command-line auditing provide good supplementary visibility into the attack staging.

## Detection Opportunities Present in This Data

1. **High-privilege process access from PowerShell**: Alert on Sysmon EID 10 where PowerShell processes access other processes with `GrantedAccess: 0x1FFFFF` or other elevated access rights, particularly when the call trace includes System.Management.Automation components.

2. **PowerShell command-line injection patterns**: Monitor Security EID 4688 for PowerShell command lines containing both legitimate process spawning (`Start-Process notepad`) and suspicious binary execution patterns (`C:\AtomicRedTeam\` paths or other non-standard locations).

3. **Cross-process access with .NET call traces**: Correlate Sysmon EID 10 events where the call trace includes .NET assemblies (System.Management.Automation) accessing processes outside the normal parent-child relationship.

4. **PowerShell error patterns**: Monitor PowerShell EID 4100 errors mentioning "system cannot find the file specified" when combined with suspicious command lines, as this may indicate failed malware execution attempts.

5. **Rapid process access sequence**: Detect patterns where a single PowerShell process accesses multiple different target processes within a short time window, which may indicate process injection reconnaissance or multi-target injection attempts.
