# T1055-11: Process Injection — Process Injection with Go using CreateThread WinAPI

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where adversaries introduce code into processes to evade detection, access process memory, or inherit elevated privileges. This particular test (T1055-11) demonstrates Go-based process injection using the Windows CreateThread API, which is less common than traditional .NET or PowerShell injection methods but increasingly relevant as more malware authors adopt Go for its cross-platform capabilities and anti-analysis features.

The detection community typically focuses on process access events with suspicious permissions (especially PROCESS_ALL_ACCESS), cross-process thread creation, memory allocation in foreign processes, and the loading of unexpected DLLs. Go-compiled binaries present unique challenges because they produce large, statically-linked executables with obfuscated symbol tables, making behavioral detection more critical than signature-based approaches.

## What This Dataset Contains

The dataset captures the execution of a Go-compiled process injection tool at `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe -debug` launched via PowerShell. The key evidence includes:

**Process creation chain**: Security EID 4688 shows PowerShell (PID 13300) spawning a child PowerShell process (PID 14584) with command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe -debug}`.

**Critical process access events**: Sysmon EID 10 reveals two significant process access attempts by PowerShell (PID 13300):
- Access to whoami.exe (PID 14028) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)
- Access to the child PowerShell process (PID 14584) with GrantedAccess 0x1FFFFF

**Call stack evidence**: The EID 10 events include detailed CallTrace fields showing the injection originating from .NET assemblies: `System.ni.dll` and `System.Management.Automation.ni.dll`, indicating PowerShell-orchestrated process manipulation.

**Process spawning behavior**: Sysmon EID 1 shows whoami.exe creation immediately preceding the process access event, suggesting the injection tool creates target processes for injection testing.

**PowerShell script execution**: EID 4104 captures the actual command execution: `& {C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe -debug}` and `{C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThread.exe -debug}`.

## What This Dataset Does Not Contain

The dataset lacks several critical elements for complete process injection analysis. Most notably, there are **no Sysmon EID 1 events for the CreateThread.exe binary itself** — the sysmon-modular configuration's include-mode filtering means the Go executable didn't match known suspicious patterns, so its process creation went unlogged by Sysmon. This is a significant blind spot since the actual injection tool execution is invisible in Sysmon telemetry.

The dataset contains **no memory allocation events** (Sysmon EID 8 ProcessAccess with VirtualAlloc indicators) or **remote thread creation events**, which would typically accompany successful CreateThread-based injection. There are also **no image load events** showing unexpected DLLs being loaded into target processes, suggesting either the injection failed or these events weren't captured.

Security EID 4688 process creation events don't show the CreateThread.exe execution, indicating it may have been blocked, crashed, or completed too quickly to generate audit events. The presence of process access events but absence of successful injection indicators suggests the technique may have been detected and mitigated by Windows Defender.

## Assessment

This dataset provides moderate value for detection engineering, primarily through its capture of the preparatory phases of process injection rather than the injection itself. The Security 4688 and Sysmon EID 10 events offer excellent detection opportunities for identifying suspicious process access patterns, particularly the PROCESS_ALL_ACCESS (0x1FFFFF) permissions requested against arbitrary processes.

The dataset's strength lies in demonstrating how PowerShell can be used to orchestrate process injection tools, with clear command-line evidence and process relationship mapping. However, the absence of the actual Go binary execution in Sysmon severely limits its utility for understanding Go-based injection techniques specifically.

For building robust detections, this data would be stronger with: Sysmon EID 1 events for all process creations (not just suspicious patterns), memory allocation events (EID 8), and remote thread creation indicators. The dataset does effectively demonstrate the importance of monitoring PowerShell script block execution and process access events as early indicators of injection attempts.

## Detection Opportunities Present in This Data

1. **Suspicious process access patterns**: Monitor Sysmon EID 10 for PROCESS_ALL_ACCESS (0x1FFFFF) permissions requested by PowerShell processes against arbitrary system utilities like whoami.exe

2. **PowerShell-orchestrated binary execution**: Detect PowerShell script blocks (EID 4104) containing execution of binaries from non-standard paths, particularly `C:\AtomicRedTeam\` or other testing directories

3. **Cross-process access from scripting engines**: Alert on Security EID 4688 showing PowerShell spawning child processes followed immediately by Sysmon EID 10 process access events from the parent

4. **Abnormal parent-child process relationships**: Flag PowerShell processes accessing their own child processes with high privileges, as shown in the PowerShell->PowerShell access pattern

5. **Command-line injection indicators**: Monitor Security EID 4688 command lines containing suspicious binary paths combined with debug flags or injection-related parameters like `-debug`

6. **CallTrace analysis for injection frameworks**: Analyze Sysmon EID 10 CallTrace fields showing .NET assemblies (System.ni.dll, System.Management.Automation.ni.dll) in the call stack during process access events

7. **Temporal correlation of process creation and access**: Create detection logic that correlates rapid succession of process creation (EID 1/4688) followed by high-privilege process access (EID 10) from the same source process
