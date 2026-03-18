# T1057-2: Process Discovery — Process Discovery - tasklist

## Technique Context

T1057 Process Discovery is a fundamental reconnaissance technique where adversaries enumerate running processes to understand the security environment, identify potential targets for privilege escalation, or locate security tools. The `tasklist` command is one of the most common Windows utilities used for this purpose, providing detailed information about running processes including process names, PIDs, memory usage, and associated services.

The detection community focuses heavily on monitoring process discovery activities because they represent early-stage reconnaissance behavior that precedes more sophisticated attacks. While legitimate administrative use of `tasklist` is common, unusual execution contexts (spawned by scripts, run from uncommon directories, or executed with suspicious parent processes) can indicate malicious activity. This technique is frequently observed in conjunction with other discovery techniques as attackers map out their target environment.

## What This Dataset Contains

This dataset captures a straightforward execution of `tasklist` through a PowerShell-spawned cmd.exe wrapper. The key process chain is clearly visible in the telemetry:

**Process Chain (Sysmon EID 1):**
- PowerShell → cmd.exe: `"cmd.exe" /c tasklist` (Process ID 4552, Parent 6744)
- cmd.exe → tasklist.exe: `tasklist` (Process ID 5332, Parent 4552)

**Security Events (EID 4688)** capture the same process creations with full command lines, providing redundant coverage. The dataset also includes a preliminary `whoami` execution showing the test framework validating execution context.

**Sysmon Process Access Events (EID 10)** show PowerShell accessing both the cmd.exe and whoami processes with full access rights (0x1FFFFF), which represents normal process management behavior during command execution.

**Image Load Events (EID 7)** reveal tasklist.exe loading several interesting libraries:
- `amsi.dll` - Anti-Malware Scan Interface integration
- `MpOAV.dll` - Windows Defender Office AntiVirus module
- `wmiutils.dll` - WMI utilities for process enumeration

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode), with no technique-specific PowerShell content.

## What This Dataset Does Not Contain

This dataset represents a successful, unblocked execution with no defensive interference. Windows Defender did not prevent the technique execution, as evidenced by clean exit codes (0x0) across all processes. 

The dataset lacks any network activity, file system artifacts beyond PowerShell profile updates, or registry modifications - tasklist is a read-only reconnaissance tool that doesn't persist changes. No WMI events are captured despite tasklist loading WMI utilities, likely because the process enumeration uses direct system calls rather than WMI queries.

The sysmon-modular configuration successfully captured all relevant processes (whoami, cmd.exe, tasklist.exe) because these utilities match the include-mode filtering patterns for known-suspicious binaries.

## Assessment

This dataset provides excellent telemetry for detecting basic process discovery techniques. The combination of Sysmon process creation events with command-line logging from Security 4688 events creates robust detection opportunities. The process chain visibility is particularly valuable - the PowerShell → cmd.exe → tasklist pattern is a common attacker execution flow that can be reliably detected.

The image load events add valuable context about the defensive tools that monitored the execution (AMSI, Defender) and the technical implementation (WMI utilities). This multi-layered visibility makes the dataset highly suitable for building comprehensive detections that consider both the primary technique and its execution context.

The main limitation is the straightforward nature of this execution - it lacks the evasive techniques (process hollowing, PPID spoofing, etc.) that more sophisticated adversaries might employ.

## Detection Opportunities Present in This Data

1. **Direct tasklist.exe execution detection** - Monitor Sysmon EID 1 for Image=`*\tasklist.exe` with any CommandLine containing process enumeration flags

2. **Suspicious parent process patterns** - Alert on tasklist.exe with ParentImage matching script interpreters (powershell.exe, cmd.exe, wscript.exe) outside of legitimate administrative contexts

3. **Process discovery command sequence** - Detect cmd.exe spawned with `/c tasklist` pattern, especially when parent is PowerShell or other scripting engines

4. **Cross-reference with process access events** - Correlate Sysmon EID 1 tasklist creation with EID 10 process access events showing reconnaissance patterns

5. **Image load behavioral analysis** - Monitor for tasklist.exe loading WMI utilities (wmiutils.dll) which may indicate more sophisticated process enumeration techniques

6. **Command-line argument analysis** - Parse Security EID 4688 command lines for tasklist executions with specific filtering or formatting options that suggest automated reconnaissance

7. **Process timing correlation** - Detect rapid sequences of discovery commands (whoami followed by tasklist) within short time windows as potential reconnaissance phases
