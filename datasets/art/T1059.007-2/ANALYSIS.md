# T1059.007-2: JavaScript — JScript execution to gather local computer information via wscript

## Technique Context

T1059.007 (JavaScript) represents attackers' use of JavaScript and JScript for command and script execution. This technique is particularly valuable to adversaries because Windows Script Host (WSH) components like wscript.exe and cscript.exe are legitimate, signed Microsoft binaries present on virtually all Windows systems. Attackers commonly leverage these interpreters to execute JavaScript payloads for reconnaissance, persistence, lateral movement, and payload delivery. The detection community focuses on monitoring process creation events for script interpreters, analyzing command-line arguments containing script paths or inline code, examining parent-child process relationships (especially when script interpreters spawn from unexpected parents), and correlating with file system events for dropped script files.

## What This Dataset Contains

This dataset captures the execution of a JavaScript reconnaissance script via Windows Script Host. The core technique evidence appears in Security event 4688 showing the process chain: `powershell.exe` → `cmd.exe` → `wscript.exe "C:\AtomicRedTeam\atomics\T1059.007\src\sys_info.js"`. Sysmon provides complementary process creation events, including EID 1 for wscript.exe with the full command line `wscript  "C:\AtomicRedTeam\atomics\T1059.007\src\sys_info.js"` and parent process information showing cmd.exe as the immediate parent.

The dataset shows AMSI integration through Sysmon EID 7 capturing `C:\Windows\System32\amsi.dll` being loaded into the wscript.exe process, indicating Windows Defender's real-time protection was active and scanning the JavaScript content. WMI activity is present through multiple vectors: WmiPrvSE.exe process creation, wmiutils.dll loading in both wscript.exe and WmiPrvSE.exe processes, and Sysmon rule tagging for T1047 (Windows Management Instrumentation).

The PowerShell telemetry contains only test framework boilerplate with `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` commands and standard error handling scriptblocks, with no evidence of the actual JavaScript payload execution being logged through PowerShell channels.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide deeper visibility into the JavaScript execution. There are no Windows Script Host operational logs (Microsoft-Windows-ScriptedDiagnosticsProvider/Operational) that might contain script execution details. No Application event logs are included that could show WSH errors or execution artifacts. The JavaScript file contents are not captured through any channel, preventing analysis of the actual reconnaissance commands being executed.

Network telemetry is absent, so if the script performed any network-based information gathering or attempted external communications, those activities are not visible. File system events beyond basic file creation are limited - there's no evidence of the script reading system files, registry keys, or creating output files with gathered information.

## Assessment

This dataset provides solid foundational telemetry for detecting JavaScript execution via Windows Script Host. The Security 4688 events offer complete process lineage with command-line logging, while Sysmon EID 1 events provide additional process context and hashing for threat hunting. The AMSI integration evidence is particularly valuable, showing how Windows Defender interacted with the script execution.

The WMI-related telemetry suggests the JavaScript likely used WMI for system information gathering, which is a common pattern in reconnaissance scripts. However, the absence of the actual script contents and any output artifacts limits the dataset's utility for understanding what information was collected or how the technique could be further analyzed for attribution or capability assessment.

For detection engineering purposes, this dataset supports building reliable detections around the process execution patterns while the AMSI integration provides opportunities for content-based detection approaches when combined with additional telemetry sources.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for wscript.exe/cscript.exe execution** - Security EID 4688 and Sysmon EID 1 showing script interpreter execution with external .js file paths

2. **Suspicious parent-child process relationships** - PowerShell spawning cmd.exe which then spawns wscript.exe, indicating potential script-based attack chains

3. **Command-line analysis for script file paths** - Detection of .js, .vbs, .wsf file extensions in wscript.exe command lines, especially from non-standard directories

4. **AMSI integration monitoring** - Sysmon EID 7 showing amsi.dll loading into script interpreter processes, which can be correlated with Windows Defender logs for script content analysis

5. **WMI activity correlation** - WmiPrvSE.exe process creation and wmiutils.dll loading events occurring temporally near script interpreter execution, indicating potential WMI-based reconnaissance

6. **File system monitoring for script files** - While not extensively present in this dataset, monitoring for .js file creation in temporary directories or user-writable locations

7. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing spawned processes with high-privilege access rights (0x1FFFFF), indicating potential process manipulation or monitoring
