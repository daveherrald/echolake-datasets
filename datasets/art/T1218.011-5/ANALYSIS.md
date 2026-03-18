# T1218.011-5: Rundll32 — Rundll32 ieadvpack.dll Execution

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to proxy execution of malicious code. Rundll32.exe is designed to execute functions within DLLs, but attackers leverage it to execute arbitrary code while appearing to use a trusted, signed Windows binary. This technique is particularly valuable because rundll32.exe executes with the same privileges as the calling process and can bypass application whitelisting solutions that trust Microsoft-signed binaries.

The ieadvpack.dll variant specifically uses the Internet Explorer Advanced Pack library's LaunchINFSection function to execute INF files. INF files are setup information files that can contain commands to install software, modify registry settings, or execute programs. Attackers often use this method because INF file execution through ieadvpack.dll can bypass certain security controls while maintaining the appearance of legitimate system administration activity.

Detection engineers typically focus on monitoring rundll32.exe command lines for suspicious DLL/function combinations, unusual child processes, network connections from rundll32.exe, and INF file creation or modification in suspicious locations.

## What This Dataset Contains

This dataset captures a successful rundll32.exe ieadvpack.dll execution with complete process telemetry. The attack chain is clearly visible in Security 4688 events:

1. PowerShell (PID 37880) spawns cmd.exe with command line: `"cmd.exe" /c rundll32.exe ieadvpack.dll,LaunchINFSection "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011.inf",DefaultInstall_SingleUser,1,`

2. cmd.exe (PID 37608) spawns rundll32.exe with command line: `rundll32.exe ieadvpack.dll,LaunchINFSection "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011.inf",DefaultInstall_SingleUser,1,`

Sysmon captures the rundll32.exe process creation (EID 1) with full context including hashes (SHA256=63D689421DB32725B79CE7E11B8B0414AB64C4208A81634F0D640E2873B63C6F), parent process details, and command line arguments. The process executes successfully with exit status 0x0, indicating the INF file execution completed without error.

The dataset also contains Sysmon process access events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), demonstrating the process injection detection capabilities.

## What This Dataset Does Not Contain

The dataset lacks several important elements for comprehensive rundll32.exe analysis. Most notably, there are no file creation events showing the contents or creation of the T1218.011.inf file itself - we only see references to it in command lines. Sysmon EID 11 events show PowerShell profile files but not the INF file operations.

There are no registry modification events (Sysmon EID 12/13) that would typically result from INF file execution via LaunchINFSection. The dataset also lacks network connection events (Sysmon EID 3), which would be critical for detecting if the INF file attempted to download additional payloads or establish command and control.

Image load events (Sysmon EID 7) for the rundll32.exe process are absent, which would show ieadvpack.dll loading and any additional DLLs required for INF processing. The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual script content that orchestrated the attack.

## Assessment

This dataset provides excellent coverage for basic rundll32.exe ieadvpack.dll detection use cases. The Security 4688 events with command-line logging capture the complete attack chain with high fidelity, and the Sysmon process creation events add valuable context including file hashes and parent-child relationships. The combination of both data sources creates redundant coverage that would be difficult for attackers to evade.

However, the dataset's utility is limited for detecting the actual malicious actions performed by the INF file. Without registry, file, or network telemetry from the rundll32.exe execution, analysts cannot determine what the technique accomplished beyond successful process execution. This makes it suitable for detecting the technique itself but insufficient for understanding impact or building behavioral detections based on post-execution artifacts.

For production detection engineering, this data quality would be adequate for signature-based detection rules but insufficient for comprehensive behavioral analytics or threat hunting focused on technique outcomes rather than just execution.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with ieadvpack.dll**: Monitor Security 4688 and Sysmon EID 1 for rundll32.exe command lines containing "ieadvpack.dll,LaunchINFSection" which is rarely used in legitimate environments.

2. **INF file references in rundll32.exe command lines**: Alert on rundll32.exe processes with command lines referencing .inf files, particularly those in non-standard locations like user-writable directories.

3. **cmd.exe spawning rundll32.exe with suspicious arguments**: Detect cmd.exe processes creating rundll32.exe children with ieadvpack.dll or other suspicious DLL/function combinations.

4. **PowerShell to cmd.exe to rundll32.exe process chain**: Monitor for this specific three-hop process chain which is commonly used in scripted attacks abusing rundll32.exe.

5. **Rundll32.exe with full command line arguments**: Create baseline behavior for legitimate rundll32.exe usage and alert on deviations, particularly long command lines with multiple comma-separated parameters.

6. **Process access patterns from scripting engines**: Monitor Sysmon EID 10 events for PowerShell or other scripting engines accessing rundll32.exe processes with high privilege access rights.
