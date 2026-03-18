# T1219-10: Remote Access Tools — UltraVNC Execution

## Technique Context

T1219 Remote Access Tools covers adversary use of legitimate remote access software to maintain persistence and move laterally through victim networks. UltraVNC is a popular open-source VNC (Virtual Network Computing) implementation that allows remote desktop access. Attackers often abuse legitimate remote access tools because they blend in with normal IT operations, bypass application whitelisting, and provide full interactive access to systems. The detection community focuses on identifying unauthorized installations, unusual command-line parameters, execution from unexpected locations, and network connections to external or suspicious destinations.

## What This Dataset Contains

This dataset captures a failed attempt to execute UltraVNC's vncviewer.exe. The PowerShell command line shows the attempted execution: `"powershell.exe" & {Start-Process $env:ProgramFiles\'uvnc bvba\UltraVnc\vncviewer.exe'}` in Security event 4688. The PowerShell ScriptBlock logging in event 4104 reveals the actual command: `& {Start-Process $env:ProgramFiles\'uvnc bvba\UltraVnc\vncviewer.exe'}`.

Key telemetry includes:
- Security 4688 events showing PowerShell process creation with the full command line
- PowerShell 4100 error: "This command cannot be run due to the error: The system cannot find the file specified"
- PowerShell 4103 CommandInvocation showing Start-Process with FilePath "C:\Program Files\uvnc bvba\UltraVnc\vncviewer.exe"
- Multiple Sysmon events for PowerShell processes (ProcessIds 20588, 17092, 35148, 21008) including process creation, image loads, and pipe creation
- Sysmon 1 events showing whoami.exe execution for system discovery

The test execution shows clear process ancestry: initial PowerShell → child PowerShell → attempted UltraVNC execution.

## What This Dataset Does Not Contain

The dataset lacks any evidence of successful UltraVNC execution because the software is not installed on the test system. There are no:
- Process creation events for vncviewer.exe or related UltraVNC binaries
- Network connections (Sysmon EID 3) to VNC servers on typical ports (5900/5901)
- File creation events for UltraVNC configuration files or logs
- Registry modifications related to UltraVNC installation or configuration
- DNS queries for VNC-related domains

The failure occurs at the file system level before any VNC-specific behavior could be observed, limiting the dataset's utility for studying actual remote access tool network behavior.

## Assessment

This dataset provides moderate value for detection engineering focused on command-line based remote access tool deployment attempts. The PowerShell telemetry clearly shows the execution attempt with full command lines preserved in both Security and PowerShell channels. However, the dataset's utility is significantly limited by the failed execution - it demonstrates detection of deployment attempts rather than active remote access tool usage.

The telemetry is strongest for identifying PowerShell-based remote access tool deployment scripts and weakest for understanding actual VNC network protocols, authentication, or session establishment. For building comprehensive T1219 detections, additional datasets with successful remote access tool execution would be necessary.

## Detection Opportunities Present in This Data

1. **PowerShell Start-Process with Remote Access Tool Paths** - Alert on PowerShell Start-Process commands referencing common remote access tool installation paths like `*uvnc*`, `*vnc*`, `*teamviewer*`, etc.

2. **Suspicious PowerShell Command Line Patterns** - Detect command lines containing remote access software names combined with Start-Process or similar execution commands.

3. **PowerShell ScriptBlock Analysis** - Monitor PowerShell 4104 events for script blocks containing remote access tool binary names and execution patterns.

4. **Process Chain Analysis** - Flag PowerShell parent processes spawning child PowerShell processes that attempt to execute remote access tools.

5. **Failed Execution Error Patterns** - Monitor PowerShell 4100 error events mentioning "system cannot find file" combined with remote access tool paths as potential reconnaissance or deployment failures.

6. **Environment Variable Expansion in Commands** - Detect use of `$env:ProgramFiles` or similar environment variables in PowerShell commands targeting remote access software directories.

7. **System Discovery After Remote Tool Attempts** - Correlate failed remote access tool execution with immediate whoami.exe or similar discovery commands as potential attack progression indicators.
