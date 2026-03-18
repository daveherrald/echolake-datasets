# T1072-2: Software Deployment Tools — PDQ Deploy RAT

## Technique Context

T1072 Software Deployment Tools represents adversaries leveraging legitimate software deployment and management tools for execution and lateral movement. PDQ Deploy is a widely-used enterprise software deployment tool that allows administrators to remotely install applications, updates, and execute commands across managed endpoints. Attackers often abuse these legitimate administrative tools because they provide authorized pathways for code execution with elevated privileges and are less likely to trigger security alerts compared to traditional malware.

The detection community focuses on identifying unusual patterns in deployment tool usage, such as execution outside normal business hours, deployment of suspicious payloads, or usage by unauthorized accounts. PDQ Deploy Console (PDQDeployConsole.exe) is particularly interesting as it provides command-line access to deployment functionality and can be used to execute arbitrary commands on remote systems.

## What This Dataset Contains

This dataset captures an attempt to execute PDQ Deploy Console through PowerShell. The key evidence includes:

**Process execution chain**: PowerShell (PID 25428) spawns `whoami.exe` (PID 26140) followed by `cmd.exe` (PID 25184) with the command line `"cmd.exe" /c "%%PROGRAMFILES(x86)%%/Admin Arsenal/PDQ Deploy/PDQDeployConsole.exe"`.

**Security audit events**: Security 4688 events show the process creations with full command lines, including the failed execution attempt with exit status 0x1 for the cmd.exe process.

**Sysmon process creation**: EID 1 events capture both the `whoami.exe` execution (flagged with T1033 System Owner/User Discovery rule) and the `cmd.exe` execution (flagged with T1059.003 Windows Command Shell rule).

**Process access events**: Sysmon EID 10 events show PowerShell accessing both child processes with full access rights (0x1FFFFF), indicating process monitoring or control.

**PowerShell telemetry**: The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual test script content.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful PDQ Deploy Console execution. The cmd.exe process exits with status 0x1, indicating failure - likely because PDQ Deploy is not installed on this test system. This means we don't see:

- Actual PDQDeployConsole.exe process creation
- Network connections to PDQ Deploy servers
- File operations related to software deployment
- Registry modifications typical of deployment tool initialization

The Sysmon ProcessCreate events for the parent PowerShell process are missing, likely filtered out by the sysmon-modular include-mode configuration since powershell.exe doesn't match the suspicious process patterns.

## Assessment

This dataset provides moderate value for detection engineering focused on deployment tool abuse attempts. While it captures the execution attempt and command-line evidence clearly through Security 4688 events and Sysmon process creation, the failed execution limits its utility for understanding successful abuse patterns. The process access events and command-line logging provide good detection signals for identifying attempts to invoke deployment tools, even when they fail. The clear process lineage from PowerShell to cmd.exe attempting to launch PDQDeployConsole.exe offers actionable detection opportunities.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection**: Monitor for processes attempting to execute PDQ Deploy binaries (`PDQDeployConsole.exe`, `PDQInventoryScanner.exe`) in command lines, particularly when invoked through cmd.exe or PowerShell

2. **Process chain analysis**: Alert on PowerShell processes spawning cmd.exe that then attempts to execute software deployment tools, especially when combined with discovery commands like `whoami.exe`

3. **Failed execution alerting**: Track cmd.exe processes with exit code 0x1 when attempting to execute deployment tool paths, as this may indicate unauthorized access attempts on systems without the tools installed

4. **Process access monitoring**: Detect PowerShell processes accessing child processes with full rights (0x1FFFFF) that involve system administration or deployment tool execution

5. **Administrative tool discovery**: Monitor for the specific file path pattern `%PROGRAMFILES(x86)%/Admin Arsenal/PDQ Deploy/` being accessed or referenced in command lines, regardless of execution success
