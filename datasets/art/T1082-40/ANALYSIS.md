# T1082-40: System Information Discovery — Discover OS Build Number via Registry

## Technique Context

T1082 System Information Discovery is a foundational reconnaissance technique where attackers gather information about the target system's operating system, hardware, and configuration. This specific test (T1082-40) focuses on discovering the OS build number through registry queries, which is a common early-stage activity in both automated and manual attack workflows.

Attackers use OS build information to tailor their approach — selecting appropriate exploits, determining privilege escalation paths, or identifying vulnerable software versions. The detection community typically focuses on monitoring registry queries to system information locations, command-line patterns that reveal reconnaissance intent, and process chains that indicate systematic information gathering.

The technique is frequently observed in initial access scenarios, post-exploitation reconnaissance, and during lateral movement preparation phases.

## What This Dataset Contains

This dataset captures a straightforward system information discovery attempt using PowerShell to invoke registry queries. The core technique execution shows:

**Primary Process Chain (Security Events 4688):**
- `powershell.exe` → `"cmd.exe" /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber` → `reg  query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber`

**Sysmon Process Creation Events (EID 1):**
- `C:\Windows\System32\whoami.exe` with CommandLine `"C:\Windows\system32\whoami.exe"`
- `C:\Windows\System32\cmd.exe` with CommandLine `"cmd.exe" /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber`
- `C:\Windows\System32\reg.exe` with CommandLine `reg  query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber`

**Sysmon Process Access Events (EID 10):** PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating parent-child process relationships.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass commands) with no evidence of the actual reconnaissance commands.

All processes executed successfully with exit status 0x0, confirming the technique completed without errors.

## What This Dataset Does Not Contain

This dataset lacks the actual registry query results — we see the process execution but not the data retrieved. Sysmon registry events (EIDs 12-14) are absent, likely due to the sysmon-modular configuration not monitoring HKLM\SOFTWARE registry modifications or reads by default.

The dataset doesn't capture any network communications, file writes containing system information, or subsequent actions based on the discovered OS build number. Additionally, there are no PowerShell script block logs showing the actual commands executed, suggesting the test used direct process invocation rather than PowerShell script execution.

## Assessment

This dataset provides excellent telemetry for detecting system information discovery attempts through its comprehensive process execution logging. The combination of Security 4688 events with full command lines and Sysmon EID 1 process creation events creates robust detection opportunities.

The data quality is strong for process-based detection but limited for understanding the technique's complete impact. The absence of registry access events reduces visibility into what specific information was accessed, but the command-line evidence clearly indicates reconnaissance intent.

For detection engineering, this represents a realistic scenario where defenders must rely on process execution patterns rather than data access logs, which is common in many enterprise environments.

## Detection Opportunities Present in This Data

1. **Registry Query Command Lines**: Direct detection of `reg query` commands targeting system version registry keys like "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

2. **PowerShell-to-CMD Process Chain**: Unusual process relationship where PowerShell spawns cmd.exe for registry operations, indicating potential evasion or scripted reconnaissance

3. **System Information Registry Paths**: Monitor for access to specific registry paths commonly used for system discovery: CurrentVersion, CurrentBuildNumber, ProductName

4. **Whoami Process Execution**: Detection of whoami.exe execution, especially when part of a broader reconnaissance pattern with registry queries

5. **Process Access Patterns**: PowerShell processes accessing child processes with full rights (0x1FFFFF) immediately after creation, suggesting automated process management

6. **Reconnaissance Command Clustering**: Temporal correlation of multiple system discovery commands (whoami + registry queries) within short time windows

7. **Living-off-the-Land Binary Usage**: Detection of legitimate Windows binaries (reg.exe, whoami.exe) used for reconnaissance activities based on command-line arguments and parent process context
