# T1195-1: Supply Chain Compromise — Octopus Scanner Malware Open Source Supply Chain

## Technique Context

T1195 Supply Chain Compromise represents attacks where adversaries manipulate products or product delivery mechanisms prior to receipt by the final consumer. The Octopus Scanner malware variant specifically targets open source software supply chains by embedding malicious code into legitimate projects, often through compromised developer environments or malicious contributions. This technique is particularly concerning because it leverages the trust relationships inherent in software distribution channels, making detection challenging until the malicious payload executes on victim systems.

The detection community focuses on identifying anomalous file operations, suspicious scheduled tasks, and unusual network behaviors that may indicate compromised software packages executing their payloads. Key indicators include unexpected persistence mechanisms, file drops to unusual locations, and command-line patterns consistent with supply chain attack frameworks.

## What This Dataset Contains

This dataset captures the execution of a simulated Octopus Scanner attack that demonstrates typical supply chain compromise behaviors. The attack sequence shows:

**Process Creation Chain**: PowerShell (PID 12352) spawns `whoami.exe` for system reconnaissance, then executes `cmd.exe` with the command `"cmd.exe" /c copy %temp%\ExplorerSync.db %temp%\..\Microsoft\ExplorerSync.db & schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\..\Microsoft\ExplorerSync.db" /sc MINUTE /f`. The cmd.exe process subsequently launches `schtasks.exe` to create persistence.

**File Operations**: Sysmon EID 11 events show the creation of the scheduled task file `C:\Windows\System32\Tasks\ExplorerSync` by svchost.exe (PID 2316), indicating successful task registration.

**Registry Modifications**: Three Sysmon EID 13 events capture the Task Scheduler service writing registry values to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\ExplorerSync\` including Index, Security Descriptor, and Task ID ({99A278C4-C196-49C9-ACF2-99C20EF0E07C}).

**Scheduled Task Creation**: Task Scheduler EID 106 and 140 events confirm the registration and update of the "ExplorerSync" task, providing the task name that could be used for hunting.

**Process Access Events**: Sysmon EID 10 events show PowerShell accessing both whoami.exe and cmd.exe with full access (0x1FFFFF), typical of process monitoring or injection preparation.

## What This Dataset Does Not Contain

The dataset lacks several critical elements of a complete supply chain compromise:

**Initial Compromise Vector**: No evidence of the malicious file (`ExplorerSync.db`) being downloaded or installed, as this would typically occur through package managers, Git repositories, or other distribution mechanisms not captured in this test execution.

**Network Activity**: Missing DNS queries, HTTP requests, or other network connections that would typically accompany the download of the malicious package or subsequent command and control communications.

**File Content Analysis**: The actual malicious payload file operations are not captured, preventing analysis of the JAR file contents or its capabilities.

**Defender Blocking**: While Windows Defender was active, no blocking events are present, suggesting this particular payload was not detected or the simulation didn't include the actual malicious content.

## Assessment

This dataset provides strong telemetry for detecting the post-compromise behaviors of supply chain attacks, particularly the persistence establishment phase. The combination of process creation events with command-line arguments, registry modifications for scheduled tasks, and file system operations creates a comprehensive view of the attack's execution phase.

The Security 4688 events with full command-line logging are particularly valuable, capturing the exact schtasks command used for persistence. The Task Scheduler operational logs provide additional confirmation and hunting opportunities through task names and user context.

However, the dataset's utility for detecting the initial supply chain compromise is limited due to the absence of network telemetry and package installation events. The focus is primarily on the payload execution rather than the supply chain infiltration mechanism itself.

## Detection Opportunities Present in This Data

1. **Suspicious Scheduled Task Creation**: Monitor Task Scheduler EID 106/140 events for tasks with unusual names (like "ExplorerSync") or Java-based execution commands, especially when created by SYSTEM context processes.

2. **Schtasks Command Line Patterns**: Alert on Security 4688 events where schtasks.exe is executed with "/create" parameter and "/tr" containing "javaw -jar" with suspicious file paths or extensions like ".db".

3. **Registry Modifications for Persistence**: Track Sysmon EID 13 events writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` for new task registrations with non-standard task names.

4. **File Drops to Microsoft Directories**: Monitor Sysmon EID 11 for unexpected file creation in `C:\Windows\Microsoft\` subdirectories, particularly files with database extensions being used as executables.

5. **Process Chain Analysis**: Detect PowerShell spawning cmd.exe which then executes schtasks.exe, especially when the intermediate cmd.exe includes file copy operations to system directories.

6. **JAR File Execution via Scheduled Tasks**: Hunt for scheduled tasks configured to execute JAR files from unusual locations, particularly when the task name doesn't match typical Windows task naming conventions.

7. **System Profile File Operations**: Investigate Sysmon EID 11 events for PowerShell profile modifications or creations that might indicate persistence mechanism setup.
