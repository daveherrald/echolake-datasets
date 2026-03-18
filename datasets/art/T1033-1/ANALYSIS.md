# T1033-1: System Owner/User Discovery — System Owner/User Discovery

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries enumerate local and remote users to understand the environment and identify high-value targets. This technique is critical in the early stages of attack chains as it helps adversaries understand privilege levels, identify administrative accounts, and plan lateral movement. Common approaches include using built-in Windows utilities like `whoami`, `net user`, `quser`, and WMI queries through `wmic useraccount`. The detection community focuses heavily on monitoring execution of these native discovery utilities, particularly when executed in rapid succession or through scripting environments like PowerShell and cmd.exe.

## What This Dataset Contains

This dataset captures a comprehensive System Owner/User Discovery execution via Atomic Red Team T1033-1. The technique executes through PowerShell, spawning a complex cmd.exe chain that runs multiple discovery commands in sequence. 

Key telemetry includes:

**Process execution chain:** PowerShell (PID 6864) → cmd.exe (PID 3448) with command line `"cmd.exe" /c cmd.exe /C whoami & wmic useraccount get /ALL & quser /SERVER:"localhost" & quser & qwinsta.exe /server:localhost & qwinsta.exe & for /F "tokens=1,2" %i in ('qwinsta /server:localhost ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > computers.txt & @FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt`

**Discovery utilities captured:**
- Security 4688 events show `whoami.exe` executions (PIDs 1684, 2000)
- `wmic.exe useraccount get /ALL` (PID 7752)
- `quser.exe` with `/SERVER:"localhost"` and standalone (PIDs 2584, 7948)
- `qwinsta.exe` with `/server:localhost` and standalone (PIDs 3056, 8184, 1504)
- `findstr.exe` filtering for "Active Disc" sessions (PID 248)

**Sysmon coverage:** EID 1 Process Create events capture the discovery utilities with full command lines, parent-child relationships showing the cmd.exe chain, and Sysmon rules tagging them with technique_id=T1033 (whoami, quser) and technique_id=T1057 (qwinsta). EID 10 Process Access events show PowerShell accessing spawned processes with full access rights (0x1FFFFF).

**PowerShell telemetry:** Contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script blocks captured.

## What This Dataset Does Not Contain

The dataset lacks several important elements for comprehensive detection coverage. Most notably absent are the actual command outputs - we see the discovery utilities executing but don't capture what user accounts, sessions, or system information they revealed. File creation events for the intermediate files `computers.txt` and `usernames.txt` are missing, though the complex for-loop logic suggests these files should have been created during execution. 

The Security log contains exit codes showing quser commands failed (exit status 0x1), indicating no interactive sessions were found, but we don't see the actual error messages. Additionally, some expected child processes may be missing from Sysmon due to the include-mode filtering that only captures processes matching known-suspicious patterns.

## Assessment

This dataset provides strong coverage for detecting T1033 System Owner/User Discovery through multiple complementary data sources. The Security 4688 events offer complete process execution visibility with full command lines, while Sysmon EID 1 events add rich metadata including hashes, parent-child relationships, and technique tagging. The combination captures both simple discovery commands (`whoami`) and complex chained operations involving multiple utilities.

The telemetry quality is high for building detections around process execution patterns, command-line analysis, and process relationship mapping. However, the lack of output capture and intermediate file operations limits its utility for understanding the technique's effectiveness and data exfiltration aspects. For detection engineering focused on identifying discovery behavior patterns, this dataset is excellent. For understanding the complete attack narrative and data gathered, additional telemetry sources would strengthen the analysis.

## Detection Opportunities Present in This Data

1. **Multiple discovery utility execution in short time window** - Detect rapid succession of whoami.exe, wmic.exe, quser.exe, and qwinsta.exe executions within seconds, indicating systematic user enumeration

2. **PowerShell spawning Windows discovery utilities** - Monitor PowerShell parent processes creating cmd.exe children that execute user discovery commands, particularly when command lines contain multiple chained discovery operations

3. **WMI user account enumeration** - Alert on `wmic useraccount get /ALL` command execution, especially when preceded or followed by other discovery utilities

4. **Complex cmd.exe command line patterns** - Detect cmd.exe processes with command lines containing multiple discovery utilities chained with `&` operators and complex for-loop logic for session enumeration

5. **Process access patterns from scripting engines** - Monitor PowerShell processes accessing multiple child processes with full access rights (0x1FFFFF), indicating potential process management for discovery operations

6. **Remote session enumeration attempts** - Detect quser and qwinsta executions with `/SERVER:` or `/server:` parameters attempting to enumerate sessions on localhost or remote systems

7. **Discovery utility process tree analysis** - Build detection logic around parent-child relationships where cmd.exe spawns multiple discovery utilities in succession, indicating scripted enumeration rather than interactive use

8. **Token privilege adjustments during discovery** - Correlate Security 4703 token privilege adjustment events with discovery utility execution, particularly when SYSTEM-level privileges are enabled during user enumeration
