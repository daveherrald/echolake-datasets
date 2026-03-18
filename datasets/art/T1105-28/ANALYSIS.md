# T1105-28: Ingress Tool Transfer — Nimgrab - Transfer Files

## Technique Context

T1105 Ingress Tool Transfer is a fundamental technique where adversaries move tools or files from external systems into a compromised environment. This is typically one of the first actions after initial access, as attackers need to bring in additional tooling for persistence, privilege escalation, or lateral movement. Common methods include using native OS utilities (curl, wget, PowerShell), custom downloaders, or legitimate cloud services.

The detection community focuses on unusual network connections to file hosting services, suspicious command-line arguments containing URLs, new file creations in temporary directories, and the execution of recently downloaded binaries. This technique is particularly important because it often represents the transition from initial compromise to more sophisticated attack phases.

## What This Dataset Contains

This dataset captures the execution of "nimgrab.exe", a file transfer utility written in the Nim programming language, attempting to download a file from GitHub. The key evidence includes:

**Process Chain**: The technique executes through a PowerShell → cmd → cmd → nimgrab.exe process chain, visible in Security events 4688 with command lines:
- `"cmd.exe" /c cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\nimgrab.exe" https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt $env:TEMP\Atomic-license.txt`
- `cmd  /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\nimgrab.exe" https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt $env:TEMP\Atomic-license.txt`

**Sysmon Coverage**: Sysmon events capture the cmd.exe process creations (EID 1) with full command-line visibility, showing the nimgrab.exe execution with source URL and destination path. However, notably absent is a Sysmon ProcessCreate event for nimgrab.exe itself, indicating it's not in the sysmon-modular include list for suspicious processes.

**Execution Failure**: Both cmd.exe processes exit with status 0x1 (failure), suggesting the download attempt was unsuccessful, likely blocked by Windows Defender or due to missing dependencies.

**PowerShell Activity**: Multiple PowerShell instances start up but the PowerShell event logs only contain standard test framework boilerplate (Set-ExecutionPolicy Bypass, Set-StrictMode) rather than the actual download commands.

## What This Dataset Does Not Contain

**Successful File Transfer**: The technique appears to fail - no network connections are captured, no downloaded files are created, and the exit codes indicate failure. This means we don't see the complete ingress tool transfer behavior.

**Nimgrab.exe Process Execution**: While the command line shows nimgrab.exe being invoked, there's no Sysmon ProcessCreate event for it, suggesting either the process failed to start or the sysmon-modular configuration doesn't include Nim-based executables in its suspicious process patterns.

**Network Telemetry**: No Sysmon network connection events (EID 3) or DNS queries are present, indicating the network connection never established or was immediately blocked.

**File Creation Events**: No Sysmon FileCreate events show the target file being written to the temp directory, confirming the download didn't complete successfully.

## Assessment

This dataset provides moderate value for detection engineering, primarily showing the initial execution phases of an ingress tool transfer attempt rather than successful completion. The Security audit logs provide excellent visibility into the process chain and command-line arguments, which are crucial for detecting download attempts regardless of success. However, the lack of network activity and file creation limits its utility for understanding complete attack chains.

The dataset effectively demonstrates how endpoint protection can prevent tool transfer while still generating valuable detection telemetry. The cmd.exe wrapper pattern and external tool execution are well-documented, making this useful for developing detections around attempted ingress rather than successful transfers.

## Detection Opportunities Present in This Data

1. **Command-line based file download detection** - Monitor for cmd.exe or PowerShell processes with command lines containing URLs and file paths, particularly with external domains
2. **Unusual process ancestry** - Detect PowerShell spawning cmd.exe which then spawns another cmd.exe, especially with external executable paths
3. **External payload directory access** - Alert on processes accessing or executing files from paths containing "ExternalPayloads" or similar staging directories
4. **Uncommon download utilities** - Monitor for execution of non-standard download tools like nimgrab.exe or other custom transfer utilities
5. **GitHub raw content access** - Detect command lines referencing raw.githubusercontent.com or similar code repository direct file access URLs
6. **Process exit code analysis** - Correlate failed process exit codes (0x1) with download-related command lines to identify blocked transfer attempts
7. **Temp directory targeting** - Monitor for command lines specifying downloads to %TEMP% or other temporary locations commonly used for staging
