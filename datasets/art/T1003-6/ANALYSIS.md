# T1003-6: OS Credential Dumping — Dump Credential Manager using keymgr.dll and rundll32.exe

## Technique Context

T1003.006 (DCSync) is commonly misidentified here - this dataset actually demonstrates credential manager access through the Windows Key Manager (keymgr.dll) using rundll32.exe. This technique allows attackers to interact with stored Windows credentials through the Credential Manager GUI or programmatically access credential vaults. The detection community focuses on rundll32.exe execution patterns with keymgr.dll, process creation chains from suspicious parent processes, and attempts to access credential storage mechanisms. Unlike memory dumping techniques that target LSASS, this approach leverages legitimate Windows credential management interfaces, making it particularly evasive when executed in environments where rundll32.exe usage is common.

## What This Dataset Contains

The dataset captures a complete execution chain starting with PowerShell launching rundll32.exe with the keymgr.dll KRShowKeyMgr export. The key evidence includes:

- **Process Creation Chain**: Security event 4688 shows `powershell.exe` (PID 5656) executing `"C:\Windows\system32\rundll32.exe" keymgr,KRShowKeyMgr`
- **Sysmon Process Creation**: Event 1 captures the same rundll32.exe execution with full command line `"C:\Windows\system32\rundll32.exe" keymgr,KRShowKeyMgr` and parent process details
- **PowerShell Script Block**: Event 4104 records the actual command `& {rundll32.exe keymgr,KRShowKeyMgr}` being executed
- **Process Access Events**: Multiple Sysmon event 10s show PowerShell accessing child processes with full access rights (0x1FFFFF)
- **DLL Loading**: Extensive Sysmon event 7 coverage of PowerShell loading .NET runtime components and Windows Defender hooks
- **Parent-Child Relationships**: Clear process ancestry from initial PowerShell (PID 6520) → child PowerShell (PID 5656) → rundll32.exe (PID 936)

## What This Dataset Does Not Contain

The dataset lacks several critical elements that would normally accompany credential access attempts:

- **No credential enumeration results** - The rundll32.exe process terminates without producing output or creating credential dumps
- **Missing registry access events** - No evidence of credential vault registry key access that typically accompanies credential manager operations
- **No file system artifacts** - No credential files, exports, or temporary artifacts created during execution
- **Limited network activity** - Only routine DNS queries for domain controller communication, no credential transmission
- **No Windows Security events** for credential access - Missing 4648 (explicit credential use) or credential-related audit events that might indicate successful credential retrieval

The technique appears to execute successfully from a process creation perspective but may have failed to interact meaningfully with stored credentials or was blocked by security controls.

## Assessment

This dataset provides excellent telemetry for detecting the initial execution phase of keymgr.dll-based credential access attempts. The Security 4688 events with command-line logging and Sysmon process creation events offer comprehensive visibility into the attack technique's signature - rundll32.exe executing with keymgr,KRShowKeyMgr parameters. The PowerShell script block logging captures the exact command syntax, making it valuable for developing content-based detections. However, the dataset's utility is limited for understanding post-execution behaviors or successful credential extraction, as the technique appears to complete without generating credential-related artifacts or access events.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with keymgr.dll execution** - Monitor Security 4688 and Sysmon 1 events for command lines matching `rundll32.exe keymgr,KRShowKeyMgr` pattern
2. **PowerShell to rundll32.exe process chain** - Detect PowerShell parent processes spawning rundll32.exe with credential-related DLL parameters
3. **PowerShell script block analysis** - Alert on script blocks containing `keymgr` and `KRShowKeyMgr` function calls in event 4104
4. **Process access with full rights** - Monitor Sysmon event 10 for PowerShell processes accessing rundll32.exe with 0x1FFFFF permissions
5. **Suspicious rundll32.exe parameter patterns** - Create signatures for rundll32.exe executions targeting Windows credential management exports
6. **Parent process context analysis** - Flag rundll32.exe executions with keymgr parameters when parent is PowerShell or other scripting engines
