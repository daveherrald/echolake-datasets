# T1059.001-10: PowerShell — PowerShell Fileless Script Execution

## Technique Context

T1059.001 PowerShell execution is a cornerstone technique for adversaries operating in Windows environments. This specific test demonstrates fileless script execution through registry-based storage and retrieval—a common evasion technique where PowerShell code is stored in the Windows registry as Base64-encoded data and executed in-memory without touching disk. The detection community focuses heavily on PowerShell monitoring because of its ubiquity in both legitimate administration and malicious activity. Key detection points include script block logging, process command lines, registry modifications, and parent-child process relationships.

## What This Dataset Contains

The dataset captures a PowerShell fileless execution sequence where the test stores Base64-encoded PowerShell in the registry and executes it using `Invoke-Expression`. Security event 4688 shows the critical command line: `powershell.exe" & {# Encoded payload in next command is the following \"Set-Content -path \"$env:SystemRoot/Temp/art-marker.txt\" -value \"Hello from the Atomic Red Team\"\"` followed by registry operations and Base64 decoding via `iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))`.

Sysmon captures process creation for both PowerShell instances (PIDs 25988 and 23384) and whoami.exe execution in event ID 1, along with .NET CLR loading events (ID 7) and process access events (ID 10) showing PowerShell accessing whoami.exe with full rights (0x1FFFFF). The CreateRemoteThread event (ID 8) indicates PowerShell injecting into an unknown target process at PID 25816.

However, the PowerShell script block logs (event ID 4104) only contain test framework boilerplate like `Set-StrictMode` commands rather than the actual malicious payload, suggesting the Base64-decoded content may have evaded script block logging or been filtered.

## What This Dataset Does Not Contain

The dataset shows process exit code 0xC0000022 (STATUS_ACCESS_DENIED) for the second PowerShell process, indicating Windows Defender blocked the technique before completion. This means we don't see successful file creation at `$env:SystemRoot/Temp/art-marker.txt` or registry modifications that would have persisted the Base64 payload. The PowerShell logs contain only error-handling scriptblocks and execution policy bypasses, not the actual malicious Base64-decoded content that would demonstrate the fileless execution.

Notably absent are Sysmon ProcessCreate events for reg.exe, which should have appeared given the command line shows registry modification attempts. This suggests the sysmon-modular config's include-mode filtering didn't capture reg.exe as a suspicious process, or Defender blocked it before execution.

## Assessment

This dataset provides good visibility into the attempt at PowerShell fileless execution, particularly through Security event command-line auditing which captured the full attack chain including Base64 payload storage and retrieval logic. The Sysmon process creation and image loading events show the PowerShell execution environment, while process access events reveal the technique's interaction with spawned processes. However, the lack of actual malicious script block content and the Defender blocking reduces its utility for understanding the complete attack execution. The dataset is valuable for detection engineering focused on command-line analysis and process behavior but limited for content-based PowerShell detection development.

## Detection Opportunities Present in This Data

1. **Command Line Base64 Patterns** - Security 4688 events contain `[Convert]::FromBase64String` and registry get-property (`gp`) operations in PowerShell command lines, indicating fileless execution attempts.

2. **Registry-Based PowerShell Execution** - The command line pattern `iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\')` represents a classic fileless PowerShell execution technique.

3. **PowerShell Parent-Child Relationships** - Multiple PowerShell processes spawning from each other (PID 25988 → 23384) combined with execution policy bypass attempts suggests malicious automation.

4. **Process Access with Full Rights** - Sysmon event ID 10 shows PowerShell accessing whoami.exe with 0x1FFFFF permissions, indicating potential process manipulation or monitoring behavior.

5. **CreateRemoteThread from PowerShell** - Sysmon event ID 8 captures PowerShell performing thread injection into unknown processes, a strong indicator of malicious activity.

6. **Execution Policy Bypass Sequences** - PowerShell event ID 4103 shows `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`, indicating attempts to circumvent security controls.

7. **PowerShell .NET CLR Loading** - Multiple Sysmon event ID 7 entries showing System.Management.Automation assembly loading can indicate PowerShell execution in non-standard contexts.

8. **Access Denied Exit Codes** - Security 4689 events with exit status 0xC0000022 from PowerShell processes indicate blocked malicious activity attempts.
