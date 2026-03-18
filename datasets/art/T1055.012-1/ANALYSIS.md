# T1055.012-1: Process Hollowing — Process Hollowing using PowerShell

## Technique Context

Process hollowing (T1055.012) is an advanced process injection technique where attackers create a legitimate process in a suspended state, replace its memory image with malicious code, then resume execution. This allows malicious code to execute within the context of a trusted process, evading process-based detections. The technique is commonly used by sophisticated malware and APT groups to blend malicious activity with legitimate system processes.

Detection engineering typically focuses on API call patterns (CreateProcess with CREATE_SUSPENDED, NtUnmapViewOfSection, WriteProcessMemory), memory manipulation indicators, and parent-child process relationships that don't align with normal system behavior. PowerShell-based implementations are particularly concerning as they combine living-off-the-land tactics with memory manipulation capabilities.

## What This Dataset Contains

This dataset captures a PowerShell-based process hollowing attempt using Atomic Red Team's implementation. The key evidence includes:

**PowerShell Script Block (EID 4104):** The actual command execution is visible: `Start-Hollow -Sponsor "C:\Windows\System32\notepad.exe" -Hollow "C:\Windows\System32\cmd.exe" -ParentPID $ppid -Verbose` showing an attempt to hollow notepad.exe and inject cmd.exe.

**Process Creation Chain (Security EID 4688 & Sysmon EID 1):** Multiple PowerShell processes spawn with the full command line: `"powershell.exe" & {. \"C:\AtomicRedTeam\atomics\T1055.012\src\Start-Hollow.ps1\"...}` executed by Process ID 30360.

**Process Access Events (Sysmon EID 10):** Two critical process access events show PowerShell (PID 30360) accessing whoami.exe (PID 25732) and another PowerShell process (PID 29984) with full access rights (0x1FFFFF), indicating memory manipulation attempts.

**Image Load Events (Sysmon EID 7):** Extensive .NET runtime loading across multiple PowerShell processes, including mscoree.dll, clr.dll, and System.Management.Automation.dll, consistent with PowerShell-based injection techniques.

**Privilege Escalation (Security EID 4703):** Token right adjustment showing elevation of multiple high-value privileges including SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, and SeBackupPrivilege.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful process hollowing completion. Notably absent are:

- **No CreateProcess events with CREATE_SUSPENDED flag** - The Sysmon config's include-mode filtering may not capture notepad.exe creation if it doesn't match suspicious patterns
- **No NtUnmapViewOfSection or WriteProcessMemory indicators** - These low-level API calls aren't captured in standard Windows event logs
- **No evidence of notepad.exe process creation** - The intended "sponsor" process doesn't appear in the telemetry
- **No network connections or file system artifacts** from the injected cmd.exe payload

This suggests either the technique failed, was blocked by Windows Defender, or the most critical process creation events weren't captured due to Sysmon filtering.

## Assessment

This dataset provides excellent visibility into PowerShell-based process injection attempts through script block logging and process access patterns. The Security and PowerShell channels capture the attack initiation and suspicious process relationships effectively. However, the lack of the target process creation limits understanding of technique success/failure.

The Sysmon EID 10 events are particularly valuable, showing clear process access patterns that indicate injection attempts. The privilege elevation telemetry in Security EID 4703 provides additional context for detection logic. The dataset effectively demonstrates detection opportunities for PowerShell-based injection, even when the technique may not complete successfully.

## Detection Opportunities Present in This Data

1. **PowerShell script block analysis** - Monitor EID 4104 for terms like "Start-Hollow", "Sponsor", "Hollow", or Win32 API references related to process manipulation

2. **Process access anomalies** - Alert on Sysmon EID 10 where PowerShell processes access non-child processes with full access rights (0x1FFFFF), especially targeting system binaries

3. **Suspicious PowerShell command lines** - Detect Security EID 4688 with command lines containing Base64, encoded commands, or references to injection-related PowerShell modules

4. **Parent-child process relationship violations** - Flag PowerShell processes accessing unrelated processes, particularly when the access includes memory manipulation rights

5. **Privilege escalation correlation** - Combine Security EID 4703 privilege adjustments (especially SeAssignPrimaryTokenPrivilege) with concurrent PowerShell activity for high-confidence alerts

6. **Multiple PowerShell process spawning** - Detect rapid creation of multiple PowerShell processes from a single parent, indicating potential injection framework execution

7. **PowerShell .NET assembly loading patterns** - Monitor Sysmon EID 7 for rapid loading of process injection-related DLLs (clr.dll, clrjit.dll) within PowerShell processes
