# T1070-2: Indicator Removal — Indicator Manipulation using FSUtil

## Technique Context

T1070 Indicator Removal encompasses various methods attackers use to delete or modify artifacts that could reveal their presence on a system. The FSUtil technique (T1070-2) specifically involves using Microsoft's built-in `fsutil.exe` utility to manipulate file system structures and metadata. Attackers commonly use `fsutil file setZeroData` to overwrite portions of files with null bytes, effectively sanitizing evidence while maintaining file structure and timestamps that might fool casual inspection.

The detection community focuses on monitoring FSUtil invocations, particularly the `setZeroData` subcommand which directly enables data destruction. This technique is attractive to attackers because FSUtil is a legitimate Windows administrative tool that may not trigger the same scrutiny as third-party file shredders. Detection engineers typically look for unusual FSUtil usage patterns, targeting of sensitive file locations, and correlation with other suspicious activities.

## What This Dataset Contains

This dataset captures a complete FSUtil-based file manipulation sequence. The core technique evidence appears in Security event 4688 showing the FSUtil execution: `"C:\Windows\system32\fsutil.exe" file setZeroData offset=0 length=10 C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1070-2.txt`. The command zeros out the first 10 bytes of the target file, demonstrating the sanitization capability.

Sysmon event 1 provides additional process creation telemetry for FSUtil with the same command line, tagged with the technique rule `technique_id=T1070,technique_name=Indicator Removal`. The parent process chain shows PowerShell (PID 17052) spawning FSUtil (PID 17320), with the parent PowerShell command line revealing the full attack sequence: file creation, content writing, and subsequent zeroing.

PowerShell script block logging captures the technique payload: `fsutil file setZeroData offset=0 length=10 "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1070-2.txt"` in event 4104. Multiple Sysmon process access events (EID 10) show PowerShell accessing both the whoami.exe and fsutil.exe processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks file system audit events that would show the actual modification of the target file's contents. Windows object access auditing was disabled (`object_access: none`), so we don't see Security events 4663 (file access) or 4658 (handle closure) that would provide direct evidence of the file manipulation. 

Notably absent are any Windows Defender alerts or blocking events, indicating the technique completed successfully without endpoint protection intervention. The zero exit codes (0x0) in Security events 4689 confirm successful process completion. There are no network artifacts since this is purely a local file manipulation technique.

Registry monitoring would not be relevant here as FSUtil operates directly on file system structures without requiring registry modifications. The technique also doesn't generate any authentication or privilege escalation events beyond the routine privilege adjustments captured in Security event 4703.

## Assessment

This dataset provides solid process-level detection opportunities for FSUtil-based indicator removal. The combination of Security 4688 and Sysmon 1 events with full command-line visibility makes the technique easily detectable through process monitoring. The PowerShell script block logging adds valuable context about the attack flow.

However, the dataset's utility for comprehensive detection is limited by the lack of file system auditing. Without object access events, defenders cannot definitively prove that file contents were actually modified, only that the attempt was made. This gap is significant because FSUtil commands can fail silently due to file locks, permissions, or other factors.

The process telemetry quality is excellent, with complete parent-child relationships, full command lines, and accurate timing information. The Sysmon rule tagging correctly identifies the technique, demonstrating how behavioral analytics can flag this activity automatically.

## Detection Opportunities Present in This Data

1. **FSUtil Process Creation with setZeroData Command** - Monitor Security 4688 and Sysmon 1 for `fsutil.exe` executions containing `setZeroData` parameters, particularly with suspicious file paths or parent processes.

2. **PowerShell Script Block Analysis** - Alert on PowerShell script blocks containing `fsutil` and `setZeroData` combinations in Security event 4104, indicating scripted file manipulation attempts.

3. **Parent Process Correlation** - Flag FSUtil executions spawned by scripting engines (PowerShell, cmd.exe, wscript.exe) rather than legitimate administrative tools or interactive sessions.

4. **Privilege Usage Patterns** - Correlate FSUtil execution with Security event 4703 privilege adjustments, particularly SeBackupPrivilege or SeRestorePrivilege which FSUtil operations may require.

5. **Process Access Monitoring** - Use Sysmon EID 10 to detect when scripting processes access FSUtil with full rights (0x1FFFFF), indicating programmatic control rather than user interaction.

6. **Command Line Parameter Analysis** - Parse FSUtil command lines for specific offset/length combinations that suggest data destruction rather than legitimate disk management operations.

7. **File Path Targeting** - Monitor FSUtil operations against non-system directories, temporary locations, or paths containing security tool names that suggest evidence destruction.
