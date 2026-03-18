# T1036.003-7: Rename Legitimate Utilities — Masquerading - windows exe running as different windows exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where attackers rename legitimate executables to masquerade as other processes, often mimicking system or benign processes to avoid detection. This technique is commonly used to make malicious or suspicious processes appear legitimate by copying and renaming utilities like cmd.exe, powershell.exe, or other Windows binaries to names that might blend in with normal system processes.

The detection community focuses on several key indicators: process/file hash mismatches (where the process name doesn't match the expected hash for that binary), original filename metadata discrepancies, and unusual process execution paths. This test specifically demonstrates copying cmd.exe to svchost.exe, creating a hash/filename mismatch that should trigger detection logic.

## What This Dataset Contains

This dataset captures a complete execution of the masquerading technique with excellent telemetry coverage:

**Process Chain**: The attack begins with PowerShell executing: `copy "$env:ComSpec" ($env:TEMP + "\svchost.exe")` followed by `Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")` and `Stop-Process -ID $myT1036_003`.

**File Operations**: Sysmon EID 11 shows file creation at `C:\Windows\Temp\svchost.exe` and EID 29 captures the file executable detection with hashes `SHA1=94BDAEB55589339BAED714F681B4690109EBF7FE` and `SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`.

**Process Execution**: Security 4688 and Sysmon EID 1 both capture the masqueraded process execution as `C:\Windows\Temp\svchost.exe` with `OriginalFileName: Cmd.Exe` and `Description: Windows Command Processor`, clearly showing the mismatch.

**PowerShell Telemetry**: Module logging (EID 4103) captures the Copy-Item, Start-Process, and Stop-Process cmdlet invocations with full parameter details, including the source path `C:\Windows\system32\cmd.exe` and destination `C:\Windows\TEMP\svchost.exe`.

## What This Dataset Does Not Contain

The dataset is quite complete for this technique. The masqueraded process runs briefly before being terminated by the Stop-Process command, so there's limited runtime activity from the renamed executable itself. No network connections are initiated by the masqueraded process, and no registry modifications occur. The technique completes successfully without any Windows Defender blocks, providing clean "success" telemetry rather than "attempt" telemetry.

## Assessment

This dataset provides excellent detection engineering value for T1036.003. The combination of file creation events with full hashes, process creation with original filename metadata, and detailed PowerShell command logging creates multiple high-fidelity detection opportunities. The presence of both Security and Sysmon process creation events offers redundancy, while the PowerShell module logging provides command-line context that would be valuable for incident response. The hash values captured in multiple events enable reliable correlation and validation of the technique execution.

## Detection Opportunities Present in This Data

1. **Hash/Filename Mismatch Detection**: Alert on processes where the executable path/name doesn't match the expected hash for that binary (svchost.exe with cmd.exe hashes)

2. **OriginalFileName Metadata Mismatch**: Detect processes where OriginalFileName field differs from the actual process image path (Cmd.Exe running as svchost.exe)

3. **Suspicious File Copy to System Process Names**: Monitor for file copies of legitimate utilities to common system process names in temp directories

4. **PowerShell Copy-Item to Process Names**: Alert on PowerShell Copy-Item cmdlets copying from system directories to temp locations with executable extensions

5. **Process Creation from Temp with System Process Names**: Flag process execution from temp directories using names commonly associated with system processes

6. **Sysmon File Executable Detection Anomalies**: Correlate EID 29 executable file creation events with known good hashes to identify renamed binaries

7. **Short-Lived Masqueraded Processes**: Detect processes that are created and immediately terminated, particularly when the creation involves file copying operations
