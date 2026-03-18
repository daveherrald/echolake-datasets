# T1036-1: Masquerading — System File Copied to Unusual Location

## Technique Context

T1036 Masquerading encompasses various methods adversaries use to manipulate file or process characteristics to evade defensive measures. The System File Copied to Unusual Location variant (T1036.001) specifically involves copying legitimate system binaries to non-standard locations where they may appear less suspicious or bypass application control mechanisms. Attackers commonly leverage this technique to execute trusted system binaries from user-writable directories, potentially evading security controls that rely on file path-based detection or allowlisting. The detection community focuses on monitoring file creation events for system binaries in unusual locations, process execution from non-standard paths, and command-line patterns that suggest file copying operations targeting system executables.

## What This Dataset Contains

This dataset captures a straightforward implementation of the technique where `cmd.exe` is copied from its legitimate location (`C:\Windows\System32\cmd.exe`) to an unusual directory (`C:\ProgramData\cmd.exe`) and then executed. The key evidence includes:

**PowerShell Script Block (EID 4104):** The complete attack sequence in a script block: `copy-item "$env:windir\System32\cmd.exe" -destination "$env:allusersprofile\cmd.exe"` followed by `start-process "$env:allusersprofile\cmd.exe"`.

**PowerShell Command Invocation (EID 4103):** Detailed cmdlet invocations showing `Copy-Item` with source `C:\Windows\System32\cmd.exe` and destination `C:\ProgramData\cmd.exe`, followed by `Start-Process` targeting the copied binary.

**Process Creation (Security EID 4688):** Shows the PowerShell process creating the copied cmd.exe at `C:\ProgramData\cmd.exe` with full command line visibility.

**File Creation (Sysmon EID 11):** Documents the actual file copy operation with `TargetFilename: C:\ProgramData\cmd.exe` created by the PowerShell process.

**File Executable Detection (Sysmon EID 29):** Captures the creation of the executable file with full hash information (SHA1, MD5, SHA256, IMPHASH) confirming it's an identical copy of the legitimate cmd.exe.

**Process Creation (Sysmon EID 1):** Shows the execution of the masqueraded binary with `Image: C:\ProgramData\cmd.exe` and the suspicious command line revealing its non-standard location.

## What This Dataset Does Not Contain

The dataset lacks certain behavioral artifacts that might be present in real-world scenarios. There are no registry modifications that might accompany more sophisticated masquerading attempts. Network connections from the masqueraded process are not captured, as this test simply copies and executes cmd.exe without additional network activity. The dataset also doesn't include file access patterns that might show the adversary reading or probing the system before selecting the target binary. Additionally, since this is a controlled test, it lacks the persistence mechanisms that attackers might implement alongside masquerading in actual campaigns.

## Assessment

This dataset provides excellent telemetry for detecting T1036.001 implementations. The combination of PowerShell logging (script blocks and command invocations), Security audit logs with command-line detail, and comprehensive Sysmon coverage creates multiple detection opportunities across different phases of the attack. The file creation events with hash information are particularly valuable for correlation and threat hunting. The process creation events clearly show the execution of a system binary from an unusual location, which is the core indicator for this technique. The data quality is high with minimal noise and clear attack artifacts.

## Detection Opportunities Present in This Data

1. **PowerShell Copy-Item cmdlet targeting system binaries** - Monitor EID 4103 for Copy-Item operations where the source path contains system directories and destination paths are in user-writable locations.

2. **File creation of known system executables in unusual locations** - Alert on Sysmon EID 11 where TargetFilename contains system binary names (cmd.exe, powershell.exe, etc.) but the path is outside standard system directories.

3. **Process execution from non-standard system binary locations** - Detect Sysmon EID 1 or Security EID 4688 where the Image/Process Name field contains system binary names but paths are in locations like ProgramData, Temp, or user directories.

4. **Hash-based correlation of copied system files** - Use Sysmon EID 29 hash values to identify when legitimate system binaries appear in unexpected locations with identical file hashes.

5. **PowerShell script block analysis for masquerading patterns** - Monitor EID 4104 for script blocks containing copy operations targeting system executables combined with execution attempts.

6. **Command-line pattern detection for system binary copying** - Analyze command lines in process creation events for patterns like copying from system32 to user-accessible directories followed by execution attempts.

7. **Parent-child process relationship anomalies** - Investigate cases where system binaries executed from unusual locations have unexpected parent processes, as shown in the ParentImage fields.
