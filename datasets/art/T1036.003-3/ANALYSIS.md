# T1036.003-3: Rename Legitimate Utilities — Masquerading - cscript.exe running as notepad.exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where adversaries rename legitimate system binaries to avoid detection by security tools that rely on process names or file paths. This specific test demonstrates renaming `cscript.exe` (Windows Script Host) to `notepad.exe` - a common masquerading pattern where potentially suspicious utilities are renamed to appear as benign applications.

The detection community focuses on several key indicators: processes running from unusual locations, file hash mismatches between expected and actual binaries, OriginalFileName fields in PE headers that don't match the actual filename, and execution of renamed LOLBins (Living Off the Land Binaries). This technique is particularly concerning because it can bypass naive detection rules that only examine process names without validating file integrity or execution context.

## What This Dataset Contains

This dataset captures a successful masquerading execution with excellent telemetry across all data sources. The attack chain begins with PowerShell executing the command `"cmd.exe" /c copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y & cmd.exe /c %APPDATA%\notepad.exe /B` as seen in Security 4688 events.

Key telemetry includes the file copy operation captured in Sysmon 11 showing `TargetFilename: C:\Windows\System32\config\systemprofile\AppData\Roaming\notepad.exe`. The critical masquerading evidence appears in Sysmon 1 for PID 476: `Image: C:\Windows\System32\config\systemprofile\AppData\Roaming\notepad.exe` with `OriginalFileName: cscript.exe` and `Description: Microsoft ® Console Based Script Host`. The process hashes (`SHA256=8757B91A13573C2C415BADEF211698D35624195DDFE6E197CB90583D7675C4BD`) match legitimate cscript.exe despite the notepad.exe filename.

Sysmon 7 ImageLoad events show the renamed binary loading itself, and the RuleName fields indicate proper MITRE technique tagging (`technique_id=T1202,technique_name=Indirect Command Execution` and `technique_id=T1574.002,technique_name=DLL Side-Loading`).

## What This Dataset Does Not Contain

The dataset doesn't capture any script execution by the renamed cscript.exe because it was launched with the `/B` (batch mode suppression) flag, causing it to exit with status 0x1 due to missing script arguments. No Windows Script Host runtime events, script parsing, or JScript/VBScript execution artifacts are present.

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without any malicious PowerShell content. Since the technique relies on simple file operations and process execution, there are no network connections, registry modifications, or advanced evasion artifacts beyond the core masquerading behavior.

## Assessment

This dataset provides excellent detection engineering value for T1036.003 with high-fidelity telemetry across multiple data sources. The Sysmon ProcessCreate events contain the critical OriginalFileName field that definitively identifies masquerading attempts, while Security 4688 events provide complementary process creation coverage with full command lines.

The file creation telemetry in Sysmon 11 enables detection of the preparation phase, and the process execution chain is clearly documented. The technique executed successfully without Windows Defender interference, providing clean telemetry of the complete attack sequence. The only limitation is the lack of actual malicious payload execution, but this doesn't diminish the dataset's value for detecting the masquerading technique itself.

## Detection Opportunities Present in This Data

1. **OriginalFileName Mismatch Detection** - Sysmon 1 events where Image filename doesn't match OriginalFileName field (notepad.exe vs cscript.exe)

2. **Suspicious File Copy to User Directories** - Sysmon 11 file creation of executable files in %APPDATA% with system binary names

3. **Renamed LOLBin Execution** - Process creation from user-writable directories with hashes matching known system binaries

4. **Command Line Pattern Detection** - Security 4688 events showing copy operations of system32 executables to user directories

5. **Process Chain Anomalies** - cmd.exe spawning processes with misleading names from unexpected locations

6. **Hash-Based Validation** - File hash verification against known good system binary hashes for processes claiming to be notepad.exe

7. **Execution Location Baseline Deviation** - Legitimate notepad.exe should execute from System32, not from user profile directories
