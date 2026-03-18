# T1036-2: Masquerading — Malware Masquerading and Execution from Zip File

## Technique Context

T1036 Masquerading is a defense evasion technique where adversaries disguise their malicious files, processes, or activities to appear benign or legitimate. The T1036.002 sub-technique specifically focuses on masquerading through right-to-left override (RTLO) characters and other filename manipulation techniques to deceive users about a file's true nature. However, this particular Atomic Red Team test attempts to simulate malware distribution via ZIP archives, a common delivery mechanism where malicious executables are disguised with seemingly harmless names like "README.cmd".

Detection engineers focus on monitoring for suspicious file executions from temporary directories, ZIP extraction activities, and processes spawned from recently extracted files. The community emphasizes detecting unusual parent-child process relationships, especially when legitimate-looking files execute from user download directories or temporary extraction paths.

## What This Dataset Contains

This dataset captures a failed attempt to execute the T1036.002 test. The key events show:

**Process Execution Chain:**
- Initial PowerShell process (PID 7212) executing with command line `powershell.exe`
- Spawned PowerShell child process (PID 3848) with the full test command: `"powershell.exe" & {Expand-Archive -Path \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1036.zip\" -DestinationPath \"$env:userprofile\Downloads\T1036\" -Force`
- CMD process (PID 7392) attempting to execute: `"C:\Windows\system32\cmd.exe" /c C:\Windows\system32\config\systemprofile\Downloads\T1036\README.cmd`

**PowerShell Script Block Activity:**
The PowerShell channel shows the actual test script attempting to:
1. Expand a ZIP archive from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1036.zip`
2. Extract contents to `$env:userprofile\Downloads\T1036`
3. Execute `README.cmd` from the extraction directory

**Error Conditions:**
PowerShell error events (EID 4100) reveal the test failed because `C:\AtomicRedTeam\ExternalPayloads\T1036.zip` does not exist, generating "PathNotFound" errors.

**File System Activity:**
Sysmon EID 11 events show the creation of the target directory `C:\Windows\System32\config\systemprofile\Downloads\T1036`, indicating the extraction attempt partially succeeded before failing on the missing ZIP file.

## What This Dataset Does Not Contain

The dataset lacks the core technique evidence because the test failed early:

- **No ZIP file extraction artifacts** - The source ZIP file was missing, so no malicious files were actually extracted
- **No masqueraded file execution** - Since extraction failed, the supposedly benign "README.cmd" (which would contain malicious commands) never executed successfully
- **No technique-specific telemetry** - Missing the deceptive filename patterns, RTLO characters, or other masquerading indicators that T1036.002 should demonstrate
- **Limited file system evidence** - Only directory creation is captured, not the typical file writes from ZIP extraction
- **No network activity** - Sysmon network events are absent, suggesting no subsequent malicious communication occurred

The CMD process (PID 7392) shows exit status 0x1, confirming execution failure when it attempted to run the non-existent README.cmd file.

## Assessment

This dataset provides limited value for T1036.002 detection engineering due to the test failure. While it demonstrates the process execution patterns and PowerShell command structures used in ZIP-based malware delivery, it lacks the actual masquerading artifacts that make this technique dangerous. The telemetry is more useful for understanding failed attack attempts and the defensive value of missing attack prerequisites.

The Security channel's process creation events (EID 4688) with full command lines and Sysmon's process creation events (EID 1) provide good coverage of the execution chain, but without successful file extraction and masqueraded execution, the technique-specific detection opportunities are minimal.

## Detection Opportunities Present in This Data

1. **PowerShell ZIP Extraction Commands** - Monitor Security EID 4688 and Sysmon EID 1 for PowerShell processes with "Expand-Archive" cmdlets extracting to user directories

2. **Suspicious Directory Creation Patterns** - Alert on Sysmon EID 11 file creation events for new directories in user Downloads folders, especially with generic names like "T1036"

3. **Failed Malware Execution Attempts** - PowerShell EID 4100 error events indicating missing external payloads can reveal attempted but unsuccessful attacks

4. **Process Chain Analysis** - Security EID 4688 events show PowerShell spawning CMD to execute extracted files, a common pattern in ZIP-delivered malware

5. **Archive Extraction to Temporary Locations** - PowerShell script blocks (EID 4104) containing Expand-Archive commands targeting user-writable directories warrant investigation

6. **CMD Execution from Downloads Directories** - Sysmon EID 1 showing cmd.exe processes executing files from recently created download subdirectories

7. **PowerShell Module Loading for Archive Operations** - PowerShell EID 4103 CommandInvocation events for "Expand-Archive" operations, especially when paired with subsequent CMD execution
