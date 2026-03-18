# T1218.001-8: Compiled HTML File — Decompile Local CHM File

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers abuse the Microsoft HTML Help executable (hh.exe) to proxy execution of malicious code. While most defensive focus centers on hh.exe executing malicious JavaScript or VBScript within CHM files, this particular test demonstrates the decompilation functionality where hh.exe extracts content from a CHM file to disk. Attackers can use this to bypass file restrictions by embedding payloads inside CHM files and extracting them to accessible locations. The technique leverages a signed Microsoft binary to perform file operations, making it appear legitimate to security tools that focus on process reputation.

## What This Dataset Contains

This dataset captures a successful CHM decompilation operation executed through PowerShell. The key evidence appears in Security event 4688 showing the process chain: `powershell.exe` → `cmd.exe /c hh.exe -decompile %temp% "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"` → `hh.exe -decompile C:\Windows\TEMP "C:\AtomicRedTeam\atomics\T1218.001\src\T1218.001.chm"`. 

Sysmon provides complementary process creation events (EID 1) with the same command lines, plus process GUID tracking showing the execution flow. Notably, Sysmon event 1 for hh.exe includes the RuleName "technique_id=T1218.001,technique_name=Compiled HTML File", indicating the sysmon-modular configuration specifically detects this technique. The dataset also contains Sysmon process access events (EID 10) where PowerShell accesses both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), and image load events (EID 7) showing DLL loading activity.

## What This Dataset Does Not Contain

The dataset lacks file system evidence of the actual decompilation results. There are no Sysmon file creation events (EID 11) showing extracted files in C:\Windows\TEMP, suggesting either the CHM file was empty/malformed, the decompilation failed, or the extracted files were immediately cleaned up. Additionally, there's no evidence of any malicious payload execution that might have occurred post-decompilation. The PowerShell events contain only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content.

## Assessment

This dataset provides excellent process-level telemetry for detecting CHM decompilation attacks. The Security 4688 events with command-line logging capture the complete attack chain with clear indicators (hh.exe with -decompile parameter). The Sysmon process creation events add valuable context like file hashes, parent-child relationships, and rule-based detection tags. However, the dataset's value is limited by the absence of file system artifacts showing the decompilation output, which would be crucial for understanding the attack's impact and building comprehensive detection coverage.

## Detection Opportunities Present in This Data

1. **Process creation monitoring** for hh.exe with -decompile parameter in command line (Security EID 4688, Sysmon EID 1)

2. **Parent process analysis** detecting hh.exe spawned from unexpected parents like cmd.exe or PowerShell rather than user applications (Sysmon EID 1 ParentImage fields)

3. **Command line pattern matching** for hh.exe combined with -decompile and file paths pointing to CHM files (Security EID 4688 command line field)

4. **Process chain analysis** identifying suspicious multi-stage execution: PowerShell → cmd.exe → hh.exe with file manipulation parameters

5. **Sysmon rule-based alerting** leveraging the built-in technique detection that tagged this activity as T1218.001 in the RuleName field

6. **Process access monitoring** for unusual cross-process access patterns where PowerShell accesses cmd.exe with full privileges during CHM operations (Sysmon EID 10)
