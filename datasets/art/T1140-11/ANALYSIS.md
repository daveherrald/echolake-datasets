# T1140-11: Deobfuscate/Decode Files or Information — Expand CAB with expand.exe

## Technique Context

T1140 (Deobfuscate/Decode Files or Information) represents attackers' need to unpack, decode, or decompress malicious payloads that were obfuscated for defense evasion. While attackers commonly use custom packers or encoding schemes, legitimate system utilities like `expand.exe` can also serve this purpose. The `expand.exe` utility is a Windows built-in tool designed to decompress Microsoft Cabinet (.CAB) files and other compressed formats.

From a detection perspective, T1140 is significant because it often represents a critical transition point in an attack chain—the moment when previously hidden malicious content becomes active. Detection engineers focus on monitoring compression/decompression utilities, particularly when used in unusual contexts or with suspicious command-line patterns. The expand utility is particularly interesting because it's signed by Microsoft but can be leveraged for malicious purposes, making it a classic "Living off the Land" binary (LOLBin).

## What This Dataset Contains

This dataset captures a complete CAB file creation and extraction workflow using built-in Windows utilities. The Security channel shows the full process tree: PowerShell (PID 41140) spawns cmd.exe (PID 3116) with the command `"cmd.exe" /c mkdir "%TEMP%\art-expand-out" >nul 2>&1 & echo hello from atomic red team > "C:\AtomicRedTeam\atomics\T1140\src\art-expand-source.txt" & makecab "C:\AtomicRedTeam\atomics\T1140\src\art-expand-source.txt" "%TEMP%\art-expand-test.cab" & pushd "%TEMP%\art-expand-out" & expand "%TEMP%\art-expand-test.cab" -F:* . & popd`.

The key T1140-relevant events include:
- Sysmon EID 1 showing `expand.exe` execution: `expand "C:\Windows\TEMP\art-expand-test.cab" -F:* .` running from the temporary extraction directory
- Sysmon EID 1 showing the parent cmd.exe chain that creates the CAB file with makecab and then extracts it
- Sysmon EID 11 showing file creation events, including the temporary directory creation
- Security EID 4688 events providing full command-line visibility for both makecab.exe and expand.exe processes

The dataset shows makecab.exe exiting with status 0x1 and expand.exe exiting with status 0xFFFFFFFF, indicating the expand operation encountered an error (likely due to the test file structure).

## What This Dataset Does Not Contain

The dataset doesn't capture successful file extraction artifacts due to the expand.exe failure (exit code 0xFFFFFFFF). You won't see the decompressed payload files being written to disk or subsequent execution of extracted content. The sysmon-modular configuration didn't capture makecab.exe process creation in Sysmon (only in Security 4688), as makecab isn't included in the process creation include rules.

Missing are network connections that might occur if extracted files attempted to download additional payloads, and registry modifications that might result from executing decompressed malware. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode), not the actual test commands.

## Assessment

This dataset provides excellent coverage for detecting T1140 abuse via expand.exe. The Security channel's command-line logging captures the complete attack flow, while Sysmon provides process lineage and timing details. The combination of EID 4688 and Sysmon EID 1 gives defenders multiple detection opportunities for both the compression preparation (makecab) and decompression execution (expand).

The LOLBin usage is clearly visible through process creation events with command-line arguments. The dataset effectively demonstrates how legitimate system utilities can be chained together for attack purposes, making it valuable for developing behavioral detections that focus on process relationships and command patterns rather than just individual tool usage.

## Detection Opportunities Present in This Data

1. **expand.exe execution with CAB file arguments** - Monitor Sysmon EID 1 and Security EID 4688 for expand.exe with .cab file paths, especially from temporary directories or unusual locations

2. **expand.exe spawned from scripting engines** - Detect expand.exe created by PowerShell, cmd.exe, or other scripting hosts, particularly in rapid succession with file creation utilities

3. **CAB file creation followed by immediate extraction** - Correlate makecab.exe and expand.exe execution within short time windows, indicating potential payload staging and deployment

4. **Temporary directory staging patterns** - Monitor file creation events (Sysmon EID 11) for temporary directories created immediately before expand.exe execution

5. **Command-line chaining with compression utilities** - Detect complex command strings that combine mkdir, makecab, pushd, expand, and popd operations in single cmd.exe invocations

6. **Process access patterns during decompression** - Monitor Sysmon EID 10 events showing PowerShell or other processes accessing expand.exe during execution, which may indicate scripted automation

7. **Expand.exe execution from non-standard working directories** - Flag expand.exe running from user temp directories or other unusual current working directories
