# T1140-2: Deobfuscate/Decode Files or Information — Certutil Rename and Decode

## Technique Context

T1140 (Deobfuscate/Decode Files or Information) is a defense evasion technique where attackers decode or deobfuscate files that were previously encoded to evade detection. This is particularly common in multi-stage attacks where initial payloads are obfuscated during delivery and then decoded on the target system for execution.

Certutil.exe is a Windows built-in utility that has become notorious in the detection community for its dual-use nature. While legitimately used for certificate management, attackers frequently abuse its `-encode` and `-decode` capabilities for base64 encoding/decoding operations. The technique demonstrated here adds an extra layer of evasion by first copying certutil.exe to an alternate filename (`tcm.tmp`), making detection rules that rely on process name matching less effective.

The detection community focuses heavily on monitoring certutil usage with encoding parameters, renamed binary executions, and the creation of encoded/decoded files in temporary directories. This technique is commonly seen in ransomware campaigns and living-off-the-land attack scenarios.

## What This Dataset Contains

This dataset captures a complete certutil rename-and-decode operation executed through PowerShell. The key telemetry includes:

**Process Chain:** PowerShell → cmd.exe → tcm.tmp (renamed certutil) executions for both encode and decode operations. Security event 4688 shows the full command line: `"cmd.exe" /c copy %windir%\system32\certutil.exe %temp%\tcm.tmp & %temp%\tcm.tmp -encode C:\Windows\System32\calc.exe %temp%\T1140_calc2.txt & %temp%\tcm.tmp -decode %temp%\T1140_calc2.txt %temp%\T1140_calc2_decoded.exe`

**Sysmon Process Creation:** EID 1 events capture the renamed certutil executions with process GUIDs {9dc7570a-7c91-69b4-6459-000000001000} and {9dc7570a-7c91-69b4-6559-000000001000}, showing command lines `C:\Windows\TEMP\tcm.tmp -encode C:\Windows\System32\calc.exe C:\Windows\TEMP\T1140_calc2.txt` and `C:\Windows\TEMP\tcm.tmp -decode C:\Windows\TEMP\T1140_calc2.txt C:\Windows\TEMP\T1140_calc2_decoded.exe`.

**File Operations:** Sysmon EID 11 events show the creation of `C:\Windows\Temp\tcm.tmp` (the renamed certutil), `C:\Windows\Temp\T1140_calc2.txt` (base64-encoded calc.exe), and `C:\Windows\Temp\T1140_calc2_decoded.exe` (the final decoded executable).

**Image Load Events:** EID 7 shows the renamed binary loading itself as an image, with the OriginalFileName field still showing "CertUtil.exe" despite the renamed execution path.

## What This Dataset Does Not Contain

**Registry Activity:** No registry modifications are captured since certutil's encoding operations don't require registry changes.

**Network Activity:** This test operates entirely locally with no network connections, so no DNS queries or network connections are present.

**File Content Analysis:** While we can see the files being created, the actual base64 content of the encoded file isn't captured in the event logs.

**Process Hollowing or Advanced Injection:** This is a straightforward file decode operation without additional process manipulation techniques.

**PowerShell Script Content:** The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual attack commands, which were likely executed through direct command invocation rather than script blocks.

## Assessment

This dataset provides excellent coverage for detecting certutil abuse through renamed binaries. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 process creation events gives detection engineers multiple high-fidelity opportunities to identify this technique. The file creation events (Sysmon EID 11) add valuable context about the artifacts being created.

The data quality is strong because certutil operations are inherently noisy—they create processes, files, and leave clear command-line evidence. The renamed binary approach actually makes detection more reliable in some ways, as the OriginalFileName field in Sysmon EID 7 still reveals the true identity of the executable regardless of the filename.

What makes this dataset particularly valuable is that it demonstrates both the evasion attempt (renaming) and the core technique (encoding/decoding) in a single execution, showing how attackers chain these techniques together.

## Detection Opportunities Present in This Data

1. **Renamed Certutil Execution** - Monitor Sysmon EID 1 and Security 4688 for processes where the OriginalFileName is "CertUtil.exe" but the Image path doesn't contain "certutil", indicating binary renaming.

2. **Certutil Encoding Parameters** - Detect command lines containing `-encode` or `-decode` parameters, especially when executed from temporary directories or with non-standard filenames.

3. **Copy-to-Temp-and-Execute Pattern** - Alert on cmd.exe command lines that copy system binaries to %temp% and immediately execute them, particularly with chained commands using `&` operators.

4. **Base64 File Creation in Temp** - Monitor Sysmon EID 11 for file creation events in temporary directories, especially files with extensions like .txt that may contain encoded data followed by .exe file creation.

5. **Process Chain Analysis** - Correlate PowerShell → cmd.exe → renamed binary execution chains, particularly when the renamed binary has encode/decode functionality.

6. **Executable Files Created by Certutil** - Monitor for Sysmon EID 11 file creation events where certutil (or renamed variants) creates .exe files, indicating potential malware decoding.

7. **Certutil Process Metadata Mismatch** - Use Sysmon EID 7 Image Load events to detect when a process loads itself with OriginalFileName="CertUtil.exe" but runs from an unexpected path or filename.
