# T1140-1: Deobfuscate/Decode Files or Information — Deobfuscate/Decode Files Or Information

## Technique Context

T1140 (Deobfuscate/Decode Files or Information) represents a critical defense evasion technique where adversaries reverse encoding, encryption, or obfuscation applied to files or information to restore it to a usable state. This technique is fundamental to multi-stage attacks where malicious payloads are delivered in encoded formats to evade detection, then decoded at execution time. Common implementations include base64 decoding, certificate utility abuse for encoding/decoding, PowerShell deobfuscation, and custom decryption routines.

The detection community focuses heavily on monitoring utilities commonly abused for encoding/decoding operations (certutil, PowerShell, Python), file creation patterns that suggest decoded payloads, and process command lines containing encoding/decoding parameters. Certutil.exe abuse for non-certificate operations is particularly well-documented as a Living off the Land technique.

## What This Dataset Contains

This dataset captures a straightforward certutil-based encoding/decoding operation executed through PowerShell. The process chain shows PowerShell spawning cmd.exe with the command line: `"cmd.exe" /c certutil -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt & certutil -decode %temp%\T1140_calc.txt %temp%\T1140_calc_decoded.exe`

The sequence of events includes:
- Security 4688 events showing process creations for whoami.exe, cmd.exe, and two certutil.exe instances with full command lines
- Sysmon EID 1 events for the same processes with additional metadata including hashes and parent process relationships
- Sysmon EID 11 file creation events showing the intermediate encoded file `C:\Windows\Temp\T1140_calc.txt` and final decoded file `C:\Windows\Temp\T1140_calc_decoded.exe`
- Multiple PowerShell startup events and Windows Defender DLL loading events

The actual technique execution is clearly visible in the certutil command lines: first encoding calc.exe to base64 format, then decoding it back to an executable.

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen T1140 detection coverage. There are no registry modifications, network connections, or advanced obfuscation techniques beyond basic base64 encoding. The PowerShell channel contains only framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual PowerShell commands that orchestrated the technique execution.

Additionally, this represents a benign encoding/decoding operation using calc.exe rather than malicious content, so there's no evidence of subsequent payload execution, persistence mechanisms, or follow-on malicious activity that would typically accompany real-world T1140 usage.

## Assessment

This dataset provides excellent telemetry for detecting basic certutil abuse for encoding/decoding operations. The combination of Security 4688 command-line logging and Sysmon process creation events offers redundant, high-fidelity detection opportunities. The file creation events clearly show the encoded intermediate file and decoded output, providing file-based detection vectors.

However, the dataset's scope is limited to this single encoding method. Real-world T1140 techniques often involve PowerShell-based deobfuscation, custom decryption algorithms, or other encoding utilities that aren't represented here. The clean execution without Windows Defender intervention also means we don't see how modern endpoint protection might interfere with such operations.

## Detection Opportunities Present in This Data

1. Command line detection for certutil.exe with -encode or -decode parameters, particularly when used with non-certificate file extensions
2. Process chain analysis detecting cmd.exe spawning certutil.exe with encoding/decoding operations
3. File creation monitoring for files in temp directories with patterns suggesting encoded content (e.g., .txt files created by certutil)
4. Temporal correlation between certutil encode and decode operations on related filenames
5. Parent process analysis detecting PowerShell or cmd.exe spawning certutil for non-standard operations
6. Process access events (Sysmon EID 10) showing PowerShell accessing child processes during command execution
7. File extension analysis detecting executable files created through decoding operations in temp directories
