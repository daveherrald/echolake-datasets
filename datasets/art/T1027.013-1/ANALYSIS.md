# T1027.013-1: Encrypted/Encoded File — Decode Eicar File and Write to File

## Technique Context

T1027.013 Encrypted/Encoded File is a defense evasion technique where adversaries encode, encrypt, or obfuscate files to hide malicious content from security tools. This technique helps bypass signature-based detection, content inspection, and file-based analysis. Attackers commonly use Base64 encoding, XOR encryption, or custom encoding schemes to disguise payloads, configuration files, or malicious scripts. The detection community focuses on identifying encoding/decoding operations, suspicious string patterns, and file creation after decoding activities. This technique is frequently observed in malware droppers, PowerShell attacks, and staged payload delivery.

## What This Dataset Contains

This dataset captures a PowerShell-based Base64 decoding operation that creates the EICAR test string. The core malicious activity is visible in Security event 4688, showing PowerShell execution with the full command line: `"powershell.exe" & {$encodedString = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="; $bytes = [System.Convert]::FromBase64String($encodedString); $decodedString = [System.Text.Encoding]::UTF8.GetString($bytes); $decodedString | Out-File T1027.013_decodedEicar.txt}`.

The PowerShell channel contains detailed script block logging (EID 4104) showing the exact decoding script and a command invocation (EID 4103) capturing the Out-File operation with the decoded EICAR string: `"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"`.

Sysmon captures the process creation chain with a parent PowerShell process spawning the target PowerShell process (EID 1), and crucially shows file creation (EID 11) of `C:\Windows\Temp\T1027.013_decodedEicar.txt`. The dataset also includes typical PowerShell .NET runtime loading (EIDs 7) and Windows Defender DLL loading, indicating active endpoint protection monitoring.

## What This Dataset Does Not Contain

The dataset lacks Windows Defender alerts or quarantine events, suggesting the EICAR test string may not have triggered real-time protection or was allowed for testing purposes. There's no evidence of the decoded file being read, executed, or transferred after creation. The Sysmon ProcessCreate events use include-mode filtering, so other non-suspicious process executions are filtered out. Network connections, DNS queries, or any lateral movement activities are absent. The technique completed successfully without apparent blocking, though Windows Defender DLLs were loaded into the PowerShell processes.

## Assessment

This dataset provides excellent telemetry for detecting T1027.013 techniques. The combination of Security audit logs with command-line logging, PowerShell script block logging, and Sysmon file creation events creates multiple detection points. The Security channel captures the complete Base64-encoded command line, while PowerShell logging reveals the decoding logic and output operations. Sysmon file creation events provide confirmation of the technique's success. The data quality is high for building detections around Base64 decoding operations, PowerShell-based file creation, and encoded payload delivery mechanisms.

## Detection Opportunities Present in This Data

1. **Base64 Decoding in PowerShell Command Lines** - Security EID 4688 showing `[System.Convert]::FromBase64String()` method calls with encoded strings in process command lines

2. **PowerShell Script Block Base64 Operations** - PowerShell EID 4104 containing `FromBase64String`, `GetString`, and encoding/decoding method combinations within script blocks

3. **Suspicious File Creation After Decoding** - Sysmon EID 11 file creation events with filenames containing suspicious patterns (like "decoded", "eicar") following PowerShell Base64 operations

4. **PowerShell Out-File After Decoding** - PowerShell EID 4103 command invocations showing Out-File operations with decoded content, particularly when preceded by encoding operations

5. **Process Chain Analysis** - Sysmon EID 1 showing PowerShell parent-child relationships where child processes contain encoding-related command lines

6. **Encoded String Pattern Matching** - Detection of Base64-encoded strings in command lines that decode to known malicious signatures or test patterns like EICAR

7. **PowerShell Encoding Method Clustering** - Multiple PowerShell events showing encoding/decoding method usage (`[System.Text.Encoding]::UTF8.GetString()`, `FromBase64String()`) within short time windows
