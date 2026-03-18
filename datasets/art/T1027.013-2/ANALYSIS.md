# T1027.013-2: Encrypted/Encoded File — Decrypt Eicar File and Write to File

## Technique Context

T1027.013 (Encrypted/Encoded File) is a defense evasion technique where adversaries encrypt, encode, or otherwise obfuscate files to hide their malicious intent from security tools. This technique is commonly used to bypass static analysis, evade signature-based detection, and conceal payloads during delivery or staging phases. Attackers frequently employ various encoding schemes (Base64, hex), encryption algorithms (AES, XOR), or custom obfuscation methods to transform malicious files into seemingly benign data.

The detection community focuses on identifying suspicious file operations involving encoded/encrypted content, monitoring for decryption activities in memory, and detecting the use of cryptographic APIs or PowerShell cmdlets like `ConvertTo-SecureString` and `ConvertFrom-SecureString`. This test specifically demonstrates PowerShell-based decryption of an encrypted EICAR test string, which is a common pattern for payload delivery.

## What This Dataset Contains

This dataset captures a PowerShell-based decryption operation that transforms an encrypted EICAR string into plaintext and writes it to disk. The core malicious activity is clearly visible in multiple telemetry sources:

**PowerShell Script Block Logging (EID 4104)** shows the complete decryption script: `$encryptedString = "76492d1116743f0423413b16050a5345MgB8AGkASwA0AHMAbwBXAFoAagBkAFoATABXAGIAdAA5AFcAWAB1AFMANABVAEEAPQA9AHwAZQBj..."` followed by `$key = [byte]1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32` and the decryption logic using `ConvertTo-SecureString` and `Marshal` operations.

**PowerShell Module Logging (EID 4103)** captures the specific cmdlet invocations with parameters, including the `ConvertTo-SecureString` call with the encrypted string and 32-byte key, and the `Out-File` call revealing the decrypted EICAR content: `X5O!P%@AP[4\PZX54(P^)7CC)7}-STANDARD-ANTIVIRUS-TEST-FILE!+H*`.

**Security Process Creation (EID 4688)** shows the PowerShell command line containing the entire encryption key and decryption script, providing complete visibility into the technique execution.

**Sysmon File Creation (EID 11)** documents the output file `C:\Windows\Temp\T1027.013_decryptedEicar.txt` being created by the PowerShell process (PID 7788).

**Sysmon Process Creation (EID 1)** captures both the initial PowerShell process and a child `whoami.exe` execution, showing the process chain and command line arguments with the embedded script.

## What This Dataset Does Not Contain

The dataset does not contain Windows Defender alert events or quarantine actions, despite the EICAR string being written to disk. This suggests either the decrypted content was not immediately detected by real-time protection, or the detection occurred after the telemetry collection window. Additionally, there are no network connections or DNS queries related to downloading encrypted payloads, as this test uses a locally embedded encrypted string rather than fetching content from external sources.

The Sysmon configuration's include-mode filtering means some supporting processes may not have generated ProcessCreate events, though the key PowerShell processes are captured due to their inclusion in the suspicious patterns list.

## Assessment

This dataset provides excellent coverage for detecting T1027.013 encrypted file techniques, particularly PowerShell-based decryption operations. The combination of PowerShell script block logging, module logging, and Security audit events creates multiple detection opportunities at different stages of the technique execution. The visibility into both the encrypted payload and the decryption key makes this dataset particularly valuable for building robust detections.

The telemetry quality is high, with complete command lines, script content, and file operations captured across multiple log sources. This multi-layered visibility ensures detection opportunities exist even if individual log sources are disabled or filtered.

## Detection Opportunities Present in This Data

1. **PowerShell ConvertTo-SecureString with hardcoded keys** - Monitor EID 4103 for ConvertTo-SecureString cmdlet usage with suspicious byte array keys, particularly sequential numeric patterns like `1,2,3,4...32`

2. **Large encoded strings in PowerShell script blocks** - Alert on EID 4104 events containing long Base64-like strings (>100 characters) combined with decryption operations

3. **PowerShell Marshal operations for SecureString conversion** - Detect EID 4104 script blocks using `[Runtime.InteropServices.Marshal]::SecureStringToBSTR` patterns indicating encrypted string decryption

4. **File creation following PowerShell decryption activities** - Correlate Sysmon EID 11 file creation events with preceding PowerShell decryption cmdlet usage (ConvertTo-SecureString + Marshal operations)

5. **Command line embedding of encryption keys** - Monitor Security EID 4688 for PowerShell processes with command lines containing `[byte]` array definitions with sequential numeric patterns

6. **PowerShell script execution with embedded encrypted payloads** - Detect EID 4688 processes where command line length exceeds thresholds (>1000 characters) and contains both encrypted strings and decryption logic

7. **EICAR pattern detection in PowerShell parameters** - Alert on EID 4103 Out-File operations where InputObject parameter contains EICAR test string patterns
