# T1027-3: Obfuscated Files or Information — Execute base64-encoded PowerShell from Windows Registry

## Technique Context

T1027 Obfuscated Files or Information encompasses various methods attackers use to hide malicious code from detection systems. This specific test demonstrates a common persistence and evasion technique where PowerShell commands are base64-encoded and stored in the Windows Registry, then retrieved and executed later. Attackers frequently use this approach because:

- Base64 encoding bypasses basic string-based detections
- Registry storage provides persistence across reboots
- The technique splits malicious activity across multiple processes and operations
- It leverages trusted system utilities (PowerShell, Registry) rather than dropping files

Detection engineers typically focus on identifying base64-encoded PowerShell execution patterns, registry modifications to unusual keys, and the characteristic command patterns used to retrieve and decode stored payloads.

## What This Dataset Contains

This dataset captures a complete execution chain of the obfuscation technique. The test first base64-encodes the command `Write-Host "Hey, Atomic!"` and stores it in `HKCU:Software\Microsoft\Windows\CurrentVersion\Debug`. Then it spawns a child PowerShell process to retrieve and execute the encoded command.

Key telemetry includes:

**Process Chain (Security 4688):**
- Initial PowerShell: `"powershell.exe" & {$OriginalCommand = 'Write-Host "Hey, Atomic!"'...}`
- Child PowerShell: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"`

**PowerShell Script Block Logging (4104):**
- Base64 encoding operation: `$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)` and `$EncodedCommand =[Convert]::ToBase64String($Bytes)`
- Registry write: `Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name Debug -Value $EncodedCommand`
- Registry read and decode: `IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))`

**PowerShell Module Logging (4103):**
- `Set-ItemProperty` invocation with base64 value: `"VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA="`
- `Get-ItemProperty` retrieval of the Debug registry value

**Sysmon Process Creation (EID 1):**
- Three PowerShell processes showing the full execution chain
- Child process command line clearly shows the base64 decoding pattern

## What This Dataset Does Not Contain

The dataset lacks direct registry modification telemetry - Sysmon registry events (EID 12/13) are not captured, likely due to the sysmon-modular configuration not monitoring all registry operations. File system artifacts are minimal since this is a registry-based technique. Network connections are absent as this is purely local execution. The technique executed successfully without any Windows Defender interference, so there are no blocked execution events or access denied errors.

## Assessment

This dataset provides excellent coverage of the T1027.003 technique from both PowerShell logging and process creation perspectives. The PowerShell channels capture the complete attack flow including encoding operations, registry manipulation, and decode/execution phases. The Security 4688 events show the process relationships clearly. The combination of script block logging (4104) and module logging (4103) provides comprehensive visibility into the PowerShell operations involved. However, the lack of registry event logging is a notable gap for complete attack reconstruction.

## Detection Opportunities Present in This Data

1. **Base64-encoded PowerShell execution pattern** - Detect PowerShell command lines containing `[Convert]::FromBase64String` combined with `IEX` or `Invoke-Expression`

2. **Suspicious registry key usage** - Monitor PowerShell `Set-ItemProperty` operations targeting unusual registry paths like `HKCU:Software\Microsoft\Windows\CurrentVersion` with non-standard value names

3. **PowerShell script block base64 operations** - Alert on script blocks containing base64 encoding/decoding functions (`ToBase64String`, `FromBase64String`) combined with execution commands

4. **Registry-based payload storage** - Correlate `Set-ItemProperty` followed by `Get-ItemProperty` operations on the same registry key/value within a short timeframe

5. **PowerShell process chains with encoding patterns** - Detect parent-child PowerShell relationships where the child process command line contains base64 decoding operations

6. **Unusual registry value names** - Flag registry modifications to standard Windows paths with non-standard value names like "Debug" in version keys

7. **PowerShell module logging base64 correlation** - Combine EID 4103 `Set-ItemProperty` events containing base64 data with subsequent `Get-ItemProperty` retrievals of the same values
