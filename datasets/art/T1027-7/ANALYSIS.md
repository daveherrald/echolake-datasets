# T1027-7: Obfuscated Files or Information — Obfuscated Command in PowerShell

## Technique Context

T1027.007 (Dynamic API Resolution) represents one of several sub-techniques under T1027 (Obfuscated Files or Information), specifically focusing on PowerShell command obfuscation. Adversaries use this technique to evade signature-based detection and complicate analysis by obscuring malicious PowerShell commands through various encoding, variable substitution, and string manipulation methods. Common obfuscation techniques include base64 encoding, character substitution, string concatenation with format operators, type casting obfuscation, and leveraging PowerShell's flexible syntax to hide malicious intent.

The detection community focuses on identifying obfuscated PowerShell patterns through script block logging analysis, looking for suspicious string operations, unusual type casting, character conversion functions, and the presence of `Invoke-Expression` or similar execution cmdlets. This technique is particularly important because PowerShell's legitimate flexibility makes it challenging to distinguish between benign and malicious obfuscation.

## What This Dataset Contains

This dataset captures a sophisticated PowerShell obfuscation example that demonstrates multiple evasion techniques. The core obfuscated command appears in Security event 4688 with the command line:
```
"powershell.exe" & {$cmDwhy =[TyPe]("{0}{1}" -f 'S','TrING') ; $pz2Sb0 =[TYpE]("{1}{0}{2}"-f'nv','cO','ert') ; &("{0}{2}{3}{1}{4}" -f'In','SiO','vOKe-EXp','ReS','n') ( (&("{1}{2}{0}"-f'blE','gET-','vaRIA') ('CMdw'+'h'+'y'))."v`ALUe"::("{1}{0}" -f'iN','jO').Invoke('',( (127, 162,151, 164,145 ,55 , 110 ,157 ,163 , 164 ,40,47, 110 , 145 ,154, 154 ,157 , 54 ,40, 146, 162 , 157,155 ,40, 120, 157 ,167,145 , 162 ,123,150 ,145 , 154 , 154 , 41,47)| .('%') { ( [CHAR] ( $Pz2sB0::"t`OinT`16"(( [sTring]${_}) ,8)))})) )}
```

The PowerShell script block logging (event ID 4104) reveals the deobfuscated execution: `Write-Host 'Hello, from PowerShell!'`. Event 4103 shows the detailed parameter bindings for `Get-Variable`, `ForEach-Object`, `Write-Host`, and `Invoke-Expression` cmdlets. The obfuscation uses format string operations (`-f`), variable indirection, type casting obfuscation (`[TyPe]`, `[TYpE]`), tick mark escaping (`` `ALUe``, `` t`OinT`16``), and octal-to-character conversion to hide the actual command.

Sysmon captures the PowerShell process creation (event ID 1), .NET runtime DLL loading events (event ID 7), named pipe creation for PowerShell remoting (event ID 17), and process access events (event ID 10) showing cross-process activity between PowerShell instances.

## What This Dataset Does Not Contain

The dataset lacks network activity that might be present in more sophisticated obfuscated PowerShell attacks targeting external resources. While Windows Defender is active, it did not block this benign obfuscated command, so we don't see the typical STATUS_ACCESS_DENIED patterns. The Sysmon process creation events for the initial PowerShell processes are missing due to the sysmon-modular include-mode filtering, though the child `whoami.exe` process is captured. File system artifacts beyond PowerShell profile creation are not present since this test only executes a simple output command.

## Assessment

This dataset provides excellent telemetry for PowerShell obfuscation detection. The combination of Security 4688 command-line logging and PowerShell 4103/4104 script block logging creates a comprehensive view of both the obfuscated command and its deobfuscated execution. The presence of detailed parameter binding information in 4103 events is particularly valuable for detection engineering, as it shows the actual cmdlet invocations regardless of obfuscation. The Sysmon events add context around process relationships and runtime behavior, though the core detection value lies in the PowerShell logs themselves.

## Detection Opportunities Present in This Data

1. **Format String Obfuscation Pattern Detection** - Security 4688 and PowerShell 4104 events containing multiple `"{n}{m}" -f` format operations combined with variable assignments for common .NET types like STRING and Convert.

2. **Type Casting Obfuscation with Case Variation** - PowerShell events showing mixed-case type references (`[TyPe]`, `[TYpE]`) combined with format string construction of type names.

3. **Variable Indirection with Get-Variable** - PowerShell 4103 events showing `Get-Variable` cmdlet usage with string concatenation to build variable names, followed by `.Value` property access.

4. **Tick Mark Escaping in Method Names** - PowerShell script blocks containing backtick escaping in .NET method calls (`` `ALUe``, `` t`OinT`16``) which is uncommon in legitimate scripts.

5. **Octal-to-Character Conversion Arrays** - PowerShell 4103/4104 events showing arrays of 3-digit numbers (127, 162, 151, etc.) passed to `ForEach-Object` with `[CHAR]` and `ToInt16` base-8 conversion.

6. **Invoke-Expression with Complex String Building** - PowerShell 4103 events showing `Invoke-Expression` receiving dynamically constructed strings from character array conversion, especially when combined with other obfuscation indicators.

7. **PowerShell Process Spawning with Obfuscated Arguments** - Sysmon event ID 1 showing PowerShell child processes launched with heavily obfuscated command lines containing multiple concatenation and conversion operations.
