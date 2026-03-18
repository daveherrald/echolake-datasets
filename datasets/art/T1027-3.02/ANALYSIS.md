# T1027-3: Obfuscated Files or Information — Execute base64-encoded PowerShell from Windows Registry

## Technique Context

T1027 Obfuscated Files or Information covers the use of encoding, encryption, and other methods to conceal malicious code from security tools and analysts. This specific test demonstrates a two-step registry-based execution technique: a PowerShell command is base64-encoded and stored as a registry value, then a second PowerShell process retrieves and executes it via `Invoke-Expression`. Attackers use this pattern for two reasons — the registry write creates persistence (the payload survives across sessions), and the consuming process's command line contains only an opaque base64 string rather than legible malicious code, making static analysis harder.

The technique exploits PowerShell's `-Command` parameter and `IEX` (Invoke-Expression) alias, which together enable arbitrary code execution from any string source including registry values. The registry path used here — `HKCU:Software\Microsoft\Windows\CurrentVersion\Debug` — is a legitimate but rarely populated key that blends in with the adjacent Windows Update and Run keys. Defenders focus on the characteristic command line pattern `powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String(...)))"`  along with `Set-ItemProperty` writes to unusual registry key names (such as `Debug` under CurrentVersion), and on PowerShell module logging (EID 4103) that captures the base64 value and the decoded command.

## What This Dataset Contains

The dataset covers approximately 6 seconds (23:03:59–23:04:05 UTC on 2026-03-14) and totals 134 events across three channels.

Security EID 4688 and Sysmon EID 1 capture the complete three-stage process chain. The staging PowerShell (PID 0xbc8) runs with the full command line including the encoding and registry write logic:

```
"powershell.exe" & {$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand
Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"}
```

The executing child PowerShell (PID 0x684) is spawned by PID 0xbc8 with the command line: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"`. This is the exact consuming process command line that a defender would see in a real intrusion, where the staging script would not be visible in the consuming process's command line.

The cleanup phase uses `Remove-ItemProperty -Force -ErrorAction Ignore -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name Debug` to erase the registry value, spawned as a separate PowerShell process (PID 0xb44).

In the full dataset (not captured in the 20-sample set), PowerShell EID 4104 script block logging records the base64 encoding operations, the `Set-ItemProperty` write with the encoded value `VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA=`, and the `IEX` decode-and-execute in the child process. PowerShell EID 4103 module logging captures the `Set-ItemProperty` and `Get-ItemProperty` invocations with parameter bindings including the base64 payload value.

SearchProtocolHost.exe appears in the Security EID 4688 samples (spawned by SearchIndexer.exe with its standard pipe arguments) — this is a Windows Search background activity unrelated to the technique.

Compared to the defended dataset (49 Sysmon events, 13 Security, 41 PowerShell), this undefended run has fewer events (31 Sysmon, 6 Security, 96 PowerShell). The higher Sysmon count in the defended run reflects background activity; the PowerShell channel increase here is due to the technique completing fully and generating additional script block logging.

## What This Dataset Does Not Contain

Sysmon EID 12/13 registry monitoring events for `HKCU:Software\Microsoft\Windows\CurrentVersion\Debug` are absent. The Sysmon configuration's registry monitoring rules do not cover the CurrentVersion key, so the registry write and delete are only observable through process creation (the Set-ItemProperty command in the PowerShell command line) and through EID 4103 module logging. The actual decoded execution output (`Write-Host "Hey, Atomic!"` writing to stdout) does not produce any event. There are no file system artifacts.

## Assessment

This dataset is excellent for detection engineering targeting the registry-based base64 execution pattern. The complete process chain is present across both Sysmon EID 1 and Security EID 4688, including both the staging process (which encodes and writes the registry value) and the consuming process (which retrieves and executes via IEX). The consuming process's command line — the one an attacker would actually deploy — is the highest-value artifact: `powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\... Debug).Debug)))"`. This exact pattern, or its structural equivalents with different registry paths, is a strong detection target. The EID 4103 module logging in the full dataset adds the base64 payload value for threat intelligence extraction.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — IEX with FromBase64String in command line**: The child PowerShell command line contains `IEX`, `[Convert]::FromBase64String`, and registry property access (`gp HKCU:...`) in a single `-Command` argument. This compound pattern is the defining signature of registry-based encoded payload execution.

2. **Sysmon EID 1 / EID 4688 — PowerShell spawning PowerShell with -Command flag**: A parent PowerShell spawning a child PowerShell with `-Command` as a flag (rather than a script file or `-File`) is associated with programmatic execution and warrants scrutiny, especially when the command body is opaque.

3. **EID 4104 — script block with Set-ItemProperty to CurrentVersion\Debug**: The registry write to the `Debug` named value under `HKCU:Software\Microsoft\Windows\CurrentVersion` is captured in script block logging. Monitoring for `Set-ItemProperty` writes to the CurrentVersion key with non-standard value names is a behavioral detection opportunity.

4. **EID 4103 — module logging capturing base64 payload**: The `Set-ItemProperty` invocation with the full base64 string `VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA=` in the parameter bindings allows extraction and decoding of the payload for threat intelligence.

5. **Sysmon EID 1 — powershell.exe spawned from powershell.exe**: The parent-child relationship PowerShell → PowerShell, where the child uses `-Command "IEX ..."`, is a behavioral pattern distinct from legitimate administrative PowerShell use, which typically uses `-File` with script paths.
