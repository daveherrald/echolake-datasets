# T1218.007-2: Msiexec — Msiexec.exe - Execute Local MSI file with embedded VBScript

## Technique Context

T1218.007 (Msiexec) is a defense evasion technique where attackers abuse the legitimate Windows Installer service (msiexec.exe) to execute malicious code while appearing legitimate. This signed Microsoft binary is commonly trusted by security tools and can execute embedded scripts within MSI packages, making it an attractive living-off-the-land technique. Attackers frequently embed VBScript, JavaScript, or PowerShell within custom MSI packages to bypass application whitelisting, execute payloads with system privileges, or establish persistence. The detection community focuses on unusual msiexec command lines (especially with network sources or non-standard switches), child process creation from msiexec, script execution within MSI context, and file creation patterns that deviate from normal software installation.

## What This Dataset Contains

This dataset captures a complete msiexec-based VBScript execution sequence. The Security 4688 events show the full process chain: PowerShell → cmd.exe → msiexec.exe with command line `c:\windows\system32\msiexec.exe /q /i "C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_VBScript.msi"`. A second msiexec process spawns with the `-Embedding` parameter (PID 21960), which then launches PowerShell with the malicious payload: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host VBScript executed me!; exit`.

Sysmon EID 1 events capture the critical process creations: the initial msiexec (PID 26836), the embedded msiexec worker (PID 21960), and the spawned PowerShell process (PID 44812). Multiple token privilege adjustments (Security 4703) show msiexec enabling and disabling high-privilege tokens including `SeRestorePrivilege` and `SeTakeOwnershipPrivilege`.

Sysmon EID 7 image load events reveal script execution infrastructure loading within msiexec: `vbscript.dll`, `wshom.ocx` (Windows Script Host Runtime Library), `scrrun.dll` (Microsoft Script Runtime), and `amsi.dll` (Anti-Malware Scan Interface). The PowerShell scriptblock logging (4104) captures the actual command execution: `Write-Host VBScript executed me!; exit`.

Application log events document the MSI installation lifecycle, including transaction start (1040), successful installation completion (11707, 1033), and transaction end (1042) for "Atomic Red Team Test Installer" version 1.0.0.

## What This Dataset Does Not Contain

The dataset lacks the actual VBScript content embedded within the MSI file, as Sysmon doesn't capture MSI internal structures. While we see the scripting engine DLLs loading and the final PowerShell command execution, there's no visibility into the VBScript code that orchestrates the PowerShell launch. The dataset also doesn't capture the MSI file creation or modification events that would show how the malicious content was embedded. Network-based MSI execution scenarios are not represented here, limiting insight into remote MSI package deployment patterns that attackers commonly use.

## Assessment

This dataset provides excellent telemetry for detecting msiexec-based script execution techniques. The combination of process creation events with full command lines, privilege escalation activities, script engine loading patterns, and the actual payload execution creates multiple detection opportunities. The Security and Sysmon data sources complement each other well - Security 4688 provides comprehensive process tracking while Sysmon adds granular image loading and file creation details. The PowerShell logging successfully captures the final payload despite the VBScript intermediary. This represents high-quality evidence for building robust detections around msiexec abuse.

## Detection Opportunities Present in This Data

1. **Msiexec child process anomalies** - Monitor for msiexec.exe spawning unexpected child processes like PowerShell, cmd.exe, or other interpreters beyond normal installer helper processes

2. **Script engine loading in msiexec context** - Alert on image loads of vbscript.dll, wshom.ocx, scrrun.dll, or jscript.dll within msiexec processes, especially when combined with AMSI loading

3. **Msiexec embedding worker processes** - Detect msiexec processes with `-Embedding` parameter that spawn scripting engines or other suspicious child processes

4. **Privilege token manipulation patterns** - Correlate Security 4703 token adjustment events showing msiexec processes enabling high-privilege tokens like SeRestorePrivilege or SeTakeOwnershipPrivilege

5. **MSI installation from non-standard locations** - Flag msiexec executing MSI files from temporary directories, user profiles, or other non-standard installation paths like `C:\AtomicRedTeam\`

6. **Suspicious MSI metadata** - Monitor Application log events 1033/11707 for MSI packages with generic names like "Atomic Red Team Test Installer" or unusual publisher information

7. **PowerShell execution via MSI context** - Detect PowerShell processes with msiexec as parent, especially with suspicious parameters like `-nop` or direct command execution patterns

8. **Rapid MSI transaction lifecycle** - Alert on MSI transactions (Application 1040/1042) that complete unusually quickly, suggesting minimal legitimate software installation activity
