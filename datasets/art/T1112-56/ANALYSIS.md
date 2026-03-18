# T1112-56: Modify Registry — Tamper Win Defender Protection

## Technique Context

T1112 Modify Registry is a fundamental technique for both defense evasion and persistence, involving direct manipulation of the Windows Registry to achieve operational objectives. The specific test variant "Tamper Win Defender Protection" targets Windows Defender's tamper protection mechanisms by attempting to disable the `TamperProtection` registry value in `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`. This technique is particularly significant because tamper protection is a key security feature that prevents unauthorized modifications to Windows Defender settings, making it a high-value target for attackers seeking to disable endpoint protection. The detection community focuses heavily on registry modifications to security product configurations, as these changes often indicate malicious intent to weaken system defenses.

## What This Dataset Contains

The dataset captures a complete process chain showing the attempted registry modification. Security Event ID 4688 shows the process creation chain: `powershell.exe` spawns `cmd.exe` with command line `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f`, which then spawns `reg.exe` with the actual registry modification command `reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f`. Critically, the `reg.exe` process exits with status `0x1` (failure), indicating the registry modification was blocked. Sysmon EID 1 events capture the same process creations with full command lines and process GUIDs. The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`), with no actual technique-specific PowerShell script blocks logged.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for this technique: successful registry modification events. There are no Sysmon EID 13 (RegistryEvent - Value Set) events showing the actual registry change, because Windows Defender's tamper protection successfully blocked the modification attempt. The failure is evidenced by the `reg.exe` exit code `0x1` in Security EID 4689. Additionally, there are no Windows Defender operational logs showing the tamper protection activation, and no System event logs indicating the security violation. The absence of registry modification telemetry makes this primarily a "detection of attempt" rather than "detection of success" scenario.

## Assessment

This dataset provides excellent telemetry for detecting attempted registry tampering of Windows Defender settings, even when the attempt fails. The complete process chain from PowerShell through cmd.exe to reg.exe is fully captured across both Security and Sysmon channels, providing redundant detection opportunities. The command-line arguments clearly show the malicious intent to disable tamper protection. However, the dataset's value is somewhat limited by the lack of successful execution telemetry - the technique was blocked before completion. For detection engineering, this represents the more common real-world scenario where modern endpoint protection prevents the attack but still generates valuable attempt indicators.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Analysis**: Security EID 4688 and Sysmon EID 1 showing `reg.exe` with command line targeting `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` and `TamperProtection` value

2. **Process Chain Analysis**: Detect PowerShell spawning cmd.exe spawning reg.exe pattern, particularly when targeting security product registry paths

3. **Windows Defender Registry Path Targeting**: Monitor any process attempting to modify registry keys under `HKLM\SOFTWARE\Microsoft\Windows Defender\` paths

4. **Failed Registry Modification Detection**: Correlate Security EID 4688 process creation with EID 4689 exit status `0x1` for registry tools targeting security products

5. **Command Line Pattern Matching**: Detect command lines containing both "Windows Defender" and "TamperProtection" registry modifications regardless of success

6. **Suspicious PowerShell Child Process**: Alert on PowerShell spawning cmd.exe that immediately executes registry modification commands against security products

7. **Registry Tool Process Lineage**: Track reg.exe processes with suspicious parent chains (PowerShell → cmd.exe → reg.exe) and security-related command arguments
