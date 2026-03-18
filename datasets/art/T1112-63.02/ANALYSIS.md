# T1112-63: Modify Registry — Scarab Ransomware Defense Evasion Activities

## Technique Context

T1112 (Modify Registry) covers a broad range of adversary behaviors where Windows registry keys are altered to change system behavior, disable security controls, or weaken authentication. This test replicates a specific action associated with the Scarab ransomware family: setting the `AllowEncryptionOracle` value under the CredSSP Parameters key to weaken Windows authentication negotiation. The specific key—`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters`—governs how the Credential Security Support Provider handles encryption oracle vulnerabilities (CVE-2018-0886). Setting the value to `2` enables the "Vulnerable" mode, which permits connections from unpatched clients, effectively re-enabling a known authentication downgrade path that Microsoft patched in 2018.

This type of registry change is characteristic of ransomware pre-staging: the attacker degrades authentication security before deploying the payload, ensuring that post-encryption remote access or lateral movement is not impeded by credential hygiene controls.

## What This Dataset Contains

This dataset captures the complete execution of the Scarab CredSSP registry modification on a Windows 11 Enterprise domain workstation with Defender disabled, recorded over a 5-second window (2026-03-14T23:52:48Z to 23:52:53Z).

The attack chain is fully visible across all three channels. The PowerShell session running as `NT AUTHORITY\SYSTEM` (PID 3736, ProcessGuid `{9dc7570a-f4cf-69b5-b012-000000000600}`) spawns two child processes in sequence. Sysmon EID 1 records both:

- `cmd.exe` (PID 4036, ProcessGuid `{9dc7570a-f4d4-69b5-b512-000000000600}`) with command line: `"cmd.exe" /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f`
- `reg.exe` (PID 1048, ProcessGuid `{9dc7570a-f4d4-69b5-b712-000000000600}`) with command line: `reg  add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f`

Security EID 4688 corroborates both process creations with `Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` for the cmd.exe spawn and `Creator Process Name: C:\Windows\System32\cmd.exe` for the reg.exe spawn, both running at `Mandatory Label: S-1-16-16384` (System integrity).

Sysmon EID 1 also captures a `whoami.exe` execution (PID 4520, RuleName `technique_id=T1033`) immediately before the registry modification, reflecting the test framework's standard pre-execution context check. Sysmon EID 10 shows PowerShell accessing both `whoami.exe` and `cmd.exe` child processes with `GrantedAccess: 0x1FFFFF` (full access), which is the expected pattern when a parent process spawns children via the .NET `System.Diagnostics.Process` API.

The Sysmon EID 7 (image load) events document the PowerShell process loading `.NET` runtime components (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`) and Windows Defender's scan interface (`MpOAV.dll`, `MpClient.dll`). The Defender DLL loads are present because the Defender service is installed even though real-time protection is disabled—the scan interface is loaded on process start regardless.

The PowerShell channel contains 36 EID 4104 (script block logging) events. The substantive content is limited to internal PowerShell runtime fragments (`Set-StrictMode`, error formatting lambdas) and the test framework wrapper script `Invoke-AtomicTest T1112 -TestNumbers 63 -Cleanup`. The actual test execution script block was not captured in the sample subset—the registry modification is driven entirely via the cmd.exe → reg.exe child process chain rather than through native PowerShell registry cmdlets, so the most forensically significant evidence is in the process creation records.

## What This Dataset Does Not Contain

The dataset does not include a Sysmon EID 13 (registry value set) event in the sample window even though the breakdown shows one exists in the full dataset. That event—which would directly record the write to `HKLM\...\CredSSP\Parameters\AllowEncryptionOracle`—was generated but is not represented in the sample set. You should expect it in the full `sysmon.jsonl` file.

There are no Security EID 4657 or EID 4663 (registry object access auditing) events. These require a SACL on the specific registry key, which is not present by default on the CredSSP Parameters path. Without object-level auditing enabled, the Security channel reflects only process creation, not the registry write itself.

No network activity is captured. Scarab ransomware's full infection chain includes network-based lateral movement, but this test is scoped to the isolated registry modification step, so no C2 or SMB traffic appears.

The PowerShell script block that orchestrated the test—containing the actual `Invoke-AtomicTest` invocation—is visible only as the cleanup wrapper, not the execution command itself. The test body is not logged as a script block because it is passed directly as a command-line argument (`powershell.exe /c ...`) rather than as a file or here-string.

## Assessment

Compared to the defended variant (Sysmon: 30, Security: 20, PowerShell: 34), this undefended dataset is notably smaller (Sysmon: 18, Security: 4, PowerShell: 36). The defended dataset shows more Security channel events because Defender's real-time protection triggers additional process inspection and event generation around the attempted registry write. With Defender disabled, the Security channel captures only the four process creation events: whoami, cmd.exe, reg.exe, and a second whoami. The core technique evidence—the command line `reg add ... /v AllowEncryptionOracle ... /d 2`—is present in both variants and remains equally detectable through process creation telemetry alone.

The smaller total event count here does not mean lower fidelity for the technique itself. The process chain (PowerShell → cmd.exe → reg.exe) with the full registry path and value in the command line is completely intact and unobscured. What is absent is the defensive noise: Defender scan events, AMSI interception records, and the elevated process inspection activity that Defender generates when it evaluates the suspicious process chain.

## Detection Opportunities Present in This Data

**Process creation with targeted command line (Sysmon EID 1 / Security EID 4688):** The full command line `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f` appears verbatim in both Sysmon and Security logs. The combination of `reg.exe` with this specific path and `/d 2` provides a high-confidence, low-ambiguity indicator.

**Parent-child process chain (Sysmon EID 1):** The chain `powershell.exe` (SYSTEM) → `cmd.exe /c reg add ...` → `reg.exe` running from `C:\Windows\TEMP\` at System integrity is distinctive. `reg.exe` launched from a PowerShell-spawned `cmd.exe` in `TEMP\` is not a pattern that occurs in normal administrative activity.

**Process access events (Sysmon EID 10):** PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF` is captured and can serve as supporting context when correlating the parent process to its children.

**Registry value set (Sysmon EID 13):** The full dataset includes one EID 13 event that directly records the write to the CredSSP Parameters key. This provides direct evidence of the registry modification independent of process creation telemetry—useful for scenarios where process argument logging is not available.
