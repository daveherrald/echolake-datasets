# T1003.002-4: Security Account Manager — PowerDump Hashes and Usernames from Registry

## Technique Context

T1003.002 targets the Security Account Manager database to extract local account NTLM hashes. PowerDump is a PowerShell-based credential extraction tool that reads the SAM registry hive directly to enumerate local user accounts and their password hashes. Unlike the `reg.exe save` approach (T1003.002-1), PowerDump reads registry keys in memory without necessarily writing hive files to disk, making it a more covert approach to credential extraction.

PowerDump works by opening `HKLM\SAM\SAM\Domains\Account\Users` registry paths, reading the encrypted password hash values, and decrypting them using the boot key extracted from `HKLM\SYSTEM`. This is all accomplished within a PowerShell session using .NET registry API calls — no external binaries required beyond PowerShell itself. The technique requires administrative privileges (specifically `SE_DEBUG_PRIVILEGE` or equivalent registry access rights to the SAM hive).

The detection community watches for registry reads against `HKLM\SAM` keys in combination with PowerShell script blocks that contain hash decryption logic. The PowerShell-native approach means script block logging (EID 4104) is the primary detection surface, alongside any registry access audit events for the SAM hive.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**PowerShell channel (107 events, all EID 4104):** The script block logging shows `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force` and the cleanup block `Invoke-AtomicTest T1003.002 -TestNumbers 4 -Cleanup -Confirm:$false`. The 107 EID 4104 events include the PowerDump script itself — PowerDump is a large PowerShell script implementing RC4 decryption and registry reading logic, which would appear as multiple script block fragments across several 4104 events. The `$ErrorActionPreference = 'Continue'` block indicates the ART test framework was configured to continue past any errors.

**Security channel (4 events, all EID 4688):** Four process creation events show `powershell.exe` spawning `whoami.exe` (0x820, pre-check), a child `powershell.exe` (0x153c) for the PowerDump execution itself, `whoami.exe` (0x23c, post-check), and another `powershell.exe` (0x7c8) for the cleanup phase. The child `powershell.exe` at 0x153c is significant — this is the PowerDump execution context, a subprocess spawned to run the credential extraction. PowerDump running as a child PowerShell process rather than inline in the parent session is a behavioral indicator.

**Sysmon channel (34 events: 16x EID 7, 7x EID 11, 4x EID 1, 4x EID 10, 3x EID 17):** EID 1 shows `whoami.exe` (PID 2080) created from `powershell.exe` at 22:45:18 UTC with `NT AUTHORITY\SYSTEM`. Three EID 17 pipe creation events reflect multiple PowerShell sessions (`\PSHost.*` pipes) — consistent with the parent PowerShell spawning a child PowerShell for execution. EID 7 image load events (16 of them) indicate the child PowerShell process loaded a notable number of DLLs, consistent with PowerDump's use of .NET cryptographic and registry APIs. EID 10 shows `powershell.exe` opening child processes with `0x1FFFFF` access.

**Compared to the defended dataset (sysmon: 36, security: 12, powershell: 49):** Event counts are very similar across channels. The key difference is in what actually completed: the defended run's 12 Security events (vs. 4 here) suggests the defended version triggered more security auditing responses before being blocked. The undefended run's 107 PowerShell events vs. 49 in the defended run indicates the PowerDump script loaded and executed fully — more than twice the script block content reached execution without interruption.

## What This Dataset Does Not Contain

Registry access audit events (EID 4656/4663) for `HKLM\SAM\SAM\Domains\Account\Users` are absent — these would require Object Access auditing for the SAM registry key, which is not enabled by default in this environment. The actual NTLM hashes extracted by PowerDump do not appear in any telemetry channel. The PowerDump script's internal content (the RC4 decryption, the registry enumeration loops) would be visible in the full 107 EID 4104 events but is not surfaced in the 20-event sample preview. No network activity or persistence artifacts are present.

## Assessment

The undefended PowerDump execution produced roughly double the PowerShell events of the defended run, confirming that the full script executed without interruption. The Security EID 4688 evidence of a child `powershell.exe` spawned specifically for the credential extraction is a clean behavioral indicator. The dataset is useful for testing whether script block logging-based detection catches PowerDump's RC4 decryption and registry reading patterns, and for validating that the spawning of a child PowerShell for credential extraction purposes is detectable through process tree analysis.

## Detection Opportunities Present in This Data

1. **EID 4104 (PowerShell ScriptBlock Logging) — PowerDump content:** PowerDump contains distinctive strings including `Get-UserHashes`, `Get-BootKey`, RC4/DES decryption function definitions, and registry path references to `SAM\SAM\Domains\Account\Users`. Any of these in script block content is a strong indicator.

2. **EID 4688 — child PowerShell process from parent PowerShell as SYSTEM:** Seeing a parent `powershell.exe` spawn a child `powershell.exe` running as `NT AUTHORITY\SYSTEM` on a workstation is unusual. The two sequential `powershell.exe` entries (0x153c and 0x7c8) in the Security log bracket the attack execution and cleanup phases.

3. **Sysmon EID 17 — multiple PSHost pipes from the same parent:** Three named pipe creation events for `\PSHost.*` from the same originating process GUID indicates multiple PowerShell sessions were spawned. Cross-correlating this with SAM-related activity anchors the session chain.

4. **Sysmon EID 7 — cryptographic DLLs loaded by PowerShell:** PowerDump's use of .NET cryptographic APIs causes `System.Security.dll` and related assemblies to load into the PowerShell process. Correlating these image loads with the absence of any network activity (PowerDump is local-only) distinguishes it from other crypto-heavy PowerShell operations.

5. **Sysmon EID 10 — child PowerShell process accessed from parent:** The parent PowerShell opening the child PowerShell with `0x1FFFFF` access is a visible indicator of the process spawning pattern used to run PowerDump in an isolated context.

6. **Timing correlation — short-lived child PowerShell:** If the child `powershell.exe` (the dump process) lives for only a few seconds before being followed by cleanup commands, this transient process pattern is detectable through process duration analysis.
