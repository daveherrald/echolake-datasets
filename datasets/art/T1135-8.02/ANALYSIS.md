# T1135-8: Network Share Discovery — PowerView ShareFinder

## Technique Context

Network Share Discovery (T1135) using PowerView's `Invoke-ShareFinder` is a close variant of `Find-DomainShare`: both functions enumerate domain computers via LDAP and then probe each for accessible shares. `Invoke-ShareFinder` uses a locally installed copy of PowerView (loaded from disk rather than downloaded) with the `-CheckShareAccess` parameter, which instructs PowerView to verify that the current user actually has access to each discovered share rather than simply listing all shares it finds. This access-checking behavior generates additional authentication traffic as PowerView attempts to open each share. When Defender is enabled, it blocks PowerView at import time because the module's signatures are well-known.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures PowerView's `Invoke-ShareFinder -CheckShareAccess` execution from a domain-joined Windows 11 workstation (ACME-WS06.acme.local).

**Process execution chain:** The defended dataset described the execution command: `"powershell.exe" & {Import-Module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerView.ps1"; Invoke-ShareFinder -CheckShareAccess}`. In the undefended run, this command ran without blocking. Security EID 4688 records two `whoami.exe` child processes spawned from `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 14584), confirming the test framework ran; the PowerView-executing child PowerShell is not captured in the Security channel samples.

**PowerShell test framework completion:** 106 PowerShell events (104 EID 4104, 2 EID 4103) including a Write-Host "DONE" completion marker in EID 4103, confirming successful end-to-end test framework execution. This contrasts with the defended run (49 PowerShell events, no completion), where Defender terminated the process.

**Sysmon EID 1 process creates:** Two `whoami.exe` executions (PIDs 17724 and 16872) both spawned from PowerShell PID 14584 running as SYSTEM (`IntegrityLevel: System`, `LogonId: 0x3E7`).

**DLL loading:** Nine Sysmon EID 7 events record .NET CLR initialization into the parent PowerShell process: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`, `System.Management.Automation.ni.dll`, `urlmon.dll`, `MpOAV.dll`, and `MpClient.dll`. The presence of `urlmon.dll` suggests network operations were prepared.

**Named pipe and process access:** Sysmon EID 17 creates the PowerShell host pipe. Two Sysmon EID 10 events record PowerShell accessing the two `whoami.exe` processes with `GrantedAccess: 0x1FFFFF`.

**Application channel:** EID 15 records SecurityCenter reporting `SECURITY_PRODUCT_STATE_ON` for Windows Defender, reflecting the defender-state notification at test startup.

The undefended dataset (15 Sysmon, 2 Security, 106 PowerShell) runs lighter than the defended variant (36 Sysmon, 10 Security, 49 PowerShell). The defended run generated more Sysmon events because Defender's scanning and blocking triggered additional system activity; here, the absence of blocking means execution is cleaner.

## What This Dataset Does Not Contain

**PowerView script block content:** The 104 EID 4104 events exist in the full dataset but only 20 samples are surfaced here. The script blocks containing `Import-Module "C:\AtomicRedTeam\...\ExternalPayloads\PowerView.ps1"` and `Invoke-ShareFinder -CheckShareAccess` are present in the full dataset's PowerShell channel.

**Network connections to domain controller and hosts:** PowerView's `Invoke-ShareFinder` begins with LDAP queries to enumerate domain computers, then makes SMB connection attempts to each. No Sysmon EID 3 (network connection) events appear in the samples — the Sysmon-modular configuration does not appear to capture LDAP or SMB connections from PowerShell.

**Share enumeration results:** No events indicate which hosts were queried, which shares were discovered, or whether any shares were accessible to the testing account.

**Child PowerShell process creation:** The second PowerShell instance that imports PowerView and runs `Invoke-ShareFinder` does not appear in Sysmon EID 1 samples; the Sysmon-modular include-mode filters likely match only specific execution patterns.

## Assessment

The key difference between T1135-8 and T1135-7 is the delivery mechanism: T1135-7 downloads PowerView at runtime from GitHub, while T1135-8 imports a locally staged copy. Both executed successfully in the undefended environment. This dataset is most useful for testing detections based on PowerShell EID 4104 script block logging — specifically, `Import-Module` loading a file named `PowerView.ps1` from an unusual path, and the `Invoke-ShareFinder` function call.

The defended variant produced a good comparison point: it confirmed Defender blocks PowerView at import time with no network activity; the undefended variant confirms the tool ran to completion but leaves minimal process-level footprint in the Security channel. The critical detection layer for this technique is PowerShell script block logging, not process creation monitoring.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** `Import-Module "C:\AtomicRedTeam\...\ExternalPayloads\PowerView.ps1"` — loading PowerView from a non-standard path, present in the full script block log
- **PowerShell EID 4104:** `Invoke-ShareFinder -CheckShareAccess` — the function call itself, uniquely associated with PowerView/PowerSploit
- **Security EID 4688 / Sysmon EID 1:** PowerShell running as SYSTEM executing `whoami.exe` child processes is anomalous on a user workstation
- **Sysmon EID 7:** `urlmon.dll` loading into a PowerShell process that then performs network enumeration provides context for retrospective investigation
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` from SYSTEM context is a reliable indicator of automated adversarial PowerShell execution
