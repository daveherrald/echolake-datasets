# T1003.002-7: Security Account Manager — WinPwn Loot Local Credentials, Dump SAM-File for NTLM Hashes

## Technique Context

T1003.002 targets the SAM database for local credential extraction. WinPwn is an all-in-one PowerShell-based post-exploitation framework that packages a wide range of credential harvesting, lateral movement, and persistence capabilities. The `samfile` function in WinPwn dumps the SAM, SYSTEM, and SECURITY registry hives using techniques similar to `reg.exe save`, then optionally parses the resulting files to extract NTLM hashes. WinPwn is designed to be loaded from memory (e.g., IEX download cradles) to avoid writing framework files to disk.

What makes WinPwn distinct from simpler tools is that it bundles multiple attack capabilities into a single PowerShell module, meaning a single import can enable a wide range of offensive operations. Detection engineers focus on identifying WinPwn-specific function names (samfile, Localrecon, etc.) in PowerShell script blocks, the module's characteristic download and in-memory execution patterns, and the resulting file artifacts from its credential dumping functions.

This dataset shows WinPwn's SAM dumping function executing on an undefended host. The defended version (sysmon: 39, security: 10, powershell: 51) was partially blocked; here the full execution completes.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**PowerShell channel (145 events: 137x EID 4104, 8x EID 4103):** This is the largest PowerShell footprint in the T1003.002 series. 145 events significantly exceeds the next-largest count (107 for T1003.002-4). The 8 EID 4103 module logging events indicate WinPwn's multiple exported functions were invoked. WinPwn is a large framework; its loading alone generates substantial script block logging as the module defines dozens of functions. The cleanup block `Invoke-AtomicTest T1003.002 -TestNumbers 7 -Cleanup -Confirm:$false` is present in the 20-event sample, confirming full test execution.

**Sysmon channel (30 events: 11x EID 7, 9x EID 11, 4x EID 1, 4x EID 10, 1x EID 17, 1x EID 22):** EID 1 events show `whoami.exe` (PID 3640, pre-check at 22:45:58 UTC), then two separate `powershell.exe` processes (PIDs 2448 and an additional instance) spawned for execution and cleanup. EID 22 (DNS query) appears once — WinPwn may issue a DNS resolution as part of its initialization or update check, which would be distinctive compared to the other SAM dump tools in this series that generate no network events. EID 17 shows one named pipe creation for the PowerShell host. The 11 EID 7 image loads reflect the WinPwn module's DLL dependencies being loaded.

**Security channel (4 events, all EID 4688):** Minimal Security log footprint: `powershell.exe` spawning `whoami.exe` (0xe38), child `powershell.exe` (0x990) for WinPwn execution, `whoami.exe` (0x121c), and child `powershell.exe` (0xbc0) for cleanup. The same child-PowerShell-from-parent-PowerShell pattern as T1003.002-4 and T1003.002-6.

**Compared to the defended dataset (sysmon: 39, security: 10, powershell: 51):** The undefended run has 145 PowerShell events vs. 51 defended — nearly 3x the script block content reached execution. The 8 EID 4103 events (vs. likely 2-3 in the defended run) confirms WinPwn's module functions executed fully. Sysmon events are lower (30 vs. 39), again showing that Defender's blocking in the defended run generated its own Sysmon telemetry.

## What This Dataset Does Not Contain

WinPwn's actual SAM dump file artifacts (the hive files it creates) are not in the 20-event sample, though they would appear in the full Sysmon EID 11 dataset. The DNS query (EID 22) subject is not visible in the sample — the full dataset would show what domain was queried. WinPwn's download cradle functionality (if used) would appear in EID 3 (network connections) or EID 22, but this test appears to use a pre-staged local copy. Registry access audit events for HKLM\SAM are absent for the same reasons as the other T1003.002 tests (Object Access auditing not configured).

## Assessment

WinPwn produces the largest PowerShell footprint of any T1003.002 variant in this batch (145 events, 137 EID 4104). This is both an opportunity and a challenge for detection: the large script block volume means more surface area for string-based detection rules, but also more potential for rule fatigue if rules are too broad. The EID 22 DNS query is a unique artifact in this test series — none of the other T1003.002 variants show network activity. The child-PowerShell execution pattern is consistent with the PowerDump and System.IO.File variants, suggesting this is a common ART test framework pattern rather than WinPwn-specific. The 8 EID 4103 module logging events are the clearest indicator of a complex PowerShell module executing versus simpler tools.

## Detection Opportunities Present in This Data

1. **EID 4104 — WinPwn function names in script blocks:** WinPwn's exported functions include distinctive names like `samfile`, `Invoke-WinPwn`, `Localrecon`, and credential-dumping submodules. These strings in EID 4104 content are high-fidelity indicators.

2. **EID 4103 (Module Logging) — high function invocation count:** Eight EID 4103 events from a single PowerShell session indicates a large framework module with many exported functions. Combined with any credential access artifact, this signals a post-exploitation framework.

3. **Sysmon EID 22 (DNS Query) from PowerShell as SYSTEM:** A DNS query from `powershell.exe` running as `NT AUTHORITY\SYSTEM` on a domain workstation, especially when paired with credential access activity, is worth investigating. WinPwn or its components may query for update servers or C2 infrastructure.

4. **EID 4688 — child PowerShell spawned by parent PowerShell as SYSTEM:** Same pattern as T1003.002-4 and T1003.002-6 — the child PowerShell execution context is where credential harvesting occurs. Detecting this process lineage combined with subsequent file creation of hive files provides the full chain.

5. **PowerShell event volume anomaly:** 145 EID 4104 events from a single test window is significantly more than normal PowerShell usage on a workstation. Volume-based detection thresholds (e.g., >50 script block events in a minute from a single PID running as SYSTEM) could flag WinPwn loading.

6. **Sysmon EID 7 — framework DLL loading by PowerShell:** WinPwn's 11 image load events represent .NET and potentially native libraries needed for its credential functions. If `samlib.dll` or `NtdsAudit.exe`-related libraries load into PowerShell, that narrows the activity further.
