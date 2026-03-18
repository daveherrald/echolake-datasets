# T1003.002-6: Security Account Manager — Dump Volume Shadow Copy Hives with System.IO.File

## Technique Context

T1003.002 targets the SAM database for credential extraction. This variant uses .NET's `System.IO.File` class within PowerShell to copy credential hives from Volume Shadow Copy paths. The approach is functionally similar to the certutil-based method (T1003.002-5) but replaces the LOLBin with native PowerShell .NET API calls: `[System.IO.File]::Copy('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\Windows\System32\config\SAM', 'C:\output\sam')`.

This is a more covert approach than using certutil because it does not spawn an additional process — the file copy happens entirely within the PowerShell process using managed .NET code. There is no certutil execution to detect, no external binary to create a Sysmon EID 1 event for, and no OID registry writes. Detection relies on PowerShell script block logging capturing the `System.IO.File::Copy` call with shadow copy paths, or on file creation events showing credential hives appearing in unexpected locations.

The defended version of this test showed fewer events overall, suggesting Defender blocked early in the execution chain. This undefended version captures the complete PowerShell-side execution.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**PowerShell channel (107 events: 96x EID 4104, 11x EID 4103):** The 11 EID 4103 (module logging) events are notable — this is the highest EID 4103 count in the T1003.002 series. Module logging fires when the PowerShell module invokes exported functions; the elevated count here suggests the test script exercised more module-level code paths than the other variants. The 96 EID 4104 events include the `System.IO.File::Copy` operation capturing the VSC path — the cleanup block `Invoke-AtomicTest T1003.002 -TestNumbers 6 -Cleanup -Confirm:$false` is present, confirming execution completed.

**Sysmon channel (29 events: 11x EID 7, 8x EID 11, 4x EID 1, 4x EID 10, 2x EID 17):** EID 1 process creation events show the standard pattern: `powershell.exe` spawning `whoami.exe` (PID 5764, pre-check at 22:45:44 UTC), then a child `powershell.exe` (PID 3280, the execution subprocess at 22:45:46 UTC), then `whoami.exe` post-check, and cleanup. The child `powershell.exe` at PID 3280 is the key process — this is where the `System.IO.File::Copy` runs. Its Sysmon EID 1 carries the rule `technique_id=T1083,technique_name=File and Directory Discovery`, suggesting the Sysmon configuration detected file access patterns. EID 11 shows that `powershell.exe` (PID 3280) wrote to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — confirming the child PowerShell ran in non-interactive mode, consistent with the `-NonInteractive` or `-Command` execution style used for the copy operation. EID 7 image loads (11 events) reflect the .NET assemblies loaded by the child PowerShell.

**Security channel (4 events, all EID 4688):** `powershell.exe` (PID 0x15a0) spawns `whoami.exe` (0x1684, pre-check), child `powershell.exe` (0xcd0, the System.IO.File execution), `whoami.exe` (0xf60, post-check), and child `powershell.exe` (0x9f4, cleanup). The minimal Security channel footprint (only 4 events, all EID 4688) contrasts with the defended run's 9 Security events — suggesting that without Defender generating its own blocking events, the Security log barely records this activity.

**Compared to the defended dataset (sysmon: 25, security: 9, powershell: 41):** PowerShell events are significantly higher undefended (107 vs. 41), and particularly the EID 4103 count (11 vs. probably 2 or fewer in the defended run) indicates fuller script execution. The Sysmon and Security counts are lower in the undefended run — Defender's blocking generated extra events in the defended scenario.

## What This Dataset Does Not Contain

The actual `System.IO.File::Copy` call targeting the VSC path is present in the full 107 PowerShell EID 4104 events but not surfaced in the 20-event sample. VSS creation events are absent — this test likely uses an existing shadow copy or the VSC enumeration is a separate operation. No hive file creation events (EID 11) showing the copied SAM/SYSTEM/SECURITY files at the destination path are in the sample, though they would be in the full Sysmon channel. There are no registry access events — the System.IO.File approach bypasses the registry API and reads the file directly from the VSC filesystem path.

## Assessment

The System.IO.File approach leaves a smaller process-based footprint than the certutil method — only PowerShell processes appear in EID 4688/EID 1, with no external binary creations. The primary detection surface is PowerShell script block logging, where the `System.IO.File::Copy` call with `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` paths is the key string. The child PowerShell spawned in non-interactive mode is detectable through its StartupProfileData-NonInteractive file access. This is a good dataset for testing whether script block content matching catches in-process .NET file operations targeting credential material.

## Detection Opportunities Present in This Data

1. **EID 4104 (PowerShell ScriptBlock Logging) — System.IO.File with VSC paths:** `[System.IO.File]::Copy` with source paths containing `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` combined with destination paths pointing to SAM, SYSTEM, or SECURITY filenames is a high-fidelity indicator.

2. **Sysmon EID 1 — child PowerShell spawned by parent PowerShell as SYSTEM:** The parent-child `powershell.exe` to `powershell.exe` execution with `NT AUTHORITY\SYSTEM` and the rule hit `T1083 File and Directory Discovery` on the child process is a meaningful behavioral chain.

3. **Sysmon EID 11 — StartupProfileData-NonInteractive creation:** The child PowerShell's non-interactive startup profile write indicates it was launched with a `-NonInteractive` or `-Command` flag. Cross-correlating this timing with any subsequent file creation of known hive names provides temporal correlation.

4. **EID 4103 (PowerShell Module Logging) — elevated function execution count:** Eleven module logging events from the Invoke-AtomicRedTeam module indicate more function calls than typical test setups. An unusually high EID 4103 count from a PowerShell session can flag complex attack module execution.

5. **Sysmon EID 7 — .NET assembly loads in child PowerShell:** The child PowerShell's 11 image load events represent its .NET runtime initialization. Monitoring for `System.IO.dll` or `mscorlib.dll` loads in a PowerShell process that subsequently accesses VSC paths provides corroborating evidence.

6. **Sysmon EID 11 — credential hive files at unexpected destination:** SAM, SYSTEM, or SECURITY filenames (without extensions) appearing in `C:\Windows\Temp\` or user temp directories, created by `powershell.exe`, would be direct artifacts of this technique that fall outside the 20-event sample but are in the full dataset.
