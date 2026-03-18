# T1562.001-14: Disable or Modify Tools — AMSI Bypass - Remove AMSI Provider Reg Key

## Technique Context

T1562.001 (Disable or Modify Tools) includes bypassing AMSI by removing its provider registration from the Windows registry. The AMSI provider at `HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}` is the Windows Defender AMSI provider. Deleting this registry key causes the AMSI subsystem to load with no registered providers, making `AmsiScanBuffer` calls return clean results regardless of content. Unlike the in-memory InitFailed bypass, this is a persistent, system-wide change that affects all processes launched after the deletion.

## What This Dataset Contains

The dataset captures 85 events across Sysmon, Security, PowerShell, and Application logs collected during a 5-second window on 2026-03-14 at 14:49 UTC.

The registry deletion command is visible in multiple log sources:

```
"powershell.exe" & {Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse}
```

Key observations from the data:

- **Sysmon EID 1**: `powershell.exe` (PID 2420) is spawned with the full `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse` command in its command line, as a child of the parent `powershell.exe` ART test framework (PID 5448). RuleName: `technique_id=T1059.001,technique_name=PowerShell`.
- **PowerShell EID 4104**: Two scriptblock events record the Remove-Item command, both variations of the same call. The AMSI provider GUID `{2781761E-28E0-4109-99FE-B9D127C57AFE}` is fully visible in the scriptblock text.
- **PowerShell EID 4103**: `CommandInvocation(Remove-Item): "Remove-Item"` with `ParameterBinding(Remove-Item): name="Path"; value="HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"` — module logging captures the exact call.
- Security EID 4688 records the new `powershell.exe` process creation with the full command line.
- Security EID 4688 also records the ART test framework's `whoami.exe` pre-execution check.
- **Application EID 15**: One Application log event is present. This is a Windows Error Reporting or application-level event associated with the provider deletion (specific content not extracted, but its presence alongside the registry operation is consistent with an AMSI provider event).
- Sysmon EID 7, 10, 11, 17 provide the standard PowerShell test framework artifacts (DLL loads, process access on whoami.exe, pipe creation, profile data file write).
- PowerShell EID 4104 also contains the ART error-handling scriptblock boilerplate.

The key difference from the InitFailed bypass (test 13): the Remove-Item command IS captured in PowerShell scriptblock logging here, because the bypass only takes effect for newly spawned processes — the PowerShell process executing Remove-Item itself still has AMSI active, so AMSI scans and logs the command. This produces better telemetry than the in-memory patch approach.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 12/13/14 (registry key delete).** The sysmon-modular configuration's RegistryEvent rules do not include a rule matching the AMSI provider key path, so the registry deletion is not captured by Sysmon directly. The deletion is visible through the PowerShell logs and process creation events instead.

**No Sysmon EID 12 (key deletion).** Sysmon RegistryDelete events (EID 12) are not generated for this path under the current Sysmon config.

**No evidence of bypass persistence impact.** The dataset captures the deletion but not the downstream impact (e.g., a subsequent script executing without AMSI inspection).

**No Defender block (0xC0000022).** Windows Defender does not block this registry modification as SYSTEM. The deletion succeeds.

## Assessment

This dataset contains the clearest telemetry of any AMSI bypass technique in this series. The Remove-Item command including the specific AMSI provider GUID is captured in three independent sources: the Sysmon process creation command line (EID 1), the PowerShell scriptblock log (EID 4104), and the PowerShell module log (EID 4103). This reflects an important defensive property: registry-based persistence bypasses produce more telemetry than in-memory approaches, because the bypass code executes before AMSI is disabled for the current process. Defenders with PowerShell logging enabled have multiple opportunities to detect this technique.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `powershell.exe` launched with command line containing `Remove-Item` and the AMSI provider GUID `{2781761E-28E0-4109-99FE-B9D127C57AFE}`.
- **PowerShell EID 4104**: Scriptblock containing `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\..."` — direct detection of the registry deletion command.
- **PowerShell EID 4103**: `CommandInvocation(Remove-Item)` with the AMSI Providers path as the parameter value — module logging provides structured detection.
- **Security EID 4688**: `powershell.exe` process creation with AMSI GUID in command line, spawned as SYSTEM from another `powershell.exe`.
- **Registry monitoring (external)**: Any deletion of keys under `HKLM:\SOFTWARE\Microsoft\AMSI\Providers\` should be treated as high-severity regardless of the specific GUID.
- **Behavioral pattern**: PowerShell spawning PowerShell with a `-Path HKLM:\SOFTWARE\Microsoft\AMSI\Providers\` argument is a reliable indicator of AMSI provider manipulation.
