# T1614.001-10: System Language Discovery — Discover System Language with PowerShell

## Technique Context

T1614.001 (System Location Discovery: System Language Discovery) covers adversary enumeration of system language, locale, and regional configuration. This test (variant 10) takes a different approach from the registry-based variant (T1614.001-1): it uses native PowerShell globalization cmdlets and .NET framework classes to comprehensively enumerate language settings entirely within the PowerShell runtime, without spawning any child processes or touching the registry directly.

The technique uses:
- `Get-WinUILanguageOverride` — returns any configured UI language override
- `Get-WinUserLanguageList` — returns the user's configured language preference list with language tags
- `Get-WinSystemLocale` — returns the system locale (affects date, time, number formatting)
- `[System.Globalization.CultureInfo]::CurrentCulture.Name` — current culture setting
- `[System.Globalization.CultureInfo]::CurrentUICulture.Name` — current UI culture
- `Get-TimeZone` — returns the configured time zone identifier

The results are collected into a hashtable and printed. This is a **fully in-memory** operation: no child process is spawned, no registry key is directly queried, no file is written. The only observable artifact is the PowerShell script block executing within an existing PowerShell host process.

## What This Dataset Contains

The dataset captures 130 events across two log sources: PowerShell (117 events: 109 EID 4104, 8 EID 4103) and Security (13 events: 8 EID 4689, 4 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The discovery script block is captured in Security EID 4688** as a child PowerShell process created by the parent PowerShell test framework:

```
"powershell.exe" & {$info = @{
  UILanguage     = Get-WinUILanguageOverride
  UserLanguages  = (Get-WinUserLanguageList).LanguageTag -join ', '
  SystemLocale   = Get-WinSystemLocale
  CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture.Name
  CurrentUICulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
  TimeZone       = (Get-TimeZone).Id
}
$info.GetEnumerator() | ForEach-Object { "$($_.Name): $($_.Value)" }}
```

This single EID 4688 record contains the complete discovery logic — all six enumeration methods and the output formatting. The child PowerShell process exited at `0x0`, confirming all cmdlets executed successfully.

A cleanup `cmd.exe` was created with an empty body (`"powershell.exe" & {}`), the standard ART cleanup stub for tests with no persistent artifacts. All four EID 4688 events exited at `0x0`.

Security EID 4703 records the parent PowerShell (PID 0x4548) receiving elevated privileges including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeSecurityPrivilege` — consistent with SYSTEM-context execution.

The PowerShell log (EID 4104, 109 events) contains the standard ART preamble (Set-ExecutionPolicy Bypass, $ErrorActionPreference) and the discovery scriptblock is embedded within the child process's PowerShell session, making it visible in the EID 4688 command line rather than as a separate EID 4104 record in this sample set.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 1 (Process Create), the child PowerShell process created for the discovery script block has no hash-level identification. Without Sysmon EID 7 (Image Loaded), you cannot observe which globalization assemblies were loaded.

**No registry access events.** The PowerShell cmdlets (`Get-WinSystemLocale`, `Get-WinUserLanguageList`, etc.) read from the registry internally, but this is not surfaced as `reg.exe` process creation events or Sysmon registry read events. The in-process registry access is entirely opaque from a Security log perspective.

**The output of the discovery script is not captured.** The language tags, locale names, culture identifiers, and time zone ID returned by the enumeration are not logged. You can confirm the discovery ran but not what it found.

**No network activity.** This is a fully local, in-memory operation.

## Assessment

The defended variant recorded 36 Sysmon, 10 Security, and 43 PowerShell events. Sysmon in that run included EID 1 (Process Create) for the child PowerShell discovery process. The undefended run produced 0 Sysmon, 13 Security, and 117 PowerShell events.

Like T1614.001-1, this technique is not blocked by Defender in either variant — it uses only signed PowerShell cmdlets and .NET APIs. The event count differences between defended and undefended runs reflect Sysmon coverage, not blocking behavior. The key difference in this variant compared to T1614.001-1 is that no `reg.exe` or `cmd.exe` is spawned — the entire discovery happens within a PowerShell child process, making the EID 4688 command line the primary forensic artifact.

The script block in the EID 4688 command line is notably comprehensive: six separate enumeration methods in a single execution reveals more than the attacker strictly needs. This is consistent with recon tooling designed for maximum coverage rather than targeted queries.

## Detection Opportunities Present in This Data

**EID 4688 — PowerShell child process command line containing multiple Win32 globalization API calls in a single scriptblock.** The simultaneous use of `Get-WinUILanguageOverride`, `Get-WinUserLanguageList`, `Get-WinSystemLocale`, `CultureInfo::CurrentCulture`, `CultureInfo::CurrentUICulture`, and `Get-TimeZone` in a single PowerShell execution is a recon sweep. Individual calls to these functions may appear in legitimate administrative scripts; six in a single hashtable collection suggests automated profiling.

**EID 4688 — Child PowerShell spawned by parent PowerShell running as SYSTEM to execute language enumeration.** A SYSTEM-context PowerShell spawning a child PowerShell to enumerate locale settings is anomalous. System processes do not typically need to determine their own time zone or UI language through scripted means.

**Comparison with T1614.001-1 for correlation.** This variant and the registry-based variant produce similar outcomes through different execution paths. If both are executed in sequence — as they might be in a recon phase — the Security log would show two distinct process chains (PowerShell → cmd.exe → reg.exe vs. PowerShell → PowerShell) occurring within seconds of each other, both querying language-related data. Temporal correlation of discovery technique artifacts is a high-fidelity cluster indicator.

**PowerShell EID 4103 (module logging) — higher count in this variant (8 vs 3 in other tests).** The additional EID 4103 events in this test reflect the more interactive PowerShell cmdlet calls (`Get-WinUILanguageOverride`, `Get-WinUserLanguageList`, etc.) generating module pipeline logging. A pattern of elevated EID 4103 counts for discovery-oriented cmdlets — particularly globalization or system information cmdlets — can serve as a behavioral baseline deviation indicator.
