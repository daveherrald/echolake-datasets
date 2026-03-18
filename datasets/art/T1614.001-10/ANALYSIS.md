# T1614.001-10: System Language Discovery — Discover System Language with PowerShell

## Technique Context

T1614.001 (System Language Discovery) covers adversary enumeration of system language and locale settings. This test uses native PowerShell cmdlets and .NET globalization classes to comprehensively enumerate the system's language configuration: `Get-WinUILanguageOverride`, `Get-WinUserLanguageList`, `Get-WinSystemLocale`, `[System.Globalization.CultureInfo]::CurrentCulture.Name`, `[System.Globalization.CultureInfo]::CurrentUICulture.Name`, and `Get-TimeZone`. The results are collected into a hashtable and displayed. This approach is fully in-memory within the PowerShell host and leaves no child process, registry write, or file artifact.

## What This Dataset Contains

The dataset spans roughly 5 seconds across three log sources (36 Sysmon events, 10 Security events, 43 PowerShell events).

**PowerShell Event 4104** captures the complete attack payload across two recordings:

```
$info = @{
 UILanguage = Get-WinUILanguageOverride
 UserLanguages = (Get-WinUserLanguageList).LanguageTag -join ', '
 SystemLocale = Get-WinSystemLocale
 CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture.Name
 CurrentUICulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
 TimeZone = (Get-TimeZone).Id
}
```

**PowerShell Event 4103** (module logging) records individual cmdlet invocations with their bindings:
- `CommandInvocation(Get-WinUILanguageOverride)`
- `CommandInvocation(Get-WinUserLanguageList)`
- `CommandInvocation(Get-WinSystemLocale)`
- `CommandInvocation(Get-TimeZone)`
- `CommandInvocation(ForEach-Object)` — used to format and print the hashtable entries

This is richer than most tests in this batch: every language/locale API call is individually logged by module logging, allowing precise reconstruction of the exact queries made.

**Sysmon Event 1** (ProcessCreate) records:
- `whoami.exe` — ART test framework identity check (tagged `technique_id=T1033`)
- A second PowerShell process for cleanup/next test (tagged `technique_id=T1059.001`)

**Sysmon Event 10** (ProcessAccess) fires on the test framework accessing child PowerShell processes.

**Sysmon Event 7** (ImageLoad) shows .NET runtime and Defender DLL loads into PowerShell instances.

**Security Event 4688** records process creations for `powershell.exe` and `whoami.exe`.

## What This Dataset Does Not Contain

No child processes for `reg.exe`, `cmd.exe`, `chcp.com`, or `dism.exe` are present — this technique is entirely in-process within PowerShell. No registry reads, file writes, or network connections are generated.

The actual values returned by the language queries — the language tags, locale names, time zone, culture codes — are not captured in any log source. PowerShell logs the cmdlet invocations but not their output.

Because no child process is spawned for the language query, Sysmon Event 1 does not fire for the discovery activity itself (only for the test framework's `whoami.exe`). Detection relies entirely on PowerShell logging.

## Assessment

This is the most PowerShell-logging-friendly variant of the T1614.001 tests. The script block log (Event 4104) captures the entire discovery script verbatim, and module logging (Event 4103) captures each individual cmdlet call. The coverage is comprehensive for environments with PowerShell logging enabled. For environments without it, this technique would be nearly invisible — no process creation, no registry activity, no network traffic. The time zone collection (`Get-TimeZone`) is a detail worth noting: combining language/locale with time zone data gives an attacker a more precise geographic fix on the target system. Defender was active and did not block this test.

## Detection Opportunities Present in This Data

- **PowerShell Event 4104**: Script blocks containing `Get-WinSystemLocale`, `Get-WinUserLanguageList`, `Get-WinUILanguageOverride`, or `[System.Globalization.CultureInfo]` in the context of a recon-style script block (building a hashtable of system properties, enumerating and displaying them).
- **PowerShell Event 4103**: Individual command invocations for locale/language/timezone cmdlets from a non-interactive SYSTEM-context PowerShell session.
- **Combination indicators**: The pattern of querying multiple locale/language properties (`CultureInfo`, `WinSystemLocale`, `WinUserLanguageList`, `TimeZone`) within a single script block or rapid succession of 4103 events is a high-confidence indicator of T1614.001 activity.
- **Context**: These cmdlets are legitimate and used by system administrators. Context matters: SYSTEM-context PowerShell querying locale and timezone data in a short automated burst is suspicious; an interactive admin session doing the same is benign. The ART test framework execution pattern (whoami followed by a specific task) is a useful correlation point.
- **PowerShell logging dependency**: This technique is effectively undetectable without PowerShell script block logging (Event 4104) or module logging (Event 4103). Environments that lack these logging configurations have no reliable telemetry for this variant.
