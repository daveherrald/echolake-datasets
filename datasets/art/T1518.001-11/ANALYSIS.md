# T1518.001-11: Security Software Discovery — Security Software Discovery - Get Windows Defender Exclusion Settings Using WMIC

## Technique Context

T1518.001 (Security Software Discovery) includes techniques that reveal not only whether
security software is present, but how it is configured. This test queries Windows Defender's
exclusion lists — paths, extensions, and processes that Defender is configured to skip — using
the legacy WMIC interface. For an adversary, discovering exclusions is directly actionable:
files dropped into an excluded path will not be scanned, making exclusions a reliable
staging ground for subsequent payloads.

## What This Dataset Contains

The test executes a WMIC command via cmd.exe to query the Defender WMI provider for exclusion
settings, as NT AUTHORITY\SYSTEM:

```
cmd.exe /c wmic /Node:localhost /Namespace:\\root\Microsoft\Windows\Defender Path
MSFT_MpPreference Get /format:list | findstr /i /C:"DisableRealtimeMonitoring"
/C:"ExclusionPath" /C:"ExclusionExtension" /C:"ExclusionProcess"
```

**Sysmon (33 events, EIDs 1, 7, 10, 11, 17):**
Three EID 1 ProcessCreate events capture the full execution chain. First, `whoami.exe` is
spawned by the ART test framework (RuleName `T1033`). Second, `cmd.exe` is created from the test framework
PowerShell with the full WMIC command line (RuleName `T1059.003/Windows Command Shell`).
Third, `findstr.exe` is created by `cmd.exe` to filter the WMIC output, with the full
`findstr` arguments preserved (RuleName `T1083`). The parent-child process chain from
`powershell.exe` → `cmd.exe` → `findstr.exe` is fully visible. The remaining events are
EID 7 ImageLoad entries for the PowerShell processes, EID 17 named pipe creates, EID 11
profile temp file creation, and EID 10 ProcessAccess events.

Note that `wmic.exe` itself does **not** appear as a Sysmon EID 1 because the sysmon-modular
include-mode config does not have an include rule matching the WMIC command line used here.
However, `wmic.exe` is captured in Security EID 4688 because the audit policy provides
comprehensive process creation coverage independent of Sysmon's include filters.

**Security (16 events, EIDs 4688, 4689, 4703):**
4688 events record `whoami.exe`, `cmd.exe`, `wmic.exe`, and `findstr.exe` creation with
full command lines. The 4688 for `wmic.exe` shows the command:
```
wmic /Node:localhost /Namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference
Get /format:list
```
All processes exit with 0x0 (4689). A 4703 token adjustment event is present for the SYSTEM
session.

**PowerShell (34 events, EIDs 4103, 4104):**
Two 4103 events record `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
(ART test framework boilerplate). The remaining 32 events are 4104 script block entries for
PowerShell's internal formatter stubs — no content specific to the WMIC query or its results.

## What This Dataset Does Not Contain (and Why)

**The exclusion list values returned:** WMIC output is not captured by any event log channel.
Whether the Defender instance had any configured exclusions — and what they were — is not
visible in this dataset. The findstr filter would only emit output to the terminal.

**Sysmon EID 1 for wmic.exe:** The sysmon-modular include-mode ProcessCreate configuration
used here matches known-suspicious command-line patterns (LOLBins, accessibility bypass,
`fltmc`, `sc`, etc.). The WMIC Defender namespace query used in this test does not match
those patterns, so Sysmon silently excludes the wmic.exe ProcessCreate. Security 4688 fills
this gap because it operates unconditionally with command-line auditing enabled.

**WMI activity or provider events:** No WMI-Activity/Operational (EID 5858/5859) events were
retained for this test window, indicating the Defender WMI query completed without error.

**Defender blocks (0xC0000022):** WMIC querying Defender's own WMI provider is a read-only
operation fully permitted by Defender. No blocking occurred.

## Assessment

The test completed successfully — WMIC was able to query the Defender WMI namespace as
SYSTEM. The combination of Sysmon and Security event channels provides a complementary
view: Sysmon captures `cmd.exe` and `findstr.exe` (include-matched patterns), while Security
4688 captures `wmic.exe` (which Sysmon filtered). The WMIC Defender namespace query is a
specific, rarely-legitimate command pattern that makes for a reliable detection rule.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `wmic.exe` with the namespace
  `\root\Microsoft\Windows\Defender` and path `MSFT_MpPreference` in the command line is a
  distinctive query. The combination of WMIC + Defender WMI namespace is unusual in normal
  operations and high-confidence for T1518.001.
- **Sysmon EID 1 / Security 4688:** `cmd.exe /c wmic ... | findstr ... ExclusionPath` as a
  piped command with exclusion-related keywords is directly indicative of an adversary
  checking whether there are safe staging paths.
- **Process chain:** `powershell.exe` (SYSTEM, session 0, no script path) → `cmd.exe` →
  `wmic.exe` → `findstr.exe` is an unusual ancestry chain for any legitimate administrative
  task. The absence of a script path for the parent PowerShell is a further anomaly.
- **Sysmon EID 1 for findstr.exe:** The findstr arguments (`DisableRealtimeMonitoring`,
  `ExclusionPath`, `ExclusionExtension`, `ExclusionProcess`) are searchable as keywords in
  a SIEM rule without any parsing complexity.
- **Temporal context:** This test ran approximately 5 seconds after T1518.001-10 (firewall
  enumeration) on the same host and SYSTEM account. A sequence of multiple Defender/firewall
  enumeration events within a short window is a higher-confidence signal than any individual
  query.
