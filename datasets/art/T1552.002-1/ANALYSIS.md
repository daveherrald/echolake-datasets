# T1552.002-1: Credentials in Registry — Enumeration for Credentials in Registry

## Technique Context

MITRE ATT&CK T1552.002 (Credentials in Registry) covers adversary searches of the Windows Registry for stored credentials. Applications, installers, and system components sometimes write plaintext or weakly-encoded passwords to registry values — common locations include autologon credentials under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, VNC passwords, MSI installer temporary values, and various software-specific locations. Test 1 performs a broad sweep using `reg query` with the `/f password` flag against both `HKLM` and `HKCU`, searching recursively for any string-type value containing the word "password". This is one of the most commonly observed registry credential hunting patterns in post-exploitation frameworks.

## What This Dataset Contains

The dataset spans approximately fifteen seconds (00:28:33–00:28:48 UTC) and contains 84 events across three log sources.

**The technique executes in full and is clearly captured.** The Sysmon ProcessCreate chain (EID 1) shows the complete execution sequence:

- `whoami.exe` (tagged T1033) — ART test framework identity check
- `cmd.exe` with `CommandLine: "cmd.exe" /c reg query HKLM /f password /t REG_SZ /s & reg query HKCU /f password /t REG_SZ /s` (tagged T1059.003)
- `reg.exe` (PID 2464) with `CommandLine: reg  query HKLM /f password /t REG_SZ /s` (tagged T1012, Query Registry)
- `reg.exe` (PID 3232) with `CommandLine: reg  query HKCU /f password /t REG_SZ /s` (tagged T1012)

The eight-second gap between the two `reg.exe` invocations (00:28:37 vs 00:28:45) reflects the time required for the first query to complete its recursive search of `HKLM`. Both queries exit with status 0x0 per Security EID 4689.

Security EID 4688 independently confirms all four process launches with full command lines. EID 4703 (token right adjustment) appears for the SYSTEM account, which is routine for processes run under this context.

The PowerShell log contains the standard ART test framework boilerplate (EID 4104 script block fragments, EID 4103 `Set-ExecutionPolicy Bypass`) but no PowerShell cmdlets specific to the technique — the registry search is performed by the native `reg.exe` binary invoked via `cmd.exe`, not through PowerShell's registry provider.

## What This Dataset Does Not Contain (and Why)

**No registry query results.** `reg query` outputs to stdout; no file is written and there is no registry access auditing configured (`object_access: none`). The actual values found (or not found) are invisible in this dataset.

**No specific credential values.** Even if `HKLM\...\Winlogon\DefaultPassword` contained a value, the data here would only confirm that the query ran, not what it returned.

**No Sysmon ProcessCreate for the `cmd.exe` dispatch of `reg.exe`.** Sysmon's include-mode configuration captures `reg.exe` directly via the T1012 (Query Registry) rule, but `cmd.exe` appears because the T1059.003 (Windows Command Shell) rule catches it. Both are captured in this case; however, analysts should be aware that in other configurations `cmd.exe` might not appear in Sysmon.

**No process injection or suspicious module loads.** The technique uses only native binaries (cmd.exe, reg.exe) and requires no special modules.

## Assessment

This is a textbook registry credential enumeration capture. The critical signals — `reg.exe` command lines with `HKLM /f password /t REG_SZ /s` and `HKCU /f password /t REG_SZ /s` — are present in both Sysmon EID 1 and Security EID 4688 with full command-line detail. The Sysmon rule tagging both events as T1012 (Query Registry) is accurate. The fifteen-second window reflects the real cost of a full recursive HKLM search. The dataset contains minimal extraneous events, making it well-suited for detection rule development and testing.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `reg.exe` launched with `/f password /t REG_SZ /s` is a near-definitive indicator. Legitimate applications do not typically perform recursive password searches of HKLM or HKCU.
- **Sysmon EID 1 (T1012 tag)**: The sysmon-modular config correctly tags these as Query Registry, providing an enriched event type for SIEM correlation.
- **Security EID 4688**: `cmd.exe /c reg query HKLM /f password /t REG_SZ /s & reg query HKCU /f password /t REG_SZ /s` — the ampersand-chained dual-hive search is a classic pattern associated with multiple offensive tools.
- **Sequence detection**: Two sequential `reg.exe` processes with the same `/f password /t REG_SZ /s` flags targeting different hives within seconds of each other from the same parent process is a strong behavioral sequence.
- **Parent process**: `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` running as SYSTEM in a non-interactive session is an unusual process tree for legitimate registry queries.
- **Timing**: The ~8-second duration of the HKLM query reflects a real system with a populated registry. Detections based on duration thresholds (reg.exe running for more than a few seconds) could complement command-line matching.
