# T1548.002-4: Bypass User Account Control — Bypass UAC using Fodhelper - PowerShell

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that silently elevate a process
to high integrity without prompting the user. This test is the PowerShell-native variant
of the Fodhelper bypass: instead of shelling out to `cmd.exe` and `reg.exe`, the payload
uses PowerShell cmdlets (`New-Item`, `New-ItemProperty`, `Set-ItemProperty`,
`Start-Process`) to manipulate `HKCU\Software\Classes\ms-settings\shell\open\command`
directly from the PowerShell provider. The technique is mechanically identical to test 3
but generates a richer PowerShell log trail because the registry operations are performed
natively in-process.

## What This Dataset Contains

The dataset spans roughly six seconds of telemetry (00:04:04–00:04:10 UTC).

**Security 4688 — PowerShell child process carrying the payload:**
```
"powershell.exe" & {
  New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
  New-ItemProperty ... -Name "DelegateExecute" -Value "" -Force
  Set-ItemProperty ... -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
  Start-Process "C:\Windows\System32\fodhelper.exe"
}
```
Token elevation type: `TokenElevationTypeDefault (1)`, Mandatory Label `S-1-16-16384`
(System). The ART test framework launches a second PowerShell process to execute the payload
block.

**PowerShell 4104 (script block logging) — full payload captured:**
The two 4104 events record the exact block above. Module logging (4103) captures each
individual cmdlet invocation with parameters, providing granular evidence of the registry
manipulation sequence.

**Sysmon Event 13 (registry value set) — two writes confirmed:**
```
HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\DelegateExecute = (Empty)
HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\(Default) = C:\Windows\System32\cmd.exe
```
These are the most direct indicators of the Fodhelper bypass pattern in Sysmon data.
Note the path appears as `HKU\.DEFAULT\` because the test runs under NT AUTHORITY\SYSTEM,
whose HKCU maps to `HKU\.DEFAULT`.

**Sysmon Event 1 — `whoami.exe` pre-check and PowerShell payload process:**
Two process-create events: the ART pre-check `whoami.exe` (IntegrityLevel=System, parent
`powershell.exe`) and the payload PowerShell child (RuleName: T1059.001).

**Application Event ID 15:**
`Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — a routine
Defender health-check event logged after the test. Defender remained active throughout.

## What This Dataset Does Not Contain (and Why)

- **`fodhelper.exe` process create.** The Sysmon include-mode filter did not match
  `fodhelper.exe` in this event window, and Defender's behavior monitoring likely
  terminated the elevated child before a 4688 was generated.
- **The elevated `cmd.exe` payload executing.** Unlike test 3, no `0xC0000022` exit
  code appears — the Security log does not show `fodhelper.exe` launching an elevated
  `cmd.exe` at all in the bundled window. The technique may have been blocked at the
  `fodhelper.exe` launch stage.
- **Registry key deletion (cleanup).** ART's per-test cleanup removes the
  `ms-settings` key afterward; this is outside the telemetry window.
- **Network or credential activity.** No lateral movement or credential access
  occurred; the test is purely a local elevation attempt.

## Assessment

This is a high-value dataset for the PowerShell-based Fodhelper bypass. The combination
of full script block logging (4104), module-level parameter logging (4103), and Sysmon
registry write events (Event 13) provides multiple corroborating layers of evidence for
the technique. The Sysmon Event 13 entries are particularly useful because they show the
exact registry key and value written, making correlation with the `DelegateExecute`
pattern straightforward.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** Script block containing `ms-settings\shell\open\command`,
  `DelegateExecute`, and `Start-Process fodhelper.exe` — direct detection of the
  technique.
- **PowerShell 4103:** Individual `New-ItemProperty` call with `DelegateExecute`
  parameter visible; detectable even if 4104 is absent.
- **Sysmon Event 13:** Registry write to `*\ms-settings\shell\open\command\DelegateExecute`
  — one of the most reliable Fodhelper detection signatures.
- **Security 4688:** Child `powershell.exe` spawned by `powershell.exe` with a script
  block argument containing `New-Item`/`fodhelper` — suspicious PowerShell process
  lineage.
- **Sysmon Event 1 (T1059.001 rule):** Sysmon's own ruleset tagged the payload
  PowerShell child, indicating the config actively matches this pattern.
