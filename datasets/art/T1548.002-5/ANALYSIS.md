# T1548.002-5: Bypass User Account Control — PowerShell

## Technique Context

T1548.002 (Bypass User Account Control) covers methods of silently elevating to high
integrity. This test substitutes `ComputerDefaults.exe` for `fodhelper.exe` as the
auto-elevating launcher, while keeping the same registry manipulation: writing a command
handler and `DelegateExecute` marker to
`HKCU\Software\Classes\ms-settings\shell\open\command`. Both `fodhelper.exe` and
`ComputerDefaults.exe` are manifested as auto-elevate binaries; both read from the same
HKCU path before launching. Using `ComputerDefaults.exe` sidesteps simple string-match
rules written specifically for `fodhelper.exe`.

The payload is delivered via a PowerShell child process, identical in structure to test 4
except for the final `Start-Process` target.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:04:24–00:04:29 UTC).

**Security 4688 — PowerShell payload process:**
```
"powershell.exe" & {
  New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
  New-ItemProperty ... -Name "DelegateExecute" -Value "" -Force
  Set-ItemProperty ... -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
  Start-Process "C:\Windows\System32\ComputerDefaults.exe"
}
```
Token elevation type: `TokenElevationTypeDefault (1)`. Parent: the ART test framework
`powershell.exe`.

**PowerShell 4104 — script block logging captures full payload:**
Two events record the identical block, showing the `ComputerDefaults.exe` substitution
explicitly. Module logging (4103) records `New-Item`, `New-ItemProperty`, and
`Set-ItemProperty` invocations with full parameter bindings.

**Sysmon Event 13 — registry writes confirmed:**
```
HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\DelegateExecute = (Empty)
HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command\(Default) = C:\Windows\System32\cmd.exe
```
These are the same writes as test 4 — the registry path is unchanged. Only the binary
that reads the path differs.

**Sysmon Event 1 — process creates:**
`whoami.exe` (pre-check, IntegrityLevel=System) and the payload `powershell.exe`
(RuleName: T1059.001). The payload child is tagged by the Sysmon ruleset.

**Security 4703 (token rights adjusted):**
`powershell.exe` has high-privilege rights enabled
(`SeBackupPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege`, etc.), consistent
with running under SYSTEM.

## What This Dataset Does Not Contain (and Why)

- **`ComputerDefaults.exe` process create.** The Sysmon include-mode filter does not
  explicitly list `ComputerDefaults.exe`, and the elevated child was not captured in the
  bundled event window.
- **Elevated `cmd.exe` payload executing.** No `0xC0000022` exit code appears and no
  elevated `cmd.exe` launch is recorded. Defender or the elevation mechanism prevented
  the payload from running; the test captures the attempt only.
- **Differences from test 4.** Aside from the `ComputerDefaults.exe` substitution in
  the PowerShell script block, the two datasets are structurally identical. The
  registry manipulation path is the same; only the trigger binary differs.
- **Registry cleanup events.** ART cleanup removes the `ms-settings` key after the test.

## Assessment

This dataset demonstrates that the `ms-settings\shell\open\command` + `DelegateExecute`
registry pattern is the invariant detection surface across both the Fodhelper and
ComputerDefaults bypass variants. Detections written against the registry key path will
catch both; detections written only against `fodhelper.exe` process creation will miss
this variant. The PowerShell script block and module logs provide rich, multi-layer
evidence.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** Script block containing `ms-settings\shell\open\command`,
  `DelegateExecute`, and `ComputerDefaults.exe` — extends Fodhelper-specific rules to
  cover this variant.
- **PowerShell 4103:** `New-ItemProperty` with `DelegateExecute` parameter binding —
  detectable independent of the trigger binary name.
- **Sysmon Event 13:** Write to `*\ms-settings\shell\open\command\DelegateExecute` —
  the common indicator across all ms-settings UAC bypass variants.
- **Security 4688:** Child `powershell.exe` spawned from `powershell.exe` with inline
  block containing registry manipulation + `Start-Process` of an auto-elevating binary.
- **Process lineage:** `powershell.exe` → `powershell.exe` → `ComputerDefaults.exe`
  is anomalous; normal user invocations of `ComputerDefaults.exe` have an Explorer or
  svchost parent.
