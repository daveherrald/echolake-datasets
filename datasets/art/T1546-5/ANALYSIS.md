# T1546-5: Event Triggered Execution — Adding Custom Debugger for Windows Error Reporting

## Technique Context

Windows Error Reporting (WER) includes a `Hangs` debugger facility: when an application hangs, WER can automatically launch a debugger specified in `HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger`. Attackers abuse this by pointing the `Debugger` value to their payload, which then executes with elevated privileges whenever a hang is detected by the system. This is a variant of the broader "application debugger hijack" class of techniques (related to Image File Execution Options). The WER trigger is particularly useful for privilege escalation and persistence in environments where application crashes or hangs are common. Defenders monitor writes to `HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger`.

## What This Dataset Contains

The attack sets `notepad.exe` as the WER hang debugger using `reg.exe` through a `cmd.exe` wrapper. All key telemetry is present.

**Sysmon EID=1 — `cmd.exe` process create:**
`"cmd.exe" /c reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs" /v Debugger /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`
Parent: `powershell.exe`, user `NT AUTHORITY\SYSTEM`.

**Sysmon EID=1 — `reg.exe` process create:**
`reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs" /v Debugger /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`
Parent: `cmd.exe`. The sysmon-modular config captures `reg.exe` under `technique_id=T1012,technique_name=Query Registry`.

**Security 4688:** Both the `cmd.exe` and `reg.exe` process creations are recorded with full command lines under the SYSTEM account.

**No Sysmon EID=13:** The registry write via `reg.exe` was not captured as a registry value set event. The sysmon-modular config's registry monitoring does not appear to have a rule matching the WER Hangs key path, so the write is visible only through the `reg.exe` command line arguments, not as a direct registry telemetry event.

## What This Dataset Does Not Contain

- No Sysmon EID=13 for the `Hangs\Debugger` write — the registry monitoring config does not cover this WER path.
- No Security 4657 — registry object auditing is not enabled.
- No trigger event — no application hang occurred during the collection window to demonstrate the payload executing.
- No PowerShell EID=4104/4103 with technique content — the payload was executed via `cmd.exe` + `reg.exe`, so the PowerShell channel contains only test framework boilerplate.
- No file activity for the WER debugger binary (notepad.exe already exists, so no EID=11).

## Assessment

This dataset demonstrates a case where the registry write is not directly captured by Sysmon, but the `reg.exe` command line provides unambiguous evidence of the technique. The `reg add ... /v Debugger` targeting the `Windows Error Reporting\Hangs` key is a high-specificity indicator. For detection engineering, this highlights the importance of process command-line monitoring as a fallback when registry-level monitoring has gaps. The sysmon-modular config should be extended with a rule for the WER Hangs registry path. Alternatively, enabling Security audit for registry object access on this key would provide the equivalent of an EID=13. The dataset would be significantly enhanced by including a trigger event (inducing a process hang) to show the debugger payload actually executing.

## Detection Opportunities Present in This Data

1. **Security 4688 / Sysmon EID=1 — `reg.exe` command line containing `Windows Error Reporting\Hangs` and `/v Debugger`**: Any `reg add` or `reg.exe` invocation targeting this specific path is an immediate indicator, regardless of what value is set.
2. **Sysmon EID=1 — `cmd.exe /c reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs"`**: The wrapper cmd.exe invocation with the full reg add command is visible as a process create.
3. **Process chain — `powershell.exe` → `cmd.exe` → `reg.exe` with WER Hangs path**: The three-process chain for what could be a single PowerShell registry cmdlet suggests the attacker is explicitly using `reg.exe` to avoid PowerShell telemetry.
4. **Baseline monitoring for `HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger`**: This value should be absent on standard workstations. Any creation of the `Debugger` value in the WER Hangs key warrants immediate investigation.
5. **Sysmon EID=13 rule extension**: Adding the WER Hangs path to the Sysmon registry monitoring config would capture the write directly, providing structured data (TargetObject, Details) to supplement the command-line evidence.
