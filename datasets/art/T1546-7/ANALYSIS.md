# T1546-7: Event Triggered Execution — Persistence via Custom DLL During RDP Session

## Technique Context

The Remote Desktop Services (RDS) Dynamic Virtual Channel (DVC) Plugin mechanism allows DLLs to be loaded by `svchost.exe` (TermService) whenever an RDP session is established. The registry key `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\<name>\Path` registers a DLL as a DVC plugin, which is then loaded into the RDP service process at session creation. This is a privileged persistence mechanism: the DLL runs in a SYSTEM-level service process and is triggered by any incoming RDP connection — including automated management connections from IT tools. Defenders monitor for new subkeys under the `Terminal Server\AddIns` path, unexpected DLL registrations, and DLL loads from non-standard paths by TermService.

## What This Dataset Contains

The attack registers `amsi.dll` (a benign system DLL used as a placeholder) as a DVC plugin named `TestDVCPlugin` using `reg.exe` through a `cmd.exe` wrapper. All process create and command line evidence is present.

**Sysmon EID=1 — `cmd.exe` process create:**
`"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\TestDVCPlugin" /v Path /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f`
Parent: `powershell.exe`, user `NT AUTHORITY\SYSTEM`. RuleName: `technique_id=T1083,technique_name=File and Directory Discovery` (the sysmon-modular cmd.exe rule fires on any cmd.exe with `/c`).

**Sysmon EID=1 — `reg.exe` process create:**
`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\TestDVCPlugin" /v Path /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f`
Parent: `cmd.exe`. The full registry path and the DLL path are visible in the command line.

**Security 4688:** Both `cmd.exe` and `reg.exe` process creations recorded with full command lines under SYSTEM.

**No Sysmon EID=13:** The Terminal Server AddIns path is not covered by the sysmon-modular registry monitoring rules, so the write is only visible through the `reg.exe` command line. The key creation (EID=12) was also not captured.

## What This Dataset Does Not Contain

- No Sysmon EID=13 (RegistryValueSet) for `Terminal Server\AddIns\TestDVCPlugin\Path` — the sysmon-modular config lacks a rule for this path.
- No Sysmon EID=12 (RegistryKeyCreate) — the key creation under `AddIns` was not captured.
- No trigger event — no RDP session was established after the plugin was registered, so no DLL load (EID=7) for `amsi.dll` by TermService was observed.
- No PowerShell EID=4104 with technique content — the payload was executed via cmd.exe/reg.exe; the PowerShell channel contains only test framework boilerplate.
- No evidence of the DVC plugin actually executing — the dataset represents only the installation phase.

## Assessment

Similar to T1546-5, this dataset shows a case where the registry write is not directly captured by Sysmon but the `reg.exe` command line provides clear evidence of the technique. The `Terminal Server\AddIns` path in a `reg add` command is highly specific and rarely appears in legitimate operations. The dataset is useful for process-command-line based detection but lacks the registry telemetry and trigger phase data. Extending the sysmon-modular config with a rule for `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns` would close the Sysmon coverage gap. To complete the dataset, follow the plugin registration with an RDP session establishment to capture the DVC plugin DLL load by TermService.

## Detection Opportunities Present in This Data

1. **Sysmon EID=1 / Security 4688 — `reg.exe` command line containing `Terminal Server\AddIns` and `/v Path`**: Any registration of a new DVC plugin via `reg.exe` is a high-fidelity indicator. Legitimate DVC plugin registration is done by software installers, not by standalone `reg.exe` invocations.
2. **Sysmon EID=1 — `cmd.exe /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\<name>" /v Path`**: The wrapper cmd.exe with the full Terminal Server path is a specific, actionable pattern.
3. **Process chain — `powershell.exe` → `cmd.exe` → `reg.exe` writing to Terminal Server paths**: The three-step chain for an operation that could be done with a single PowerShell cmdlet suggests deliberate evasion of PowerShell script block logging.
4. **Baseline monitoring for `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\`**: New subkeys under this path are uncommon. Any new plugin registration that is not associated with a known software installation event warrants investigation.
5. **Sysmon EID=7 (when triggered) — DLL load by `svchost.exe` (TermService group) from `AddIns`-registered path**: When an RDP session is established, the registered DLL will be loaded by the RDP service host. A DLL load from an unexpected path in this context is the runtime detection signal.
