# T1489-3: Windows — Stop Service by Killing Process

## Technique Context

T1489 (Service Stop) via direct process termination (`taskkill`) bypasses the Service Control Manager entirely. Rather than requesting a graceful stop through the SCM API, an attacker kills the service host process directly with `taskkill /f /im`. This approach is more disruptive — it does not trigger graceful shutdown handlers — and is used when services are configured to reject SCM stop requests (many security products set their service to not accept stop commands). `taskkill /f` (force kill) is a recognized technique for bypassing service protection, and it produces a characteristic Windows System EID 7031 ("Service terminated unexpectedly") because the SCM detects the unexpected process exit.

## What This Dataset Contains

The test kills `spoolsv.exe` (Print Spooler service process) using `taskkill /f /im spoolsv.exe`. Security EID 4688 captures the full chain:

- `powershell.exe` spawns `cmd.exe /c taskkill.exe /f /im spoolsv.exe`
- `cmd.exe` spawns `taskkill.exe /f /im spoolsv.exe`

Sysmon EID 1 captures both: cmd.exe (tagged `technique_id=T1083`) and taskkill.exe (tagged `technique_id=T1489,technique_name=Service Stop` — the strongest direct technique tag in this group of datasets). Both taskkill.exe and spoolsv.exe exit with code `0x1`, and Security EID 4689 confirms spoolsv.exe termination.

System EID 7031 records the unexpected service termination:
> "The Print Spooler service terminated unexpectedly. It has done this 1 time(s). The following corrective action will be taken in 5000 milliseconds: Restart the service."

This is the only dataset in this group that generates a System channel service failure event — a detection source that is unique to the force-kill approach.

The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

No EID 4697 (service registration change) events are present — force-killing a process does not modify the service's registry configuration. There is no Sysmon EID 1 for `spoolsv.exe` being launched by the SCM in recovery (the restart action in 7031 would happen 5 seconds after the kill, likely outside the dataset's collection window). There are no privilege escalation events — the test runs as SYSTEM and force-killing `spoolsv.exe` does not require elevated privilege beyond what SYSTEM already has.

## Assessment

This is the strongest of the three T1489 datasets for detection engineering purposes because it produces a distinctive System channel event (EID 7031) that is absent from the sc.exe and net.exe variants. The combination of taskkill.exe process creation (Security 4688, Sysmon EID 1 with T1489 tag) and System EID 7031 ("terminated unexpectedly") creates a two-source correlated detection that is highly reliable. The sysmon-modular rule explicitly tagged this as T1489, indicating the ruleset has specific coverage for taskkill against service processes.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1**: `taskkill.exe /f /im` targeting a known service process executable — direct detection, explicitly tagged `technique_id=T1489` by sysmon-modular.
2. **Security EID 4688**: `taskkill.exe` with `/f` (force) and `/im <service_exe>` arguments — command-line detection for forced process termination against service hosts.
3. **System EID 7031**: "Service terminated unexpectedly" — high-fidelity signal unique to the force-kill approach, absent from graceful stop via sc or net.
4. **System EID 7031 + Sysmon EID 1 correlation**: taskkill.exe execution followed within seconds by a 7031 event for the targeted service — causal chain confirming the kill was effective.
5. **Security EID 4688**: `cmd.exe /c taskkill.exe /f /im` from a `powershell.exe` parent — scripted force-kill pattern; unusual in normal operations.
6. **Security EID 4689**: spoolsv.exe (or other service process) terminating with exit code `0x1` (killed) rather than `0x0` (graceful) — anomalous service exit code as a force-kill indicator.
