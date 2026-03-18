# T1489-1: Windows — Stop Service Using Service Controller

## Technique Context

T1489 (Service Stop) describes adversary actions that disable or terminate critical services to disrupt operations, impair defenses, or facilitate further attack stages. Ransomware operators routinely stop backup services (VSS, Windows Backup), database services (SQL Server, MySQL), and endpoint security services before encryption to prevent file locking by those services and to disable recovery mechanisms. `sc.exe stop` is one of the most direct methods — it invokes the Service Control Manager API to request a graceful service stop. Defenders focus on `sc.exe stop` against high-value service names, especially when invoked at scale or from unusual parent processes.

## What This Dataset Contains

The test stops the Print Spooler service (`spooler`) using `sc.exe stop`. Security EID 4688 captures the full process chain:

- `powershell.exe` spawns `cmd.exe /c sc.exe stop spooler`
- `cmd.exe` spawns `sc.exe stop spooler`
- `spoolsv.exe` terminates (EID 4689)

Sysmon EID 1 captures both cmd.exe (tagged `technique_id=T1059.003`) and sc.exe (tagged `technique_id=T1543.003,technique_name=Windows Service`). The sc.exe process exits cleanly (`0x0`), confirming the service was successfully stopped. Security EID 4689 records `spoolsv.exe` terminating (`exit=0x0` — normal graceful shutdown triggered by SCM).

This is clean, complete execution telemetry: the command ran successfully, the service stopped, and both the invocation and the service termination are captured. The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

There is no Windows System channel event for the service stopping (such as EID 7036 "Service entered the stopped state") in the bundled data — the System channel was not included in this dataset's collection scope. No Security EID 4697 (service installed/modified) or 4657 (registry object changed for service parameters) events are present — object access auditing is disabled. The dataset targets only the Print Spooler as a demonstration service; detections built on this data should generalize to other high-value service names rather than being spooler-specific.

## Assessment

This is a high-quality, compact dataset for the `sc stop` pattern. All three key events are present: the initiating PowerShell context, the cmd.exe wrapper, the sc.exe invocation with command line, and the spoolsv.exe termination. Sysmon provides hash-enriched process creation with technique tagging. The successful execution (no Defender blocking, all exits 0x0) makes this a clean positive example. The primary limitation is the absence of System channel EID 7036, which many mature security stacks rely on as a service-stop detection point — adding the System channel to collection would significantly strengthen the dataset.

## Detection Opportunities Present in This Data

1. **Security EID 4688**: `sc.exe stop <service_name>` with parent `cmd.exe` spawned from `powershell.exe` — PowerShell-driven service stop, anomalous for most enterprise environments.
2. **Sysmon EID 1**: `sc.exe` spawned from `cmd.exe` with `stop` argument, tagged `T1543.003` — sysmon-modular confirms sc.exe matched service-manipulation rules.
3. **Security EID 4688 + 4689 correlation**: sc.exe process creation immediately followed by the target service process (spoolsv.exe) termination — causal chain confirming successful stop.
4. **Security EID 4688**: `cmd.exe /c sc.exe stop` pattern from a scripting host parent — batch/scripted service stop rather than interactive service management.
5. **Sysmon EID 1**: sc.exe with `stop` argument against services on a watchlist (spooler, MSSQL, vss, WinDefend, etc.) — high-value service stop detection.
6. **Security EID 4689**: Target service process terminating with exit code `0x0` in temporal proximity to an sc.exe invocation — correlation for service stop confirmation.
