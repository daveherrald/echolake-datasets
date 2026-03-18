# T1489-2: Windows — Stop Service Using net.exe

## Technique Context

T1489 (Service Stop) via `net.exe stop` is a classic and widely-observed technique. `net stop` is one of the most commonly scripted service-stop commands seen in malware, ransomware batch scripts, and lateral movement playbooks. It differs from `sc stop` in that it routes through `net1.exe` as a subprocess, producing a distinctive two-process chain. The `net.exe` → `net1.exe` parent-child relationship is a well-known detection signal because `net1.exe` is rarely spawned by anything other than `net.exe` and serves no purpose other than executing `net` commands. Ransomware families such as Ryuk, Conti, LockBit, and REvil have all been observed running `net stop` commands against lists of backup and security services at scale.

## What This Dataset Contains

The test stops the Print Spooler service using `net.exe stop`. Security EID 4688 captures the full process chain:

- `powershell.exe` spawns `cmd.exe /c net.exe stop spooler`
- `cmd.exe` spawns `net.exe stop spooler`
- `net.exe` spawns `net1 stop spooler`

Sysmon EID 1 captures all three process-create events: cmd.exe (tagged `technique_id=T1059.003`), net.exe (tagged `technique_id=T1018`), and net1.exe (also tagged `technique_id=T1018`). All processes exit cleanly (`0x0`). Security EID 4689 records `spoolsv.exe` terminating normally, confirming successful service stop.

The `net.exe` → `net1.exe` chain is clearly visible in both Sysmon and Security channels. The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

As with T1489-1, the Windows System channel (which would contain EID 7036 "Service entered the stopped state") is not in this dataset's scope. No EID 4697 (service change) or registry change events for the service's configuration are present. The sysmon-modular tagging of `net.exe` and `net1.exe` as `T1018` (Remote System Discovery) rather than T1489 reflects a limitation in how the ruleset maps these tools — net.exe is multi-purpose and the tag reflects its network enumeration uses, not the service-stop use shown here.

## Assessment

This is a clean, complete dataset for the `net stop` pattern with the distinctive `net.exe` → `net1.exe` chain captured in both Sysmon and Security channels. The successful execution, confirmed service termination (spoolsv.exe exit 0x0), and multi-source coverage make this strong detection engineering material. The net.exe → net1.exe chain is particularly valuable because it is a reliable, low-false-positive indicator. Comparing this dataset directly with T1489-1 (sc.exe) is useful for demonstrating how the same technique maps to different tool chains and detection points.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1**: `net1.exe` spawned by `net.exe` — the net.exe→net1.exe parent-child chain is a reliable indicator of net command execution.
2. **Security EID 4688**: `net.exe stop <service_name>` with parent `cmd.exe` — command-line based service stop detection.
3. **Security EID 4688**: `net1.exe` with `stop <service_name>` arguments — complementary detection on the net1 subprocess.
4. **Sysmon EID 1**: `net.exe` (or `net1.exe`) spawned from `cmd.exe` spawned from `powershell.exe` — three-level scripted service stop chain; unusual in normal operations.
5. **Security EID 4688 + 4689 correlation**: net.exe invocation followed within seconds by the target service process (spoolsv.exe) termination — causal confirmation of successful stop.
6. **Sysmon EID 1**: net.exe or net1.exe targeting services on a watchlist (spooler, vss, WinDefend, MSSQL, etc.) — high-value target service name matching.
