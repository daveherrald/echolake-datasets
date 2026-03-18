# T1652-1: Device Driver Discovery — Device Driver Discovery

## Technique Context

T1652 (Device Driver Discovery) covers adversary enumeration of installed drivers to identify security products, virtualization software, kernel-level defenses, or exploitable vulnerable drivers. Adversaries use driver discovery as part of pre-exploitation reconnaissance — identifying kernel-mode security tools to bypass, or finding drivers with known vulnerabilities for privilege escalation (BYOVD). The `driverquery` utility is a built-in Windows tool that lists all installed drivers with optional verbose output.

## What This Dataset Contains

This dataset captures two `driverquery` invocations run sequentially via a PowerShell-launched `powershell.exe` process, as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

The core payload script block logged in PowerShell EID 4104:
```
& {driverquery /v /fo list
driverquery /si /fo list}
```
The `/v` flag requests verbose output; `/fo list` formats as a list. The `/si` flag requests driver signature information — a detail specifically relevant to identifying unsigned or weakly signed drivers.

**Sysmon (42 events)** — EID 7 (image load) for the initial SYSTEM-context PowerShell DLL loads (Defender DLL tagged T1574.002, urlmon.dll); EID 17 (named pipe) for PSHost pipes; EID 10 (process access) tagged T1055.001; EID 1 (process create):
  - `whoami.exe` tagged `technique_id=T1033`
  - `powershell.exe` (test process) with full command line `"powershell.exe" & {driverquery /v /fo list\ndriverquery /si /fo list}` tagged `technique_id=T1059.001`
  - A second `powershell.exe` spawned as part of the test execution
- EID 7 for `WmiPrvSE.exe` loading urlmon.dll (incidental WMI provider activity)
- EID 11 (file create) events for the PowerShell startup profile

**Security log (14 events)** — EID 4688/4689 process lifecycle events for `whoami.exe` and the test PowerShell processes; EID 4703 token right adjustments. The provenance data notes 83 security events in the source window, with 14 included in the bundle after time-range filtering.

**PowerShell log (37 events)** — EID 4103 for `Set-ExecutionPolicy Bypass` and the standard test framework boilerplate EID 4104 stubs. The key script block with `driverquery` is captured in EID 4104. Note: the provenance data records 14,055 PowerShell events in the source window — an extremely large count that almost certainly reflects the verbose output of `driverquery /v` being written through a PowerShell pipeline and logged as EID 4104 fragments. Only 37 events are included in the bundled dataset after filtering for the relevant time window.

## What This Dataset Does Not Contain (and Why)

- **driverquery output** — The driver list returned by `driverquery /v /fo list` and `driverquery /si /fo list` is not captured in Windows event logs. The 14,055-event PowerShell source count suggests the output may have been piped through PowerShell and logged as script blocks, but the bundled dataset is filtered to the 37 most relevant events.
- **Sysmon ProcessCreate for driverquery.exe** — `driverquery` does not appear on the sysmon-modular include list, so no EID 1 for it appears. The Security 4688 log would cover it if the Security log window captured it; the 14 bundled security events focus on the PowerShell and whoami processes.
- **Kernel driver enumeration details** — The names, versions, and signing status of installed drivers are not visible in the event data.

## Assessment

The test completed successfully. The PowerShell EID 4104 script block captures both `driverquery` invocations including the `/si` (signature information) flag. The large source PowerShell event count (14,055) reflects the verbosity of `driverquery` output being processed through PowerShell's logging infrastructure. The Sysmon EID 1 for the test PowerShell process provides the full command line. The `/si` flag is particularly noteworthy for detection: it is specifically used to identify driver signing status, which is the reconnaissance step preceding BYOVD attacks.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / PowerShell EID 4104**: `driverquery` with `/v` and especially `/si` flags in a script block executed from SYSTEM PowerShell is a strong indicator of driver enumeration for offensive purposes.
- **Security EID 4688 / Sysmon EID 1**: A `powershell.exe` process spawned from `powershell.exe` (SYSTEM context) with an inline block containing `driverquery` is anomalous.
- **Volume indicator**: A sudden spike in PowerShell EID 4104 events (the 14,055 source-window count vs. a baseline) correlates with verbose command output being processed through PowerShell logging, which can serve as an anomaly detection trigger independent of command-line content.
- **`/si` flag correlation**: Pairing `driverquery /si` with subsequent network connections or file drops of known vulnerable driver binaries would indicate a BYOVD preparation sequence.
