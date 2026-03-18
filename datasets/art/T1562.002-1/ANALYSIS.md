# T1562.002-1: Disable Windows Event Logging — Disable Windows IIS HTTP Logging

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test disables HTTP access logging on IIS using `appcmd.exe`, the IIS command-line administration tool. Disabling IIS HTTP logging prevents web server access records from being written, erasing evidence of web-based delivery, exploitation, or C2 activity served through IIS. The command sets the `dontLog` flag to `true` on the default web site's `httpLogging` configuration section.

## What This Dataset Contains

The dataset captures 91 events across Sysmon (36), Security (10), and PowerShell (45) channels over a six-second window.

**PowerShell 4104 (script block logging)** records the exact command:

```
C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true
```

This appears twice — once as the outer ART test framework invocation wrapper (`& { ... }`) and once as the inner block.

**Sysmon Event ID 1 (process create)** captures two relevant processes:
- `whoami.exe` (rule: `T1033`) confirming SYSTEM execution context
- `powershell.exe` (rule: `T1059.001`) with the full command line including the `appcmd.exe` invocation

The fact that `appcmd.exe` itself does not appear as a Sysmon Event ID 1 is expected — the sysmon-modular include-mode filter does not have a rule matching `appcmd.exe`, and it is launched as a child of PowerShell rather than being directly invoked.

**Security 4688** records `powershell.exe` creation under `NT AUTHORITY\SYSTEM`. The command-line field in the 4688 event includes the partial `appcmd.exe` invocation (truncated to ~256 characters by the field length limit). Security 4689 records exit status `0x0` for both powershell.exe and conhost.exe, confirming successful execution.

**PowerShell 4103 (module logging)** does not record an `appcmd.exe` invocation directly because `appcmd.exe` is a native executable, not a cmdlet. The 4103 events are limited to `Set-ExecutionPolicy` (test framework boilerplate) and the ART test framework infrastructure.

## What This Dataset Does Not Contain (and Why)

There is no Sysmon Event ID 1 for `appcmd.exe`. The sysmon-modular include-mode ProcessCreate filter does not include `appcmd.exe` or `inetsrv` path patterns. Security 4688 provides the gap coverage here, as it logs all process creations regardless of Sysmon rules.

There are no IIS-specific event log entries. IIS does not write to the Windows event log for logging configuration changes — the change takes effect in IIS configuration files (`applicationHost.config`) without generating a Windows event. Object access auditing is disabled in this environment, so no 4656/4663 events appear for the configuration file modification.

Windows Defender did not block this action. `appcmd.exe` is a signed Microsoft binary performing a legitimate administrative function, and this specific configuration change does not trigger behavioral detections.

## Assessment

The technique executed successfully. The Security 4689 exit status of `0x0` for PowerShell confirms the command completed without error. IIS HTTP logging on the default web site is disabled. This is a low-noise technique when executed through a signed Microsoft tool, and its primary detection surface is in the process command line rather than any dedicated audit event.

Note that this technique is only meaningful on systems where IIS is installed and running. On a workstation, the impact is limited, but the telemetry pattern would be identical on a server.

## Detection Opportunities Present in This Data

- **Security 4688 (process create with command line):** `appcmd.exe` with arguments `set config` + `/section:httplogging` + `/dontLog:true` is a high-fidelity detection. This command has no legitimate routine use case and should be treated as an anomaly.
- **PowerShell 4104:** The script block containing `appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true` is captured verbatim and detectable by keyword matching on `dontLog:true` or `httplogging`.
- **Sysmon 1 (process create):** `powershell.exe` launched as SYSTEM (LogonId `0x3E7`) with `appcmd.exe` in the command line is visible from the Sysmon PowerShell process create, though `appcmd.exe` itself is not captured by Sysmon in this configuration.
- **Parent-child relationship:** Any process create where `appcmd.exe` is the child of `powershell.exe` or `cmd.exe` in a non-administrative maintenance context should be investigated.
