# T1562.002-2: Disable Windows Event Logging — Disable Windows IIS HTTP Logging via PowerShell

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test achieves the same outcome as T1562.002-1 (disabling IIS HTTP logging) but uses a native PowerShell cmdlet rather than `appcmd.exe`. The `Set-WebConfigurationProperty` cmdlet from the `WebAdministration` module writes directly to IIS configuration, setting `dontLog = $true` on the `system.webServer/httpLogging` section for the default web site. This approach leaves no child process to detect — the entire action occurs within the PowerShell process.

## What This Dataset Contains

The dataset captures 102 events across Sysmon (46), Security (10), and PowerShell (46) channels over a six-second window.

**PowerShell 4104 (script block logging)** records the exact command:

```
set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\" -filter "system.webServer/httpLogging" -name dontLog -value $true
```

This appears twice — the outer test framework invocation wrapper and the inner block.

**PowerShell 4103 (module logging)** captures `CommandInvocation(Set-ExecutionPolicy)` (test framework boilerplate) but does not independently record the `Set-WebConfigurationProperty` invocation as a separate 4103 entry, as the cmdlet executes within the same scope as the block logged by 4104.

**Sysmon Event ID 1** captures `whoami.exe` (rule: `T1033`) and `powershell.exe` (rule: `T1059.001`). Unlike T1562.002-1, there is no child process beyond PowerShell itself — `Set-WebConfigurationProperty` is an in-process operation. Sysmon also records extensive image loads (Event ID 7) for the PowerShell process including DLLs tagged with rules `T1055` and `T1574.002`, and a named pipe (Event ID 17, `\PSHost.*`). A process access event (Event ID 10, rule `T1055.001`) shows the ART test framework PowerShell touching the child PowerShell process.

**Security 4688/4689** records process creation and exit for `powershell.exe` and `conhost.exe` under `NT AUTHORITY\SYSTEM`. Exit status `0x0` confirms successful execution. The 4688 command line includes the `set-WebConfigurationProperty` invocation.

## What This Dataset Does Not Contain (and Why)

There is no child process for any IIS tool — the entire operation runs inside PowerShell. No `appcmd.exe`, `iisreset.exe`, or other IIS administration binary appears.

There are no IIS configuration file modification events. The `applicationHost.config` change happens through the `WebAdministration` module's COM interface to WAS (Windows Activation Service) without generating Windows event log entries. Object access auditing is disabled here, so no file system audit events appear.

No Sysmon Event ID 13 (registry value set) appears for IIS configuration — IIS logging state is stored in XML configuration files, not the registry.

Windows Defender did not interfere with this action. Loading the `WebAdministration` module and calling its cmdlets is indistinguishable from routine IIS administration.

## Assessment

The technique executed successfully, as confirmed by the `0x0` exit status on PowerShell and the absence of any error output in the PowerShell logs. This variant is slightly more evasion-oriented than T1562.002-1 because it produces no child process, reducing the number of detection points available. The primary detection surface is the PowerShell script block log.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** The script block containing `set-WebConfigurationProperty` with `dontLog` set to `$true` is the highest-fidelity signal in this dataset. The string `dontLog` combined with `httpLogging` or `WebConfigurationProperty` is a reliable detection.
- **PowerShell 4103 / 4688:** The command line visible in both sources shows the `set-WebConfigurationProperty` call targeting IIS logging. Alerting on `WebConfigurationProperty` + `dontLog` + `$true` in command-line telemetry would catch this technique.
- **Sysmon 1 (process create):** `powershell.exe` as SYSTEM (LogonId `0x3E7`) executing IIS-related cmdlets is anomalous on a workstation and should trigger investigation in most environments.
- **Module load correlation:** Sysmon 7 events show the `WebAdministration` module DLLs loading into a SYSTEM-context PowerShell process. Monitoring for IIS management module loads in non-interactive SYSTEM sessions can surface this pattern.
