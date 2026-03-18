# T1562.006-5: Indicator Blocking — Disable PowerShell ETW Provider - Windows

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) covers adversary actions that prevent defensive tools
from capturing telemetry. Disabling the PowerShell ETW provider removes visibility into PowerShell
command execution for tools that rely on ETW-based logging rather than the Windows PowerShell
Operational channel. This technique is used by ransomware operators and post-exploitation
frameworks to suppress script execution logging before running malicious payloads.

The ETW provider for PowerShell (`Microsoft-Windows-PowerShell`) feeds the Event Log session
`EventLog-Application`. Removing this provider from the trace session silences ETW consumers
without touching the PowerShell Operational log channel itself.

## What This Dataset Contains

The test launches PsExec under SYSTEM context to run `logman` and remove the PowerShell ETW
provider from the `EventLog-Application` trace session:

```
cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\pstools\PsExec.exe"
  -accepteula -i -s cmd.exe /c logman update trace "EventLog-Application"
  --p "Microsoft-Windows-Powershell" -ets
```

The Security log (EID 4688) records the process chain: `powershell.exe` → `cmd.exe` → PsExec
invocation with full command-line arguments. Sysmon EID 1 captures the same chain with parent
process context. The PowerShell Operational log (EID 4104) records the exact scriptblock
dispatched by the ART test framework, making the intent unambiguous.

Sysmon EID 7 (ImageLoad) fires for DLLs loaded by the PowerShell process with rule annotations
`technique_id=T1055,technique_name=Process Injection` and `technique_id=T1059.001` — these are
from the sysmon-modular configuration matching PowerShell DLL load patterns.

## What This Dataset Does Not Contain (and Why)

No PsExec process creation appears in Sysmon EID 1. The sysmon-modular configuration uses
include-mode filtering for ProcessCreate; PsExec is not in the LOLBin/suspicious-process
include list, so it does not generate a Sysmon event. Security EID 4688 covers it via
audit policy. There is no Sysmon EID 13 (registry modification) because `logman` modifies
trace session state through the ETW API, not the registry. No network events are present;
PsExec is run locally. There are no logon events beyond the ambient SYSTEM logon token.

## Assessment

The test executed its payload successfully. The critical forensic evidence is in Security
EID 4688: the full `logman update trace ... --p "Microsoft-Windows-Powershell" -ets` command
line is captured verbatim. The ART test framework executed as `NT AUTHORITY\SYSTEM`, which is
reflected consistently across all sources. This dataset provides clean, matched telemetry
across three log sources with clear chain-of-custody for the entire process tree.

The PowerShell boilerplate blocks (EID 4104 fragments for `Set-StrictMode` and error handling
overhead) are test framework artifacts and represent the standard ART execution wrapper, not
attacker code.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `logman.exe` or `cmd.exe` command lines containing `logman update
  trace` with `--p` and `-ets` flags targeting PowerShell ETW providers.
- **Sysmon EID 1**: Same command line in process create events with parent process context.
- **PowerShell EID 4104**: Scriptblock containing `PsExec.exe` combined with `logman update
  trace` and `Microsoft-Windows-Powershell` string — the full ART payload is captured
  because the technique had not yet succeeded at logging time.
- **Process ancestry**: `powershell.exe` → `cmd.exe` → PsExec-spawned `cmd.exe` running
  `logman` is an unusual chain that warrants investigation in any environment.
