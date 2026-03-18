# T1562.010-3: Downgrade Attack — PowerShell Version 2 Downgrade

## Technique Context

MITRE ATT&CK T1562.010 (Downgrade Attack) includes using legacy PowerShell versions to
bypass modern security controls. PowerShell version 2 predates Script Block Logging (EID 4104),
AMSI integration, Constrained Language Mode, and other script-level security features
introduced in PowerShell 3.0 and later. Invoking `powershell.exe -version 2` forces the
engine to load version 2 if the .NET 2.0/3.5 runtime is present, executing scripts without
the logging protections available to modern PowerShell. Threat actors have used this to run
Mimikatz, Empire, and other in-memory tools while avoiding script block logging.

## What This Dataset Contains

The test attempts to launch PowerShell v2 running `Invoke-Mimikatz`:

```
PowerShell -version 2 -command 'Invoke-Mimikatz'
```

Security EID 4688 records the outer `powershell.exe` process containing this command.
Sysmon EID 8 (CreateRemoteThread) fires, showing `powershell.exe` creating a remote thread
in an unknown process — consistent with Windows Defender blocking the v2 engine load and
the process exiting before Sysmon resolves its image name.

Sysmon EID 7 (ImageLoad) records multiple DLLs loaded by the outer PowerShell process,
with rule annotations for T1055 (Process Injection) and T1059.001 (PowerShell) from
sysmon-modular — these reflect the standard PowerShell DLL set, not additional malicious
loading.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 1 for a PowerShell v2 child process appears. Windows Defender (fully active,
signature version `1.445.536.0`) blocked the `Invoke-Mimikatz` invocation. The `-version 2`
flag itself is not sufficient to bypass AMSI in all configurations; Defender's behavior
monitoring intercepted the `Invoke-Mimikatz` command before a separate v2 process completed
launch. The `0xC0000022` (Access Denied) status would typically accompany such a Defender
block, though the specific process exit code is not exposed in the events in this dataset.

No Mimikatz-related activity (LSASS access, credential dump, etc.) is present because the
attempt was blocked before execution. No EID 4104 scriptblock for `Invoke-Mimikatz` exists
because the v2 engine, if launched, does not generate script block log events.

## Assessment

This dataset primarily documents the attempt pattern rather than a successful downgrade.
The most valuable event is Security EID 4688 capturing `PowerShell -version 2 -command
'Invoke-Mimikatz'` — this exact string in a process command line is a strong indicator
regardless of execution success. The Sysmon EID 8 CreateRemoteThread is consistent with
Defender intervention during process initialization.

In environments where PowerShell v2 is not disabled (Windows feature
`MicrosoftWindowsPowerShellV2Root` can be removed), this technique would succeed and produce
no EID 4104 events for the v2 session, leaving a telemetry gap. The absence of EID 4104 for
a `powershell -version 2` process is itself a detection signal.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `powershell.exe` command line containing `-version 2` (or `-v 2`,
  `-ver 2`) combined with `-command` or `-encodedcommand` arguments.
- **Sysmon EID 1**: Same PowerShell v2 invocation with parent process context.
- **Absence-based detection**: A `powershell.exe -version 2` process create (EID 4688) with
  no corresponding EID 4104 from that process — script block logging is silent for v2,
  making its absence under an active session an anomaly.
- **Sysmon EID 8**: CreateRemoteThread from `powershell.exe` during a v2 downgrade attempt
  is consistent with Defender intervention and should be correlated with the triggering
  process command line.
