# T1569.002-8: Service Execution — Pipe Creation - PsExec Tool Execution From Suspicious Locations

## Technique Context

T1569.002 (Service Execution) covers adversary use of the Service Control Manager to
execute programs. PsExec (Sysinternals) functions by copying itself to the target,
installing a service (`PSEXESVC`), and executing commands through it. This ART test
focuses on a specific detection pattern: PsExec executed from a non-standard location
(`C:\Users\Public\Temp\`). Executing remote administration tools from user-writable
directories rather than `C:\Windows\System32\` or administrative paths is a common
lateral movement tactic and the basis of numerous detection rules. The test invokes
`PsExec.exe -i -s cmd -accepteula` locally under SYSTEM, simulating the attacker having
already dropped PsExec to a staging directory.

## What This Dataset Contains

**Sysmon EID 1** — PowerShell process create with the PsExec invocation:

> `CommandLine: "powershell.exe" & {cd C:\Users\Public\Temp\ .\PsExec.exe -i -s cmd -accepteula}`
> `User: NT AUTHORITY\SYSTEM`

This reveals the staging directory (`C:\Users\Public\Temp\`) and the `-accepteula` flag
commonly used in automated attack tooling to suppress interactive prompts.

**Sysmon EID 17** — named pipe creations for three PowerShell host processes:

> `PipeName: \PSHost.134179723182198744.5912.DefaultAppDomain.powershell`
> `PipeName: \PSHost.134179723214434449.1812.DefaultAppDomain.powershell`
> `PipeName: \PSHost.134179723226015671.4684.DefaultAppDomain.powershell`

The ART test name references "Pipe Creation" as the detection focus — a PsExec execution
creates the named pipe `\PSEXESVC` as part of its service communication. However, in
this dataset the only named pipe events captured are the standard PowerShell host pipes
from the test framework processes. The actual PSEXESVC pipe was not captured, likely because
Windows Defender blocked PsExec execution before the service pipe was created.

**Sysmon EID 11** — file creates in `C:\Windows\System32\config\systemprofile\AppData\
Local\Microsoft\Windows\PowerShell\StartupProfileData-*` by the PowerShell processes.

**Sysmon EID 7** — DLL image loads for PowerShell processes, tagged with `T1055`,
`T1059.001`, and `T1574.002` rule names.

**Security EID 4688/4689** — process creation/exit for `powershell.exe` and `whoami.exe`
under SYSTEM. Notably, there is no 4688 for `PsExec.exe` itself.

**PowerShell EID 4104** — script block logs capturing the test payload:

> `{cd C:\Users\Public\Temp\ .\PsExec.exe -i -s cmd -accepteula}`

and ART test framework boilerplate blocks (`Set-StrictMode`, error handler fragments).

## What This Dataset Does Not Contain (and Why)

**No PSEXESVC named pipe or service installation.** Windows Defender blocked PsExec
before it could install the PSEXESVC service or create the characteristic `\PSEXESVC`
named pipe. The test name targets this pipe as a detection signal, but the pipe does
not appear. Defender 4.18.26010.5 with current signatures detects PsExec from
non-standard locations as suspicious.

**No Security EID 4688 for PsExec.exe.** Defender's process creation block prevents
the process from appearing in audit logs. The attempt is visible only through the
PowerShell command line that invoked it.

**No System EID 7045** (service install). PsExec installs `PSEXESVC` as a temporary
service, but Defender blocked execution before this stage.

**No Sysmon EID 25 (process tampering).** Block-level interference by Defender does
not always generate Sysmon process events; the absence of a Sysmon EID 1 for PsExec.exe
despite the PowerShell launch command confirms the block.

## Assessment

This dataset captures the attempt telemetry for PsExec execution from a suspicious
location. The definitively useful signals are in the PowerShell script block (EID 4104)
and the Security EID 4688 command line for the parent PowerShell process. The PsExec
pipe creation that gives this test its name is absent because Defender blocked execution.
The dataset is valuable for training detectors on the pre-execution pattern (staging
path + command line) rather than the execution artifact (PSEXESVC pipe/service).

## Detection Opportunities Present in This Data

- **PowerShell EID 4104** — `PsExec.exe` invocation from `C:\Users\Public\` or any
  world-writable path is captured in script block logging even when the binary is
  subsequently blocked; this provides detection independent of process execution success.
- **Security EID 4688 / Sysmon EID 1** — PowerShell command line containing `PsExec`
  with a path outside `System32` or standard tool directories.
- **Path-based detection** — `C:\Users\Public\Temp\` as a working directory for
  `powershell.exe` under SYSTEM is anomalous; `C:\Windows\TEMP` is more typical for
  SYSTEM-context scripting.
- **Sysmon EID 17** — in a successful PsExec execution, the `\PSEXESVC` named pipe
  would appear here; absence of this pipe combined with presence of the command line
  is itself evidence of a Defender block and can be used as a block-confirmation signal.
- **`-accepteula` flag** — automated use of this PsExec flag is a common indicator
  of tooling rather than interactive use; it appears in both the 4104 script block
  and the 4688 command line.
