# T1569.002-2: Service Execution — Use PsExec to Execute a Command on a Remote Host

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. PsExec (Sysinternals) is the canonical example: it
copies itself to the target, creates a service named `PSEXESVC`, starts it to execute the
specified command, and then deletes the service. PsExec has been used in APT campaigns,
ransomware deployments, and red team engagements for over a decade. Its telemetry footprint
is extensively documented: Service Installation EID 7045 on the target, network connections
to SMB (445/tcp), characteristic named pipe activity (`\PSEXESVC`), and process creation
from `services.exe`.

This test runs PsExec against `localhost`, exercising the local PsExec workflow with
hardcoded credentials (`DOMAIN\Administrator / P@ssw0rd1`) and `calc.exe` as the payload.
Running against localhost means all target-side artifacts appear on the same host.

In the defended variant, Windows Defender blocked PsExec execution. The `cmd.exe` wrapper
exited with `0x1`, no PSEXESVC service was installed, no EID 7045 appeared, and no named
pipe was created. The command line in Sysmon EID 1 revealed the full credential set and
target path. In this undefended dataset, PsExec executes against localhost.

## What This Dataset Contains

The dataset spans approximately 2 seconds (17:41:38–17:41:40 UTC) and contains 121 total
events across two channels.

**Security channel (14 events) — EIDs 4688, 4689, 4703:**

EID 4688 records capture the attack chain:

**Pre-flight `whoami.exe`:**
```
New Process Name: C:\Windows\System32\whoami.exe
Process Command Line: "C:\Windows\system32\whoami.exe"
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0x0
```

**`cmd.exe` PsExec wrapper:**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPay...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0x1
```

The `ExternalPay...` prefix continues as `loads\PsExec.exe` — the full command from the
defended Sysmon EID 1 is:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost
  -i -u DOMAIN\Administrator -p P@ssw0rd1 -accepteula "C:\Windows\System32\calc.exe"
```

This exposes: the PsExec binary location, the target (`\\localhost`), the credentials
(`DOMAIN\Administrator / P@ssw0rd1`), the `-accepteula` automation flag, and the payload
(`calc.exe`). The `0x1` exit status from `cmd.exe` indicates PsExec returned a non-zero
error code — likely because `\\localhost` remote execution requires SMB connectivity
configured in a way the test environment does not fully support, or the credential set was
rejected. The test still exercises the PsExec invocation pattern.

**Second `whoami.exe` (post-execution):**
```
Process Command Line: "C:\Windows\system32\whoami.exe"
Exit Status: 0x0
```

**Cleanup `cmd.exe`:**
```
Process Command Line: "cmd.exe" /c
Exit Status: 0x0
```

EID 4703 records SYSTEM token rights adjustment enabling `SeAssignPrimaryTokenPrivilege`,
`SeLoadDriverPrivilege`, `SeSecurityPrivilege`, and related elevated privileges.

**PowerShell channel (107 events) — EIDs 4104, 4103:**

The 104 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The PsExec invocation itself runs via `cmd.exe /c` and
does not generate 4104 script block records.

## What This Dataset Does Not Contain

**No System EID 7045 (service installation) for PSEXESVC.** If PsExec successfully installed
the PSEXESVC service on localhost, EID 7045 would appear in the System log. Its absence
(the System channel is not in this dataset) means either the service was not collected or
PsExec failed before reaching the service installation step. The `cmd.exe` exit code `0x1`
suggests PsExec did not fully execute the remote session.

**No Sysmon events.** The Sysmon channel is absent. In the defended dataset, Sysmon EID 1
provided the full PsExec command line including credentials, EID 10 showed PowerShell
accessing `cmd.exe`, EID 17 showed named pipe creation, and EID 7 showed DLL loads. None
of those appear in this undefended dataset. The Security channel's truncated EID 4688
command line is the only evidence of the PsExec invocation.

**No PsExec.exe process creation event.** Security EID 4688 captures `cmd.exe` as the
wrapper but not PsExec.exe itself as a child. PsExec.exe runs as a child of `cmd.exe`, and
the audit policy scope here does not capture it separately.

**No PSEXESVC named pipe or network events.** The characteristic `\PSEXESVC` named pipe
that PsExec creates for inter-process communication with the remote service does not appear
in any channel. Either PsExec failed before pipe creation, or the pipe event was not
collected.

## Assessment

This dataset is weaker than the defended variant for telemetry quality. The defended dataset
contained Sysmon EID 1 with the full, un-truncated PsExec command line (credentials
included), while this undefended dataset's EID 4688 provides only a truncated fragment.
The `0x1` exit code from `cmd.exe` indicates PsExec did not fully succeed against
`\\localhost` in this environment configuration, which is consistent with the absence of
downstream service and pipe artifacts.

The primary value of this dataset is the EID 4688 record showing `cmd.exe` wrapping a
PsExec invocation from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe` — the
path itself (a non-standard, user-accessible location) is an indicator independent of
whether PsExec succeeded.

## Detection Opportunities Present in This Data

**Security EID 4688 — `cmd.exe` launching from `ExternalPayloads\PsExec.exe`:** The path
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe` is a non-standard location.
Legitimate PsExec usage typically runs from `C:\Windows\System32\` or a controlled admin
path. PsExec execution from `%APPDATA%`, `%TEMP%`, `C:\Users\Public\`, or any
`\atomics\` path is a high-fidelity indicator of adversarial use.

**Security EID 4688 — `-accepteula` flag:** The `-accepteula` switch in a PsExec command
line suppresses the interactive EULA dialog and is used exclusively in scripted/automated
contexts. Legitimate interactive administrative use would not require this flag in most
managed environments.

**Security EID 4703 — SYSTEM privilege set including `SeLoadDriverPrivilege`:** The elevated
privilege set enabled in the SYSTEM token before PsExec execution is a precondition for
service installation. Correlating EID 4703 with a subsequent `cmd.exe` launching a remote
administration tool provides a contextual enrichment opportunity.

**`cmd.exe` exit code `0x1` following PsExec invocation:** A non-zero exit code from a
PsExec wrapper indicates either the tool was blocked or the remote session failed. In a
monitored environment, this pattern — PsExec invoked from non-standard path, returning
failure — may indicate an adversary testing connectivity before adjusting their approach.
