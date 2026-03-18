# T1569.002-7: Service Execution — Modifying ACL of Service Control Manager via SDET

## Technique Context

T1569.002 (Service Execution) covers use of the Service Control Manager to execute
programs. This test simulates a technique used by adversaries and the Metasploit
`exploit/windows/local/service_permissions` module: modifying the Security Descriptor
of the Service Control Manager (SCM) itself using `sc.exe sdset scmanager`. By granting
world-accessible (`WD`) permissions including `KA` (KEY_ALL_ACCESS), an attacker
enables unprivileged users to create and manage services without administrative rights.
This is a privilege escalation and persistence enablement technique that modifies
security posture rather than directly executing code.

## What This Dataset Contains

**Sysmon EID 1** — process create for `sc.exe`:

> `CommandLine: sc.exe sdset scmanager D:(A;;KA;;;WD)`

This command sets the DACL on the SCM itself, granting `KEY_ALL_ACCESS` to the World
(`WD`) SID — effectively allowing any user to install services. The parent chain is
`powershell.exe` → `cmd.exe` → `sc.exe`, all running as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 1** — test framework precursor `whoami.exe`:

> `CommandLine: "C:\Windows\system32\whoami.exe"` (RuleName: T1033)

**Sysmon EID 7** — DLL image loads for the PowerShell processes, annotated with
`technique_id=T1055` and `technique_id=T1059.001` and `technique_id=T1574.002` rule
names from the sysmon-modular configuration.

**Sysmon EID 10** — process access events (`T1055.001,Dynamic-link Library Injection`)
from one PowerShell process accessing another, representing ART test framework instrumentation.

**Sysmon EID 17** — named pipe creation:

> `PipeName: \PSHost.134179722961712185.6124.DefaultAppDomain.powershell`

**Security EID 4688/4689** — process creation and exit for `powershell.exe`, `cmd.exe`,
`sc.exe`, and `whoami.exe` under SYSTEM. No 4703 token adjustment events were filtered
into this dataset for this test.

**PowerShell EID 4104** — the `sc.exe sdset scmanager` command is visible in the Sysmon
EID 1 command line. The 4104 script blocks are entirely ART test framework boilerplate:
`Set-StrictMode -Version 1`, `$_.PSMessageDetails`, `$_.ErrorCategory_Message`,
`$_.OriginInfo` — repeating patterns with no test-specific payload logged.

## What This Dataset Does Not Contain (and Why)

**No security descriptor change audit event.** Policy change auditing is set to `none`
in this environment. A production environment with policy change auditing enabled would
generate Security EID 4670 (permissions on an object were changed) for the SCM object.

**No Sysmon EID 13.** Unlike service creation (T1569.002-6), this test does not write
to `HKLM\CurrentControlSet\Services`. The SCM security descriptor is stored in a
different registry key (`HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security`
or as an in-memory object), and no registry write via `services.exe` is captured here.

**No Defender block.** Modifying the SCM DACL via `sc.exe sdset` is not detected as
malicious by Windows Defender 4.18.26010.5 with the signatures present.

**No verification of success.** The test does not subsequently attempt to create a
service as a non-privileged user to confirm the ACL change took effect.

**No System EID 7045.** No service was installed in this test; only the SCM's own
permissions were altered.

## Assessment

This dataset demonstrates the telemetry floor for a subtle privilege escalation preparatory
step. The only definitive detection signal is in the `sc.exe` command line captured via
Security EID 4688 and Sysmon EID 1. The SDET (Security Descriptor Editor Tool) mnemonic
`sdset scmanager` combined with a permissive SDDL string containing `WD` (World) is a
high-confidence indicator. The absence of policy change auditing means the actual ACL
modification is invisible to Security event logs, making host-level telemetry the
primary detection path.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688** — `sc.exe` with `sdset scmanager` as the command
  argument is a reliable, low-false-positive detection opportunity; legitimate tooling
  rarely modifies the SCM's own DACL.
- **SDDL content analysis** — the string `D:(A;;KA;;;WD)` or any DACL entry granting
  `WD` (World) broad access to `scmanager` is a high-fidelity IOC.
- **Parent process chain** — `sc.exe` launched from `cmd.exe` launched from `powershell.exe`
  under SYSTEM from `C:\Windows\TEMP` is an anomalous execution context.
- **Absence detection** — organizations with policy change auditing enabled should alert
  on absence of EID 4670 correlating with known `sc.exe sdset` executions, or add that
  audit category to ensure coverage.
- **Sysmon-modular RuleName**: the `T1543.003,Windows Service` rule fires on `sc.exe`,
  providing pre-labeled evidence for SIEM correlation.
