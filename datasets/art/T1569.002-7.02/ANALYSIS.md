# T1569.002-7: Service Execution — Modifying ACL of Service Control Manager via SDET

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. This test simulates a privilege escalation enablement
technique used by the Metasploit `exploit/windows/local/service_permissions` module and
documented adversary tooling: modifying the Security Descriptor (DACL) of the Service
Control Manager (SCM) itself using `sc.exe sdset scmanager`.

The SCM has its own access control list that determines which accounts can create, manage,
and start services. By default, only administrators can install new services. The command:

```
sc.exe sdset scmanager D:(A;;KA;;;WD)
```

sets a DACL on the SCM granting `KEY_ALL_ACCESS` (`KA`) to the World (`WD`) SID — every
user on the system. After this modification, any unprivileged user can install and start
services without administrative rights, enabling persistence and privilege escalation for
any local account.

This is a posture-modification attack rather than a direct execution attack: the adversary
changes the security configuration of Windows itself to enable later service-based actions
without elevation. The technique requires administrative access initially but removes the
requirement for subsequent service operations.

In the defended variant, this test succeeded without Defender interference (`sc.exe sdset`
is a legitimate administrative command). The defended dataset contained Sysmon EID 1 for
`sc.exe`, process chain events, and PowerShell infrastructure events, but no security
descriptor change audit (EID 4670) because policy change auditing was disabled. This
undefended dataset reflects the same execution pattern.

## What This Dataset Contains

The dataset spans approximately 3 seconds (17:42:10–17:42:13 UTC) and contains 123 total
events across two channels.

**Security channel (15 events) — EIDs 4688, 4689, 4703:**

EID 4688 captures the full attack chain:

**`cmd.exe` sc.exe sdset wrapper:**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c sc.exe sdset scmanager D:(A;;KA;;;WD)
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**`sc.exe sdset` invocation:**
```
New Process Name: C:\Windows\System32\sc.exe
Process Command Line: sc.exe  sdset scmanager D:(A;;KA;;;WD)
Creator Process Name: C:\Windows\System32\cmd.exe
Exit Status: 0x0
```

`sc.exe` exits `0x0`, confirming the SCM DACL was modified successfully. The full SDDL
string `D:(A;;KA;;;WD)` is visible in both the `cmd.exe` and `sc.exe` command lines.

This SDDL fragment means: `D:` (DACL) `(A;;KA;;;WD)` — Allow (`A`), no special flags,
`KA` (KEY_ALL_ACCESS = full control over service creation/management), to `WD` (World/
Everyone). After this executes, any user on the system can call `CreateService()`.

**Cleanup `cmd.exe`:**
```
Process Command Line: "cmd.exe" /c
Exit Status: 0x0
```
The ART cleanup phase (likely restoring the original SCM DACL via a second `sc.exe sdset`)
runs as the empty `"cmd.exe" /c` visible here, confirming cleanup succeeded.

**Pre- and post-execution `whoami.exe`:**
```
Process Command Line: "C:\Windows\system32\whoami.exe"
Exit Status: 0x0
```
Both ART identity checks complete successfully.

**EID 4703** — SYSTEM token rights adjustment for `powershell.exe`, enabling
`SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`, `SeSecurityPrivilege`,
`SeTakeOwnershipPrivilege`.

**PowerShell channel (108 events) — EIDs 4104, 4103:**

The 105 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The `sc.exe sdset` command runs via `cmd.exe /c` and does
not appear as a 4104 script block.

## What This Dataset Does Not Contain

**No Security EID 4670 (permissions on object changed).** Policy change auditing is set to
`none` in this environment. A production environment with policy change auditing enabled
would generate EID 4670 for the SCM object when its DACL is modified. This is the event
most directly relevant to detecting this technique, and its absence represents a significant
audit policy gap.

**No Sysmon events.** The Sysmon channel is absent. The defended variant's 27 Sysmon events
included EID 1 for `sc.exe` with the full `sdset scmanager` command line, DLL loads,
process access events, and named pipe creation. Without Sysmon, the Security EID 4688
provides the command line, but not the hash or parent process metadata Sysmon would add.

**No registry events.** The SCM security descriptor is not stored in the typical Services
registry hive path (`HKLM\SYSTEM\CurrentControlSet\Services`); it is stored in
`HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security` or as an in-memory
object. No Sysmon EID 13 fires for this modification.

**No validation of the DACL change's persistence.** The dataset does not include any
subsequent `sc.exe sdshow scmanager` query or SAM access that would confirm the modified
DACL was in effect. The `0x0` exit from `sc.exe` is the only confirmation.

## Assessment

The core attack event is fully captured: `sc.exe sdset scmanager D:(A;;KA;;;WD)` appears
in both the `cmd.exe` EID 4688 wrapper and the `sc.exe` EID 4688 process creation record,
with a `0x0` exit confirming success. The SDDL string `D:(A;;KA;;;WD)` is visible verbatim
in the log.

This technique succeeds identically with or without Defender. The defended dataset and this
undefended dataset are functionally equivalent — the only difference is the absence of
Defender-related infrastructure events. This reflects the nature of the attack: it modifies
a Windows security configuration object rather than running malicious code, and is therefore
not intercepted by behavior-based detection.

The absence of EID 4670 is the most significant gap. Without policy change auditing, the
SCM DACL modification leaves no dedicated audit trail. The EID 4688 command line record
is the primary (and in this dataset, only) evidence.

## Detection Opportunities Present in This Data

**Security EID 4688 — `sc.exe sdset scmanager`:** The string `sdset scmanager` in an
`sc.exe` command line is a high-fidelity indicator. Legitimate administrative operations
do not typically require modifying the SCM security descriptor. A process baseline query
for any `sc.exe sdset` invocation in your environment would likely return zero or very few
results.

**Security EID 4688 — SDDL containing `KA;;;WD`:** The substring `KA;;;WD` in any command
line involving service configuration indicates a grant of full service control to Everyone.
Parsing SDDL strings in command line arguments for overly permissive grants is a proactive
detection approach.

**Parent-child chain: `powershell.exe` → `cmd.exe` → `sc.exe sdset`:** The process
ancestry (`NT AUTHORITY\SYSTEM` PowerShell spawning `cmd.exe` to run `sc.exe sdset`) is
anomalous. Normal administrative operations would not use this chain for SCM DACL
modification; direct `sc.exe` invocation from an admin shell is more typical.

**Absence of EID 4670 as audit policy gap indicator:** If your environment does not generate
EID 4670 for object permission changes, the SCM DACL modification would be invisible except
through the EID 4688 command line. Auditing the audit policy itself (ensuring object access
auditing is enabled) is a prerequisite for detecting this technique reliably.
