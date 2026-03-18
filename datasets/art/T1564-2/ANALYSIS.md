# T1564-2: Hide Artifacts — Create a Hidden User Called "$"

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) covers a broad family of defense evasion techniques in which adversaries obscure evidence of their presence. This test creates a local Windows user account with the name `$` — a dollar-sign-only username that is conventionally associated with hidden administrative shares and causes some user enumeration tools to skip it. The account is added with `net user` while the system is running as NT AUTHORITY\SYSTEM, which is the typical privilege level for post-exploitation persistence steps.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:18:32–14:18:37 UTC) and captures the full process tree for account creation.

**Process execution chain (Sysmon EID 1 / Security EID 4688):**

The ART test framework launched two sequential PowerShell instances from the QEMU guest agent, each running `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (visible in PowerShell EID 4103). The second PowerShell invocation issued the attack payload through cmd.exe:

```
"cmd.exe" /c net user $ ATOMIC123! /add /active:yes
```

This spawned `net.exe` and its subprocess `net1.exe`, both with the identical command line:

```
net  user $ ATOMIC123! /add /active:yes
net1  user $ ATOMIC123! /add /active:yes
```

A preparatory `whoami.exe` was also captured, tagged by Sysmon as T1033 (System Owner/User Discovery), which is standard ART test framework behavior.

**Sysmon EID 7 (Image Load):** Both PowerShell instances loaded DLLs annotated with RuleNames `technique_id=T1055,technique_name=Process Injection` and `technique_id=T1059.001,technique_name=PowerShell`, and one loaded `urlmon.dll`. These are expected artifacts of PowerShell startup under sysmon-modular rules.

**Sysmon EID 17 (Pipe Created):** Named pipe `\PSHost.*.powershell` created by each PowerShell host process.

**Sysmon EID 10 (Process Access):** PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF` (full access), annotated as T1055.001.

**Sysmon EID 11 (File Create):** PowerShell wrote `StartupProfileData-NonInteractive` under the SYSTEM profile.

**Security EID 4688/4689:** Process creation and termination for powershell.exe, conhost.exe, whoami.exe, cmd.exe, net.exe, net1.exe — all running as S-1-5-18 (SYSTEM).

**Security EID 4703:** Token right adjusted for SYSTEM account.

**PowerShell EID 4103/4104:** Module logging shows `Set-ExecutionPolicy` invocations. Script block logging captures the internal PowerShell error-handling boilerplate (`$_.PSMessageDetails`, `$_.OriginInfo`, etc.) that the ART framework emits across every test.

## What This Dataset Does Not Contain (and Why)

**No Security Account Manager (SAM) account management events (4720, 4726, 4738):** Although object access auditing is not enabled in this environment (`object_access: none`), account management auditing is also disabled (`account_management: none`). The actual user creation in the SAM is therefore invisible in the Security log. These events would be the primary indicator of account creation in a fully-instrumented environment.

**No net user output or success/failure indicator:** The dataset captures the invocation but not the result. Whether the account was successfully created is not determinable from these events alone.

**No Security EID 4624/4625 (logon):** The newly created account was not used to log on during the capture window.

**No Sysmon EID 12/14 (Registry Create/Delete):** SAM-related registry operations were not captured, consistent with the disabled audit policy and sysmon-modular not specifically targeting SAM hive writes.

## Assessment

The technique executed successfully from a telemetry perspective — the attack command is fully visible in the command-line fields of both Sysmon EID 1 and Security EID 4688. The dollar-sign username is present verbatim in the logged command line. The absence of account management events (4720) means that a detection relying solely on those events would have a blind spot, but the process execution path provides a reliable alternative signal. The bulk of the PowerShell log volume consists of internal error-formatting script blocks from the ART test framework rather than attack-relevant content.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `net.exe` or `net1.exe` command line containing `user $ ... /add`. The dollar-sign-only username is distinctive and unlikely in legitimate administration.
- **Sysmon EID 1 / Security EID 4688:** `cmd.exe` spawned by `powershell.exe` running as SYSTEM with `net user` arguments.
- **Sysmon EID 10:** PowerShell with full process access (`0x1FFFFF`) to cmd.exe and net.exe child processes — a consistent pattern for ART-style test framework execution that may itself be a detection pivot.
- **PowerShell EID 4103:** `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` executed under SYSTEM in a non-interactive session, which is a reliable test framework artifact but also a common attacker pattern.
- **Correlation:** `net.exe` / `net1.exe` processes with parent `cmd.exe` and grandparent `powershell.exe` running as SYSTEM, where no interactive logon session is present.
