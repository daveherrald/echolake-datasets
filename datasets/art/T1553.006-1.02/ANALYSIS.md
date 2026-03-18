# T1553.006-1: Subvert Trust Controls: Code Signing Policy Modification — Code Signing Policy Modification

## Technique Context

T1553.006 covers adversary modification of code signing policies to permit execution of unsigned or improperly signed code. On Windows, the primary mechanism exposed by this test is enabling test signing mode via `bcdedit /set testsigning on`. Test signing mode instructs the Windows kernel to accept drivers and executables signed with self-signed or test certificates — certificates that would ordinarily be rejected by Windows' normal signature verification chain. This capability is used by attackers deploying custom kernel drivers, rootkits, or other components that cannot obtain a legitimate Microsoft-issued Extended Validation (EV) code signing certificate.

The technique falls under Defense Evasion (TA0005) and is typically a pre-exploitation step rather than an end goal. Enabling test signing requires `SeLoadDriverPrivilege` and typically requires administrator or SYSTEM privileges. The modification takes effect at the next boot.

This test ran on ACME-WS06 with Defender disabled. The ART test both enables and then disables test signing mode (the cleanup action executes `bcdedit /set testsigning off`), so both the attack and the remediation are captured in this dataset.

## What This Dataset Contains

The dataset contains 134 total events: 21 Sysmon events, 107 PowerShell operational events, and 6 Security events.

**Sysmon EID 1 (Process Create)** captures the complete process chain. Six process creation events show the attack and cleanup sequences:

The attack sequence:
```
CommandLine: "cmd.exe" /c bcdedit /set testsigning on
Image: C:\Windows\System32\cmd.exe
User: NT AUTHORITY\SYSTEM
```

```
CommandLine: bcdedit  /set testsigning on
Image: C:\Windows\System32\bcdedit.exe
User: NT AUTHORITY\SYSTEM
RuleName: technique_id=T1490,technique_name=Inhibit System Recovery
```

The cleanup sequence:
```
CommandLine: "cmd.exe" /c bcdedit /set testsigning off
Image: C:\Windows\System32\cmd.exe
User: NT AUTHORITY\SYSTEM
```

```
CommandLine: bcdedit  /set testsigning off
Image: C:\Windows\System32\bcdedit.exe
User: NT AUTHORITY\SYSTEM
RuleName: technique_id=T1490,technique_name=Inhibit System Recovery
```

The `whoami.exe` calls also appear as Sysmon EID 1, part of the ART test framework identity confirmation.

**Security EID 4688 (Process Create)** captures all six process creation events with command-line auditing. The parent-child relationships are clearly recorded: PowerShell (PID 0x466c) spawns `cmd.exe`, which spawns `bcdedit.exe`. All processes run under `NT AUTHORITY\SYSTEM` (Security ID `S-1-5-18`, Logon ID `0x3E7`).

The full command audit trail in Security events:
- `"cmd.exe" /c bcdedit /set testsigning on` (creator: powershell.exe)
- `bcdedit  /set testsigning on` (creator: cmd.exe)
- `"cmd.exe" /c bcdedit /set testsigning off` (creator: powershell.exe)
- `bcdedit  /set testsigning off` (creator: cmd.exe)

**Sysmon EID 7 (Image Load)** accounts for 9 events, recording DLL loads into the PowerShell process.

**Sysmon EID 10 (Process Access)** accounts for 4 events, with the parent PowerShell process accessing child processes at `GrantedAccess: 0x1FFFFF`.

**PowerShell EID 4104 (Script Block Logging)** captures 104 script block logging entries. The substantial number reflects multiple PowerShell instances spawned by the ART test framework. EID 4103 captures the `Set-ExecutionPolicy Bypass -Scope Process -Force` invocation and test framework completion markers.

## What This Dataset Does Not Contain

**No BCD (Boot Configuration Data) store modification events.** Windows does not natively emit dedicated event log entries when the BCD store is modified. The only evidence of the BCD change is the `bcdedit.exe` process execution — there is no event equivalent to a registry audit event for BCD modifications.

**No reboot-related events.** Test signing mode requires a reboot to take effect. This dataset captures only the `bcdedit` command execution, not any subsequent boot sequence or System event log entries confirming the mode change took effect.

**No Security EID 4657 (Registry value modified)** events. While `bcdedit` modifies the BCD store (which is stored in a file, not standard registry), you would not expect registry modification events here.

**No Sysmon EID 12/13 (Registry events)** capturing BCD store changes, for the same reason as above.

**No Windows System event log entries** that would reflect the BCD modification — those would appear post-reboot.

## Assessment

With Defender disabled, `bcdedit /set testsigning on` executes without obstruction and completes successfully. The dataset faithfully captures the full process chain: PowerShell → cmd.exe → bcdedit.exe, twice (once for the attack, once for the cleanup). The execution context — SYSTEM privileges, running from `C:\Windows\TEMP\` — is recorded clearly.

Compared to the defended variant, the undefended dataset has slightly fewer total events because Defender's own process activity (quarantine operations, scan processes) is absent. The event volumes are similar (defended: 37 Sysmon, 10 PowerShell, 6 Security; undefended: 21 Sysmon, 107 PowerShell, 6 Security), with the undefended variant showing substantially more PowerShell operational events because the test framework runs to completion without interruption.

The technique itself is interesting from a detection standpoint because `bcdedit` is a legitimate system binary, the command is simple and brief, and the change has no observable immediate effect — it only matters at the next boot. Detection must rely entirely on the process execution record rather than any behavioral consequence visible in the event stream.

Note that Sysmon labels `bcdedit.exe` with `RuleName: technique_id=T1490,technique_name=Inhibit System Recovery` — a common tagging for bcdedit use — which is a reasonable but imprecise classification. The technique in use here is T1553.006 (code signing policy modification), not T1490 (inhibit system recovery), though the same binary covers both.

## Detection Opportunities Present in This Data

**Sysmon EID 1** and **Security EID 4688** both capture `bcdedit /set testsigning on` with full command-line context. This is among the most reliably detectable forms of this technique: the argument `testsigning on` combined with `bcdedit.exe` is a highly specific and unusual pattern on production endpoints. The parent process chain (powershell.exe → cmd.exe → bcdedit.exe) executing from `C:\Windows\TEMP\` as SYSTEM adds additional context.

**Security EID 4688** provides the parent-child chain explicitly: the creator process ID and name are recorded, allowing reconstruction of the full execution path from the ART test framework PowerShell instance through cmd.exe to bcdedit.exe.

**PowerShell EID 4104 script block logging** would capture the actual PowerShell command (`cmd /c bcdedit /set testsigning on`) if the script block containing it appeared in the sampled events. The EID 4103 module logging captures `Set-ExecutionPolicy Bypass -Scope Process -Force`, useful as a precursor indicator when correlated with subsequent bcdedit execution within the same PowerShell session.

The cleanup execution (`bcdedit /set testsigning off`) also appears identically in the event stream — an analyst reviewing logs would see both the enable and disable, which provides temporal context. An attacker who fails to run cleanup (or who reboots before cleanup) would leave only the enable event.
