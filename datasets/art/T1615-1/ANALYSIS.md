# T1615-1: Group Policy Discovery — Display Group Policy Information via gpresult

## Technique Context

T1615 (Group Policy Discovery) covers adversary enumeration of Group Policy Objects (GPOs) applied to a host or domain. GPO enumeration helps attackers understand defensive controls, software restrictions, logon scripts, and mapped drives that may affect their operations. The `gpresult` utility is a built-in Windows tool that reports the Resultant Set of Policy (RSoP) for a user or computer.

## What This Dataset Contains

This dataset captures a `gpresult /z` query executed via `cmd.exe` from a PowerShell test framework, running as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

**Security log (12 events)** — EID 4688 (process creation) records:
- `whoami.exe` spawned from PowerShell (test framework identity check)
- `"cmd.exe" /c gpresult /z` spawned from PowerShell with full command line
- Corresponding 4689 process termination events
- One EID 4703 token right adjustment for PowerShell

Note: `gpresult.exe` itself does not generate a 4688 event in this dataset. This is consistent with the Sysmon ProcessCreate include-mode filtering — `gpresult` is not on the include list — and the Security log 4688 coverage, which shows the `cmd.exe` launch but not the `gpresult` child process. This indicates that `gpresult` was spawned directly by `cmd.exe` and the Security log captured `cmd.exe` but the chain terminated there in the bundled window.

**Sysmon (28 events)** — EID 7 (image load) events show the PowerShell process loading standard DLLs (mscoree, system management assemblies, Windows Defender DLL tagged T1574.002); EID 17 (named pipe) shows `\PSHost...` pipe creation for both PowerShell instances; EID 10 (process access) fires on the PowerShell host; EID 11 (file created) for the PowerShell startup profile. Sysmon EID 1 fires for:
- `whoami.exe` tagged `technique_id=T1033`
- `cmd.exe` tagged `technique_id=T1059.003` with command line `"cmd.exe" /c gpresult /z`

**PowerShell log (34 events)** — Entirely ART test framework boilerplate: EID 4104 script block stubs for PowerShell error-handling internals and two EID 4103 entries for `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`. No script block for the gpresult invocation itself (it runs through `cmd.exe`).

## What This Dataset Does Not Contain (and Why)

- **Sysmon ProcessCreate for gpresult.exe** — `gpresult` is not matched by the sysmon-modular include rules for ProcessCreate; it does not appear as an EID 1 event. Its execution is visible only through the `cmd.exe` parent's command line.
- **Security 4688 for gpresult.exe** — The bundled event window does not include a 4688 for the gpresult child process; it is captured at the `cmd.exe` level.
- **GPO policy output** — The actual RSoP data returned by `gpresult /z` (applied GPOs, settings, etc.) is not captured in any event channel.
- **LDAP or network queries** — `gpresult` may query the domain controller for policy information; no network or Kerberos events from this query appear in the dataset.

## Assessment

The test completed successfully. The command `gpresult /z` produces a verbose RSoP report, but the security telemetry reflects only the invocation, not the results. The dataset is representative of what defenders will see for this simple, native-tool discovery technique: a `cmd.exe` process launched from PowerShell with `gpresult` in the command line. The test framework boilerplate dominates the PowerShell log.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: `cmd.exe` with command line containing `gpresult` spawned from `powershell.exe` is a reliable indicator; `gpresult` has very limited legitimate administrative use cases that would originate from a PowerShell SYSTEM process.
- **Sysmon EID 1, RuleName T1059.003**: The sysmon-modular config already tags this `cmd.exe` invocation, enabling alert-ready enrichment.
- **Parent process chain**: PowerShell → cmd.exe → gpresult is unusual for normal workstation activity and warrants investigation regardless of the specific gpresult flags used.
- **`/z` flag**: The verbose output flag on `gpresult` maximizes information returned and is more likely to be adversarial than the simpler `/r` flag used by administrators.
