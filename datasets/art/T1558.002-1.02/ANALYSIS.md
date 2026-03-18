# T1558.002-1: Steal or Forge Kerberos Tickets: Silver Ticket — Crafting Active Directory Silver Tickets with Mimikatz

## Technique Context

MITRE ATT&CK T1558.002 (Silver Ticket) involves forging a Kerberos Service Ticket (TGS) rather than a TGT. Unlike a golden ticket — which requires the KRBTGT hash and grants access to all services domain-wide — a silver ticket requires only the target service account's NTLM hash or AES key, and grants forged access only to the specific service managed by that account. Silver tickets are stealthier by design: they are constructed entirely on the client, never involve the domain controller, and bypass KDC validation entirely. The forged ticket grants direct, DC-invisible access to the target service.

Mimikatz performs silver ticket forging with `kerberos::golden /service:<servicename>` — the same module as golden tickets but with a service name specified and the service account's hash supplied instead of KRBTGT. This test targets the HOST service on the domain controller (`/service:HOST /target:<dc>`) to demonstrate scheduled task access via forged authentication.

With Defender disabled, the full Mimikatz silver ticket logic executes without AMSI interception.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 1 second. It contains 159 events across four channels: 28 Sysmon, 101 PowerShell, 29 Security, and 1 Application.

**Command executed (Security EID=4688):**
The test constructs a batch file containing:
```
C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe
  "kerberos::golden /domain:%userdnsdomain%
   /sid:DOMAIN_SID
   /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
   /user:silverticketfakeuser
   /service:HOST
   /target:%logonserver:\\=%.%userdnsdomain%
   /ptt" "exit"
```
Then executes it via `runas /netonly /user:fake C:\Windows\TEMP\silver.bat`. The full PowerShell script block appears in Security EID=4688.

**Security EID=4799 (Security-Enabled Local Group Membership Enumerated):** 19 EID=4799 events record Mimikatz or the silver ticket execution framework enumerating local group memberships. The following groups were queried:
- Administrators
- Access Control Assistance Operators
- Backup Operators
- Cryptographic Operators
- Device Owners
- Event Log Readers
- Distributed COM Users
- Guests
- IIS_IUSRS
- Users

These events are attributed to `ACME-WS06$` (the machine account). This local group enumeration is a reconnaissance side effect of the silver ticket execution — likely from Mimikatz probing the local authorization context or from the batch file execution environment initializing.

**Security EID=4798 (User Account Local Group Membership Enumerated):** Five EID=4798 events record per-user group membership queries for: Administrator, DefaultAccount, Guest, WDAGUtilityAccount, and mm11711. These user-specific enumeration events are also attributed to `ACME-WS06$`.

**Sysmon EID=8 (CreateRemoteThread):** One EID=8 event showing `powershell.exe` (PID 14424) creating a remote thread in `<unknown process>` (PID 14260), tagged `technique_id=T1055,technique_name=Process Injection`. StartAddress: `0x00007FF658E64EB0` — the same address appearing in T1555.004-2 and T1558.001-1, consistent with a common Mimikatz/WinPwn in-memory loading mechanism.

**Sysmon EID=10 (Process Access):** Three EID=10 events at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=1 (Process Create):** Four process creations including `WmiPrvSE.exe` (spawned by svchost DcomLaunch, `NT AUTHORITY\NETWORK SERVICE`) and `whoami.exe` instances. The WMI Provider Host instantiation may reflect a WMI query issued during the silver ticket batch execution.

**Security EID=4688:** Five process creation events including `WmiPrvSE.exe` and the silver ticket PowerShell invocation.

**PowerShell EID=4104:** 97 script block events. The full silver ticket construction script is evaluated and logged — the Mimikatz invocation, the service account specification, the `/service:HOST /target:` syntax, and the batch file construction logic including `silver.bat` and `silver.txt` output filenames.

## What This Dataset Does Not Contain

**Mimikatz execution process in Sysmon EID=1.** Mimikatz is invoked from `silver.bat` via the `runas /netonly` session. The Sysmon ProcessCreate filter does not match `mimikatz.exe` by name, so no EID=1 fires for the Mimikatz process itself. Security EID=4688 captures `powershell.exe` with the batch-construction script but not the Mimikatz child process within the batch context.

**Kerberos service ticket events.** A successfully forged silver ticket is used directly against the target service without any domain controller interaction. By design, T1558.002's defining characteristic is the absence of DC-side EID=4769 events — even in a successful run, those events would not appear here.

**runas /netonly logon event (EID=4624).** Unlike T1558.001-2 (Rubeus golden ticket), no EID=4624 logon type 9 event appears in this dataset for the `runas /netonly /user:fake` session. This may reflect the shorter capture window (1 second vs 5 seconds) or differences in the session lifecycle timing.

**LSASS access events.** Mimikatz's silver ticket function (`kerberos::golden /service:`) operates from a supplied hash parameter. When the hash is provided as an argument (as in this test), LSASS access is not required.

**Comparison with the defended variant:** In the defended dataset (sysmon: 35, security: 10, powershell: 50), AMSI blocked the Mimikatz payload before the silver ticket logic could execute. The defended security event count was 10 — none of the 4798/4799 enumeration events appear. The undefended dataset's 29 security events include 19 EID=4799 and 5 EID=4798 events that are direct artifacts of the silver ticket execution proceeding further than the defended run allowed. This difference is the most forensically significant distinction between the two datasets for this test.

## Assessment

The most distinctive feature of this dataset compared to its defended counterpart is the 24 Security EID=4798/4799 events recording comprehensive local group and user account enumeration. This enumeration activity did not appear in the defended run because AMSI blocked execution before the batch file launched. In the undefended run, the Mimikatz silver ticket execution (or its initialization context) triggered a systematic query of all local groups and users on the workstation — a reconnaissance side effect that is directly observable and attributable to the attack.

The PowerShell EID=4104 events preserve the complete `kerberos::golden /service:HOST` invocation with the test AES256 key and the `silverticketfakeuser` username, providing full context for the forging attempt.

## Detection Opportunities Present in This Data

**Security EID=4799 — bulk local group enumeration from machine account:** 19 EID=4799 events enumerating all local security groups in rapid succession from `ACME-WS06$` (machine account) is anomalous. Normal administrative activity would not enumerate every local group in this manner.

**Security EID=4798 — per-user group membership enumeration for all local accounts:** Five EID=4798 events covering all local users (Administrator, DefaultAccount, Guest, WDAGUtilityAccount, and a domain account) in the same short time window correlates with automated enumeration rather than interactive administration.

**PowerShell EID=4104 — kerberos::golden /service: invocation:** The presence of `/service:HOST` (or any service name) in a `kerberos::golden` command string within a PowerShell script block is a direct indicator of silver ticket forging intent.

**PowerShell EID=4104 — silver.bat and silver.txt batch file construction pattern:** References to `silver.bat` combined with `runas /netonly /user:fake` and Mimikatz invocation strings identify the isolation-based silver ticket execution pattern.

**Sysmon EID=8 — CreateRemoteThread at StartAddress 0x00007FF658E64EB0:** This specific start address appears across multiple Mimikatz/WinPwn tests in this series. Its correlation with Kerberos forging activity in PowerShell script blocks makes it a meaningful behavioral indicator.

**Sysmon EID=1 — WmiPrvSE.exe spawned during ticket attack window:** WMI Provider Host instantiation in close temporal proximity to a Kerberos forging execution may indicate WMI-based reconnaissance or service enumeration as part of the attack's operational preparation.
