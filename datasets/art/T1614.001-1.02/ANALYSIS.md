# T1614.001-1: System Language Discovery — Discover System Language by Registry Query

## Technique Context

T1614.001 (System Location Discovery: System Language Discovery) covers adversary enumeration of the operating system's configured language, locale, and regional settings. Many malware families — particularly ransomware, banking trojans, and nation-state implants — check system language before executing their payload. The rationale varies: avoiding systems in CIS countries (to reduce legal risk for operators), confirming the host is not a sandbox (many research sandboxes use default English locale), or selecting localized lure content.

This test queries the Windows language configuration using the registry. Specifically, it reads `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language` using `reg.exe`. This registry key contains values like `Default` (the system default language ID), `InstallLanguage`, and `Default` which encode Windows locale identifiers as hex strings (e.g., `0409` for English US). The technique is a pure living-off-the-land read: `reg.exe` is a signed Windows binary, the registry key requires no special privileges to read, and the operation leaves no persistent artifacts.

## What This Dataset Contains

The dataset captures 122 events across two log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103) and Security (15 events: 9 EID 4689, 5 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The registry query chain is fully captured in Security EID 4688.** PowerShell spawned cmd.exe:

```
"cmd.exe" /c reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

cmd.exe spawned reg.exe:

```
New Process Name: C:\Windows\System32\reg.exe
Process Command Line: reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language
Creator Process Name: C:\Windows\System32\cmd.exe
```

Both processes exited at `0x0`. The cleanup step is an empty cmd.exe (`"cmd.exe" /c` with no argument body) — the ART cleanup stub for a test that produces no persistent artifacts.

Security EID 4703 records the parent PowerShell (PID 0x4014) receiving elevated privileges consistent with SYSTEM-context execution, including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege`.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 1 (Process Create with hashes and parent chain), EID 12 (Registry Object Accessed), or EID 13 (Registry Value Set), you do not have hash-level identification or dedicated registry read events. Registry reads — as opposed to writes — are generally not logged by Windows Security auditing or Sysmon without specific registry auditing SACL configuration.

**No registry read event.** Neither Windows Security auditing nor the standard Sysmon configuration produces an event for registry key reads (as opposed to writes). The `reg.exe query` is visible only through the process command line in EID 4688, not as a registry access record.

**The output of the reg.exe query is not captured.** You cannot determine from this dataset what language identifiers were returned — the actual locale values (`Default`, `InstallLanguage`, etc.) are not logged anywhere.

**No network activity.** This is a purely local registry read with no outbound connections.

## Assessment

The defended variant recorded 38 Sysmon, 12 Security, and 36 PowerShell events. Sysmon in that run would have included EID 1 (Process Create) for both cmd.exe and reg.exe with full image hashes and parent chain detail. The undefended run produced 0 Sysmon, 15 Security, and 107 PowerShell events. The Security channel provides the complete execution chain at lower fidelity — command lines are present but no hashes.

The undefended and defended runs produce essentially identical outcomes here: `reg.exe query` against the NLS Language key is a benign-appearing, low-risk operation that Defender does not block. The primary difference is Sysmon coverage, not technique success. In both cases, the registry query ran successfully.

This is a minimal-artifact technique: no writes, no network, no new files. The only forensic record of the activity is the `reg.exe` process creation event with its command line argument.

## Detection Opportunities Present in This Data

**EID 4688 — reg.exe querying `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language` from a PowerShell/cmd.exe chain.** While querying NLS language settings is not inherently malicious, the execution context matters: a SYSTEM-context PowerShell launching cmd.exe → reg.exe to read language configuration — without any adjacent administrative task that would explain the need — is a detectable pattern. In isolation, this event is low-confidence; combined with other indicators (network beaconing, lateral movement, or privilege escalation) it becomes a meaningful data point.

**EID 4688 — Process chain: PowerShell (SYSTEM) → cmd.exe → reg.exe with NLS registry path.** The three-process chain for a simple registry read is itself an indicator of scripted, non-interactive execution. A human administrator checking system locale would use `Get-WinSystemLocale` in PowerShell or examine Control Panel settings, not a cmd.exe → reg.exe chain.

**Temporal clustering with other discovery techniques.** T1614.001-1 is one of many discovery techniques (T1082, T1016, T1057, T1083) that adversaries execute in rapid succession during initial recon. A single `reg.exe query` against the NLS key is low-fidelity; five `reg.exe` queries in different registry paths within a 60-second window — particularly in the Security log — is a high-confidence recon sweep.

**reg.exe reading system configuration keys from a SYSTEM process.** The `NLS\Language` key is not typically accessed by SYSTEM-context processes during normal operation. Baselining which processes read this key and from which parent process trees would surface scripted recon tooling.
