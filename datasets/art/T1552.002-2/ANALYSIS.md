# T1552.002-2: Credentials in Registry — Enumeration for PuTTY Credentials in Registry

## Technique Context

MITRE ATT&CK T1552.002 (Credentials in Registry) includes harvesting credentials stored by third-party applications. PuTTY, the widely-used SSH and Telnet client, stores session configurations in `HKCU\Software\SimonTatham\PuTTY\Sessions\`. Each named session may contain hostname, username, and — in older versions or with certain configurations — proxy passwords (`ProxyPassword`) or pre-shared key material. Adversaries targeting sysadmin workstations frequently query PuTTY sessions to enumerate SSH infrastructure and potentially recover stored credentials. Test 2 performs a direct targeted query against this specific key path, in contrast to the broad sweep of test 1.

## What This Dataset Contains

The dataset spans approximately five seconds (00:29:10–00:29:15 UTC) and contains 74 events across three log sources.

**The technique executes and is clearly captured.** The Sysmon ProcessCreate chain (EID 1) shows:

- `whoami.exe` (tagged T1033)
- `cmd.exe` with `CommandLine: "cmd.exe" /c reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s` (tagged T1059.003)
- `reg.exe` (PID 6048) with `CommandLine: reg  query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s` (tagged T1012)

Security EID 4688 independently confirms all three process launches with full command-line detail. EID 4689 records `reg.exe` exiting with status 0x0, indicating the query completed successfully (though the key may be empty or absent on this system).

The PowerShell log contains the ART test framework boilerplate (EID 4104 script block fragments, EID 4103 `Set-ExecutionPolicy Bypass`).

Unlike test 1's dual-hive search which ran for ~8 seconds, this targeted single-key query completes nearly instantly — the cmd.exe and reg.exe processes appear at 00:29:14, consistent with a rapid lookup rather than a broad recursive search.

## What This Dataset Does Not Contain (and Why)

**No PuTTY session data.** `reg query` outputs to stdout. No registry access auditing is configured. Whether PuTTY is installed on this system, whether any sessions exist, and what values (if any) were returned are all unknown from this dataset.

**No ProxyPassword or credential values.** Even if PuTTY sessions existed with stored credentials, those values would only appear in the console output — not captured here.

**No lateral movement or follow-on activity.** This dataset covers only the enumeration step. Subsequent use of discovered SSH hostnames or credentials would require additional datasets.

**No Sysmon ProcessCreate for the `cmd.exe` → `reg.exe` relationship detail.** Sysmon captures both processes, but the parent-child relationship between them is inferred from timing rather than explicit parent process fields at the bundled event count level.

## Assessment

This is a tight, focused dataset for a highly targeted credential enumeration technique. The five-second window and small event count (74 total) reflect the efficiency of a specific-path registry query versus the broad sweep in test 1. The key detection signal — `reg query HKCU\Software\SimonTatham\PuTTY\Sessions` — is unambiguous and present in both Sysmon and Security logs. PuTTY is common on developer and sysadmin workstations, making this a realistic and relevant threat pattern. The dataset is well-suited for detection validation given its clean, low-event profile.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `reg.exe` with `HKCU\Software\SimonTatham\PuTTY\Sessions` in the command line is a specific, high-confidence indicator. There is no legitimate reason for automated processes to query this path.
- **Sysmon EID 1 (T1012 tag)**: The Query Registry tag provides enriched classification for SIEM routing.
- **Path specificity**: Any process accessing `HKCU\Software\SimonTatham\PuTTY\Sessions` via `reg.exe` (or PowerShell's registry provider, or direct API) should be treated as suspicious unless the process is PuTTY itself or a known backup/sync tool.
- **Process tree**: `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` as SYSTEM is anomalous. PuTTY users access these registry keys interactively; automated SYSTEM-level queries are a red flag.
- **Companion to test 1**: Adversaries performing both T1552.002-1 (broad password sweep) and T1552.002-2 (PuTTY-specific) in sequence are conducting thorough credential enumeration. Detecting the combination suggests a deliberate post-exploitation phase.
- **Expand to similar paths**: The same detection logic applies to other SSH client credential stores: `HKCU\Software\9bis.com\KiTTY\Sessions`, `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`, and MobaXterm configuration paths.
