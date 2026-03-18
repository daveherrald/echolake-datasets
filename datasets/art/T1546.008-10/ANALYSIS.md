# T1546.008-10: Accessibility Features — Replace AtBroker.exe (App Switcher Binary) with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) via file replacement targets not just the classic Sticky Keys (`sethc.exe`) but any accessibility binary that Windows is configured to launch at the logon screen or on keyboard shortcut. `AtBroker.exe` (Assistive Technology Broker) is a less commonly targeted binary in this class, making it potentially less likely to trigger existing detections that focus on the canonical targets (sethc.exe, utilman.exe, osk.exe). The replacement approach is identical across targets: take ownership, grant write permissions, copy a shell binary over the accessibility executable. By varying the target binary, attackers attempt to evade signature-based or path-specific detection rules that list only the most common accessibility feature targets. Detection engineering must cover the full set of accessibility binaries — or ideally, detect the ownership and permission modification pattern regardless of target.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-13 23:42:43–23:42:48) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (30 events, IDs: 1, 7, 10, 11, 17, 22):** The execution chain in Sysmon ID=1 (ProcessCreate) events mirrors T1546.008-2 but targets `AtBroker.exe`:

1. `whoami.exe` (test framework context check)
2. `cmd.exe` with:
   ```
   "cmd.exe" /c IF NOT EXIST C:\Windows\System32\AtBroker_backup.exe (copy C:\Windows\System32\AtBroker.exe C:\Windows\System32\AtBroker_backup.exe) & takeown /F C:\Windows\System32\AtBroker.exe /A & icacls C:\Windows\System32\AtBroker.exe /grant Administrators:F /t & copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\AtBroker.exe
   ```
3. `takeown.exe` with `/F C:\Windows\System32\AtBroker.exe /A` (tagged T1222.001)
4. `icacls.exe` with `C:\Windows\System32\AtBroker.exe /grant Administrators:F /t` (tagged T1222.001)

Sysmon ID=11 (FileCreate) confirms `C:\Windows\System32\AtBroker.exe` was written, with `CreationUtcTime: 2026-03-13 02:04:51.971` matching `cmd.exe`'s original timestamp — the copy succeeded.

Uniquely, this dataset includes a Sysmon ID=22 (DnsQuery) event from `lsass.exe` for `_ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones.acme.local`, resolving to `192.168.4.10` (ACME-DC01). This is domain controller discovery by LSASS, unrelated to the technique — it is real-world OS activity occurring in the background.

**Security (15 events, IDs: 4688, 4689, 4703):** Process creations and terminations for the execution chain.

**PowerShell (34 events, IDs: 4103, 4104):** Test framework boilerplate only.

## What This Dataset Does Not Contain

- **No Defender block:** Like T1546.008-2, the file copy succeeded — the Sysmon ID=11 event confirms the write to `AtBroker.exe`. This dataset does not include Application log events (no ID=15 Defender state notifications), suggesting Defender's response to `AtBroker.exe` modification was different from its response to `sethc.exe` modification.
- **No IFEO registry keys:** This is the file replacement variant, not the IFEO debugger variant covered in T1546.008-1. No Sysmon ID=13 events are present.
- **No trigger execution:** `AtBroker.exe` (now `cmd.exe`) is not launched in this window.
- **No Application log events:** Unlike T1546.008-2, there are no Windows Defender status events, which may indicate Defender does not treat `AtBroker.exe` as a monitored system binary with the same priority as `sethc.exe`.

## Assessment

This dataset is structurally similar to T1546.008-2 and is best used alongside it to build detections that cover the broader class of accessibility binary replacements rather than just Sticky Keys. The absence of Application log ID=15 events (compared to T1546.008-2) is a meaningful observation: it suggests Windows Defender may have different detection coverage for different accessibility binaries. For a detection engineer, the `takeown.exe` + `icacls.exe` + `copy /Y cmd.exe <accessibility_binary>` pattern is the most reliable cross-target indicator. The background LSASS DNS query (Sysmon ID=22) is genuine OS noise that confirms the dataset was collected from a live domain-joined workstation.

## Detection Opportunities Present in This Data

1. **Sysmon ID=11:** A write (file creation event) to `C:\Windows\System32\AtBroker.exe` — or any accessibility binary — that changes its hash from the known-good value is a high-confidence indicator, independent of the attack chain that produced it.
2. **Sysmon ID=1 / Security ID=4688:** `takeown.exe /F C:\Windows\System32\AtBroker.exe` is suspicious regardless of subsequent steps; ownership changes to System32 binaries have no legitimate administrative use case outside OS patching.
3. **Sysmon ID=1 / Security ID=4688:** `icacls.exe <System32_binary> /grant Administrators:F` is an unusual permission modification that should be flagged for any binary under `C:\Windows\System32\`.
4. **Sysmon ID=1 compound pattern:** The `cmd.exe /c` compound command containing `takeown`, `icacls`, and `copy /Y cmd.exe <target_binary>` in a single command string is an extremely specific indicator of accessibility binary replacement.
5. **Cross-dataset pattern (T1546.008-2 vs T1546.008-10):** Building a detection that covers `takeown.exe` + `icacls.exe` + `copy` targeting any of the known accessibility binaries (sethc.exe, osk.exe, utilman.exe, magnify.exe, narrator.exe, atbroker.exe, DisplaySwitch.exe) as a group — rather than any individual path — provides evasion-resistant coverage across the T1546.008 sub-technique variants.
