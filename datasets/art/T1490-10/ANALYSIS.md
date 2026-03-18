# T1490-10: Inhibit System Recovery — Windows - vssadmin Resize Shadowstorage Volume

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes manipulation of the VSS shadow storage allocation as an alternative to outright shadow copy deletion. `vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%` shrinks the storage area allocated for volume shadow copies to 20% of the volume — a size that is typically too small to retain any existing shadow copies, causing Windows to automatically purge them to fit within the new limit. This is a subtler evasion variant compared to `vssadmin delete shadows all`: it does not call a "delete" command and may evade detections based on the word "delete" in shadow copy operations. The resize variant has been observed in some Conti affiliate playbooks and in manual attacker activity.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
Three process create events are captured. `whoami.exe` is the test framework preflight (tagged T1033). A PowerShell process is then created with the command line `"powershell.exe" & {vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%%}` (tagged T1059.001). That PowerShell process in turn launches `"C:\Windows\system32\vssadmin.exe" resize shadowstorage /For=C: /On=C: /MaxSize=20%%` (tagged T1490). The full chain and all argument strings are captured.

**Security (Event IDs 4688/4689/4703):**
The Security channel confirms the same chain. `vssadmin.exe` exits with `0x0` (success). Token right adjustment (4703) is present for the `vssadmin.exe` process, reflecting the elevated privilege context used during VSS storage modification.

**PowerShell (Event ID 4104) — Script Block Logging:**
Two script block entries capture the resize command:
- `& {vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%}`
- `{vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%}`

The script block logging confirms the exact command passed to the PowerShell invocation, which is consistent with what Sysmon and Security logs show.

**Sysmon (Event ID 7) — ImageLoad:** Numerous DLL load events from two PowerShell processes and the SYSTEM profile PowerShell startup are present. These show .NET runtime, System.Management.Automation, and Windows Defender (MpOAV.dll, MpClient.dll) DLLs being loaded — the latter indicating Defender was actively scanning the PowerShell session. These are standard PowerShell startup artifacts.

**Sysmon (Event ID 17) — PipeCreate:** Named pipe creation events for `\PSHost.*` pipes from both PowerShell processes — standard PowerShell inter-process communication artifacts.

**PowerShell channel:** The bulk of the events are `Set-StrictMode` boilerplate fragments and `Set-ExecutionPolicy -Bypass` invocations from the test framework. The substantive technique content is the two 4104 script block events noted above.

## What This Dataset Does Not Contain

- **No VSS Application log confirmation** that shadow copies were actually purged as a result of the resize. The resize succeeded (exit `0x0`) but there are no Application log events indicating how many shadows were evicted.
- **No Sysmon EID 3 (NetworkConnect)** for VSS service activity.
- **No indication of the shadow copy state before and after** the resize. A detection that relies on the MaxSize value alone should note that `20%` is specific to this test; attackers may use other small values (e.g., `300MB`, `1%`).

## Assessment

This dataset cleanly captures the resize-as-deletion variant of T1490 with full fidelity across Sysmon, Security, and PowerShell channels. The exit code `0x0` confirms the resize succeeded. The primary detection challenge with this technique is that `vssadmin resize shadowstorage` has more legitimate administrative uses than `vssadmin delete shadows` — administrators occasionally tune VSS storage allocation. Detection logic should focus on the combination of a very small `MaxSize` value (below roughly 20–25%) and anomalous execution context (SYSTEM account, TEMP directory, PowerShell wrapper). The PowerShell EID 4104 script block is a useful independent detection layer for the version that pipes through PowerShell.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `vssadmin.exe resize shadowstorage /For=C: /On=C: /MaxSize=20%%`** — the combination of `resize shadowstorage` with a small MaxSize value; Sysmon tags this T1490.
2. **Security EID 4688 — `vssadmin.exe` command line with `resize shadowstorage` and `/MaxSize=` below a threshold** — command-line auditing captures this independently.
3. **PowerShell EID 4104 — script block containing `vssadmin resize shadowstorage`** — catches the case where the resize command is wrapped in PowerShell and the command line might be partially obscured.
4. **`/MaxSize=` with a small percentage value** — tuning the detection to trigger on `MaxSize` values below 25% filters out legitimate VSS storage management while catching the adversary pattern.
5. **PowerShell → vssadmin process chain** — `vssadmin.exe` launched by `powershell.exe` from `C:\Windows\TEMP\` as SYSTEM is an anomalous execution path that narrows the detection to the attacker scenario.
