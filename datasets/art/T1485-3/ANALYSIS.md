# T1485-3: Data Destruction — Overwrite Deleted Data on C Drive

## Technique Context

T1485 (Data Destruction) covers adversary actions that permanently destroy data to interrupt availability or obstruct incident response. Unlike ransomware (T1486), which encrypts data for leverage, destruction is purely punitive or disruptive — used in wiper attacks, sabotage campaigns, and as a last-resort action before defenders regain control. The Windows `cipher.exe /w` variant is particularly important: it overwrites the free space sectors of a drive with random data to make forensic recovery of previously deleted files impossible. Defenders monitor for this to detect anti-forensic wiping and end-of-incident cleanup operations.

## What This Dataset Contains

The test invokes `cipher.exe /w:C:` from PowerShell running as `NT AUTHORITY\SYSTEM`. Security EID 4688 captures the full process chain:

- `powershell.exe` spawns `cmd.exe /c cipher.exe /w:C:`
- `cmd.exe` (parent) spawns `cipher.exe /w:C:`

Sysmon EID 1 (ProcessCreate) captures two of these steps, with the cmd.exe event tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. The cipher.exe process itself ran for approximately two minutes (the dataset spans ~125 seconds from 22:33:46 to 22:35:51), consistent with the time required to overwrite free space on even a small drive. Security EID 4689 shows cipher.exe terminating with exit code `0xFFFFFFFF`, which indicates it was killed or interrupted before completing — the test framework cleanup likely terminated it rather than Defender blocking it.

Additional telemetry includes:
- Sysmon EID 17: PowerShell host pipe creation (`\PSHost.*.powershell`)
- Sysmon EID 10: PowerShell accessing whoami.exe, cmd.exe, conhost.exe, and cipher.exe (process access handles)
- Sysmon EID 11: File creation of PowerShell startup profile data
- Sysmon EID 3: mDNS traffic from svchost (background noise, not technique-related)
- Sysmon EID 7: 19 image load events from DLL loading during PowerShell and cipher execution
- Security EID 4624/4627/4672: SYSTEM logon and special privilege assignment
- System EID 7040: BITS service startup type changed (background activity)
- WMI EID 5858: WMI query failure for `Win32_ProcessStartTrace` watching for wsmprovhost.exe — background test framework activity

The PowerShell channel contains only internal PS module boilerplate (Set-StrictMode, CIM alias definitions) with no technique-specific script block content.

## What This Dataset Does Not Contain

`cipher.exe` does not appear as a Sysmon EID 1 event. The sysmon-modular include-mode configuration does not match `cipher.exe` as a suspicious process, so its process creation was filtered. The full extent of the wiping operation (which disk sectors were targeted, how much free space was overwritten) is not captured — there is no file-level telemetry for the overwrite behavior itself, only the process invocation. Object access auditing is disabled, so no EID 4663 file access events exist. Because cipher.exe was terminated early (0xFFFFFFFF exit), the overwrite did not complete, but the telemetry does not distinguish incomplete from complete execution.

## Assessment

This dataset provides a solid process chain for detecting the `cipher /w` anti-forensic pattern. Security EID 4688 is the strongest source, capturing the full command line `cipher.exe  /w:C:` with parent process context. Sysmon EID 1 captures the cmd.exe wrapper but misses the cipher.exe child due to include-mode filtering. The dataset would be stronger if cipher.exe appeared in Sysmon EID 1 with hash data; detection engineers wanting hash-based rules will need to rely on EID 4688. The ~2-minute runtime is realistic for actual attacks and the early termination is an artifact of the test framework, not Defender blocking.

## Detection Opportunities Present in This Data

1. **Security EID 4688**: Process creation for `cipher.exe` with command line containing `/w:` — direct detection of free-space wiping invocation.
2. **Security EID 4688**: `powershell.exe` spawning `cmd.exe /c cipher.exe` — suspicious parent chain from an interactive PowerShell session.
3. **Sysmon EID 1**: `cmd.exe` spawned from `powershell.exe` with command line `cipher.exe /w:C:` — same signal available in Sysmon where cmd.exe matched include rules.
4. **Security EID 4689**: `cipher.exe` exit code `0xFFFFFFFF` — abnormal termination of a wiping process may itself be a detection signal (interrupted wiper).
5. **Security EID 4688 + 4689 correlation**: `cipher.exe /w:` process creation followed within seconds by anomalous exit code — behavioral sequence rule.
6. **Sysmon EID 10**: PowerShell obtaining a process handle to cipher.exe — powershell directly accessing the wiper process is anomalous relative to normal system use.
