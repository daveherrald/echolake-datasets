# T1036.003-1: Rename Legitimate Utilities — Masquerading as Windows LSASS process

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where adversaries copy legitimate system binaries to new locations under deceptive names to blend in with the system process list. This specific test represents one of the most audacious masquerading targets: naming a binary `lsass.exe`. The legitimate `lsass.exe` (Local Security Authority Subsystem Service) is one of Windows' most critical processes — it handles authentication, stores credentials in memory, and runs as SYSTEM. Attackers copy `cmd.exe` to `C:\Windows\Temp\lsass.exe` and execute it, betting that operators performing rapid incident response may overlook a process named `lsass.exe` without closely examining its path or parent process.

In real attacker deployments, this technique precedes activities the attacker wants to obscure — a remote access tool, a credential dumper, or a lateral movement utility running under a trusted-looking process name. The masquerading is most effective against tooling that filters on process name without also checking the binary's path, original filename, or digital signature.

Detection relies on path anomalies: the real `lsass.exe` runs from `C:\Windows\System32\`, so any process named `lsass.exe` running from `C:\Windows\Temp\`, `C:\Users\`, or other writable directories should be treated as high-fidelity malicious activity. Sysmon's `OriginalFileName` field (from the PE header) is particularly valuable here, as it will show `cmd.exe` regardless of what the file is renamed to.

## What This Dataset Contains

This dataset spans a short execution window and contains 132 events: 105 PowerShell events, 6 Security events, 21 Sysmon events, and 6 Task Scheduler events.

The Security channel (EID 4688) contains the essential attack evidence. A `cmd.exe` process is launched by PowerShell with the command: `cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe & %SystemRoot%\Temp\lsass.exe /B`. This single command line both copies `cmd.exe` to `C:\Windows\Temp\lsass.exe` and immediately executes it with the `/B` (background) flag. A subsequent EID 4688 records the masqueraded process itself running: `NewProcessName: C:\Windows\Temp\lsass.exe`, `CommandLine: C:\Windows\Temp\lsass.exe /B`, with `ParentProcessName: C:\Windows\System32\cmd.exe`. The cleanup EID 4688 shows `cmd.exe /c del /Q /F %SystemRoot%\Temp\lsass.exe >nul 2>&1`.

This is the key difference from the defended dataset: in the defended version, Defender would block or flag execution of a renamed `lsass.exe` from a temp directory; here the execution proceeds cleanly. The process `C:\Windows\Temp\lsass.exe` running with parent `cmd.exe` appears in the Security log without any disruption.

Sysmon EID 1 records `cmd.exe` launching with the copy+execute command, tagged `technique_id=T1083,technique_name=File and Directory Discovery` (a Sysmon rule tag based on the filesystem copy operation). EID 10 shows PowerShell accessing `whoami.exe` memory. EID 7 image loads capture the standard .NET/Defender DLL chain for the test framework PowerShell process.

The Task Scheduler channel shows `\Microsoft\Windows\Workplace Join\Automatic-Device-Join` task executing — this is background domain join activity coinciding with the test window, completely unrelated to the technique.

One notable absence compared to the defended dataset (42 Sysmon events): the undefended version has 21 Sysmon events, reflecting that Defender's monitoring in the defended case generates additional events when examining the suspicious process.

## What This Dataset Does Not Contain

Sysmon EID 1 does not directly capture the execution of `C:\Windows\Temp\lsass.exe` itself — it appears in Security EID 4688 but falls outside the Sysmon include rules (which target known LOLBin patterns, not renamed temp-directory processes). This is a notable gap: the process running under the masqueraded name is only visible in Security log process creation, not Sysmon process creation.

No Sysmon EID 11 (file create) event captures the copy of `cmd.exe` to `lsass.exe` in `C:\Windows\Temp\`. File creation events in that directory are apparently not captured by this Sysmon configuration for `.exe` files created via `copy` commands.

The `OriginalFileName` field from the PE header — which would show `Cmd.Exe` for the `lsass.exe` process — is not surfaced in the Security EID 4688 events, only in Sysmon EID 1. Since the masqueraded process does not appear in Sysmon EID 1 in this dataset, that field is not directly available here.

## Assessment

This is a high-value dataset for detection engineering on process masquerading as critical system processes. The combination of Security 4688 showing the copy command and the execution of `C:\Windows\Temp\lsass.exe` provides clear ground-truth evidence. The dataset confirms the technique executes fully without interference when Defender is disabled. It is particularly useful for training models or testing detections that focus on process path anomalies for protected system processes.

## Detection Opportunities Present in This Data

1. EID 4688 (or Sysmon EID 1) for any process named `lsass.exe` running from a path other than `C:\Windows\System32\` is an extremely high-fidelity indicator that should be treated as confirmed malicious activity.

2. EID 4688 for `cmd.exe` with a command line containing `copy` with a destination filename matching a critical system process name (`lsass.exe`, `svchost.exe`, `csrss.exe`, etc.) in a writable directory.

3. The parent-child relationship `cmd.exe` → `lsass.exe` (where `lsass.exe` is in `C:\Windows\Temp\`) is anomalous — the real `lsass.exe` is started by `wininit.exe` and never has `cmd.exe` as a parent.

4. Any process running from `C:\Windows\Temp\` with a name matching a known critical Windows process (`lsass.exe`, `winlogon.exe`, `csrss.exe`, `smss.exe`) should trigger immediate investigation, regardless of command-line content.

5. EID 4688 command line containing `del /Q /F` targeting a path in `%SystemRoot%\Temp\` shortly after the execution of a suspiciously-named process from that same directory indicates deliberate cleanup of masqueraded process artifacts.
