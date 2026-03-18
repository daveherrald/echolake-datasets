# T1562.001-54: Disable or Modify Tools — Disable EventLog-Application Auto Logger Session Via Registry - Cmd

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools, including event logging infrastructure. This test disables the `EventLog-Application` ETW Auto Logger session by setting `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\Start` to `0` via `reg.exe`. The Auto Logger is a kernel-level ETW session that starts at boot time and feeds events into the Windows Event Log service. Disabling it prevents Application log events from being collected during early boot before the Event Log service starts. This technique targets event log infrastructure rather than a security product directly, making it useful for reducing forensic visibility during early-stage attack activity that occurs before full system initialization.

## What This Dataset Contains

**Security (4688):** Two meaningful process creation events capture the execution chain:
1. A parent PowerShell spawning `cmd.exe` with:
   ```
   "cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d "0" /f
   ```
2. `cmd.exe` spawning `reg.exe` executing the same command directly.

Both processes exit with status 0x0. The test framework PowerShell and `conhost.exe` lifecycle events are also present.

**Sysmon Event 1:** Process creation events for `whoami.exe` (test framework pre-check), `cmd.exe` (test framework spawning the command), and `reg.exe` (executing the registry write). The `reg.exe` command line clearly shows the target AutoLogger path and `Start = 0`.

**Sysmon Event 7 (Image Loaded):** Multiple DLL load events for `.NET` runtime components and Defender's `MpClient.dll` loading into the test framework PowerShell — standard PowerShell initialization noise.

**Sysmon Event 10 (Process Access):** Cross-process access events from the test framework PowerShell to other PowerShell instances — consistent with ART test framework behavior.

**Sysmon Event 17 (Pipe Created):** Named pipe creation `\PSHost.*` events for each PowerShell instance.

**PowerShell (4104):** The ART test framework `Set-ExecutionPolicy Bypass` script blocks are present. The technique command itself does not appear in a 4104 block because it is executed via `cmd.exe` rather than as a PowerShell expression.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 (RegistryValue Set):** Despite `reg.exe` successfully writing to `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\Start`, the Sysmon registry monitoring configuration does not match this path for Event 13 capture. The write is only evidenced by the `reg.exe` command line.

**No PowerShell technique script block:** Because the technique is dispatched via `cmd.exe` rather than as a PowerShell expression, no 4104 script block containing the technique content is generated. The ART test framework script block shows the `cmd.exe` invocation only.

**No Event Log service disruption events:** The Auto Logger `Start = 0` change takes effect on next reboot. No immediate disruption of the running Event Log service is captured.

**No Windows Event Log channel-specific events:** There are no events from the Application log itself confirming the Auto Logger was active before the change.

## Assessment

The technique executed successfully with `reg.exe` exiting 0x0. The detection surface is limited to process creation telemetry — the `reg.exe` command line containing the full AutoLogger path and `Start /d 0`. The absence of Sysmon 13 for this path is a notable coverage gap. Security 4688 and Sysmon 1 are the primary detection sources. This dataset pairs with T1562.001-55 which performs the equivalent operation via PowerShell, providing a useful contrast for detection coverage comparison.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1:** `reg.exe` process creation with command line containing `WMI\Autologger\EventLog-Application` and `/v Start /d 0` — specific and high-fidelity
- **Sysmon 1:** `cmd.exe` spawned from `powershell.exe` with the full AutoLogger disable command visible
- **Security 4688:** `powershell.exe → cmd.exe → reg.exe` execution chain targeting an ETW AutoLogger path — the chain itself is suspicious
- **Temporal pattern:** `whoami.exe` followed immediately by `cmd.exe`/`reg.exe` targeting event log infrastructure — consistent with ART test framework pre-execution identity check
- **AutoLogger key hunting:** Periodic queries for `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\Start = 0` as a registry state hunt
