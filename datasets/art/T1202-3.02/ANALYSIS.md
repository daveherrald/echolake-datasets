# T1202-3: Indirect Command Execution — conhost.exe

## Technique Context

T1202 (Indirect Command Execution) covers the use of trusted Windows binaries to launch arbitrary processes, bypassing controls that focus on the launched process's own characteristics. `conhost.exe` — the Windows Console Host — is normally an infrastructure process that manages console window rendering for command-line applications. However, it accepts command-line arguments and can be used to spawn processes in a way that shifts the apparent parent from a suspicious binary to the innocuous-looking conhost.exe. The technique `conhost.exe notepad.exe` causes conhost to launch notepad as if notepad were the hosted console application.

## What This Dataset Contains

This dataset captures the core command sequence for conhost.exe-based indirect execution. Security EID 4688 records 4 process creations: two `whoami.exe` invocations (ART test framework validation), and two `cmd.exe` invocations. The key technique execution is the `cmd.exe` (PID 0x31ec) process with the suspicious indirect execution pattern.

The Sysmon channel provides 19 events: 9 EID 7 (DLL loads), 4 EID 1 (process creation), 4 EID 10 (process access), 1 EID 17 (named pipe), and 1 EID 11 (file creation). Sysmon EID 1 captures two `whoami.exe` creations and two `cmd.exe` creations. The process access events (EID 10) show PowerShell accessing the spawned processes with handle rights typical of process management.

The EID 11 event records the standard PowerShell startup profile file write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`.

The PowerShell channel provides 107 events, all ART test framework boilerplate — `Set-ExecutionPolicy Bypass -Scope Process -Force`, `Write-Host "DONE"`, and StrictMode setup blocks. The Application channel records 1 event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, confirming defenses were re-enabled post-test.

## What This Dataset Does Not Contain

There is no Sysmon EID 1 event for a `conhost.exe` process with a child argument, nor any process creation event showing `notepad.exe` launching as a result of the technique. This may reflect either the Sysmon configuration's process include rules (conhost.exe is often excluded from monitoring as infrastructure noise), or a timing issue where the process completed before all events were collected. The Security channel EID 4688 events similarly do not show conhost.exe or notepad.exe process creations in the available samples.

In the defended variant (Sysmon: 36, Security: 11, PowerShell: 34), the technique also executed but produced more Sysmon events. The difference (19 vs. 36 Sysmon events) is unexpected given that Defender is disabled here — it may reflect the conhost process completing more quickly without Defender's scan overhead, compressing the event capture window.

No network connections (Sysmon EID 3), DNS queries (EID 22), or file writes related to the technique are present, consistent with this being a purely local execution test.

## Assessment

The available telemetry documents the command invocation (`cmd.exe /c conhost.exe "notepad.exe"`) at the Security EID 4688 layer but the conhost.exe and notepad.exe process creations themselves are not captured in the sampled events. The dataset still provides value as a training example because the Security channel command line with `conhost.exe "notepad.exe"` as the argument is the primary detection artifact — the child process's own creation is secondary confirmation. Defenders who rely solely on parent-child process tree analysis may miss this technique if conhost.exe is filtered as infrastructure noise; the command line content is the more reliable signal.

Compared to the defended dataset, this undefended version shows that Defender does not block conhost.exe-based proxy execution — the technique succeeds in both environments — making the command-line detection approach critical regardless of endpoint protection status.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: `cmd.exe` with arguments containing `conhost.exe` followed by an executable path — this is not a normal pattern for cmd.exe usage; conhost.exe is normally launched by the operating system, not called directly from cmd
- **Security EID 4688**: `cmd.exe /c conhost.exe "<payload>"` as a child of `powershell.exe` represents the indirect execution pattern; the conhost argument should be a console-attached subprocess reference, not a standalone binary path
- **Process lineage anomaly**: `notepad.exe` (or any interactive/GUI application) appearing as a child of `conhost.exe` in an automated or SYSTEM context is strongly anomalous — legitimate conhost children are always console-subsystem processes
- **Sysmon EID 10**: PowerShell accessing newly created processes with full access rights in sequence with cmd.exe invocations is a behavioral pattern of scripted multi-step execution
