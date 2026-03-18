# T1082-35: System Information Discovery — Check OS version via "ver" command

## Technique Context

T1082 (System Information Discovery) includes the most primitive OS enumeration technique on Windows: running `ver` from the command prompt. The `ver` command returns the Windows version string and has been a standard recon step for decades, appearing in malware, pen test toolkits, batch scripts, and ransomware alike. Adversaries use it during initial access validation to confirm they have a real Windows target, to select payloads appropriate for the OS version, and to determine whether patches of interest are likely installed.

The test executes `cmd.exe /c ver` as a child of PowerShell, which is the pattern you would observe when an attacker issues the command from within a PowerShell session. Defender does not flag `ver`, so the defended and undefended datasets are structurally identical — this is a fully detectable-but-not-blocked technique in both environments.

## What This Dataset Contains

This dataset covers a 4-second window (2026-03-14T23:32:58Z–23:33:02Z) capturing the `ver` command execution chain.

**Process execution chain**: Sysmon EID 1 records three processes. First, `whoami.exe` (PID 3060) at 23:32:58 as a pre-execution identity check. Then `cmd.exe` (PID 6524) at 23:33:01 with command line `"cmd.exe" /c ver`, tagged by sysmon-modular with `technique_id=T1059.003,technique_name=Windows Command Shell`. The working directory is `C:\Windows\TEMP\` and the process runs as `NT AUTHORITY\SYSTEM`. Finally, a second `whoami.exe` (PID 4308) at 23:33:02 as a post-execution check.

The parent PowerShell process is not captured as an EID 1 event in the available samples (it was created slightly before the window), but is implied by the `whoami.exe` and `cmd.exe` processes running under the test framework.

**Security events**: Three EID 4688 events cover `whoami.exe`, `cmd.exe`, and a second `whoami.exe`. The `cmd.exe` entry confirms `New Process Name: C:\Windows\System32\cmd.exe` with the `"cmd.exe" /c ver` command. Creator SID is `S-1-5-18` (SYSTEM) with logon ID `0x3E7`.

**PowerShell script block logging**: 93 EID 4104 events were captured. The available samples are PowerShell initialization fragments; the actual `cmd.exe /c ver` command is a native process launch, not a PowerShell script block, so the most important telemetry for this technique is in EID 4688 and Sysmon EID 1.

**DLL loading**: Nine Sysmon EID 7 events reflect the lightweight .NET and PowerShell runtime. Compared to the PowerSharpPack tests, the DLL load count is lower because no large C# assembly was loaded.

**Process access**: Three Sysmon EID 10 events show the test framework PowerShell accessing child processes.

**Named pipe**: Sysmon EID 17 records the standard `\PSHost.*.powershell` pipe.

The undefended run (16 sysmon, 3 security, 93 powershell) is nearly identical to the defended run (36 sysmon, 12 security, 34 powershell) in structural content, though the event counts differ. The defended run's higher Sysmon and Security counts reflect Defender-related process activity, while its lower PowerShell count reflects different initialization behavior. For the technique itself, the telemetry is the same in both environments.

## What This Dataset Does Not Contain

The `ver` command output — the actual Windows version string — does not appear in any event. The command runs in a non-interactive context (`cmd.exe /c ver`), and output goes to the parent process, not to a log. There are no file writes, no network connections, and no registry reads associated with this technique. The technique's footprint is limited to the process creation events.

## Assessment

This is the simplest dataset in this collection. The only technique-relevant events are the `cmd.exe /c ver` process creation in Sysmon EID 1 and Security EID 4688. The command line is explicit and unobfuscated. The context — SYSTEM-level PowerShell spawning `cmd.exe` from `C:\Windows\TEMP\` — is the strongest anomaly indicator here.

The dataset demonstrates that even the most basic recon commands produce complete, accurate process creation telemetry. An attacker who obfuscates the PowerShell invocation that leads to `cmd.exe /c ver` may evade script block detection, but the `cmd.exe` process creation event remains.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: `cmd.exe /c ver` spawned from `powershell.exe` running as SYSTEM in `C:\Windows\TEMP\` is a reliable indicator. The command itself is not suspicious — it is the execution context that matters.

**Process ancestry**: `NT AUTHORITY\SYSTEM` → `powershell.exe` → `cmd.exe /c ver` → `whoami.exe` as a rapid sequence in under 4 seconds is a behavioral signature of automated reconnaissance. Legitimate administrators running `ver` interactively do not generate this process chain.

**Working directory**: `C:\Windows\TEMP\` as the `CurrentDirectory` for the PowerShell parent process is a consistent test framework artifact, but also reflects real-world attacker behavior where the initial foothold lands in a writable system directory.

**Temporal correlation**: This test executed at 23:33:01, within seconds of `Get-CimInstance Win32_OperatingSystem` (T1082-34 at 23:32:49) and `hostname` (T1082-7 at 23:33:12). A burst of OS discovery commands within a 30-second window, all as SYSTEM, is a strong indicator of systematic enumeration.
