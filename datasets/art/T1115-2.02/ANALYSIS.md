# T1115-2: Clipboard Data — Execute Commands from Clipboard using PowerShell

## Technique Context

T1115 Clipboard Data describes adversaries collecting data stored in the clipboard, which may contain credentials, sensitive documents, or other valuable information copied by users. This test demonstrates a more active variant of the technique: the attacker does not merely read the clipboard passively but instead weaponizes it as a command execution channel.

The test uses `clip.exe`, the built-in Windows clipboard command, to load a PowerShell command string (`Get-Process`) into the clipboard. It then retrieves that content with `Get-Clipboard` and pipes the result through `iex` (Invoke-Expression) for immediate execution. This is a code execution pattern — use the clipboard as an in-memory staging area to avoid writing payloads to disk. In real-world attacks, this technique is used to make `iex` calls look less suspicious by obscuring the actual command string in a clipboard operation rather than embedding it directly in a script.

The specific payload here is benign (`Get-Process`), but the execution pathway — `clip.exe` to populate clipboard, then `Get-Clipboard | iex` — is what matters for detection.

## What This Dataset Contains

The dataset captures 40 Sysmon events, 5 Security events, and 123 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The technique execution is cleanly recorded in Security EID 4688. A child PowerShell process spawns with the command:

```
"powershell.exe" & {echo Get-Process | clip
Get-Clipboard | iex}
```

`clip.exe` is created as a further child process: `"C:\Windows\system32\clip.exe"`, with `powershell.exe` as the parent (EID 4688).

Sysmon EID 1 records the same two-step process chain with full SHA256 hashes: the spawned `powershell.exe` (`SHA256: 3247BCFD...`, IMPHASH: `AFACF6DC...`) and `clip.exe`. Sysmon EID 10 (Process Accessed) shows PowerShell accessing the spawned child processes with `GrantedAccess: 0x1FFFFF`.

Sysmon EID 17 records two named pipe creations for the PowerShell host processes:
- `\PSHost.134182389691583719.14884.DefaultAppDomain.powershell`
- `\PSHost.134182389750038048.15580.DefaultAppDomain.powershell`

These correspond to the outer ART test framework process and the child PowerShell that runs the technique.

Sysmon EID 11 (File Create) records two file system artifacts in the PowerShell profile directory:
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`

These are normal PowerShell startup artifacts written when a new PowerShell process initializes under `NT AUTHORITY\SYSTEM` for the first time.

The PowerShell channel (123 events) is dominated by EID 4104 script block boilerplate from the ART test framework. The `Get-Clipboard | iex` payload itself is simple enough that it executes without generating large script block captures beyond the command block visible in the process creation log.

The Security channel also records the cleanup-phase `whoami.exe` invocation (EID 4688), which is the ART test framework confirming context after execution.

## What This Dataset Does Not Contain

This dataset does not contain any clipboard content capture of user-typed data — the technique here writes to the clipboard rather than reading data the user already placed there. You will not see Windows Clipboard History events or any Clipboard Manager artifacts.

There are no network events. The `Get-Process` payload produced local output only.

No Security EID 4663 (Object Access) for clipboard API calls, because the host does not have Object Access auditing enabled and Windows clipboard operations do not generate Security audit events in the default configuration.

Compared to the defended variant (27 Sysmon / 12 Security / 50 PowerShell), this dataset is substantially larger in the PowerShell channel (123 vs. 50). With Defender disabled, the AMSI provider is not present to gate script block submissions, resulting in the full volume of PS host boilerplate blocks being logged. The Security channel is smaller here (5 vs. 12) because the defended execution triggered additional Defender process creation events during inspection.

## Assessment

This is a complete dataset for the clipboard-as-execution-channel pattern. The `clip.exe` invocation and the `Get-Clipboard | iex` command string are both present verbatim in process creation logs. You have the full process ancestry: outer PowerShell test framework → spawned PowerShell → `clip.exe`.

The dataset accurately represents what this technique looks like when fully executed without interference. The command-line content in EID 4688 and Sysmon EID 1 is the primary detection surface; the `Get-Clipboard | iex` pattern is a distinctive indicator that does not appear in legitimate PowerShell usage.

The dataset is compact (collected within a few seconds) and the event volume is moderate, making it tractable for building and validating behavioral analytics.

## Detection Opportunities Present in This Data

**`Get-Clipboard` combined with `iex` in a PowerShell command line or script block.** EID 4688 and Sysmon EID 1 record the child PowerShell command line containing `Get-Clipboard | iex`. This specific combination — clipboard read directly piped to expression evaluation — is unusual in legitimate administrative PowerShell and high-fidelity as an indicator.

**`clip.exe` spawned by PowerShell.** Security EID 4688 and Sysmon EID 1 record `clip.exe` with `powershell.exe` as the parent. While `clip.exe` is a legitimate utility, it is rarely launched directly from PowerShell rather than from command-line pipelines or batch scripts. Parent-child analysis on this pair, especially combined with the `Get-Clipboard | iex` in the sibling PowerShell invocation, provides strong compound detection.

**PowerShell spawning a child PowerShell.** Sysmon EID 1 shows `powershell.exe` as both the `Image` and `ParentImage`. Double-hop PowerShell spawning is a hallmark of both ART-style test frameworkes and real offensive tools that use PowerShell-to-PowerShell launching for privilege separation or script isolation. Combined with the clipboard payload pattern, this is high-confidence.

**Script block logging capturing `Set-ExecutionPolicy Bypass`.** EID 4104 records `Set-ExecutionPolicy Bypass -Scope Process -Force`, which is characteristic of the ART test framework but is also commonly used by offensive PowerShell tools to remove execution policy enforcement before running downloaded or injected payloads.
