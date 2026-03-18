# T1105-7: Ingress Tool Transfer — certutil download (urlcache)

## Technique Context

T1105 (Ingress Tool Transfer) covers tools pulled onto a target system from external sources. Certutil.exe is one of the most widely documented LOLBins for file downloads: it is present on every Windows system, digitally signed by Microsoft, and its `-urlcache` flag was designed to fetch and cache certificates but will download any URL to disk. The `-split` flag combined with `-f` forces re-download even if a cached copy exists.

The command `certutil -urlcache -split -f <url> <local_filename>` has appeared in real-world adversary operations across diverse sectors for over a decade. This test downloads the Atomic Red Team license file from GitHub's raw content CDN to demonstrate the mechanism.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The download completed without interference.

**Process Chain (Security EID 4688):**

The ART test framework PowerShell (PID 0xa7c / 2684) spawns `cmd.exe` (PID 0x1178 / 4472) with:

```
"cmd.exe" /c cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
```

The double-cmd structure (`cmd /c cmd /c certutil ...`) is a common obfuscation pattern used by adversaries and some ART tests to add a layer of indirection—the outer cmd process is visible in parent process tracking, and its child cmd process actually spawns certutil. Note that certutil itself is not captured as a separate Security 4688 event in the samples (the collection window captured the cmd invocation), but Sysmon EID 1 evidence covers the process execution telemetry.

**Sysmon CreateRemoteThread (EID 8):**

A `CreateRemoteThread` event is detected at 23:46:02.815, with PowerShell (PID 2684) as the source and an `<unknown process>` (PID 4472, the cmd.exe instance that became a child of certutil) as the target. `StartAddress: 0x00007FF7F015F8F0`, `StartModule: -`, `StartFunction: -`—the module is not resolvable, indicating it is executing in the context of the freshly-created child process before its image is loaded and mapped. Sysmon tags this `technique_id=T1055,technique_name=Process Injection`. This is a false-positive classification in this context: the thread creation reflects how the .NET System.Diagnostics.Process class creates and monitors child processes via `CreateRemoteThread`-equivalent mechanisms, not actual shellcode injection. It is a recurring artifact of PowerShell-driven child process execution.

**Registry Writes (Sysmon EID 13):**

Three registry set events appear at 23:45:57.753, all written by `svchost.exe` (PID 1448) to `HKLM\System\CurrentControlSet\Services\NcbService\NCBKapiNlmCache\2\`:
- `\Networks` (Binary Data)
- `\NumNetworks` (DWORD: 0x1)
- `\Timestamp` (QWORD: 0x01dcb40c-0xb4a425af)

These are NcbService (Network Connectivity Broker) cache updates triggered by the network activity from the certutil download. The service detects a network connection and updates its internal network count and timestamp. These events are real OS behavior, not adversary artifacts—they confirm that a network connection was made.

**Process Access (Sysmon EID 10):**

PowerShell (PID 2684) accesses `whoami.exe` (PID 7164 and 6668) with `GrantedAccess: 0x1FFFFF`—the standard ART test framework process-wait pattern.

**Image Loads (Sysmon EID 7):**

Nine DLL load events for the PowerShell test framework process, including `mscoree.dll`, `mscoreei.dll`, `clr.dll`, and the standard .NET stack.

**Named Pipe (Sysmon EID 17):**

`\PSHost.134180055578689080.2684.DefaultAppDomain.powershell` created by PID 2684.

**PowerShell Script Block Logging (EID 4104/4100/4103):**

55 events total: 52 EID 4104 script block events, 2 EID 4100 (command not found / error start), and 1 EID 4103 (pipeline execution). The 4100/4103 events reflect execution of the certutil command string via `Invoke-Expression` or similar, where the error-handling path is triggered.

## What This Dataset Does Not Contain

There is no Sysmon EID 3 network connection event capturing certutil's outbound connection to GitHub. Certutil performs HTTP downloads through its own network stack (cryptnet.dll via WinHTTP), which may not generate Sysmon network events in standard configurations. No DNS query (EID 22) is captured either.

No Sysmon EID 11 file creation event captures the `Atomic-license.txt` download target. The downloaded file lands in `C:\Windows\TEMP\` (based on the working directory), but this specific write was not captured in the Sysmon sample. You cannot confirm the download completed from EID 11 alone in this dataset.

The certutil.exe process creation itself (EID 1 for certutil) is not in the sample set—the double-cmd wrapper means two cmd.exe instances appear in the process tree, and the certutil EID 1 event was sampled out of the Sysmon sample window.

## Assessment

This dataset is a strong capture of a well-known, high-value technique. The certutil urlcache command line appears verbatim in Security 4688, the NcbService registry updates confirm network activity occurred, and the process chain shows PowerShell driving cmd.exe to certutil. The absence of a certutil EID 1 and network EID 3 are instrumentation gaps, but the Security 4688 event with the full command line is the single most actionable piece of evidence in this dataset.

Compared to the defended variant, the undefended dataset has 55 PowerShell events versus 36 in the defended version. The defended run generates fewer PowerShell events because Defender intercepts or delays certutil execution, producing a shorter execution timeline. The Security channel has the same count (3 events) in both variants.

The EID 8 CreateRemoteThread artifact (Sysmon tagging it as T1055 injection) is a false positive that will appear consistently in ART test framework tests—it reflects PowerShell child process management, not actual injection.

## Detection Opportunities Present in This Data

**Certutil -urlcache in command line (EID 4688):** The string `certutil -urlcache -split -f <https-url>` in a Security 4688 New Process event is a direct, high-confidence indicator. This technique is so well-known that any occurrence in production telemetry warrants immediate investigation.

**Double-cmd wrapper pattern:** `cmd /c cmd /c certutil ...` is an obfuscation pattern that adds a layer to the process tree. Monitoring for cmd.exe processes whose command line starts with `/c cmd /c` and whose child process is certutil is a more specific behavioral indicator.

**NcbService registry write timing (EID 13):** The NCBKapiNlmCache registry writes at `HKLM\System\...\NcbService\` are a side-channel indicator of unexpected network connections during what should be non-network activity. While not directly attributable to certutil without correlation, a sudden NumNetworks update coinciding with a certutil process start is a meaningful correlation.

**PowerShell EID 4100/4103 alongside EID 4104:** The appearance of error-related pipeline events (4100/4103) mixed with 4104 script block events can indicate a command that was passed to a shell via string-based execution rather than a native PowerShell cmdlet.
