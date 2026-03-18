# T1095-2: Non-Application Layer Protocol — Netcat C2

## Technique Context

T1095 (Non-Application Layer Protocol) covers adversary use of non-HTTP/HTTPS protocols for C2. Netcat (`nc`/`ncat`) is one of the most commonly referenced tools in this category: a low-level TCP/UDP socket utility that can establish raw connections, act as a listener or connector, forward data between endpoints, and serve as a simple reverse shell transport. Its simplicity and availability make it ubiquitous in both red team exercises and real-world intrusions.

The Nmap project includes `ncat.exe` as a feature-rich Netcat implementation bundled with their network scanner. Attackers commonly stage `ncat.exe` separately from Nmap (using only the single binary) to establish raw TCP connections to C2 listeners. Because `ncat.exe` generates raw TCP traffic rather than HTTP, it can bypass network security controls that inspect only application-layer traffic — though its connections to unusual ports and lack of HTTP headers make it detectable by network monitoring that baselines expected traffic patterns.

This test executes `ncat.exe 127.0.0.1 80` — connecting to loopback on port 80 — as a proof-of-concept for netcat-based raw TCP C2. The loopback destination is used to demonstrate the execution behavior without making external connections in the lab environment.

## What This Dataset Contains

The dataset spans approximately fifteen seconds (2026-03-14T23:39:01Z–23:39:16Z) on ACME-WS06.acme.local and contains 155 events across four channels.

**The core execution command** appears in both Security EID 4688 and Sysmon EID 1. Security EID 4688 (PID 0x414, PowerShell) shows:

```
"powershell.exe" & {cmd /c \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe\" 127.0.0.1 80}
```

A second Security 4688 event captures the cmd.exe expansion (PID 0x59C):

```
"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe 127.0.0.1 80
```

Both run under `NT AUTHORITY\SYSTEM`.

**Sysmon EID 1** (2 events) captures:
- `whoami.exe` (PID 5208, rule `T1033`, parent powershell.exe PID 7028)
- `powershell.exe` (PID 1044, rule `T1059.001`, parent powershell.exe PID 7028): `"powershell.exe" & {cmd /c \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe\" 127.0.0.1 80}`

The `cmd.exe` and `ncat.exe` processes are not captured as Sysmon EID 1 events (ProcessCreate filter gap for these binaries in this test's sample), but the full command line is present in the Security channel.

**Sysmon EID 10** (5 events) records process access events with 0x1FFFFF access from PowerShell against child processes.

**Sysmon EID 7** (25 events) documents DLL loads for PowerShell instances: .NET runtime components and `System.Management.Automation.ni.dll` (rule `T1059.001`).

**Sysmon EID 17** (3 events) records named pipe creation from PowerShell.

**Sysmon EID 11** (3 events) captures PowerShell startup profile data file creation under `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`.

**Security EID 4688** (5 events total): two `whoami.exe` executions bracketing the test, the PowerShell with the ncat command, `cmd.exe` executing ncat, and the cleanup PowerShell `& {}`.

**PowerShell EID 4104** (106 events) and **EID 4103** (2 events) document the script block session. The ncat invocation (`cmd /c "...ncat.exe" 127.0.0.1 80`) appears in EID 4104, providing a second independent capture of the command. An EID 4103 pipeline execution event contains `Write-Host "DONE"` at completion.

**Application channel** (1 event, EID 15): standard Defender status update.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events appear for the ncat connection. Since the target is loopback (127.0.0.1), Sysmon does not generate EID 3 events for loopback connections on Windows — a known behavior. In a real deployment targeting an external C2, EID 3 would capture the TCP connection attempt including destination IP, port, and source port.

The `ncat.exe` process itself does not appear as a Sysmon EID 1 event — the ProcessCreate filter covers `cmd.exe` and `powershell.exe` via rules, but `ncat.exe` is not specifically included. The binary's execution is inferred from the `cmd.exe` command line argument.

No Defender blocking events exist anywhere in the dataset. In the defended variant, Defender detects `ncat.exe` as a potentially unwanted application (PUA) or tool and blocks or alerts on its execution; that blocking telemetry is absent here because Defender is disabled.

## Assessment

With Defender disabled, ncat executed without interference. The dataset provides clear, complete documentation of the ncat command line in both Security and Sysmon channels, along with a PowerShell EID 4104 script block capture.

Compared to the defended variant (39 Sysmon, 12 Security, 37 PowerShell), the undefended dataset is comparable in Sysmon (41 vs. 39) and slightly larger in PowerShell (108 vs. 37). The Security channel is smaller here (5 vs. 12) because Defender's inspection and alerting processes do not run. The higher PowerShell count in the undefended run reflects fuller script block logging without AMSI interference.

The fundamental detection data — the ncat command line with target IP and port — is equivalently captured in both variants.

## Detection Opportunities Present in This Data

**Process creation: ncat.exe from Nmap staging path**: Security EID 4688 captures the full path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe`. Any execution of `ncat.exe` from a non-standard administrative path (i.e., not from a documented IT toolset installation) is worth alerting on. Ncat's file name and the Nmap directory structure are distinctive.

**cmd.exe with ncat.exe as argument**: The Security 4688 event for `cmd.exe` contains `ncat.exe 127.0.0.1 80` as the command. Detecting `ncat.exe` or `nc.exe` in `cmd.exe` command line arguments provides a catch-all for ncat invocations regardless of the launching mechanism.

**PowerShell → cmd → ncat chain**: The process chain PowerShell spawning cmd.exe to execute a raw TCP socket tool under SYSTEM context is a behavioral pattern distinguishable from legitimate admin activity, particularly when the tool path includes staging directories like `ExternalPayloads`.

**Sysmon EID 3 to non-standard ports**: In a real deployment with an external C2 listener, `ncat.exe` connecting to an external IP on an unusual port would generate a Sysmon EID 3 event that is trivially detectable. The loopback destination in this test is a lab safety constraint; real-world use would be immediately visible in network telemetry.
