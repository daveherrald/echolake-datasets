# T1090.003-1: Multi-hop Proxy — Psiphon

## Technique Context

T1090.003 (Proxy: Multi-hop Proxy) covers adversary use of layered proxy infrastructure to obscure command-and-control communications and evade network-based detection. Psiphon is an open-source internet circumvention tool originally designed to bypass government censorship; it creates encrypted tunnels that route traffic through a distributed network of servers, effectively hiding the true destination of outbound connections.

Threat actors abuse Psiphon for C2 because its traffic patterns blend with legitimate censorship-circumvention usage in certain regions, its distributed server pool makes blocklist-based prevention difficult, and its installer/runner can be embedded as a batch file or single executable. When executed on a compromised host, Psiphon establishes an encrypted proxy locally (typically on a loopback port) and routes traffic through the Psiphon network — masking the real C2 endpoint from network monitoring focused on destination IP/domain reputation.

This test executes a Psiphon batch file included in the ART atomics repository (`C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat`) to demonstrate the installation and launch behavior, and tests cleanup via registry proxy settings restoration.

## What This Dataset Contains

The dataset spans approximately four minutes of activity (2026-03-14T23:35:30Z–23:39:33Z) on ACME-WS06.acme.local and contains 191 events across seven channels, making it the most event-rich dataset in this batch.

**The core execution chain** is captured in multiple channels. Security EID 4688 shows the complete process sequence:

1. `whoami.exe` — test framework environment check under SYSTEM
2. PowerShell (PID 3036): `"powershell.exe" & {& \"C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat\""}`
3. `cmd.exe`: `C:\Windows\system32\cmd.exe /c ""C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat""`
4. `sppsvc.exe` — Software Protection Platform, triggered by system activity during the test window
5. `MicrosoftEdgeUpdate.exe` — scheduled task running concurrently
6. Second `whoami.exe` — post-execution test framework check
7. Cleanup PowerShell: `"powershell.exe" & {$Proxy = Get-Content $env:Temp\proxy-backup.txt ... Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name "ProxyServer" -Value $Proxy}`

The cleanup step is significant: it reads a backed-up proxy setting from `$env:Temp\proxy-backup.txt` and restores the `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` registry value. This implies the Psiphon batch file modified the system proxy setting before the cleanup runs — a behavioral pattern you would see from a real Psiphon deployment that routes browser traffic through its local listener.

**Sysmon EID 1** (6 events) captures `whoami.exe` (PID 568) and the PowerShell child (PID 3036) with full command lines and hashes. The Psiphon batch invocation is flagged with rule `technique_id=T1059.001,technique_name=PowerShell`.

**Sysmon EID 10** (8 events) records PowerShell accessing child processes with 0x1FFFFF access.

**Sysmon EID 11** (7 events) records file creations, primarily PowerShell profile data files and standard PS startup artifacts under `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`.

**Sysmon EID 13** (1 event, registry value set) captures the proxy setting restoration in the cleanup phase, setting `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer`.

**Sysmon EID 17** (3 events) records named pipe creation from PowerShell processes.

**Sysmon EID 7** (27 events) documents DLL loads across the multiple PowerShell instances spawned during the test.

**Task Scheduler channel** (7 events) contains a full `MicrosoftEdgeUpdateTaskMachineUA` task lifecycle (EIDs 107, 100, 129, 200, 102, 201) plus EID 140 (task update for `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`). These are background OS events coinciding with the test window — their presence is a realistic representation of the ambient noise a defender would see on an active Windows workstation during investigation.

**System channel** (1 event, EID 7040) records a service startup type change, consistent with system activity during the test window.

**WMI channel** (1 event, EID 5858) records a WMI query error, also background activity.

**PowerShell EID 4104** (107 events) and **EID 4103** (12 events) document the full script block activity. Key blocks include the Psiphon.bat invocation, the proxy restore cleanup command, `Import-Module` for ART, and numerous runtime closure fragments.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events appear. If Psiphon successfully launched and connected to its relay network, the outbound TCP connections it establishes would appear here — their absence suggests either the Psiphon binary was not present at the expected path or failed to complete the network handshake during the test window.

No file creation events capture a Psiphon executable being downloaded or staged; the test relies on a pre-staged binary referenced by the batch file.

No registry events (Sysmon EID 13) capture the initial proxy modification by Psiphon — only the cleanup restoration is captured. The forward change (Psiphon setting the proxy) either happened before the event capture window or via a method that didn't trigger a Sysmon registry event in the sample set.

Psiphon's own process creation does not appear as a Sysmon EID 1, consistent with the coverage gap for third-party tools in the sysmon-modular configuration's ProcessCreate filter.

## Assessment

With Defender disabled, the test ran without blocking. The dataset contains compelling evidence of the Psiphon execution chain: the batch file invocation is fully captured in Security and Sysmon process creation events, and the cleanup phase's proxy registry restore is captured in Sysmon EID 13 — providing forensic evidence that the proxy settings were modified during execution.

Compared to the defended variant (42 Sysmon, 24 Security, 61 PowerShell, 1 System, 1 WMI), the undefended dataset is larger overall (52 Sysmon, 8 Security, 119 PowerShell, 1 System, 1 WMI, 7 TaskScheduler). The undefended run's additional Task Scheduler events represent a legitimate difference in the test window — a scheduled EdgeUpdate task fired during the longer execution period, adding realistic ambient context. The Security channel difference (8 vs. 24) likely reflects that the defended run generated Security events from Defender processes inspecting the Psiphon binary.

The most forensically interesting artifact unique to this dataset is the proxy cleanup command in the Security and PowerShell channels — it proves that the `HKCU:\...\Internet Settings\ProxyServer` key was modified during the test, even though the forward modification event is not directly captured.

## Detection Opportunities Present in This Data

**Process creation: Psiphon.bat from staging path**: Security EID 4688 and Sysmon EID 1 both capture `cmd.exe /c "C:\AtomicRedTeam\atomics\T1090.003\src\Psiphon.bat"`. Any execution of a file named `Psiphon.bat` or a command line containing `Psiphon` warrants investigation, particularly when invoked from PowerShell under SYSTEM.

**Registry modification to HKCU ProxyServer**: Sysmon EID 13 and the cleanup PowerShell script block in EID 4104 both show manipulation of `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer`. Proxy setting changes made programmatically — especially by non-browser processes — are a reliable behavioral indicator of proxy-based C2 tooling.

**PowerShell reading and writing proxy configuration files**: The cleanup block reads from `$env:Temp\proxy-backup.txt`. Processes reading from temp files with "proxy" in the filename and then writing registry proxy settings is a specific, detectable behavior pattern.

**SYSTEM-context batch file execution for circumvention tools**: The full chain runs under `NT AUTHORITY\SYSTEM` with a PowerShell → cmd.exe → batch file execution pattern. On a domain workstation, this combination without a clear administrative trigger is anomalous.

**Network connection to Psiphon relay infrastructure**: Though not present in this dataset, a successful Psiphon execution would generate Sysmon EID 3 events to Psiphon relay servers (typically on port 443 or 8080). Network-based monitoring for Psiphon's known certificate fingerprints or relay IP ranges provides a complementary detection layer.
