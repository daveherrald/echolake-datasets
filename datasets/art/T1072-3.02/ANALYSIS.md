# T1072-3: Software Deployment Tools — Deploy 7-Zip Using Chocolatey

## Technique Context

T1072 (Software Deployment Tools) covers adversaries who abuse legitimate software deployment mechanisms — package managers, configuration management systems, remote administration platforms — to deliver and execute malicious payloads at scale. In an enterprise, these tools have broad reach by design: a single command can push software to hundreds or thousands of endpoints. When an attacker gains access to or abuses such a channel, the resulting activity is difficult to distinguish from legitimate IT operations.

Chocolatey is a Windows package manager that automates the download and installation of software from public or private package repositories. It is widely used by IT teams to manage software lifecycles on Windows endpoints. An attacker who can execute PowerShell commands as a privileged user can use Chocolatey to install attacker-controlled tools under the guise of routine software deployment — or, in a more opportunistic scenario, simply demonstrate that arbitrary software installation is possible from a compromised context.

This test exercises the basic primitive: using Chocolatey to install 7-Zip on a domain-joined workstation, run as SYSTEM, replicating what a threat actor with deployment tool access might do to stage additional capability.

## What This Dataset Contains

This dataset captures the full execution of `choco install -y 7zip` on a Windows 11 Enterprise domain workstation (ACME-WS06.acme.local) with Defender disabled. The test runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) and Sysmon (EID 1) both record the initiating PowerShell process with the complete command line visible:

```
"powershell.exe" & {# Deploy 7-Zip using Chocolatey
choco install -y 7zip}
```

This is the ART test's literal test content — the comment and command are passed verbatim as a PowerShell script block.

The Sysmon channel captures 57 total events: 30 EID 11 (file creation), 16 EID 7 (image/DLL load), 4 EID 1 (process creation), 4 EID 10 (process access), and 3 EID 17 (named pipe creation). The EID 17 events show PowerShell host pipes being created under `NT AUTHORITY\SYSTEM`:

```
PipeName: \PSHost.134180045357621609.6096.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The Security channel (17 events) breaks down as: 16 EID 4688 (process creation) and 1 EID 4985 (transaction state change). The 4688 events include `mscorsvw.exe` (the .NET Native Image Generator worker process) appearing repeatedly — this is the .NET background compiler that runs automatically when new .NET assemblies are registered, triggered by Chocolatey's package installation activity. The `mscorsvw.exe` instances are characteristic background activity produced by any software installation that includes managed .NET components.

The PowerShell channel contains 104 EID 4104 script block events. These include the ART test framework module import (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`) and cleanup block (`Invoke-AtomicTest T1072 -TestNumbers 3 -Cleanup -Confirm:$false`), with the remainder being PowerShell runtime internal script blocks.

The file creation events (EID 11) are dominated by `mscorsvw.exe` writing compiled native images to `C:\Windows\assembly\NativeImages_v4.0.30319_64\`, representing the .NET NGen compilation of newly installed managed assemblies.

Compared to the defended dataset (26 sysmon, 10 security, 42 PowerShell events), this undefended capture contains roughly double the event volume across all channels. The defended dataset showed truncated execution with Defender interfering with the installation process; here the installation runs to completion.

## What This Dataset Does Not Contain

The package installation succeeded (7-Zip was installed on the endpoint), but the Sysmon file creation samples captured in this dataset do not include events for the 7-Zip binary itself (`7z.exe`, `7z.dll`) being written to `C:\Program Files\7-Zip\` — the samples show the .NET NGen compilation side effects rather than the installation target. The 30 total EID 11 file creation events in this dataset are dominated by `mscorsvw.exe` and `.NET assembly` cache writes.

There are no Sysmon EID 3 (network connection) events in this dataset, meaning the actual download of the 7-Zip package from the Chocolatey CDN is not captured as a network connection event. Chocolatey's download mechanism uses HTTPS and the network connection may not have matched Sysmon's network filtering rules, or the download completed before/outside the precise capture window for that event type.

This dataset does not include Windows Installer (`msiexec.exe`) or setup process events, which would appear in a more complete capture of a full MSI-based installation.

## Assessment

This dataset demonstrates what software deployment tool abuse looks like from an endpoint telemetry perspective when the execution is not interrupted. The key artifacts are the PowerShell process creation event with `choco install -y 7zip` in the command line, the subsequent mscorsvw.exe activity confirming that package installation triggered .NET compilation (a reliable indicator that a managed software package was actually installed), and the named pipe creation events showing PowerShell host instances spun up under SYSTEM.

The undefended execution provides a baseline for what Chocolatey-based software deployment generates in telemetry. An attacker performing this action in a real environment would produce the same process creation and NGen compilation events — the distinguishing factor would be context: who is running Chocolatey, from what parent process, installing what package, at what time.

The comparison with the defended dataset is instructive: Defender's interference in the defended run reduced event volume significantly. The undefended dataset shows the complete execution path without truncation.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — Command line visibility:** The PowerShell command line `choco install -y 7zip` is recorded verbatim in the process creation event. This is the most direct indicator of Chocolatey-based installation activity initiated by a non-interactive process.

**Parent-child process relationship:** The `choco` invocation originates from a `powershell.exe` process running as `NT AUTHORITY\SYSTEM`, which is itself spawned by the ART runner. In a real deployment tool abuse scenario, the parent would be the deployment agent (e.g., SCCM client, remote management tool, scheduled task); the anomaly lies in the lineage and context, not the Chocolatey command itself.

**mscorsvw.exe spawning as SYSTEM:** Multiple `mscorsvw.exe` (NGen worker) processes created under `NT AUTHORITY\SYSTEM` in rapid succession with pipe-based IPC arguments is a reliable secondary indicator that .NET assembly registration occurred — which follows any managed software installation. This pattern can be correlated with the preceding package manager invocation.

**Sysmon EID 17 — Named pipe creation:** PowerShell host pipes created under SYSTEM (`\PSHost.*`) indicate non-interactive PowerShell execution. Combined with the process creation events, these confirm a headless PowerShell session running privileged operations.

**Security EID 4985 — Transaction state change:** The presence of a transactional NTFS state change event during software installation indicates file system transaction activity consistent with an installer that uses atomic file operations. This event type is uncommon in normal endpoint operation and can help corroborate that a significant file system modification occurred.
