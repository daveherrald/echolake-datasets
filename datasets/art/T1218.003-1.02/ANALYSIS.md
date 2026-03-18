# T1218.003-1: CMSTP — CMSTP Executing Remote Scriptlet

## Technique Context

CMSTP (Microsoft Connection Manager Service Profile Installer, `cmstp.exe`) is a signed Windows binary designed to install Connection Manager service profiles for VPN and dial-up configurations. T1218.003 exploits CMSTP's ability to execute code from `.inf` files — specifically, the `RegisterOCXSection` or `RunPreSetupCommandsSection` keys within a crafted INF file can point to remote scriptlets (`.sct` files), causing `cmstp.exe` to download and execute arbitrary code.

The technique is attractive to adversaries because `cmstp.exe` is signed by Microsoft, can bypass many application whitelisting controls, and can execute remote payloads via `scrobj.dll` without writing the scriptlet to disk. The `/s` (silent) flag suppresses the usual user consent dialog. Detection typically focuses on `cmstp.exe` command-line arguments containing `/s`, the presence of suspicious `.inf` files referencing remote URLs, CMSTP network connections, and service configuration changes that follow CMSTP execution.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-17T16:49:26Z to 16:49:32Z) across 216 total events: 107 PowerShell, 16 Security, 87 Sysmon, 1 System, and 5 Task Scheduler events.

**CMSTP invocation chain (Sysmon EID 1 and Security EID 4688):** The execution chain is clearly visible. PowerShell (PID 16644, parent) spawned `cmd.exe` (PID 17072 / 0x42b0) with the command:

```
"cmd.exe" /c cmstp.exe /s "C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003.inf"
```

`cmd.exe` then spawned `cmstp.exe` (PID 0x4564). The Security EID 4688 records confirm the chain: PowerShell (0x4104) → cmd.exe (0x42b0) → cmstp.exe (0x4564). The working directory throughout is `C:\Windows\TEMP\` and all processes run as `NT AUTHORITY\SYSTEM`.

**CMSTP file creation (Sysmon EID 11):** `cmstp.exe` (PID 17764) created a directory at `C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Network\Connections`. This is the standard CMSTP profile storage path and confirms `cmstp.exe` processed the INF file to the point of writing profile data. The sysmon-modular rule tagged this as `technique_id=T1574.010,technique_name=Services File Permissions Weakness` due to the sensitive system profile path.

**Service configuration change (System EID 7040):** The `Remote Access IP ARP Driver` service had its start type changed from demand start to auto start. This is a direct consequence of CMSTP processing the `.inf` file — the INF's `[DefaultInstall]` section configures network connectivity services. This service modification is a distinctive artifact of CMSTP execution with a valid profile INF.

**Service process creation (Security EID 4688):** Multiple `svchost.exe` processes were spawned by `services.exe` (PID 0x2f0) following the service start type change, confirming that Windows acted on the CMSTP-modified service configuration.

**Logon events (Security EID 4624/4672):** Three Logon Type 5 (service logon) events and corresponding special privilege assignments confirm service account activity triggered by the CMSTP execution and resulting service changes.

**Task Scheduler background activity:** Task Scheduler events (EIDs 100, 129, 200, 201, 102) record the `\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload` task launching `dmclient.exe` — unrelated background Windows telemetry that coincided with the test window.

**Sysmon EID 13 registry events (45 total, not in sample set):** The breakdown shows 45 registry value set events captured in the full dataset. These are sampled out of the 20-event sample window, but their presence confirms that CMSTP processing the INF file triggered extensive registry writes — typically writing Connection Manager profile settings under `HKLM\SYSTEM\CurrentControlSet\Services\` and related service configuration keys.

**Process access events (Sysmon EID 10):** PowerShell (PID 16644) opened four child processes with full access rights: whoami.exe (PID 18208), cmd.exe (PID 17072), whoami.exe (PID 16176), and cmd.exe (PID 17448) — all tagged `technique_id=T1055.001`. This reflects normal test framework monitoring behavior.

## What This Dataset Does Not Contain

The remote scriptlet execution itself — the core payload delivery mechanism — is not visible here. The test INF file at `C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003.inf` references a remote scriptlet URL, but there are **no network connection events (Sysmon EID 3)** in the dataset. This means either the remote scriptlet host was unreachable during the test (the URL likely references `127.0.0.1` or a local simulation), or the network connection fell outside the Sysmon capture window.

Also absent:
- `scrobj.dll` image loads that would accompany COM scriptlet execution
- Any process spawned by `cmstp.exe` as a child (the scriptlet payload)
- DNS resolution events for any remote scriptlet host (Sysmon EID 22 shows only one event, which is unrelated)
- File writes of a downloaded `.sct` payload

## Assessment

This is a successful and well-evidenced CMSTP execution. The complete process chain from PowerShell through `cmd.exe` to `cmstp.exe` is recorded with full command lines. The service start type modification (System EID 7040) and subsequent `svchost.exe` spawning confirm that CMSTP processed the INF file to completion. The file creation at the Connections profile path provides a filesystem artifact tied specifically to `cmstp.exe`.

Comparing with the defended variant (16 Sysmon, 12 Security, 35 PowerShell events): the undefended run captures substantially more — 87 Sysmon events (the 45 registry events alone represent CMSTP's service configuration writes) versus 16 in the defended run. This difference highlights exactly what Defender suppresses: the downstream service configuration telemetry that follows CMSTP execution. The core `cmstp.exe` process create is present in both, but the rich registry change trail is unique to the undefended dataset.

## Detection Opportunities Present in This Data

**`cmstp.exe` with `/s` flag and a non-standard INF path (Sysmon EID 1, Security EID 4688):** The command line `cmstp.exe /s "C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003.inf"` makes the technique explicit. Legitimate CMSTP usage rarely involves `/s` with INF files outside of system directories.

**`cmd.exe` spawned by PowerShell, immediately executing `cmstp.exe` (Sysmon EID 1):** The parent-child chain PowerShell → cmd.exe → cmstp.exe is a reliable hunting anchor, particularly when the parent is a non-interactive PowerShell session running as SYSTEM from `C:\Windows\TEMP\`.

**System EID 7040 — service start type change following CMSTP execution:** The `Remote Access IP ARP Driver` service transition from demand start to auto start is a direct consequence of INF processing. Correlating a System 7040 event with a preceding `cmstp.exe` process create is a high-fidelity detection pattern.

**`cmstp.exe` file creation in system profile network connections path (Sysmon EID 11):** The write to `C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Network\Connections` by `cmstp.exe` is a distinctive file system artifact. File creation or modification under this path by `cmstp.exe` is worth flagging.

**Service logon events (Security EID 4624/4672) correlated with service changes:** Multiple service logons immediately following a CMSTP process create indicate that the INF file triggered service activation, which is the intended CMSTP abuse mechanism.
