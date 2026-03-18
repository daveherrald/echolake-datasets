# T1569.002-6: Service Execution — Snake Malware Service Create

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. This test simulates the Snake malware family's
technique of installing a persistence service using `sc.exe create` with a masqueraded
service name and a binary path pointing to a deeply-nested legitimate-looking executable.
Snake (also known as Uroburos), attributed to Russia's FSB, is a sophisticated modular
rootkit that uses Windows services for persistence. The ART test creates a service named
`WerFaultSvc` with a binary path referencing a deep WinSxS path to blend with legitimate
OS components.

The service name `WerFaultSvc` deliberately mimics the Windows Error Reporting service
(`WerSvc`), and the binary path — a WinSxS path for a legacy WerFault.exe build — creates
the appearance of a legitimate Windows component service. The binary path contains an
unexpanded environment variable (`$env:windir`) which is anomalous: the SCM stores fully-
expanded paths in the registry.

In the defended variant, this test succeeded without Defender interference (service creation
via `sc.exe` is not blocked by Defender). The defended dataset contained System EID 7045,
Sysmon EID 1 for `sc.exe`, and Sysmon EID 13 for six registry writes by `services.exe`.
This undefended dataset reflects the same technique executing identically, with the expected
artifacts present.

## What This Dataset Contains

The dataset spans approximately 3 seconds (17:42:02–17:42:05 UTC) and contains 126 total
events across three channels.

**System channel (1 event) — EID 7045:**

The System EID 7045 (new service installed) is the most operationally significant event:

```
Service Name:  WerFault Service
Service File Name:  $env:windir\WinSxS\x86_microsoft-windows-errorreportingfaults_31bf3856ad364e35_4.0.9600.16384_none_a13f7e283339a050\WerFault.exe
Service Type:  user mode service
Service Start Type:  auto start
Service Account:  LocalSystem
```

Two indicators stand out:

1. **`$env:windir` in the service binary path** — the SCM stores fully-expanded paths
   (e.g., `C:\Windows\WinSxS\...`). An unexpanded environment variable is anomalous and
   indicates the service was created programmatically rather than through normal installer
   channels. This service would fail to start because the SCM cannot resolve the literal
   string `$env:windir`.

2. **`auto start` + `LocalSystem`** — an auto-start LocalSystem service with a non-existent
   effective binary is a persistence mechanism: it registers as a service that runs at boot
   but would fail silently. The service would appear in `sc query` output as a registered
   service.

**Security channel (18 events) — EIDs 4688, 4689, 4703:**

EID 4688 captures the full service creation chain:

**`cmd.exe` sc.exe create wrapper:**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c sc.exe create "WerFaultSvc" binPath= "$e...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**`sc.exe create` invocation:**
```
New Process Name: C:\Windows\System32\sc.exe
Process Command Line: sc.exe  create "WerFaultSvc" binPath= "$env:windir\WinSxS\x86_micro...
Creator Process Name: C:\Windows\System32\cmd.exe
Exit Status: 0x0
```
`sc.exe` exits `0x0`, confirming the service was successfully created.

**`cmd.exe` sc.exe delete wrapper (cleanup):**
```
Process Command Line: "cmd.exe" /c sc.exe delete "WerFaultSvc"
```

**`sc.exe delete` invocation:**
```
Process Command Line: sc.exe  delete "WerFaultSvc"
Exit Status: 0x0
```
The ART cleanup phase deletes the service, completing the lifecycle. Both create and delete
are visible in the same dataset.

**EID 4703 — two token right adjustment events:**
- For `powershell.exe`: `SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`,
  `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`
- For `services.exe`: `SeBackupPrivilege`, `SeRestorePrivilege`, `SeSecurityPrivilege`,
  `SeTakeOwnershipPrivilege` — this is `services.exe` adjusting its own token during
  service registry operations, confirming `services.exe` wrote the service configuration.

**PowerShell channel (107 events) — EIDs 4104, 4103:**

The 104 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The `sc.exe create` command runs via `cmd.exe /c` and does
not generate 4104 script block records beyond the outer test framework wrapper.

## What This Dataset Does Not Contain

**No Sysmon events.** The Sysmon channel is absent. The defended variant's 23 Sysmon events
included EID 1 for `sc.exe` (with full command line), EID 13 for six service registry writes
by `services.exe` under `HKLM\System\CurrentControlSet\Services\WerFaultSvc\`, and EID 10
for process access events. The full WinSxS path in the `ImagePath` registry value would be
visible in Sysmon EID 13. Without Sysmon, the Security channel provides the same `sc.exe`
command line through EID 4688, but without registry telemetry.

**No service execution artifacts.** The test only creates and then deletes the service; it
does not start it. No EID 7036 (service state change to Running) appears. The Snake malware
would start the service; this ART test does not.

**No kernel driver artifacts.** The real Snake malware installs a kernel driver. This test
installs a user-mode service with a legitimate-looking binary path. No driver load events,
no Sysmon EID 6 (driver load), and no Security EID 4656/4657 for kernel object access
appear.

## Assessment

This dataset is particularly complete for a service-based persistence test because it
captures the full create-and-delete lifecycle in a single 3-second window, includes the
defining System EID 7045 with the anomalous `$env:windir` binary path, and shows the
`services.exe` EID 4703 token adjustment confirming the SCM wrote the service configuration.

The comparison with the defended dataset is minimal — this technique succeeds with or
without Defender because `sc.exe` is a legitimate Windows administrative tool. Both the
defended and undefended datasets produce identical outcomes. The undefended dataset is
slightly richer in Security events (18 vs 12 in the defended variant) due to the absence
of any Defender-related process activity interfering with the collection window.

## Detection Opportunities Present in This Data

**System EID 7045 — `$env:windir` in service binary path:** Unexpanded environment variable
syntax in a service `ImagePath` is a strong anomaly indicator. Legitimate service installers
always expand paths before registering them with the SCM. A query of
`HKLM\System\CurrentControlSet\Services\*\ImagePath` for values containing `$env:` or `%`
followed by a variable name that Windows itself would not use in registry storage is a
reliable detection for this technique variant.

**System EID 7045 — `WinSxS` service binary path:** The WinSxS component store path format
in a service `ImagePath` is unusual for production services. Combined with `auto start` and
`LocalSystem`, this is anomalous enough to warrant investigation regardless of the specific
file path.

**Security EID 4688 — `sc.exe create` with `WerFault`-mimicking service name:** Service
names that closely resemble Windows Error Reporting services (`WerFaultSvc`, `WerSvc2`,
`WindowsErrorReportingSvc`) warrant examination. The naming is chosen to blend with the
legitimate `WerSvc` service.

**Security EID 4703 — `services.exe` token adjustment:** EID 4703 for `services.exe`
appearing shortly after an `sc.exe create` command is consistent with the SCM writing
service configuration to the registry. Correlating this with the preceding `sc.exe create`
command creates a complete evidence chain.
