# T1569.002-6: Service Execution — Snake Malware Service Create

## Technique Context

T1569.002 (Service Execution) covers adversary use of the Windows Service Control Manager
to execute programs. This test simulates the Snake malware family's technique of
installing a persistence service using `sc.exe create` with a masqueraded service name
and binary path pointing to a legitimate-looking executable. Snake (also known as Uroburos)
is a sophisticated Russian APT rootkit that installs a kernel-level driver as a service.
The ART test creates a service named "WerFaultSvc" with a binary path referencing a
deep WinSxS path to blend with legitimate OS components.

## What This Dataset Contains

**System Event 7045** — new service installed:

> `Service Name: WerFault Service`
> `Service File Name: $env:windir\WinSxS\x86_microsoft-windows-errorreportingfaults_31bf3856ad364e35_4.0.9600.16384_none_a13f7e283339a050\WerFault.exe`
> `Service Type: user mode service | Service Start Type: auto start | Service Account: LocalSystem`

The service name deliberately mimics the Windows Error Reporting service. The binary path
uses an unexpanded `$env:windir` environment variable, which is anomalous — the Service
Control Manager stores expanded paths in the registry. This creates a service that would
fail to start but registers as a persistence mechanism.

**Sysmon EID 1** — process create for `sc.exe`:

> `CommandLine: sc.exe create "WerFaultSvc" binPath= "$env:windir\WinSxS\x86_micro..."`
> `ParentImage: C:\Windows\System32\cmd.exe`

**Sysmon EID 13** — registry value sets by `services.exe` writing the new service entry
under `HKLM\System\CurrentControlSet\Services\WerFaultSvc\` (Type, Start, ImagePath,
ErrorControl, DisplayName, ObjectName — six separate registry write events).

**Sysmon EID 10** — PowerShell accessing another PowerShell process, flagged with
`technique_id=T1055.001,technique_name=Dynamic-link Library Injection`, representing
the ART test framework's internal AMSI instrumentation.

**Security EID 4688/4689** — process creation and termination for `powershell.exe`,
`cmd.exe`, `whoami.exe`, and `sc.exe`, all under `NT AUTHORITY\SYSTEM`.

**Security EID 4703** — token right adjusted for SYSTEM.

**PowerShell EID 4104** — script block logging captures the test framework boilerplate
(`Set-StrictMode`, `$_.PSMessageDetails`, `$_.ErrorCategory_Message`, `$_.OriginInfo`).
The actual `sc.exe create` command is visible in the EID 4688 command line rather than
in a distinct 4104 block, because the ART test framework invokes it via `cmd.exe /c`.

## What This Dataset Does Not Contain (and Why)

**No service start or execution telemetry.** The test only creates the service; it does
not attempt to start it. No EID 7036 (service state change) or further process execution
from the WerFaultSvc binary is present.

**No kernel driver install artifacts.** The real Snake malware installs a kernel driver.
This test installs a user-mode service with a legitimate binary path and does not drop
any actual malicious binary.

**No Defender block.** Windows Defender does not block service creation via `sc.exe`
with a legitimate binary path; the operation completes successfully.

**No Sysmon EID 12 (registry key create).** The new service key creation under
`CurrentControlSet\Services` generates EID 13 (value set) entries but the initial key
creation event is not present, likely filtered by the sysmon-modular configuration.

**No file write to system directories.** The test references an existing WinSxS binary
rather than dropping a new file, so no EID 11 for a suspicious path appears.

## Assessment

This dataset captures the core service installation telemetry needed to detect Snake-style
service persistence. The combination of System 7045, Security 4688 for `sc.exe`, and
Sysmon EID 13 registry writes provides three independent detection paths. The masqueraded
service name and unexpanded environment variable in the ImagePath are concrete, queryable
IOCs. The dataset is free of complicating factors such as Defender blocks or service
start failures.

## Detection Opportunities Present in This Data

- **System EID 7045** with `ServiceFileName` containing unexpanded environment variables
  (e.g., `$env:windir`) is highly anomalous; the SCM stores fully expanded paths at
  registration time in legitimate scenarios.
- **System EID 7045** with a `ServiceFileName` containing WinSxS paths from older OS
  versions (build `4.0.9600`) on a Windows 11 host is a version mismatch indicator.
- **Sysmon EID 1** for `sc.exe` with `create` and a WinSxS binary path; the
  sysmon-modular config includes `sc` in its LOLBin include rules, ensuring capture.
- **Sysmon EID 13** — six sequential registry writes to `HKLM\System\CurrentControlSet\
  Services\<new_name>\` by `services.exe` within the same second correlates with
  programmatic service installation.
- **Security EID 4688** — `sc.exe` process creation under SYSTEM from a `cmd.exe` parent
  spawned from `powershell.exe` is an unusual process hierarchy for service operations.
- **Correlation across sources**: 7045 ServiceName + 4688 sc.exe CommandLine +
  Sysmon EID 13 ImagePath should resolve to the same string within the same second.
