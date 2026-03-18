# T1543.003-3: Windows Service — Service Installation PowerShell

## Technique Context

T1543.003 (Windows Service) executed via PowerShell's `New-Service` cmdlet is a common variation of service-based persistence that avoids spawning `sc.exe` — an LOLBin that is heavily monitored. `New-Service` interacts directly with the Service Control Manager through the Win32 API (`CreateService`), leaving the same underlying registry artifacts but potentially bypassing rules that look specifically for `sc.exe` command lines. PowerShell-based service installation is used in fileless malware, post-exploitation frameworks, and malicious provisioning scripts. Detection extends coverage from `sc.exe` patterns to include `New-Service` in script blocks and registry writes from `services.exe`.

## What This Dataset Contains

The test installs a new service using PowerShell's `New-Service` cmdlet and then starts it:

```powershell
New-Service -Name "AtomicTestService_PowerShell" -BinaryPathName "C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe"
Start-Service -Name "AtomicTestService_PowerShell"
```

This script block appears in PowerShell Event ID 4104 (Script Block Logging). Notably, **Event ID 4103 (Module Logging) does not capture `New-Service` or `Start-Service` parameter bindings** — only the two `Set-ExecutionPolicy` test framework calls appear in 4103. This occurs because `New-Service` and `Start-Service` use the ServiceController module, which is not fully instrumented for parameter-level logging in the same way as cmdlets with explicit parameter-set definitions.

**System Event ID 7045** records the successful service installation:
- Service Name: `AtomicTestService_PowerShell`
- Service File Name: `C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe`
- Service Type: user mode service
- Service Start Type: auto start
- Service Account: LocalSystem

Sysmon Event ID 13 would record `services.exe` writing the service registry keys, as seen in T1543.003-2. Security 4688 captures `powershell.exe` with the full `New-Service` command in the command line.

Security 4624 (Type 5 service logon), 4627 (group membership), and 4672 (special privileges) appear, reflecting the service execution context for the started service.

## What This Dataset Does Not Contain

**No `sc.exe` in process creations.** `New-Service` does not invoke `sc.exe`; the Service Control Manager is called directly from PowerShell. This means `sc.exe`-based detection rules produce no matches.

**No `New-Service` or `Start-Service` in Event ID 4103 module logging**, despite module logging being enabled for `*`. The cmdlets execute without triggering per-parameter binding capture in this configuration.

**No Sysmon ProcessCreate for `AtomicService.exe`** — the include-mode filter does not match the service binary.

## Assessment

This dataset is valuable precisely because it demonstrates the PowerShell-native service installation path. The 4104 script block captures the exact cmdlet invocations, and System 7045 provides the same reliable service installation record as in the `sc.exe` case (T1543.003-2). The absence of `New-Service` in module logging (4103) highlights a gap: if script block logging were disabled, the PowerShell channel would provide no evidence. System 7045 and Sysmon registry writes are the resilient cross-tool signals. The dataset also shows that the 4624/4672 logon events appear when the installed service actually starts — these can be correlated with the service installation to confirm execution.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104**: Script block containing `New-Service -Name` with `-BinaryPathName` — PowerShell-native service installation without `sc.exe`.
2. **PowerShell Event ID 4104**: `Start-Service` following `New-Service` in the same script block — install-and-execute sequence.
3. **System Event ID 7045**: New service installed — identical signal to the `sc.exe` case; `New-Service` and `sc.exe` both produce 7045.
4. **Security 4688 / Sysmon Event ID 1**: `powershell.exe` with `New-Service` in command line — PowerShell service installation visible in process creation logs.
5. **Sysmon Event ID 13**: `services.exe` writing to `HKLM\System\CurrentControlSet\Services\AtomicTestService_PowerShell\ImagePath` — registry artifact independent of how the service was created.
6. **Security 4624 Type 5 logon correlation**: A service logon (Type 5) for LocalSystem shortly after a 7045 event for the same service — confirmation the installed service started successfully.
