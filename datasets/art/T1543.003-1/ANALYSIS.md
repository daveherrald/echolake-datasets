# T1543.003-1: Windows Service — Modify Fax Service to Run PowerShell

## Technique Context

T1543.003 (Windows Service) is a persistence and privilege escalation technique where adversaries create or modify Windows services to run malicious payloads. Service-based persistence executes with SYSTEM privileges by default, survives reboots, and can be used to elevate from an administrative context to SYSTEM. Modifying an existing service (rather than creating a new one) has historically been a lower-profile approach since legitimate services are already present in the service registry; changing only the `ImagePath` may not trigger creation-focused detection rules. Detection focuses on: `sc.exe config` modifying an existing service's binary path, Sysmon Event ID 13 (registry write) to `HKLM\System\CurrentControlSet\Services\<name>\ImagePath`, and System Event ID 7040 (service configuration changed).

## What This Dataset Contains

The test attempts to modify the `Fax` service to execute PowerShell, then start it:

```
sc config Fax binPath= "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -c \"write-host 'T1543.003 Test'\"" & sc start Fax
```

The command chain runs as `powershell.exe` → `cmd.exe` → `sc.exe` (config) → `sc.exe` (start). Security 4688 and Sysmon Event ID 1 record the full command line including the malicious `binPath` value, preserving the PowerShell argument used to hijack the service binary path.

Both `sc.exe` processes exited with status `0x424` (decimal 1060: `ERROR_SERVICE_DOES_NOT_EXIST`), and `cmd.exe` also exited `0x424`. The `Fax` service is not present on this Windows 11 Enterprise Evaluation installation. The technique failed at the `sc config` step — the modification was never applied and no service registry write occurred.

Because the service modification failed, **no Sysmon Event ID 13** appears for the Fax service registry key. No System Event ID 7040 (service config changed) appears.

## What This Dataset Does Not Contain

**No service registry modification.** The Fax service does not exist; `sc config` returned `ERROR_SERVICE_DOES_NOT_EXIST` and wrote nothing to `HKLM\System\CurrentControlSet\Services\Fax`.

**No System Event ID 7040** (service configuration change) or **7036** (service state changed). These would be the primary System channel indicators for a successful service modification.

**No execution of the malicious PowerShell payload.** Since `sc start Fax` also failed, no `powershell.exe` running `write-host 'T1543.003 Test'` appears.

**The Sysmon registry write (Event ID 13) for `ImagePath`** — which would be the key detection artifact for a live service modification — is absent for this same reason.

## Assessment

This dataset is primarily useful as command-line–focused evidence for the attempt to use `sc config` to hijack a service binary path. The full malicious `binPath` value — including the PowerShell invocation — appears in both Security 4688 and Sysmon Event ID 1. For environments where the Fax service exists (older Windows SKUs, or systems with Fax role installed), this exact command would succeed and produce registry modification events. The failure here reflects a real environmental dependency: the Fax service is absent from modern Windows 11 builds without the optional Fax/Scan feature. A dataset where the modification succeeds would add Sysmon ID 13 writes to `Services\Fax\ImagePath` and System 7040.

## Detection Opportunities Present in This Data

1. **Security 4688 / Sysmon Event ID 1**: `sc.exe` with `config` and `binPath=` in command line — service binary path modification attempt.
2. **Security 4688 / Sysmon Event ID 1**: `sc.exe config` where the `binPath` value contains `powershell.exe` — service hijacked to run PowerShell interpreter.
3. **Sysmon Event ID 1**: `cmd.exe` spawned by `powershell.exe` with a command line containing `sc config` followed by `sc start` — compound service-modify-and-start pattern.
4. **Security 4689**: `sc.exe` exiting `0x424` (`ERROR_SERVICE_DOES_NOT_EXIST`) after a `config` invocation — failed attempt on a non-existent service, which can still indicate reconnaissance or scripted deployment.
5. **Sysmon Event ID 13 (on success)**: Registry write to `HKLM\System\CurrentControlSet\Services\<name>\ImagePath` with a value containing `powershell.exe` — most direct indicator if the target service exists.
6. **System Event ID 7040 (on success)**: Service configuration change event — provides service-native confirmation of binary path modification.
