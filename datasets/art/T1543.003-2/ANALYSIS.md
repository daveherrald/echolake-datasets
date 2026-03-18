# T1543.003-2: Windows Service — Service Installation CMD

## Technique Context

T1543.003 (Windows Service) covers adversaries installing new services to achieve persistence and privilege escalation. Installing a new service via `sc.exe create` is a well-known and heavily-detected technique, but it remains prevalent because it reliably executes under SYSTEM with automatic-start semantics and survives reboots. Many malware families — including RATs, backdoors, and ransomware — install themselves as services during deployment. Detection focuses on `sc.exe create` with `binPath`, System Event ID 7045 (new service installed), Sysmon Event ID 13 registry writes to `HKLM\System\CurrentControlSet\Services\<name>`, and file creation of service binaries.

## What This Dataset Contains

The test installs a new service named `AtomicTestService_CMD` using `sc.exe`, then starts it:

```
sc.exe create AtomicTestService_CMD binPath= "C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe" start=auto type=Own & sc.exe start AtomicTestService_CMD
```

This is driven by `powershell.exe` → `cmd.exe` → `sc.exe` (create) → `sc.exe` (start). Both `sc.exe` processes exited `0x0`, confirming the service was successfully installed and started.

**System Event ID 7045** appears with the full service details:
- Service Name: `AtomicTestService_CMD`
- Service File Name: `C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe`
- Service Type: user mode service
- Service Start Type: auto start
- Service Account: LocalSystem

**Sysmon Event ID 13** records five registry writes from `services.exe` to the new service key: `ImagePath`, `Start`, `ObjectName`, `ErrorControl`, and `Type`. Two additional Sysmon 13 events record `AtomicService.exe` registering its own event log source under `HKLM\System\CurrentControlSet\Services\EventLog\Application\AtomicService\EventMessageFile`.

Security 4688 captures `sc.exe create` with the full `binPath` value in the command line.

The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`, `Set-StrictMode` fragments).

## What This Dataset Does Not Contain

**No Sysmon ProcessCreate for `AtomicService.exe` itself.** The sysmon-modular include-mode filter does not match `AtomicService.exe`, so no Sysmon Event ID 1 appears for the service process startup. Security 4688 would capture it if process creation auditing catches service starts — but only `sc.exe` processes appear in the Security log here.

**No System Event ID 7036** (service state changed to running) or 7009 (service timeout). The service start is confirmed only by `sc.exe` exiting `0x0`.

**No Security account management events** for service account changes.

## Assessment

This is a high-quality dataset for service installation detection. System Event ID 7045 provides a clean, self-contained record of the new service with all relevant metadata. The Sysmon ID 13 events show `services.exe` writing the exact `ImagePath` value, enabling registry-based detection independent of `sc.exe` command-line logging. Security 4688 provides the command-line evidence. All three telemetry layers are present and consistent. The 7045 event is the recommended primary signal for this technique; it is reliably generated, low-volume, and rarely false-positive on endpoints where service installation is not normal operational behavior.

## Detection Opportunities Present in This Data

1. **System Event ID 7045**: New service installed — `AtomicTestService_CMD` with `start=auto` and `type=Own` running as LocalSystem; any new service installation outside a known change window warrants investigation.
2. **System Event ID 7045**: Service file name pointing to a path outside standard service directories (`C:\Windows\System32`, `C:\Program Files`) — service binary in `C:\AtomicRedTeam` or similar user-accessible paths.
3. **Security 4688 / Sysmon Event ID 1**: `sc.exe` with `create` and `binPath=` and `start=auto` in command line — explicit service installation with autostart.
4. **Sysmon Event ID 13**: `services.exe` writing to `HKLM\System\CurrentControlSet\Services\<new_name>\ImagePath` — registry-level service installation independent of the creating tool.
5. **Sysmon Event ID 13**: `AtomicService.exe` (or any unexpected binary) writing `EventMessageFile` under `HKLM\System\CurrentControlSet\Services\EventLog\Application` — service registering its own event source, a pattern many malware services replicate.
6. **Sequence**: `sc.exe create` followed within seconds by `sc.exe start` for the same service name — immediate execution after installation, typical of malware deployment.
