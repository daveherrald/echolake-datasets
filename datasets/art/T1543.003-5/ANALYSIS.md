# T1543.003-5: Windows Service — Remote Service Installation CMD

## Technique Context

T1543.003 (Create or Modify System Process: Windows Service) covers attacker use of Windows services for persistence and privilege escalation. Services run as SYSTEM by default, execute automatically at boot, and receive no interactive UI, making them ideal for maintaining long-term footholds. Defenders focus on new service creation events (System 7045), registry writes under `HKLM\SYSTEM\CurrentControlSet\Services\`, and the use of `sc.exe` with unusual `binPath` values — especially paths outside `System32`, to temp directories, or to scripting engines. The remote variant (targeting `\\<host>`) is particularly noteworthy as it indicates lateral movement intent even when applied to localhost, as attackers reuse the same pattern remotely.

## What This Dataset Contains

The dataset captures a complete successful service installation and execution via `sc.exe` targeting localhost. The process chain is fully visible across multiple channels:

**Security 4688 (process creation with command line):**
- PowerShell spawns `cmd.exe` with the full compound command:
  `"cmd.exe" /c sc.exe \\localhost create AtomicTestService_CMD binPath= "C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe" start=auto type=Own & sc.exe \\localhost start AtomicTestService_CMD`
- `cmd.exe` spawns `sc.exe \\localhost create AtomicTestService_CMD binPath= "C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe" start=auto type=Own`
- `cmd.exe` spawns `sc.exe \\localhost start AtomicTestService_CMD`
- `services.exe` spawns `C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe` (the service binary actually running)

**Sysmon EID=1 (ProcessCreate):** Captures the same `cmd.exe` and both `sc.exe` invocations with RuleNames `technique_id=T1059.003` and `technique_id=T1543.003` respectively, plus the `AtomicService.exe` launch with DLL load events.

**Sysmon EID=13 (RegistryValueSet):** `services.exe` writes five values to `HKLM\System\CurrentControlSet\Services\AtomicTestService_CMD\`: `Type` (0x10), `Start` (0x02 = auto), `ObjectName` (LocalSystem), `ImagePath` (`C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe`), and `ErrorControl`.

**System EID=7045:** "A service was installed in the system" — `Service Name: AtomicTestService_CMD`, `Service File Name: C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe`, `Service Type: user mode service`, `Service Start Type: auto start`, `Service Account: LocalSystem`.

**Sysmon EID=7 (ImageLoad):** DLL loads for `AtomicService.exe` itself, tagged with `technique_id=T1055`.

## What This Dataset Does Not Contain

- No Security 4697 (Service was installed in the system) — this channel requires object access auditing configured at the `SC_MANAGER` level, which is not enabled. System 7045 provides equivalent coverage.
- No `sc.exe` stop or delete events — cleanup occurred but is outside the collection window.
- The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy fragments) — no technique-specific script block content because the actual service creation was done via `cmd.exe`/`sc.exe`, not directly in PowerShell.
- No network traffic to the `\\localhost` RPC endpoint — Sysmon network connect was not triggered for loopback named pipe/RPC service control traffic.

## Assessment

This is a high-quality dataset for detecting service-based persistence. The key evidence — System 7045, Sysmon EID=13 registry writes, and Security 4688 with the full `sc.exe` command line — is all present. The complete process chain from PowerShell through cmd.exe through sc.exe through services.exe to AtomicService.exe is reconstructable. For detection engineering, the combination of System 7045 plus a `binPath` outside canonical service directories (`System32`, `SysWOW64`, `Program Files`) is the most actionable signal. To strengthen the dataset, adding Security 4697 (requires `auditpol /set /subcategory:"Security System Extension" /success:enable`) would provide the SCM-level audit record.

## Detection Opportunities Present in This Data

1. **System EID=7045 with non-standard service binary path**: `AtomicTestService_CMD` with `Service File Name` pointing to `C:\AtomicRedTeam\` — any service `ImagePath` outside Windows system directories warrants investigation.
2. **Sysmon EID=1 — `sc.exe` with `create` and `binPath=` arguments**: The command line `sc.exe \\localhost create ... binPath= ... start=auto` is a high-fidelity pattern; `\\localhost` targeting is unusual in legitimate service management.
3. **Sysmon EID=13 — `services.exe` writing new subkey under `HKLM\System\CurrentControlSet\Services\`**: A new key with `Start=2` (auto) and an `ImagePath` outside canonical paths correlates directly with the 7045 event.
4. **Security 4688 — `cmd.exe /c sc.exe \\<host> create ... & sc.exe \\<host> start ...`**: The compound create-then-start pattern in a single cmd.exe invocation is a strong attacker behavioral pattern.
5. **Sysmon EID=1 — `services.exe` as parent of an unsigned binary outside `System32`**: `AtomicService.exe` launched directly by `services.exe` from `C:\AtomicRedTeam\` is a robust detection anchor.
6. **Process chain correlation**: `powershell.exe` → `cmd.exe` → `sc.exe` (create) + `sc.exe` (start) within a 1-second window is a reliable sequence-based detection.
