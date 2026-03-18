# T1569.002-1: Service Execution — Execute a Command as a Service

## Technique Context

T1569.002 (Service Execution) covers adversaries creating and starting Windows services to
execute payloads with SYSTEM-level privileges and persistence. Creating a service via `sc.exe`
is a technique associated with tools like Metasploit's `psexec` module, PsExec itself, and
numerous lateral movement frameworks. The key characteristic is that the service binary path
can be any executable, including `cmd.exe` or `powershell.exe` with arbitrary arguments —
making it a powerful one-step privilege escalation and execution path. This test creates
a service named `ARTService` whose binary path is `cmd.exe /c powershell.exe -nop -w hidden
-command New-Item -ItemType File C:\art-marker.txt`, then starts and deletes it.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:29:41–14:29:46 UTC) from ACME-WS02, and
includes four log sources.

**Sysmon Event 1 (Process Create)** captures the complete process chain:
1. `whoami.exe` (ART pre-flight, tagged T1033)
2. `cmd.exe /c sc.exe create ARTService binPath= "%%COMSPEC%% /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt" & sc.exe start ARTService & sc.exe delete ARTService` (tagged T1059.003 Windows Command Shell)
3. `sc.exe create ARTService binPath= "C:\Windows\system32\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt"` (tagged T1543.003 Windows Service)
4. `sc.exe start ARTService` (tagged T1543.003)
5. `cmd.exe` — the service binary — with `C:\Windows\system32\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt` (tagged T1059.003)
6. `powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt` (tagged T1059.001)
7. `sc.exe delete ARTService` (tagged T1543.003)

This shows the full service lifecycle: create, start (spawning cmd.exe → powershell.exe),
delete.

**Sysmon Event 13 (Registry Value Set)** captures `services.exe` writing the service
registration to the registry:
- `HKLM\System\CurrentControlSet\Services\ARTService\ImagePath` = `C:\Windows\system32\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt`
- `HKLM\System\CurrentControlSet\Services\ARTService\Type` = `0x10` (own process)
- `HKLM\System\CurrentControlSet\Services\ARTService\ObjectName` = `LocalSystem`
- `HKLM\System\CurrentControlSet\Services\ARTService\Start` = `0x3` (demand start)
- `HKLM\System\CurrentControlSet\Services\ARTService\DeleteFlag` = `0x1` (marked for deletion)

**Sysmon Event 12 (Registry Key Delete)** captures `services.exe` removing
`HKLM\System\CurrentControlSet\Services\ARTService` after deletion.

**System log events**:
- Event 7045: `A service was installed in the system. Service Name: ARTService. Service File Name: C:\Windows\system32\cmd.exe /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt`
- Event 7009: `A timeout was reached (30000 milliseconds) while waiting for the ARTService service to connect.`
- Event 7000: `The ARTService service failed to start due to the following error: The service did not respond to the start or control request in a timely fashion.`

The service was installed and started, but timed out. `powershell.exe -w hidden` does not
send a service start acknowledgment to the SCM, so the 30-second timeout is expected behavior
when using this technique.

**Security 4688/4689** capture `sc.exe`, `cmd.exe`, and `powershell.exe` lifecycle events.

## What This Dataset Does Not Contain (and Why)

**No confirmation that art-marker.txt was created.** Object access auditing is disabled
(`object_access: none`). Whether `New-Item -ItemType File C:\art-marker.txt` succeeded before
the timeout is not determinable from the logs. The service timed out per System Event 7009,
but the PowerShell command may have completed before the SCM gave up.

**No Security 4697 (Service Installation).** Event 4697 is a Security log event for service
installation that requires the `audit_policy` for `policy_change: success`. The audit policy
here has `policy_change: none`, so 4697 is not present. System 7045 fills this gap.

**No Sysmon ProcessCreate for `art-marker.txt` write activity.** File creation auditing for
arbitrary .txt files is not covered by the sysmon-modular include rules.

## Assessment

This is the most telemetry-rich of the T1569.002 variants, with four log sources providing
complementary coverage. System Event 7045 and Sysmon Event 13 (ImagePath registry write)
together give two independent records of the service installation with full payload visibility.
The process chain in Sysmon Event 1 traces the full execution: `cmd.exe` → `sc.exe` → service
binary (`cmd.exe`) → `powershell.exe -w hidden`. The 30-second timeout in System Event 7009
is characteristic of this technique and can aid in identifying it versus a legitimate service.

## Detection Opportunities Present in This Data

- **System 7045**: Service installation with `ImagePath` containing `cmd.exe /c` or
  `powershell.exe` is a reliable high-fidelity indicator. Filter on service names that do not
  match known software.

- **Sysmon Event 13**: Registry write to `HKLM\System\CurrentControlSet\Services\*\ImagePath`
  by `services.exe` where the value contains `powershell.exe` or `cmd.exe` is a direct match
  for this technique.

- **System 7009/7000**: Service start timeout immediately following a 7045 for an unusual
  service name is a secondary indicator — `powershell.exe -w hidden` routinely triggers this.

- **Sysmon Event 1**: `sc.exe create` with `binPath=` containing interpreter paths (`cmd.exe`,
  `powershell.exe`) is directly captured when Sysmon ProcessCreate matches `sc.exe`.

- **Security 4688**: Full command line for `sc.exe create ... binPath=` and subsequent
  `sc.exe start` and `sc.exe delete` in rapid succession under the same logon session.
