# T1564-4: Hide Artifacts — Create and Hide a Service with sc.exe

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) includes hiding Windows services from standard enumeration. This test creates a new Windows service named `AtomicService` pointing to `calc.exe`, then applies a restrictive DACL using `sc sdset` that denies read and control access to Interactive Users (IU), Service Users (SU), and Built-in Administrators (BA). The DACL modification causes the service to be invisible to standard `sc query` enumeration and most GUI service management tools, because those tools read the service object and are denied access.

This is a realistic persistence or rootkit-adjacent technique. The combination of service creation plus a restrictive DACL written in SDDL format is a hallmark of advanced persistent threat tooling.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:19:19–14:19:25 UTC) and includes a System log event in addition to the standard three channels.

**Process execution chain (Sysmon EID 1 / Security EID 4688):**

The ART test framework issued a combined command through cmd.exe:

```
"cmd.exe" /c sc.exe create AtomicService binPath= "C:\Windows\System32\calc.exe" & sc sdset AtomicService "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
```

Two separate `sc.exe` processes were spawned in sequence — one for `create`, one for `sdset` — both visible in Sysmon EID 1 with their full command lines preserved.

**Sysmon EID 13 (Registry Value Set):** The service creation was followed by `services.exe` writing the new service's registry keys under `HKLM\System\CurrentControlSet\Services\AtomicService\`:
- `ImagePath: C:\Windows\System32\calc.exe`
- `ObjectName: LocalSystem`
- `ErrorControl: DWORD (0x00000001)`
- `Start: DWORD (0x00000003)` (demand start)
- `Type: DWORD (0x00000010)` (own process)
- `Security\Security: Binary Data` — the DACL written by `sc sdset`

These registry writes from `services.exe` provide a second, independent evidence trail of the service installation.

**System EID 7045:** A new service installed event was captured:

```
Service Name:  AtomicService
Service File Name:  C:\Windows\System32\calc.exe
Service Type:  user mode service
Service Start Type:  demand start
Service Account:  LocalSystem
```

This is the canonical service installation event and is present in the bundled data.

**Security EID 4688:** Confirms process creation for cmd.exe and two sc.exe instances, all parented to the SYSTEM-context PowerShell process.

**Sysmon EID 17:** Named pipe for the PowerShell host.

**PowerShell EID 4103/4104:** Test framework boilerplate — `Set-ExecutionPolicy -Bypass` and internal error-handling script blocks.

## What This Dataset Does Not Contain (and Why)

**No Security EID 4697 (Service Installed in the System):** Despite being a documented Windows Security event for service installation, this event requires `Special Logon` or specific audit policy settings. The audit policy in this environment has `policy_change: none`, so 4697 is absent. System EID 7045 provides equivalent coverage from a different channel.

**No SACL audit events:** The `sc sdset` DACL modification is captured only through the registry write (`Security\Security: Binary Data`) in Sysmon. The actual SDDL string applied is visible in the `sc sdset` command-line argument but not in a dedicated ACL-change event, since object access auditing is disabled.

**The service was never started:** The dataset captures creation and DACL hardening but not execution. There are no process creation events for `calc.exe` running as a service. The test appears to verify service creation only.

**No cleanup:** Per the dataset metadata, cleanup is per-test. The cleanup step's events are not included in this window.

## Assessment

This dataset is noteworthy for containing multiple corroborating evidence sources for the same underlying event: the `sc.exe` command lines, the `services.exe` registry writes, and the System 7045 event all independently document the service installation. The SDDL-format DACL in the `sc sdset` command line contains the deny ACEs `(D;;DCLCWPDTSD;;;IU)`, `(D;;DCLCWPDTSD;;;SU)`, and `(D;;DCLCWPDTSD;;;BA)` that implement the hiding mechanism — these are available to detections that parse the command-line argument.

## Detection Opportunities Present in This Data

- **System EID 7045 / Sysmon EID 13:** Service installation with an unusual binary path (`calc.exe`, or any non-service-binary path), combined with a subsequent `Security\Security` binary data write from `reg.exe` or `sc.exe`. The 7045 event alone is valuable for new service detection.
- **Sysmon EID 1:** `sc.exe` invocation with `sdset` argument, particularly where the SDDL contains deny ACEs (`D;;...`) for standard user or administrator SIDs. This is rare in legitimate administrative workflows.
- **Sysmon EID 13:** Registry value sets to `HKLM\System\CurrentControlSet\Services\<name>\Security\Security` written by `sc.exe` (rather than the service installer itself) indicate post-creation DACL manipulation.
- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` spawned by `powershell.exe` as SYSTEM with both `sc create` and `sc sdset` in the same command string.
- **Correlation:** Service installation (7045) followed within seconds by a DACL change (`sc sdset`) on the same service name is a high-confidence indicator of deliberate service hiding.
