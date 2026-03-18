# T1574.011-2: Services Registry Permissions Weakness — Service ImagePath Change with reg.exe

## Technique Context

T1574.011 (Hijack Execution Flow: Services Registry Permissions Weakness) exploits Windows service configurations where the registry keys controlling a service are writable by non-privileged users. An adversary with write access to `HKLM\SYSTEM\CurrentControlSet\Services\<service>\ImagePath` can redirect the service to an attacker-controlled binary. The next time the service starts — whether manually, on a schedule, or on reboot — the attacker's binary executes in the service's security context, which is often SYSTEM or a high-privileged account.

This test demonstrates the exploitation step using `reg.exe` to directly modify the `ImagePath` value of a test service (`calcservice`) to point to `cmd.exe`. Rather than using the Service Control Manager (`sc.exe config`), `reg.exe` writes the registry value directly, bypassing SCM validation. It then cleans up by deleting the service with `sc.exe delete calcservice`.

## What This Dataset Contains

The dataset captures 125 events across two log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103) and Security (18 events: 11 EID 4689, 6 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The registry modification is fully captured in Security EID 4688.** PowerShell spawned cmd.exe with:

```
"cmd.exe" /c reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\calcservice" /f /v ImagePath /d "%windir%\system32\cmd.exe"
```

The child `reg.exe` process was created with the resolved command line:

```
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\calcservice" /f /v ImagePath /d "C:\Windows\system32\cmd.exe"
Creator Process Name: C:\Windows\System32\cmd.exe
```

This directly writes `cmd.exe` as the `ImagePath` for `calcservice`. Note the use of `reg.exe add` with `/f` (force overwrite) — the same pattern used by attackers to silently modify existing values.

The cleanup phase is also captured — a separate `cmd.exe` (EID 4688) was created with:

```
"cmd.exe" /c sc.exe delete calcservice
```

Which spawned `sc.exe` (EID 4688):

```
sc.exe delete calcservice
Creator Process Name: C:\Windows\System32\cmd.exe
```

All six EID 4688 process creation events exited at `0x0`, confirming all operations completed successfully.

Security EID 4703 records PowerShell (PID 0x4588) receiving elevated privileges including `SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`, `SeSecurityPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege` — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 13 (Registry Value Set), you do not have a dedicated event recording the `HKLM\SYSTEM\CurrentControlSet\Services\calcservice\ImagePath` write. The modification is only visible through the `reg.exe` command line in EID 4688.

**The service was not started.** This test modifies the registry key but does not actually start `calcservice` to execute `cmd.exe`. There is no service execution event, no EID 7045 (Service Installed), and no record of `cmd.exe` running as a service. The test demonstrates the persistence write, not the triggered execution.

**No Sysmon EID 12 (Registry Object Added/Deleted).** The service key itself may have been created before the test window (or represents a pre-existing test artifact), so the initial service creation is not captured here.

## Assessment

The defended variant recorded 36 Sysmon, 13 Security, 34 PowerShell, 1 System, and 1 WMI event. The undefended run produced 0 Sysmon, 18 Security, and 107 PowerShell events. The Sysmon channel in the defended run would have included EID 13 (Registry Value Set) and EID 1 (Process Create with hashes), both absent here.

The undefended dataset shows the registry write and service deletion completing cleanly — both operations exited at `0x0`. In the defended variant, Defender may have flagged the `reg.exe` write to `HKLM\Services`. Here, both the attack and cleanup proceed unimpeded, and the Security channel records both the `reg.exe` and `sc.exe` command lines in full.

The dataset is straightforward but limited without Sysmon: the primary forensic artifact is the `reg.exe` command line modifying `ImagePath` to `cmd.exe`, which is a high-confidence indicator even without registry-native event logging.

## Detection Opportunities Present in This Data

**EID 4688 — reg.exe modifying `HKLM\SYSTEM\CurrentControlSet\Services\<service>\ImagePath`.** Writing any value under `HKLM\SYSTEM\CurrentControlSet\Services\` using `reg.exe` from a PowerShell/cmd.exe chain running as SYSTEM is suspicious. Legitimate service configuration changes go through the Service Control Manager (`sc.exe config` or `Set-Service`), not direct `reg.exe` writes. The `/f` flag (force overwrite) is a further indicator of scripted, non-interactive registry manipulation.

**EID 4688 — `ImagePath` being set to a system utility (`cmd.exe`).** Even if `reg.exe` writing to service registry keys were somehow legitimate, setting `ImagePath` to `cmd.exe`, `powershell.exe`, `wscript.exe`, or any other interpreter is a clear red flag. Real services point to application-specific executables, not generic shells.

**EID 4688 — sc.exe delete following a service registry modification.** Rapid modification of a service registry key followed immediately by service deletion from a scripted context suggests post-exploitation cleanup. The pattern of create/modify → execute → delete is a recognizable artifact of persistence testing.

**EID 4703 — PowerShell receiving extensive system privileges.** The privilege adjustment to include `SeLoadDriverPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` in a PowerShell process is consistent with SYSTEM-level execution and warrants attention when paired with service registry manipulation events in the same time window.
