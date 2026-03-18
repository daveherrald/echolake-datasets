# T1490-7: Inhibit System Recovery — wbadmin Delete systemstatebackup

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes targeted deletion of Windows system state backups. The `wbadmin delete systemstatebackup -keepVersions:0` command instructs the Windows Backup engine to retain zero versions of the system state backup — effectively deleting all existing system state backups. System state backups include the Active Directory database (on domain controllers), the registry, COM+ class registration, and boot files. On workstations the system state is less critical, but on domain controllers this command is catastrophically destructive: it eliminates the only reliable path to AD forest recovery. Threat actors targeting domain controllers have used this technique as part of destructive operations. This test variant is less commonly signatured than `delete catalog` because it requires the target to have existing system state backups to be impactful.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The attack chain `cmd.exe /c wbadmin delete systemstatebackup -keepVersions:0` → `wbadmin.exe delete systemstatebackup -keepVersions:0` is fully captured. Both processes run as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. Sysmon tags both the `cmd.exe` and `wbadmin.exe` process creates with `technique_id=T1490,technique_name=Inhibit System Recovery`. The `cmd.exe` invocation is additionally tagged with `technique_id=T1059.003`.

**Security (Event IDs 4688/4689/4703):**
Standard process creation/exit telemetry. `wbadmin.exe` exits with status `0xFFFFFFFD` — a non-zero error code. This is important context: the deletion failed, likely because no system state backup exists on this workstation. The exit code `0xFFFFFFFD` (-3) indicates the backup engine found nothing to delete. This is "attempt" telemetry — the command was issued but was not destructive on this target.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. No technique-relevant content.

## What This Dataset Does Not Contain

- **No Application log confirmation events** (unlike T1490-3). Because no system state backup existed, the backup engine did not generate EID 524 or similar deletion confirmation messages.
- **No `wbengine.exe` or `vds.exe` side effects.** In T1490-3 (catalog delete), the backup engine spun up companion services. Here, the missing backup catalog prevents the engine from progressing far enough to trigger those service activations.
- **No WMI activity.** The `wbadmin` command path does not invoke WMI in this flow.
- **No System log or Application log backup service events** beyond what ambient OS background activity would generate.
- **Success confirmation is absent.** There is no way to determine from this dataset whether the command would have been destructive on a system with actual system state backups.

## Assessment

This is a lean but functionally sufficient dataset for the process/command-line detection use case. The `wbadmin delete systemstatebackup -keepVersions:0` command string is captured in two sources and is distinctly suspicious regardless of whether backups exist on the target. The exit code `0xFFFFFFFD` is useful context for understanding what happens on a workstation without existing system state backups — the attempt still generates the same process telemetry you would see on a domain controller where the deletion would be destructive. Detection engineers building content for this technique should not require a successful exit to fire their detections. The dataset would be significantly strengthened by running the test on a system with an actual system state backup present, which would trigger Application log events.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `wbadmin.exe delete systemstatebackup -keepVersions:0`** — the exact argument combination is unambiguous T1490; Sysmon labels it directly.
2. **Security EID 4688 — `wbadmin delete systemstatebackup -keepVersions:0`** command line — independent of Sysmon via command-line auditing.
3. **`-keepVersions:0` argument specifically** — this argument is the destructive flag that instructs deletion of all versions; legitimate backup management uses non-zero values.
4. **Security EID 4689 — non-zero exit code `0xFFFFFFFD`** for `wbadmin.exe` — while this indicates the attempt failed on this target, the exit code can be used to distinguish "no backups found" from "backups deleted successfully" when triaging alerts.
5. **Parent process chain** `cmd.exe → wbadmin.exe` from `C:\Windows\TEMP\` as SYSTEM — the execution context is anomalous for legitimate Windows Backup management.
