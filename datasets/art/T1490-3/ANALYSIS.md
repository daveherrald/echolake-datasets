# T1490-3: Inhibit System Recovery — wbadmin Delete Windows Backup Catalog

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes destruction of backup catalogs as a pre-encryption or post-compromise step. The Windows Backup catalog (`wbadmin delete catalog`) records metadata about all Windows Server Backup jobs. Deleting it orphans any existing backup sets — they cannot be restored without a valid catalog. Ransomware operators such as those deploying Conti and Maze have used this command alongside VSC deletion to ensure no offline restore path remains. On workstations, the backup catalog is less commonly populated, so this command often produces an informational "no catalog found" outcome rather than actual data destruction — but the attempt telemetry is equally relevant for detection.

## What This Dataset Contains

This dataset is notably richer than most other T1490 tests because `wbadmin` triggers service start activity that generates Application log and WMI events.

**Sysmon (Event ID 1) — ProcessCreate:**
The chain is `cmd.exe /c wbadmin delete catalog -quiet` → `wbadmin.exe delete catalog -quiet`. Both processes are captured with full command lines and run as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. Sysmon tags both with `technique_id=T1490`. Additionally, the Sysmon EID 1 capture includes `wbengine.exe` (Block Level Backup Engine) launched by the Service Control Manager as a side effect of the backup operation being checked, and `vdsldr.exe` and `vds.exe` (Virtual Disk Service) also spin up. This service activation chain is a useful corroborating indicator.

**Security (Event ID 4688/4689/4624/4627/4672):**
Beyond standard process creation records for `whoami.exe`, `cmd.exe`, `wbadmin.exe`, `wbengine.exe`, `vdsldr.exe`, and `vds.exe`, this dataset includes logon events (4624 type 5 service logons) and special logon events (4672) for the elevated service accounts starting the backup engine. These enriched logon events reflect the real-world authentication side effects of backup service activation.

**Application log (Event IDs 524, 612, 753):**
- **EID 753**: `"The Block Level Backup Engine service has successfully started."` — confirms wbengine was activated.
- **EID 524**: `"The system catalog has been deleted."` — direct confirmation that the backup catalog deletion succeeded.
- **EID 612**: `"The scheduled backup was canceled. To create a new backup, you must reconfigure scheduled backups or run a one-time backup operation."` — secondary effect confirming the catalog deletion broke any configured scheduled backups.

**System log (Event ID 3):** Service started event for the backup engine service.

**WMI Activity log (Event ID 5858):** Two WMI error events showing failed `CreateInstanceEnum` operations against `MS_SM_PortInformationMethods` and `MSiSCSI_PortalInfoClass`. These are benign side effects of the backup engine probing storage topology — not technique-related, but realistic noise accompanying backup operations.

**Sysmon (Event ID 3) — Network Connection:** mDNS (port 5353) traffic from `svchost.exe` during the execution window. This is incidental OS noise, not technique-related.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. No substantive technique content.

## What This Dataset Does Not Contain

- **Sysmon EID 13 (RegistryEvent)** for any registry keys written during backup service startup — those keys are not captured in the included file.
- **The backup catalog content itself** — what backups were lost. On a fresh test VM the catalog was likely empty, making EID 524 a "deletion of nothing" outcome, but the telemetry looks identical to a destructive real-world case.
- **Command-line arguments in Security 4688** for the service-spawned processes (`wbengine.exe`, `vdsldr.exe`, `vds.exe`) — those appear without arguments because they are launched by SCM.

## Assessment

This is one of the most complete datasets in the T1490 collection. The Application log events (524, 612, 753) provide direct confirmation of technique completion — not just an attempt — and the accompanying service activation chain (`wbengine.exe`, `vdsldr.exe`, `vds.exe`) is authentic background activity you would see in any real execution. Detection engineers can use EID 524 as a near-zero false-positive indicator of backup catalog deletion. To strengthen the dataset, adding the `Microsoft-Windows-Backup` channel would capture additional operational detail. The WMI 5858 errors are realistic noise that defenders should expect alongside backup operations.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `wbadmin.exe delete catalog -quiet`** with parent `cmd.exe` running from SYSTEM as `C:\Windows\TEMP\`; Sysmon tags this T1490 directly.
2. **Security EID 4688 — `wbadmin delete catalog -quiet`** command line; independent of Sysmon, available via command-line auditing alone.
3. **Application EID 524 — "The system catalog has been deleted"** — highest-confidence single-event indicator of successful backup catalog destruction; extremely rare in legitimate operations.
4. **Application EID 612 — scheduled backup cancellation** following catalog deletion; useful as a corroborating event when EID 524 is present.
5. **Application EID 753 — wbengine service start** immediately preceding a backup deletion; the combination of wbengine activation followed by catalog deletion is a useful sequence-based detection.
6. **Security EID 4672 (special logon)** for elevated service accounts spinning up during backup service activation — combined with `wbadmin.exe` process creation, indicates privileged backup access in a short time window.
