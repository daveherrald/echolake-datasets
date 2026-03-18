# T1003.003-8: NTDS — Create Symlink to Volume Shadow Copy

## Technique Context

T1003.003 targets the Active Directory database (NTDS.dit) for domain credential extraction. This variant uses a two-step approach: first, create a Volume Shadow Copy of the system drive using `vssadmin.exe create shadow /for=c:`; second, create a symbolic link pointing to the shadow copy, making the locked NTDS.dit accessible through a persistent path like `C:\vss` or `C:\shadow`. With the symlink in place, the attacker can read `C:\vss\Windows\NTDS\ntds.dit` directly rather than needing to reference the long `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\` path each time.

The symlink approach is preferred in adversarial operations because it creates a stable, persistent access point to the shadow copy. Tools like `secretsdump.py` can then be pointed at the symlink path. The VSS creation itself (`vssadmin create shadow`) is a well-known indicator, but the subsequent `mklink /d` command creating the directory junction is a complementary artifact that detection rules should cover.

This test runs on a domain **workstation** (ACME-WS06). Vssadmin can create shadow copies on workstations, but NTDS.dit only exists on domain controllers — so the shadow copy creation and symlink steps produce telemetry even if the actual NTDS.dit file is not present on this host.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Security channel (197 events: 185x EID 4664, 7x EID 5379, 5x EID 4688):** The 185 EID 4664 events again reflect heavy background installer/update activity. The 5 meaningful EID 4688 process creation events show: `powershell.exe` spawning `whoami.exe` (0x5f8, pre-check), `cmd.exe` (0x23c, which invokes vssadmin), `vssadmin.exe` (0x520, the shadow copy creation), `whoami.exe` (0x12dc, post-check), and `cmd.exe` (0x16ac, cleanup). The `vssadmin.exe` process creation (PID 0x520, created by `cmd.exe` 0x23c) is the key event — it is the Volume Shadow Copy Service invocation.

**Sysmon channel (58 events: 42x EID 11, 7x EID 7, 5x EID 1, 4x EID 10, 1x EID 17):** Sysmon EID 1 events confirm the vssadmin execution: `cmd.exe` (PID 5804) created at 22:46:44 UTC with the execution context for the symlink/VSS operations. The cmd.exe command line in the EID 1 sample is shown as empty (`"cmd.exe" /c` without visible arguments due to truncation), but the Security EID 4688 already confirms vssadmin.exe was spawned from this cmd.exe. EID 11 file creation events (42 of them) are dominated by background activity. EID 10 shows `powershell.exe` (PID 5536) accessing `cmd.exe` processes (PIDs 4828 and 5804) with `0x1FFFFF` — the ART test framework spawning child processes.

**PowerShell channel (104 events: 102x EID 4104, 2x EID 4103):** Standard ART test framework events.

**Compared to the defended dataset (sysmon: 31, security: 14, powershell: 35):** The undefended run has substantially more Security events (197 vs. 14), but this is almost entirely the EID 4664 background activity. The 5 meaningful EID 4688 events vs. 14 Security events in the defended run suggests the defended run generated more actual Security-relevant events (possibly Defender blocking events being logged as auditable process creations). Sysmon is higher undefended (58 vs. 31), again driven by background file creation. PowerShell significantly higher (104 vs. 35) confirming full execution. The key new artifact undefended: `vssadmin.exe` process creation is captured in EID 4688, confirming the shadow copy creation was attempted.

## What This Dataset Does Not Contain

The `mklink /d` command creating the actual symbolic link is not visible in the 20-event sample — it would appear as a `cmd.exe` EID 1 event with `mklink` in the command line. VSS creation confirmation events (like Volume Shadow Copy service events or Sysmon EID 29) are absent from this dataset — unlike T1003.003-9 which uses diskshadow and generates EID 29 events, vssadmin does not produce Sysmon EID 29 in this configuration. The symlink itself would appear as a junction point on the filesystem, detectable via directory enumeration but not captured as a Sysmon EID 11 event in the same way a file would be. NTDS.dit is not present on this workstation's shadow copy, so the credential extraction would fail even if the technique completed.

## Assessment

The `vssadmin.exe` process creation is the key detection artifact — it appears in Security EID 4688 and would appear in Sysmon EID 1 with full command line context. The process chain (PowerShell as SYSTEM → cmd.exe → vssadmin.exe) on a domain workstation is a distinctive behavioral pattern. The heavy EID 4664 background activity (185 events) is a reminder that Security log volume can mask meaningful process creation telemetry; detection rules that filter specifically on EID 4688 with relevant process names will perform better than rules that look at overall Security log activity.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — vssadmin.exe creating a shadow copy:** `vssadmin.exe` executing with `create shadow` arguments on a non-backup workstation is highly suspicious. The `GrantedAccess` combination with subsequent symlink creation makes this a compound indicator.

2. **Sysmon EID 1 — mklink /d command:** `cmd.exe /c mklink /d [symlink_path] \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\` is the symlink creation command. The combination of `mklink` with a shadow copy path as the link target is a near-unique indicator of this technique.

3. **EID 4688 — vssadmin.exe parent process anomaly:** On a workstation, `vssadmin.exe` being spawned by `cmd.exe` from a PowerShell-as-SYSTEM session is not a legitimate operational workflow. Shadow copy creation on workstations is typically performed by backup software with its own service context.

4. **Sysmon EID 10 — powershell.exe accessing cmd.exe with full access:** The EID 10 events showing `powershell.exe` (PID 5536) opening `cmd.exe` processes with `0x1FFFFF` provide a behavioral chain anchoring the originating session to the vssadmin execution.

5. **Sysmon EID 11 — symlink target directory creation:** When the `mklink /d` command creates the junction, a directory appears at the link path. Monitoring for new directory creations by `cmd.exe` running as SYSTEM in root-level or temp paths provides a detection opportunity.

6. **Security EID 4664 volume as context:** While EID 4664 activity here is background noise, detection systems should note that heavy 4664 bursts can coincide with attack activity. Using 4664 volume as a base rate rather than a detection signal allows filtering while preserving the 4688 events that matter.
