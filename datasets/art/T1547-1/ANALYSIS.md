# T1547-1: Boot or Logon Autostart Execution — Add a Driver

## Technique Context

T1547 covers Boot or Logon Autostart Execution — mechanisms that cause adversary code to run when a system boots or a user logs on. This test exercises driver installation as a persistence vector. By registering a kernel driver, an adversary can achieve code execution at boot time with kernel-level privileges. The test uses the Windows Service Control Manager (`sc.exe`) or related interfaces to register a driver entry. This variant represents the broader T1547 technique before sub-technique categorization, specifically targeting driver registration.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The ART test framework invokes the test via WMI (WmiPrvSE.exe) rather than directly — a characteristic of the QEMU guest-agent execution method used across this collection.

**Sysmon (18 events — Event IDs 1, 7, 10, 11, 17):**
- Sysmon Event ID 1 (ProcessCreate) captures `WmiPrvSE.exe` launching as part of the ART invocation chain, tagged with `technique_id=T1047`. This is the WMI-based execution path from the test framework.
- Sysmon Event ID 1 also captures `whoami.exe` (tagged `technique_id=T1033`) used by the test framework for context validation, and `cmd.exe` (tagged `technique_id=T1059.003`) as a command shell. The `cmd.exe` commandline shows `pnputil.exe` invocation.
- Sysmon Event ID 7 (ImageLoad) captures .NET runtime DLLs, `MpOAV.dll`, `MpClient.dll`, and `urlmon.dll` loading into `powershell.exe` — standard PowerShell startup DLL loads.
- Sysmon Event ID 10 (ProcessAccess) records `powershell.exe` accessing `whoami.exe` and `cmd.exe` child processes, tagged `technique_id=T1055.001`.
- Sysmon Event ID 11 (FileCreate) records the PowerShell profile and startup data files being touched.
- Sysmon Event ID 17 (PipeCreate) records the PowerShell named pipe.
- Note: `pnputil.exe` itself does not appear in the Sysmon ProcessCreate events — it falls outside the sysmon-modular include filter for this rule set.

**Security (19 events — Event IDs 4624, 4627, 4672, 4688, 4689, 4703):**
- Event ID 4688 records process creation for `WmiPrvSE.exe`, `svchost.exe`, `whoami.exe`, `cmd.exe`, and `pnputil.exe` with full command lines. The `pnputil.exe` entry provides the actual driver operation command.
- Event ID 4689 records corresponding process exits, including `pnputil.exe` exiting with status `0x0`.
- Event ID 4624 records a SYSTEM logon (Logon Type 5 — Service), and Event ID 4627 records associated group membership. These appear because WmiPrvSE launches under a service logon context.
- Event ID 4672 records special privileges (SeLoadDriverPrivilege, SeDebugPrivilege, and others) assigned to the SYSTEM logon — relevant because driver loading requires SeLoadDriverPrivilege.
- Event ID 4703 records a token right adjustment by lsass for the PowerShell process.

**PowerShell (26 events — Event IDs 4103, 4104):**
- The PowerShell script block content in this test is minimal — only the ART test framework boilerplate is present (two invocations of `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`).
- All Event ID 4104 blocks are runtime error-handling lambdas (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, `$_.OriginInfo`, `$this.Exception.InnerException.PSMessageDetails`).
- No substantive test payload appears in the 4104 events, because the actual driver operation is executed via `cmd.exe /c pnputil.exe ...` rather than native PowerShell cmdlets.

## What This Dataset Does Not Contain

- No Sysmon Event ID 13 (RegistrySetValue). Driver registration via pnputil modifies the registry, but the Sysmon config did not capture those registry write operations for this test.
- No Sysmon ProcessCreate for `pnputil.exe` — it was not matched by the sysmon-modular include-mode filter. The process creation is only visible in Security Event ID 4688.
- No driver load events (Sysmon Event ID 6, which logs kernel driver loads). Sysmon ID 6 is not enabled in this collection configuration.
- No confirmation of whether the driver was actually installed persistently. The process exit code is 0x0, but verification of driver registration in the service database is not captured (no object access auditing enabled).
- No Defender block events. The test completed successfully.
- No network events.

## Assessment

This dataset captures the process execution chain for driver installation using pnputil, with the key evidence split between Security Event ID 4688 (which captures the full `pnputil.exe` command line) and Sysmon Event ID 1 (which captures the broader execution context via WMI). The logon artifacts (4624, 4627, 4672) provide useful context about the privilege level at which the operation ran. The absence of Sysmon's driver-load event (ID 6) means the dataset documents the installation attempt rather than confirmed kernel loading.

## Detection Opportunities Present in This Data

- **Security Event ID 4688**: `pnputil.exe` process creation with `-i -a` flags (install and add) pointing to `.inf` files, particularly outside of normal software installation workflows.
- **Security Event ID 4688**: `pnputil.exe` invoked as a child of `cmd.exe` which is a child of `powershell.exe` which is a child of `WmiPrvSE.exe` — this WMI-to-PowerShell-to-cmd chain is a high-fidelity process ancestry indicator.
- **Security Event ID 4672**: SeLoadDriverPrivilege appearing in logon events associated with unusual processes or non-system accounts.
- **Sysmon Event ID 1**: `cmd.exe` with a command line containing `pnputil` and `.inf` path references, particularly when spawned by scripting hosts.
- **PowerShell Event ID 4103**: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` as a test framework indicator, though this is common across all ART tests and not specific to driver installation.
- Monitoring `HKLM\SYSTEM\CurrentControlSet\Services\` for new driver service registrations (requires registry auditing not present in this dataset) would complement this process-based detection.
