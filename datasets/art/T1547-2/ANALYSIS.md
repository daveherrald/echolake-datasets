# T1547-2: Boot or Logon Autostart Execution — Driver Installation Using pnputil.exe

## Technique Context

T1547 covers Boot or Logon Autostart Execution. This test specifically exercises `pnputil.exe`, the Windows Plug and Play utility, as the mechanism for installing a driver package. `pnputil.exe -i -a <inf>` installs a driver into the Windows driver store and can register it for loading at boot time. Adversaries abuse this to achieve kernel-mode persistence: a malicious driver registered via pnputil will load on subsequent boots without further user interaction. This test uses a legitimate INF file (`acpipmi.inf`) from `C:\Windows\INF\` to demonstrate the installation pathway without requiring a malicious payload.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The ART test framework invokes the operation via PowerShell, which executes `pnputil.exe -i -a C:\Windows\INF\acpipmi.inf`.

**Sysmon (37 events — Event IDs 1, 7, 10, 11, 17):**
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `technique_id=T1033`), and two distinct `powershell.exe` child instances. The second PowerShell spawn (tagged `technique_id=T1059.001`) executes the pnputil command. The Sysmon ProcessCreate for `pnputil.exe` itself is not present — the include-mode filter did not match `pnputil.exe` in this test context.
- Sysmon Event ID 10 (ProcessAccess) records the parent `powershell.exe` accessing `whoami.exe` and the child `pnputil.exe` process, tagged `technique_id=T1055.001`.
- Sysmon Event ID 7 (ImageLoad) records .NET runtime DLLs (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`), PowerShell management automation DLL (`System.Management.Automation.ni.dll`, tagged `T1059.001`), Defender DLLs (`MpOAV.dll`, `MpClient.dll`, tagged `T1574.002`), and `urlmon.dll` loading into both PowerShell instances. These are standard process initialization artifacts repeated for each PowerShell spawn.
- Sysmon Event ID 11 (FileCreate) records the PowerShell `StartupProfileData-Interactive` and `StartupProfileData-NonInteractive` files being written.
- Sysmon Event ID 17 (PipeCreate) records the named pipe `\PSHost.<...>.powershell` for each PowerShell instance.

**Security (12 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records process creation for `powershell.exe`, `whoami.exe`, and `pnputil.exe`. The `pnputil.exe` creation entry provides the command line: `pnputil.exe -i -a C:\Windows\INF\acpipmi.inf`. All processes run as `S-1-5-18` (SYSTEM).
- Event ID 4689 records corresponding exits. `pnputil.exe` exits with status `0x0`, indicating successful completion.
- Event ID 4703 records a token right adjustment for the PowerShell process.
- This test lacks the logon events (4624, 4627, 4672) present in T1547-1 — the WMI execution path was not taken here, so no new service logon was created.

**PowerShell (37 events — Event IDs 4103, 4104):**
- Event ID 4104 captures two key script blocks: `& {pnputil.exe -i -a C:\Windows\INF\acpipmi.inf}` (the outer invocation wrapper) and `{pnputil.exe -i -a C:\Windows\INF\acpipmi.inf}` (the inner body). Both blocks are logged, reflecting how ART wraps test execution.
- Event ID 4103 records two `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` invocations — one per PowerShell instance spawned by the test framework.
- The remaining 4104 events are runtime error-handling boilerplate.

## What This Dataset Does Not Contain

- No Sysmon Event ID 1 for `pnputil.exe` itself — the sysmon-modular include-mode filter did not match it. Process-level evidence for pnputil is only in Security Event ID 4688.
- No Sysmon Event ID 6 (DriverLoad). The collection configuration does not enable driver load logging, so confirmation that the driver was registered for loading is absent.
- No Sysmon Event ID 13 (RegistrySetValue). `pnputil.exe` writes service entries under `HKLM\SYSTEM\CurrentControlSet\Services\`, but registry auditing was not configured.
- No Defender block events. The test used a legitimate inbox INF file and completed successfully.
- No network events.
- No Event ID 4656/4663 (file or registry object access auditing). Object access policy is set to none.

## Assessment

This dataset provides clear evidence of `pnputil.exe` being invoked to install a driver package, with the full command line captured in Security Event ID 4688 and the PowerShell payload captured in Event ID 4104 script block logging. The pnputil exit code of 0x0 confirms the operation completed. The absence of Sysmon's driver-load event (ID 6) is a known gap in this collection configuration — the installation is documented but the subsequent boot-time load would not appear here.

## Detection Opportunities Present in This Data

- **Security Event ID 4688**: `pnputil.exe` launched with `-i -a` (install-and-add) arguments, especially when the parent process is `powershell.exe`, `cmd.exe`, or `WmiPrvSE.exe` rather than a legitimate installer process.
- **Security Event ID 4688**: `pnputil.exe` invoked from non-standard working directories or referencing INF files outside of `C:\Windows\INF\` (the test used an inbox file; real attacks would reference dropped malicious INF files).
- **Sysmon Event ID 10**: `powershell.exe` accessing a `pnputil.exe` child process — parent-child access events for this combination are uncommon in normal operations.
- **PowerShell Event ID 4104**: Script blocks containing `pnputil.exe` with install-mode flags.
- **PowerShell Event ID 4103**: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` followed closely by pnputil-related script block activity indicates ART-style or similar test framework-driven execution.
- For deeper coverage, enabling Sysmon Event ID 6 (DriverLoad) would allow detection of the driver's subsequent loading at boot, which is not present in this dataset.
