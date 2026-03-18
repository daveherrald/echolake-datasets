# T1564.006-1: Run Virtual Instance — Register Portable VirtualBox

## Technique Context

T1564.006 (Run Virtual Instance) covers adversary use of virtualization technology to run malicious activity inside a guest VM, isolating it from the host's endpoint protection and monitoring stack. Endpoint agents running on the host cannot observe processes or filesystem activity inside a guest VM unless they have specific hypervisor-level or guest-agent visibility. The "portable VirtualBox" variant is particularly notable because it does not require an administrative installer — the attacker registers and starts the VirtualBox kernel driver directly from a local path, making it possible to deploy VirtualBox from a writable location without leaving an Add/Remove Programs entry.

This test registers the VirtualBox kernel driver by calling `VBoxSVC.exe /reregserver`, registering the COM server DLL with `regsvr32`, loading the runtime DLL with `rundll32`, creating the kernel driver service with `sc create`, and then starting it with `sc start VBoxDRV`.

## What This Dataset Contains

**Security 4688** records two process creations: `whoami.exe` (ART prerequisite) and the full `cmd.exe /c` command chain:
```
"C:\Program Files\Oracle\VirtualBox\VBoxSVC.exe" /reregserver
  & regsvr32 /S "C:\Program Files\Oracle\VirtualBox\VboxC.dll"
  & rundll32 "C:\Program Files\Oracle\VirtualBox\VBoxRT.dll,RTR3Init"
  & sc create VBoxDRV binpath= "C:\Program Files\Oracle\VirtualBox\drivers\VboxDrv.sys" type= kernel start= auto error= normal displayname= PortableVBoxDRV
  & sc start VBoxDRV
```

A third 4688 records `sc.exe start VBoxDRV` as a separate child process of the `cmd.exe` chain (captured because `sc.exe` is in the sysmon-modular include rules).

**Security 4689** shows `sc.exe` and `cmd.exe` both exit with `0x424` (decimal 1060 = `ERROR_SERVICE_DOES_NOT_EXIST`). This indicates that `sc start VBoxDRV` failed — the driver service creation step did not succeed, likely because the binpath pointed to a driver file that Windows could not load (possibly due to driver signature enforcement or a missing/invalid `.sys` file).

**Sysmon EID 1** captures both `cmd.exe` and `sc.exe` process creations with full command lines and parent chain. `sc.exe` is tagged by sysmon-modular as a monitored binary. The parent-child chain `powershell.exe` → `cmd.exe` → `sc.exe` is fully reconstructable.

**PowerShell 4103** captures the ART test framework boilerplate (`Set-ExecutionPolicy Bypass`) for both the outer test framework and the inner test session. No technique-specific PowerShell content appears because the technique runs through `cmd.exe`.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 13 (RegistryValue set) appears for the `VBoxSVC.exe /reregserver` or `regsvr32` calls. Registry modification events require the Registry audit policy subcategory to be enabled, and the environment is configured with `object_access: none`. Sysmon registry events would require explicit EID 12/13/14 include rules, which are not present in this configuration.

No Sysmon EID 7 (ImageLoad) for VirtualBox DLLs appears, despite image load monitoring being enabled. The sysmon-modular EID 7 rules are selective — they do not match VirtualBox DLL paths. Only the PowerShell test framework DLL loads (standard Microsoft DLLs) appear in EID 7.

No kernel driver load event (Sysmon EID 6) appears because the driver start failed with `0x424`. Had the driver loaded successfully, EID 6 (DriverLoad) would have recorded it.

## Assessment

The technique partially executed. `VBoxSVC.exe`, `regsvr32`, and `rundll32` ran, but the critical `sc start VBoxDRV` failed with `ERROR_SERVICE_DOES_NOT_EXIST`. The VirtualBox kernel driver registration did not complete to the point of a functional running driver. Despite the failure, the dataset is valuable: the full registration attempt is documented in Security 4688 and Sysmon EID 1, and the `0x424` failure code is itself a detectable artifact. Real-world adversaries attempting this technique would encounter the same failure mode if driver files are absent or blocked by code integrity enforcement.

## Detection Opportunities Present in This Data

- **`sc create` with `type= kernel` in the command line**: creating a kernel-mode service from a non-standard path (`C:\Program Files\Oracle\VirtualBox\drivers\`) is an unusual and high-confidence indicator for driver-based virtualization installation.
- **`regsvr32 /S` for a VirtualBox DLL**: silent COM server registration of virtualization-related DLLs from a writable or user-controlled path is a strong behavioral signal.
- **`rundll32` loading a VirtualBox runtime DLL**: `rundll32` combined with VirtualBox, VMware, or similar virtualization library names warrants investigation.
- **`sc.exe` with `VBoxDRV` or similar virtualization service names**: the service name itself is a known indicator; detection rules for virtualization driver service creation and start attempts cover this class of behavior.
- **`0x424` (ERROR_SERVICE_DOES_NOT_EXIST) from `sc.exe` after a `sc create` sequence**: this exit code pattern, when preceded by service creation commands, indicates a blocked or failed kernel driver registration attempt worth investigating in context.
