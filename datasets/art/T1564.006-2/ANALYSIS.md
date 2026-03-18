# T1564.006-2: Run Virtual Instance — Create and Start VirtualBox Virtual Machine

## Technique Context

T1564.006 (Run Virtual Instance) covers adversary use of virtualization to hide malicious activity from host-based endpoint protection. This test exercises the next phase after driver registration: creating, configuring, and starting a virtual machine using `VBoxManage.exe`, the VirtualBox command-line management tool. By running payloads inside a guest VM, adversaries can avoid detection by EDR agents that have no visibility into the guest. The `--firmware efi` flag is used to configure the VM with UEFI firmware, which may be chosen to evade some bootkit or legacy-firmware detection methods. Adversaries with VirtualBox already installed on a compromised host can use this technique to spin up isolated execution environments on demand.

## What This Dataset Contains

**Security 4688** captures the full `cmd.exe /c` command:
```
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "Atomic VM" --register
  & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "Atomic VM" --firmware efi
  & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "Atomic VM"
```

**Security 4689** shows `cmd.exe` exiting with `0x1` (generic failure). This indicates `VBoxManage.exe` returned a non-zero exit code — likely because the VirtualBox driver was not successfully loaded (see T1564.006-1), making VM start impossible. The VM creation or start step failed, but the command line was issued and logged.

**Sysmon EID 1** captures both `cmd.exe` and the `whoami.exe` prerequisite check with full parent-child linkage: `powershell.exe` → `cmd.exe` → (VBoxManage invocations within cmd). The `cmd.exe` invocation is tagged by sysmon-modular as suspicious based on its parent being the ART test framework PowerShell.

**PowerShell 4103** captures `Set-ExecutionPolicy Bypass` ART test framework boilerplate for both the outer and inner PowerShell sessions. The technique executes within `cmd.exe`, so no technique-specific PowerShell content appears in module logging.

**4703 (Token Right Adjusted)** records SYSTEM-context privilege enablement for the PowerShell test framework session.

The test window spans 6 seconds (14:27:42–14:27:48), consistent with VBoxManage commands that fail quickly when the underlying driver is not running.

## What This Dataset Does Not Contain (and Why)

No individual `VBoxManage.exe` process creation events appear in Sysmon EID 1 or Security 4688. The three `VBoxManage.exe` invocations run as sub-executions within the `cmd.exe /c` chain — each `&`-separated command in a single `cmd.exe /c` invocation does not necessarily generate separate 4688 events for each program unless each is launched via a separate `CreateProcess` call. The three VBoxManage calls are all within the same `cmd.exe` session and their process creations are not separately captured.

No Sysmon EID 7 (ImageLoad) for VirtualBox DLLs appears. The sysmon-modular configuration's EID 7 include rules do not match VirtualBox binaries, and since the driver was not loaded, VirtualBox DLL initialization did not occur at the depth required to trigger matches.

No network activity appears. VBoxManage VM creation and start operations are local.

No Sysmon EID 11 (FileCreate) for VM disk or configuration files appears. When VBoxManage fails to start the VM, no disk image is written. The VM configuration XML may have been created in `%USERPROFILE%\.VirtualBox\Machines\` but this path is not in the Sysmon EID 11 include rules.

## Assessment

The technique failed to start the virtual machine due to the underlying VirtualBox driver not being loaded (a dependency on the failed T1564.006-1 driver registration). Despite this, the full command line intent is documented in Security 4688, and the `0x1` failure exit from `cmd.exe` is itself a detectable artifact when viewed in context. The dataset demonstrates the telemetry available from a failed VM-launch attempt, which is realistic: many adversary operations fail due to driver signing enforcement or missing components, and the attempt artifacts are what defenders will encounter in practice.

## Detection Opportunities Present in This Data

- **`VBoxManage.exe createvm` or `startvm` in any command line**: invocation of `VBoxManage.exe` with VM lifecycle subcommands (`createvm`, `startvm`, `modifyvm`) is highly anomalous in enterprise environments where VirtualBox use is not explicitly authorized.
- **`--register` combined with `--name` in a VBoxManage command line**: registering a newly created VM immediately before starting it is the standard adversary workflow for spinning up an ephemeral VM.
- **`--firmware efi` in a VBoxManage modifyvm call**: EFI firmware configuration is an uncommon option that may indicate adversary attempts to run UEFI-aware payloads or bypass legacy-firmware defenses.
- **`cmd.exe` exit code `0x1` following VBoxManage invocations**: a failure exit from a cmd chain containing VBoxManage commands still indicates the attempt was made; correlating with the command line identifies the technique.
- **`powershell.exe` → `cmd.exe` with `VBoxManage.exe` in the command line**: this parent-child pattern with a VM management tool is unlikely in legitimate enterprise usage and is a strong behavioral detection candidate.
