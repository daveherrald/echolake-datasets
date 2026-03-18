# T1218.011-6: Rundll32 — Rundll32 syssetup.dll Execution

## Technique Context

T1218.011 abuses `rundll32.exe` to proxy execution of code through a legitimate, Microsoft-signed binary. This test targets a specific export from `syssetup.dll`: `SetupInfObjectInstallAction`. The command line is:

```
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf"
```

`syssetup.dll` is the Windows Setup support library. Its `SetupInfObjectInstallAction` export processes Windows INF (Setup Information) files — the same file format used to install device drivers and system components. An INF file can contain directives to copy files, modify registry keys, execute commands, and run arbitrary programs. By supplying a custom INF file, an attacker can use `rundll32.exe` + `syssetup.dll` to trigger any of those operations while appearing as legitimate setup activity.

The `128` parameter maps to `SPINST_ALL`, which tells the INF processor to execute all sections in the file. This is the maximum-breadth execution flag for INF processing.

## What This Dataset Contains

**Security EID 4688** captures the full execution chain:

1. `cmd.exe` (PID 0x4190) spawned by `powershell.exe` (PID 0x479c) with command line: `"cmd.exe" /c rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf"`
2. `rundll32.exe` (PID 0x4298) spawned by `cmd.exe` with command line: `rundll32.exe  syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 "C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf"`

Both events fully expose the technique. The attack is visible from either the `cmd.exe` or `rundll32.exe` event — the DLL name, export function, parameters, and INF file path are all present. Note the double space between `rundll32.exe` and `syssetup.dll` in the direct invocation, which is the ART test framework artifact of how it constructs the command string.

**Sysmon EID 1** confirms `cmd.exe` and `rundll32.exe` process creations with full command lines, integrity levels (`System`), and hashes. The `cmd.exe` SHA1 is `94BDAEB55589339BAED714F681B4690109EBF7FE`.

**Sysmon EID 7** (9 events) records DLL loads into `powershell.exe` — `.NET` runtime components, Defender libraries (`MpOAV.dll`, `MpClient.dll`), and `urlmon.dll`. No specific `syssetup.dll` load event appears in the sample set for `rundll32.exe`, but the technique executed fully given the clean exit codes.

**Sysmon EID 10** (4 events) shows `powershell.exe` accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF` — the ART test framework pattern.

The dataset contains 5 Security EID 4688 events total (including ART pre/post `whoami.exe` and cleanup `cmd.exe`), 20 Sysmon events, and 96 PowerShell events (all test framework boilerplate).

## What This Dataset Does Not Contain

The INF file contents are not represented in any event. To understand what `T1218.011_DefaultInstall.inf` actually does — what commands it runs, what files it copies, what registry keys it modifies — you would need to examine the INF file itself or observe the side effects of its execution in additional telemetry (file creation, registry, process spawn from the INF actions).

There are no **Sysmon EID 11** (file creation) or EID 12/13 (registry) events showing the downstream effects of INF processing. If the INF file created files or modified registry keys, those artifacts are not captured.

The dataset does not include a **Sysmon EID 7** for `syssetup.dll` loading into `rundll32.exe`, which would directly confirm the DLL was invoked. The 9 EID 7 events captured are all in the `powershell.exe` context.

Compared to the defended variant (37 Sysmon, 14 Security, 42 PowerShell), this undefended dataset has fewer Sysmon events (20 vs. 37) and fewer Security events (5 vs. 14). The defended dataset's higher counts likely include Defender telemetry and relaunch attempts triggered by the AV blocking.

## Assessment

This is a high-value undefended dataset for the syssetup.dll INF-execution variant. The command lines in both the Security and Sysmon channels are complete and specific. The combination of `rundll32.exe`, `syssetup.dll`, `SetupInfObjectInstallAction`, and a path to an INF file outside of `C:\Windows\inf\` is a reliable detection anchor — legitimate Windows setup operations use INF files from the Windows directory, not from user-controlled paths. The dataset effectively demonstrates the full execution chain of this LOLBin abuse.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** shows `rundll32.exe` with `syssetup.dll,SetupInfObjectInstallAction` in the command line. The `syssetup.dll` + `SetupInfObjectInstallAction` combination in any `rundll32.exe` invocation is rare outside of legitimate Windows component installation flows.
- **Security EID 4688** and **Sysmon EID 1** both contain the INF file path `C:\AtomicRedTeam\atomics\T1218.011\src\T1218.011_DefaultInstall.inf`. An INF file path outside of `C:\Windows\INF\` or a system driver store in a `rundll32.exe` + `syssetup.dll` command line is a strong indicator of abuse.
- **Security EID 4688** shows the parent chain: `powershell.exe` → `cmd.exe` → `rundll32.exe`. This three-hop chain with a script engine at the root and `rundll32.exe` at the leaf is a consistent T1218.011 behavioral signature.
- The `SPINST_ALL` (128) parameter value is explicitly visible. Legitimate uses of `SetupInfObjectInstallAction` from setup automation typically specify narrower action flags.
- **Sysmon EID 1** captures the hash of `rundll32.exe` (`SHA1=D8240...`), enabling correlation with other T1218.011 variants in this dataset where the same binary appears.
