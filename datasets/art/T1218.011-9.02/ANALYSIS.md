# T1218.011-9: Rundll32 — Launches an Executable Using Rundll32 and pcwutl.dll

## Technique Context

T1218.011 covers proxy execution of arbitrary code through `rundll32.exe`. This test uses `pcwutl.dll` (PC Wellness Utility Library) and its `LaunchApplication` export. The command line is:

```
rundll32.exe pcwutl.dll,LaunchApplication C:\Windows\System32\notepad.exe
```

`pcwutl.dll` is a standard Windows component. Its `LaunchApplication` function is designed to launch executables as part of the Program Compatibility Wizard workflow. In normal use, it would open an application for compatibility testing. Abused here, it becomes a `rundll32`-mediated process launcher: pass any executable path and `rundll32.exe` will launch it.

The payload here is `notepad.exe`, standing in for any executable an attacker might want to run — a reverse shell, a downloaded implant, a persistence mechanism. The technique matters because the resulting process chain is: `rundll32.exe` spawns `notepad.exe`. A detection rule looking for `notepad.exe` with `explorer.exe` or `cmd.exe` as parent may miss a `rundll32.exe` parent entirely.

## What This Dataset Contains

This dataset provides complete, clean execution telemetry with both Security and Sysmon channels fully populated.

**Security EID 4688** captures the full process chain:

1. `cmd.exe` (PID 0x35a4) spawned by `powershell.exe` (PID 0x4770): `"cmd.exe" /c rundll32.exe pcwutl.dll,LaunchApplication %windir%\System32\notepad.exe`
2. `rundll32.exe` (PID 0x4640) spawned by `cmd.exe`: `rundll32.exe  pcwutl.dll,LaunchApplication C:\Windows\System32\notepad.exe`
3. `notepad.exe` (PID 0x42c4) spawned by `rundll32.exe` (PID 0x4640): `"C:\Windows\System32\notepad.exe"`

The third event is the critical payload creation artifact: `notepad.exe` with `rundll32.exe` as the creator process. `notepad.exe` spawned by `rundll32.exe` is not a process relationship that occurs in normal Windows operation.

Note that in the `cmd.exe` event the path uses the environment variable (`%windir%\System32\notepad.exe`) while in the `rundll32.exe` event it is fully resolved (`C:\Windows\System32\notepad.exe`) — this variable-to-path expansion is itself a minor behavioral detail visible in the telemetry.

**Sysmon EID 1** independently captures `cmd.exe`, `rundll32.exe`, and additional whoami.exe processes. The `cmd.exe` EID 1 record is tagged `RuleName: technique_id=T1083,technique_name=File and Directory Discovery` (Sysmon's heuristic tagging) with command line: `"cmd.exe" /c rundll32.exe pcwutl.dll,LaunchApplication %%windir%%\System32\notepad.exe`.

**Sysmon EID 22 (DNS Query)** records a DNS lookup for `github.com` by `MsMpEng.exe` (Windows Defender engine, PID 3556) with `QueryStatus: 9701` (DNS_ERROR_RCODE_NAME_ERROR — NXDOMAIN or unreachable). This is the Defender service attempting a cloud query, unrelated to the attack. It documents real-world background activity occurring during the capture window.

Total event counts: 0 Application, 108 PowerShell, 6 Security (EID 4688), 22 Sysmon.

## What This Dataset Does Not Contain

The dataset does not contain telemetry about what `notepad.exe` did after spawning. In a real attack, the payload binary would likely establish persistence, beacon out, or execute additional stages. Those downstream artifacts are absent.

No **Sysmon EID 7** events specifically showing `pcwutl.dll` loading into `rundll32.exe` appear in the sample set. The 10 EID 7 events captured are all in the `powershell.exe` context.

No **Sysmon EID 3** (network connection) events appear from `notepad.exe` or `rundll32.exe`. In a real attack with a network-capable payload, network connections would be a key additional indicator.

The **PowerShell channel** (108 events) is test framework boilerplate only. The technique executed via `cmd.exe`.

Compared to the defended variant (39 Sysmon, 14 Security, 42 PowerShell), this undefended dataset has significantly fewer Sysmon events (22 vs. 39). The defended run's higher Sysmon count likely reflects Defender interception and any associated process activity around blocking.

## Assessment

This dataset is a clean, complete capture of the pcwutl.dll `LaunchApplication` technique. Its most forensically valuable artifact is the Security EID 4688 showing `notepad.exe` (or any target executable) spawned with `rundll32.exe` as the parent. This parent-child relationship — executable spawned by `rundll32.exe` — is the primary detection hook for this variant. The dataset is particularly useful for validating rules that monitor `rundll32.exe` child process spawning, since the complete chain including both the `rundll32.exe` invocation and the resulting child process appear in the Security log.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** shows `notepad.exe` spawned by `rundll32.exe`. Any executable spawned with `rundll32.exe` as the creator process is anomalous for most environments. In a real attack, the payload binary rather than `notepad.exe` would appear here — the detection logic is the same.
- **Security EID 4688** contains `pcwutl.dll,LaunchApplication` in a `rundll32.exe` command line. This DLL/export combination has no typical use outside of the Program Compatibility Wizard's internal flows and is uncommon in observed enterprise telemetry.
- **Sysmon EID 1** for `cmd.exe` captures the unexpanded `%windir%` path, while Security EID 4688 captures the resolved `C:\Windows\System32\notepad.exe` path. The discrepancy between test framework-executed environment variable form and the resolved form is a minor but consistent artifact of this ART test pattern.
- **Security EID 4688** shows `powershell.exe` → `cmd.exe` → `rundll32.exe` → `notepad.exe`. The four-hop depth with a scripting engine at root and an unexpected parent-child relationship at the leaf is a high-confidence behavioral cluster.
- **Sysmon EID 22** records `MsMpEng.exe` making a DNS query to `github.com`. This is real background OS activity — not attack-related — demonstrating what ambient Defender cloud-query telemetry looks like during an attack window. Understanding this background activity helps calibrate what is and is not technique-generated noise.
