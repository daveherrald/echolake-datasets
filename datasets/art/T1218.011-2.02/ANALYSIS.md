# T1218.011-2: Rundll32 — Rundll32 Execute VBscript Command

## Technique Context

T1218.011 covers proxy execution of malicious code through `rundll32.exe`, a Microsoft-signed Windows binary. This test variant uses the `vbscript:` protocol handler — the VBScript counterpart to the `javascript:` variant. The command line is:

```
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
```

The same mechanism applies as in the JavaScript variant: `rundll32` loads `mshtml.dll` and calls `RunHTMLApplication`, which creates an HTA execution context. VBScript code then executes within that context. Here, `CreateObject("WScript.Shell").Run("calc.exe")` invokes `calc.exe` as the payload proxy. In a real attack, `calc.exe` would be replaced with anything the attacker wants to launch.

This variant matters because some detection rules focus specifically on `javascript:` in `rundll32` command lines and miss `vbscript:`. The two variants are distinct strings but functionally identical techniques.

## What This Dataset Contains

The key artifact is a **Security EID 4688** process creation event containing the full attack command line:

```
"cmd.exe" /c rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
```

The creator process is `powershell.exe` (PID 0x4144) and the new process is `cmd.exe` (PID 0x3984). Every component of the attack is captured: `rundll32`, `vbscript:`, `mshtml`, `RunHTMLApplication`, `CreateObject`, `WScript.Shell`, and `Run("calc.exe")`. The command line is unambiguously malicious — no legitimate application invokes `rundll32` with `vbscript:` as a protocol handler.

Because Defender was disabled, `calc.exe` was actually launched. A second **Security EID 4688** shows `cmd.exe` (PID 0x42e0) spawned by `powershell.exe` after the attack completes, which is the ART cleanup/teardown step.

**Sysmon EID 1** fires twice for `whoami.exe` processes (ART's pre- and post-execution checks). Notably, Sysmon does not produce an EID 1 for `rundll32.exe` itself — the ART test framework spawned `rundll32` via `cmd.exe` and the Sysmon include rules did not match the `rundll32.exe` invocation in the samples captured.

**Sysmon EID 8 (CreateRemoteThread)** records `powershell.exe` (PID 17168) creating a remote thread in an `<unknown process>`. This is the same pattern seen in T1218.011-1: the target process exited before Sysmon resolved its image name. The combination of EID 8 with `<unknown process>` and a `powershell.exe` source is a consistent pattern across these short-lived `rundll32` invocations.

**Sysmon EID 7** (9 DLL load events) shows `.NET` runtime and Windows Defender libraries loading into `powershell.exe`. No `mshtml.dll` or `vbscript.dll` load events appear in the sample set, but the technique executed fully.

Total event counts: 0 Application, 110 PowerShell, 4 Security (EID 4688), 18 Sysmon.

## What This Dataset Does Not Contain

The dataset does not contain a **Security EID 4688** for `rundll32.exe` itself or for `calc.exe` being launched. These processes ran and exited, but their creation events either fell outside the capture window or were not captured given the brief execution duration.

There are no **Sysmon EID 1** events for `rundll32.exe` or `calc.exe`. If detecting a child process spawned from `rundll32.exe` as a payload indicator is the goal, this dataset does not provide that evidence — the process chain is visible only in the Security 4688 for `cmd.exe`.

No **Application log events** (EID 1000/1001 crashes, Defender events, AMSI telemetry) appear. The technique completed cleanly.

The **PowerShell channel** (110 events) is entirely test framework boilerplate. The `vbscript:` invocation went through `cmd.exe`, not a PowerShell cmdlet, so it produces no PowerShell script block telemetry.

Compared to the defended variant (16 Sysmon, 10 Security, 41 PowerShell), this dataset shows fewer Security events (4 vs. 10), consistent with Defender not generating additional log entries from blocking attempts.

## Assessment

This is a solid undefended dataset for the VBScript variant of T1218.011. The complete attack command line is preserved in the Security channel. The fact that `calc.exe` was launched (the payload proxy for this test) is implicit — the technique executed without interference — but direct evidence of `calc.exe` spawning is absent from the captured data. The dataset is most useful for validating `vbscript:` + `RunHTMLApplication` detection logic against a successful execution example, and for comparing against the defended variant where Defender's blocking activity generates significantly more Security events.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** contains `vbscript:` as part of a `rundll32` command line — this string combination has no legitimate use case and should trigger on any endpoint or SIEM with command-line logging enabled.
- **Security EID 4688** also contains `RunHTMLApplication` in the command line — this export name appearing in any process command line is a strong indicator regardless of whether `javascript:` or `vbscript:` is used.
- **Security EID 4688** shows `powershell.exe` spawning `cmd.exe` carrying the attack — the parent-child pair (`powershell.exe` → `cmd.exe` with a `rundll32 vbscript:` command) is a reliable behavioral signature.
- **Sysmon EID 8** fires from `powershell.exe` into `<unknown process>`. Correlating this EID 8 event with the adjacent EID 4688 event bearing the malicious command line, time-windowed within a few seconds, closes the observability gap between the two channels.
- **Sysmon EID 10** records `powershell.exe` opening `whoami.exe` with full access (`0x1FFFFF`). Real attackers using `whoami` for user context discovery before lateral movement produce identical telemetry.
