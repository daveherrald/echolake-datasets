# T1562.001-29: Disable or Modify Tools — Kill Antimalware Protected Processes Using Backstab

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) covers adversary actions that prevent
security software from running or reporting. Backstab is an open-source offensive tool that
abuses the legitimate, Microsoft-signed Process Explorer driver (`procexp.sys`) to kill
processes protected by Antimalware Protection Light (PPL). PPL is the kernel-level mechanism
that prevents user-mode processes from opening handles to PPL-protected processes like
`MsMpEng.exe` (Windows Defender). Backstab requests the driver to kill the target process,
bypassing standard userland restrictions. This technique has been observed in ransomware
operators' toolkits.

In this dataset, Defender is **disabled** at the policy level. The test attempts to kill
`MsMpEng.exe` using `Backstab64.exe -k -n MsMpEng.exe`.

## What This Dataset Contains

The dataset captures 88 events across three channels (1 Application, 84 PowerShell, 3
Security) spanning approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation,
2026-03-17T17:36:16Z–17:36:20Z).

**Security EID 4688 — Process creation for the ART test framework launch of Backstab.** The test framework
spawns a child `powershell.exe` with:

```
"powershell.exe" & {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Backstab64.exe" -k -n MsMpEng.exe}
```

The `-k` flag instructs Backstab to kill the target, `-n MsMpEng.exe` names the target
process. The parent is the ART test framework PowerShell running as `NT AUTHORITY\SYSTEM`.
Two additional 4688 events capture `whoami.exe` pre- and post-execution checks.

**Application EID 15 — Defender state registered as `SECURITY_PRODUCT_STATE_ON`.** The
Security Center Defender state refreshed within the test window, consistent with Defender
engine activity or a post-attack health registration update.

**PowerShell EID 4104 — 83 script block events.** The substantive blocks are the ART test framework
boilerplate: `Set-ExecutionPolicy Bypass -Scope Process -Force`, `$ErrorActionPreference =
'Continue'`, and the cleanup invocation `Invoke-AtomicTest T1562.001 -TestNumbers 29
-Cleanup`. No Backstab-specific script block content appears beyond the 4688 command line,
because `Backstab64.exe` is a compiled binary invoked via `&` (call operator), not a
PowerShell script.

**PowerShell EID 4103 — One module pipeline event** for the `Set-ExecutionPolicy` test framework
call.

## What This Dataset Does Not Contain

**No Backstab64.exe process creation event.** Neither Security 4688 nor Sysmon (absent from
this dataset) captures `Backstab64.exe` as a process creation event. This aligns with the
defended dataset, where Backstab64.exe also did not appear as a Sysmon EID 1 — the
difference here is that the binary was invoked via the `&` call operator in a child
PowerShell, and the absence of a separate 4688 for `Backstab64.exe` is consistent with how
`&` execution via PowerShell works when the child binary is the outermost invocation in the
child process.

**No procexp.sys driver load event.** Backstab's core mechanism is loading or communicating
with the Process Explorer driver kernel. Without Sysmon EID 6 (driver loaded) data in the
bundled channels, there is no visibility into whether the driver was loaded. The Security
4688 chain captures only the PowerShell and test framework layer.

**No MsMpEng.exe termination event.** Whether `MsMpEng.exe` was successfully killed cannot
be confirmed from the events in this dataset. No Security 4689 (process exit) for
`MsMpEng.exe`, no System EID 7034/7036 (service crash/state change), and no Sysmon EID 5
(process terminated) appear. The Application EID 15 `SECURITY_PRODUCT_STATE_ON` suggests
the Defender service was still registering as active.

**No Sysmon data.** The defended variant includes Sysmon EID 1, 7, and 10 events that show
the PowerShell process tree and DLL loads. All of that telemetry is absent from the undefended
dataset's bundled files.

**No PowerShell error events (EID 4100).** Unlike tests 27 and 28, no Access Denied error
was raised at the PowerShell test framework level, suggesting the Backstab invocation did not
throw a catchable .NET exception in the test framework's `Invoke-Process` path.

## Assessment

This dataset captures the invocation of Backstab64.exe targeting `MsMpEng.exe` on a host
with Defender disabled. The primary artifact is the Security 4688 command line showing
`Backstab64.exe -k -n MsMpEng.exe`. The absence of a 4100 error event (unlike tests 27 and
28) suggests the Backstab binary was at least launched without a process-start-level failure,
though outcome confirmation is not available in this telemetry.

The undefended dataset provides fewer events than the defended variant (88 vs. roughly 103
across all channels including Sysmon), primarily because Sysmon is not bundled. The key
forensic value is in the 4688 command line with the `ExternalPayloads\Backstab64.exe` path
and the explicit `-k -n MsMpEng.exe` arguments, which are equivalent in both variants.

## Detection Opportunities Present in This Data

**Security EID 4688 — `Backstab64.exe` or `Backstab.exe` in any command line.** The tool
name is a strong indicator. The path `ExternalPayloads\Backstab64.exe` is ART-specific;
in a real attack, Backstab would typically be staged in a less obvious location, but the
binary name and `-k -n <process>` argument pattern remain characteristic.

**Security EID 4688 — PowerShell spawning an executable from a staging directory with
`-k -n <security process name>`.** The combination of a compiled binary invoked from
PowerShell targeting a named security process is a high-fidelity behavioral indicator.

**PowerShell EID 4104 — `ExternalPayloads` directory path.** As with test 28, the
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\` path in a script block or 4688 command line
is a testing artifact. Real Backstab deployments would use an attacker-controlled path.

**Application EID 15 with `SECURITY_PRODUCT_STATE_ON` near suspicious PowerShell activity.**
The Security Center health refresh event appears in the same time window and can serve as a
temporal anchor when correlating with process creation events.
