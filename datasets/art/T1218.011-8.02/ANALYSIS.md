# T1218.011-8: Rundll32 — Execution of HTA and VBS Files using Rundll32 and URL.dll

## Technique Context

T1218.011 abuses `rundll32.exe` for proxy execution. This test demonstrates two `URL.dll` export functions — `OpenURL` and `FileProtocolHandler` — used to open and execute HTA and VBScript files respectively. The full command issued is:

```
rundll32.exe url.dll,OpenURL "C:\AtomicRedTeam\atomics\T1218.011\src\index.hta" & rundll32.exe URL.dll,FileProtocolHandler "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"
```

`url.dll` (the URL Shell Extension) is a standard Windows component that handles protocol dispatch. Its `OpenURL` export treats the argument as a URL and routes it through the appropriate handler — for an `.hta` file, that means launching `mshta.exe`. Its `FileProtocolHandler` export opens files using their registered shell handler — for a `.vbs` file, that invokes `wscript.exe`.

The result: `rundll32.exe` launches `mshta.exe` to execute an HTA file, and `wscript.exe` to execute a VBS file. Neither execution path requires the attacker to call `mshta.exe` or `wscript.exe` directly — `rundll32.exe` acts as the broker, making the direct source of the HTA/VBS execution less obvious in a process-name-based detection model.

## What This Dataset Contains

This dataset captures a complete, successful dual-execution — both the HTA and the VBS file executed fully with Defender disabled.

**Security EID 4688** records the complete process chain:

1. `cmd.exe` (PID 0x46bc) spawned by `powershell.exe` (PID 0x4474) with the full chained command: `"cmd.exe" /c rundll32.exe url.dll,OpenURL "C:\AtomicRedTeam\atomics\T1218.011\src\index.hta" & rundll32.exe URL.dll,FileProtocolHandler "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`
2. `rundll32.exe` (PID 0x3ca0) spawned by `cmd.exe`: `rundll32.exe  url.dll,OpenURL "C:\AtomicRedTeam\atomics\T1218.011\src\index.hta"`
3. `rundll32.exe` (PID 0x3e40) spawned by `cmd.exe`: `rundll32.exe  URL.dll,FileProtocolHandler "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`
4. `wscript.exe` (PID 0x252c) spawned by `rundll32.exe` (PID 0x3e40): `"C:\Windows\System32\WScript.exe" "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`

The fourth event is critical: `wscript.exe` spawned with a parent of `rundll32.exe`. This is the direct evidence that `FileProtocolHandler` successfully invoked the VBS handler. A `wscript.exe` process with a parent of `rundll32.exe` is an unusual parent-child relationship that represents a high-confidence detection signal.

**Sysmon EID 1** independently captures the `cmd.exe` and both `rundll32.exe` process creations with full command lines, hashes, and integrity levels. The `rundll32.exe` that invoked `OpenURL` is tagged `RuleName: technique_id=T1218.011,technique_name=rundll32.exe`.

Total event counts: 1 Application (EID 15), 108 PowerShell, 7 Security (EID 4688), 26 Sysmon.

## What This Dataset Does Not Contain

The HTA execution path — `rundll32.exe url.dll,OpenURL "index.hta"` — would typically result in `mshta.exe` being launched. No Security EID 4688 or Sysmon EID 1 event for `mshta.exe` appears in the captured samples. Either `mshta.exe` did not spawn (the HTA opened in a browser context instead), or its process creation event fell outside the sample window.

No **Sysmon EID 3** (network connection) events appear. If `index.hta` or `akteullen.vbs` made network connections as part of their payload, that activity is not captured.

No **Sysmon EID 11** (file creation) events from `wscript.exe` or `rundll32.exe` appear, so the downstream effects of the VBS payload are not visible. The VBS file executed, but what it did is not represented.

The **PowerShell channel** (108 events) is entirely test framework boilerplate — `Set-StrictMode`, error handling framework. The attack was invoked via `cmd.exe`.

Compared to the defended variant (33 Sysmon, 15 Security, 35 PowerShell), this dataset has slightly fewer Sysmon events (26 vs. 33) but provides the `wscript.exe` child process creation that the defended run would suppress through Defender blocking.

## Assessment

This is a high-fidelity undefended dataset that demonstrates the full `url.dll` proxy execution chain. The most forensically significant artifact is Security EID 4688 showing `wscript.exe` spawned with `rundll32.exe` as its direct parent — a parent-child relationship that does not occur in normal Windows operation. The `cmd.exe` event containing both `url.dll,OpenURL` and `URL.dll,FileProtocolHandler` in the same command line is also a strong detection point. The dataset demonstrates that `URL.dll` can be used to execute both HTA and VBS files in a single `cmd.exe` invocation, which is a pattern worth encoding in behavioral analytics.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** shows `wscript.exe` with parent `rundll32.exe` (PID 0x3e40). A `wscript.exe` process whose creator process is `rundll32.exe` is anomalous and has very high detection fidelity for this technique.
- **Security EID 4688** contains `url.dll,OpenURL` and `URL.dll,FileProtocolHandler` in a single `cmd.exe` command line alongside `.hta` and `.vbs` file paths. The combination of `URL.dll` with script file extensions in a `rundll32` command line is a reliable indicator.
- **Sysmon EID 1** independently confirms both `rundll32.exe` invocations with command lines, allowing hash-based and command-line-based detection in parallel.
- **Security EID 4688** shows the parent chain `powershell.exe` → `cmd.exe` → `rundll32.exe` → `wscript.exe`. The four-hop depth with `powershell.exe` at the root and `wscript.exe` executing a VBS file at the leaf is a high-specificity behavioral signature.
- The VBS file path `C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs` is outside of any expected application directory. Detecting `wscript.exe` executing VBS files from non-standard paths via a `rundll32.exe` parent is directly observable here.
