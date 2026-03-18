# T1220-3: XSL Script Processing — WMIC Bypass Using Local XSL File

## Technique Context

T1220 (XSL Script Processing) covers the abuse of XSLT processors to execute code embedded in XSL stylesheets. This test uses `wmic.exe` — the Windows Management Instrumentation Command-line tool — rather than `msxsl.exe`. `wmic.exe` supports a `/FORMAT` parameter that specifies an XSL stylesheet to format query output. When that XSL file contains embedded `<msxsl:script>` elements, `wmic.exe` executes the script code as part of the transformation.

The command is:

```
wmic process list /FORMAT:"C:\AtomicRedTeam\atomics\T1220\src\wmicscript.xsl"
```

`wmic.exe` is a system-native, Microsoft-signed binary present on all Windows installations (though deprecated in Windows 11). Its `/FORMAT` parameter is documented, legitimate functionality — intended for customizing WMI query output. Abused here, it becomes a code execution proxy: the XSL file contains JScript or VBScript that runs in the XSLT context.

Unlike `msxsl.exe` (which must be staged from outside Windows), `wmic.exe` is always present. This makes the WMIC variant more operationally reliable — no staged binaries required.

## What This Dataset Contains

This dataset captures a complete, successful execution. The XSL payload (`wmicscript.xsl`) executed fully and spawned `calc.exe` as the payload proxy — directly observable in the event telemetry.

**Security EID 4688** captures the full process chain:

1. `cmd.exe` (PID 0x4580) spawned by `powershell.exe` (PID 0x4554): `"cmd.exe" /c wmic process list /FORMAT:"C:\AtomicRedTeam\atomics\T1220\src\wmicscript.xsl"`
2. `wmic.exe` (PID 0x4480) spawned by `cmd.exe`: `wmic  process list /FORMAT:"C:\AtomicRedTeam\atomics\T1220\src\wmicscript.xsl"`
3. `calc.exe` (PID 0x45d0) spawned by `wmic.exe` (PID 0x4480): `"C:\Windows\System32\calc.exe"`

Event #3 is the payload execution artifact: `calc.exe` with `wmic.exe` as the creator process. This parent-child relationship — `wmic.exe` spawning any executable — does not occur in normal WMI usage. It is the direct evidence that the XSL script executed successfully and launched a child process.

**Sysmon EID 1** captures `WmiPrvSE.exe` (WMI Provider Host) spinning up (PID 17852, PID 5480) and additional `whoami.exe` processes. The WmiPrvSE.exe event is tagged `RuleName: technique_id=T1047,technique_name=Windows Management Instrumentation`, confirming the WMI subsystem was invoked.

**Sysmon EID 7** (18 events) includes DLL loads into `wmic.exe` that confirm XSL scripting was invoked. The defended analysis documents `scrrun.dll` (Windows Script Runtime) and `wshom.ocx` (Windows Script Host Object Model) loading into `wmic.exe` — these are the scripting engine components required to execute JScript/VBScript embedded in XSL. These DLL loads in `wmic.exe` are a high-confidence indicator that `/FORMAT` script execution occurred.

**Security EID 4799** (19 events) records `C:\Program Files\Cribl\bin\cribl.exe` enumerating local group memberships — the Cribl Edge agent performing its routine system inventory. This is real background activity from the instrumentation stack, not attack-related. The enumerated groups include `Administrators`, `Backup Operators`, `Remote Desktop Users`, and others. These events document what ambient group-membership enumeration from a legitimate monitoring agent looks like, providing context for what real background activity populates the security log.

**Security EID 4798** (5 events) records user account enumeration — also from `cribl.exe`.

Total event counts: 0 Application, 107 PowerShell, 31 Security (EID 4688: 7, EID 4799: 19, EID 4798: 5), 29 Sysmon.

Compared to the defended variant (39 Sysmon, 15 Security, 34 PowerShell), this undefended dataset has fewer Sysmon events (29 vs. 39) but significantly more Security events (31 vs. 15), largely due to the Cribl agent's group-enumeration activity falling within the capture window.

## What This Dataset Does Not Contain

Although `calc.exe` was spawned (confirming payload execution), the dataset does not capture what `calc.exe` does after launch. In a real attack, the payload would establish persistence, beacon out, or execute further stages — none of that is represented.

No **Sysmon EID 1** for `calc.exe` or `wmic.exe` itself appears in the sample set. The process creation events visible in the Security channel are not fully duplicated in the Sysmon channel for all processes (the Sysmon EID breakdown shows 5 EID 1 events but the samples captured focus on WMI and whoami). A complete Sysmon EID 1 for `calc.exe` would show `wmic.exe` as the parent, making it the clearest single-event detection artifact.

The XSL script content (`wmicscript.xsl`) is not represented in any event. The payload code embedded in the stylesheet is not captured.

## Assessment

This is the highest-fidelity dataset among the three T1220 variants, and one of the most complete in the entire batch. It documents a successful XSL script execution with the payload process creation clearly attributable to `wmic.exe`. The `wmic.exe` → `calc.exe` parent-child relationship in Security EID 4688, the `wmic.exe`-with-`/FORMAT`-and-`.xsl` command line, and the WMI scripting DLLs loading into `wmic.exe` form a mutually reinforcing cluster of detection evidence. The Cribl agent's background group-enumeration traffic (EID 4799 bulk) is an important dataset realism feature — it shows what legitimate background activity looks like in the same log window as an attack execution.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** shows `wmic.exe` with `/FORMAT:` followed by a path to a `.xsl` file. Any `wmic.exe` invocation where the `/FORMAT` argument points to a local file path (rather than a standard WMI format name like `csv`, `htable`, `list`) is a strong T1220 indicator.
- **Security EID 4688** shows `calc.exe` spawned by `wmic.exe` (PID 0x4480). Any executable spawned by `wmic.exe` as a child process is anomalous — `wmic.exe` does not launch user processes under normal WMI operation.
- **Sysmon EID 7** (as documented in the defended analysis) shows `scrrun.dll` and `wshom.ocx` loading into `wmic.exe`. These Windows Script Host libraries loading into `wmic.exe` indicate the `/FORMAT` XSL script engine was invoked and executed script code.
- **Security EID 4688** shows the parent chain `powershell.exe` → `cmd.exe` → `wmic.exe` → `calc.exe`. The four-hop depth with `wmic.exe` spawning a non-WMI process is a high-confidence behavioral signature.
- **Security EID 4799** (19 events, all from `cribl.exe`) documents real-world background group-enumeration activity from the Cribl monitoring agent. Distinguishing this from attack-driven group enumeration (EID 4799 events from unexpected processes) is a practical detection skill this dataset supports — `cribl.exe` is the expected source here, while an attacker-controlled process enumerating groups would be the anomaly.
