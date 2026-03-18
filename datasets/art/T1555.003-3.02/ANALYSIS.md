# T1555.003-3: Credentials from Web Browsers — LaZagne - Credentials from Browser

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) covers adversary techniques that extract saved passwords from browser credential stores. LaZagne is an open-source, Python-compiled credential recovery tool that targets dozens of applications including Chrome, Firefox, Opera, Edge, and Internet Explorer. It accesses browser SQLite databases and Windows DPAPI-protected blobs to recover plaintext credentials without requiring a browser to be running. It is widely used in post-exploitation toolkits and has been observed in ransomware precursor activity, targeted intrusion campaigns, and commodity malware.

With Defender disabled, LaZagne executes without behavioral blocking or AMSI interception. The `browsers` subcommand targets all supported browser credential stores simultaneously.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 3 seconds. It contains 130 events across three channels: 19 Sysmon, 107 PowerShell, and 4 Security.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1555.003\bin\LaZagne.exe" browsers
```
The full command line appears verbatim in both Security EID=4688 and Sysmon EID=1. The binary path — `C:\AtomicRedTeam\atomics\T1555.003\bin\LaZagne.exe` — identifies both the tool and its location as an ART-bundled payload. Running as `NT AUTHORITY\SYSTEM`.

**Sysmon EID=1 — cmd.exe:** The `cmd.exe` process is captured (tagged `technique_id=T1059.003,technique_name=Windows Command Shell`), parent `powershell.exe`, with the full LaZagne command line.

**Sysmon EID=10 (Process Access):** Four EID=10 events showing `powershell.exe` accessing child processes at `GrantedAccess: 0x1FFFFF`, tagged `technique_id=T1055.001`. The cross-process handle access reflects the ART test framework managing child process execution.

**Sysmon EID=1 (Process Create):** Four process creations: two `whoami.exe` instances (tagged T1033), `cmd.exe` (tagged T1059.003) with the LaZagne invocation, and a second `cmd.exe` as part of the test framework cleanup phase.

**PowerShell EID=4104:** 104 script block events capturing the ART test framework boilerplate and the cmd-based LaZagne invocation wrapper.

**Security EID=4688:** Four process creation events (SYSTEM context) capturing `whoami.exe` twice, `cmd.exe` with the LaZagne command line, and the cleanup `cmd.exe`.

**Sysmon EID=17 (Pipe Created):** One named pipe creation from PowerShell console host infrastructure.

**Sysmon EID=11 (File Created):** One EID=11 event in the dataset, though the sample may reflect a PowerShell startup profile artifact rather than LaZagne output given the SYSTEM context.

Note: The sysmon-modular ProcessCreate filter does not include a rule matching `LaZagne.exe` by name — LaZagne's own process creation does not appear as a Sysmon EID=1 event. The binary runs as a child of `cmd.exe` but Sysmon's include-mode filtering means only `cmd.exe` is captured in EID=1, not LaZagne itself.

## What This Dataset Does Not Contain

**LaZagne.exe in Sysmon EID=1.** The sysmon-modular config uses include-mode ProcessCreate filtering. LaZagne's binary name does not match any include rules, so no Sysmon EID=1 fires for the LaZagne process itself. Security EID=4688 shows `cmd.exe` but not the child `LaZagne.exe` process (unless command-line auditing captures it in the cmd event — the cmd event shows the LaZagne invocation in cmd's own command line, which is sufficient for detection purposes).

**Credential output.** LaZagne found no browser credentials to dump under the SYSTEM account — browser installations are per-user and the SYSTEM profile contains no Chrome, Firefox, or Opera data. LaZagne's output is captured only in process stdout, which is not logged by any of the configured channels.

**LaZagne DLL loads.** The LaZagne binary loads Python runtime DLLs and browser-specific libraries. Sysmon EID=7 events in this dataset are from the parent PowerShell process, not from LaZagne itself (because LaZagne does not appear in Sysmon's monitoring scope).

**Comparison with the defended variant:** In the defended dataset (sysmon: 35, security: 10, powershell: 34), Windows Defender blocked LaZagne.exe before it could access browser stores. The defended Sysmon event count (35) is actually higher than the undefended (19) because Defender's monitoring adds its own telemetry. The defended security event count (10) versus undefended (4) reflects Defender-generated process lifecycle events. The key difference in the undefended dataset is that LaZagne ran to completion — even though it found no credentials, the tool executed without interruption and the full process chain is preserved.

## Assessment

This dataset provides a clean view of the LaZagne browser credential theft execution pattern. The cmd.exe process create with the full `LaZagne.exe browsers` command line in both Security EID=4688 and Sysmon EID=1 is the primary detection artifact. The tool ran without interference for its full execution window.

The dataset's practical limitation is the absence of credential output — the SYSTEM account context means LaZagne found nothing. For analysts studying LaZagne behavior, the process chain and command-line arguments are the primary detection anchors available in this telemetry.

## Detection Opportunities Present in This Data

**Security EID=4688 / Sysmon EID=1 — cmd.exe with LaZagne.exe path:** The command line `"cmd.exe" /c "...\LaZagne.exe" browsers` is a direct, specific indicator. The binary name and the `browsers` subcommand both appear.

**Security EID=4688 — AtomicRedTeam path in command line:** The path `C:\AtomicRedTeam\atomics\T1555.003\bin\LaZagne.exe` reveals the specific binary location. In production environments, LaZagne would appear from different paths (temp directories, user profiles, ProgramData), but the detection logic applies regardless of path.

**Process lineage — powershell.exe → cmd.exe → (implied) LaZagne.exe:** The chain of PowerShell spawning cmd.exe with a path to a credential-access tool is a consistent behavioral pattern. The cmd.exe command line contains the full LaZagne invocation.

**Sysmon EID=10 — PROCESS_ALL_ACCESS from PowerShell to child processes:** The cross-process access pattern in combination with a child process that carries credential-tool command lines elevates this event's significance.

**PowerShell EID=4104 — cmd invocation of credential tool:** The script block logging captures the PowerShell wrapper that launched cmd.exe with LaZagne. The path to LaZagne appears in the 4104 event when the test framework builds the command string.
