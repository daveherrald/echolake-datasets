# T1550.002-1: Pass the Hash — Mimikatz Pass the Hash

## Technique Context

Pass the Hash (T1550.002) enables an attacker to authenticate to remote Windows services using a captured NTLM hash without ever knowing the plaintext password. Mimikatz implements this via `sekurlsa::pth`, which manipulates the Windows authentication provider to construct a logon session token containing the attacker-supplied hash. Processes launched within that forged session can then authenticate to NTLM-reliant remote services as the hash owner. This technique remains effective against all Windows versions where NTLM authentication is available — which includes virtually every domain environment — and against local accounts on workstations even in hardened configurations.

In the defended variant of this test, Windows Defender blocked the Mimikatz binary before it could execute, producing a `STATUS_ACCESS_DENIED` (0xC0000022) exit code from the `cmd.exe` launcher. No `sekurlsa::pth` activity occurred; the only artifacts were the process creation log and the blocked execution.

In this undefended run, Defender was disabled. The Mimikatz binary was free to execute, and `sekurlsa::pth` ran to completion, producing a process running under the forged NTLM token.

## What This Dataset Contains

The dataset spans approximately three seconds of telemetry (2026-03-17T17:17:55Z–17:17:58Z) across four log sources, with 133 total events.

**Security EID 4688 — four process creates recorded:**
The full attack chain is visible:

1. `whoami.exe` (PID 0x3f68) — ART pre-check, parent `powershell.exe` (PID 0x1074)
2. `cmd.exe` (PID 0x4428) launching Mimikatz:
   ```
   "cmd.exe" /c %tmp%\mimikatz\x64\mimikatz.exe "sekurlsa::pth /user:Administrator /domain:%userdnsdomain% /ntlm:cc36cf7a8514893efccd3324464tkg1a"
   ```
3. `whoami.exe` (PID 0x439c) — the ART post-execution check
4. `cmd.exe` (PID 0x43e0) — cleanup invocation with empty command (`"cmd.exe" /c`)

The full Mimikatz command line in event 2 is the most significant artifact: it documents the target user (`Administrator`), the domain specification (`%userdnsdomain%` — which resolves to `acme.local` at runtime), and the NTLM hash value (`cc36cf7a8514893efccd3324464tkg1a`). In the defended run, this same command line was recorded but the binary was killed before it ran. Here, it ran.

**Sysmon EID breakdown — 18 events: 9 EID 7, 3 EID 1, 3 EID 10, 1 EID 17, 1 EID 8, 1 EID 11:**
The most significant undefended-specific artifact is **Sysmon EID 8 (CreateRemoteThread)**:
```
Source: powershell.exe (PID 4212)
Target: <unknown process> (PID 17448)
StartAddress: 0x00007FF7818C0570
StartModule: -
StartFunction: -
```
This event captures Mimikatz's `sekurlsa::pth` core mechanism: it creates a remote thread in a new process to set up the forged authentication context. The target process is listed as `<unknown process>` because the process was created and manipulated by Mimikatz faster than Sysmon could register its identity — a characteristic artifact of this technique. The thread start address (`0x00007FF7818C0570`) is within the Mimikatz PE's memory space.

The EID 11 (File Create) event reflects a temporary file written during the operation, consistent with Mimikatz's working directory usage.

No EID 7 events for `mimikatz.exe` itself appear — Sysmon's image load monitoring captures DLL loads into process space, and Mimikatz ran and exited within the capture window without its own DLL loads being recorded before the process terminated.

**PowerShell — 110 events: 104 EID 4104, 4 EID 4103, 2 EID 4100:**
The two EID 4100 error events are notable. In the defended run, only one appeared (the Mimikatz AMSI block). Here, two appear — one is an expected test framework error, and the second captures a runtime error from the Mimikatz invocation context. The EID 4103 module log records `Write-Host "DONE"` — this is the test framework success marker, confirming that `sekurlsa::pth` returned output that the script treated as successful completion rather than a blocked execution. In the defended run, the 4103 log did not record a `Write-Host "DONE"` because the process was killed before reaching that point.

**Application — 1 EID 15 event:**
Single Defender state-machine event, not technique-related.

## What This Dataset Does Not Contain

The dataset does not contain a Sysmon EID 4624 (Logon) event reflecting the creation of the forged token session — logon events for PtH tokens created in-memory by `sekurlsa::pth` do not always generate 4624 events since the token is manipulated internally rather than through the standard Kerberos/NTLM negotiation path. This is consistent with real-world PtH forensics: the absence of a corresponding logon event is expected.

There are no network connection events (Sysmon EID 3) in this dataset. The test invokes `sekurlsa::pth` to create a forged-token process but does not specify a network target in the ART invocation — the forged process is created locally but not directed to authenticate remotely within the capture window.

Mimikatz console output (which would show the created PID and token session details) is not captured in any log source — this output goes to stdout, which is not logged by any of the instrumented channels. You can infer the outcome from the EID 8 CreateRemoteThread event and the `Write-Host "DONE"` marker, but the explicit Mimikatz output is absent from the telemetry.

## Assessment

This is the dataset that defines the difference between a defended and undefended PtH attempt. The defended version shows only the command line in EID 4688 and a kill event. This version adds the Sysmon EID 8 CreateRemoteThread event that is Mimikatz `sekurlsa::pth`'s signature — a thread creation into an unknown target process from a parent process that just invoked a credential manipulation binary. The combination of Security EID 4688 with the full Mimikatz command line, Sysmon EID 8 with an unknown target process, and the `Write-Host "DONE"` success marker in the module log creates a complete forensic picture of a successful Pass-the-Hash token forge. This dataset is directly applicable to validating detection logic for the CreateRemoteThread-based token manipulation that `sekurlsa::pth` uses.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `ProcessCommandLine` containing `sekurlsa::pth` — this is the most specific and highest-confidence indicator, present regardless of whether Defender is enabled or disabled, as the command line is logged before the binary runs.

2. Sysmon EID 8 (CreateRemoteThread) from any process with `TargetImage` showing as `<unknown process>` — this pattern indicates a process was created and manipulated before Sysmon could enumerate it, which is characteristic of Mimikatz token manipulation and process injection techniques.

3. Security EID 4688 showing `cmd.exe /c` launching a binary from `%TEMP%` or `%TMP%` subdirectories — legitimate software rarely executes from temporary directories, and `mimikatz` in the path is an obvious high-confidence match.

4. Sysmon EID 1 with `CommandLine` matching the pattern `sekurlsa::pth /user:` combined with `GrantedAccess: 0x1FFFFF` in a near-simultaneous EID 10 event — the process access chain from PowerShell through cmd.exe to the Mimikatz-spawned target is recoverable from these two event types.

5. PowerShell EID 4103 recording `Write-Host "DONE"` immediately following a `cmd.exe` launch sequence that includes a known attack tool name — this success marker is specific to ART but the pattern of monitoring for execution outcome markers in module logs is generalizable.

6. Absence correlation: A Security EID 4688 for `cmd.exe` launching a known attack binary followed by no `mimikatz.exe` EID 4688 child process creation, combined with a Sysmon EID 8 CreateRemoteThread shortly after — this pattern (binary launch without visible child process, but with thread injection) indicates the binary executed and spawned something via injection rather than normal process creation.
