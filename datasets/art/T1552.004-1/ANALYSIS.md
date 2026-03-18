# T1552.004-1: Private Keys — Private Keys

## Technique Context

MITRE ATT&CK T1552.004 (Private Keys) covers adversary searches for private key files that can be used for authentication or decryption. Private key files (`.key`, `.pem`, `.pfx`, `.p12`, `.cer`, `.crt`) may be present on developer and administrator workstations due to SSH key pairs, TLS certificates, code signing certificates, or PKI operations. Test 1 performs a broad filesystem sweep using `dir` and `findstr` to enumerate all files with a `.key` extension on the `C:\` drive. This is a simple reconnaissance step that an adversary would perform early in a credential access phase to understand what cryptographic material is available on the host.

## What This Dataset Contains

The dataset spans approximately twenty-seven seconds (00:29:27–00:29:54 UTC) and contains 86 events across three log sources.

**The core filesystem search is captured.** The Sysmon ProcessCreate chain (EID 1) shows:

- `whoami.exe` (tagged T1033)
- `cmd.exe` with `CommandLine: "cmd.exe" /c dir c:\ /b /s .key | findstr /e .key` (tagged T1083, File and Directory Discovery)
- `cmd.exe` (internal) with `CommandLine: C:\Windows\system32\cmd.exe  /S /D /c" dir c:\ /b /s .key "` — the shell expansion of the piped command
- `findstr.exe` with `CommandLine: findstr  /e .key` — the pipe consumer filtering results to `.key` extension

Security EID 4688 independently confirms all process launches with full command-line detail. EID 4689 records `cmd.exe` exit.

The PowerShell log contains the ART test framework boilerplate. The `Set-ExecutionPolicy Bypass` EID 4103 and the script block EID 4104 fragments are present.

The twenty-seven second window reflects the time required to recursively enumerate the entire `C:\` drive looking for `.key` files — a genuine indication that the search traversed a substantial directory tree.

## What This Dataset Does Not Contain (and Why)

**No key file content or filenames found.** The search output goes to stdout. Object access auditing is not configured, so individual file access events are not recorded. Whether any `.key` files exist on this system and what was found are not captured.

**No exfiltration or key loading.** This dataset covers only the discovery phase. The adversary has not accessed any specific key file in a recoverable way.

**No SSH or TLS context.** The technique is purely filesystem enumeration; no cryptographic operations occur.

**Sysmon ProcessCreate for `cmd.exe` captured here.** The sysmon-modular T1083 (File and Directory Discovery) rule catches `cmd.exe` when it contains `dir` with filesystem parameters, which is why `cmd.exe` appears in EID 1 events — not the case in all configurations.

**Limited Sysmon coverage of the `findstr` child process.** `findstr.exe` appears in EID 1 (tagged T1083) because the include-mode rule covers it. The recursive nature of the `dir /s` command means many directory entries are evaluated but none generate individual Sysmon events.

## Assessment

This is a straightforward private key discovery dataset. The `dir c:\ /b /s .key | findstr /e .key` pattern is a simple, dependency-free search that any attacker could execute without specialized tooling. The twenty-seven second execution time is notable — it demonstrates that even a simple recursive `dir` on a VM with limited files takes a non-trivial amount of time, which has implications for behavioral detection (process duration anomalies). The process chain is cleanly captured across both Sysmon and Security logs. The dataset is appropriate for validating detections for filesystem-based private key enumeration.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `dir c:\ /b /s` combined with `.key` (or `.pem`, `.pfx`, `.p12`) in the command line is a strong indicator of private key enumeration. The `/s` (recursive) and `/b` (bare format) flags together indicate automated enumeration rather than interactive browsing.
- **Sysmon EID 1 (T1083 tag)**: File and Directory Discovery tag provides enriched classification.
- **`findstr /e .key`**: `findstr` filtering for file extensions is an extension of the discovery technique — the combination of `dir /b /s` piped to `findstr` targeting certificate/key extensions is a specific behavioral pattern.
- **Process duration**: `cmd.exe` running for ~26 seconds with a recursive `dir` command is anomalous for legitimate use cases and could be a behavioral threshold trigger.
- **Process tree anomaly**: `cmd.exe` → `findstr.exe` pipe spawned from `powershell.exe` running as SYSTEM in a non-interactive session.
- **Extension coverage**: Extend detection to other private key extensions beyond `.key`: `.pem`, `.pfx`, `.p12`, `.cer`, `.crt`, `.ppk` (PuTTY private key format).
