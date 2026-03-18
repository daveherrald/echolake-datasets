# T1105-20: Ingress Tool Transfer — Download a File with Microsoft Connection Manager Auto-Download

## Technique Context

T1105 (Ingress Tool Transfer) covers adversary techniques for pulling tools and payloads into a compromised environment. This test targets Microsoft Connection Manager Auto-Download — a feature of the Microsoft Connection Manager (CMSTP/CMAK) infrastructure designed to automatically download and execute content from a specified URL when a Connection Manager profile is activated.

CMSTP.exe has a well-documented history as a LOLBin: it can execute arbitrary JScript or VBScript from remote UNC paths or URLs embedded in `.inf` Connection Manager profile files, bypass User Account Control (UAC) in certain configurations, and download files via its Auto-Download mechanism. The Auto-Download feature specifically allows `.cmp` profile files to specify a URL from which additional components are fetched and optionally executed on connection.

The `T1105.bat` batch file in this test configures and invokes the Connection Manager Auto-Download mechanism to demonstrate file retrieval via this alternative download vector. On a workstation where PowerShell download methods are monitored or restricted, CMSTP-based Auto-Download provides an alternative that may bypass those controls.

## What This Dataset Contains

The dataset spans approximately twenty seconds (2026-03-14T23:44:36Z–23:45:02Z) on ACME-WS06.acme.local and contains 110 events across three channels.

**The core execution** is captured in Security EID 4688 (cmd.exe spawned by PowerShell):

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1105\src\T1105.bat" 1>NUL
```

The `1>NUL` stdout redirect suppresses console output — a common technique to keep execution quiet. The actual mechanism (Connection Manager profile configuration, URL specification, and download invocation) is contained within `T1105.bat` itself, which runs as a subprocess of this `cmd.exe`. The batch file's content is not captured in the dataset's event channels.

**Security EID 4688** (3 events):
- `whoami.exe` — initial test framework environment check under SYSTEM
- `cmd.exe` with the `T1105.bat 1>NUL` command
- `whoami.exe` — post-test framework check

**Sysmon EID 1** (3 events) confirms the process chain. The Sysmon ProcessCreate for `cmd.exe` flags rule `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Sysmon EID 3** (1 event, network connection): This is the single most significant event in the dataset. A network connection from `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` (Windows Defender's antimalware engine) to `172.178.160.26:443` (TCP, outbound) is captured at 2026-03-14T23:45:01.619Z, approximately 25 seconds after the batch file executed. Sysmon tags this with rule `technique_id=T1036,technique_name=Masquerading` — a rule that fires when a well-known process image connects to unexpected destinations. The source IP is `192.168.4.16` (the ACME-WS06 workstation address), source port 52290, destination port 443.

This Sysmon EID 3 event is the clearest observable consequence of the T1105.bat execution. The Connection Manager Auto-Download mechanism appears to have triggered `MsMpEng.exe` to make an outbound HTTPS connection — possibly because the batch configures a Connection Manager profile that references a URL Defender then fetches as part of its own scan/inspection process, or because the download mechanism routes through the Defender platform. Regardless of the precise mechanism, the network connection to 172.178.160.26 is the forensic record that something was downloaded or attempted.

**Sysmon EID 7** (6 events): DLL loads for the PowerShell process.

**Sysmon EID 10** (3 events): PowerShell accessing child processes with 0x1FFFFF.

**Sysmon EID 17** (1 event): PowerShell named pipe creation.

**PowerShell EID 4104** (93 events): script block fragments for the ART test framework — module import, cleanup invocation, and runtime closures. No script block content reveals the details of `T1105.bat`'s implementation; that information lives in the batch file, not in PowerShell telemetry.

## What This Dataset Does Not Contain

The contents of `C:\AtomicRedTeam\atomics\T1105\src\T1105.bat` are not captured in any event. The batch file's Connection Manager profile configuration, the target URL, and the specific download mechanism are opaque from the Windows event telemetry perspective. File read operations are not captured by Sysmon EID 1.

No `cmstp.exe` process creation event appears in either Security or Sysmon channels. If the batch file invokes `cmstp.exe` to apply a Connection Manager profile, that process execution is not in the Sysmon EID 1 sample set.

No file creation event (Sysmon EID 11) confirms whether the download actually wrote a file to disk. The EID 3 network connection suggests an attempt was made, but the result (success/failure, destination path) is not captured.

No DNS resolution events appear for the IP address 172.178.160.26 — the connection goes directly to IP, which may indicate a hardcoded destination in the Connection Manager profile.

## Assessment

With Defender disabled, the batch file executed without blocking, and the Sysmon EID 3 network connection from `MsMpEng.exe` to 172.178.160.26:443 is the primary forensic artifact showing that the download mechanism triggered outbound network activity. The test ran successfully (both `whoami.exe` test framework checks completed, `cmd.exe` exit code was non-fatal).

Compared to the defended variant (26 Sysmon, 10 Security, 34 PowerShell), the undefended dataset is smaller across all channels (14 Sysmon, 3 Security, 93 PowerShell). The PowerShell channel count is significantly higher in the undefended run (93 vs. 34), suggesting fuller script block logging fidelity. The Sysmon EID 3 network connection from MsMpEng.exe to the external IP is present in both the undefended run and would be in the defended run, since MsMpEng itself is not disabled — only Defender's real-time protection and behavioral monitoring are disabled. This network event is therefore a reliable indicator regardless of Defender state.

The Sysmon EID 3 rule tag `T1036 Masquerading` on the MsMpEng.exe network connection deserves attention: the connection is from a legitimate Microsoft binary but to an IP address that is not a Microsoft endpoint — the masquerading rule fires because the process name suggests a security tool but the connection destination is anomalous.

## Detection Opportunities Present in This Data

**`cmd.exe` executing a `.bat` file from `C:\AtomicRedTeam\atomics\T1105\src\` with stdout suppressed**: Security EID 4688 and Sysmon EID 1 capture `cmd.exe /c "...\T1105.bat" 1>NUL`. The `1>NUL` redirect is a stealth indicator — legitimate administrative batch files rarely discard all stdout. Detecting batch file executions with stdout discarded from staging directories is a useful behavioral pattern.

**`MsMpEng.exe` network connection to non-Microsoft IP**: Sysmon EID 3 captures `MsMpEng.exe` connecting to `172.178.160.26:443`. Windows Defender's antimalware engine should only connect to Microsoft-owned infrastructure (update servers, MAPS telemetry endpoints). A connection from `MsMpEng.exe` to a non-Microsoft IP — particularly one not in the Microsoft IP range — is anomalous and worth investigating regardless of whether the test was CMSTP-based or used another mechanism.

**CMSTP.exe process creation (expected, not captured here)**: In a real deployment, `cmstp.exe` executing a Connection Manager profile would appear as a process creation event and is a well-known LOLBin indicator. Any `cmstp.exe` invocation outside of legitimate VPN profile provisioning contexts warrants investigation.

**Batch file execution with `1>NUL` in staging directories**: The pattern `cmd.exe /c "path\*.bat" 1>NUL` from non-standard paths under SYSTEM context is consistent with automated payload delivery — the output suppression specifically evades log-scraping and interactive monitoring.
