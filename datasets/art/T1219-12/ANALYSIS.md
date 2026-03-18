# T1219-12: Remote Access Tools — RustDesk Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) involves adversaries using legitimate remote access software to maintain persistence and move laterally through victim networks. While these tools have legitimate administrative uses, they're frequently abused by threat actors because they blend with normal network traffic and often bypass security controls that focus on obviously malicious software. RustDesk is an open-source remote desktop tool similar to TeamViewer or AnyDesk, written in Rust and designed for cross-platform remote access. The detection community focuses on monitoring the installation and execution of such tools in environments where they're not expected, as well as tracking the network connections and file artifacts they create.

## What This Dataset Contains

This dataset captures a PowerShell-based installation of RustDesk 1.2.3-1, executed via Atomic Red Team. The key evidence includes:

**PowerShell Script Execution**: Security event 4688 shows the initial PowerShell command line: `"powershell.exe" & {$file = Join-Path $env:USERPROFILE \"Desktop\rustdesk-1.2.3-1-x86_64.exe\"; Invoke-WebRequest -OutFile $file https://github.com/rustdesk/rustdesk/releases/download/1.2.3-1/rustdesk-1.2.3-1-x86_64.exe; Start-Process -FilePath $file \"/S\""}`. PowerShell events 4103 capture the individual cmdlet invocations for Join-Path, Invoke-WebRequest, and Start-Process.

**File Download**: Sysmon event 11 shows the RustDesk installer being written to `C:\Windows\System32\config\systemprofile\Desktop\rustdesk-1.2.3-1-x86_64.exe`. DNS queries (event 22) show lookups for `github.com` and `release-assets.githubusercontent.com`, with network connections (event 3) to GitHub's infrastructure for the download.

**Installer Execution**: Sysmon event 1 captures the RustDesk installer execution with command line `"C:\Windows\system32\config\systemprofile\Desktop\rustdesk-1.2.3-1-x86_64.exe" /S` (silent installation). The executable is signed by "Zhou Huabing" and has hash SHA256=4996194639C099DB0D854D20832A64E6629FEFA37CE6A01FFD8710AC6C9E2522.

**File Artifacts**: Multiple Sysmon event 11 entries document the installation creating RustDesk components in `C:\Windows\System32\config\systemprofile\AppData\Local\rustdesk\`, including the main executables (`rustdesk.exe`, `RuntimeBroker_rustdesk.exe`) and various DLL plugins (`desktop_drop_plugin.dll`, `flutter_windows.dll`, `librustdesk.dll`, etc.).

## What This Dataset Does Not Contain

The test execution appears to have completed successfully, so there's no evidence of Windows Defender blocking the installation. The dataset doesn't show the RustDesk service actually starting up or establishing remote desktop connections, as this test focuses only on file detection rather than operational use. There are no registry modifications captured, likely because Sysmon's configuration doesn't include registry monitoring. The test also doesn't show any post-installation persistence mechanisms or configuration file creation beyond the basic file extraction.

## Assessment

This dataset provides excellent coverage for detecting RustDesk installation attempts. The combination of PowerShell command-line logging, network telemetry showing the download, and comprehensive file creation events gives defenders multiple detection opportunities. The Security 4688 events with full command-line capture are particularly valuable, as they show the complete attack chain from download to installation. The Sysmon file creation events provide detailed artifact tracking that could support both real-time detection and forensic analysis. This represents a strong example of how properly configured logging can capture the full lifecycle of remote access tool deployment.

## Detection Opportunities Present in This Data

1. **PowerShell Download Commands**: Monitor for `Invoke-WebRequest` cmdlets downloading executables from GitHub releases, especially when combined with `Start-Process` for silent installation (`/S` parameter).

2. **GitHub RAT Downloads**: Alert on downloads from `github.com/rustdesk/rustdesk/releases/` or `release-assets.githubusercontent.com` domains, particularly executable files.

3. **RustDesk File Artifacts**: Monitor for file creation in user AppData directories with RustDesk-specific filenames (`rustdesk.exe`, `librustdesk.dll`, `RuntimeBroker_rustdesk.exe`).

4. **Remote Access Tool Signatures**: Track process creation events for executables signed by "Zhou Huabing" or matching RustDesk file hashes.

5. **Silent Installer Execution**: Detect processes launched with `/S` (silent) parameter from temporary or user profile locations.

6. **Suspicious PowerShell Script Blocks**: Alert on PowerShell script blocks containing remote desktop software download URLs combined with silent execution parameters.

7. **Cross-Process Access**: Monitor for PowerShell processes accessing newly created executable files (Sysmon event 10) as indicators of script-driven software installation.
