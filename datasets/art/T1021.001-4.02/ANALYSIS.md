# T1021.001-4: Remote Desktop Protocol — Disable NLA for RDP via Command Prompt

## Technique Context

T1021.001 covers abuse of Remote Desktop Protocol for lateral movement. One common preparatory step is disabling Network Level Authentication (NLA), a security feature that requires a user to authenticate before the full RDP session is established. With NLA disabled, any user can initiate an RDP connection and see the login screen without pre-authenticating, enabling pass-the-hash attacks, brute-force attempts, and unauthenticated probing of RDP.

The registry value controlling NLA is `UserAuthentication` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`. Setting it to `0` disables NLA; `1` enables it. This change requires SYSTEM or Administrator privileges and takes effect immediately for new connections. Attackers typically make this change as part of enabling persistent RDP access after gaining elevated privileges, allowing them to return even if their initial access vector is closed.

Detection engineers monitor for registry modifications to the Terminal Server key path, particularly for `UserAuthentication` being set to `0`. The `reg.exe` command-line pattern is a reliable detection target since legitimate NLA management is typically done through Group Policy or Remote Desktop settings UI, not direct `reg add` commands. This technique also appeared in the defended dataset with identical command lines and similar event counts — NLA modification via `reg.exe` does not trigger Windows Defender.

## What This Dataset Contains

The dataset spans roughly 15 seconds (23:03:14–23:03:29 UTC on 2026-03-14) and contains 124 events across two channels.

The complete process chain is documented in Sysmon EID 1 and Security EID 4688. PowerShell (PID 1016) spawns `cmd.exe` (PID from Security: cmd.exe process) with the command line `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`. That cmd.exe spawns `reg.exe` with `reg  add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`.

The cleanup phase reverses the change: a second cmd.exe is spawned with `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 1 /t REG_DWORD -f >nul 2>&1`, and a second `reg.exe` sets `UserAuthentication` back to `1`. The `>nul 2>&1` redirect in the cleanup command is an interesting artifact — the technique command uses `/f` while cleanup uses `-f` (Unix-style flag), a minor inconsistency in the ART test definition.

EID 4103 module logging confirms execution completed: `CommandInvocation(Write-Host): "Write-Host"` with `value="DONE"` is present in the PowerShell channel, indicating the full test cycle ran to completion without interruption.

Sysmon EID 11 captures PowerShell writing its interactive startup profile to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`, a routine event for new PowerShell sessions running as SYSTEM.

The defended dataset had 36 Sysmon events and 12 Security events. This undefended run has 14 Sysmon events and 6 Security events — fewer events, not more, because the background OS servicing activity that inflated the defended dataset's counts happened to fall in a different timing window here.

## What This Dataset Does Not Contain

The most significant gap is the absence of registry modification events. Security EID 4657 (a registry value was modified) is not generated because registry auditing via the Global Object Access Auditing policy is not configured in this environment. Sysmon EID 13 (registry value set) is also absent for the specific `UserAuthentication` key — the Sysmon configuration does not have a registry monitoring rule covering this path. This means the actual registry change itself is only inferable from the `reg.exe` command-line arguments, not directly observable as a registry event. There are no Windows Firewall or RDP-specific events, and no subsequent RDP connection events since this test only changes the configuration without actually connecting.

## Assessment

This is a clean and complete process creation dataset for the NLA disable/re-enable pattern. Both the disable command (`/d 0`) and the cleanup restore command (`/d 1`) are present with full command lines across Sysmon EID 1 and Security EID 4688. The PowerShell EID 4103 completion confirmation and Sysmon named pipe creation event round out the execution context. The absence of registry events means this dataset is not useful for building registry-based detections, but it is well-suited for developing process creation analytics that catch the `reg.exe` invocation pattern against the RDP-Tcp key.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — reg.exe command line with UserAuthentication path**: The full registry path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` with `/v UserAuthentication` and `/d 0` is present in the `reg.exe` command line. This is a precise, high-fidelity detection opportunity.

2. **Sysmon EID 1 / EID 4688 — cmd.exe spawning reg.exe for RDP keys**: The process chain powershell.exe → cmd.exe → reg.exe where the cmd.exe argument contains `Terminal Server` is detectable without requiring full command line access to the reg.exe arguments, which may be truncated in some SIEM configurations.

3. **Sysmon EID 1 — reg.exe modifying HKLM system control paths as SYSTEM**: `reg.exe` modifying `HKLM\SYSTEM\CurrentControlSet\Control` paths when spawned by PowerShell rather than by a user-interactive session or a system management process is an anomaly worth alerting on broadly.

4. **EID 4103 — Write-Host "DONE" following reg.exe activity**: The `Write-Host "DONE"` module logging event appearing immediately after `reg.exe` process creation activity is an ART test framework artifact that, while not directly useful for production detections, confirms successful execution and is useful for validating detection coverage against this specific test.

5. **Sysmon EID 1 — cmd.exe from TEMP with registry modification**: Both cmd.exe invocations have `CurrentDirectory: C:\Windows\TEMP\`, consistent with automated tool execution rather than interactive administrative work. Filtering reg.exe invocations launched from TEMP-like directories would reduce false positives from IT management scripts.
