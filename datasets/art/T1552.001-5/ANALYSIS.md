# T1552.001-5: Credentials In Files — Access unattend.xml

## Technique Context

MITRE ATT&CK T1552.001 (Credentials in Files) includes accessing Windows deployment answer files, which commonly contain plaintext administrator passwords. The `unattend.xml` (and its counterpart `Unattend\unattend.xml`) is created by Windows Setup or deployment tools (MDT, SCCM, WDS) and often persists long after installation in `C:\Windows\Panther\`. It may contain the `<AutoLogon>` password, local administrator credentials, or domain join account passwords in cleartext or base64. Test 5 reads both standard locations using `type`, a simple built-in command that produces no file-access audit events and requires no special privileges.

## What This Dataset Contains

The dataset spans approximately five seconds (00:25:32–00:25:37 UTC) and contains 70 events across three log sources.

**The core technique command is captured in full.** The Sysmon ProcessCreate chain (EID 1) shows:

- `whoami.exe` (test framework pre-check, tagged T1033)
- `cmd.exe` with `CommandLine: "cmd.exe" /c type C:\Windows\Panther\unattend.xml & type C:\Windows\Panther\Unattend\unattend.xml` (tagged T1059.003)

Security EID 4688 independently confirms both the `whoami.exe` and `cmd.exe` process launches with full command-line detail. The `cmd.exe` process completes and exits with status 0x0 (EID 4689), confirming both `type` commands ran without error.

The PowerShell log (EID 4104) records the ART test framework script block and the standard boilerplate `Set-ExecutionPolicy Bypass` (EID 4103). The test framework invokes the test as an inline command block, so the full `cmd.exe /c type ...` command appears in the PowerShell host application field of subsequent module log entries.

The Sysmon log shows the standard PowerShell DLL image load sequence (EID 7, tagged T1055/T1059.001/T1574.002), a named pipe creation (EID 17), and a process access event (EID 10). No ProcessCreate entry for `cmd.exe` appears in Sysmon because `cmd.exe` is not in the sysmon-modular include-mode LOLBin list for ProcessCreate — it is captured only via Security EID 4688.

## What This Dataset Does Not Contain (and Why)

**No file content.** The `type` command outputs to stdout. No object access auditing is configured, so there is no record of whether the files existed or what they contained. A system that had never been deployed via an answer file would simply produce a "file not found" error — this dataset does not distinguish between those outcomes.

**No Sysmon ProcessCreate for cmd.exe.** The sysmon-modular include-mode configuration captures `cmd.exe` only under specific patterns. The Security log's EID 4688 provides the command line that Sysmon does not here.

**No indication of whether credentials were found.** Exit status 0x0 on `cmd.exe` means both `type` commands ran but does not confirm the files existed or contained credentials. Exit code behavior for `type` on missing files is not captured.

**No registry or network activity.** The technique involves only file reads and does not touch the registry or network.

## Assessment

This is a compact, high-fidelity dataset for a fast-executing technique. The five-second window captures the entire lifecycle. The critical detection signal — the `type C:\Windows\Panther\unattend.xml` command — is present in both the Security EID 4688 command-line field and in the PowerShell host application field within the module log context. The Sysmon log by itself does not show `cmd.exe` spawning due to include-mode filtering, illustrating why Security EID 4688 with command-line logging is a necessary complement to Sysmon in this environment. The event count is small (70 total), making this a clean, low-complexity dataset for detection development.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` launched with a command line referencing `C:\Windows\Panther\unattend.xml`. This path is a near-universal indicator — legitimate access outside of deployment tooling is extremely rare.
- **Security EID 4688**: Use of `type` (or `Get-Content`) targeting `C:\Windows\Panther\Unattend\` is a strong signal regardless of the specific file.
- **PowerShell EID 4103 / 4104**: The host application field in module log entries embeds the full command string, providing a secondary capture of the `type` command.
- **Sysmon EID 17**: Named pipe creation from a PowerShell process spawned as NT AUTHORITY\SYSTEM with no interactive session is consistent with automated test framework execution and can serve as a correlation anchor.
- **Path-based alerting**: Any process reading `C:\Windows\Panther\unattend.xml`, `C:\Windows\Panther\Unattend\unattend.xml`, or `C:\Windows\system32\sysprep\unattend.xml` warrants investigation. These paths are commonly checked by post-exploitation frameworks.
