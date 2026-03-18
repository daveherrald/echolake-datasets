# T1505.003-1: Server Software Component — Web Shell Written to Disk

## Technique Context

T1505.003 (Web Shell) describes the placement of malicious scripts in web-accessible directories to provide persistent, interactive access to a compromised server via HTTP(S). Web shells are a foundational persistence technique used by threat actors across the entire threat landscape — from commodity attackers through nation-state APT groups. They are installed after initial exploitation of internet-facing web servers (IIS, Apache, Exchange OWA, SharePoint) and allow the attacker to execute commands, upload/download files, and maintain access even after the initial vulnerability is patched. Defenders focus on detecting file creation events in web root directories (`C:\inetpub\wwwroot\`, Exchange OWA paths), unusual file types (`.aspx`, `.php`, `.jsp`) appearing in those locations, and web server processes spawning child shells.

## What This Dataset Contains

The technique is executed by copying web shell source files from the ART atomics directory to IIS's web root. The execution chain is visible in Sysmon Event ID 1 and Security Event ID 4688:

```
powershell.exe
  └─ cmd.exe /c xcopy /I /Y "C:\AtomicRedTeam\atomics\T1505.003\src" C:\inetpub\wwwroot
       └─ xcopy.exe /I /Y "C:\AtomicRedTeam\atomics\T1505.003\src" C:\inetpub\wwwroot
```

Both `cmd.exe` (with the full xcopy command) and `xcopy.exe` are captured as Sysmon Event ID 1 and Security 4688 records. The destination path `C:\inetpub\wwwroot` is explicitly visible in all process creation events across both channels. The parent chain from `powershell.exe` through `cmd.exe` to `xcopy.exe` is fully preserved, including parent command lines. The `xcopy /I /Y` flags indicate overwrite-without-prompt, which is characteristic of scripted file deployment.

The PowerShell channel contains only ART test framework boilerplate. The sysmon-modular include-mode config captures `cmd.exe` (T1059.003 rule match) and `xcopy.exe` as process creations, but does not capture file creation events for the web shell files written to `C:\inetpub\wwwroot\`. The two Sysmon Event ID 11 (FileCreate) entries in the dataset are both `StartupProfileData` files for the PowerShell host — not the web shell payload.

## What This Dataset Does Not Contain

- **No Sysmon Event ID 11 (FileCreate) for the web shell files**: The xcopy operation writing web shell files to `C:\inetpub\wwwroot\` is not captured by Sysmon's file monitoring. The sysmon-modular config does not include IIS web root paths in its FileCreate monitoring rules. This is a meaningful gap: the most direct evidence of web shell placement — the file appearing in the web root — is absent from the Sysmon channel. Security object access auditing (set to `none`) does not fill this gap either.
- **No web shell content visible in telemetry**: The source files at `C:\AtomicRedTeam\atomics\T1505.003\src` are not examined by any captured event. The web shell script content (typically ASPX/PHP code with command execution capability) is not logged.
- **No IIS activity**: The dataset captures the installation of the web shell, not its use. There are no IIS access log entries, no `w3wp.exe` spawning child processes, and no HTTP request events — those would require separate IIS log collection.
- **No Sysmon Event ID 12/13 registry events**: Web shell deployment via xcopy does not involve registry modifications.

## Assessment

This dataset provides reliable process-chain evidence of web shell deployment via `xcopy` to a web root. The command lines in Sysmon and Security channels are specific and actionable: `xcopy` copying from an attacker-controlled source directory to `C:\inetpub\wwwroot` is an unusual operation for SYSTEM-context PowerShell. The critical limitation is the absence of Sysmon FileCreate coverage for the web root. For a complete web shell detection dataset, you would want to augment this with Sysmon rules targeting `.aspx`, `.php`, `.jsp`, and `.asp` file creation events under `C:\inetpub\wwwroot\` and Exchange OWA paths. Without file creation events, detection relies entirely on the xcopy process chain — which adversaries can easily replace with API-based file writes that would not spawn xcopy at all.

## Detection Opportunities Present in This Data

1. **`xcopy.exe` (or any copy utility) with a destination path of `C:\inetpub\wwwroot\` or other web root paths** — Security 4688 and Sysmon Event ID 1 capture the full xcopy command; file copy operations to web-accessible directories by non-web-service processes are high-confidence indicators.
2. **`cmd.exe` spawned by `powershell.exe` (SYSTEM) with `xcopy` targeting `inetpub\wwwroot`** — The parent chain (PowerShell → cmd.exe → xcopy) copying to the web root is the classic scripted web shell deployment pattern.
3. **`xcopy.exe` with `/Y` (overwrite without prompt) and `/I` (destination is a directory) flags copying to web directories** — The flag combination indicates automated, non-interactive file deployment; legitimate web deployments via xcopy in enterprise environments are typically tied to deployment pipeline accounts, not SYSTEM-context PowerShell.
4. **`powershell.exe` as the ultimate ancestor of any process writing to IIS web root paths** — Even if xcopy is replaced with other copy mechanisms, PowerShell as the root ancestor of a process tree that results in web root modification is a detection pattern applicable across xcopy, robocopy, and other file transfer utilities.
5. **File creation events (if Sysmon FileCreate is extended to cover web root paths) for `.aspx`, `.php`, or `.asp` files in `C:\inetpub\wwwroot\`** — Adding Sysmon Event ID 11 coverage for web root directories would capture the actual web shell artifact; the process chain evidence in this dataset supports the detection but does not replace this file-level indicator.
