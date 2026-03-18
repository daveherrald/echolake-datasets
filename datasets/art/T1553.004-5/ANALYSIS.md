# T1553.004-5: Install Root Certificate — Install Root CA on Windows

## Technique Context

T1553.004 (Subvert Trust Controls: Install Root Certificate) covers adversary installation of
rogue root CA certificates into the Windows certificate trust store. A certificate installed in
the Trusted Root Certification Authorities store causes Windows to treat any certificate signed by
that CA as trusted — enabling HTTPS interception, code signing bypass, and EAP/802.1x network
authentication attacks. This technique is used by nation-state actors, commercial surveillance
software, and network inspection appliances alike. Test 5 uses the PowerShell `Import-Certificate`
cmdlet to install a certificate from a local file.

## What This Dataset Contains

The dataset captures a failed root CA installation due to a missing prerequisite file, with
complete telemetry of the attempt.

**PowerShell EID 4104 records the full attack script:**

```
$cert = Import-Certificate -FilePath rootCA.cer -CertStoreLocation Cert:\LocalMachine\My
Move-Item -Path $cert.PSPath -Destination "Cert:\LocalMachine\Root"
```

The intent is to import a certificate into the `My` store first, then move it to the `Root`
(Trusted Root CAs) store — a two-step approach to bypass UAC-adjacent prompts that appear when
writing directly to the Root store from some contexts.

**PowerShell EID 4100 (Error) records the failure explicitly:**

```
Error Message = The certificate file could not be found.
Fully Qualified Error ID = System.IO.FileNotFoundException,Microsoft.CertificateServices.Commands.ImportCertificateCommand
```

The file `rootCA.cer` does not exist in the working directory (`C:\Windows\TEMP\`), so the
operation terminates immediately.

**Sysmon EID 1 (Process Create)** records the PowerShell invocation with the full command line,
tagged `technique_id=T1059.001`. The ART test framework `whoami.exe` pre-check is also present.

**Security EID 4688/4689** provide independent process creation and termination records for the
PowerShell session.

The dataset spans 26 Sysmon events, 11 Security events, and 45 PowerShell events over 5 seconds.
The presence of EID 4100 (PowerShell error) is significant — this event is only generated when
errors occur, making it a useful signal for failed attack attempts.

## What This Dataset Does Not Contain (and Why)

**No certificate store modifications.** Because the source file `rootCA.cer` does not exist,
`Import-Certificate` throws immediately. There are no Sysmon EID 13 registry write events for
`HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\`, confirming the installation
did not proceed.

**No Sysmon EID 11 (File Create).** No certificate material was written to disk.

**No successful Move-Item execution.** The script terminates at the first cmdlet failure; the
`Move-Item` step to the `Root` store is never reached.

**No logon events.** Unlike tests that trigger service logons, this test ran within an existing
SYSTEM session.

Boilerplate PowerShell EID 4104 script blocks (internal error-handling closures from session
startup) make up the majority of the 45 PowerShell events. The EID 4100 error message and
the two substantive EID 4104 blocks containing the actual script are the relevant events.

## Assessment

This dataset represents a blocked attack where the blocking mechanism is a missing prerequisite
rather than a security control. The telemetry is valuable precisely because it shows what a
failed certificate installation attempt looks like: PowerShell EID 4100 errors correlated with
the absence of expected EID 13 registry writes provides a pattern for distinguishing partial
execution from successful installation. For detection purposes, the intent is fully captured even
though the operation failed.

## Detection Opportunities Present in This Data

- **EID 4104 script block**: `Import-Certificate` with a destination of `Cert:\LocalMachine\My`
  followed by `Move-Item` targeting `Cert:\LocalMachine\Root` is a recognizable pattern for
  root CA installation. Either cmdlet used against the Root store path warrants review.
- **EID 4100 correlation**: A PowerShell EID 4100 error referencing `ImportCertificateCommand`
  alongside a matching EID 4104 block provides a signal for failed attempts that can be used to
  identify attackers missing prerequisite files but having positioned themselves for re-execution.
- **EID 4688 command line**: The `Import-Certificate` cmdlet and `Cert:\LocalMachine\Root`
  destination are fully visible in the process command line without requiring script block logging.
- **Absence pattern**: A detection rule looking for `Import-Certificate` or `Move-Item`
  targeting `Cert:\LocalMachine\Root` in any PowerShell event (4104, 4103, or 4688) covers both
  successful and failed attempts.
- **SYSTEM context**: `Import-Certificate` operations targeting `LocalMachine` certificate stores
  from a SYSTEM-owned PowerShell session warrant investigation in most environments.
