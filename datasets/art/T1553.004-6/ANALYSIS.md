# T1553.004-6: Install Root Certificate — Install Root CA on Windows with certutil

## Technique Context

T1553.004 (Subvert Trust Controls: Install Root Certificate) covers installation of rogue CA
certificates into the Windows trust store. Test 6 uses `certutil.exe -addstore` to add a
certificate to a certificate store. `certutil.exe` is a built-in Windows LOLBin (living-off-the-land
binary) with extensive certificate management capabilities. Adversaries prefer it over PowerShell
cmdlets because it requires no module imports, is present on all Windows versions, and its
certificate manipulation capabilities may be less monitored than PowerShell. The `-addstore`
flag with the `root` store name would install a root CA; this test uses `my` (the personal store),
representing the preparation step before promotion.

## What This Dataset Contains

The dataset captures a `certutil.exe` invocation to add a certificate to the personal (`my`)
certificate store, executed via PowerShell as SYSTEM.

**Sysmon EID 1 (Process Create) records the PowerShell invocation** (tagged `T1059.001`):

```
"powershell.exe" & {certutil -addstore my $env:Temp\rootCA2.cer}
```

**Sysmon EID 1 also records the certutil.exe execution** (tagged `T1202,technique_name=Indirect Command Execution`):

```
"C:\Windows\system32\certutil.exe" -addstore my C:\Windows\TEMP\rootCA2.cer
```

The `T1202` (Indirect Command Execution) rule tag reflects Sysmon-modular's classification of
`certutil.exe` as a LOLBin capable of indirect execution.

**Sysmon EID 10 (Process Access)** shows PowerShell accessing `certutil.exe` with
`GrantedAccess: 0x1FFFFF` before it spawns — consistent with the .NET `Process.Start()` method
used by the ART test framework to launch child processes.

**PowerShell EID 4104** records both the test framework wrapper and the inner script block:

```
& {certutil -addstore my $env:Temp\rootCA2.cer}
```

**Security EID 4688** confirms the `certutil.exe` process creation with full command line
arguments, providing a detection path independent of Sysmon.

The dataset spans 48 Sysmon events, 12 Security events, and 37 PowerShell events over 6 seconds.
The relatively high Sysmon count (48 events with 35 being EID 7 image loads) reflects two
separate PowerShell session startups loading .NET and Defender AMSI DLLs.

## What This Dataset Does Not Contain (and Why)

**No registry modification events (Sysmon EID 13).** The `certutil -addstore my` command
adds the certificate to the personal store (`HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates\My\`
or `HKLM\SOFTWARE\Microsoft\SystemCertificates\My\`), but no EID 13 events appear. This may
indicate the certificate file `rootCA2.cer` was not present in `C:\Windows\TEMP\`, causing
certutil to fail without writing to the registry — similar to the failed import in test 5.

**No certutil output.** Process output is not captured in Windows event logs. Whether certutil
reported success or a file-not-found error is not determinable from this dataset.

**No DLL loads for certutil.exe itself.** Sysmon EID 7 events are for PowerShell processes, not
`certutil.exe`. The Sysmon ImageLoad configuration does not appear to be filtering on certutil.

**No root store modification.** The test targets the `my` store, not `root`. A root CA
installation attack would use `certutil -addstore root <cert>`, which is not what is captured here.

The large majority of PowerShell EID 4104 events are boilerplate internal script blocks.

## Assessment

This dataset captures a `certutil -addstore` invocation with full command-line visibility across
both Sysmon and the Security log. The `T1202` (Indirect Command Execution) rule tag on certutil
reflects its standing as a monitored LOLBin in the Sysmon-modular configuration. The dataset
is most useful as a reference for the specific command-line patterns produced when PowerShell
uses certutil as a subprocess for certificate operations, particularly when combined with the
registry write events that would appear on successful execution.

## Detection Opportunities Present in This Data

- **EID 4688 / Sysmon EID 1 command line**: `certutil.exe -addstore` is directly observable.
  The combination of `certutil`, `-addstore`, and `root` (or `my`) in any process creation event
  is a high-fidelity indicator. In production, legitimate `certutil -addstore root` usage is
  extremely rare outside of PKI administration.
- **Sysmon EID 1 T1202 tag**: `certutil.exe` spawned by `powershell.exe` as SYSTEM from
  `C:\Windows\TEMP\` matches the Indirect Command Execution profile.
- **Process chain**: `powershell.exe` → `certutil.exe` (via `.NET Process.Start()`, visible in
  EID 10) for certificate management is anomalous outside administrative contexts.
- **Broader certutil monitoring**: Any `certutil -addstore root`, `certutil -urlcache`, or
  `certutil -decode` invocation from non-administrative tools warrants review given certutil's
  extensive history of abuse as a download and encoding utility.
