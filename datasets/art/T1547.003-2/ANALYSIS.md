# T1547.003-2: Time Providers — Edit an Existing Time Provider

## Technique Context

T1547.003 (Time Providers) — this test variant modifies an *existing* W32Time time provider (NtpServer) rather than creating a new one. By overwriting the `DllName` value of the built-in `NtpServer` provider, an attacker hijacks a legitimately-present time provider with a malicious DLL. This is stealthier than creating a new provider key (test -1) because the NtpServer key pre-exists in a normal Windows configuration; only the DLL path is changed. The technique still requires administrator privileges but leaves a smaller structural footprint in the registry.

## What This Dataset Contains

The dataset captures an 8-second window on ACME-WS02 with telemetry across four log sources.

**PowerShell 4104 script block logging** captures the full test payload:

```powershell
net stop w32time
Copy-Item "C:\AtomicRedTeam\atomics\T1547.003\bin\AtomicTest.dll" C:\Users\Public\AtomicTest.dll
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" /t REG_SZ /v "DllName" /d "C:\Users\Public\AtomicTest.dll" /f
reg add "...\NtpServer" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "...\NtpServer" /v "InputProvider" /t REG_DWORD /d 1 /f
net start w32time
```

The target key is `NtpServer` rather than a new `AtomicTest` key, which is the defining difference from test -1.

**Sysmon Event 13 (RegistrySetValue)** events confirm the three registry writes:

- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer\DllName` → `C:\Users\Public\AtomicTest.dll`
- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer\Enabled` → `DWORD (0x00000001)`
- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer\InputProvider` → `DWORD (0x00000001)`

As with test -1, none of the Sysmon 13 events carry a named T1547.003 rule — they fire on the default catch-all (RuleName: `-`). The svchost-sourced write to `NtpClient\SpecialPollTimeRemaining` reappears as a legitimate W32Time reaction.

**Sysmon Event 29 (FileExecutableDetected):** `C:\Users\Public\AtomicTest.dll` again detected as a PE in a world-writable location, tagged T1059.001.

**Sysmon Event 1 (ProcessCreate):** Same pattern as test -1 — `whoami.exe`, `net.exe`/`net1.exe`, `powershell.exe`, three `reg.exe` invocations.

**Sysmon Event 22 (DNSQuery):** `svchost.exe` querying `ACME-DC01.acme.local` post-service restart.

**System log events (4 events):** Events 37 (NTP data received), 132 (duplicate NTP peer error — domain DC and manual IP both point to same host), 135 (duplicate manual peer error), and 37 again — identical to test -1's side-effects from the service restart/reconfiguration.

The Security log in this test does not contain a 4616 (System Time Changed) event — unlike test -1, the time did not change measurably during the restart, or the delta was below the logging threshold. This is a minor difference in side-effect telemetry between the two tests.

## What This Dataset Does Not Contain

- **No structural registry difference from baseline.** Because `NtpServer` already exists, a detection that only looks for *new* time provider keys would miss this technique entirely. Only a DllName value comparison to known-good paths would detect it.
- **No Security 4616 time change event.** Unlike test -1, the service restart here did not produce a measurable time adjustment.
- **No DLL load into W32Time.** The stub DLL was placed and the service restarted, but no successful execution telemetry exists.
- **No T1547.003-specific Sysmon rule match.** Registry writes captured only by the catch-all rule.

## Assessment

This dataset is structurally very similar to T1547.003-1 but highlights the detection challenge specific to modifying existing providers: the `NtpServer` key is a legitimate, pre-existing registry path. Defenders who only alert on the *creation* of new time provider keys would receive no alert on this technique. The actionable detection must focus on the `DllName` value changing to a non-system-path location.

The absence of Security 4616 (compared to test -1) is a meaningful difference, demonstrating that not all W32Time restarts produce identical side-effect telemetry. The System log events 132/135 (duplicate peer errors) appear in both tests as consistent, reliable side effects of the service restart on a domain member.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Modification of `DllName` under any `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\*` key to a path outside `C:\Windows\System32\` is high-confidence. Specifically, writing to an existing key's `DllName` (not just creating a new subkey) requires detecting value changes on pre-existing keys.
- **Sysmon Event 29:** DLL written to `C:\Users\Public\` — same detection as test -1.
- **Sysmon Event 1 process chain:** `net stop w32time` → `reg.exe` modifying W32Time keys → `net start w32time` is the same sequence as test -1 and equally detectable.
- **PowerShell 4104:** Script blocks with `W32Time\TimeProviders\NtpServer` and `DllName` together with a non-standard path are suspicious.
- **Comparing test -1 and -2:** A detection that checks whether the `DllName` value of any time provider diverges from the expected Microsoft-signed DLL will catch both variants. Allowlisting `w32tm.dll` and `vmictimeprovider.dll` as the only legitimate values is a practical approach.
