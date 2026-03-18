# T1555.003-1: Credentials from Web Browsers — Run Chrome-password Collector

## Technique Context

T1555.003 covers credential theft specifically from web browsers. Browsers like Chrome, Edge (Chromium), and Firefox store passwords in local SQLite databases, encrypted with DPAPI (Data Protection API) under the user's profile. An attacker with access to the victim's user context (or SYSTEM context with the ability to impersonate) can read the encrypted database and decrypt credentials using the DPAPI master key. Chrome specifically stores its login data at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`. Tools targeting Chrome passwords typically need to copy the SQLite database (since Chrome locks it while running) and decrypt entries using `CryptUnprotectData`. This is a high-value credential source because users frequently save credentials to many web services in their browser.

## What This Dataset Contains

The dataset spans approximately 7 seconds (2026-03-14T14:03:15Z – 14:03:22Z) on ACME-WS02.

**The attack command visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals\accesschk.exe" -ArgumentList "-accepteula ."}`

This is a prerequisite step from the ART test definition — running `accesschk.exe` (a Sysinternals tool) with `-accepteula` to accept the EULA silently before the main Chrome credential collector runs. The test failed at this prerequisite step.

**PowerShell EID 4100 records the failure:**

> `Error Message = This command cannot be run due to the error: The system cannot find the file specified.`
> `Fully Qualified Error ID = InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand`

The `accesschk.exe` binary does not exist at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals\accesschk.exe`. The ART test's prerequisite step failed because the ExternalPayloads directory was not populated with the Sysinternals tools. The main credential-collecting payload never ran.

Sysmon events include:
- EID 1: `whoami.exe` (tagged T1033) and a PowerShell child process (tagged T1083)
- EID 10: PowerShell accessing the `whoami.exe` process (tagged T1055.001)
- EID 11: PowerShell profile data file creation (`StartupProfileData-Interactive`)
- EID 13: Registry value sets for `rdyboost` service parameters — background Windows service activity unrelated to the test

The dataset timestamp (14:03:15Z) is approximately 14 hours after the other tests in this group, consistent with this test being run in a separate execution session.

## What This Dataset Does Not Contain (and Why)

**Chrome credential access or any browser password extraction.** The test failed at the prerequisite step (missing `accesschk.exe`). No Chrome-related processes, no access to the `Login Data` SQLite file, no DPAPI calls, and no `CryptUnprotectData` invocations appear anywhere in the dataset.

**The actual Chrome password collector binary or script.** The ART test for T1555.003-1 deploys a dedicated credential-collecting executable. It was never staged because the prerequisite check failed first.

**A Defender block.** The failure mechanism is a missing file (`FileNotFoundException`), not an AV/AMSI detection. Defender was not involved in stopping this test.

**Sysmon EID 22 DNS events or network activity.** The test made no network connections; the prerequisite failure terminated execution before any payload download or Chrome data exfiltration.

## Assessment

This dataset captures a **failed test due to a missing prerequisite binary**, not a security control. The `accesschk.exe` binary from Sysinternals was not present in the ART ExternalPayloads directory. The telemetry is minimal: a PowerShell process, a `whoami.exe` call, a `Start-Process` invocation for a nonexistent path, and the resulting `InvalidOperationException`. The dataset value is primarily in illustrating what incomplete ART test execution looks like — an analyst encountering this data in isolation might see the `Start-Process` command and the missing file error and recognize a failed tool staging attempt. The `accesschk.exe -accepteula .` pattern, while innocuous in isolation, is a known ART/testing framework prerequisite pattern that can indicate an automated attack framework is running even when the main payload fails.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `powershell.exe` with `Start-Process "C:\AtomicRedTeam\..."` in the command line. The `C:\AtomicRedTeam\` path is a direct indicator of the ART framework being present and active on the workstation.
- **PowerShell EID 4104**: Scriptblock captures the `Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Sysinternals\accesschk.exe" -ArgumentList "-accepteula ."` invocation. The `ExternalPayloads\Sysinternals\accesschk.exe` path and `-accepteula` flag are recognizable testing framework artifacts.
- **PowerShell EID 4100**: `InvalidOperationException,StartProcessCommand` — a failed `Start-Process` call for a missing executable within the ART directory tree. While not a direct credential theft indicator, it signals failed tool deployment.
- **Sysmon EID 10**: PowerShell accessing `whoami.exe` via `OpenProcess` (tagged T1055.001) — the standard ART pre-execution pattern present across all tests in this collection.
- **File system indicator**: The presence of `C:\AtomicRedTeam\` on a production workstation is itself a high-fidelity indicator of an active red team or attack framework regardless of whether individual tests succeed.
