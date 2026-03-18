# T1110.003-6: Password Spraying — Password Spray Invoke-DomainPasswordSpray Light

## Technique Context

Password spraying (T1110.003) against Active Directory accounts typically relies on external tooling downloaded at runtime or pre-staged binaries. Test 6 in the T1110.003 series takes a simpler approach: it embeds a lightweight password spray function — `Invoke-dpsLight` — directly in the PowerShell command line rather than downloading a full framework. This "light" implementation is a self-contained LDAP authentication loop that reads a user list from disk, constructs an LDAP distinguished name from the current domain, and iterates through each user attempting to bind with the supplied password (`Spring2020`).

The technique is more primitive than DomainPasswordSpray or WinPwn, but it has a lower detection surface: there is no external download, no tool binary, no GitHub URL, and no recognized tool name. The entire attack logic is inlined in the command line passed to powershell.exe via Security EID 4688 — making the process creation event the single most important telemetry source for this test.

Notably, this test is bounded by the prerequisite of a user list file on disk (`$userlist`). Because the test ran in a clean environment without that pre-staged file, the loop would have immediately failed with a file-not-found error. The dataset therefore shows the launch and initialization telemetry rather than actual authentication attempts.

In the defended variant, Defender blocked execution before initialization. This dataset captures the full initialization sequence.

## What This Dataset Contains

This dataset captures 156 events across four channels (2 Application, 109 PowerShell, 4 Security, 41 Sysmon) collected over a 4-second window (2026-03-14T23:48:20Z–23:48:24Z) on ACME-WS06 with Defender disabled.

**Application Channel (EID 15):**
Two EID 15 events record `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — test framework artifacts from the test framework toggling Defender state before and after this test.

**Process Creation Chain (Security EID 4688 and Sysmon EID 1):**

The full `Invoke-dpsLight` function definition is captured in the Security EID 4688 command line for the child PowerShell process (PID 23588, based on the 4688 record):

```
"powershell.exe" & {function Invoke-dpsLight ($Password, $userlist) {
$users = Get-Content $userlist
$Domain = "LDAP://" + ([ADSI]"").distinguishedName
foreach ($User in $users) {
  $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain, $User, $Password)
  if ($Domain_check.name -ne $null) {
    Write-Host -ForegroundColor Green "Password found for User:$User Password:$Password"
  }
  else { Write-Host ". " -NoNewline}
```

This is the complete attack implementation — the LDAP bind using `System.DirectoryServices.DirectoryEntry` with the target username and password is the authentication attempt that would generate DC-side events if it reached the domain controller.

Sysmon EID 1 also captures this child PowerShell process (PID 6456) with the command line, hash data (SHA256: `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80`), and parent process GUID linking back to the test framework parent.

A Sysmon EID 1 for `whoami.exe` (PID 2120) running under the same parent confirms the pre-test system identity check.

**PowerShell Script Block Logging (EID 4104):**

107 EID 4104 events are present, dominated by the same PowerShell runtime boilerplate fragments (`Set-StrictMode`, `PSMessageDetails`) seen throughout this test series. The `Invoke-dpsLight` function body and its invocation are compiled and logged through the 4104 mechanism.

**Sysmon File Creates (EID 11):**

Two EID 11 events show files created by `MsMpEng.exe` in `C:\Windows\Temp\`: `01dcb40d092b7288`. These are Defender temporary files from the test framework Defender toggle, not attack artifacts.

**Sysmon Image Loads (EID 7):**

25 EID 7 events for the .NET runtime DLL sequence loaded by the attack PowerShell process (PID 6696), consistent with the pattern across all PowerShell-based tests.

## What This Dataset Does Not Contain

- **Authentication attempts on the domain controller:** `Invoke-dpsLight` requires a valid user list file. Because the file was not present, the `Get-Content` call at line 2 of the function would have raised a terminating error, and no LDAP authentication binds would have been issued. The DC-side evidence (EID 4625, 4771, 4768) is therefore absent from both this dataset and the DC's logs.
- **LDAP connection events:** For the same reason — execution failed at file read — no `System.DirectoryServices.DirectoryEntry` objects were instantiated and no network connections to the DC were established.
- **Registry modifications or persistence artifacts:** This test is purely credential access; no persistence mechanisms are exercised.
- **The full Invoke-dpsLight source in the 4104 samples:** The 20 sample events shown are the boilerplate fragments. The function definition itself appears in 4104 but is not represented in the provided samples.

## Assessment

This dataset represents a minimal-footprint password spray attempt: no external download, no pre-staged binary, no recognized tool name. The entire attack is inlined in a single PowerShell command line. This pattern is harder to detect with tool-name or URL matching and requires defenders to either recognize the `System.DirectoryServices.DirectoryEntry` authentication pattern in script block logging or identify the embedded function structure in the process creation command line.

Compared to the defended variant (85 events: 48 PowerShell, 10 Security, 27 Sysmon), the undefended version (156 events) contains more events primarily because the execution was not interrupted early. The additional Sysmon events (41 vs. 27) reflect the fuller process tree captured here.

The failure to actually spray — due to the missing user list — means this dataset shows the launch and initialization telemetry for a living-off-the-land spray approach without the DC-side authentication noise. This makes it useful specifically for training on workstation-side detection, where the command line and script block content are the primary evidence.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — Inline LDAP Authentication Function:**
The process creation command line contains the complete `Invoke-dpsLight` function definition including the `System.DirectoryServices.DirectoryEntry` constructor call with username and password parameters. This pattern — instantiating a `DirectoryEntry` object with explicit credentials in a loop — is not a pattern seen in normal PowerShell administration and provides a high-fidelity behavioral indicator.

**EID 4104 — Script Block Content with DirectoryServices:**
The function definition is compiled and logged via script block logging. Searching EID 4104 content for `System.DirectoryServices.DirectoryEntry` combined with loop structures (`foreach`) and credential parameters provides durable coverage even if the command line is obfuscated.

**EID 4688 — Unusually Long PowerShell Command Line:**
The embedded function definition makes this command line substantially longer than typical administrative PowerShell. Command line length alone is not a detection, but it can serve as a triage signal to prioritize inspection of EID 4688 records from PowerShell.

**Sysmon EID 1 — PowerShell Hash Correlation:**
The SHA256 hash `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80` identifies the specific PowerShell binary. Combined with IMPHASH `E09C4F82A1DA13A09F4FF2E625FEBA20`, this provides a stable process identity baseline for the Windows 11 22H2 environment.
