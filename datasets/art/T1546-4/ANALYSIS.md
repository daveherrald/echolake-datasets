# T1546-4: Event Triggered Execution — WMI Invoke-CimMethod Start Process

## Technique Context

T1546 via WMI covers the use of Windows Management Instrumentation to spawn processes, often as a lateral movement precursor or remote execution method. `Invoke-CimMethod` on the `Win32_Process` class with the `Create` method launches a process on a local or remote host through the WMI infrastructure, with the spawned process appearing as a child of `WmiPrvSE.exe` rather than of the calling process. This parent-process masquerading is a key evasion benefit: processes started via WMI lack a direct parent-child relationship to the originating attacker shell. Defenders watch for `WmiPrvSE.exe` spawning unexpected processes, NTLM authentication failures preceding WMI execution, and explicit credential usage from PowerShell to localhost.

## What This Dataset Contains

The test attempts to create a CIM session to `localhost` using hardcoded credentials (`Administrator` / `P@ssword1`) and spawn `calc.exe` via `Win32_Process.Create`. The credentials are wrong on this host, so the process creation fails, but the authentication attempt and the WMI infrastructure activity are fully captured.

**Sysmon EID=1 (ProcessCreate):** The complete attack script is embedded in the child PowerShell command line, including:
- `$RemoteComputer = "localhost"`, `$PWord = ConvertTo-SecureString -String "P@ssword1"`, `New-Object PSCredential "Administrator"`
- `New-CimSession -ComputerName $RemoteComputer -Credential $Credential`
- `Invoke-CimMethod ... -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "calc.exe"}`

**Security 4648 (Explicit Credential Logon):** PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) attempted logon to `ACME-WS02.acme.local` using the `Administrator` account with explicit credentials. Two 4648 events are present (one per authentication attempt).

**Security 4625 (Logon Failure):** Two Type 3 (Network) logon failures for `Administrator` from `::1` (IPv6 loopback), Logon Process `NtLmSsp`, status `0xC000006D / 0xC000006A` (wrong password). Source ports 49851 and 49856 match the Sysmon EID=3 network connections.

**Sysmon EID=3 (NetworkConnect):** Two TCP connections from `::1` to `::1` on WMI-related ports, tagged `technique_id=T1021,technique_name=Remote Services`. Both show `Process ID: 4` on the receiving side (kernel-level), consistent with WMI service port handling.

**Sysmon EID=1 — `WmiPrvSE.exe`:** Later in the dataset (timestamp ~23:36:56), a `WmiPrvSE.exe` process is spawned with `-Embedding`, running as `NT AUTHORITY\NETWORK SERVICE` — evidence of the WMI infrastructure responding to the CIM session request.

## What This Dataset Does Not Contain

- No successful process creation via WMI — `calc.exe` was never spawned because authentication failed. There is no `WmiPrvSE.exe` → `calc.exe` process chain.
- No WMI operational log events (Microsoft-Windows-WMI-Activity/Operational) — this channel is not in the collection scope.
- No Security 4688 for `calc.exe` or any process created via `Win32_Process.Create`.
- The hardcoded credential `P@ssword1` is visible in plain text in the Sysmon EID=1 CommandLine field — note that this is sensitive data in the dataset.

## Assessment

This dataset is valuable primarily for two detection patterns: PowerShell with hardcoded credentials targeting WMI-based process creation, and the authentication failure sequence that results when attacker tools use wrong credentials. The combination of Security 4648 (explicit credential use) + Security 4625 (Type 3 failure from loopback) + Sysmon EID=1 (PowerShell with `Invoke-CimMethod Win32_Process Create`) is a strong multi-source correlation. The absence of a successful process creation limits its use for detecting the execution phase of WMI lateral movement. For a more complete dataset, run the test with valid credentials so that the `WmiPrvSE.exe` → `calc.exe` process lineage appears.

## Detection Opportunities Present in This Data

1. **Sysmon EID=1 — PowerShell command line containing `Invoke-CimMethod` with `Win32_Process` and `Create`**: The explicit WMI process creation method with a class name in the command line is a high-fidelity pattern.
2. **Security 4648 + 4625 pair from PowerShell process**: A `4648` (explicit credential logon attempt from powershell.exe) immediately followed by `4625` (Type 3 NTLM failure from loopback) is a characteristic pattern of automated credential stuffing against local WMI.
3. **Sysmon EID=3 — loopback TCP connection tagged `T1021:Remote Services`**: Outbound connections from a non-service process to `::1` on WMI ports (135, 49xxx dynamic) correlate with the CIM session establishment attempt.
4. **PowerShell command line containing `ConvertTo-SecureString -AsPlainText` with `New-Object PSCredential`**: The pattern of constructing credentials from a plaintext string in a script is a common attacker pattern for credential embedding.
5. **Sysmon EID=1 — `WmiPrvSE.exe` with `-Embedding` argument spawned during the activity window**: The WMI provider host activation within the same timeframe as the CIM session attempt confirms WMI infrastructure engagement.
6. **Correlation: Explicit credential use (4648) → Network logon failure (4625) → WmiPrvSE activity within 2 seconds**: This sequence in close temporal proximity is a reliable indicator of a WMI-based attack attempt regardless of success.
