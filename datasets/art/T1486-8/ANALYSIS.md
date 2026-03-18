# T1486-8: Data Encrypted for Impact — Data Encrypted with GPG4Win

## Technique Context

T1486 (Data Encrypted for Impact) includes the use of legitimate encryption utilities to make data inaccessible. GPG (GNU Privacy Guard) is a well-known, widely deployed tool that threat actors increasingly repurpose for encryption in lieu of custom ransomware binaries — it produces standard-format encrypted output, resists AV detection, and requires only a passphrase or public key. GPG-based encryption has appeared in targeted attacks against enterprise environments where attackers use `gpg --batch --yes -c` (symmetric passphrase encryption) to encrypt files before exfiltrating or destroying the originals. Defenders focus on detecting `gpg.exe` invoked non-interactively with `--batch` and `--passphrase` arguments.

## What This Dataset Contains

The test creates a test file then encrypts it using GPG4Win. Security EID 4688 captures three key process creations:

1. PowerShell creating `test.txt` in `%temp%`:
   ```
   "powershell.exe" & {Set-Content -Path "$env:temp\test.txt" -Value "populating this file with some text"
   ```
2. cmd.exe wrapping the GPG invocation:
   ```
   "C:\Windows\system32\cmd.exe" /c ""C:\Program Files (x86)\GnuPG\bin\gpg.exe"
     --passphrase 'SomeParaphraseBlah' --batch --yes -c "C:\Windows\TEMP\test.txt""
   ```

Sysmon EID 1 captures the cmd.exe process creation (tagged `technique_id=T1059.003`). Sysmon EID 11 records `test.txt` being created in `C:\Windows\Temp\`. The PowerShell pre-requisite step also appears as a Sysmon EID 1 (tagged `technique_id=T1059.001,technique_name=PowerShell`) because a new powershell.exe child process was spawned.

All three cmd.exe invocations exit with code `0x1`. This means gpg.exe either was not installed at the expected path (`C:\Program Files (x86)\GnuPG\bin\gpg.exe`) or encountered a non-zero error. GPG4Win must be pre-installed as a prerequisite; if it was absent, the test would still generate the process creation events but produce no encrypted output file.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

`gpg.exe` does not appear in Sysmon EID 1 — it is not matched by sysmon-modular include-mode rules. Security EID 4688 also does not show a gpg.exe child process creation, which means either gpg.exe failed to launch (path not found) or its creation was not captured because the cmd.exe exit code `0x1` indicates the subprocess failed before creating a process entry visible to audit policy. There is no Sysmon EID 11 for the encrypted output file (`.gpg` extension), no hash of the gpg binary, and no network activity. The passphrase `SomeParaphraseBlah` is visible in the command line — a real-world attacker might pass it via environment variable or stdin to avoid command-line exposure.

## Assessment

This dataset's highest value is the EID 4688 event containing the full GPG command line with `--batch --passphrase --yes -c` flags and the passphrase in plaintext. This is exactly the invocation pattern to detect. The failure to capture gpg.exe as a child process is a limitation, but the cmd.exe wrapper with the complete argument string is sufficient for a strong detection rule. The dataset would be meaningfully improved by confirming GPG4Win was installed so that the encrypted output file creation (Sysmon EID 11, `.gpg` extension) could also be captured.

## Detection Opportunities Present in This Data

1. **Security EID 4688**: `cmd.exe` with command line containing `gpg.exe` + `--batch` + `--passphrase` — direct detection of non-interactive GPG encryption.
2. **Security EID 4688**: `gpg.exe --passphrase` with a value directly on the command line — passphrase exposure as an IOC for automated encryption.
3. **Security EID 4688**: `gpg.exe --yes -c` (symmetric cipher mode) invoked from cmd.exe spawned by powershell.exe — behavioral chain detection.
4. **Sysmon EID 1**: `cmd.exe` spawned from `powershell.exe` containing `GnuPG` or `gpg.exe` in the command line.
5. **Sysmon EID 11**: File creation of `*.gpg` files in batch — multiple `.gpg` files created in a short window indicates a file encryption sweep.
6. **Security EID 4688**: PowerShell creating a file in `%temp%` immediately followed by an encryption invocation — two-step staging-then-encrypt pattern.
