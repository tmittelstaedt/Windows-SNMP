\# Invoke-SnmpV3Get.ps1



A standalone, zero-dependency \*\*SNMPv3 GET\*\* client written in pure PowerShell. It implements native ASN.1 BER packet encoding/decoding, RFC 3414 / RFC 7860 User-based Security Model (USM) key localization and HMAC signing (`MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`), and RFC 3826 privacy encryption (`AES-128-CFB128` and `DES-CBC`) using built-in .NET cryptography and UDP sockets.



\---



\## Why Use Pure PowerShell Instead of Windows Net-SNMP Binaries?



\* \*\*No External Binaries or Code-Signing Hurdles:\*\* Compiling Net-SNMP for Windows or deploying third-party executables into locked-down enterprise environments requires code-signing certificates to pass Application Control, AppLocker, or Defender policies. Furthermore, most pre-compiled free Net-SNMP binaries available online are years out of date.

\* \*\*Out-of-the-Box SHA-2 Support (`SHA2-256` / `SHA2-384` / `SHA2-512`):\*\* When Net-SNMP is compiled on Windows using its default internal cryptography (without linking external OpenSSL libraries), it omits SHA-2 authentication algorithms such as `SHA2-512`. Because `Invoke-SnmpV3Get.ps1` relies directly on the Windows .NET cryptographic provider, full SHA-2 and AES-128 work natively on Windows Server 2019+ and Windows 10/11.

\* \*\*Native PowerShell Objects \& USM Error Translation:\*\* Automatically handles SNMPv3 `EngineID`, `EngineBoots`, and `EngineTime` discovery, decodes USM `Report` PDUs into human-readable warnings (such as wrong digest or unknown username), and returns structured PowerShell objects.



\---



\## Hardware Verification \& Test Notes



This script has been tested and verified against a \*\*Canon imageCLASS MF450 Series\*\* multifunction printer using the default SNMPv3 username (`username`) across multiple security configurations:



\* \*\*Authentication Algorithms Tested:\*\* Both `SHA1` and `SHA2-512`.

\* \*\*Security Levels Tested:\*\* Both `authNoPriv` (Authentication On / Encryption Off via `-NoPriv`) and full `authPriv` (Authentication On / AES-128 Encryption On).

\* \*\*Device Behavior:\*\* On current Canon MF450 firmware, an initial power-cycle is required when first enabling SNMPv3, after which subsequent changes to authentication algorithms, encryption toggles, or passwords take effect immediately without requiring additional reboots.

\* \*\*UDP 161 USM vs. TCP 10161 TLS:\*\* Although Canon's web interface requires HTTPS/TLS to be active on its Remote UI portal before enabling SNMPv3, the printer's SNMPv3 agent communicates using standard SNMPv3 USM encryption over \*\*UDP port 161\*\* (not RFC 6353 SNMP-over-TLS on TCP port `10161`). Leave `-UseTls` omitted for Canon and standard network printers.



\---



\## Parameters



| Parameter | Type | Required | Default | Description |

| :--- | :--- | :---: | :--- | :--- |

| `-TargetIP` | `\[string]` | Yes | — | IPv4 address or hostname of the target SNMPv3 agent. |

| `-OID` | `\[string]` | Yes | — | Numeric OID to retrieve (e.g., `1.3.6.1.2.1.1.5.0` for `sysName.0`). |

| `-DefaultUsername` | `\[string]` | No | `"username"` | Default SNMPv3 USM username used directly in `noAuthNoPriv` mode or pre-filled in the credential prompt. |

| `-NonDefaultAuth` | `\[switch]` | No | `$false` | Opens the standard Windows credential prompt (`Get-Credential`) to supply the SNMPv3 username and password securely in memory without exposing credentials on the command line or disk. |

| `-AuthProtocol` | `\[string]` | No | `"SHA512"` | USM HMAC authentication algorithm: `"MD5"`, `"SHA1"`, `"SHA256"`, `"SHA384"`, or `"SHA512"`. |

| `-PrivProtocol` | `\[string]` | No | `"AES"` | USM privacy encryption algorithm when using `authPriv`: `"AES"` (AES-128-CFB128) or `"DES"` (DES-CBC). |

| `-NoPriv` | `\[switch]` | No | `$false` | Uses `authNoPriv` (authentication without payload encryption) when `-NonDefaultAuth` is specified. |

| `-UseTls` | `\[switch]` | No | `$false` | Wraps SNMPv3 packets in TLS over TCP (RFC 6353, default port `10161`), accepting self-signed certificates. |

| `-Port` | `\[int]` | No | `161` / `10161` | Target port (defaults to `161` for UDP or `10161` when `-UseTls` is set). |

| `-TimeoutMs` | `\[int]` | No | `3000` | Socket send/receive timeout in milliseconds. |



\---



\## Command-Line Usage Examples



\### Load the Function Into Your Current Session

```powershell

. C:\\scripts\\Invoke-SnmpV3Get.ps1

```



\### 1. Query Using Default Username (`noAuthNoPriv`, No Password)

```powershell

Invoke-SnmpV3Get -TargetIP "192.168.1.20" -OID "1.3.6.1.2.1.1.5.0"

```



\### 2. Query With Full Encryption (`authPriv`: `SHA2-512` + `AES-128`)

Prompts via the Windows credential dialog for the SNMPv3 username and password in memory:

```powershell

Invoke-SnmpV3Get -TargetIP "192.168.1.20" -OID "1.3.6.1.2.1.1.5.0" -NonDefaultAuth -AuthProtocol SHA512

```



\### 3. Query With Authentication Only (`authNoPriv`: `SHA1`, Encryption Off)

```powershell

Invoke-SnmpV3Get -TargetIP "192.168.1.20" -OID "1.3.6.1.2.1.1.5.0" -NonDefaultAuth -NoPriv -AuthProtocol SHA1

```



\### Sample Output

```text

OID               EngineID                         Type Value

\---               --------                         ---- -----

1.3.6.1.2.1.1.5.0 80-00-06-42-05-00-00-00-00-00-00 0x04 MF450 Series

```



\---



\## Re-Sourcing \& Memory State Note



When testing or modifying `Invoke-SnmpV3Get.ps1` repeatedly in an interactive PowerShell console, always re-dot-source the script (`. C:\\scripts\\Invoke-SnmpV3Get.ps1`) to reload the updated function definition and ensure any transient in-memory credential variables from prior runs are cleared.



