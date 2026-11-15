\# Invoke-SnmpV3Walk.ps1



A standalone, zero-dependency \*\*SNMPv3 MIB Subtree Walker\*\* written in pure PowerShell. It discovers the target agent's `EngineID`, `EngineBoots`, and `EngineTime` once up front, derives localized RFC 3414 / RFC 7860 keys (`MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`), and walks an entire OID subtree via iterative `GetNextRequest` PDUs with optional RFC 3826 payload encryption (`AES-128-CFB128` or `DES-CBC`) and automatic UDP retry recovery.



\---



\## Key Features \& Advantages Over Windows Net-SNMP Binaries



\* \*\*No External Executables or Code-Signing Hurdles:\*\* Avoids deploying outdated third-party Windows Net-SNMP builds or obtaining code-signing certificates for custom-compiled binaries in environments guarded by AppLocker or Windows Defender Application Control.

\* \*\*Native SHA-2 Support (`SHA2-256` / `SHA2-384` / `SHA2-512`):\*\* Default Windows Net-SNMP builds compiled without external OpenSSL libraries omit SHA-2 authentication protocols. `Invoke-SnmpV3Walk.ps1` leverages the built-in .NET cryptographic provider so full `SHA2-512` + `AES-128` encryption works natively on Windows Server 2019+ and Windows 10/11.

\* \*\*Automatic Clock Synchronization \& UDP Retry Resilience:\*\* Synchronizes `EngineBoots` and `EngineTime` from every agent response to prevent AES-CFB IV drift during long walks, and includes a 3-attempt UDP retry loop to recover seamlessly from momentary packet drops on embedded printer NICs.

\* \*\*Smart Value Decoding:\*\* Automatically formats dotted `OBJECT IDENTIFIER` (`0x06`) values, IPv4 addresses (`0x40`), `TimeTicks` (`0x43`), printable ASCII strings, and binary `OCTET STRING` blobs (rendered as clean hex when non-ASCII bytes are detected).



\---



\## Hardware Verification \& Test Notes



Verified end-to-end against a \*\*Canon imageCLASS MF450 Series\*\* multifunction printer using the default SNMPv3 username (`username`) across full private enterprise MIB walks (`1.3.6.1.4.1.1602`) and standard MIB-2 trees (`1.3.6.1.2.1.1`):



\* \*\*Algorithms \& Modes Verified:\*\* Tested with both `SHA1` and `SHA2-512` authentication, with encryption both enabled (`authPriv` AES-128) and disabled (`authNoPriv` via `-NoPriv`).

\* \*\*Firmware Behavior:\*\* On current Canon MF450 firmware, an initial power-cycle is required when first enabling SNMPv3, after which subsequent changes to authentication algorithms, encryption settings, or passwords take effect immediately without additional reboots.

\* \*\*UDP 161 USM vs. TCP 10161 TLS:\*\* Although Canon's web portal requires HTTPS/TLS on its Remote UI before enabling SNMPv3, the printer's SNMPv3 agent uses standard USM encryption over \*\*UDP port 161\*\* (not RFC 6353 SNMP-over-TLS on TCP port `10161`). Omit `-UseTls` for standard network printers.



\---



\## Parameters



| Parameter | Type | Required | Default | Description |

| :--- | :--- | :---: | :--- | :--- |

| `-TargetIP` | `\[string]` | Yes | — | IPv4 address or hostname of the target SNMPv3 agent. |

| `-RootOID` | `\[string]` | Yes | — | Starting root OID of the subtree to walk (e.g., `1.3.6.1.2.1.1` or `1.3.6.1.2.1.43`). |

| `-DefaultUsername` | `\[string]` | No | `"username"` | Default USM username used directly in `noAuthNoPriv` mode or pre-filled in the credential prompt. |

| `-NonDefaultAuth` | `\[switch]` | No | `$false` | Opens the native Windows credential prompt (`Get-Credential`) to supply the username and password in memory without exposing credentials on the command line or disk. |

| `-AuthProtocol` | `\[string]` | No | `"SHA512"` | USM HMAC authentication algorithm: `"MD5"`, `"SHA1"`, `"SHA256"`, `"SHA384"`, or `"SHA512"`. |

| `-PrivProtocol` | `\[string]` | No | `"AES"` | USM privacy encryption algorithm when using `authPriv`: `"AES"` (AES-128-CFB128) or `"DES"` (DES-CBC). |

| `-NoPriv` | `\[switch]` | No | `$false` | Uses `authNoPriv` (authentication without payload encryption) when `-NonDefaultAuth` is specified. |

| `-UseTls` | `\[switch]` | No | `$false` | Wraps SNMPv3 packets in TLS over TCP (RFC 6353, default port `10161`), accepting self-signed certificates. |

| `-Port` | `\[int]` | No | `161` / `10161` | Target port (defaults to `161` for UDP or `10161` when `-UseTls` is set). |

| `-TimeoutMs` | `\[int]` | No | `3000` | Socket send/receive timeout in milliseconds per attempt (up to 3 UDP attempts per OID). |

| `-MaxResults` | `\[int]` | No | `10000` | Safety ceiling on the maximum number of OIDs walked per invocation. |



\---



\## Command-Line Usage Examples



\### Load the Function Into Your Current Session

```powershell

. C:\\scripts\\Invoke-SnmpV3Walk.ps1

```



\### 1. Walk the Standard System MIB With Full Encryption (`SHA2-512` + `AES-128`)

```powershell

Invoke-SnmpV3Walk -TargetIP "192.168.1.20" -RootOID "1.3.6.1.2.1.1" -NonDefaultAuth -AuthProtocol SHA512

```



\### 2. Walk Using Authentication Only (`authNoPriv`: `SHA1`, Encryption Off)

```powershell

Invoke-SnmpV3Walk -TargetIP "192.168.1.20" -RootOID "1.3.6.1.2.1.43" -NonDefaultAuth -NoPriv -AuthProtocol SHA1

```



\### 3. Walk Using Default Username (`noAuthNoPriv`, No Password)

```powershell

Invoke-SnmpV3Walk -TargetIP "192.168.1.20" -RootOID "1.3.6.1.2.1.1"

```



\### Sample Output

```text

OID               Type Value

\---               ---- -----

1.3.6.1.2.1.1.1.0 0x04 Canon MF450 Series /P

1.3.6.1.2.1.1.2.0 0x06 1.3.6.1.4.1.1602.4.7

1.3.6.1.2.1.1.3.0 0x43 01:59:08.3600000

1.3.6.1.2.1.1.4.0 0x04 Administrator

1.3.6.1.2.1.1.5.0 0x04 MF450 Series

1.3.6.1.2.1.1.6.0 0x04

1.3.6.1.2.1.1.7.0 0x02 72

```



\---



\## Re-Sourcing \& Memory State Note



When modifying or testing `Invoke-SnmpV3Walk.ps1` repeatedly in an interactive PowerShell session, always re-dot-source the script (`. C:\\scripts\\Invoke-SnmpV3Walk.ps1`) to load the updated function definition and ensure any transient in-memory credential variables from prior runs are cleared.



