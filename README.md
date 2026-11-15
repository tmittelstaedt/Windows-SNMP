# Windows-SNMP
SNMP Get and SNMP Walk implemented in Powershell

Microsoft does not supply any programs with Windows to make SNMP Queries so a common way of making these queries from Windows is to install the Net-SNMP tools.  However, these are non-trivial to install because the Net-SNMP project does not maintain binaries of these tools for Windows.  They are buildable with cygwin and Mingw32 for Windows but will cause Windows Defender to flag them and block execution using Smart App Control, and Device Guard / Memory Integrity which was considerably tightened up in the November 2026 Update to Windows 11, if they are not signed.  While it is possible to get free code signing certificates from the SignPath foundation for Open Source projects, these certificates expire after 15 months so the binary must be timestamped.  But that opens another can of worms because if not enough people install the binary over the lifetime of the certificate used to timestamp it, it will not build up a positive reputation and will end up being flagged.  This is quite likely to happen for Windows builds of the latest versions of Net-SNMP since it's not a commonly used program.

The solution I used here is to avoid the issue by recreating versions of the SNMP tools in Powershell.  All of these scripts were written using AI, they are all intended to be run from Windows Powershell command windows.  They can be used as standalone diagnostic tools or they can be used, along with public or private MIB files, to seed an AI, to then create specialty SNMP scripts for specific queries, or they can be refactored as Powershell cmdlets and used by other Powershell scripts.  No support for SNMP MIB files is included with the command line scripts.  There are 3 scripts:

Test-Basic-Get.ps1

This PowerShell script uses the legacy olePrn.OleSNMP COM object to query standard SNMP v1 OIDs such as sysName and sysDescr.  Microsoft maintains this COM object in Windows since it is used by the Standard TCP/IP port monitor in the Windows Printing subsystem.  It does not support SNMP v2 queries (and never will)  While as of 2026 it is still safe to use this COM object for SNMP v1 queries, some of the underlying SNMP api's that this object uses are themselves deprecated, and Microsoft is attempting (without much success) to get printing users to switch over to the IPP Port Monitor protocol.

Invoke-SnmpV2Get.ps1 / Invoke-SnmpV2Walk.ps1

These powershell scripts implement the basic SNMP Get and SNMP Walk commands for both SNMP v1 and SNMP v2 queries. (see the documentation for how to select version 1 or version 2 queries)  These are the workhorse scripts, they use no COM objects, and instead use the native .NET Sockets and construct the query packets themselves.

Invoke-SnmpV3Get.ps1 / Invoke-SnmpV3Walk.ps1

These powershell scripts implement the basic SNMP Get and SNMP Walk commands for SNMP v3 queries.  They implement native ASN.1 BER packet encoding/decoding, RFC 3414 / RFC 7860 User-based Security Model (USM) key localization and HMAC signing (MD5, SHA1, SHA256, SHA384, SHA512), and RFC 3826 privacy encryption (AES-128-CFB128 and DES-CBC) using built-in .NET cryptography and UDP sockets APIs.  These also construct the UDP query packets.  The SNMP Walk command is able to walk extremely large private MIB trees by using multiple UDP packets.  They DO NOT require 3rd party programs such as OpenSSL.

Please see the HTML documentation for these commands for details
