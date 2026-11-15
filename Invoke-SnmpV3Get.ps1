<#
.SYNOPSIS
    Pure-PowerShell SNMPv3 GET client supporting USM (noAuthNoPriv, authNoPriv, authPriv AES/DES)
    and optional SNMP-over-TLS (RFC 6353) with self-signed certificate support.
#>

function Invoke-SnmpV3Get {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,

        [Parameter(Mandatory=$true)]
        [string]$OID,

        [string]$DefaultUsername = "username",

        [switch]$NonDefaultAuth,

        [ValidateSet("SHA1","MD5","SHA256","SHA384","SHA512")]
        [string]$AuthProtocol = "SHA512",

        [ValidateSet("AES","DES")]
        [string]$PrivProtocol = "AES",

        [switch]$NoPriv,

        [switch]$UseTls,

        [int]$Port = 0,
        [int]$TimeoutMs = 3000
    )

    if ($Port -eq 0) {
        $Port = if ($UseTls) { 10161 } else { 161 }
    }

    # Resolve credentials
    $UserName = $DefaultUsername
    $PlainPassword = ""
    $SecLevel = 0x04 # Reportable flag (0x04) + noAuthNoPriv (0x00)

    if ($NonDefaultAuth) {
        $Cred = Get-Credential -UserName $DefaultUsername -Message "Enter SNMPv3 Credentials for $TargetIP"
        if (-not $Cred) {
            Write-Warning "SNMPv3 credential prompt cancelled."
            return
        }
        $UserName = $Cred.UserName
        $PlainPassword = $Cred.GetNetworkCredential().Password

        if ([string]::IsNullOrEmpty($PlainPassword)) {
            $SecLevel = 0x04 # noAuthNoPriv + reportable
        }
        elseif ($NoPriv) {
            $SecLevel = 0x05 # authNoPriv (0x01) + reportable (0x04)
        }
        else {
            $SecLevel = 0x07 # authPriv (0x03) + reportable (0x04)
        }
    }

    # --- ASN.1 BER Helpers ---
    function Encode-BerLength([int]$Length) {
        if ($Length -lt 128) { return ,[byte[]]@($Length) }
        $Bytes = [System.Collections.Generic.List[byte]]::new()
        while ($Length -gt 0) {
            $Bytes.Insert(0, [byte]($Length -band 0xFF))
            $Length = $Length -shr 8
        }
        $Bytes.Insert(0, [byte](0x80 -bor $Bytes.Count))
        return ,$Bytes.ToArray()
    }

    function Encode-BerInt([int64]$Val) {
        if ($Val -eq 0) { return ,[byte[]]@(0x02, 0x01, 0x00) }
        $Bytes = [System.Collections.Generic.List[byte]]::new()
        $Temp = $Val
        while ($Temp -gt 0) {
            $Bytes.Insert(0, [byte]($Temp -band 0xFF))
            $Temp = $Temp -shr 8
        }
        if (($Bytes.Item(0) -band 0x80) -ne 0) { $Bytes.Insert(0, 0x00) }
        [byte[]]$LenBytes = Encode-BerLength $Bytes.Count
        [byte[]]$ValBytes = $Bytes.ToArray()
        [byte[]]$Out = New-Object byte[] (1 + $LenBytes.Length + $ValBytes.Length)
        $Out[0] = 0x02
        [Buffer]::BlockCopy($LenBytes, 0, $Out, 1, $LenBytes.Length)
        [Buffer]::BlockCopy($ValBytes, 0, $Out, 1 + $LenBytes.Length, $ValBytes.Length)
        return ,$Out
    }

    function Encode-BerOctet([byte[]]$Data) {
        if ($null -eq $Data -or $Data.Length -eq 0) { return ,[byte[]]@(0x04, 0x00) }
        [byte[]]$LenBytes = Encode-BerLength $Data.Length
        [byte[]]$Out = New-Object byte[] (1 + $LenBytes.Length + $Data.Length)
        $Out[0] = 0x04
        [Buffer]::BlockCopy($LenBytes, 0, $Out, 1, $LenBytes.Length)
        [Buffer]::BlockCopy($Data, 0, $Out, 1 + $LenBytes.Length, $Data.Length)
        return ,$Out
    }

    function Encode-BerSequence([byte[]]$Data) {
        [byte[]]$LenBytes = Encode-BerLength $Data.Length
        [byte[]]$Out = New-Object byte[] (1 + $LenBytes.Length + $Data.Length)
        $Out[0] = 0x30
        [Buffer]::BlockCopy($LenBytes, 0, $Out, 1, $LenBytes.Length)
        [Buffer]::BlockCopy($Data, 0, $Out, 1 + $LenBytes.Length, $Data.Length)
        return ,$Out
    }

    function Join-Bytes([byte[][]]$Arrays) {
        $Total = 0
        foreach ($a in $Arrays) { if ($a) { $Total += $a.Length } }
        [byte[]]$Res = New-Object byte[] $Total
        $Offset = 0
        foreach ($a in $Arrays) {
            if ($a -and $a.Length -gt 0) {
                [Buffer]::BlockCopy($a, 0, $Res, $Offset, $a.Length)
                $Offset += $a.Length
            }
        }
        return ,$Res
    }

    function Encode-BerOid([string]$OidString) {
        [uint32[]]$Parts = $OidString.TrimStart('.').Split('.') | ForEach-Object { [uint32]$_ }
        $Encoded = [System.Collections.Generic.List[byte]]::new()
        $Encoded.Add([byte]((40 * $Parts.Get(0)) + $Parts.Get(1)))
        for ($i = 2; $i -lt $Parts.Count; $i++) {
            $Val = $Parts[$i]
            if ($Val -eq 0) { $Encoded.Add(0x00); continue }
            $Temp = [System.Collections.Generic.List[byte]]::new()
            while ($Val -gt 0) {
                $Temp.Insert(0, [byte](($Val -band 0x7F) -bor 0x80))
                $Val = $Val -shr 7
            }
            $LastIdx = $Temp.Count - 1
            $Temp[$LastIdx] = $Temp[$LastIdx] -band 0x7F
            $Encoded.AddRange($Temp)
        }
        [byte[]]$OidBody = $Encoded.ToArray()
        [byte[]]$LenBytes = Encode-BerLength $OidBody.Length
        return ,(Join-Bytes @([byte[]]@(0x06), $LenBytes, $OidBody))
    }

    function Read-BerTlv([byte[]]$Buf, [int]$Offset) {
        $Tag = $Buf[$Offset]
        $LenByte = $Buf[$Offset + 1]
        if ($LenByte -lt 128) {
            $Len = $LenByte
            $ValStart = $Offset + 2
        } else {
            $NumLenBytes = $LenByte -band 0x7F
            $Len = 0
            for ($i = 0; $i -lt $NumLenBytes; $i++) {
                $Len = ($Len -shl 8) -bor $Buf[$Offset + 2 + $i]
            }
            $ValStart = $Offset + 2 + $NumLenBytes
        }
        return @{ Tag = $Tag; Length = $Len; ValStart = $ValStart; Next = $ValStart + $Len }
    }

    # --- RFC 3414 / 7860 Key Localization ---
    function Get-LocalizedKey([string]$Password, [byte[]]$EngineId, [string]$Algo) {
        $PassBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $Buf = New-Object byte[] 1048576
        for ($i = 0; $i -lt 1048576; $i++) {
            $Buf[$i] = $PassBytes[$i % $PassBytes.Length]
        }
        $Hasher = switch ($Algo) {
            "MD5"    { [System.Security.Cryptography.MD5]::Create() }
            "SHA1"   { [System.Security.Cryptography.SHA1]::Create() }
            "SHA256" { [System.Security.Cryptography.SHA256]::Create() }
            "SHA384" { [System.Security.Cryptography.SHA384]::Create() }
            "SHA512" { [System.Security.Cryptography.SHA512]::Create() }
        }
        [byte[]]$Ku = $Hasher.ComputeHash($Buf)
        [byte[]]$Combined = New-Object byte[] ($Ku.Length + $EngineId.Length + $Ku.Length)
        [Buffer]::BlockCopy($Ku, 0, $Combined, 0, $Ku.Length)
        [Buffer]::BlockCopy($EngineId, 0, $Combined, $Ku.Length, $EngineId.Length)
        [Buffer]::BlockCopy($Ku, 0, $Combined, $Ku.Length + $EngineId.Length, $Ku.Length)
        [byte[]]$Kul = $Hasher.ComputeHash($Combined)
        $Hasher.Dispose()
        return ,$Kul
    }

    # --- RFC 3826 AES-128-CFB128 Helper (Works natively in PS 5.1 & PS 7+) ---
    function Invoke-Aes128Cfb([byte[]]$Data, [byte[]]$Key16, [byte[]]$Iv16, [bool]$Encrypt) {
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.KeySize = 128
        $Aes.Mode    = [System.Security.Cryptography.CipherMode]::ECB
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $Aes.Key     = $Key16
        $Encryptor   = $Aes.CreateEncryptor()

        [byte[]]$Out      = New-Object byte[] $Data.Length
        [byte[]]$Feedback = New-Object byte[] 16
        [Buffer]::BlockCopy($Iv16, 0, $Feedback, 0, 16)
        [byte[]]$Keystream = New-Object byte[] 16

        for ($offset = 0; $offset -lt $Data.Length; $offset += 16) {
            [void]$Encryptor.TransformBlock($Feedback, 0, 16, $Keystream, 0)
            $blockLen = [Math]::Min(16, $Data.Length - $offset)
            for ($i = 0; $i -lt $blockLen; $i++) {
                $Out[$offset + $i] = $Data[$offset + $i] -bxor $Keystream[$i]
                $Feedback[$i] = if ($Encrypt) { $Out[$offset + $i] } else { $Data[$offset + $i] }
            }
        }
        $Encryptor.Dispose()
        $Aes.Dispose()
        return ,$Out
    }

    # --- Transport Helper (UDP 161 or TLS over TCP 10161) ---
    function Send-SnmpBytes([byte[]]$Payload) {
        if ($UseTls) {
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $TcpClient.ReceiveTimeout = $TimeoutMs
            $TcpClient.SendTimeout = $TimeoutMs
            $TcpClient.Connect($TargetIP, $Port)
            $Callback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e) return $true }
            $SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $false, $Callback)
            try {
                $SslStream.AuthenticateAsClient($TargetIP)
                $SslStream.Write($Payload, 0, $Payload.Length)
                $SslStream.Flush()
                $ReadBuf = New-Object byte[] 8192
                $BytesRead = $SslStream.Read($ReadBuf, 0, $ReadBuf.Length)
                [byte[]]$Slice = New-Object byte[] $BytesRead
                [Buffer]::BlockCopy($ReadBuf, 0, $Slice, 0, $BytesRead)
                return ,$Slice
            }
            finally {
                $SslStream.Close()
                $TcpClient.Close()
            }
        }
        else {
            $UdpClient = New-Object System.Net.Sockets.UdpClient
            $UdpClient.Client.ReceiveTimeout = $TimeoutMs
            $RemoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                [void]$UdpClient.Send($Payload, $Payload.Length, $TargetIP, $Port)
                [byte[]]$UdpResp = $UdpClient.Receive([ref]$RemoteEP)
                return ,$UdpResp
            }
            finally {
                $UdpClient.Close()
            }
        }
    }

    # --- Build SNMPv3 Packet Helper ---
    function Build-V3Packet(
        [int]$MsgId,
        [byte[]]$EngineId, [int]$Boots, [int]$Time,
        [string]$User, [byte]$Flags,
        [byte[]]$AuthParam, [byte[]]$PrivParam,
        [byte[]]$ScopedPduBytes
    ) {
        $GlobalData = Encode-BerSequence (Join-Bytes @(
            (Encode-BerInt $MsgId),
            (Encode-BerInt 65507),
            (Encode-BerOctet ([byte[]]@($Flags))),
            (Encode-BerInt 3)
        ))
        [byte[]]$UserBytes = if ([string]::IsNullOrEmpty($User)) { [byte[]]@() } else { [System.Text.Encoding]::ASCII.GetBytes($User) }
        $UsmInner  = Join-Bytes @(
            (Encode-BerOctet $EngineId),
            (Encode-BerInt $Boots),
            (Encode-BerInt $Time),
            (Encode-BerOctet $UserBytes),
            (Encode-BerOctet $AuthParam),
            (Encode-BerOctet $PrivParam)
        )
        $SecParams = Encode-BerOctet (Encode-BerSequence $UsmInner)

        $MsgBody = Join-Bytes @(
            (Encode-BerInt 3),
            $GlobalData,
            $SecParams,
            $ScopedPduBytes
        )
        return ,(Encode-BerSequence $MsgBody)
    }

    try {
        # STEP 1: EngineID Discovery Probe (Empty User, Empty EngineID, Reportable=1)
        $EmptyGetPdu    = Join-Bytes @([byte[]]@(0xA0), (Encode-BerLength 11), (Encode-BerInt 1), (Encode-BerInt 0), (Encode-BerInt 0), (Encode-BerSequence ([byte[]]@())))
        $EmptyScopedPdu = Encode-BerSequence (Join-Bytes @((Encode-BerOctet ([byte[]]@())), (Encode-BerOctet ([byte[]]@())), $EmptyGetPdu))

        $DiscMsgId = Get-Random -Minimum 1000 -Maximum 32767
        [byte[]]$DiscoveryPkt = Build-V3Packet -MsgId $DiscMsgId -EngineId ([byte[]]@()) -Boots 0 -Time 0 -User "" -Flags 0x04 -AuthParam ([byte[]]@()) -PrivParam ([byte[]]@()) -ScopedPduBytes $EmptyScopedPdu
        [byte[]]$DiscoveryResp = Send-SnmpBytes $DiscoveryPkt

        # Parse EngineID, Boots, and Time from Report PDU
        $Pos = (Read-BerTlv $DiscoveryResp 0).ValStart
        $Pos = (Read-BerTlv $DiscoveryResp $Pos).Next # Version
        $Pos = (Read-BerTlv $DiscoveryResp $Pos).Next # GlobalData
        $SecTlv = Read-BerTlv $DiscoveryResp $Pos
        $UsmSeq = Read-BerTlv $DiscoveryResp $SecTlv.ValStart
        $uPos   = $UsmSeq.ValStart

        $EngTlv   = Read-BerTlv $DiscoveryResp $uPos; $uPos = $EngTlv.Next
        $BootsTlv = Read-BerTlv $DiscoveryResp $uPos; $uPos = $BootsTlv.Next
        $TimeTlv  = Read-BerTlv $DiscoveryResp $uPos

        [byte[]]$EngineId = New-Object byte[] $EngTlv.Length
        if ($EngTlv.Length -gt 0) {
            [Buffer]::BlockCopy($DiscoveryResp, $EngTlv.ValStart, $EngineId, 0, $EngTlv.Length)
        }
        [int]$EngineBoots = 0
        for ($i = 0; $i -lt $BootsTlv.Length; $i++) { $EngineBoots = ($EngineBoots -shl 8) -bor $DiscoveryResp[$BootsTlv.ValStart + $i] }
        [int]$EngineTime  = 0
        for ($i = 0; $i -lt $TimeTlv.Length; $i++)  { $EngineTime  = ($EngineTime -shl 8)  -bor $DiscoveryResp[$TimeTlv.ValStart + $i] }

#        Write-Host "DEBUG Discovery -> EngineID: $([BitConverter]::ToString($EngineId)) | Boots: $EngineBoots | Time: $EngineTime" -ForegroundColor DarkGray

        # STEP 2: Build Real GetRequest ScopedPDU
        $ReqId     = Get-Random -Minimum 1 -Maximum 32767
        $Vb        = Encode-BerSequence (Join-Bytes @((Encode-BerOid $OID), [byte[]]@(0x05, 0x00)))
        $VbList    = Encode-BerSequence $Vb
        $PduBody   = Join-Bytes @((Encode-BerInt $ReqId), (Encode-BerInt 0), (Encode-BerInt 0), $VbList)
        $GetPdu    = Join-Bytes @([byte[]]@(0xA0), (Encode-BerLength $PduBody.Length), $PduBody)
        [byte[]]$ScopedPdu = Encode-BerSequence (Join-Bytes @((Encode-BerOctet $EngineId), (Encode-BerOctet ([byte[]]@())), $GetPdu))

        $MacLen = switch ($AuthProtocol) {
            "MD5"    { 12 }
            "SHA1"   { 12 }
            "SHA256" { 24 }
            "SHA384" { 32 }
            "SHA512" { 48 }
        }
        [byte[]]$AuthPlaceholder = if (($SecLevel -band 0x01) -ne 0) { New-Object byte[] $MacLen } else { [byte[]]@() }
        [byte[]]$PrivSalt        = [byte[]]@()
        [byte[]]$PayloadPdu      = $ScopedPdu

        # STEP 3: Optional Privacy Encryption (AES-128 CFB or DES CBC)
        if (($SecLevel -band 0x02) -ne 0) {
            [byte[]]$PrivKey = Get-LocalizedKey -Password $PlainPassword -EngineId $EngineId -Algo $AuthProtocol
            [byte[]]$SaltBytes = New-Object byte[] 8
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($SaltBytes)
            $PrivSalt = $SaltBytes

            if ($PrivProtocol -eq "AES") {
        [byte[]]$IvPrefix = [byte[]]@(
            (($EngineBoots -shr 24) -band 0xFF), (($EngineBoots -shr 16) -band 0xFF), (($EngineBoots -shr 8) -band 0xFF), ($EngineBoots -band 0xFF),
            (($EngineTime -shr 24) -band 0xFF),  (($EngineTime -shr 16) -band 0xFF),  (($EngineTime -shr 8) -band 0xFF),  ($EngineTime -band 0xFF)
        )
        [byte[]]$Iv = Join-Bytes @($IvPrefix, $SaltBytes)
                [byte[]]$Key16 = New-Object byte[] 16
                [Buffer]::BlockCopy($PrivKey, 0, $Key16, 0, 16)
                [byte[]]$EncBytes = Invoke-Aes128Cfb -Data $ScopedPdu -Key16 $Key16 -Iv16 $Iv -Encrypt $true
                $PayloadPdu = Encode-BerOctet $EncBytes
            }
            else {
                [byte[]]$Iv = New-Object byte[] 8
                for ($i = 0; $i -lt 8; $i++) { $Iv[$i] = $PrivKey[$i + 8] -bxor $SaltBytes[$i] }
                $PadLen = 8 - ($ScopedPdu.Length % 8)
                [byte[]]$Padded = New-Object byte[] ($ScopedPdu.Length + $PadLen)
                [Buffer]::BlockCopy($ScopedPdu, 0, $Padded, 0, $ScopedPdu.Length)
                [byte[]]$Key8 = New-Object byte[] 8
                [Buffer]::BlockCopy($PrivKey, 0, $Key8, 0, 8)

                $Des = [System.Security.Cryptography.DES]::Create()
                $Des.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $Des.Padding = [System.Security.Cryptography.PaddingMode]::None
                $Des.Key = $Key8
                $Des.IV  = $Iv
                [byte[]]$EncBytes = $Des.CreateEncryptor().TransformFinalBlock($Padded, 0, $Padded.Length)
                $Des.Dispose()
                $PayloadPdu = Encode-BerOctet $EncBytes
            }
        }

        # STEP 4: Assemble Packet & Compute HMAC AuthParam if authNoPriv / authPriv
        $PacketMsgId = Get-Random -Minimum 1000 -Maximum 32767
        [byte[]]$FinalPacket = Build-V3Packet -MsgId $PacketMsgId -EngineId $EngineId -Boots $EngineBoots -Time $EngineTime -User $UserName -Flags $SecLevel -AuthParam $AuthPlaceholder -PrivParam $PrivSalt -ScopedPduBytes $PayloadPdu

        if (($SecLevel -band 0x01) -ne 0) {
            [byte[]]$AuthKey = Get-LocalizedKey -Password $PlainPassword -EngineId $EngineId -Algo $AuthProtocol
            $Hmac = switch ($AuthProtocol) {
                "MD5"    { New-Object System.Security.Cryptography.HMACMD5 -ArgumentList @(,$AuthKey) }
                "SHA1"   { New-Object System.Security.Cryptography.HMACSHA1 -ArgumentList @(,$AuthKey) }
                "SHA256" { New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList @(,$AuthKey) }
                "SHA384" { New-Object System.Security.Cryptography.HMACSHA384 -ArgumentList @(,$AuthKey) }
                "SHA512" { New-Object System.Security.Cryptography.HMACSHA512 -ArgumentList @(,$AuthKey) }
            }
            [byte[]]$FullHash = $Hmac.ComputeHash($FinalPacket)
            [byte[]]$Digest   = New-Object byte[] $MacLen
            [Buffer]::BlockCopy($FullHash, 0, $Digest, 0, $MacLen)
            $Hmac.Dispose()

            # Rebuild packet with the EXACT SAME $PacketMsgId and real HMAC digest
            $FinalPacket = Build-V3Packet -MsgId $PacketMsgId -EngineId $EngineId -Boots $EngineBoots -Time $EngineTime -User $UserName -Flags $SecLevel -AuthParam $Digest -PrivParam $PrivSalt -ScopedPduBytes $PayloadPdu
        }
#        Write-Host "DEBUG Packet ($($FinalPacket.Length)B): $([BitConverter]::ToString($FinalPacket))" -ForegroundColor DarkGray
        [byte[]]$Resp = Send-SnmpBytes $FinalPacket

        # STEP 5: Send Authenticated/Encrypted Request & Decode Response

        $Pos = (Read-BerTlv $Resp 0).ValStart
        $Pos = (Read-BerTlv $Resp $Pos).Next # Version
        $GlobalTlv = Read-BerTlv $Resp $Pos; $Pos = $GlobalTlv.Next
        $RespFlags = $Resp[(Read-BerTlv $Resp ((Read-BerTlv $Resp ((Read-BerTlv $Resp $GlobalTlv.ValStart).Next)).Next)).ValStart]

        $SecTlv = Read-BerTlv $Resp $Pos; $Pos = $SecTlv.Next
        $UsmSeq = Read-BerTlv $Resp $SecTlv.ValStart
        $uPos   = $UsmSeq.ValStart
        $uPos   = (Read-BerTlv $Resp $uPos).Next # EngineID
        $uPos   = (Read-BerTlv $Resp $uPos).Next # Boots
        $uPos   = (Read-BerTlv $Resp $uPos).Next # Time
        $uPos   = (Read-BerTlv $Resp $uPos).Next # User
        $uPos   = (Read-BerTlv $Resp $uPos).Next # AuthParam
        $RespPrivTlv = Read-BerTlv $Resp $uPos

        # Decrypt ScopedPDU if encrypted flag (0x02) is set on response
        if (($RespFlags -band 0x02) -ne 0) {
            $EncScopedTlv = Read-BerTlv $Resp $Pos
            [byte[]]$EncData  = New-Object byte[] $EncScopedTlv.Length
            [Buffer]::BlockCopy($Resp, $EncScopedTlv.ValStart, $EncData, 0, $EncScopedTlv.Length)
            [byte[]]$RespSalt = New-Object byte[] $RespPrivTlv.Length
            [Buffer]::BlockCopy($Resp, $RespPrivTlv.ValStart, $RespSalt, 0, $RespPrivTlv.Length)
            [byte[]]$PrivKey  = Get-LocalizedKey -Password $PlainPassword -EngineId $EngineId -Algo $AuthProtocol

            if ($PrivProtocol -eq "AES") {
                [byte[]]$IvPrefix = [byte[]]@(
                    (($EngineBoots -shr 24) -band 0xFF), (($EngineBoots -shr 16) -band 0xFF), (($EngineBoots -shr 8) -band 0xFF), ($EngineBoots -band 0xFF),
                    (($EngineTime -shr 24) -band 0xFF),  (($EngineTime -shr 16) -band 0xFF),  (($EngineTime -shr 8) -band 0xFF),  ($EngineTime -band 0xFF)
                )
                [byte[]]$Iv = Join-Bytes @($IvPrefix, $RespSalt)
                [byte[]]$Key16 = New-Object byte[] 16
                [Buffer]::BlockCopy($PrivKey, 0, $Key16, 0, 16)
                [byte[]]$ScopedBytes = Invoke-Aes128Cfb -Data $EncData -Key16 $Key16 -Iv16 $Iv -Encrypt $false
            }
            else {
                [byte[]]$Iv = New-Object byte[] 8
                for ($i = 0; $i -lt 8; $i++) { $Iv[$i] = $PrivKey[$i + 8] -bxor $RespSalt[$i] }
                [byte[]]$Key8 = New-Object byte[] 8
                [Buffer]::BlockCopy($PrivKey, 0, $Key8, 0, 8)
                $Des = [System.Security.Cryptography.DES]::Create()
                $Des.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $Des.Padding = [System.Security.Cryptography.PaddingMode]::None
                $Des.Key = $Key8
                $Des.IV  = $Iv
                [byte[]]$ScopedBytes = $Des.CreateDecryptor().TransformFinalBlock($EncData, 0, $EncData.Length)
                $Des.Dispose()
            }
            $sPos = (Read-BerTlv $ScopedBytes 0).ValStart
        }
        else {
            [byte[]]$ScopedBytes = $Resp
            $sPos = (Read-BerTlv $ScopedBytes $Pos).ValStart
        }

        # Walk ContextEngineID -> ContextName -> PDU -> VarBindList -> VarBind -> OID & Value
        $sPos = (Read-BerTlv $ScopedBytes $sPos).Next # ContextEngineID
        $sPos = (Read-BerTlv $ScopedBytes $sPos).Next # ContextName
        $PduTlv = Read-BerTlv $ScopedBytes $sPos
        $pPos = $PduTlv.ValStart
        $pPos = (Read-BerTlv $ScopedBytes $pPos).Next # ReqId
        $pPos = (Read-BerTlv $ScopedBytes $pPos).Next # ErrStatus
        $pPos = (Read-BerTlv $ScopedBytes $pPos).Next # ErrIndex
        $pPos = (Read-BerTlv $ScopedBytes $pPos).ValStart # VarBindList
        $pPos = (Read-BerTlv $ScopedBytes $pPos).ValStart # VarBind

        $RetOidTlv = Read-BerTlv $ScopedBytes $pPos; $pPos = $RetOidTlv.Next
        [byte[]]$RetOidBytes = New-Object byte[] $RetOidTlv.Length
        [Buffer]::BlockCopy($ScopedBytes, $RetOidTlv.ValStart, $RetOidBytes, 0, $RetOidTlv.Length)
        $Arcs = [System.Collections.Generic.List[uint64]]::new()
        $First = [int]$RetOidBytes.Get(0)
        $Arcs.Add([math]::Floor($First / 40)); $Arcs.Add($First % 40)
        [uint64]$v = 0
        for ($i = 1; $i -lt $RetOidBytes.Length; $i++) {
            $b = $RetOidBytes[$i]
            $v = ($v -shl 7) -bor ($b -band 0x7F)
            if (($b -band 0x80) -eq 0) { $Arcs.Add($v); $v = 0 }
        }
        $ReturnedOid = ($Arcs -join ".")

        # If PDU Tag is 0xA8 (Report), translate the USM error OID cleanly
        if ($PduTlv.Tag -eq 0xA8) {
            $UsmReason = switch ($ReturnedOid) {
                "1.3.6.1.6.3.15.1.1.1.0" { "usmStatsUnsupportedSecLevels (Printer requires Auth/Priv or different Security Level)" }
                "1.3.6.1.6.3.15.1.1.2.0" { "usmStatsNotInTimeWindows (EngineBoots/Time sync mismatch)" }
                "1.3.6.1.6.3.15.1.1.3.0" { "usmStatsUnknownUserNames (Username '$UserName' not found or not enabled on printer)" }
                "1.3.6.1.6.3.15.1.1.4.0" { "usmStatsUnknownEngineIDs (EngineID mismatch)" }
                "1.3.6.1.6.3.15.1.1.5.0" { "usmStatsWrongDigests (Authentication password or protocol mismatch)" }
                "1.3.6.1.6.3.15.1.1.6.0" { "usmStatsDecryptionErrors (Encryption password or AES/DES protocol mismatch)" }
                default { "SNMPv3 Report PDU returned OID: $ReturnedOid" }
            }
            Write-Warning "SNMPv3 Agent Rejected Request: $UsmReason"
            return
        }

        $ValTlv = Read-BerTlv $ScopedBytes $pPos
        [byte[]]$RawData = New-Object byte[] $ValTlv.Length
        if ($ValTlv.Length -gt 0) {
            [Buffer]::BlockCopy($ScopedBytes, $ValTlv.ValStart, $RawData, 0, $ValTlv.Length)
        }

        $DecodedValue = switch ($ValTlv.Tag) {
            0x02 { [int64]$n = 0; foreach ($b in $RawData) { $n = ($n -shl 8) -bor $b }; $n }
            0x04 { [System.Text.Encoding]::ASCII.GetString($RawData) }
            0x05 { "NULL" }
            0x40 { ($RawData | ForEach-Object { $_.ToString() }) -join "." }
            0x41 { [uint64]$n = 0; foreach ($b in $RawData) { $n = ($n -shl 8) -bor $b }; $n }
            0x42 { [uint64]$n = 0; foreach ($b in $RawData) { $n = ($n -shl 8) -bor $b }; $n }
            0x43 { [uint64]$t = 0; foreach ($b in $RawData) { $t = ($t -shl 8) -bor $b }; [TimeSpan]::FromMilliseconds($t * 10).ToString() }
            0x46 { [uint64]$n = 0; foreach ($b in $RawData) { $n = ($n -shl 8) -bor $b }; $n }
            0x80 { "NoSuchObject" }
            0x81 { "NoSuchInstance" }
            default { "Raw Hex (Tag 0x$($ValTlv.Tag.ToString('X2'))): " + ([BitConverter]::ToString($RawData)) }
        }

        return [PSCustomObject]@{
            OID      = $ReturnedOid
            EngineID = ([BitConverter]::ToString($EngineId))
            Type     = "0x$($ValTlv.Tag.ToString('X2'))"
            Value    = $DecodedValue
        }
    }
    catch {
        Write-Warning "SNMPv3 request to $TargetIP failed: $($_.Exception.Message)"
    }
}
