function Invoke-SnmpV2Get {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        
        [string]$Community = "public",
        
        [Parameter(Mandatory=$true)]
        [string]$OID,
        
        [int]$Port = 161,
        [int]$TimeoutMs = 3000
    )

    function Encode-BerLength([int]$Length) {
        if ($Length -lt 128) {
            return [byte[]]@($Length)
        }
        $Bytes = [System.Collections.Generic.List[byte]]::new()
        while ($Length -gt 0) {
            $Bytes.Insert(0, [byte]($Length -band 0xFF))
            $Length = $Length -shr 8
        }
        $Bytes.Insert(0, [byte](0x80 -bor $Bytes.Count))
        return $Bytes.ToArray()
    }

    function Encode-BerOid([string]$OidString) {
        $Parts = $OidString.TrimStart('.').Split('.') | ForEach-Object { [uint32]$_ }
        $Encoded = [System.Collections.Generic.List[byte]]::new()
        
        $Encoded.Add([byte]((40 * $Parts[0]) + $Parts[1]))
        
        for ($i = 2; $i -lt $Parts.Count; $i++) {
            $Val = $Parts[$i]
            if ($Val -eq 0) {
                $Encoded.Add(0x00)
                continue
            }
            $Temp = [System.Collections.Generic.List[byte]]::new()
            while ($Val -gt 0) {
                $Temp.Insert(0, [byte](($Val -band 0x7F) -bor 0x80))
                $Val = $Val -shr 7
            }
            $Temp[$Temp.Count - 1] = $Temp[$Temp.Count - 1] -band 0x7F
            $Encoded.AddRange($Temp)
        }
        
        $LenBytes = Encode-BerLength $Encoded.Count
        return [byte[]]@(0x06) + $LenBytes + $Encoded.ToArray()
    }

    $OidBytes = Encode-BerOid $OID
    $NullBytes = [byte[]]@(0x05, 0x00)
    $VarBindContent = $OidBytes + $NullBytes
    $VarBind = [byte[]]@(0x30) + (Encode-BerLength $VarBindContent.Length) + $VarBindContent
    $VarBindList = [byte[]]@(0x30) + (Encode-BerLength $VarBind.Length) + $VarBind

    $ReqId = Get-Random -Minimum 1 -Maximum 32767
    $ReqIdBytes = [byte[]]@(0x02, 0x02, (($ReqId -shr 8) -band 0xFF), ($ReqId -band 0xFF))
    $ErrorStatus = [byte[]]@(0x02, 0x01, 0x00)
    $ErrorIndex  = [byte[]]@(0x02, 0x01, 0x00)
    
    $PduContent = $ReqIdBytes + $ErrorStatus + $ErrorIndex + $VarBindList
    $Pdu = [byte[]]@(0xA0) + (Encode-BerLength $PduContent.Length) + $PduContent

    $VersionBytes = [byte[]]@(0x02, 0x01, 0x01)
    $CommStringBytes = [System.Text.Encoding]::ASCII.GetBytes($Community)
    $CommBytes = [byte[]]@(0x04) + (Encode-BerLength $CommStringBytes.Length) + $CommStringBytes

    $MessageContent = $VersionBytes + $CommBytes + $Pdu
    $Packet = [byte[]]@(0x30) + (Encode-BerLength $MessageContent.Length) + $MessageContent

    $UdpClient = New-Object System.Net.Sockets.UdpClient
    $UdpClient.Client.ReceiveTimeout = $TimeoutMs
    $RemoteEndPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

    try {
        [void]$UdpClient.Send($Packet, $Packet.Length, $TargetIP, $Port)
        $ResponseBytes = $UdpClient.Receive([ref]$RemoteEndPoint)
        return Parse-SnmpResponse -Bytes $ResponseBytes -RequestedOid $OID
    }
    catch [System.Net.Sockets.SocketException] {
        Write-Warning "SNMP request to $TargetIP timed out or failed: $($_.Exception.Message)"
    }
    finally {
        $UdpClient.Close()
    }
}

function Parse-SnmpResponse {
    param ([byte[]]$Bytes, [string]$RequestedOid)

    # Helper to read BER Tag, Length, and Value boundaries at a given offset
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
        return @{
            Tag      = $Tag
            Length   = $Len
            ValStart = $ValStart
            Next     = $ValStart + $Len
        }
    }

    # Walk exact ASN.1 structure:
    # 1. Outer Message SEQUENCE (0x30) -> enter ValStart
    $Msg = Read-BerTlv $Bytes 0
    $Pos = $Msg.ValStart

    # 2. Skip Version (INTEGER) and Community (OCTET STRING)
    $Ver  = Read-BerTlv $Bytes $Pos; $Pos = $Ver.Next
    $Comm = Read-BerTlv $Bytes $Pos; $Pos = $Comm.Next

    # 3. Enter GetResponse PDU (0xA2)
    $Pdu = Read-BerTlv $Bytes $Pos; $Pos = $Pdu.ValStart

    # 4. Skip RequestID, ErrorStatus, ErrorIndex
    $ReqId  = Read-BerTlv $Bytes $Pos; $Pos = $ReqId.Next
    $ErrSt  = Read-BerTlv $Bytes $Pos; $Pos = $ErrSt.Next
    $ErrIdx = Read-BerTlv $Bytes $Pos; $Pos = $ErrIdx.Next

    # 5. Enter VarBindList (SEQUENCE) -> Enter first VarBind (SEQUENCE)
    $VbList = Read-BerTlv $Bytes $Pos; $Pos = $VbList.ValStart
    $Vb     = Read-BerTlv $Bytes $Pos; $Pos = $Vb.ValStart

    # 6. Skip response OID (0x06) to land directly on the Value TLV
    $RespOid = Read-BerTlv $Bytes $Pos; $Pos = $RespOid.Next
    $ValTlv  = Read-BerTlv $Bytes $Pos

    $ValTag  = $ValTlv.Tag
    $RawData = if ($ValTlv.Length -gt 0) {
        $Bytes[$ValTlv.ValStart..($ValTlv.ValStart + $ValTlv.Length - 1)]
    } else {
        [byte[]]@()
    }

    $DecodedValue = switch ($ValTag) {
        0x02 { # INTEGER
            [int64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x04 { # OCTET STRING
            [System.Text.Encoding]::ASCII.GetString($RawData)
        }
        0x05 { "NULL" }
        0x40 { # IpAddress (4 bytes)
            ($RawData | ForEach-Object { $_.ToString() }) -join "."
        }
        0x41 { # Counter32
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x42 { # Gauge32
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x43 { # TimeTicks (hundredths of a second)
            [uint64]$Ticks = 0
            foreach ($b in $RawData) { $Ticks = ($Ticks -shl 8) -bor $b }
            [TimeSpan]::FromMilliseconds($Ticks * 10).ToString()
        }
        0x46 { # Counter64
            [uint64]$Num = 0
            foreach ($b in $RawData) { $Num = ($Num -shl 8) -bor $b }
            $Num
        }
        0x80 { "NoSuchObject" }
        0x81 { "NoSuchInstance" }
        default { "Raw Hex (Tag 0x$($ValTag.ToString('X2'))): " + ([BitConverter]::ToString($RawData)) }
    }

    return [PSCustomObject]@{
        OID   = $RequestedOid
        Type  = "0x$($ValTag.ToString('X2'))"
        Value = $DecodedValue
    }
}
