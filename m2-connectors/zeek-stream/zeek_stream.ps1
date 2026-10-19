param(
    [switch]$Once,
    [switch]$ResetCheckpoint,

    [string]$LogstashHost = "127.0.0.1",
    [int]$LogstashPort = 5000,

    [int]$PollSeconds = 1,
    [int]$RetryCount = 3,
    [int]$RetryDelaySeconds = 1
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$inputFolder = Join-Path $PSScriptRoot "input"
$stateFolder = Join-Path $PSScriptRoot "state"
$rejectedFolder = Join-Path $PSScriptRoot "rejected"

$checkpointPath = Join-Path $stateFolder "checkpoints.json"
$rejectedPath = Join-Path $rejectedFolder "zeek_rejected.ndjson"

$m2Root = Split-Path -Parent $PSScriptRoot
$adapterPath = Join-Path $m2Root "common\m3_adapter.ps1"

$script:checkpoints = @{}

$script:client = $null
$script:networkStream = $null
$script:writer = $null

# SHA-256 of an empty byte sequence. Offset 0 is generation-neutral.
$script:emptySha256 =
    "e3b0c44298fc1c149afbf4c8996fb924" +
    "27ae41e4649b934ca495991b7852b855"


function Close-LogstashConnection {

    if ($null -ne $script:writer) {
        try {
            $script:writer.Dispose()
        }
        catch {
        }

        $script:writer = $null
    }

    if ($null -ne $script:networkStream) {
        try {
            $script:networkStream.Dispose()
        }
        catch {
        }

        $script:networkStream = $null
    }

    if ($null -ne $script:client) {
        try {
            $script:client.Close()
        }
        catch {
        }

        $script:client = $null
    }
}


function Connect-Logstash {

    Close-LogstashConnection

    $script:client = New-Object System.Net.Sockets.TcpClient

    $script:client.Connect(
        $LogstashHost,
        $LogstashPort
    )

    $script:networkStream = $script:client.GetStream()

    $script:writer = New-Object System.IO.StreamWriter(
        $script:networkStream,
        [Text.UTF8Encoding]::new($false)
    )

    $script:writer.NewLine = "`n"
    $script:writer.AutoFlush = $true
}


function Send-PayloadToLogstash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Payload
    )

    $lastError = $null

    for (
        $attempt = 1;
        $attempt -le $RetryCount;
        $attempt++
    ) {
        try {

            if (
                $null -eq $script:client -or
                -not $script:client.Connected -or
                $null -eq $script:writer
            ) {
                Connect-Logstash
            }

            $script:writer.WriteLine($Payload)
            $script:writer.Flush()

            return
        }
        catch {
            $lastError = $_

            Close-LogstashConnection

            if ($attempt -lt $RetryCount) {

                Write-Warning (
                    "Logstash send failed " +
                    "(attempt $attempt/$RetryCount). " +
                    "Reconnecting..."
                )

                Start-Sleep `
                    -Seconds $RetryDelaySeconds
            }
        }
    }

    throw (
        "Failed to send event to Logstash after " +
        "$RetryCount attempt(s): " +
        $lastError.Exception.Message
    )
}


function Get-PrefixSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [long]$Length
    )

    if ($Length -lt 0) {
        throw "Hash length cannot be negative."
    }

    $sha = [Security.Cryptography.SHA256]::Create()
    $fileStream = $null

    try {
        $share = (
            [IO.FileShare]::ReadWrite -bor
            [IO.FileShare]::Delete
        )

        $fileStream = New-Object System.IO.FileStream(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            $share
        )

        if ($Length -gt $fileStream.Length) {
            throw (
                "Cannot hash $Length bytes; " +
                "file currently contains only " +
                "$($fileStream.Length) bytes."
            )
        }

        $buffer = New-Object byte[] 65536
        $remaining = $Length

        while ($remaining -gt 0) {

            $wanted = [int][Math]::Min(
                [long]$buffer.Length,
                $remaining
            )

            $read = $fileStream.Read(
                $buffer,
                0,
                $wanted
            )

            if ($read -le 0) {
                throw "Unexpected end of file while hashing."
            }

            $null = $sha.TransformBlock(
                $buffer,
                0,
                $read,
                $null,
                0
            )

            $remaining -= $read
        }

        $empty = New-Object byte[] 0

        $null = $sha.TransformFinalBlock(
            $empty,
            0,
            0
        )

        return (
            [BitConverter]::ToString(
                $sha.Hash
            ).Replace("-", "").ToLowerInvariant()
        )
    }
    finally {

        if ($null -ne $fileStream) {
            $fileStream.Dispose()
        }

        $sha.Dispose()
    }
}


function Get-BytesSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if (
        $Length -lt 0 -or
        $Length -gt $Bytes.Length
    ) {
        throw "Invalid byte length for SHA-256."
    }

    $sha = [Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash(
            $Bytes,
            0,
            $Length
        )

        return (
            [BitConverter]::ToString(
                $hash
            ).Replace("-", "").ToLowerInvariant()
        )
    }
    finally {
        $sha.Dispose()
    }
}


function Load-Checkpoints {

    $script:checkpoints = @{}

    if (-not (Test-Path $checkpointPath)) {
        return
    }

    try {
        $raw = [System.IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        )

        if ([string]::IsNullOrWhiteSpace($raw)) {
            return
        }

        $items = @(
            $raw |
                ConvertFrom-Json `
                    -ErrorAction Stop
        )

        foreach ($item in $items) {

            if (
                $null -eq $item.path -or
                $null -eq $item.offset
            ) {
                throw "Invalid checkpoint record."
            }

            $script:checkpoints[[string]$item.path] =
                [PSCustomObject]@{
                    offset        = [long]$item.offset
                    prefix_sha256 = [string]$item.prefix_sha256
                }
        }
    }
    catch {
        throw (
            "Failed to load Zeek checkpoints: " +
            $_.Exception.Message
        )
    }
}


function Save-AllCheckpoints {

    $items = @(
        foreach (
            $path in (
                $script:checkpoints.Keys |
                    Sort-Object
            )
        ) {
            $checkpoint = $script:checkpoints[$path]

            [ordered]@{
                path          = $path
                offset        = [long]$checkpoint.offset
                prefix_sha256 = [string]$checkpoint.prefix_sha256
                updated_at    = (
                    Get-Date
                ).ToUniversalTime().ToString("o")
            }
        }
    )

    $json = $items |
        ConvertTo-Json `
            -Depth 5

    $tempPath = "$checkpointPath.tmp"

    [System.IO.File]::WriteAllText(
        $tempPath,
        $json,
        [Text.UTF8Encoding]::new($false)
    )

    Move-Item `
        -Path $tempPath `
        -Destination $checkpointPath `
        -Force
}


function Set-FileCheckpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [long]$Offset,

        [Parameter(Mandatory = $true)]
        [string]$PrefixSha256
    )

    # IMPORTANT: never reopen Path here to calculate the hash.
    # PrefixSha256 must come from the same buffered file generation
    # that supplied the bytes represented by Offset.
    $script:checkpoints[$Path] =
        [PSCustomObject]@{
            offset        = $Offset
            prefix_sha256 = $PrefixSha256
        }

    Save-AllCheckpoints
}


function Get-ValidatedCheckpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)

    if (
        -not $script:checkpoints.ContainsKey(
            $fullPath
        )
    ) {
        Set-FileCheckpoint `
            -Path $fullPath `
            -Offset 0 `
            -PrefixSha256 $script:emptySha256

        return [long]0
    }

    $checkpoint = $script:checkpoints[$fullPath]
    $offset = [long]$checkpoint.offset

    $fileInfo = Get-Item `
        -LiteralPath $fullPath `
        -ErrorAction Stop

    if ($offset -gt $fileInfo.Length) {

        Write-Warning (
            "$($fileInfo.Name) was truncated or replaced. " +
            "Resetting its checkpoint."
        )

        Set-FileCheckpoint `
            -Path $fullPath `
            -Offset 0 `
            -PrefixSha256 $script:emptySha256

        return [long]0
    }

    if ($offset -gt 0) {

        $currentPrefixHash = Get-PrefixSha256 `
            -Path $fullPath `
            -Length $offset

        if (
            $currentPrefixHash -ne
            [string]$checkpoint.prefix_sha256
        ) {
            Write-Warning (
                "$($fileInfo.Name) content before the " +
                "saved checkpoint changed. " +
                "Treating it as a replacement/rotation."
            )

            Set-FileCheckpoint `
                -Path $fullPath `
                -Offset 0 `
                -PrefixSha256 $script:emptySha256

            return [long]0
        }
    }

    return $offset
}


function Get-CompleteLinesFromOffset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [long]$Offset
    )

    $fileStream = $null

    try {
        $share = (
            [IO.FileShare]::ReadWrite -bor
            [IO.FileShare]::Delete
        )

        # Open the file once and take one byte snapshot from this handle.
        # If the pathname is atomically replaced while records are being
        # sent, this handle still represents the generation we buffered.
        $fileStream = New-Object System.IO.FileStream(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            $share
        )

        $snapshotLength = [long]$fileStream.Length

        if ($Offset -gt $snapshotLength) {
            throw "Saved offset is beyond the current file length."
        }

        if ($snapshotLength -gt [int]::MaxValue) {
            throw "Zeek log is too large for one snapshot scan."
        }

        # Nothing new in this generation.
        if ($Offset -eq $snapshotLength) {
            return @()
        }

        $null = $fileStream.Seek(
            0,
            [IO.SeekOrigin]::Begin
        )

        $snapshotBytes =
            New-Object byte[] ([int]$snapshotLength)

        $totalRead = 0

        while ($totalRead -lt $snapshotBytes.Length) {

            $read = $fileStream.Read(
                $snapshotBytes,
                $totalRead,
                $snapshotBytes.Length - $totalRead
            )

            if ($read -le 0) {
                break
            }

            $totalRead += $read
        }

        if ($totalRead -lt $snapshotBytes.Length) {

            $trimmed = New-Object byte[] $totalRead

            if ($totalRead -gt 0) {
                [Array]::Copy(
                    $snapshotBytes,
                    0,
                    $trimmed,
                    0,
                    $totalRead
                )
            }

            $snapshotBytes = $trimmed
        }

        if ($Offset -gt $snapshotBytes.Length) {
            throw (
                "File changed while taking the Zeek snapshot; " +
                "saved offset is beyond the captured generation."
            )
        }

        $lines = @()
        $lineStart = [int]$Offset

        for (
            $i = [int]$Offset;
            $i -lt $snapshotBytes.Length;
            $i++
        ) {
            # Only newline-terminated records are complete.
            if ($snapshotBytes[$i] -ne 10) {
                continue
            }

            $lineLength = $i - $lineStart

            # Remove CR from CRLF without changing the saved byte offset.
            if (
                $lineLength -gt 0 -and
                $snapshotBytes[
                    $lineStart + $lineLength - 1
                ] -eq 13
            ) {
                $textLength = $lineLength - 1
            }
            else {
                $textLength = $lineLength
            }

            $lineBytes = New-Object byte[] $textLength

            if ($textLength -gt 0) {
                [Array]::Copy(
                    $snapshotBytes,
                    $lineStart,
                    $lineBytes,
                    0,
                    $textLength
                )
            }

            $endOffset = [long]($i + 1)

            # Calculate the checkpoint hash from the SAME in-memory
            # generation that supplied this line. Do not reopen Path.
            $prefixHash = Get-BytesSha256 `
                -Bytes $snapshotBytes `
                -Length ($i + 1)

            $lines += [PSCustomObject]@{
                bytes         = $lineBytes
                start         = [long]$lineStart
                end_offset    = $endOffset
                prefix_sha256 = $prefixHash
            }

            $lineStart = $i + 1
        }

        # Any bytes after the last newline are deliberately NOT returned.
        # Their checkpoint is therefore not advanced. Once Zeek finishes
        # the line and writes a newline, it will be read on the next scan.

        return $lines
    }
    finally {

        if ($null -ne $fileStream) {
            $fileStream.Dispose()
        }
    }
}


function Write-RejectedRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [long]$ByteOffset,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [string]$RawLine,

        [string]$RawBytesBase64
    )

    $record = [ordered]@{
        rejected_at = (
            Get-Date
        ).ToUniversalTime().ToString("o")

        source_type = "zeek"
        input_file  = $FileName
        byte_offset = $ByteOffset
        reason      = $Reason
    }

    if ($PSBoundParameters.ContainsKey("RawLine")) {
        $record["raw_line"] = $RawLine
    }

    if (
        $PSBoundParameters.ContainsKey(
            "RawBytesBase64"
        )
    ) {
        $record["raw_bytes_base64"] =
            $RawBytesBase64
    }

    $json = $record |
        ConvertTo-Json `
            -Depth 10 `
            -Compress

    [System.IO.File]::AppendAllText(
        $rejectedPath,
        $json + "`n",
        [Text.UTF8Encoding]::new($false)
    )
}


function Get-ZeekTimestamp {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    $tsProperty = $Event.PSObject.Properties["ts"]

    if ($null -eq $tsProperty) {
        throw "Zeek record is missing ts."
    }

    $value = $tsProperty.Value

    if ($null -eq $value) {
        throw "Zeek ts is null."
    }

    # Normal Zeek JSON: Unix epoch seconds.
    try {
        $epochSeconds = [Convert]::ToDouble(
            $value,
            [Globalization.CultureInfo]::InvariantCulture
        )

        if (
            [double]::IsNaN($epochSeconds) -or
            [double]::IsInfinity($epochSeconds)
        ) {
            throw "non-finite timestamp"
        }

        return (
            [DateTimeOffset]::FromUnixTimeMilliseconds(
                [long]($epochSeconds * 1000)
            ).UtcDateTime.ToString("o")
        )
    }
    catch {
        # Test fixtures may use ISO timestamps.
        try {
            return (
                [DateTimeOffset]::Parse(
                    [string]$value,
                    [Globalization.CultureInfo]::InvariantCulture
                )
            ).UtcDateTime.ToString("o")
        }
        catch {
            throw "Invalid Zeek ts value: $value"
        }
    }
}


try {
    if (-not (Test-Path $adapterPath)) {
        throw "M3 adapter not found: $adapterPath"
    }

    . $adapterPath

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $inputFolder |
        Out-Null

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $stateFolder |
        Out-Null

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $rejectedFolder |
        Out-Null

    if ($ResetCheckpoint) {

        if (Test-Path $checkpointPath) {
            Remove-Item `
                -LiteralPath $checkpointPath `
                -Force
        }

        $script:checkpoints = @{}

        Write-Host (
            "Zeek checkpoints reset. " +
            "Complete existing records will be replayed."
        )
    }
    else {
        Load-Checkpoints
    }

    Write-Host "Watching Zeek logs in $inputFolder"

    if ($Once) {
        Write-Host "Running one scan only."
    }
    else {
        Write-Host (
            "Continuous mode. Poll interval: " +
            "$PollSeconds second(s)."
        )
    }

    do {
        $files = @(
            Get-ChildItem `
                -Path $inputFolder `
                -File `
                -ErrorAction Stop |
            Where-Object {
                $_.Extension -ieq ".json" -or
                $_.Extension -ieq ".log"
            }
        )

        foreach ($file in $files) {

            $fullPath = [IO.Path]::GetFullPath(
                $file.FullName
            )

            $offset = Get-ValidatedCheckpoint `
                -Path $fullPath

            $completeLines = @(
                Get-CompleteLinesFromOffset `
                    -Path $fullPath `
                    -Offset $offset
            )

            foreach ($line in $completeLines) {

                $rawLine = $null

                try {
                    $strictUtf8 = New-Object `
                        System.Text.UTF8Encoding(
                            $false,
                            $true
                        )

                    $rawLine = $strictUtf8.GetString(
                        [byte[]]$line.bytes
                    )
                }
                catch {
                    $base64 = [Convert]::ToBase64String(
                        [byte[]]$line.bytes
                    )

                    Write-RejectedRecord `
                        -FileName $file.Name `
                        -ByteOffset $line.start `
                        -Reason "Invalid UTF-8 Zeek record." `
                        -RawBytesBase64 $base64

                    Set-FileCheckpoint `
                        -Path $fullPath `
                        -Offset $line.end_offset `
                        -PrefixSha256 $line.prefix_sha256

                    Write-Warning (
                        "Rejected invalid UTF-8 record " +
                        "from $($file.Name) at byte " +
                        "$($line.start)."
                    )

                    continue
                }

                if (
                    [string]::IsNullOrWhiteSpace(
                        $rawLine
                    )
                ) {
                    Set-FileCheckpoint `
                        -Path $fullPath `
                        -Offset $line.end_offset `
                        -PrefixSha256 $line.prefix_sha256

                    continue
                }

                try {
                    $event = $rawLine |
                        ConvertFrom-Json `
                            -ErrorAction Stop
                }
                catch {
                    Write-RejectedRecord `
                        -FileName $file.Name `
                        -ByteOffset $line.start `
                        -Reason (
                            "Invalid JSON: " +
                            $_.Exception.Message
                        ) `
                        -RawLine $rawLine

                    Set-FileCheckpoint `
                        -Path $fullPath `
                        -Offset $line.end_offset `
                        -PrefixSha256 $line.prefix_sha256

                    Write-Warning (
                        "Rejected malformed JSON from " +
                        "$($file.Name) at byte " +
                        "$($line.start)."
                    )

                    continue
                }

                try {
                    # Validate ts here so one invalid timestamp
                    # cannot terminate the stream.
                    $timestamp = Get-ZeekTimestamp `
                        -Event $event

                    $normalized = Convert-ZeekEventToM3 `
                        -Event $event `
                        -RawLine $rawLine `
                        -LogType $file.BaseName

                    # Extra normalized time for raw-index searching.
                    # The original Zeek ts remains unchanged at top level
                    # for M3's Zeek parser.
                    $normalized |
                        Add-Member `
                            -NotePropertyName "timestamp" `
                            -NotePropertyValue $timestamp `
                            -Force

                    $payload = $normalized |
                        ConvertTo-Json `
                            -Depth 20 `
                            -Compress
                }
                catch {
                    Write-RejectedRecord `
                        -FileName $file.Name `
                        -ByteOffset $line.start `
                        -Reason $_.Exception.Message `
                        -RawLine $rawLine

                    Set-FileCheckpoint `
                        -Path $fullPath `
                        -Offset $line.end_offset `
                        -PrefixSha256 $line.prefix_sha256

                    Write-Warning (
                        "Rejected Zeek record from " +
                        "$($file.Name) at byte " +
                        "$($line.start)`: " +
                        $_.Exception.Message
                    )

                    continue
                }

                # If sending fails, this throws and the checkpoint is NOT
                # advanced. The same record will therefore be retried.
                Send-PayloadToLogstash `
                    -Payload $payload

                Set-FileCheckpoint `
                    -Path $fullPath `
                    -Offset $line.end_offset `
                    -PrefixSha256 $line.prefix_sha256

                Write-Host (
                    "Sent Zeek event from " +
                    "$($file.Name), checkpoint " +
                    "$($line.end_offset)"
                )
            }
        }

        if (-not $Once) {
            Start-Sleep `
                -Seconds $PollSeconds
        }

    } while (-not $Once)

    Write-Host "Zeek streaming run completed."
}
catch {
    Write-Error (
        "Zeek stream failed: " +
        $_.Exception.Message
    )

    exit 1
}
finally {
    Close-LogstashConnection
}