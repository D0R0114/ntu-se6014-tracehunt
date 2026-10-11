param(
    [switch]$Once
)

$ErrorActionPreference = "Stop"

$inputFolder = Join-Path $PSScriptRoot "input"
$logstashHost = "127.0.0.1"
$logstashPort = 5000

New-Item -ItemType Directory -Force -Path $inputFolder | Out-Null

$positions = @{}

$client = $null
$stream = $null
$writer = $null

try {
    Write-Host "Connecting to Logstash..."

    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($logstashHost, $logstashPort)

    $stream = $client.GetStream()

    $writer = New-Object System.IO.StreamWriter(
        $stream,
        [Text.UTF8Encoding]::new($false)
    )

    $writer.NewLine = "`n"
    $writer.AutoFlush = $true

    Write-Host "Watching Zeek JSON logs in $inputFolder"

    if ($Once) {
        Write-Host "Running one scan only."
    }
    else {
        Write-Host "Continuous mode."
    }

    do {
        $files = @(
            Get-ChildItem -Path $inputFolder -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -eq ".json" -or $_.Extension -eq ".log"
            }
        )

        foreach ($file in $files) {

            if (-not $positions.ContainsKey($file.FullName)) {
                $positions[$file.FullName] = 0
            }

            # Read plain .NET strings so PowerShell file metadata
            # is not attached to each line.
            $lines = [System.IO.File]::ReadAllLines($file.FullName)

            # Handle file truncation / rotation.
            if ($positions[$file.FullName] -gt $lines.Length) {
                $positions[$file.FullName] = 0
            }

            for (
                $i = $positions[$file.FullName];
                $i -lt $lines.Length;
                $i++
            ) {
                $rawLine = [string]$lines[$i]

                if ([string]::IsNullOrWhiteSpace($rawLine)) {
                    continue
                }

                try {
                    $event = $rawLine | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    Write-Warning "Invalid JSON in $($file.Name) at line $($i + 1)"
                    continue
                }

                # Default timestamp if the event has no ts field.
                $timestamp = (Get-Date).ToUniversalTime().ToString("o")

                if ($null -ne $event.ts) {

                    $originalTs = $event.ts

                    # Real Zeek JSON uses Unix epoch seconds.
                    if (
                        $originalTs -isnot [string] -or
                        [string]$originalTs -match '^\d+(\.\d+)?$'
                    ) {
                        $epochSeconds = [Convert]::ToDouble(
                            $originalTs,
                            [Globalization.CultureInfo]::InvariantCulture
                        )

                        $timestamp = [DateTimeOffset]::FromUnixTimeMilliseconds(
                            [long]($epochSeconds * 1000)
                        ).UtcDateTime.ToString("o")

                        # Keep the original Zeek epoch value.
                        $event | Add-Member `
                            -NotePropertyName "ts_epoch" `
                            -NotePropertyValue $epochSeconds `
                            -Force
                    }
                    else {
                        # Also allow ISO timestamps in test fixtures.
                        $timestamp = [DateTimeOffset]::Parse(
                            [string]$originalTs,
                            [Globalization.CultureInfo]::InvariantCulture
                        ).UtcDateTime.ToString("o")
                    }

                    # Existing Elasticsearch mapping expects raw_event.ts
                    # to be a date, not Zeek epoch seconds.
                    $event | Add-Member `
                        -NotePropertyName "ts" `
                        -NotePropertyValue $timestamp `
                        -Force
                }

                $payloadObject = [ordered]@{
                    timestamp   = $timestamp
                    event_id    = 0
                    provider    = "Zeek"
                    computer    = $env:COMPUTERNAME
                    source_type = "zeek"
                    zeek_log    = $file.BaseName

                    # Exact unmodified line produced by Zeek.
                    raw_line    = $rawLine

                    # Parsed copy for downstream schema/search work.
                    raw_event   = $event
                }

                $payload = $payloadObject |
                    ConvertTo-Json -Depth 10 -Compress

                $writer.WriteLine($payload)

                Write-Host "Sent Zeek event from $($file.Name)"
            }

            $positions[$file.FullName] = $lines.Length
        }

        if (-not $Once) {
            Start-Sleep -Seconds 1
        }

    } while (-not $Once)
}
finally {
    if ($null -ne $writer) {
        $writer.Flush()
        $writer.Dispose()
    }

    if ($null -ne $stream) {
        $stream.Dispose()
    }

    if ($null -ne $client) {
        $client.Close()
    }
}

Write-Host "Zeek streaming run completed."