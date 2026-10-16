param(
    [string]$LogstashHost = "127.0.0.1",
    [int]$LogstashPort = 5000
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$dropFolder = Join-Path $PSScriptRoot "drop"
$outputFolder = Join-Path $PSScriptRoot "output"

$m2Root = Split-Path -Parent $PSScriptRoot
$commonFolder = Join-Path $m2Root "common"
$adapterPath = Join-Path $commonFolder "m3_adapter.ps1"


function Get-NestedValue {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($null -eq $Object) {
        return $null
    }

    # First support a literal property containing dots,
    # e.g. "event.code".
    $exactProperty = $Object.PSObject.Properties[$Path]

    if ($null -ne $exactProperty) {
        return $exactProperty.Value
    }

    $current = $Object

    foreach ($part in $Path.Split(".")) {

        if ($null -eq $current) {
            return $null
        }

        $property = $current.PSObject.Properties[$part]

        if ($null -eq $property) {
            return $null
        }

        $current = $property.Value
    }

    return $current
}


function Get-FirstValue {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    foreach ($path in $Paths) {

        $value = Get-NestedValue `
            -Object $Object `
            -Path $path

        if ($null -eq $value) {
            continue
        }

        if (
            $value -is [string] -and
            [string]::IsNullOrWhiteSpace($value)
        ) {
            continue
        }

        return $value
    }

    return $null
}


function Convert-WindowsNdjsonRecordToM3 {
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$RawLine,

        [Parameter(Mandatory = $true)]
        [int]$LineNumber
    )

    $timestamp = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "@timestamp",
            "timestamp",
            "TimeCreated.SystemTime"
        )

    if ($null -eq $timestamp) {
        throw "NDJSON line $LineNumber is missing a timestamp."
    }

    try {
        $timestamp = [DateTimeOffset]::Parse(
            [string]$timestamp,
            [Globalization.CultureInfo]::InvariantCulture
        ).UtcDateTime.ToString("o")
    }
    catch {
        throw "NDJSON line $LineNumber has an invalid timestamp: $timestamp"
    }

    $eventId = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "event.code",
            "winlog.event_id",
            "event_id",
            "EventID"
        )

    if ($null -eq $eventId) {
        throw "NDJSON line $LineNumber is missing an event ID."
    }

    $computerName = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "host.name",
            "winlog.computer_name",
            "Computer",
            "computer"
        )

    $rawXml = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "raw_xml"
        )

    # If the old M2 NDJSON contains raw_xml,
    # recover the host name from the original Windows XML.
    if (
        $null -eq $computerName -and
        $null -ne $rawXml
    ) {
        try {
            $xml = [xml][string]$rawXml

            $computerNode = $xml.SelectSingleNode(
                "/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Computer']"
            )

            if ($null -ne $computerNode) {
                $computerName = [string]$computerNode.InnerText
            }
        }
        catch {
            throw "NDJSON line $LineNumber contains invalid raw_xml."
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$computerName)) {
        throw "NDJSON line $LineNumber is missing the computer/host name required by M3."
    }

    $provider = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "event.provider",
            "winlog.provider_name",
            "provider"
        )

    if ($null -eq $provider) {
        $provider = "Microsoft-Windows-Security-Auditing"
    }

    $recordId = Get-FirstValue `
        -Object $Record `
        -Paths @(
            "winlog.record_id",
            "record_id",
            "EventRecordID"
        )

    $eventData = [ordered]@{}

    # Recover decoded fields from raw Windows XML when available.
    if ($null -ne $rawXml) {

        $xmlEventData = Get-EventDataMap `
            -XmlText ([string]$rawXml)

        foreach ($key in $xmlEventData.Keys) {
            $eventData[$key] = $xmlEventData[$key]
        }
    }

    # Keep already-decoded winlog.event_data fields.
    $existingEventData = Get-NestedValue `
        -Object $Record `
        -Path "winlog.event_data"

    if ($null -ne $existingEventData) {

        foreach ($property in $existingEventData.PSObject.Properties) {
            $eventData[$property.Name] = $property.Value
        }
    }

    # Support common flat Windows Security aliases.
    $windowsFields = @(
        "TargetUserName",
        "TargetDomainName",
        "IpAddress",
        "IpPort",
        "LogonType",
        "Status"
    )

    foreach ($field in $windowsFields) {

        $value = Get-FirstValue `
            -Object $Record `
            -Paths @($field)

        if ($null -ne $value) {
            $eventData[$field] = $value
        }
    }

    $normalized = [ordered]@{
        "@timestamp" = $timestamp

        event = [ordered]@{
            code     = [string]$eventId
            provider = [string]$provider
            dataset  = "windows.security"
        }

        host = [ordered]@{
            name = [string]$computerName
        }

        winlog = [ordered]@{
            channel       = "Security"
            provider_name = [string]$provider
            event_id      = $eventId
            record_id     = $recordId
            computer_name = [string]$computerName
            event_data    = $eventData
        }

        source_type = "windows-security"

        # Preserve the exact original NDJSON input.
        raw_line = $RawLine
    }

    if ($null -ne $rawXml) {
        $normalized["raw_xml"] = [string]$rawXml
    }

    return [PSCustomObject]$normalized
}


function Write-Utf8NoBomLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )

    [System.IO.File]::WriteAllLines(
        $Path,
        $Lines,
        [Text.UTF8Encoding]::new($false)
    )
}


function Send-LinesToLogstash {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )

    $client = $null
    $stream = $null
    $writer = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient

        $client.Connect(
            $LogstashHost,
            $LogstashPort
        )

        $stream = $client.GetStream()

        $writer = New-Object System.IO.StreamWriter(
            $stream,
            [Text.UTF8Encoding]::new($false)
        )

        $writer.NewLine = "`n"

        foreach ($line in $Lines) {

            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $writer.WriteLine($line)
        }

        $writer.Flush()
    }
    finally {

        if ($null -ne $writer) {
            $writer.Dispose()
        }

        if ($null -ne $stream) {
            $stream.Dispose()
        }

        if ($null -ne $client) {
            $client.Close()
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
        -Path $dropFolder |
        Out-Null

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $outputFolder |
        Out-Null

    $files = @(
        Get-ChildItem `
            -Path $dropFolder `
            -File `
            -ErrorAction Stop |
        Where-Object {
            $_.Extension -ieq ".evtx" -or
            $_.Extension -ieq ".ndjson"
        }
    )

    if ($files.Count -eq 0) {
        Write-Host "No EVTX or NDJSON files found in $dropFolder"
        exit 0
    }

    foreach ($file in $files) {

        Write-Host "Reading $($file.Name)..."

        $outputLines = @()

        if ($file.Extension -ieq ".evtx") {

            # Materialise the read before sending anything.
            # A Get-WinEvent read error therefore stops this file
            # instead of falsely reporting success.
            $events = @(
                Get-WinEvent `
                    -Path $file.FullName `
                    -ErrorAction Stop
            )

            foreach ($event in $events) {

                $normalized = Convert-WindowsSecurityEventToM3 `
                    -Event $event

                $outputLines += (
                    $normalized |
                    ConvertTo-Json `
                        -Depth 20 `
                        -Compress
                )
            }

            $outputFile = Join-Path `
                $outputFolder `
                ($file.BaseName + ".ndjson")
        }
        else {

            $inputLines = [System.IO.File]::ReadAllLines(
                $file.FullName
            )

            for (
                $i = 0;
                $i -lt $inputLines.Length;
                $i++
            ) {
                $rawLine = [string]$inputLines[$i]

                if ([string]::IsNullOrWhiteSpace($rawLine)) {
                    continue
                }

                try {
                    $record = $rawLine |
                        ConvertFrom-Json `
                            -ErrorAction Stop
                }
                catch {
                    throw "Invalid JSON in $($file.Name) at line $($i + 1): $($_.Exception.Message)"
                }

                $normalized = Convert-WindowsNdjsonRecordToM3 `
                    -Record $record `
                    -RawLine $rawLine `
                    -LineNumber ($i + 1)

                $outputLines += (
                    $normalized |
                    ConvertTo-Json `
                        -Depth 20 `
                        -Compress
                )
            }

            $outputFile = Join-Path `
                $outputFolder `
                ($file.BaseName + ".normalized.ndjson")
        }

        Write-Utf8NoBomLines `
            -Path $outputFile `
            -Lines $outputLines

        Write-Host "Created: $outputFile"
        Write-Host "Prepared $($outputLines.Count) event(s)."

        Write-Host "Sending events to Logstash..."

        Send-LinesToLogstash `
            -Lines $outputLines

        Write-Host "Sent $($outputLines.Count) event(s) to Logstash successfully."
    }

    Write-Host "Windows pull completed successfully."
}
catch {
    Write-Error "Windows pull failed: $($_.Exception.Message)"
    exit 1
}