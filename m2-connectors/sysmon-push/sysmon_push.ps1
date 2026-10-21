
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

$logName = "Microsoft-Windows-Sysmon/Operational"

$m2Root = Split-Path -Parent $PSScriptRoot
$adapterPath = Join-Path $m2Root "common\m3_adapter.ps1"

$stateFolder = Join-Path $PSScriptRoot "state"
$checkpointPath = Join-Path $stateFolder "checkpoint.json"

$rejectedFolder = Join-Path $PSScriptRoot "rejected"
$rejectedPath = Join-Path $rejectedFolder "sysmon_rejected.ndjson"


function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        $Text
    )

    $sha = [Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash($bytes)

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


function Get-EventFingerprint {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    $xml = $Event.ToXml()

    if ([string]::IsNullOrWhiteSpace([string]$xml)) {
        throw "Cannot fingerprint an event with empty XML."
    }

    return Get-Sha256Hex -Text ([string]$xml)
}


function Get-EventTimeUtc {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    if ($null -eq $Event.TimeCreated) {
        return $null
    }

    return $Event.TimeCreated.
        ToUniversalTime().
        ToString("o")
}


function Read-Checkpoint {

    $emptyCheckpoint = [PSCustomObject]@{
        last_record_id       = [long]0
        last_record_sha256   = $null
        last_event_time_utc  = $null
        updated_at           = $null
    }

    if (-not (Test-Path $checkpointPath)) {
        return $emptyCheckpoint
    }

    try {
        $content = [System.IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        )

        if ([string]::IsNullOrWhiteSpace($content)) {
            return $emptyCheckpoint
        }

        $checkpoint = $content |
            ConvertFrom-Json `
                -ErrorAction Stop

        if ($null -eq $checkpoint.last_record_id) {
            throw "Checkpoint does not contain last_record_id."
        }

        $shaProperty = $checkpoint.PSObject.Properties[
            "last_record_sha256"
        ]

        if ($null -ne $shaProperty) {
            $recordSha256 = [string]$shaProperty.Value
        }
        else {
            $recordSha256 = $null
        }

        $eventTimeProperty = $checkpoint.PSObject.Properties[
            "last_event_time_utc"
        ]

        if ($null -ne $eventTimeProperty) {
            $eventTimeUtc = [string]$eventTimeProperty.Value
        }
        else {
            $eventTimeUtc = $null
        }

        $updatedProperty = $checkpoint.PSObject.Properties[
            "updated_at"
        ]

        if ($null -ne $updatedProperty) {
            $updatedAt = ([DateTimeOffset]$updatedProperty.Value).ToUniversalTime().ToString("o")
        }
        else {
            $updatedAt = $null
        }

        return [PSCustomObject]@{
            last_record_id       = [long]$checkpoint.last_record_id
            last_record_sha256   = $recordSha256
            last_event_time_utc  = $eventTimeUtc
            updated_at           = $updatedAt
        }
    }
    catch {
        throw "Failed to read checkpoint: $($_.Exception.Message)"
    }
}


function Save-Checkpoint {
    param(
        [Parameter(Mandatory = $true)]
        [long]$RecordId,

        [string]$RecordSha256,

        [string]$EventTimeUtc
    )

    $checkpointObject = [ordered]@{
        last_record_id = $RecordId
    }

    if (
        -not [string]::IsNullOrWhiteSpace(
            $RecordSha256
        )
    ) {
        $checkpointObject["last_record_sha256"] =
            $RecordSha256
    }

    if (
        -not [string]::IsNullOrWhiteSpace(
            $EventTimeUtc
        )
    ) {
        $checkpointObject["last_event_time_utc"] =
            $EventTimeUtc
    }

    $checkpointObject["updated_at"] = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    $json = $checkpointObject |
        ConvertTo-Json `
            -Compress

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


function Write-RejectedEvent {
    param(
        [Parameter(Mandatory = $true)]
        $Event,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $rawXml = $null

    try {
        $rawXml = $Event.ToXml()
    }
    catch {
        $rawXml = $null
    }

    $rejected = [ordered]@{
        timestamp   = (
            Get-Date
        ).ToUniversalTime().ToString("o")

        source_type = "sysmon"
        record_id   = $Event.RecordId
        event_id    = $Event.Id
        reason      = $Reason
        raw_xml     = $rawXml
    }

    $line = $rejected |
        ConvertTo-Json `
            -Depth 10 `
            -Compress

    [System.IO.File]::AppendAllText(
        $rejectedPath,
        $line + "`n",
        [Text.UTF8Encoding]::new($false)
    )
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
        $client = $null
        $stream = $null
        $writer = $null

        try {
            $client = New-Object `
                System.Net.Sockets.TcpClient

            $client.Connect(
                $LogstashHost,
                $LogstashPort
            )

            $stream = $client.GetStream()

            $writer = New-Object `
                System.IO.StreamWriter(
                    $stream,
                    [Text.UTF8Encoding]::new($false)
                )

            $writer.NewLine = "`n"
            $writer.AutoFlush = $true

            $writer.WriteLine($Payload)
            $writer.Flush()

            return
        }
        catch {
            $lastError = $_

            if ($attempt -lt $RetryCount) {
                Write-Warning (
                    "Logstash send failed " +
                    "(attempt $attempt/$RetryCount). " +
                    "Retrying..."
                )

                Start-Sleep `
                    -Seconds $RetryDelaySeconds
            }
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

    throw (
        "Failed to send event to Logstash after " +
        "$RetryCount attempt(s): " +
        $lastError.Exception.Message
    )
}


function Test-IsNoMatchingEventsError {
    param(
        [Parameter(Mandatory = $true)]
        $ErrorRecord
    )

    $fullyQualifiedErrorId =
        [string]$ErrorRecord.FullyQualifiedErrorId

    if (
        $fullyQualifiedErrorId -like
        "NoMatchingEventsFound*"
    ) {
        return $true
    }

    $message =
        [string]$ErrorRecord.Exception.Message

    if (
        $message -match
        "(?i)NoMatchingEventsFound|No events were found that match"
    ) {
        return $true
    }

    return $false
}


function Test-CheckpointGeneration {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AvailableEvents,

        [Parameter(Mandatory = $true)]
        $Checkpoint
    )

    $checkpointId =
        [long]$Checkpoint.last_record_id

    if ($checkpointId -le 0) {
        return [PSCustomObject]@{
            reset_detected = $false
            reason         = $null
        }
    }

    if ($AvailableEvents.Count -eq 0) {
        return [PSCustomObject]@{
            reset_detected = $false
            reason         = $null
        }
    }

    $highestRecordId =
        [long]$AvailableEvents[-1].RecordId

    if ($highestRecordId -lt $checkpointId) {
        return [PSCustomObject]@{
            reset_detected = $true
            reason         = (
                "current highest RecordId $highestRecordId " +
                "is below checkpoint $checkpointId"
            )
        }
    }

    $checkpointEvent = @(
        $AvailableEvents |
        Where-Object {
            [long]$_.RecordId -eq $checkpointId
        }
    ) |
        Select-Object -First 1

    $savedHash =
        [string]$Checkpoint.last_record_sha256

    if (
        -not [string]::IsNullOrWhiteSpace(
            $savedHash
        )
    ) {
        if ($null -ne $checkpointEvent) {
            $currentHash = Get-EventFingerprint `
                -Event $checkpointEvent

            if ($currentHash -ne $savedHash) {
                return [PSCustomObject]@{
                    reset_detected = $true
                    reason         = (
                        "checkpoint RecordId $checkpointId " +
                        "now refers to a different event"
                    )
                }
            }

            return [PSCustomObject]@{
                reset_detected = $false
                reason         = $null
            }
        }

        $hasLowerRecord = @(
            $AvailableEvents |
            Where-Object {
                [long]$_.RecordId -lt $checkpointId
            }
        ).Count -gt 0

        $hasHigherRecord = @(
            $AvailableEvents |
            Where-Object {
                [long]$_.RecordId -gt $checkpointId
            }
        ).Count -gt 0

        # If records from both sides of the saved checkpoint still
        # exist but the exact checkpoint event disappeared, this cannot
        # be explained by normal oldest-first log retention. Treat the
        # snapshot as a different generation.
        if (
            $hasLowerRecord -and
            $hasHigherRecord
        ) {
            return [PSCustomObject]@{
                reset_detected = $true
                reason         = (
                    "records exist below and above checkpoint " +
                    "$checkpointId but its fingerprint anchor is absent"
                )
            }
        }

        return [PSCustomObject]@{
            reset_detected = $false
            reason         = $null
        }
    }

    # Backward compatibility for checkpoints written by older versions.
    #
    # Old checkpoints do not contain a fingerprint. If the event with the
    # same RecordId exists but was created after the checkpoint file was
    # written, it must belong to a recreated/newer log generation.
    $savedUpdatedAt =
        [string]$Checkpoint.updated_at

    # Legacy checkpoints have no event fingerprint. If the anchor is absent
    # while records on both sides remain, use event timestamps to distinguish
    # a recreated generation from normal oldest-first retention.
    if (
        $null -eq $checkpointEvent -and
        -not [string]::IsNullOrWhiteSpace($savedUpdatedAt)
    ) {
        $hasLowerRecord = @(
            $AvailableEvents |
            Where-Object {
                [long]$_.RecordId -lt $checkpointId
            }
        ).Count -gt 0

        $hasHigherRecord = @(
            $AvailableEvents |
            Where-Object {
                [long]$_.RecordId -gt $checkpointId
            }
        ).Count -gt 0

        if ($hasLowerRecord -and $hasHigherRecord) {
            try {
                $legacyCheckpointWritten = [DateTimeOffset]::Parse(
                    $savedUpdatedAt,
                    [Globalization.CultureInfo]::InvariantCulture
                )

                $hasLowerRecordCreatedAfterCheckpoint = @(
                    $AvailableEvents |
                    Where-Object {
                        [long]$_.RecordId -lt $checkpointId -and
                        $null -ne $_.TimeCreated -and
                        ([DateTimeOffset]$_.TimeCreated) -gt
                            $legacyCheckpointWritten
                    }
                ).Count -gt 0

                if ($hasLowerRecordCreatedAfterCheckpoint) {
                    return [PSCustomObject]@{
                        reset_detected = $true
                        reason         = (
                            "Legacy checkpoint anchor is absent and lower " +
                            "RecordIds were created after the checkpoint; " +
                            "treating this as a recreated log generation"
                        )
                    }
                }
            }
            catch {
                # If timestamps are unavailable or invalid, do not infer reset.
            }
        }
    }

    if (
        $null -ne $checkpointEvent -and
        -not [string]::IsNullOrWhiteSpace(
            $savedUpdatedAt
        ) -and
        $null -ne $checkpointEvent.TimeCreated
    ) {
        try {
            $checkpointWritten =
                [DateTimeOffset]::Parse(
                    $savedUpdatedAt,
                    [Globalization.CultureInfo]::InvariantCulture
                )

            $eventCreated =
                [DateTimeOffset]$checkpointEvent.TimeCreated

            if ($eventCreated -gt $checkpointWritten) {
                return [PSCustomObject]@{
                    reset_detected = $true
                    reason         = (
                        "legacy checkpoint RecordId $checkpointId " +
                        "now refers to an event created after the " +
                        "checkpoint was written"
                    )
                }
            }
        }
        catch {
            # If legacy timestamp parsing fails, keep the conservative
            # RecordId behavior rather than aborting ingestion.
        }
    }

    return [PSCustomObject]@{
        reset_detected = $false
        reason         = $null
    }
}


function Get-SysmonPollResult {
    param(
        [Parameter(Mandatory = $true)]
        $Checkpoint
    )

    try {
        $availableEvents = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName = $logName
                    Id      = 1
                } `
                -ErrorAction Stop |
            Sort-Object `
                -Property RecordId
        )
    }
    catch {
        if (
            Test-IsNoMatchingEventsError `
                -ErrorRecord $_
        ) {
            return [PSCustomObject]@{
                events         = @()
                reset_detected = $false
                reset_reason   = $null
            }
        }

        throw
    }

    if ($availableEvents.Count -eq 0) {
        return [PSCustomObject]@{
            events         = @()
            reset_detected = $false
            reset_reason   = $null
        }
    }

    $generationResult =
        Test-CheckpointGeneration `
            -AvailableEvents $availableEvents `
            -Checkpoint $Checkpoint

    if ($generationResult.reset_detected) {
        $newEvents = @($availableEvents)
    }
    else {
        $afterRecordId =
            [long]$Checkpoint.last_record_id

        $newEvents = @(
            $availableEvents |
            Where-Object {
                [long]$_.RecordId -gt $afterRecordId
            }
        )
    }

    return [PSCustomObject]@{
        events         = @($newEvents)
        reset_detected = [bool]$generationResult.reset_detected
        reset_reason   = $generationResult.reason
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
        -Path $stateFolder |
        Out-Null

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $rejectedFolder |
        Out-Null

    if ($ResetCheckpoint) {
        Save-Checkpoint -RecordId 0

        Write-Host (
            "Sysmon checkpoint reset to 0. " +
            "Existing Event ID 1 records will be replayed."
        )
    }

    $checkpoint = Read-Checkpoint

    Write-Host "Sysmon push connector started."
    Write-Host "Log: $logName"
    Write-Host (
        "Checkpoint: " +
        $checkpoint.last_record_id
    )

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
        $pollResult = Get-SysmonPollResult `
            -Checkpoint $checkpoint

        if ($pollResult.reset_detected) {
            Write-Warning (
                "Sysmon event-log generation changed. " +
                "Resetting checkpoint. Reason: " +
                $pollResult.reset_reason
            )

            Save-Checkpoint -RecordId 0

            $checkpoint = Read-Checkpoint
        }

        $events = @($pollResult.events)

        if ($events.Count -gt 0) {
            Write-Host (
                "Found $($events.Count) new " +
                "Sysmon Event ID 1 record(s)."
            )
        }
        else {
            Write-Host (
                "No new Sysmon Event ID 1 records."
            )
        }

        foreach ($event in $events) {
            $recordId =
                [long]$event.RecordId

            $recordFingerprint = $null
            $eventTimeUtc = $null

            try {
                $recordFingerprint =
                    Get-EventFingerprint `
                        -Event $event

                $eventTimeUtc =
                    Get-EventTimeUtc `
                        -Event $event

                $normalized =
                    Convert-SysmonEventToM3 `
                        -Event $event

                $payload = $normalized |
                    ConvertTo-Json `
                        -Depth 20 `
                        -Compress

                Send-PayloadToLogstash `
                    -Payload $payload

                Save-Checkpoint `
                    -RecordId $recordId `
                    -RecordSha256 $recordFingerprint `
                    -EventTimeUtc $eventTimeUtc

                $checkpoint = Read-Checkpoint

                Write-Host (
                    "Sent Sysmon Event ID " +
                    "$($event.Id), record $recordId"
                )
            }
            catch {
                $reason =
                    $_.Exception.Message

                if (
                    $reason -like
                    "Failed to send event to Logstash*"
                ) {
                    throw
                }

                Write-RejectedEvent `
                    -Event $event `
                    -Reason $reason

                Save-Checkpoint `
                    -RecordId $recordId `
                    -RecordSha256 $recordFingerprint `
                    -EventTimeUtc $eventTimeUtc

                $checkpoint = Read-Checkpoint

                Write-Warning (
                    "Rejected Sysmon record " +
                    "$recordId`: $reason"
                )
            }
        }

        if (-not $Once) {
            Start-Sleep `
                -Seconds $PollSeconds
        }

    } while (-not $Once)

    Write-Host "Sysmon push run completed."
}
catch {
    Write-Error (
        "Sysmon push failed: " +
        $_.Exception.Message
    )

    exit 1
}
