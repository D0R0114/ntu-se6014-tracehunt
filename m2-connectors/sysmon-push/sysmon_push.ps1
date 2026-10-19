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


function Read-Checkpoint {
    if (-not (Test-Path $checkpointPath)) {
        return [long]0
    }

    try {
        $content = [System.IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        )

        if ([string]::IsNullOrWhiteSpace($content)) {
            return [long]0
        }

        $checkpoint = $content |
            ConvertFrom-Json `
                -ErrorAction Stop

        if ($null -eq $checkpoint.last_record_id) {
            throw "Checkpoint does not contain last_record_id."
        }

        return [long]$checkpoint.last_record_id
    }
    catch {
        throw "Failed to read checkpoint: $($_.Exception.Message)"
    }
}


function Save-Checkpoint {
    param(
        [Parameter(Mandatory = $true)]
        [long]$RecordId
    )

    $checkpointObject = [ordered]@{
        last_record_id = $RecordId
        updated_at     = (
            Get-Date
        ).ToUniversalTime().ToString("o")
    }

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

    $fullyQualifiedErrorId = [string]$ErrorRecord.FullyQualifiedErrorId

    if (
        $fullyQualifiedErrorId -like
        "NoMatchingEventsFound*"
    ) {
        return $true
    }

    $message = [string]$ErrorRecord.Exception.Message

    if (
        $message -match
        "(?i)NoMatchingEventsFound|No events were found that match"
    ) {
        return $true
    }

    return $false
}


function Get-SysmonPollResult {
    param(
        [Parameter(Mandatory = $true)]
        [long]$AfterRecordId
    )

    # Read the complete Event ID 1 snapshot first.
    #
    # We deliberately do not use -MaxEvents here. Besides avoiding burst
    # loss, the snapshot lets us recognise the reviewer-reproduced reset
    # case where the persisted checkpoint belongs to an older log
    # generation (for example checkpoint 20, current records 1..3).
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
            # An empty Event ID 1 selection is a normal idle poll.
            return [PSCustomObject]@{
                events         = @()
                reset_detected = $false
            }
        }

        # Any other Get-WinEvent failure remains visible to the caller.
        throw
    }

    if ($availableEvents.Count -eq 0) {
        return [PSCustomObject]@{
            events         = @()
            reset_detected = $false
        }
    }

    $highestRecordId = [long](
        $availableEvents[-1].RecordId
    )

    $resetDetected = (
        $AfterRecordId -gt 0 -and
        $highestRecordId -lt $AfterRecordId
    )

    if ($resetDetected) {
        # The current Event ID 1 generation is entirely below the
        # persisted checkpoint. Treat it as a cleared/recreated log
        # instead of silently waiting for RecordId to exceed the old
        # generation's checkpoint.
        $newEvents = @($availableEvents)
    }
    else {
        $newEvents = @(
            $availableEvents |
            Where-Object {
                [long]$_.RecordId -gt $AfterRecordId
            }
        )
    }

    return [PSCustomObject]@{
        events         = @($newEvents)
        reset_detected = $resetDetected
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

    $lastRecordId = Read-Checkpoint

    Write-Host "Sysmon push connector started."
    Write-Host "Log: $logName"
    Write-Host "Checkpoint: $lastRecordId"

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
            -AfterRecordId $lastRecordId

        if ($pollResult.reset_detected) {
            Write-Warning (
                "Sysmon Event ID 1 RecordId moved below " +
                "checkpoint $lastRecordId. " +
                "Treating this as an event-log reset/recreation."
            )

            # Persist generation reset before sending. If a send fails,
            # the next run starts from 0 and retries the current
            # generation instead of restoring the stale old checkpoint.
            Save-Checkpoint -RecordId 0
            $lastRecordId = [long]0
        }

        $events = @($pollResult.events)

        if ($events.Count -gt 0) {
            Write-Host (
                "Found $($events.Count) new " +
                "Sysmon Event ID 1 record(s)."
            )
        }
        else {
            Write-Host "No new Sysmon Event ID 1 records."
        }

        foreach ($event in $events) {
            $recordId = [long]$event.RecordId

            try {
                $normalized = Convert-SysmonEventToM3 `
                    -Event $event

                $payload = $normalized |
                    ConvertTo-Json `
                        -Depth 20 `
                        -Compress

                Send-PayloadToLogstash `
                    -Payload $payload

                # Advance checkpoint only after a successful send.
                Save-Checkpoint `
                    -RecordId $recordId

                $lastRecordId = $recordId

                Write-Host (
                    "Sent Sysmon Event ID " +
                    "$($event.Id), record $recordId"
                )
            }
            catch {
                $reason = $_.Exception.Message

                # If conversion itself is bad, retain the rejected
                # event and advance past it so one damaged record
                # cannot block every later event.
                #
                # If Logstash sending failed, do NOT advance:
                # the event will be retried on the next run.
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
                    -RecordId $recordId

                $lastRecordId = $recordId

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
