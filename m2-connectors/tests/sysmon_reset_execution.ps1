$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)

    if ([string]$Actual -ne [string]$Expected) {
        throw "$Message | expected=[$Expected] actual=[$Actual]"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Sequence {
    param(
        [object[]]$Actual,
        [object[]]$Expected,
        [string]$Message
    )

    $actualText = (
        @($Actual) |
        ForEach-Object { [string]$_ }
    ) -join ","

    $expectedText = (
        @($Expected) |
        ForEach-Object { [string]$_ }
    ) -join ","

    if ($actualText -ne $expectedText) {
        throw "$Message | expected=[$expectedText] actual=[$actualText]"
    }
}

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash($bytes)

        return (
            [BitConverter]::ToString($hash).
            Replace("-", "").
            ToLowerInvariant()
        )
    }
    finally {
        $sha.Dispose()
    }
}

function Write-CheckpointFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Value
    )

    $json = $Value | ConvertTo-Json -Depth 10 -Compress

    [IO.File]::WriteAllText(
        $Path,
        $json,
        [Text.UTF8Encoding]::new($false)
    )
}

function Read-CheckpointFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (
        [IO.File]::ReadAllText(
            $Path,
            [Text.Encoding]::UTF8
        ) | ConvertFrom-Json
    )
}

function Start-TcpRecorder {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedLines
    )

    return Start-Job -ArgumentList @(
        $Port,
        $ExpectedLines
    ) -ScriptBlock {
        param(
            [int]$Port,
            [int]$ExpectedLines
        )

        $ErrorActionPreference = "Stop"
        $listener = $null

        try {
            $listener = New-Object System.Net.Sockets.TcpListener(
                [Net.IPAddress]::Loopback,
                $Port
            )

            $listener.Start()

            $lines = New-Object System.Collections.Generic.List[string]
            $deadline = [DateTime]::UtcNow.AddSeconds(30)

            while (
                $lines.Count -lt $ExpectedLines -and
                [DateTime]::UtcNow -lt $deadline
            ) {
                if (-not $listener.Pending()) {
                    Start-Sleep -Milliseconds 50
                    continue
                }

                $client = $null
                $reader = $null

                try {
                    $client = $listener.AcceptTcpClient()

                    $reader = New-Object System.IO.StreamReader(
                        $client.GetStream(),
                        [Text.UTF8Encoding]::new($false)
                    )

                    while (($line = $reader.ReadLine()) -ne $null) {
                        $lines.Add($line)
                    }
                }
                finally {
                    if ($null -ne $reader) {
                        $reader.Dispose()
                    }

                    if ($null -ne $client) {
                        $client.Close()
                    }
                }
            }

            return [PSCustomObject]@{
                lines     = @($lines.ToArray())
                timed_out = ($lines.Count -lt $ExpectedLines)
            }
        }
        finally {
            if ($null -ne $listener) {
                $listener.Stop()
            }
        }
    }
}

function Receive-RecorderResult {
    param(
        [Parameter(Mandatory = $true)]
        $Job
    )

    $null = Wait-Job -Job $Job -Timeout 35

    if ($Job.State -eq "Running") {
        Stop-Job -Job $Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue

        throw "TCP recorder timed out."
    }

    $result = Receive-Job -Job $Job

    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue

    if ($null -eq $result) {
        throw "TCP recorder returned no result."
    }

    return $result
}

function Write-MockHarness {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$ConnectorPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "reset",
        "reset25",
        "legacyMissingAnchor",
        "empty",
        "failure"
    )]
    [string]$Mode,

    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

function New-FakeSysmonEvent {
    param(
        [Parameter(Mandatory = $true)]
        [long]$RecordId,

        [string]$Generation = "NEW"
    )

    $xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Sysmon'/>
<EventID>1</EventID>
<TimeCreated SystemTime='2026-10-19T08:00:00.0000000Z'/>
<EventRecordID>$RecordId</EventRecordID>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>RESET-PC</Computer>
</System>
<EventData>
<Data Name='UtcTime'>2026-10-19 08:00:00.000</Data>
<Data Name='ProcessGuid'>{${Generation}-$RecordId}</Data>
<Data Name='ProcessId'>$RecordId</Data>
<Data Name='Image'>C:\Windows\System32\cmd.exe</Data>
<Data Name='CommandLine'>cmd.exe /c echo $Generation-$RecordId</Data>
<Data Name='User'>TEST\user</Data>
<Data Name='ParentProcessId'>100</Data>
<Data Name='ParentImage'>C:\Windows\explorer.exe</Data>
</EventData>
</Event>
"@

    $event = [pscustomobject]@{
        Id           = 1
        RecordId     = $RecordId
        ProviderName = "Microsoft-Windows-Sysmon"
        LogName      = "Microsoft-Windows-Sysmon/Operational"
        MachineName  = "RESET-PC"
        TimeCreated  = [datetime]::Parse(
            "2026-10-19T08:00:00Z"
        ).ToUniversalTime()
        Xml          = $xml
    }

    $event | Add-Member `
        -MemberType ScriptMethod `
        -Name ToXml `
        -Value { return $this.Xml }

    return $event
}

function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable)

    switch ($Mode) {
        "reset" {
            return @(
                New-FakeSysmonEvent -RecordId 1
                New-FakeSysmonEvent -RecordId 2
                New-FakeSysmonEvent -RecordId 3
            )
        }

        "reset25" {
            return @(foreach ($id in (1..25)) {
                New-FakeSysmonEvent `
                    -RecordId $id `
                    -Generation "NEW"
            })
        }

        "legacyMissingAnchor" {
            $ids = @((1..19) + (21..25))

            return @(foreach ($id in $ids) {
                New-FakeSysmonEvent `
                    -RecordId $id `
                    -Generation "NEW"
            })
        }

        "empty" {
            $exception = New-Object System.Exception(
                "No events were found that match the specified selection criteria."
            )

            $errorRecord = New-Object `
                System.Management.Automation.ErrorRecord(
                    $exception,
                    "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand",
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $null
                )

            throw $errorRecord
        }

        "failure" {
            throw "Controlled Get-WinEvent read failure."
        }
    }
}

& $ConnectorPath `
    -Once `
    -LogstashHost "127.0.0.1" `
    -LogstashPort $Port `
    -RetryCount 1 `
    -RetryDelaySeconds 0
'@

    [IO.File]::WriteAllText(
        $Path,
        $content,
        [Text.UTF8Encoding]::new($false)
    )
}

function Invoke-Harness {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShellPath,

        [Parameter(Mandatory = $true)]
        [string]$HarnessPath,

        [Parameter(Mandatory = $true)]
        [string]$ConnectorPath,

        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [int]$Port = 0,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath
    )

    $argumentLine = (
        '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
        '-ConnectorPath "{1}" -Mode "{2}" -Port {3}'
    ) -f $HarnessPath, $ConnectorPath, $Mode, $Port

    $process = Start-Process `
        -FilePath $ShellPath `
        -ArgumentList $argumentLine `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath

    $stdout = ""
    $stderr = ""

    if (Test-Path $StdoutPath) {
        $stdout = [IO.File]::ReadAllText(
            $StdoutPath,
            [Text.Encoding]::UTF8
        )
    }

    if (Test-Path $StderrPath) {
        $stderr = [IO.File]::ReadAllText(
            $StderrPath,
            [Text.Encoding]::UTF8
        )
    }

    return [PSCustomObject]@{
        ExitCode = [int]$process.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
    }
}

function New-OldGenerationEvent20Xml {
    return @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Sysmon'/>
<EventID>1</EventID>
<TimeCreated SystemTime='2026-10-19T07:00:00.0000000Z'/>
<EventRecordID>20</EventRecordID>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>RESET-PC</Computer>
</System>
<EventData>
<Data Name='UtcTime'>2026-10-19 07:00:00.000</Data>
<Data Name='ProcessGuid'>{OLD-20}</Data>
<Data Name='ProcessId'>20</Data>
<Data Name='Image'>C:\Windows\System32\cmd.exe</Data>
<Data Name='CommandLine'>cmd.exe /c echo OLD-20</Data>
<Data Name='User'>TEST\user</Data>
<Data Name='ParentProcessId'>100</Data>
<Data Name='ParentImage'>C:\Windows\explorer.exe</Data>
</EventData>
</Event>
"@
}

$m2Root = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue

if ($null -ne $pwsh) {
    $shellPath = $pwsh.Source
}
else {
    $shellPath = (
        Get-Command powershell.exe -ErrorAction Stop
    ).Source
}

$tempRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ("tracehunt-sysmon-reset-" + [Guid]::NewGuid().ToString("N"))

try {
    New-Item `
        -ItemType Directory `
        -Force `
        -Path $tempRoot |
        Out-Null

    $testM2Root = Join-Path $tempRoot "m2-connectors"

    Copy-Item `
        -Path $m2Root `
        -Destination $testM2Root `
        -Recurse

    $sysmonRoot = Join-Path $testM2Root "sysmon-push"
    $stateFolder = Join-Path $sysmonRoot "state"
    $checkpointPath = Join-Path $stateFolder "checkpoint.json"
    $connectorPath = Join-Path $sysmonRoot "sysmon_push.ps1"
    $harnessPath = Join-Path $tempRoot "sysmon_mock_harness.ps1"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $stateFolder |
        Out-Null

    Write-MockHarness -Path $harnessPath

    # Case 1: checkpoint ahead of recreated log.

    Write-CheckpointFile `
        -Path $checkpointPath `
        -Value ([ordered]@{
            last_record_id = 20
            updated_at = "2026-10-19T07:00:00.0000000Z"
        })

    $port = Get-Random -Minimum 25000 -Maximum 45000

    $receiver = Start-TcpRecorder `
        -Port $port `
        -ExpectedLines 3

    Start-Sleep -Milliseconds 500

    $result = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "reset" `
        -Port $port `
        -StdoutPath (Join-Path $tempRoot "reset.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "reset.stderr.txt")

    $capture = Receive-RecorderResult -Job $receiver

    Assert-Equal $result.ExitCode 0 "Simple reset exit code"
    Assert-True (-not $capture.timed_out) "Simple reset TCP recorder timed out"
    Assert-Equal @($capture.lines).Count 3 "Simple reset sent count"

    $resetIds = @(foreach ($line in $capture.lines) {
        $payload = $line | ConvertFrom-Json
        [long]$payload.winlog.record_id
    })

    Assert-Sequence `
        -Actual $resetIds `
        -Expected @(1, 2, 3) `
        -Message "Simple reset RecordIds"

    $checkpoint = Read-CheckpointFile -Path $checkpointPath

    Assert-Equal $checkpoint.last_record_id 3 "Simple reset checkpoint"

    Assert-True (
        -not [string]::IsNullOrWhiteSpace(
            [string]$checkpoint.last_record_sha256
        )
    ) "Simple reset checkpoint fingerprint missing"

    # Case 2: fingerprint-bearing generation detection.

    $oldEvent20Hash = Get-Sha256Hex `
        -Text (New-OldGenerationEvent20Xml)

    Write-CheckpointFile `
        -Path $checkpointPath `
        -Value ([ordered]@{
            last_record_id = 20
            last_record_sha256 = $oldEvent20Hash
            last_event_time_utc = "2026-10-19T07:00:00.0000000Z"
            updated_at = "2026-10-19T07:00:01.0000000Z"
        })

    $port25 = Get-Random -Minimum 25000 -Maximum 45000

    $receiver25 = Start-TcpRecorder `
        -Port $port25 `
        -ExpectedLines 25

    Start-Sleep -Milliseconds 500

    $result25 = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "reset25" `
        -Port $port25 `
        -StdoutPath (Join-Path $tempRoot "reset25.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "reset25.stderr.txt")

    $capture25 = Receive-RecorderResult -Job $receiver25

    Assert-Equal $result25.ExitCode 0 "Fingerprint generation exit code"
    Assert-True (-not $capture25.timed_out) "Fingerprint generation recorder timed out"
    Assert-Equal @($capture25.lines).Count 25 "Fingerprint generation sent count"

    $ids25 = @(foreach ($line in $capture25.lines) {
        $payload = $line | ConvertFrom-Json
        [long]$payload.winlog.record_id
    })

    Assert-Sequence `
        -Actual $ids25 `
        -Expected @(1..25) `
        -Message "Fingerprint generation RecordIds"

    $checkpoint25 = Read-CheckpointFile -Path $checkpointPath

    Assert-Equal $checkpoint25.last_record_id 25 "Fingerprint generation checkpoint"

    Assert-True (
        -not [string]::IsNullOrWhiteSpace(
            [string]$checkpoint25.last_record_sha256
        )
    ) "Fingerprint generation checkpoint hash missing"

    Assert-True (
        [string]$checkpoint25.last_record_sha256 -ne $oldEvent20Hash
    ) "Fingerprint generation checkpoint still contains old hash"

    # Case 3: legacy checkpoint without fingerprint; RecordId 20 absent.

    Write-CheckpointFile `
        -Path $checkpointPath `
        -Value ([ordered]@{
            last_record_id = 20
            updated_at = "2026-10-19T07:00:00.0000000Z"
        })

    $port24 = Get-Random -Minimum 25000 -Maximum 45000

    $receiver24 = Start-TcpRecorder `
        -Port $port24 `
        -ExpectedLines 24

    Start-Sleep -Milliseconds 500

    $legacyResult = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "legacyMissingAnchor" `
        -Port $port24 `
        -StdoutPath (Join-Path $tempRoot "legacy.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "legacy.stderr.txt")

    $legacyCapture = Receive-RecorderResult -Job $receiver24

    Assert-Equal $legacyResult.ExitCode 0 "Legacy missing-anchor exit code"
    Assert-True (-not $legacyCapture.timed_out) "Legacy missing-anchor recorder timed out"
    Assert-Equal @($legacyCapture.lines).Count 24 "Legacy missing-anchor sent count"

    $expectedLegacyIds = @((1..19) + (21..25))

    $legacyIds = @(foreach ($line in $legacyCapture.lines) {
        $payload = $line | ConvertFrom-Json
        [long]$payload.winlog.record_id
    })

    Assert-Sequence `
        -Actual $legacyIds `
        -Expected $expectedLegacyIds `
        -Message "Legacy missing-anchor RecordIds"

    $checkpointAfterLegacy = Read-CheckpointFile -Path $checkpointPath

    Assert-Equal $checkpointAfterLegacy.last_record_id 25 "Legacy checkpoint after migration"

    Assert-True (
        -not [string]::IsNullOrWhiteSpace(
            [string]$checkpointAfterLegacy.last_record_sha256
        )
    ) "Legacy checkpoint fingerprint missing after migration"

    # Case 4: second run must not replay the 24 sent records.
    # Port 1 has no listener; accidental replay should fail.

    $secondRun = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "legacyMissingAnchor" `
        -Port 1 `
        -StdoutPath (Join-Path $tempRoot "legacy-second.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "legacy-second.stderr.txt")

    Assert-Equal $secondRun.ExitCode 0 "Legacy second run exit code"

    Assert-True (
        $secondRun.Stdout -notmatch "Sent Sysmon Event ID"
    ) "Legacy second run replayed records"

    $checkpointAfterSecondRun = Read-CheckpointFile -Path $checkpointPath

    Assert-Equal $checkpointAfterSecondRun.last_record_id 25 "Checkpoint after second run"

    Assert-Equal `
        $checkpointAfterSecondRun.last_record_sha256 `
        $checkpointAfterLegacy.last_record_sha256 `
        "Checkpoint hash must remain unchanged on second run"

    # Case 5: no matching events is a normal idle poll.

    $emptyResult = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "empty" `
        -Port 1 `
        -StdoutPath (Join-Path $tempRoot "empty.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "empty.stderr.txt")

    Assert-Equal $emptyResult.ExitCode 0 "NoMatchingEventsFound exit code"

    $checkpointAfterEmpty = Read-CheckpointFile -Path $checkpointPath

    Assert-Equal $checkpointAfterEmpty.last_record_id 25 "Idle poll must preserve checkpoint"

    # Case 6: a genuine Get-WinEvent failure must remain visible.

    $failureResult = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "failure" `
        -Port 1 `
        -StdoutPath (Join-Path $tempRoot "failure.stdout.txt") `
        -StderrPath (Join-Path $tempRoot "failure.stderr.txt")

    Assert-Equal $failureResult.ExitCode 1 "Genuine read failure exit code"

    Write-Host "[PASS] Sysmon reset, fingerprint generation, legacy missing-anchor migration,"
    Write-Host "       second-run no-replay, idle poll, and genuine read-failure tests."
    Write-Host "Simple reset sent RecordIds: 1,2,3"
    Write-Host "Fingerprint generation sent RecordIds: 1..25"
    Write-Host "Legacy migration sent RecordIds: 1..19,21..25 (24 records)"
    Write-Host "Second run replayed no records."

    exit 0
}
catch {
    Write-Host "[FAIL] Sysmon checkpoint execution tests - $($_.Exception.Message)"
    exit 1
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item `
            -LiteralPath $tempRoot `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}