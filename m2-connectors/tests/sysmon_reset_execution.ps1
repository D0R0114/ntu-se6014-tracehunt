$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)

    if ([string]$Actual -ne [string]$Expected) {
        throw "$Message | expected=[$Expected] actual=[$Actual]"
    }
}

function Assert-Sequence {
    param(
        [object[]]$Actual,
        [object[]]$Expected,
        [string]$Message
    )

    $actualText = (@($Actual) | ForEach-Object { [string]$_ }) -join ","
    $expectedText = (@($Expected) | ForEach-Object { [string]$_ }) -join ","

    if ($actualText -ne $expectedText) {
        throw "$Message | expected=[$expectedText] actual=[$actualText]"
    }
}

function Start-TcpRecorder {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [int]$ExpectedLines = 3
    )

    return Start-Job -ArgumentList @(
        $Port,
        $ExpectedLines
    ) -ScriptBlock {
        param(
            $Port,
            $ExpectedLines
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
            $deadline = [DateTime]::UtcNow.AddSeconds(12)

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
                lines     = @($lines)
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
    param($Job)

    $null = Wait-Job -Job $Job -Timeout 20

    if ($Job.State -eq "Running") {
        Stop-Job -Job $Job
        Remove-Job -Job $Job
        throw "TCP recorder timed out."
    }

    $result = Receive-Job -Job $Job
    Remove-Job -Job $Job

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
    [ValidateSet("reset", "empty", "failure")]
    [string]$Mode,

    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

function New-FakeSysmonEvent {
    param(
        [Parameter(Mandatory = $true)]
        [long]$RecordId
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
<Data Name='ProcessGuid'>{TEST-$RecordId}</Data>
<Data Name='ProcessId'>$RecordId</Data>
<Data Name='Image'>C:\Windows\System32\cmd.exe</Data>
<Data Name='CommandLine'>cmd.exe /c echo $RecordId</Data>
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
        -Value {
            return $this.Xml
        }

    return $event
}

function Get-WinEvent {
    [CmdletBinding()]
    param(
        $FilterHashtable
    )

    switch ($Mode) {
        "reset" {
            return @(
                New-FakeSysmonEvent -RecordId 1
                New-FakeSysmonEvent -RecordId 2
                New-FakeSysmonEvent -RecordId 3
            )
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

    $process = Start-Process `
        -FilePath $ShellPath `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $HarnessPath,
            "-ConnectorPath", $ConnectorPath,
            "-Mode", $Mode,
            "-Port", [string]$Port
        ) `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath

    return [int]$process.ExitCode
}

$m2Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

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

    # -----------------------------------------------------------------
    # Case 1: old checkpoint 20, recreated log now contains IDs 1,2,3.
    # All three must be sent and the checkpoint must end at 3.
    # -----------------------------------------------------------------
    $checkpoint20 = [ordered]@{
        last_record_id = 20
        updated_at     = "2026-10-19T07:00:00.0000000Z"
    } | ConvertTo-Json -Compress

    [IO.File]::WriteAllText(
        $checkpointPath,
        $checkpoint20,
        [Text.UTF8Encoding]::new($false)
    )

    $port = Get-Random -Minimum 25000 -Maximum 45000
    $receiver = Start-TcpRecorder -Port $port

    Start-Sleep -Milliseconds 700

    $resetOut = Join-Path $tempRoot "reset.stdout.txt"
    $resetErr = Join-Path $tempRoot "reset.stderr.txt"

    $resetExit = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "reset" `
        -Port $port `
        -StdoutPath $resetOut `
        -StderrPath $resetErr

    $capture = Receive-RecorderResult -Job $receiver

    Assert-Equal $resetExit 0 "Reset case exit code"
    Assert-Equal @($capture.lines).Count 3 "Reset case sent count"

    $recordIds = @(
        foreach ($line in @($capture.lines)) {
            $payload = $line | ConvertFrom-Json
            [long]$payload.winlog.record_id
        }
    )

    Assert-Sequence `
        -Actual $recordIds `
        -Expected @(1, 2, 3) `
        -Message "Reset case sent RecordIds"

    $checkpointAfterReset = [IO.File]::ReadAllText(
        $checkpointPath,
        [Text.Encoding]::UTF8
    ) | ConvertFrom-Json

    Assert-Equal `
        $checkpointAfterReset.last_record_id `
        3 `
        "Checkpoint after event-log reset"

    # -----------------------------------------------------------------
    # Case 2: NoMatchingEventsFound is a normal idle poll.
    # It must exit 0 and preserve the checkpoint.
    # -----------------------------------------------------------------
    $emptyOut = Join-Path $tempRoot "empty.stdout.txt"
    $emptyErr = Join-Path $tempRoot "empty.stderr.txt"

    $emptyExit = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "empty" `
        -Port 1 `
        -StdoutPath $emptyOut `
        -StderrPath $emptyErr

    Assert-Equal $emptyExit 0 "NoMatchingEventsFound exit code"

    $checkpointAfterEmpty = [IO.File]::ReadAllText(
        $checkpointPath,
        [Text.Encoding]::UTF8
    ) | ConvertFrom-Json

    Assert-Equal `
        $checkpointAfterEmpty.last_record_id `
        3 `
        "Idle poll must preserve checkpoint"

    # -----------------------------------------------------------------
    # Case 3: a genuine Get-WinEvent read failure remains visible.
    # -----------------------------------------------------------------
    $failureOut = Join-Path $tempRoot "failure.stdout.txt"
    $failureErr = Join-Path $tempRoot "failure.stderr.txt"

    $failureExit = Invoke-Harness `
        -ShellPath $shellPath `
        -HarnessPath $harnessPath `
        -ConnectorPath $connectorPath `
        -Mode "failure" `
        -Port 1 `
        -StdoutPath $failureOut `
        -StderrPath $failureErr

    Assert-Equal $failureExit 1 "Real read failure exit code"

    Write-Host "[PASS] Sysmon reset and empty-poll execution tests"
    Write-Host "Reset sent RecordIds: 1,2,3"
    Write-Host "Checkpoint after reset: 3"
    Write-Host "NoMatchingEventsFound exit: 0"
    Write-Host "Real read failure exit: 1"
    exit 0
}
catch {
    Write-Host (
        "[FAIL] Sysmon reset and empty-poll execution tests - " +
        $_.Exception.Message
    )

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
