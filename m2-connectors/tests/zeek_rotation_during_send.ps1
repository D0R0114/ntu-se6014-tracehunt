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

function Get-Sha256Hex {
    param([byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()

    try {
        $hash = $sha.ComputeHash($Bytes)

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

function Start-TcpRecorder {
    param(
        [int]$Port,
        [string]$ReplacementPath,
        [string]$TargetPath,
        [switch]$ReplaceAfterFirstRecord
    )

    return Start-Job -ArgumentList @(
        $Port,
        $ReplacementPath,
        $TargetPath,
        [bool]$ReplaceAfterFirstRecord
    ) -ScriptBlock {
        param(
            $Port,
            $ReplacementPath,
            $TargetPath,
            $DoReplace
        )

        $ErrorActionPreference = "Stop"
        $listener = $null
        $client = $null
        $reader = $null

        try {
            $listener = [Net.Sockets.TcpListener]::new(
                [Net.IPAddress]::Loopback,
                $Port
            )

            $listener.Start()

            $deadline = [DateTime]::UtcNow.AddSeconds(12)

            while (-not $listener.Pending()) {
                if ([DateTime]::UtcNow -ge $deadline) {
                    return [PSCustomObject]@{
                        lines     = @()
                        replaced  = $false
                        timed_out = $true
                    }
                }

                Start-Sleep -Milliseconds 50
            }

            $client = $listener.AcceptTcpClient()
            $reader = New-Object System.IO.StreamReader(
                $client.GetStream(),
                [Text.UTF8Encoding]::new($false)
            )

            $lines = New-Object System.Collections.Generic.List[string]
            $replaced = $false

            while (($line = $reader.ReadLine()) -ne $null) {
                $lines.Add($line)

                if ($DoReplace -and -not $replaced) {
                    # Replace the pathname only after the first old record
                    # has reached the TCP recorder. The connector has already
                    # buffered the old file generation by this point.
                    $backupPath = "$TargetPath.rotation-test.bak"

                    if (Test-Path $backupPath) {
                        Remove-Item `
                            -LiteralPath $backupPath `
                            -Force
                    }

                    [System.IO.File]::Replace(
                        $ReplacementPath,
                        $TargetPath,
                        $backupPath
                    )

                    if (Test-Path $backupPath) {
                        Remove-Item `
                            -LiteralPath $backupPath `
                            -Force
                    }

                    $replaced = $true
                }
            }

            return [PSCustomObject]@{
                lines     = @($lines)
                replaced  = $replaced
                timed_out = $false
            }
        }
        finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }

            if ($null -ne $client) {
                $client.Close()
            }

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

function Invoke-Connector {
    param(
        [string]$ShellPath,
        [string]$ConnectorPath,
        [int]$Port,
        [switch]$ResetCheckpoint,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $ConnectorPath,
        "-Once",
        "-LogstashHost", "127.0.0.1",
        "-LogstashPort", [string]$Port,
        "-RetryCount", "10",
        "-RetryDelaySeconds", "1"
    )

    if ($ResetCheckpoint) {
        $arguments += "-ResetCheckpoint"
    }

    $process = Start-Process `
        -FilePath $ShellPath `
        -ArgumentList $arguments `
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
    $windowsPowerShell = Get-Command powershell.exe -ErrorAction Stop
    $shellPath = $windowsPowerShell.Source
}

$tempRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ("tracehunt-zeek-rotation-" + [Guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

    $testM2Root = Join-Path $tempRoot "m2-connectors"

    Copy-Item `
        -Path $m2Root `
        -Destination $testM2Root `
        -Recurse

    $zeekRoot = Join-Path $testM2Root "zeek-stream"
    $inputFolder = Join-Path $zeekRoot "input"
    $stateFolder = Join-Path $zeekRoot "state"

    New-Item -ItemType Directory -Force -Path $inputFolder | Out-Null
    New-Item -ItemType Directory -Force -Path $stateFolder | Out-Null

    $connectorPath = Join-Path $zeekRoot "zeek_stream.ps1"
    $connPath = Join-Path $inputFolder "conn.log"
    $replacementPath = Join-Path $inputFolder "replacement.tmp"
    $checkpointPath = Join-Path $stateFolder "checkpoints.json"

    $oldLines = @(
        for ($i = 1; $i -le 100; $i++) {
            [PSCustomObject][ordered]@{
                ts          = 1760000000 + $i
                uid         = ("OLD{0:D4}" -f $i)
                "id.orig_h" = "10.0.0.1"
                "id.orig_p" = 50000
                "id.resp_h" = "10.0.0.2"
                "id.resp_p" = 443
                proto       = "tcp"
            } | ConvertTo-Json -Compress
        }
    )

    $newLines = @(
        for ($i = 1; $i -le 100; $i++) {
            [PSCustomObject][ordered]@{
                ts          = 1760000000 + $i
                uid         = ("NEW{0:D4}" -f $i)
                "id.orig_h" = "10.0.0.1"
                "id.orig_p" = 50000
                "id.resp_h" = "10.0.0.2"
                "id.resp_p" = 443
                proto       = "tcp"
            } | ConvertTo-Json -Compress
        }
    )

    $oldText = ($oldLines -join "`n") + "`n"
    $newText = ($newLines -join "`n") + "`n"

    $utf8 = [Text.UTF8Encoding]::new($false)
    $oldBytes = $utf8.GetBytes($oldText)
    $newBytes = $utf8.GetBytes($newText)

    Assert-Equal `
        $oldBytes.Length `
        $newBytes.Length `
        "Old and replacement logs must have equal byte length"

    [IO.File]::WriteAllBytes(
        $connPath,
        $oldBytes
    )

    [IO.File]::WriteAllBytes(
        $replacementPath,
        $newBytes
    )

    $oldHash = Get-Sha256Hex -Bytes $oldBytes
    $newHash = Get-Sha256Hex -Bytes $newBytes

    Assert-True `
        ($oldHash -ne $newHash) `
        "Old and replacement log hashes must differ"

    # First run:
    # after the first old event reaches the recorder, atomically replace
    # conn.log while the connector is still sending its buffered old batch.
    $port1 = Get-Random -Minimum 25000 -Maximum 45000

    $receiver1 = Start-TcpRecorder `
        -Port $port1 `
        -ReplacementPath $replacementPath `
        -TargetPath $connPath `
        -ReplaceAfterFirstRecord

    Start-Sleep -Milliseconds 700

    $stdout1 = Join-Path $tempRoot "run1.stdout.txt"
    $stderr1 = Join-Path $tempRoot "run1.stderr.txt"

    $exit1 = Invoke-Connector `
        -ShellPath $shellPath `
        -ConnectorPath $connectorPath `
        -Port $port1 `
        -ResetCheckpoint `
        -StdoutPath $stdout1 `
        -StderrPath $stderr1

    $capture1 = Receive-RecorderResult -Job $receiver1

    Assert-Equal $exit1 0 "First connector run exit code"
    Assert-True $capture1.replaced "Replacement did not occur during send"
    Assert-Equal @($capture1.lines).Count 100 "First run sent count"

    $uids1 = @(
        foreach ($line in @($capture1.lines)) {
            ($line | ConvertFrom-Json).uid
        }
    )

    Assert-Equal $uids1[0] "OLD0001" "First old UID"
    Assert-Equal $uids1[99] "OLD0100" "Last old UID"

    Assert-True (Test-Path $checkpointPath) "Checkpoint was not created"

    $checkpoint1 = @(
        [IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        ) | ConvertFrom-Json
    )[0]

    Assert-Equal `
        $checkpoint1.offset `
        $oldBytes.Length `
        "First-run checkpoint offset"

    Assert-Equal `
        $checkpoint1.prefix_sha256 `
        $oldHash `
        "Checkpoint hash must belong to the buffered OLD generation"

    Assert-True `
        ([string]$checkpoint1.prefix_sha256 -ne $newHash) `
        "Checkpoint incorrectly used the replacement generation hash"

    # Second run:
    # the saved old-generation hash must not match the replacement file,
    # so the connector must reset this path to offset 0 and send NEW records.
    $port2 = Get-Random -Minimum 25000 -Maximum 45000

    $receiver2 = Start-TcpRecorder `
        -Port $port2 `
        -ReplacementPath "" `
        -TargetPath $connPath

    Start-Sleep -Milliseconds 700

    $stdout2 = Join-Path $tempRoot "run2.stdout.txt"
    $stderr2 = Join-Path $tempRoot "run2.stderr.txt"

    $exit2 = Invoke-Connector `
        -ShellPath $shellPath `
        -ConnectorPath $connectorPath `
        -Port $port2 `
        -StdoutPath $stdout2 `
        -StderrPath $stderr2

    $capture2 = Receive-RecorderResult -Job $receiver2

    Assert-Equal $exit2 0 "Second connector run exit code"
    Assert-Equal @($capture2.lines).Count 100 "Replacement run sent count"

    $uids2 = @(
        foreach ($line in @($capture2.lines)) {
            ($line | ConvertFrom-Json).uid
        }
    )

    Assert-Equal $uids2[0] "NEW0001" "First replacement UID"
    Assert-Equal $uids2[99] "NEW0100" "Last replacement UID"

    $checkpoint2 = @(
        [IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        ) | ConvertFrom-Json
    )[0]

    Assert-Equal `
        $checkpoint2.offset `
        $newBytes.Length `
        "Replacement checkpoint offset"

    Assert-Equal `
        $checkpoint2.prefix_sha256 `
        $newHash `
        "Replacement checkpoint hash"

    Write-Host "[PASS] Zeek rotation during send"
    Write-Host "First run: 100 OLD records"
    Write-Host "Second run: 100 NEW records"
    Write-Host "Exit codes: $exit1, $exit2"
    exit 0
}
catch {
    Write-Host "[FAIL] Zeek rotation during send - $($_.Exception.Message)"
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
