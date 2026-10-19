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
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [int]$ExpectedLines = 100
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
            $listener = [Net.Sockets.TcpListener]::new(
                [Net.IPAddress]::Loopback,
                $Port
            )

            $listener.Start()

            $lines =
                New-Object System.Collections.Generic.List[string]

            $deadline =
                [DateTime]::UtcNow.AddSeconds(20)

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
                    $client =
                        $listener.AcceptTcpClient()

                    $reader =
                        New-Object System.IO.StreamReader(
                            $client.GetStream(),
                            [Text.UTF8Encoding]::new($false)
                        )

                    while (
                        ($line = $reader.ReadLine()) -ne $null
                    ) {
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
                timed_out = (
                    $lines.Count -lt $ExpectedLines
                )
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

    $null = Wait-Job `
        -Job $Job `
        -Timeout 25

    if ($Job.State -eq "Running") {
        Stop-Job `
            -Job $Job `
            -ErrorAction SilentlyContinue

        Remove-Job `
            -Job $Job `
            -Force `
            -ErrorAction SilentlyContinue

        throw "TCP recorder timed out."
    }

    $result = Receive-Job -Job $Job

    Remove-Job `
        -Job $Job `
        -Force `
        -ErrorAction SilentlyContinue

    if ($null -eq $result) {
        throw "TCP recorder returned no result."
    }

    return $result
}

function Wait-ForFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$TimeoutSeconds = 10
    )

    $deadline =
        [DateTime]::UtcNow.AddSeconds(
            $TimeoutSeconds
        )

    while (-not (Test-Path $Path)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Timed out waiting for $Path"
        }

        Start-Sleep -Milliseconds 50
    }
}

$m2Root = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$pwsh =
    Get-Command pwsh -ErrorAction SilentlyContinue

if ($null -ne $pwsh) {
    $shellPath = $pwsh.Source
}
else {
    $shellPath = (
        Get-Command `
            powershell.exe `
            -ErrorAction Stop
    ).Source
}

$tempRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    (
        "tracehunt-zeek-pre-snapshot-" +
        [Guid]::NewGuid().ToString("N")
    )

$receiver = $null
$process = $null

try {
    New-Item `
        -ItemType Directory `
        -Force `
        -Path $tempRoot |
        Out-Null

    $testM2Root =
        Join-Path $tempRoot "m2-connectors"

    Copy-Item `
        -Path $m2Root `
        -Destination $testM2Root `
        -Recurse

    $zeekRoot =
        Join-Path $testM2Root "zeek-stream"

    $inputFolder =
        Join-Path $zeekRoot "input"

    $stateFolder =
        Join-Path $zeekRoot "state"

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

    $connectorPath =
        Join-Path $zeekRoot "zeek_stream.ps1"

    $connPath =
        Join-Path $inputFolder "conn.log"

    $replacementPath =
        Join-Path $inputFolder "replacement.tmp"

    $checkpointPath =
        Join-Path $stateFolder "checkpoints.json"

    $readyPath =
        Join-Path $zeekRoot "pre_snapshot.ready"

    $continuePath =
        Join-Path $zeekRoot "pre_snapshot.continue"

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
            } |
                ConvertTo-Json -Compress
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
            } |
                ConvertTo-Json -Compress
        }
    )

    $utf8 =
        [Text.UTF8Encoding]::new($false)

    $oldText =
        ($oldLines -join "`n") + "`n"

    $newText =
        ($newLines -join "`n") + "`n"

    $oldBytes =
        $utf8.GetBytes($oldText)

    $newBytes =
        $utf8.GetBytes($newText)

    Assert-Equal `
        $oldBytes.Length `
        $newBytes.Length `
        "OLD and NEW logs must have equal length"

    [IO.File]::WriteAllBytes(
        $connPath,
        $oldBytes
    )

    [IO.File]::WriteAllBytes(
        $replacementPath,
        $newBytes
    )

    # Saved checkpoint represents first 50 records of OLD generation.
    $oldPrefixText =
        ($oldLines[0..49] -join "`n") + "`n"

    $oldPrefixBytes =
        $utf8.GetBytes($oldPrefixText)

    $oldPrefixHash =
        Get-Sha256Hex `
            -Bytes $oldPrefixBytes

    $fullOldHash =
        Get-Sha256Hex `
            -Bytes $oldBytes

    $fullNewHash =
        Get-Sha256Hex `
            -Bytes $newBytes

    Assert-True `
        ($fullOldHash -ne $fullNewHash) `
        "OLD and NEW generations must differ"

    $checkpoint = [ordered]@{
        path          = [IO.Path]::GetFullPath(
            $connPath
        )
        offset        = $oldPrefixBytes.Length
        prefix_sha256 = $oldPrefixHash
        updated_at    = (
            Get-Date
        ).ToUniversalTime().ToString("o")
    } |
        ConvertTo-Json

    [IO.File]::WriteAllText(
        $checkpointPath,
        $checkpoint,
        $utf8
    )

    # Patch ONLY the temporary connector copy.
    #
    # Pause after checkpoint offset is obtained but before
    # Get-CompleteLinesFromOffset opens the file.
    $connectorText =
        [IO.File]::ReadAllText(
            $connectorPath,
            [Text.Encoding]::UTF8
        )

    $anchor =
        '            $completeLines = @('

    Assert-True `
        ($connectorText.Contains($anchor)) `
        "Could not locate Zeek pre-snapshot hook point"

    $hook = @'
            $testReadyPath = Join-Path `
                $PSScriptRoot `
                "pre_snapshot.ready"

            $testContinuePath = Join-Path `
                $PSScriptRoot `
                "pre_snapshot.continue"

            [IO.File]::WriteAllText(
                $testReadyPath,
                "ready",
                [Text.UTF8Encoding]::new($false)
            )

            $testDeadline =
                [DateTime]::UtcNow.AddSeconds(10)

            while (-not (Test-Path $testContinuePath)) {
                if (
                    [DateTime]::UtcNow -ge
                    $testDeadline
                ) {
                    throw "Pre-snapshot test hook timed out."
                }

                Start-Sleep -Milliseconds 25
            }

            $completeLines = @(
'@

    $connectorText =
        $connectorText.Replace(
            $anchor,
            $hook
        )

    [IO.File]::WriteAllText(
        $connectorPath,
        $connectorText,
        $utf8
    )

    $port =
        Get-Random `
            -Minimum 25000 `
            -Maximum 45000

    $receiver =
        Start-TcpRecorder `
            -Port $port `
            -ExpectedLines 100

    Start-Sleep -Milliseconds 500

    $stdoutPath =
        Join-Path $tempRoot "connector.stdout.txt"

    $stderrPath =
        Join-Path $tempRoot "connector.stderr.txt"

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $connectorPath,
        "-Once",
        "-LogstashHost", "127.0.0.1",
        "-LogstashPort", [string]$port,
        "-RetryCount", "1",
        "-RetryDelaySeconds", "0"
    )

    $process = Start-Process `
        -FilePath $shellPath `
        -ArgumentList $arguments `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    # Connector has already read the OLD checkpoint offset,
    # but has not opened its snapshot yet.
    Wait-ForFile `
        -Path $readyPath `
        -TimeoutSeconds 10

    $backupPath =
        "$connPath.pre-snapshot.bak"

    if (Test-Path $backupPath) {
        Remove-Item `
            -LiteralPath $backupPath `
            -Force
    }

    [IO.File]::Replace(
        $replacementPath,
        $connPath,
        $backupPath
    )

    if (Test-Path $backupPath) {
        Remove-Item `
            -LiteralPath $backupPath `
            -Force
    }

    # Allow snapshot open only AFTER pathname replacement.
    [IO.File]::WriteAllText(
        $continuePath,
        "continue",
        $utf8
    )

    if (-not $process.WaitForExit(20000)) {
        try {
            $process.Kill()
        }
        catch {
        }

        throw "Zeek connector process timed out."
    }

    $exitCode =
        [int]$process.ExitCode

    $capture =
        Receive-RecorderResult `
            -Job $receiver

    $receiver = $null

    Assert-Equal `
        $exitCode `
        0 `
        "Connector exit code"

    Assert-True `
        (-not $capture.timed_out) `
        "TCP recorder timed out"

    Assert-Equal `
        @($capture.lines).Count `
        100 `
        "Replacement sent count"

    $uids = @(
        foreach ($line in @($capture.lines)) {
            ($line | ConvertFrom-Json).uid
        }
    )

    Assert-Equal `
        $uids[0] `
        "NEW0001" `
        "First NEW UID"

    Assert-Equal `
        $uids[99] `
        "NEW0100" `
        "Last NEW UID"

    $checkpointAfter = @(
        [IO.File]::ReadAllText(
            $checkpointPath,
            [Text.Encoding]::UTF8
        ) |
            ConvertFrom-Json
    )[0]

    Assert-Equal `
        $checkpointAfter.offset `
        $newBytes.Length `
        "Final checkpoint offset"

    Assert-Equal `
        $checkpointAfter.prefix_sha256 `
        $fullNewHash `
        "Final checkpoint generation hash"

    Write-Host (
        "[PASS] Zeek replacement before snapshot open"
    )
    Write-Host "Saved OLD checkpoint: first 50 records"
    Write-Host "Replacement sent: 100 NEW records"
    Write-Host "First UID: NEW0001"
    Write-Host "Last UID: NEW0100"
    Write-Host "Exit code: 0"

    exit 0
}
catch {
    Write-Host (
        "[FAIL] Zeek replacement before snapshot open - " +
        $_.Exception.Message
    )

    exit 1
}
finally {
    if (
        $null -ne $process -and
        -not $process.HasExited
    ) {
        try {
            $process.Kill()
        }
        catch {
        }
    }

    if ($null -ne $receiver) {
        Stop-Job `
            -Job $receiver `
            -ErrorAction SilentlyContinue

        Remove-Job `
            -Job $receiver `
            -Force `
            -ErrorAction SilentlyContinue
    }

    if (Test-Path $tempRoot) {
        Remove-Item `
            -LiteralPath $tempRoot `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
