$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [string]$Message
    )

    if ([string]$Actual -ne [string]$Expected) {
        throw "$Message | expected=[$Expected] actual=[$Actual]"
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Start-TcpRecorder {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    return Start-Job -ArgumentList $Port -ScriptBlock {
        param($Port)

        $ErrorActionPreference = "Stop"

        $listener = $null
        $client = $null
        $reader = $null

        try {
            $listener = New-Object System.Net.Sockets.TcpListener(
                [Net.IPAddress]::Loopback,
                $Port
            )

            $listener.Start()

            $deadline = [DateTime]::UtcNow.AddSeconds(15)

            while (-not $listener.Pending()) {
                if ([DateTime]::UtcNow -ge $deadline) {
                    return [PSCustomObject]@{
                        lines     = @()
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

            while (($line = $reader.ReadLine()) -ne $null) {
                $lines.Add($line)
            }

            return [PSCustomObject]@{
                lines     = @($lines)
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
    param(
        [Parameter(Mandatory = $true)]
        $Job
    )

    $null = Wait-Job `
        -Job $Job `
        -Timeout 20

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

function Invoke-WindowsConnector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShellPath,

        [Parameter(Mandatory = $true)]
        [string]$ConnectorPath,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath
    )

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $ConnectorPath,
        "-LogstashHost", "127.0.0.1",
        "-LogstashPort", [string]$Port
    )

    $process = Start-Process `
        -FilePath $ShellPath `
        -ArgumentList $arguments `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath

    return [int]$process.ExitCode
}

$m2Root = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$samplePath = Join-Path `
    $m2Root `
    "samples\windows\windows_security_sample.ndjson"

$pwsh = Get-Command `
    pwsh `
    -ErrorAction SilentlyContinue

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
    ("tracehunt-windows-sample-" +
        [Guid]::NewGuid().ToString("N"))

$receiver = $null

try {
    Assert-True `
        (Test-Path $samplePath) `
        "Windows sample file does not exist."

    $sampleLines = @(
        Get-Content $samplePath |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
    )

    Assert-Equal `
        $sampleLines.Count `
        20 `
        "Windows sample input count"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $tempRoot |
        Out-Null

    $testM2Root = Join-Path `
        $tempRoot `
        "m2-connectors"

    Copy-Item `
        -Path $m2Root `
        -Destination $testM2Root `
        -Recurse

    $windowsRoot = Join-Path `
        $testM2Root `
        "windows-pull"

    $dropFolder = Join-Path `
        $windowsRoot `
        "drop"

    $outputFolder = Join-Path `
        $windowsRoot `
        "output"

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

    Remove-Item `
        (Join-Path $dropFolder "*") `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item `
        (Join-Path $outputFolder "*") `
        -Force `
        -ErrorAction SilentlyContinue

    $testSamplePath = Join-Path `
        $dropFolder `
        "windows_security_sample.ndjson"

    Copy-Item `
        -Path $samplePath `
        -Destination $testSamplePath `
        -Force

    $connectorPath = Join-Path `
        $windowsRoot `
        "windows_pull.ps1"

    $port = Get-Random `
        -Minimum 25000 `
        -Maximum 45000

    $receiver = Start-TcpRecorder `
        -Port $port

    Start-Sleep `
        -Milliseconds 700

    $stdoutPath = Join-Path `
        $tempRoot `
        "windows.stdout.txt"

    $stderrPath = Join-Path `
        $tempRoot `
        "windows.stderr.txt"

    $exitCode = Invoke-WindowsConnector `
        -ShellPath $shellPath `
        -ConnectorPath $connectorPath `
        -Port $port `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath

    $capture = Receive-RecorderResult `
        -Job $receiver

    $receiver = $null

    Assert-Equal `
        $exitCode `
        0 `
        "Windows sample connector exit code"

    Assert-True `
        (-not $capture.timed_out) `
        "TCP recorder timed out."

    Assert-Equal `
        @($capture.lines).Count `
        20 `
        "Windows sample sent event count"

    $payloads = @(
        foreach ($line in @($capture.lines)) {
            $line | ConvertFrom-Json
        }
    )

    foreach ($payload in $payloads) {
        Assert-Equal `
            $payload.host.name `
            "TRACEHUNT-SAMPLE-PC" `
            "Windows sample host.name"

        Assert-Equal `
            $payload.winlog.event_data.TargetUserName `
            "sampleuser" `
            "Windows sample TargetUserName"
    }

    $normalizedPath = Join-Path `
        $outputFolder `
        "windows_security_sample.normalized.ndjson"

    Assert-True `
        (Test-Path $normalizedPath) `
        "Normalized Windows output file was not created."

    $normalizedLines = @(
        Get-Content $normalizedPath |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
    )

    Assert-Equal `
        $normalizedLines.Count `
        20 `
        "Normalized Windows output count"

    Write-Host "[PASS] Windows sample execution test"
    Write-Host "Input records: 20"
    Write-Host "Sent events: 20"
    Write-Host "Exit code: 0"
    Write-Host "host.name: TRACEHUNT-SAMPLE-PC"
    Write-Host "TargetUserName: sampleuser"

    exit 0
}
catch {
    Write-Host (
        "[FAIL] Windows sample execution test - " +
        $_.Exception.Message
    )

    exit 1
}
finally {
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