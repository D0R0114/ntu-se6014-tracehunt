$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$m2Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$adapterPath = Join-Path $m2Root "common\m3_adapter.ps1"

$script:passed = 0
$script:failed = 0

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

function Run-Test {
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    try {
        & $Body
        $script:passed++
        Write-Host "[PASS] $Name"
    }
    catch {
        $script:failed++
        Write-Host "[FAIL] $Name - $($_.Exception.Message)"
    }
}

function New-FakeEvent {
    param(
        [int]$Id,
        [long]$RecordId,
        [string]$Provider,
        [string]$Channel,
        [string]$Computer,
        [string]$EventDataXml
    )

    $xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='$Provider'/>
<EventID>$Id</EventID>
<TimeCreated SystemTime='2026-10-16T09:00:00.0000000Z'/>
<EventRecordID>$RecordId</EventRecordID>
<Channel>$Channel</Channel>
<Computer>$Computer</Computer>
</System>
<EventData>
$EventDataXml
</EventData>
</Event>
"@

    $event = [pscustomobject]@{
        Id           = $Id
        RecordId     = $RecordId
        ProviderName = $Provider
        LogName      = $Channel
        MachineName  = $Computer
        TimeCreated  = [datetime]::Parse("2026-10-16T09:00:00Z").ToUniversalTime()
        Xml          = $xml
    }

    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
        return $this.Xml
    }

    return $event
}

Run-Test "PowerShell syntax" {

    $files = Get-ChildItem $m2Root -Recurse -Filter *.ps1 -File

    foreach ($file in $files) {
        $tokens = $null
        $errors = $null

        [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName,
            [ref]$tokens,
            [ref]$errors
        ) | Out-Null

        if (@($errors).Count -gt 0) {
            throw "$($file.Name): $(
                ($errors | ForEach-Object { $_.Message }) -join '; '
            )"
        }
    }
}

. $adapterPath

Run-Test "Windows Security adapter contract" {

    $eventData = @"
<Data Name='TargetUserName'>test-user</Data>
<Data Name='TargetDomainName'>TEST</Data>
<Data Name='LogonType'>3</Data>
<Data Name='IpAddress'>10.20.30.40</Data>
<Data Name='IpPort'>50000</Data>
<Data Name='Status'>0xc000006d</Data>
"@

    $event = New-FakeEvent `
        -Id 4625 `
        -RecordId 100 `
        -Provider "Microsoft-Windows-Security-Auditing" `
        -Channel "Security" `
        -Computer "TEST-PC" `
        -EventDataXml $eventData

    $record = Convert-WindowsSecurityEventToM3 -Event $event

    Assert-Equal $record.event.code "4625" "event.code"
    Assert-Equal $record.host.name "TEST-PC" "host.name"
    Assert-Equal $record.winlog.event_data.TargetUserName "test-user" "TargetUserName"
    Assert-Equal $record.source_type "windows-security" "source_type"
    Assert-True ($record.raw_xml.Length -gt 0) "raw_xml missing"
}

Run-Test "Sysmon adapter contract" {

    $eventData = @"
<Data Name='UtcTime'>2026-10-16 09:00:00.000</Data>
<Data Name='ProcessGuid'>{TEST-GUID}</Data>
<Data Name='ProcessId'>1234</Data>
<Data Name='Image'>C:\Windows\System32\notepad.exe</Data>
<Data Name='CommandLine'>notepad.exe</Data>
<Data Name='User'>TEST\user</Data>
<Data Name='ParentProcessId'>1000</Data>
<Data Name='ParentImage'>C:\Windows\explorer.exe</Data>
"@

    $event = New-FakeEvent `
        -Id 1 `
        -RecordId 200 `
        -Provider "Microsoft-Windows-Sysmon" `
        -Channel "Microsoft-Windows-Sysmon/Operational" `
        -Computer "TEST-PC" `
        -EventDataXml $eventData

    $record = Convert-SysmonEventToM3 -Event $event

    Assert-Equal $record.event.code "1" "event.code"
    Assert-Equal $record.host.name "TEST-PC" "host.name"
    Assert-Equal $record.winlog.event_data.Image "C:\Windows\System32\notepad.exe" "Image"
    Assert-Equal $record.winlog.event_data.CommandLine "notepad.exe" "CommandLine"
    Assert-Equal $record.source_type "sysmon" "source_type"
}

Run-Test "Zeek adapter contract" {

    $raw = '{"ts":1747147647.668533,"uid":"TEST-ZEEK","id.orig_h":"192.168.1.8","id.orig_p":52917,"id.resp_h":"192.0.78.212","id.resp_p":80,"proto":"tcp"}'

    $event = $raw | ConvertFrom-Json

    $record = Convert-ZeekEventToM3 `
        -Event $event `
        -RawLine $raw `
        -LogType "conn"

    Assert-Equal $record.'id.orig_h' "192.168.1.8" "id.orig_h"
    Assert-Equal $record.'id.resp_h' "192.0.78.212" "id.resp_h"
    Assert-Equal $record.log_type "conn" "log_type"
    Assert-Equal $record.event.dataset "zeek.conn" "event.dataset"
    Assert-Equal $record.source_type "zeek" "source_type"
    Assert-Equal $record.raw_line $raw "raw_line"
}

function Invoke-ExecutionTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestFile
    )

    $testPath = Join-Path $PSScriptRoot $TestFile

    if (-not (Test-Path $testPath)) {
        throw "Execution test not found: $testPath"
    }

    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue

    if ($null -ne $pwsh) {
        & $pwsh.Source `
            -NoProfile `
            -File $testPath
    }
    else {
        $windowsPowerShell = Get-Command `
            powershell.exe `
            -ErrorAction Stop

        & $windowsPowerShell.Source `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $testPath
    }

    if ($LASTEXITCODE -ne 0) {
        throw "$TestFile exited with code $LASTEXITCODE"
    }
}

Run-Test "Sysmon reset and idle-poll execution" {
    Invoke-ExecutionTest `
        -TestFile "sysmon_reset_execution.ps1"
}

Run-Test "Zeek rotation-during-send execution" {
    Invoke-ExecutionTest `
        -TestFile "zeek_rotation_during_send.ps1"
}

Run-Test "Zeek pre-snapshot rotation execution" {
    Invoke-ExecutionTest `
        -TestFile "zeek_pre_snapshot_rotation_execution.ps1"
}

Run-Test "Windows sample execution" {
    Invoke-ExecutionTest `
        -TestFile "windows_sample_execution.ps1"
}
Write-Host ""
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    exit 1
}

exit 0