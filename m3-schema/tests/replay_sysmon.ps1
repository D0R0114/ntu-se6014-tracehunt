param(
    [Parameter(Mandatory = $true)][string]$Connector,
    [Parameter(Mandatory = $true)][string]$Sample,
    [Parameter(Mandatory = $true)][int]$Port
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Only the event-log reader is simulated. The unmodified M2 connector and
# adapter perform conversion, TCP delivery, and checkpoint handling.
$global:M3ReplayEvents = @(
    foreach ($line in [IO.File]::ReadAllLines($Sample)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $record = $line | ConvertFrom-Json
        $time = [DateTimeOffset]::Parse($record.timestamp).UtcDateTime
        $utcTime = $time.ToString("yyyy-MM-dd HH:mm:ss.fff", [Globalization.CultureInfo]::InvariantCulture)
        $image = [Security.SecurityElement]::Escape([string]$record.image)
        $command = [Security.SecurityElement]::Escape([string]$record.command_line)
        $parent = [Security.SecurityElement]::Escape([string]$record.parent_image)
        $xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Computer>M3-REPLAY-HOST</Computer></System>
<EventData>
<Data Name='UtcTime'>$utcTime</Data>
<Data Name='Image'>$image</Data>
<Data Name='CommandLine'>$command</Data>
<Data Name='ParentImage'>$parent</Data>
</EventData>
</Event>
"@
        $event = [pscustomobject]@{
            Id = [int]$record.event_id
            RecordId = [long]1
            ProviderName = "Microsoft-Windows-Sysmon"
            MachineName = "M3-REPLAY-HOST"
            TimeCreated = $time
            Xml = $xml
        }
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml }
        $event
    }
)

function Get-WinEvent {
    [CmdletBinding()]
    param([hashtable]$FilterHashtable)
    return $global:M3ReplayEvents
}

& $Connector -Once -LogstashHost "127.0.0.1" -LogstashPort $Port -RetryCount 1
if (-not $?) { exit 1 }
