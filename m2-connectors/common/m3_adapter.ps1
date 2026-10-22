Set-StrictMode -Version Latest

function Get-EventDataMap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$XmlText
    )

    $result = [ordered]@{}

    $xml = [xml]$XmlText

    # Use local-name() so Windows Event XML namespaces do not break parsing.
    $nodes = $xml.SelectNodes(
        "//*[local-name()='EventData']/*[local-name()='Data']"
    )

    foreach ($node in @($nodes)) {
        $name = [string]$node.GetAttribute("Name")

        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $result[$name] = [string]$node.InnerText
    }

    return $result
}


function Get-EventComputerName {
    param(
        [Parameter(Mandatory = $true)]
        $Event,

        [Parameter(Mandatory = $true)]
        [string]$XmlText
    )

    if (
        $null -ne $Event.MachineName -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$Event.MachineName
        )
    ) {
        return [string]$Event.MachineName
    }

    $xml = [xml]$XmlText

    $computerNode = $xml.SelectSingleNode(
        "/*[local-name()='Event']/*[local-name()='System']/*[local-name()='Computer']"
    )

    if (
        $null -ne $computerNode -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$computerNode.InnerText
        )
    ) {
        return [string]$computerNode.InnerText
    }

    throw "Event does not contain a computer name."
}


function Convert-WindowsSecurityEventToM3 {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    if ($null -eq $Event.TimeCreated) {
        throw "Windows Security event is missing TimeCreated."
    }

    $rawXml = $Event.ToXml()

    $eventData = Get-EventDataMap -XmlText $rawXml

    $computerName = Get-EventComputerName `
        -Event $Event `
        -XmlText $rawXml

    $timestamp = $Event.TimeCreated.
        ToUniversalTime().
        ToString("o")

    $record = [ordered]@{
        "@timestamp" = $timestamp

        event = [ordered]@{
            code     = [string]$Event.Id
            provider = [string]$Event.ProviderName
            dataset  = "windows.security"
        }

        host = [ordered]@{
            name = $computerName
        }

        winlog = [ordered]@{
            channel       = "Security"
            provider_name = [string]$Event.ProviderName
            event_id      = $Event.Id
            record_id     = $Event.RecordId
            computer_name = $computerName
            event_data    = $eventData
        }

        # M2 metadata
        source_type = "windows-security"

        # Preserve the complete original event.
        raw_xml = $rawXml
    }

    return [PSCustomObject]$record
}


function Convert-SysmonEventToM3 {
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    if ($null -eq $Event.TimeCreated) {
        throw "Sysmon event is missing TimeCreated."
    }

    $rawXml = $Event.ToXml()

    $eventData = Get-EventDataMap -XmlText $rawXml

    $computerName = Get-EventComputerName `
        -Event $Event `
        -XmlText $rawXml

    $timestamp = $Event.TimeCreated.
        ToUniversalTime().
        ToString("o")

    $record = [ordered]@{
        "@timestamp" = $timestamp

        event = [ordered]@{
            code     = [string]$Event.Id
            provider = [string]$Event.ProviderName
            dataset  = "sysmon.events"
        }

        host = [ordered]@{
            name = $computerName
        }

        winlog = [ordered]@{
            channel       = "Microsoft-Windows-Sysmon/Operational"
            provider_name = [string]$Event.ProviderName
            event_id      = $Event.Id
            record_id     = $Event.RecordId
            computer_name = $computerName
            event_data    = $eventData
        }

        # M2 metadata
        source_type = "sysmon"

        # Preserve the complete original event.
        raw_xml = $rawXml
    }

    return [PSCustomObject]$record
}


function Convert-ZeekEventToM3 {
    param(
        [Parameter(Mandatory = $true)]
        $Event,

        [Parameter(Mandatory = $true)]
        [string]$RawLine,

        [Parameter(Mandatory = $true)]
        [string]$LogType
    )

    $record = [ordered]@{}

    # IMPORTANT:
    # Keep Zeek fields such as id.orig_h and id.resp_h at the top level.
    # M3 maps these directly to source.ip and destination.ip.
    foreach ($property in $Event.PSObject.Properties) {
        $record[$property.Name] = $property.Value
    }

    # Helps M3 automatic source detection.
    $record["log_type"] = $LogType

    $record["event"] = [ordered]@{
        dataset = "zeek.$LogType"
    }

    # M2 metadata.
    $record["source_type"] = "zeek"

    # Exact original Zeek JSON line.
    $record["raw_line"] = $RawLine

    return [PSCustomObject]$record
}