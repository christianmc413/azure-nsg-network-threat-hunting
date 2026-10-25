# azure-nsg-network-threat-hunting

## Overview

This project documents a set of network-focused security investigations performed against Azure network telemetry. The goal was to take raw NSG flow data and turn it into practical SOC-style hunting use cases using KQL.

The investigations include:

- Port scan detection
- Traffic allowed by overly permissive NSG rules
- Denied inbound connection analysis
- Outbound beaconing analysis
- Potential data exfiltration analysis

The lab used a fixed investigation window of **June 2, 2026 00:00:00 through June 3, 2026 00:00:00** so the same time range could be reused across investigations.

---

## Technologies and Skills

- Microsoft Azure
- Azure Network Security Groups (NSGs)
- Azure Log Analytics
- Microsoft Defender / Microsoft Sentinel ecosystem
- `NTANetAnalytics`
- Kusto Query Language (KQL)
- Network traffic analysis
- Threat hunting
- Security event investigation

## Repository Structure

```text
azure-nsg-network-threat-hunting/
|
|-- README.md
|-- queries/
|   |-- 01-port-scan-detection.kql
|   |-- 02-permissive-nsg-rules.kql
|   |-- 03-denied-inbound-flows.kql

# Investigation 1: Port Scan Detection

## Objective

Identify source systems communicating with a large number of destination ports. A source touching many ports on the same destination is worth reviewing as possible reconnaissance or scanning behavior.

## KQL

```kusto
let startTime = datetime(2026-06-02 00:00:00);
let endTime = datetime(2026-06-03 00:00:00);

NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowStatus == "Allowed"
| where isnotempty(SrcIp)
| summarize DistinctPorts = dcount(DestPort),
            Ports = make_set(DestPort, 50)
    by SrcIp, DestIp, AclRule
| where DistinctPorts > 50
| sort by DistinctPorts desc
```

## What the Query Does

1. Restricts the investigation to the selected time window.
2. Keeps network flows that were allowed.
3. Removes rows without a source IP.
4. Groups activity by source IP, destination IP, and ACL rule.
5. Counts how many distinct destination ports were contacted.
6. Surfaces records where the distinct destination-port count exceeds 50.
7. Sorts the results from highest to lowest port count.

## Evidence
<img width="468" height="215" alt="image" src="https://github.com/user-attachments/assets/4d12f3c4-e226-4ad4-a310-377ff08598df" />


## Analyst Takeaway

This hunt converts individual flow records into a pattern-based view. Instead of reviewing connections one at a time, the query highlights sources that contacted an unusually broad set of destination ports and gives an analyst a smaller set of systems to investigate further.

---

# Investigation 2: Overly Permissive NSG Rules

## Objective

Review allowed network activity associated with NSG/ACL rule names that may indicate broad or dangerous access.

## KQL

```kusto
let startTime = datetime(2026-06-02 00:00:00);
let endTime = datetime(2026-06-03 00:00:00);

NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowStatus == "Allowed"
| where AclRule has_any ("allow_all", "danger", "any")
| summarize FlowCount = count(),
            Sources = dcount(SrcIp),
            Dests = dcount(DestIp)
    by AclRule
| sort by FlowCount desc
```

## What the Query Does

The query searches allowed traffic for ACL rule names containing `allow_all`, `danger`, or `any`, then summarizes:

- Total flow count
- Number of unique source IPs
- Number of unique destination IPs

This provides a quick way to understand how much traffic is passing through rules whose names suggest broad access.

## Evidence
<img width="468" height="453" alt="image" src="https://github.com/user-attachments/assets/60b27cab-85bd-466c-a85f-c6724fed0554" />


## Analyst Takeaway

A rule being permissive does not automatically prove malicious activity. The value of this hunt is that it helps prioritize firewall rules for review by showing which matching rules are actively allowing traffic and how broadly they are being used.

---

# Investigation 3: Denied Inbound Connections

## Objective

Identify inbound traffic that was blocked by the network controls and determine which source IPs, destinations, ports, and protocols generated the greatest number of denied flows.

## KQL

```kusto
let startTime = datetime(2026-06-02 00:00:00);
let endTime = datetime(2026-06-03 00:00:00);

NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where isnotempty(SrcIp)
| where FlowDirection == "Inbound"
| where DeniedInFlows > 0
| summarize TotalDenied = sum(DeniedInFlows)
    by IpAddress = SrcIp, DestIp, DestPort, L4Protocol
| sort by TotalDenied desc
```

## What the Query Does

This query focuses on blocked inbound traffic and aggregates denied attempts by:

- Source IP
- Destination IP
- Destination port
- Layer 4 protocol

The source IP is renamed to `IpAddress` in the query. The lab specifically called out this rename so Defender recognizes the result as an IP-address field and enriches the data.

## Evidence
<img width="468" height="181" alt="image" src="https://github.com/user-attachments/assets/8fe78efd-a9c5-4683-bbe2-9faec1a468d8" />


## Analyst Takeaway

Denied traffic still has investigative value. Sorting blocked inbound connections by total denied flows helps identify sources generating repeated attempts and provides a starting point for deeper review of the targeted destination and service.

---

# Key Takeaways

This project helped me practice turning raw Azure network telemetry into focused security investigations with KQL. The biggest lesson was that the value of network logs comes from aggregating and shaping the data around a security question.

Instead of simply looking at individual firewall events, these hunts look for patterns such as:

- One source touching many destination ports
- Traffic flowing through broadly named firewall rules
- Repeated blocked inbound attempts
- Consistent outbound timing patterns
- High-volume outbound transfers to public destinations

The queries also reinforced practical KQL concepts including `where`, `summarize`, `dcount`, `make_set`, `extend`, `sort`, `prev`, and `serialize`.

---

# Skills Demonstrated

- Network security monitoring
- Azure NSG telemetry analysis
- KQL query development and interpretation
- Threat hunting methodology
- Network reconnaissance investigation
- Firewall rule review
- Denied-traffic analysis
- Outbound traffic analysis
- Security documentation
