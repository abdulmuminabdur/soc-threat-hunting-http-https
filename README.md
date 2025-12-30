soc-http-https-scanning-threat-hunt

SOC threat hunting investigation identifying sustained HTTP/HTTPS scanning activity using Microsoft Defender for Endpoint and KQL.


Overview

This project documents a proactive threat-hunting investigation conducted in Microsoft Defender for Endpoint to identify anomalous internal network activity. The investigation focused on repeated failed network connections indicative of automated reconnaissance behavior. The objective of this hunt was to determine whether the observed behavior represented benign misconfiguration or malicious reconnaissance requiring containment.


Timeline Summary and Findings

Initial Detection


During routine threat hunting, Windows-target-1 was observed generating a high volume of failed network connection attempts to multiple internal hosts.

Detection logic used:
DeviceNetworkEvents
where ActionType == "ConnectionFailed"
summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
order by ConnectionCount


![image alt](https://github.com/abdulmuminabdur/soc-http-https-scanning-threat-hunt/blob/main/1st.png?raw=true)



IP-Focused Analysis: 

Following identification of abnormal connection failures, analysis pivoted to the suspected source host 10.0.0.5. Activity patterns were consistent with automated web service scanning primarily targeting port 80 (HTTP) and port 443 (HTTPS).

Analysis logic used:

let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc


![image alt](https://github.com/abdulmuminabdur/soc-http-https-scanning-threat-hunt/blob/main/Screenshot%202025-12-28%20220217.png?raw=true)

![image alt](https://github.com/abdulmuminabdur/soc-http-https-scanning-threat-hunt/blob/main/Screenshot%202025-12-28%20220443.png?raw=true)




Activity Duration and Scope:

The activity persisted for approximately 12 hours on December 28, 2025, with repeated attempts observed across multiple internal IP addresses. The sustained nature and consistency of the traffic strongly suggested automated behavior rather than user-driven or misconfigured application activity.

![image alt](https://github.com/abdulmuminabdur/soc-http-https-scanning-threat-hunt/blob/main/actual-ip-screenshot.png?raw=true)




Finding:

Identified sustained HTTP/HTTPS scanning activity originating from internal IP 10.0.0.5, consistent with automated web reconnaissance.



Evidence:

- Repeated failed connections to ports 80 and 443
- High fan-out across multiple internal hosts
- Burst-style activity over short time intervals
- No associated browser, update service, or user-driven processes observed



Assessment:

The observed behavior is consistent with automated web reconnaissance or vulnerability probing, rather than legitimate administrative activity or normal endpoint behavior.



Impact:

No successful exploitation, lateral movement, or persistence was observed during the investigation window.



Response and Containment Actions:

Isolated the affected endpoint to prevent further network activity
Performed endpoint malware scanning (no detections identified)
Maintained isolation as a precautionary control
Submitted a ticket for endpoint reimage and rebuild



MITRE ATT&CK Mapping:

T1046 – Network Service Scanning (Discovery)
High-volume connection attempts used to enumerate exposed services.

T1595.001 – Active Scanning: Scanning IP Blocks (Reconnaissance)
Sustained probing across multiple internal IP addresses.

T1595.002 – Active Scanning: Vulnerability Scanning (Reconnaissance)
Focused scanning activity targeting HTTP/HTTPS services.


Summary:

This investigation identified and contained automated reconnaissance activity without business impact. The case demonstrates effective use of Defender Advanced Hunting, KQL-based analysis, evidence-driven assessment, and appropriate SOC response actions. The activity was contained without business impact.
