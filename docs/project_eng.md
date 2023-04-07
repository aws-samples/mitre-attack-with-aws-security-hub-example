## Virtual SOC with MITRE Attack integration with AWS Security Hub

## Source

As a security operator using **only native tools** from the AWS environment, you will find that the information provided in the Security Hub dashboards are too limited to give a **threat and attacker centric focus**; the findings in Security Hub are more geared towards giving a quick reference to security standards compliance.

Only some findings provide information from the [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/cloud/) framework from the originating service (Amazon GuardDuty provides this information for a percentage of its finding types).

We wanted to extend this capability to a wider range of findings, giving the security operator a quick understanding of how exposed their environment is and *to what kind of attacks*.

## Objectives

1.   **Correlation** or mapping of [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/cloud/) tactics and techniques applicable to the AWS environment, with rules and events that can be handled natively.
2.   Formation of **MITRE ATT&CK Compliance Rules Package** for AWS Config.
3.   Finally, creation of a findings enrichment process in Security Hub with the above processed information.

## Current status

-  **60 Techniques/Sub-Techniques** (TTPs) have been catalogued (out of 97 applicable to cloud environments), spread across 11 different Tactics (TA).
- These have been linked to **277 rules/events** of AWS native services that can be centralised in Security Hub.
- Controls have been linked to the main security standards (ISO27K, ENS, NIST, CIS, PCI, C5).
- A **MITRE ATT&CK Compliance Rules Package** has been formalised with 120 managed rules.
- The enrichment process currently has the capability to create, update and archive MITRE findings based on the original findings.

## Vision for the future

Possible roads for the project are being considered:

- Development of panels for better visualization
- Add a MITRE ATT&CK - Campaings service
- Mapping of events from third party services
- Self-remediation from AWS Config for ConformancePack