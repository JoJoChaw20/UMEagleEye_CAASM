# UMEagleEye vs. Industry Standard CAASM

This document serves as a continuous monitoring baseline to compare the current capabilities of **UMEagleEye** against industry-standard Cyber Asset Attack Surface Management (CAASM) tools (such as Axonius, JupiterOne, or Brinqa). 

It highlights current achievements, existing gaps, and provides a roadmap for bringing the system closer to enterprise-level production capabilities.

---

## 1. Asset Discovery & Integration

> [!NOTE]
> **Core Concept:** CAASM relies on comprehensive visibility. You cannot secure what you cannot see.

| Capability | UMEagleEye Current Implementation | Industry Standard Production | Gap / Improvement Roadmap |
| :--- | :--- | :--- | :--- |
| **Discovery Method** | Entirely network-based (Active scanning via Nmap/Masscan and Passive via Scapy). | API-driven integrations with 100+ data sources (AWS, Azure, AD, MDMs, EDRs, IdPs) supplemented by network scans. | **High Priority:** Implement API connectors. Network scanning alone cannot discover remote endpoints, cloud instances, or assets behind firewalls. |
| **Agent Requirements** | Agentless (Network probes). | Agentless via APIs, but leverages data from existing deployed agents (e.g., CrowdStrike, SentinelOne). | **Medium Priority:** Ingest telemetry from EDRs/MDMs to enrich asset data beyond what network probes can see. |
| **Asset Types** | IP-addressable network assets (Servers, IoT, Workstations). | Comprehensive (Cloud resources, SaaS applications, User Identities, Code Repositories). | **Future Expansion:** Expand the `Asset` schema to support non-IP assets like IAM roles or GitHub repos. |

---

## 2. Identity Resolution & Data Deduplication

> [!WARNING]
> **Core Concept:** Assets frequently change IP addresses. Relying on IPs leads to duplicated assets and skewed posture metrics.

| Capability | UMEagleEye Current Implementation | Industry Standard Production | Gap / Improvement Roadmap |
| :--- | :--- | :--- | :--- |
| **Primary Keys** | Relies primarily on `ip_address` and `mac_address`. | Complex Identity Resolution Engine prioritizing unique identifiers (Serial Number, Agent ID, Cloud Instance ID). | **High Priority:** Develop an entity resolution algorithm to merge duplicate records when an asset moves between networks. |
| **Data Conflict Resolution** | Last-write wins. Whatever Nmap discovers simply overwrites the database record. | Confidence-based scoring. If AWS says an asset is Windows, but a local scan says Linux, the system trusts the higher-confidence source (AWS). | **Medium Priority:** Implement a source-trust hierarchy to handle conflicting data from multiple discovery tools. |
| **Asset Lifecycle** | Assets persist indefinitely once discovered. No automated archival. | Automated staleness tracking. Assets unseen for X days are flagged as stale and eventually archived/deleted. | **High Priority:** Add a `status` field (Active, Offline, Stale, Archived) and a Celery beat task to auto-retire old assets. |

---

## 3. Vulnerability & Risk Management

> [!IMPORTANT]
> **Core Concept:** Identifying vulnerabilities is only half the battle; prioritizing them based on business context is the real value of CAASM.

| Capability | UMEagleEye Current Implementation | Industry Standard Production | Gap / Improvement Roadmap |
| :--- | :--- | :--- | :--- |
| **Vulnerability Identification** | Scans CVEs based on software versions detected by Nmap (CPE matching). | API ingestion from dedicated vulnerability scanners (Tenable, Qualys, Snyk) combined with CISA KEV catalogs. | **Medium Priority:** Integrate with tools like Trivy or Nessus APIs instead of relying solely on Nmap's version guessing, which is prone to false positives. |
| **Risk Scoring** | Static criticality score assigned to assets (1-10). | Dynamic, composite risk scoring calculating Asset Criticality + Vulnerability Severity + Exploitability + Internet Exposure. | **Medium Priority:** Enhance the `composite_risk_score` algorithm to dynamically adjust based on external threat intel (e.g., EPSS scores). |

---

## 4. Architecture & Scalability

> [!TIP]
> **Core Concept:** Enterprise networks can contain millions of assets. The architecture must scale horizontally.

| Capability | UMEagleEye Current Implementation | Industry Standard Production | Gap / Improvement Roadmap |
| :--- | :--- | :--- | :--- |
| **Scanner Deployment** | Monolithic container (Celery worker) running scans centrally. | Distributed, lightweight "Sensor" nodes deployed across various network segments/VPCs, reporting back to the cloud. | **High Priority (for Enterprise):** Decouple the scanning engine into standalone, deployable sensor binaries to navigate segmented VLANs and firewalls. |
| **Privilege Management** | The Celery worker requires root-level network privileges to execute `-O` (OS detection) and passive packet sniffing. | Principle of Least Privilege. Central APIs have no network access; sensors run with isolated, minimal privileges. | **Security Improvement:** Isolate network-sniffing tasks into highly restricted micro-containers away from the main application logic. |
| **Historical Auditing** | Dynamic real-time Posture Metrics (live dashboard calculations) and basic Golden Image baselines. | Graph-based timeline tracking (e.g., "What did this asset's attack surface look like exactly 30 days ago?"). | **Future Expansion:** Transition to a Graph Database (like Neo4j) to map relationships between Users, Devices, and Policies. |

---

## 5. Monitoring, SLA & Alerting

> [!NOTE]
> **Core Concept:** A CAASM platform is only effective if it drives remediation. Automating alerting and Service Level Agreements (SLAs) is critical.

| Capability | UMEagleEye Current Implementation | Industry Standard Production | Gap / Improvement Roadmap |
| :--- | :--- | :--- | :--- |
| **SLA Enforcement** | Automated Celery tasks tracking Critical alerts > 4 hours and escalating via Telegram Bot. | Complex matrix SLA engines (based on criticality, environment, owner) integrating with Jira/ServiceNow. | **Medium Priority:** Add bi-directional ticketing integration (e.g., auto-creating and closing Jira tickets) instead of just Telegram messaging. |
| **Alert Routing** | Single Telegram channel broadcast. | Owner-based routing (Slack/Teams/Email) based on asset ownership tags. | **Medium Priority:** Implement ownership tagging on assets so alerts go to the specific Business Owner rather than a global channel. |
| **Posture Dashboards** | Dynamic, real-time calculation of total assets, critical assets, and open critical events. | Multi-dimensional BI reporting tailored to different personas (CISO vs. Analyst). | **Future Expansion:** Add customizable dashboard widgets allowing users to build their own metrics views. |
---

## Conclusion & Next Steps for SMEs

While UMEagleEye currently lacks the deep API integrations required by massive enterprises, its architecture is **perfectly tailored for the Malaysian SME market**. SMEs typically have centralized, relatively flat networks where active Nmap/Masscan discovery provides 90% of the required visibility without the overhead of purchasing multiple API-driven security tools.

**Recommended Short-Term Improvements:**
1. Implement automated **Staleness Tracking** (retiring assets unseen for 14 days).
2. Add a basic **Data Deduplication** rule (merging records if MAC addresses match, even if IPs change).
3. Connect to at least one cloud provider API (e.g., AWS EC2 list instances) to demonstrate hybrid discovery capabilities for your final presentation.
