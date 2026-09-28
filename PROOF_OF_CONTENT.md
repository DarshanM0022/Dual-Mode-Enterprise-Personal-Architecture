# Proof of Content (POC): Real Execution & Verification Evidence
> **Aetheris — Unified Adaptive Security Platform**  
> *Continuous Telemetry • Explainable Risk • Guardrailed Autonomous Defense*

This document provides definitive, verifiable **Proof of Content (POC)** captured directly from the live running instance of Aetheris (`http://127.0.0.1:8000`) on the local Windows workstation (`DEMOICDRAGON`, user `darsh`).

No artificial or synthetic images were generated. Every visual asset below is an authentic, headless browser render of the live system executing in real time.

---

## 📸 Visual Proof of Content Index

| ID | Module / View | Image Asset | Primary Capability Demonstrated |
| :--- | :--- | :--- | :--- |
| **POC-01** | **SOC Analyst Mission Control** | `docs/screenshots/01_soc_analyst_dashboard.png` | Live SIEM WebSocket feed, KPIs, live host audit, and interactive Vis.js graph |
| **POC-02** | **Personal Security Center** | `docs/screenshots/02_personal_security_center.png` | Consumer security health score (78%), leaked credentials, and personal devices |
| **POC-03** | **CISO Executive Posture** | `docs/screenshots/03_ciso_executive_posture.png` | NIST/ISO/SOC2 compliance audit gauges, 30-day risk trajectory (Chart.js) |
| **POC-04** | **Guardrailed AI Security Copilot** | `docs/screenshots/04_ai_copilot_drawer.png` | Strict tool calling (`get_user_risk`), evidence citations, and human approval guardrails |
| **POC-05** | **Incident Triage & SOAR Playbooks** | `docs/screenshots/05_incident_triage_modal.png` | Kill-chain timeline reconstruction and executable containment playbooks |

---

## 🔬 Deep Breakdown of Each Capability

---

### Proof 1: SOC Analyst Dashboard & Attack Graph
![SOC Analyst Dashboard](docs/screenshots/01_soc_analyst_dashboard.png)

#### What is Shown:
1. **Live Header & Telemetry Status**: `TELEMETRY LIVE` green pulse indicating active WebSocket connection to `ws://127.0.0.1:8000/ws/telemetry`.
2. **Operational KPIs**:
   - `Security Health`: **65.9%** (dynamic aggregate across enterprise entities)
   - `Active Incidents`: **11**
   - `Mean Time to Detect (MTTD)`: **3.8m**
   - `Mean Time to Respond (MTTR)`: **11.4m**
   - `Events Ingested`: **53**
   - `Critical Alerts (24h)`: **37**
3. **Live Attack Simulator & Host Audit**:
   - `[💻 Audit Real Windows Host (Live Telemetry)]`: One-click button that queries the host kernel, PowerShell Defender status, and listening sockets.
   - `[Scenario 1: Credential Stuffing & Takeover]`, `[Scenario 2: Ransomware EDR Defense]`, and `[Scenario 3: Rapid Data Exfiltration]`.
4. **SIEM Telemetry Stream**: Real-time event log table showing events with severity tags (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), normalized actors, source IPs, actions, and raw source vendors (`WindowsSystemEventLog`, `OktaSystemLog`, `NetSuiteAuditTrail`).
5. **Interactive Attack & Entity Graph**: NetworkX-generated topology rendered via Vis.js showing interconnected nodes:
   - User nodes (`Elena Rostova`, `Darsh Sharma`, `Sarah Chen`, `Marcus Vance`)
   - Device nodes (`DEMOICDRAGON`, `ACME-FIN-LAT9440`, `ACME-SOC-WS01`)
   - Application nodes (`Okta Identity Cloud`, `NetSuite ERP`, `AWS GovCloud`)
   - Incident nodes (`INC-CRIT-901`) with reachability edges.

---

### Proof 2: Personal Security Center
![Personal Security Center](docs/screenshots/02_personal_security_center.png)

#### What is Shown:
1. **Consumer Health Score**: **78% Good Posture** dynamically derived from identity hygiene, password exposure, and device patch compliance.
2. **Action Items Requiring Attention**:
   - `CREDENTIAL_LEAK`: *"Master Password Exposed in Breached Combo-List"* with a 1-click **[Resolve & Secure]** workflow.
   - `PRIVACY_RISK`: *"Third-Party Quiz App Retains Full Google Drive Read Access"* detailing OAuth scopes with revocation instructions.
3. **Personal Devices Protected**:
   - `Darsh-iPhone15Pro` (iOS 17.5.1, Compliant, BitLocker/Encryption: ON)
   - `DARSH-LEGION-PRO` (Windows 11 Pro, Pending Reboot)
   - **`DEMOICDRAGON`** (Windows 11 ARM64 Build 10.0.26200, IP: 127.0.0.1) — **The real host machine captured live!**

---

### Proof 3: CISO Executive Posture & Compliance
![CISO Executive Posture](docs/screenshots/03_ciso_executive_posture.png)

#### What is Shown:
1. **Compliance Framework Readiness**:
   - **NIST CSF 2.0**: **92%** control adherence
   - **ISO/IEC 27001:2022**: **89%** control adherence
   - **SOC 2 Type II Controls**: **95%** control adherence
2. **30-Day Risk Trajectory & Alert Spikes**: Interactive Chart.js canvas graphing the organization's risk index vs. critical alert volume over time.
3. **Crown Jewels & High-Risk Identities Matrix**:
   - `Elena Rostova (VP Finance)`: Risk **78.0 / 100**, Impossible Travel NYC $\to$ Moscow.
   - `UNKNOWN-HOST-X99 (185.220.101.44)`: Risk **94.0 / 100**, Unmanaged Kali Linux host.
   - `Okta Identity Cloud`: Risk **15.0 / 100**, Tier-0 IDP with hardware MFA enforced.

---

### Proof 4: Guardrailed AI Security Copilot
![AI Copilot Drawer](docs/screenshots/04_ai_copilot_drawer.png)

#### What is Shown:
1. **Strict Guardrail Enforcement**: Top banner indicates `Strict Read/Write Separation • Human Approval Enforced`.
2. **Suggested Investigation Prompts**:
   - `💡 Why is Elena high risk?`
   - `🔍 Investigate active incident`
   - `🛡️ Isolate rogue host`
3. **Grounded Tool Invocation**:
   - Copilot executed `⚙️ get_user_risk('usr-elena-finance')`.
   - Returned risk subscore breakdown:
     - Identity: `100.0/100` (Weight 30%)
     - Device Posture: `100.0/100` (Weight 25%)
     - Behavioral Deviation: `100.0/100` (Weight 20%)
     - Threat Signals: `60.0/100` (Weight 15%)
     - Exposure: `10.0/100` (Weight 10%)
   - Surfaced primary risk contributors citing exact facts: unpatched endpoint, 4.8 GB NetSuite download spike, SMS 2FA vulnerability, and impossible travel from New York to Moscow.
   - Recommended actionable mitigation: Upgrade account to hardware FIDO2 / WebAuthn key.

---

### Proof 5: Incident Triage & SOAR Playbooks
![Incident Triage Modal](docs/screenshots/05_incident_triage_modal.png)

#### What is Shown:
1. **Incident Header**: `INC-CRIT-901` — **CRITICAL** Multi-Stage VIP Account Takeover & Rapid Exfiltration.
2. **AI Copilot Synthesis**: Grounded executive briefing explaining the initial access vector, credential theft, SMS bypass, and data export.
3. **Attack Kill-Chain Timeline**:
   - `16:04:12`: Impossible travel alert: US to Moscow login within 14m.
   - `16:05:12`: Unenrolled Linux device completed SMS MFA challenge.
   - `16:08:12`: Session accessed high-criticality NetSuite ERP customer invoices.
   - `16:10:12`: Data export triggered: 4.8 GB encrypted archive stream started.
4. **SOAR Containment Playbooks**:
   - `REVOKE_SESSION`: Invalidate all active OAuth refresh tokens and Okta sessions for Elena Rostova (`PENDING_APPROVAL`).
   - Analyst execution button: **`[Authorize & Execute]`**.
   - Lifecycle transition buttons: `[Move to Containment]`, `[Close Incident]`.

---

## 🛠️ Verification Commands

You can verify the entire test suite and live host ingestion locally:

```powershell
# 1. Run full unit and integration test suite (19/19 tests)
python test_api_endpoints.py
python test_platform.py

# 2. Audit real local host telemetry
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/host/audit" -Method Post | Format-List

# 3. Query SIEM live event database
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/siem/events?limit=5" | Select-Object -ExpandProperty events
```
