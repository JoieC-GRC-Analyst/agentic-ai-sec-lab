# Agentic AI Security & Governance Laboratory (`agentic-ai-sec-lab`)

A local-first, reproducible security engineering and AI Governance, Risk, and Compliance (GRC) laboratory. This project demonstrates pre-execution policy enforcement, adversarial resilience testing, and automated governance evidence mapping for Large Language Models (LLMs) and AI agents.

---

## 🛡️ Core Capabilities
* **Fail-Closed Policy Gateway:** Intercepts unauthorized tool invocations and out-of-bounds endpoint requests before execution.
* **Strict Schema Validation:** Enforces data type safety and input boundaries using Pydantic.
* **Automated Telemetry Mapping:** Links security decisions directly to industry standards (**OWASP Top 10 for LLMs**, **MITRE ATLAS**, and **NIST AI RMF**).
* **Stakeholder-Ready Reporting:** Translates technical telemetry into plain-English executive assurance summaries.

---

## 📁 Repository Structure
```text
agentic-ai-sec-lab/
├── src/
│   ├── blue_team/guardrails.py    # Hardened policy enforcement gateway & schemas
│   ├── governance/                # Framework telemetry mappers (NIST, OWASP, ATLAS)
│   ├── run_pipeline.py            # End-to-end simulation orchestrator
│   └── generate_report.py         # Executive markdown report generator
├── tests/
│   └── test_guardrails.py         # Regression test suite
├── artifacts/
│   ├── demo_report.json           # Machine-readable audit evidence
│   └── executive_summary.md       # Plain-English stakeholder report
└── README.md
```

---

## 🚀 How to Set Up & Run the Lab

### 1. Clone and Prepare Environment
```bash
git clone https://github.com/JoieC-GRC-Analyst/agentic-ai-sec-lab.git
cd agentic-ai-sec-lab
python3 -m venv venv
source venv/bin/activate
pip install pydantic
```

### 2. Run the Regression Test Suite
Verify that all security guardrails, allowlists, and schema constraints pass unit testing:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
*(Expected output: )*

### 3. Execute the Security Simulation Pipeline
Run the orchestrator to test adversarial inputs, unauthorized actions, and generate raw audit telemetry:
```bash
python3 src/run_pipeline.py
```

### 4. Generate the Executive Stakeholder Report
Translate technical test results into a plain-English management report (`artifacts/executive_summary.md`):
```bash
python3 src/generate_report.py
```

---

## 📊 Stakeholder & Governance Mapping Overview
| Test ID | Scenario Description | Guardrail Decision | Governance Alignment |
| :--- | :--- | :--- | :--- |
| **TEST-001** | Authorized Database Query | 🟢 **ALLOWED** | NIST MAP 1.5 / OWASP LLM06 |
| **TEST-002** | Prohibited Shell Execution | 🔴 **BLOCKED** | NIST MEASURE 2.6 / MITRE ATLAS AML.T0051 |
| **TEST-003** | Unauthorized Tool Request | 🔴 **BLOCKED** | NIST MAP 1.5 / OWASP LLM06 (Excessive Agency) |
| **TEST-004** | Unauthorized Endpoint Access | 🔴 **BLOCKED** | NIST MAP 1.5 (Boundary Protection) |
| **TEST-005** | Malformed Schema Input | 🟠 **REJECTED** | Strict Type & Boundary Validation |

---
*Disclaimer: This lab operates entirely within a local simulation boundary for educational, control verification, and risk governance testing.*
