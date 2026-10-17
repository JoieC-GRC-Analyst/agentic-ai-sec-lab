# Agentic AI Security Lab

A local security laboratory designed for Red/Blue teaming, Pydantic-based guardrail enforcement, and security telemetry mapping for AI agents and Large Language Models.

## 🛡️ Framework Alignment

* **MITRE ATLAS:** Adversarial Threat Landscape for Artificial-Intelligence Systems
* **OWASP Top 10 for LLMs / Agentic AI**
* **NIST AI RMF (Risk Management Framework)**

## 📁 Project Structure

```text
agentic-ai-sec-lab/
├── src/
│   ├── red_team/       # Attack simulations & injection payloads
│   ├── blue_team/      # Pydantic validation & guardrails
│   ├── governance/     # Framework telemetry mappers
│   └── run_pipeline.py # Unified execution pipeline
├── config.yaml         # Security thresholds & configurations
├── requirements.txt    # Project dependencies
└── README.md

```

## 🚀 Quickstart & Usage

1. **Clone the repository:**
```bash
git clone https://github.com/JoieC-GRC-Analyst/agentic-ai-sec-lab.git
cd agentic-ai-sec-lab

```


2. **Install dependencies:**
```bash
pip install -r requirements.txt

```


3. **Run the security pipeline validation locally:**
```bash
python3 src/run_pipeline.py

```
