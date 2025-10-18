#  Hands-On Real-Time Threat Management with MITRE ATLAS

This project demonstrates **AI threat detection and mapping** using the **MITRE ATLAS** framework — simulating attacks, detecting adversarial activity, and visualizing it through OpenSearch Dashboards.

---

## Setup Overview

Before running the demo, ensure the following components are set up:

### Core Tools
- **Docker** – for running OpenSearch and OpenSearch Dashboards  
- **Python 3.9+** – for the detection and simulation scripts  
- **LangChain** – to simulate AI-based interactions and attacks  
- **Presidio (Microsoft)** – for PII detection and anonymization in logs  
- **OpenSearch** – to store detection data  
- **OpenSearch Dashboards** – to visualize real-time detections

---

## MITRE ATLAS Resources

- **MITRE ATLAS Framework** → [https://atlas.mitre.org](https://atlas.mitre.org)  
  *Knowledge base of adversarial tactics and techniques targeting AI systems.*

- **MITRE ATT&CK / ATLAS Navigator** → [https://github.com/mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator)  
  *Web-based visualization tool for exploring tactics and techniques.*

---

## Quick Reference Summary

| Component | Purpose |
|------------|----------|
| **MITRE ATLAS** | Framework for mapping AI adversarial behavior |
| **LangChain** | Simulate prompt injections and attack scenarios |
| **Threat Detector** | Map logs to MITRE ATLAS techniques |
| **Presidio** | Redact sensitive data before storing logs |
| **OpenSearch + Dashboards** | Store and visualize real-time detections |

---

## Authors
**Smita Jha** & **Shashwath Aiyappa**  
*OWASP AppSec Days Bangalore — 2025 Presentation*
