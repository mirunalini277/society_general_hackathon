# 🛡️ SupplyShield
### AI-Powered Software Supply Chain Risk Analyzer

SupplyShield is an enterprise-grade Software Supply Chain Risk Analyzer developed for the Société Générale Hackathon. It analyzes Software Bill of Materials (SBOM) files to identify vulnerabilities, license compliance issues, maintenance risks, dependency relationships, and overall software supply chain exposure.

---

## 📌 Problem Statement

Modern enterprise applications rely heavily on open-source software. A single vulnerable or outdated dependency can compromise an entire application. Organizations require an automated solution to:

- Analyze Software Bill of Materials (SBOM)
- Detect known vulnerabilities
- Identify license compliance violations
- Detect outdated and unmaintained packages
- Calculate application risk scores
- Visualize dependency relationships
- Generate AI-powered security recommendations

SupplyShield provides all these capabilities through an interactive enterprise dashboard.

---

# ✨ Features

## 📂 SBOM Analysis
- Upload CycloneDX/SPDX SBOM files
- Parse and normalize dependency data
- Validate uploaded files

---

## 🔍 Vulnerability Detection
- Detect vulnerable packages using the vulnerability database
- CVE severity classification
- Patch availability tracking
- Search and filter vulnerabilities

---

## ⚖️ License Compliance
- Detect incompatible licenses
- Identify GPL/AGPL exposure
- Unknown license detection
- Enterprise compliance recommendations

---

## 🔧 Maintenance Analysis
- Detect outdated packages
- Identify unsupported dependencies
- Maintenance lifecycle analysis
- Upgrade recommendations

---

## 📈 Risk Scoring Engine

Each application receives a weighted enterprise risk score based on:

| Factor | Weight |
|---------|---------|
| Vulnerabilities | **45%** |
| License Compliance | **25%** |
| Maintenance Risk | **20%** |
| Dependency Depth | **10%** |

Applications are automatically categorized into Low, Medium, High, or Critical risk levels.

---

## 🌐 Interactive Dependency Graph

- Direct dependency visualization
- Transitive dependency exploration
- Vulnerable dependency highlighting
- Interactive search
- Hover information
- Dependency relationship analysis

---

## 🤖 AI Executive Summary

Powered by **Google Gemini API**, SupplyShield generates:

- Executive security summaries
- Risk explanations
- Recommended remediation actions
- Security insights

---

## 📄 Report Generation

Generate enterprise reports in:

- PDF
- CSV

---

# 🏗️ Project Architecture

```
SBOM
   │
   ▼
Parser
   │
   ▼
Dependency Graph Builder
   │
   ├────────► Vulnerability Checker
   │
   ├────────► License Checker
   │
   ├────────► Maintenance Checker
   │
   ▼
Risk Engine
   │
   ▼
Gemini AI Explainer
   │
   ▼
PDF / CSV Reports
```

---

# 📁 Project Structure

```
source_code/
│
├── app.py
│
├── assets/
│   └── css/
│
├── dashboard/
│   ├── application.py
│   ├── dependency_graph.py
│   ├── vulnerabilities.py
│   ├── licenses.py
│   └── maintenance.py
│
├── modules/
│   ├── parser.py
│   ├── validator.py
│   ├── graph_builder.py
│   ├── vulnerability_checker.py
│   ├── license_checker.py
│   ├── maintenance_checker.py
│   ├── risk_engine.py
│   ├── ai_explainer.py
│   └── report_generator.py
│
├── data/
├── reports/
├── backend_test.py
├── testing_api.py
└── requirements.txt
```

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/<your-repository>.git
```

Move into the project

```bash
cd source_code
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file

```text
GOOGLE_API_KEY=YOUR_GEMINI_API_KEY
```

Run the application

```bash
streamlit run app.py
```

---

# 🧪 Backend Testing

Run backend validation

```bash
python backend_test.py
```

Test Gemini API integration

```bash
python testing_api.py
```

---

# 📊 Technologies Used

### Frontend
- Streamlit
- HTML
- CSS

### Backend
- Python
- Pandas
- NetworkX
- PyVis
- Plotly
- ReportLab

### AI
- Google Gemini API

### Reports
- PDF
- CSV

---

# 📷 Dashboard Modules

- Home Dashboard
- Application Investigation
- Vulnerability Analysis
- License Compliance
- Maintenance Analysis
- Dependency Graph
- AI Executive Summary
- Report Generation

---

# 📈 Performance

- Enterprise Applications Analyzed: **10**
- Dependencies Processed: **500**
- Vulnerability Findings: **304**
- License Analysis: **500**
- Maintenance Analysis: **500**
- Interactive Dependency Graph
- AI Executive Summaries
- PDF & CSV Export

---

# 🎯 Future Enhancements

- Real-time CVE integration (NVD API)
- SBOM comparison
- Multi-project portfolio analysis
- CI/CD pipeline integration
- Dependency drift detection
- CVSS trend analytics
- Automated remediation suggestions

---

# 👩‍💻 Team

Developed for the **Société Générale Hackathon**.

Project Name:
**SupplyShield – AI-Powered Software Supply Chain Risk Analyzer**

---

## 📄 License

This project was developed solely for educational and hackathon purposes.