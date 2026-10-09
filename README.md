# VulnPilot AI 🛡️✈️
### AI-Powered Vulnerability Analysis and Remediation Assistant

**VulnPilot AI** is a full-stack, enterprise-grade Application Security Testing (SAST) and AI-driven Remediation Assistant. It automatically scans source code snippets or project repositories for OWASP Top 10 security vulnerabilities, enriches findings via Vector RAG knowledge retrieval, provides AI security explanations, and generates side-by-side secure code diffs with live rescan verification.

---

## 🌟 Core Features

1. **Multi-Language SAST Scanning**:
   - Supports Python, JavaScript/TypeScript, PHP, Java, Go, Dockerfiles, and Config files.
   - Integrates Semgrep CLI and Trivy CLI if available on system, plus a **Builtin Multi-language AST Engine** that works out-of-the-box everywhere.
2. **Vulnerability Severity Classification**:
   - Categorizes security findings into **Critical**, **High**, **Medium**, and **Low** severities.
   - Computes dynamic **Security Health Index (0-100)** score.
3. **RAG Vector Knowledge Search**:
   - Contextual retrieval matching findings to **OWASP Top 10 (2021/2025)** categories and **CWE IDs** using local TF-IDF vector similarity.
4. **LangGraph Workflow Pipeline**:
   - Multi-stage agentic workflow: `[Scan Source Code]` -> `[RAG OWASP Enrichment]` -> `[AI Remediation]` -> `[Rescan Verification]` -> `[Metrics Indexing]`.
5. **LLM Integration & Offline Fallback Engine**:
   - Seamlessly uses **Gemini 1.5 Flash** or **GPT-4o-mini** when API keys are provided.
   - **Guaranteed Local Offline Operation**: Works locally without any API keys using built-in rule-based OWASP knowledge and AST refactoring templates.
6. **Side-by-Side Secure Code Diff**:
   - Interactive Before vs. After code comparison diff viewer.
7. **Rescan Verification**:
   - Re-analyzes updated secure code snippets to verify whether the vulnerability pattern has been resolved.
8. **Exportable Security Reports**:
   - Instant downloadable reports in **PDF**, **Markdown (.md)**, **HTML**, and **JSON** formats.
9. **Cybersecurity Dashboard UI**:
   - Responsive dark navy UI built with React, Vite, Tailwind CSS, Lucide icons, and interactive metrics.

---

## 🏗️ Tech Stack

- **Frontend**: React 18, Vite, Tailwind CSS
- **Backend**: Python 3.11+, FastAPI, Uvicorn, SQLAlchemy, SQLite
- **Security Scanners**: Semgrep, Trivy, VulnPilot AST SAST Engine
- **Agentic AI & RAG**: LangChain, LangGraph, Scikit-learn Vector Retrieval
- **LLM**: Gemini AI / OpenAI (with local rule fallback)
- **Deployment**: Docker, Docker Compose

---

## 🚀 Quickstart Guide

### 1. Backend Setup

```bash
cd backend
python -m venv venv

# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Backend API will run at `http://localhost:8000`. API Docs available at `http://localhost:8000/docs`.

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Frontend Web Dashboard will run at `http://localhost:5173`.

---

## 🐳 Docker Deployment

To build and launch the entire stack using Docker Compose:

```bash
docker-compose up --build
```
- Web Application: `http://localhost`
- Backend API: `http://localhost:8000`

---

## 🔒 Security & Safe Execution Safeguards

- Uploaded files are stored in sandboxed directories.
- VulnPilot AI **never automatically executes uploaded code**.
- AI fixes are previewed as code diffs requiring user verification.

---

## 📄 License
MIT License - Built for Application Security Engineers & Developers.
