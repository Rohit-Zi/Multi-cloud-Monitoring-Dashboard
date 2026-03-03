
# Multi-Cloud Monitoring Dashboard

A full-stack cloud security monitoring platform that simulates and monitors alerts across AWS, Azure, and GCP under a unified dashboard.

---

## 🚀 Features

- Cloud alert ingestion (simulated + rule-based)
- Multi-cloud ready architecture (AWS implemented, Azure & GCP structured)
- Rule Engine for alert detection
- Severity normalization
- Alert filtering (cloud, severity, status)
- Interactive alert dialogs
- Cloud-specific detail pages
- Trend analytics with charts
- Clean Git-based project structure

---

## 🏗 Architecture

### Frontend
- React
- TypeScript
- TailwindCSS
- Recharts

### Backend
- FastAPI
- SQLite
- Rule Engine Processor
- CloudTrail Simulator
- Modular service structure

---

## 📂 Project Structure

```

project-minor/
│
├── Backend/        
├── frontend/       
└── README.md

````

---

## ⚙️ How to Run

### 1️⃣ Backend

```bash
cd Backend
pip install -r requirements.txt
uvicorn app.main:app --reload
````

Runs on:

```
http://127.0.0.1:8000
```

---

### 2️⃣ Frontend

```bash
cd frontend
npm install
npm run dev
```

Runs on:

```
http://localhost:5173
```

---
OR
run:
```
npm run dev
```
in the root folder.
## 🎯 Project Goal

To design a scalable, multi-cloud security monitoring system that can:

* Detect suspicious cloud activities
* Normalize security events
* Visualize alerts in real-time dashboards
* Be extendable to production-grade cloud integrations

---

## 👨‍💻 Author
Rohit Zi
