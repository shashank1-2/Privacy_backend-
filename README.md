# 🛡️ PrivacyProxy — Zero-Trust Privacy Backend

> Enterprise-grade PII redaction, AI-powered security auditing, quantum-inspired access control, and encrypted file sharing — all in one FastAPI backend.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?logo=fastapi&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4.6+-47A248?logo=mongodb&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![Railway](https://img.shields.io/badge/Railway-Deploy-0B0D0E?logo=railway&logoColor=white)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Environment Variables](#-environment-variables)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Testing](#-testing)

---

## 🔍 Overview

**PrivacyProxy** is a privacy-first backend platform that acts as a security layer between users and AI services. It automatically detects and redacts Personally Identifiable Information (PII) from text before forwarding it to LLMs, audits the redaction quality using a multi-agent AI crew, and provides a zero-trust encrypted file vault with quantum-inspired access verification.

### Core Workflow

```
User Text → PII Detection (Presidio NLP) → Redaction (strict/mask/synthetic)
         → AI Audit (3-Agent CrewAI) → Safety Gate (score ≥ 70)
         → LLM Proxy (Groq Llama 3.1) → Response
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Application                     │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│   Auth   │  Vault   │  Vault   │  Vault   │    Analytics    │
│  Routes  │  Files   │  Share   │ Security │     Routes      │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│                     Service Layer                            │
├────────┬────────┬────────┬────────┬────────┬────────┬───────┤
│Redact- │ Audit  │  QKD   │ Email  │  Geo   │Device  │GridFS │
│  ion   │  Log   │Service │Service │Service │Service │Service│
│Engine  │Service │(BB84)  │(SMTP)  │(MaxMind│(Hash)  │(Mongo)│
├────────┴────────┴────────┴────────┴────────┴────────┴───────┤
│              CrewAI Multi-Agent Audit System                  │
│         ┌─────────┐  ┌─────────┐  ┌──────────┐             │
│         │ Hacker  │→ │  Judge  │→ │ Reporter │             │
│         │(Pen-test│  │(Usability│  │  (CISO)  │             │
│         └─────────┘  └─────────┘  └──────────┘             │
├──────────────────────────────────────────────────────────────┤
│                 MongoDB + GridFS Storage                      │
│    users │ shared_files │ share_links │ audit_logs │ GridFS  │
└──────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🔐 PII Redaction Engine
- **Presidio NLP-powered** detection with spaCy `en_core_web_lg` model
- **8 entity types**: `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `API_KEY`, `IP_ADDRESS`, `LOCATION`
- **3 redaction modes**:
  - **Strict** — replaces PII with `<ENTITY_TYPE>` placeholders
  - **Mask** — numbered masks like `PERSON 1`, `EMAIL_ADDRESS 2`
  - **Synthetic** — replaces PII with realistic fake data (via Faker)
- Smart IP vs Phone conflict resolution (prevents `192.168.1.1` from being tagged as a phone number)
- Custom recognizers for API keys (OpenAI `sk-*`, GitHub `ghp_*`, AWS `AKIA*`)
- Luhn checksum validation for credit cards

### 🤖 AI Multi-Agent Audit (CrewAI)
- **3-agent sequential crew** powered by Groq Llama 3.1 8B:
  - **Hacker** — white-hat agent that attempts to reverse-engineer redacted values
  - **Judge** — usability analyst ensuring text remains functional after redaction
  - **Reporter** — CISO that synthesizes findings into `safety_score` + `usability_score` + `critique`
- **Safety gate**: blocks chat requests if `safety_score < 70`
- False positive detection to prevent over-blocking
- Exponential backoff retry logic for rate limit resilience

### 🔒 Zero-Trust File Vault
- **Encrypted file storage** via MongoDB GridFS
- **PII auto-scan** on upload for text-based files (`.txt`, `.csv`, `.json`, `.html`, `.md`)
- SHA-256 file integrity hashing
- Configurable max upload size (default 50 MB)

### 🔗 Secure File Sharing
- **Time-limited share links** (1–168 hours expiry)
- **View count limits** with burn-after-reading support
- **Geo-fencing** — country & city-level restrictions with alias support (e.g., `Vizag → Visakhapatnam`, `Bangalore → Bengaluru`)
- **Device locking** — first-access device binding via fingerprint hashing
- **Screenshot detection** — auto-revokes links after configurable threshold
- **Dynamic watermarking** per recipient
- **Kill switch** — revoke all active links instantly

### 🔑 BB84 Quantum Key Distribution (Simulated)
- Software simulation of the BB84 QKD protocol for share link access verification
- Random basis selection using `secrets` (CSPRNG)
- Basis reconciliation and sifting
- HKDF-SHA256 session key derivation
- One-time session tokens (replay attack prevention)
- Automatic fallback to SHA-256 if QKD session is expired

### 📧 Email System
- Branded HTML email templates (dark theme)
- **User verification**: 6-digit codes + JWT magic links
- **Share notifications**: one-click access with embedded JWT tokens
- SMTP integration optimized for Gmail App Passwords
- MIMEMultipart with plain text + HTML fallback

### 🛡️ Authentication & Authorization
- JWT (HS256) access tokens with configurable expiry
- Bcrypt password hashing (salt rounds)
- HTTP-only secure cookies
- Role-based access control (`user` / `admin`)
- Email verification (code + magic link)
- Password reset flow with time-limited tokens

### 📊 Analytics & Audit Trail
- **Dual logging**: rotating JSONL file + MongoDB
- Per-user event isolation
- Severity classification (`low`, `medium`, `high`, `info`)
- PII distribution aggregation (for radar charts)
- Hourly timeline bucketing (for trend charts)
- Risk scoring per share link (0–100 scale: SECURE → CRITICAL)
- Security event filtering (geo blocks, device mismatches, screenshots)

### ⚡ Rate Limiting
- SlowAPI integration with per-endpoint limits:
  - `/sanitize` — 100/min
  - `/audit` — 5/min
  - `/chat` — 10/min
  - `/stats` — 20/min
  - `/events`, `/pii-distribution`, `/timeline` — 60/min

---

## 🛠️ Tech Stack

| Category | Technology |
|---|---|
| **Framework** | FastAPI 0.104+ with Uvicorn ASGI |
| **Database** | MongoDB (Motor async driver + PyMongo sync) |
| **File Storage** | MongoDB GridFS |
| **PII Detection** | Microsoft Presidio (Analyzer + Anonymizer) |
| **NLP Model** | spaCy `en_core_web_lg` |
| **Fake Data** | Faker |
| **AI Agents** | CrewAI with Groq LLM (Llama 3.1 8B) |
| **LLM Gateway** | LiteLLM |
| **Auth** | python-jose (JWT) + bcrypt |
| **Email** | smtplib (SMTP/TLS) |
| **Geo-fencing** | MaxMind GeoLite2 (geoip2) |
| **Rate Limiting** | SlowAPI |
| **Containerization** | Docker |
| **Deployment** | Railway |

---

## 📁 Project Structure

```
backend-main/
├── Dockerfile                    # Docker build config (Python 3.10-slim)
├── railway.toml                  # Railway deployment config
├── requirements.txt              # Python dependencies
├── test_email_service.py         # Email service tests
├── test_geo_fencing.py           # Geo-fencing tests
├── test_smtp.py                  # SMTP connectivity tests
├── test_zero_trust.py            # Zero-trust verification tests
├── verify_all.py                 # Full system verification script
│
└── app/
    ├── __init__.py
    ├── main.py                   # FastAPI app, middleware, core endpoints
    ├── database.py               # MongoDB connection, collections, indexes
    ├── dependencies.py           # Auth dependency injection (get_current_user)
    │
    ├── models/
    │   ├── schemas.py            # Sanitize, Audit, Chat request/response models
    │   ├── auth_schemas.py       # User, Token, Password reset models
    │   └── vault_schemas.py      # File, ShareLink, Security, Risk models
    │
    ├── routes/
    │   ├── auth.py               # /auth/* — register, login, verify, reset
    │   ├── vault_files.py        # /vault/upload, /vault/files — file management
    │   ├── vault_share.py        # /vault/share, /vault/verify — share links
    │   ├── vault_security.py     # /vault/screenshot, /vault/killswitch, /vault/risk
    │   └── analytics.py          # /vault/analytics — dashboard metrics
    │
    ├── services/
    │   ├── redaction_engine.py    # Presidio-based PII detection & redaction
    │   ├── qkd_service.py        # BB84 quantum key distribution simulation
    │   ├── email_service.py      # SMTP email with branded HTML templates
    │   ├── geo_service.py        # MaxMind GeoIP2 geo-fencing
    │   ├── audit_log_service.py  # MongoDB audit log queries & aggregations
    │   ├── auth_service.py       # JWT + bcrypt utilities
    │   ├── device_service.py     # Device fingerprint hashing
    │   └── gridfs_service.py     # MongoDB GridFS file upload/download
    │
    └── crew/
        ├── audit_crew.py         # CrewAI multi-agent audit system
        └── config/
            ├── agents.yaml       # Agent definitions (hacker, judge, reporter)
            └── tasks.yaml        # Task definitions & prompts
```

---

## 🔐 Environment Variables

Create a `.env` file in the `backend-main/` directory with the following variables:

```env
# ────────────────────────────────────────────
# MongoDB
# ────────────────────────────────────────────
MONGO_URL=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority

# ────────────────────────────────────────────
# JWT Authentication
# ────────────────────────────────────────────
JWT_SECRET_KEY=your-super-secret-jwt-key-min-32-chars
JWT_EXPIRE_HOURS=24

# ────────────────────────────────────────────
# AI / LLM (Groq)
# ────────────────────────────────────────────
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ────────────────────────────────────────────
# Email (Gmail SMTP)
# ────────────────────────────────────────────
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-gmail-app-password

# ────────────────────────────────────────────
# Geo-Fencing (MaxMind)
# ────────────────────────────────────────────
MAXMIND_DB_PATH=./GeoLite2-City.mmdb

# ────────────────────────────────────────────
# Security
# ────────────────────────────────────────────
DEVICE_HASH_SALT=your-random-device-hash-salt
SCREENSHOT_REVOKE_THRESHOLD=5

# ────────────────────────────────────────────
# File Upload
# ────────────────────────────────────────────
MAX_UPLOAD_SIZE_MB=50
```

### Variable Reference

| Variable | Required | Description |
|---|---|---|
| `MONGO_URL` | ✅ | MongoDB connection string (Atlas or local) |
| `JWT_SECRET_KEY` | ✅ | Secret key for signing JWT tokens (min 32 chars recommended) |
| `JWT_EXPIRE_HOURS` | ❌ | Token expiry duration in hours (default: `24`) |
| `GROQ_API_KEY` | ✅ | Groq API key for Llama 3.1 (AI audit + chat proxy) |
| `EMAIL_USER` | ❌ | Gmail address for sending emails |
| `EMAIL_PASS` | ❌ | Gmail App Password (not your regular password) |
| `MAXMIND_DB_PATH` | ❌ | Path to GeoLite2-City.mmdb (default: `./GeoLite2-City.mmdb`) |
| `DEVICE_HASH_SALT` | ❌ | Salt for device fingerprint hashing (default: `default_salt`) |
| `SCREENSHOT_REVOKE_THRESHOLD` | ❌ | Screenshot attempts before auto-revoke (default: `5`) |
| `MAX_UPLOAD_SIZE_MB` | ❌ | Maximum file upload size in MB (default: `50`) |

> ⚠️ **Gmail App Password**: Go to [Google Account → Security → 2FA → App Passwords](https://myaccount.google.com/apppasswords) to generate one. Do **not** use your regular Gmail password.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- MongoDB (local or [MongoDB Atlas](https://www.mongodb.com/atlas))
- [Groq API Key](https://console.groq.com/)
- (Optional) [MaxMind GeoLite2 City Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/shashank1-2/Privacy_backend-.git
cd Privacy_backend-/backend-main

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download spaCy model (required for PII detection)
python -m spacy download en_core_web_lg

# 5. Create .env file (see Environment Variables section above)
cp .env.example .env    # or create manually

# 6. Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

### Docker Setup

```bash
# Build the image
docker build -t privacyproxy-backend .

# Run with environment variables
docker run -p 8000:8000 --env-file .env privacyproxy-backend
```

---

## 📡 API Reference

### Health & Status

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/` | ❌ | Root status check |
| `GET` | `/health` | ❌ | Health check with engine status and log size |

### PII Redaction & Audit

| Method | Endpoint | Auth | Rate Limit | Description |
|---|---|---|---|---|
| `POST` | `/sanitize` | ✅ | 100/min | Sanitize text (strict/mask/synthetic modes) |
| `POST` | `/audit` | ✅ | 5/min | Run multi-agent AI audit on redacted text |
| `POST` | `/chat` | ✅ | 10/min | Full pipeline: sanitize → audit → LLM → respond |

### Authentication (`/auth`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | ❌ | Create account + send verification email |
| `POST` | `/auth/login` | ❌ | Login + set httpOnly cookie |
| `POST` | `/auth/logout` | ❌ | Clear auth cookie |
| `GET` | `/auth/me` | ✅ | Get current user profile |
| `POST` | `/auth/forgot-password` | ❌ | Request password reset |
| `POST` | `/auth/reset-password` | ❌ | Reset password with token |
| `POST` | `/auth/verify-code` | ❌ | Verify email with 6-digit code |
| `POST` | `/auth/send-verification` | ❌ | Resend verification email |
| `GET` | `/auth/verify?token=...` | ❌ | Magic link email verification |

### Vault — File Management (`/vault`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/vault/upload` | ✅ | Upload file (auto PII scan for text files) |
| `GET` | `/vault/files` | ✅ | List user's files |
| `GET` | `/vault/files/{file_id}` | ✅ | Get file metadata |
| `DELETE` | `/vault/files/{file_id}` | ✅ | Soft-delete a file |

### Vault — Sharing (`/vault`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/vault/share` | ✅ | Create a share link with security config |
| `GET` | `/vault/links` | ✅ | List share links (with optional status filter) |
| `PATCH` | `/vault/links/{token}/revoke` | ✅ | Revoke a share link |
| `DELETE` | `/vault/links/{token}` | ✅ | Delete a share link |
| `POST` | `/vault/verify/{token}` | ❌ | Zero-trust verification (public — validates email + access code + geo + device) |
| `GET` | `/vault/stream/{token}` | ❌* | Stream file content (requires `view_token` query param) |
| `POST` | `/vault/verify-email-token` | ❌ | Decode JWT from notification email for auto-fill |

### Vault — Security (`/vault`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/vault/screenshot/{token}` | ❌ | Report screenshot attempt (auto-revokes at threshold) |
| `GET` | `/vault/status/{token}` | ❌ | Check link status, views, screenshot count |
| `POST` | `/vault/killswitch` | ✅ | Emergency revoke ALL active links |
| `GET` | `/vault/risk/{token}` | ✅ | Compute risk score (0–100) for a share link |
| `GET` | `/vault/security-events` | ✅ | List security events (geo blocks, screenshots, etc.) |
| `DELETE` | `/vault/security-events` | ✅ | Clear security events |

### Analytics & Dashboard

| Method | Endpoint | Auth | Rate Limit | Description |
|---|---|---|---|---|
| `GET` | `/vault/analytics` | ✅ | — | Full vault analytics (files, links, views, PII, security) |
| `GET` | `/stats` | ✅ | 20/min | Redaction/audit stats with entity breakdown |
| `GET` | `/events` | ✅ | 60/min | Recent audit & redaction events |
| `DELETE` | `/events` | ✅ | — | Clear all audit logs |
| `GET` | `/pii-distribution` | ✅ | 60/min | Aggregated PII entity counts |
| `GET` | `/timeline` | ✅ | 60/min | Hourly event timeline (last N hours) |

---

## 🚢 Deployment

### Railway (Recommended)

The project includes a `railway.toml` for one-click Railway deployment:

1. Connect your GitHub repo to [Railway](https://railway.app)
2. Add all environment variables in Railway's dashboard
3. Railway auto-detects the Dockerfile and deploys
4. Health check configured at `/health` with 300s timeout

### Docker (Manual)

```bash
docker build -t privacyproxy-backend .
docker run -d \
  -p 8000:8000 \
  -e MONGO_URL="your-mongo-url" \
  -e JWT_SECRET_KEY="your-jwt-secret" \
  -e GROQ_API_KEY="your-groq-key" \
  privacyproxy-backend
```

---

## 🧪 Testing

The project includes test files for critical subsystems:

```bash
# Test email service
python test_email_service.py

# Test geo-fencing logic
python test_geo_fencing.py

# Test SMTP connectivity
python test_smtp.py

# Test zero-trust verification flow
python test_zero_trust.py

# Run full system verification
python verify_all.py
```

---

## 📜 License

This project is proprietary. All rights reserved.

---

<p align="center">
  Built with 🛡️ by <strong>PrivacyProxy Team</strong>
</p>
