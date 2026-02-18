# ForgeAI Govern™ - Healthcare AI Governance Platform

[![View Portal](https://img.shields.io/badge/View%20Portal-ForgeAI%20Govern-blue)](https://github.com/Bjay0727-jay/AI-Governance)

A cloud-native, multi-tenant SaaS platform for managing AI governance across healthcare organizations. Built on Cloudflare's edge computing infrastructure, aligned with NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state AI legislation.

## Platform Overview

ForgeAI Govern™ provides healthcare organizations with a comprehensive platform to manage the full lifecycle of AI governance — from asset inventory and risk assessment through compliance management, continuous monitoring, and incident response.

### Core Capabilities

| Module | Description |
|--------|-------------|
| **AI Asset Registry** | Centralized catalog of all AI/ML systems with metadata, ownership, and risk classification |
| **Risk Assessment Engine** | Structured, tiered assessment workflows mapped to NIST AI RMF with 6 risk dimensions |
| **Algorithmic Impact Assessments** | Bias testing and fairness evaluation across protected demographic categories |
| **Multi-Framework Compliance** | Cross-walk controls across NIST AI RMF, FDA SaMD, ONC HTI-1, HIPAA, and state regulations |
| **Monitoring Dashboard** | Real-time performance, bias, and drift metrics with automated alerting |
| **Vendor Assessment Portal** | Standardized AI-specific due diligence with weighted risk scoring |
| **Maturity Assessment** | 7-domain governance maturity model with 5-level scoring scale |
| **Incident Management** | AI-specific incident tracking with auto-suspension for critical patient safety events |

### Regulatory Framework Coverage

- **NIST AI RMF 1.0** — Full Govern, Map, Measure, Manage function alignment
- **NIST AI 600-1** — Healthcare-specific companion guidance
- **FDA SaMD Framework** — AI/ML-based Software as a Medical Device
- **ONC HTI-1 Final Rule** — Health IT transparency requirements
- **HIPAA** — Privacy and Security Rule compliance for PHI-processing AI
- **State AI Laws** — Colorado SB 21-169, California AB-2013, Connecticut SB 1103, NYC Local Law 144

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Cloudflare CDN + WAF                  │
│              DDoS Protection · SSL Termination           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Frontend    │  │  API Worker   │  │   R2 Storage  │  │
│  │  Cloudflare   │  │  Cloudflare   │  │   Evidence    │  │
│  │    Pages      │  │   Workers     │  │   Documents   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘  │
│         │                  │                             │
│         │           ┌──────┴───────┐                    │
│         │           │  Cloudflare   │                    │
│         │           │     D1        │                    │
│         │           │  (SQLite)     │                    │
│         │           └──────────────┘                    │
│         │           ┌──────────────┐                    │
│         └──────────►│  Cloudflare   │                    │
│                     │     KV        │                    │
│                     │  (Sessions)   │                    │
│                     └──────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | SPA (HTML/CSS/JS) | Responsive governance dashboard |
| API | Cloudflare Workers | Edge-deployed REST API with JWT auth |
| Database | Cloudflare D1 (SQLite) | Multi-tenant data with row-level isolation |
| Storage | Cloudflare R2 | Evidence files and assessment artifacts |
| Cache | Cloudflare KV | Sessions, feature flags, configuration |
| Security | JWT + PBKDF2-SHA256 | Stateless auth with 100k iteration hashing |
| CDN/WAF | Cloudflare | DDoS protection, SSL, edge caching |

## Project Structure

```
AI-Governance/
├── src/
│   ├── api/
│   │   ├── worker.js              # Main Cloudflare Worker entry point
│   │   ├── router.js              # API route handler
│   │   ├── auth.js                # Authentication & authorization (JWT, PBKDF2)
│   │   ├── utils.js               # Utility functions
│   │   └── handlers/
│   │       ├── ai-assets.js       # AI asset registry CRUD
│   │       ├── risk-assessments.js # Multi-dimensional risk scoring
│   │       ├── impact-assessments.js # Algorithmic impact (bias/fairness)
│   │       ├── compliance.js       # Multi-framework compliance engine
│   │       ├── vendors.js          # Vendor due diligence & scoring
│   │       ├── monitoring.js       # Performance metrics & alerting
│   │       ├── dashboard.js        # Portfolio stats & executive reports
│   │       ├── maturity.js         # 7-domain maturity assessments
│   │       └── incidents.js        # AI incident management
│   ├── database/
│   │   ├── schema.sql             # Full database schema (12 tables)
│   │   └── seed.sql               # Compliance control catalog (25 controls)
│   ├── frontend/
│   │   ├── index.html             # SPA entry point
│   │   ├── css/
│   │   │   ├── main.css           # Core styles
│   │   │   └── dashboard.css      # Dashboard-specific styles
│   │   └── js/
│   │       ├── api.js             # API client with JWT management
│   │       ├── app.js             # App controller & navigation
│   │       └── pages.js           # Page renderers & form modals
│   ├── assessment/
│   │   ├── maturity-scoring-template.json  # 7-domain maturity model
│   │   └── risk-assessment-template.json   # 6-dimension risk template
│   └── compliance/
│       └── regulatory-crosswalk.json       # Multi-framework mapping
├── package.json
├── wrangler.toml                  # Cloudflare Worker configuration
└── .gitignore
```

## Deployment

### Prerequisites

- Cloudflare account with Workers, D1, R2, and KV enabled
- Node.js 18+ (for Wrangler CLI)

### Setup Steps

1. **Install Wrangler CLI:**
   ```bash
   npm install -g wrangler
   wrangler login
   ```

2. **Create D1 Database:**
   ```bash
   wrangler d1 create forgeai-govern-db
   ```
   Update the `database_id` in `wrangler.toml` with the returned ID.

3. **Initialize Schema:**
   ```bash
   npm run db:init
   ```

4. **Seed Compliance Controls:**
   ```bash
   npm run db:seed
   ```

5. **Configure Secrets:**
   ```bash
   wrangler secret put JWT_SECRET
   ```

6. **Deploy:**
   ```bash
   npm run deploy
   ```

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create tenant and admin user |
| POST | `/api/v1/auth/login` | Authenticate, receive JWT |
| POST | `/api/v1/auth/refresh` | Refresh expired access token |

### AI Asset Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ai-assets` | List all AI assets (filterable) |
| POST | `/api/v1/ai-assets` | Register new AI asset |
| GET | `/api/v1/ai-assets/:id` | Get asset details |
| PUT | `/api/v1/ai-assets/:id` | Update asset |
| DELETE | `/api/v1/ai-assets/:id` | Decommission asset |

### Risk & Impact Assessments
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/v1/risk-assessments` | List/create risk assessments |
| POST | `/api/v1/risk-assessments/:id/approve` | Approve/reject assessment |
| GET/POST | `/api/v1/impact-assessments` | List/create algorithmic impact assessments |

### Compliance & Governance
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/controls` | List governance control catalog |
| GET | `/api/v1/controls/:id/frameworks` | Get cross-framework mappings |
| GET/POST | `/api/v1/implementations` | List/record control implementations |

### Vendor Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/v1/vendor-assessments` | List/create vendor assessments |
| POST | `/api/v1/vendor-assessments/:id/score` | Calculate vendor risk score |

### Dashboard & Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dashboard/stats` | Portfolio governance statistics |
| GET | `/api/v1/reports/compliance` | Compliance report by framework |
| GET | `/api/v1/reports/executive` | Executive summary report |

## Security

- **Authentication:** JWT with 15-minute access tokens, 7-day refresh rotation
- **Password Hashing:** PBKDF2-SHA256 with 100,000 iterations and random salt
- **Authorization:** Role-based access control (admin, governance_lead, reviewer, viewer)
- **Data Isolation:** Tenant-scoped at database query layer
- **Encryption:** TLS 1.2+ in transit, AES-256 at rest
- **Account Protection:** Auto-lockout after 5 failed login attempts (30-minute lockout)
- **Audit Trail:** Immutable logging for all governance activities

## Healthcare Recommendations

Based on our review of the governance documents, the following strategic recommendations apply to healthcare organizations implementing this platform:

1. **Start with AI inventory** — You cannot govern what you do not know exists
2. **Prioritize patient safety scoring** — Weight clinical risk dimensions highest
3. **Implement bias monitoring early** — Demographic-disaggregated metrics from day one
4. **Map compliance once, satisfy many** — Use the multi-framework crosswalk to reduce duplication
5. **Automate drift detection** — AI performance degrades silently; monitoring must be continuous
6. **Require vendor transparency** — Contractual provisions for audit rights and bias test results
7. **Build governance as an accelerator** — Clear pathways reduce deployment friction, not increase it

## License

Proprietary — Forge Cyber Defense. All rights reserved.
