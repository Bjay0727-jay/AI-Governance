# ForgeAI Govern™ - Penetration Testing & Security Assessment Guide

## Pre-Production Security Checklist

This document outlines the required third-party penetration test scope and
remediation criteria before accepting PHI-handling tenants.

### Scope

The penetration test MUST cover all of the following:

#### 1. Authentication & Session Management
- [ ] JWT token security (httpOnly cookies, SameSite=Strict, Secure flag)
- [ ] TOTP MFA enforcement for admin/governance_lead roles
- [ ] Account lockout after 5 failed attempts
- [ ] Password policy enforcement (minimum 12 characters)
- [ ] Token refresh rotation and revocation via KV
- [ ] Session fixation and session hijacking vectors

#### 2. Authorization & Access Control
- [ ] Tenant isolation — verify no cross-tenant data access
- [ ] RBAC enforcement on all endpoints (admin, governance_lead, reviewer, viewer)
- [ ] IDOR testing on all resource endpoints (/ai-assets/:id, /users/:id, etc.)
- [ ] Privilege escalation from viewer → admin
- [ ] HIPAA BAA enforcement (PHI access blocked without signed BAA)

#### 3. Input Validation & Injection
- [ ] SQL injection on all D1 query parameters (parameterized queries verified)
- [ ] XSS via stored and reflected vectors (sanitizeInput on user-facing fields)
- [ ] CSRF protection on all POST/PUT/PATCH/DELETE endpoints
- [ ] JSON body size limits and unknown field rejection
- [ ] File upload security (evidence upload endpoint)

#### 4. API Security
- [ ] Rate limiting effectiveness (per-tenant and per-IP)
- [ ] CORS configuration (origin whitelist only)
- [ ] Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- [ ] Error handling (no stack traces or internal details in production)
- [ ] API versioning and deprecation

#### 5. Data Protection
- [ ] Encryption in transit (TLS 1.2+ via Cloudflare)
- [ ] PHI data classification in audit logs
- [ ] Audit log integrity (SHA-256 hash chaining)
- [ ] Backup encryption and access controls (R2)
- [ ] Data retention compliance (6-year HIPAA minimum)

#### 6. Infrastructure
- [ ] Cloudflare Workers security configuration
- [ ] D1 database access controls
- [ ] R2 bucket permissions
- [ ] KV namespace isolation
- [ ] Secret management (wrangler secrets, not env vars)

### Severity Classification

| Severity | SLA | Criteria |
|----------|-----|----------|
| Critical | Block deployment | RCE, auth bypass, PHI exposure, SQL injection |
| High     | Fix within 7 days | Privilege escalation, IDOR, XSS, CSRF bypass |
| Medium   | Fix within 30 days | Information disclosure, missing headers, verbose errors |
| Low      | Fix within 90 days | Best practice deviations, minor misconfigurations |

### Remediation Requirements

- All **critical** and **high** findings must be remediated before production
- Re-test must confirm remediation effectiveness
- Findings and remediation evidence must be documented in the audit trail
- Annual re-testing is required for HIPAA compliance

### Recommended Testing Firms

Select a firm with healthcare/HIPAA experience and CREST or OSCP certification.
The test should follow OWASP Testing Guide v4 methodology.

### Post-Test Actions

1. Import findings into ForgeAI Govern incident tracker
2. Create remediation plans with assigned owners and deadlines
3. Track remediation in compliance control implementations
4. Store pentest report as evidence (POST /api/v1/evidence)
5. Schedule annual re-test
