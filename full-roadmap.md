# CloudGuard — Full Roadmap (Post-Core-AWS-Integration)

Builds on top of the working AWS CloudTrail pipeline already shipped (connector, rule engine, dedup, polling, sync endpoint, corrected timestamps).

**Budget rule for everything below:** every phase must stay $0 unless explicitly marked ⚠️. Use AWS student credits only for the *monitored* demo resources (Phase B), never for hosting the dashboard stack itself.

---

## ⚠️ Corrections & Scope Flags (read first)
- **Kubernetes is not required.** Docker Compose covers this project's real needs. Included below only as an optional stretch item.
- **GuardDuty is not free after a 30-day trial** — contradicts your $0 goal. Excluded from core scope; only revisit as a deliberately time-boxed trial, disabled promptly after.
- **Full multi-tenant self-serve onboarding for arbitrary users is too large for Oct 15 alongside everything else.** Scoped down to: build the real cross-account mechanism, prove it with one additional test AWS account — not a polished public sign-up flow.
- **Don't run the whole stack (backend+frontend+DB+Prometheus+Grafana+n8n) on a single free-tier micro EC2 instance** — RAM-constrained. Host the dashboard stack separately from the AWS resources it's monitoring.
- **Multi-tenant + Kubernetes are stretch goals, not committed scope.** Everything else is realistic before Oct 15.

---

## Phase A — Noise & Resource Foundation
*(carries over from current session, do this first)*
- [ ] Add `is_system_noise` flag to `Log` model + migration
  - Tag by exact event source (`resource-explorer-2.amazonaws.com`) and exact event name list (`GetAccountColor`, `GetCostAndUsage`, etc.)
  - **Save everything, hide by default** — don't discard data, just don't surface it
- [ ] Frontend: Activity Logs defaults to hiding tagged noise, add a "Show system events" toggle
- [ ] Real AWS resource inventory
  - New connector functions: `describe_instances` (EC2), `list_buckets` (S3), `list_users` (IAM)
  - Store full metadata per resource (not just a name string)
  - Refresh on sync/poll, same cadence as CloudTrail events
- [ ] Resource detail view — click a resource → modal/page with full stored metadata
- [ ] Fix console-login region gap — poll `us-east-2` / `eu-north-1` / `ap-southeast-2` in addition to `us-east-1` for `ConsoleLogin` events specifically
- [ ] Expand rule mappings: `CreateBucket`, `PutBucketPolicy` (parse for `"Principal": "*"` before alerting), `RunInstances` (already mapped)

---

## Phase B — Demo Cloud Footprint (real resources to monitor)
- [ ] Launch EC2 instance
  - `t2.micro` or `t3.micro` only — confirm your account is still within the 12-month free tier window first
  - Deploy a tiny web app on it (nginx default page or a one-file Flask "hello world" is enough — gives the instance a real purpose)
  - **Stop or terminate it when not actively demoing** — free tier covers 750 hrs/month, not unlimited
- [ ] Create S3 bucket, upload one small demo file (few KB — cost is negligible regardless)
- [ ] Confirm both show up correctly in the new Resource inventory (Phase A)
- [ ] Confirm state changes on them (SG edits on the instance, a bucket policy change) correctly generate Logs/Alerts
- [ ] **Set or verify an AWS Budget alarm** on this account as a safety net (you may already have one from earlier work — confirm it covers this usage too)

---

## Phase C — Observability (Prometheus + Grafana)
*(monitoring your own tool's health — a meta-layer, genuinely valuable for a portfolio)*
- [ ] Instrument FastAPI backend with a `/metrics` endpoint (`prometheus-fastapi-instrumentator`, free)
  - Expose: alerts created by severity, sync success/failure count, poll cycle duration
- [ ] Add Prometheus as a Docker Compose service, scraping `/metrics`
- [ ] Add Grafana as a Docker Compose service
  - Build one dashboard: alerts over time, severity breakdown, sync health
- [ ] **Optional/stretch:** pull real CloudWatch metrics (e.g. EC2 CPU) into Prometheus via an exporter, visualize resource health in Grafana too — adds real complexity, do only if time allows

---

## Phase D — Automation & Notifications (n8n)
*(directly solves "notify me on high/critical only, not noise")*
- [ ] Self-host n8n via Docker Compose (free — do not use n8n cloud, that's paid)
- [ ] Backend posts a webhook to n8n **only** when an Alert with `severity in [high, critical]` is created
  - This alone satisfies "don't repeat noise" — noise never becomes an Alert in the first place, by design already in place
- [ ] n8n workflow: receive webhook → route to Discord webhook (free) or Telegram bot (free) or email (SMTP, free)

---

## Phase E — Dashboard Login System
*(must land before Docker/deployment — same rule as before)*
- [ ] Expand `User` model (email, hashed password, timestamps) — draft already prepared from earlier session
- [ ] Migration for the updated `users` table
- [ ] `POST /auth/register`, `POST /auth/login` (bcrypt + JWT — both already in `requirements.txt`)
- [ ] Reusable "get current user" dependency
- [ ] Protect all existing endpoints (`/alerts`, `/logs`, `/aws/sync`, etc.) behind a valid JWT
- [ ] Frontend: login page, token storage, protected routes, redirect if unauthenticated
- [ ] Replace hardcoded `SECRET_KEY` fallback in `config.py` with a real random secret

---

## Phase F — Multi-Tenant AWS Connection (reduced/demo scope)
*(prove the mechanism, don't build a public product)*
- [ ] Add `tenant_id`/`user_id` column to `Alert`, `Log`, `Resource` tables
- [ ] Build the "Connect AWS Account" flow — see separate walkthrough below for the exact mechanism
- [ ] Backend: store each tenant's IAM Role ARN + generated External ID
- [ ] Scheduler loops per connected tenant instead of one global poll, using STS `AssumeRole` temporary credentials (not static keys) per tenant
- [ ] Test with **one additional AWS account** (a second personal/free account, or ask a friend) — this is the proof, not a public launch

---

## Phase G — Containerization & Deployment
- [ ] Dockerfile: backend
- [ ] Dockerfile: frontend
- [ ] `docker-compose.yml` wiring: backend, frontend, database (consider Postgres over SQLite here), Prometheus, Grafana, n8n
- [ ] **Confirm auth (Phase E) is fully enforced before this step — hard rule, not optional**
- [ ] **Optional/stretch:** Kubernetes manifests, deploy locally via `minikube` just to demonstrate familiarity — not required for the project to function, purely a resume-value add-on if time remains
- [ ] Deploy the dashboard stack itself to a free host (Render/Railway free tier, Oracle Cloud Free Tier, or a *separate* dedicated free-tier EC2 instance) — kept separate from the AWS resources being monitored (Phase B)

---

## Phase H — GitHub & Final Polish
- [ ] Re-check `.gitignore` — new services mean new `.env`/secret files (Postgres credentials, n8n, Grafana admin password)
- [ ] Push full stack
- [ ] Update README — architecture diagram now includes Prometheus/Grafana/n8n, note multi-tenant scope explicitly (same "defensible tradeoff, named" approach as before)
- [ ] Teammate mirrors the AWS pattern for Azure

---

## Separate walkthrough: How a user connects their own AWS account

This is the standard pattern real SaaS security tools use (Wiz, Datadog, Prisma Cloud) — **cross-account IAM Role assumption with an External ID.** The user never gives you their AWS keys.

**What the user (customer) does:**
1. Logs into your dashboard (Phase E auth)
2. Clicks **"Connect AWS Account"**
3. Dashboard shows them a unique **External ID** (a random string generated just for their account) and your dashboard's own AWS Account ID
4. User creates an **IAM Role in their own AWS account** (via a CloudFormation template you provide, or manual console steps) that:
   - Trusts your dashboard's AWS account specifically (by account ID)
   - Requires that External ID as a condition (this is what stops anyone else from impersonating them — the "confused deputy" problem)
   - Has a read-only policy attached (same `ReadOnlyAccess`, or a tighter custom one)
5. User copies the new **Role ARN** and pastes it back into your dashboard
6. Done — the user never typed a password or access key into your app at all

**What happens on your backend after that:**
1. Backend stores the tenant's Role ARN + External ID
2. When it's time to sync that tenant's data, backend calls AWS STS `AssumeRole` using *its own* base credentials, passing the tenant's Role ARN + External ID
3. AWS returns **temporary credentials** (valid ~1 hour) scoped only to what that tenant's role allows
4. Backend uses those temporary credentials to run the exact same `process_aws_event` pipeline you already built — nothing about the core pipeline changes
5. Every `Log`/`Alert` row gets saved with that tenant's `tenant_id`, so their dashboard view only ever shows their own data
6. Temporary credentials expire automatically — backend re-assumes the role on the next sync cycle, no long-lived secrets stored anywhere

**Why this is safe:** you never hold anyone's real AWS credentials, permissions are exactly as narrow as the role the customer defines, and the External ID prevents cross-tenant impersonation even if someone knew your account ID.
