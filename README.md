# Sama AI · Public service workspace

Sama includes two separate React + TypeScript applications backed by one FastAPI service, PostgreSQL/pgvector, PaddleOCR, Ollama and Docker Compose. The officer workspace runs at port 5173; the citizen portal runs at port 5174.

## Start the app

Prerequisites: Docker Desktop with its Linux engine running, and Git. The repo includes a local `.env` on this machine, but it is ignored by Git. For another machine:

```powershell
Copy-Item .env.example .env
```

Set unique values for `POSTGRES_PASSWORD`, the matching password in `DATABASE_URL`, `JWT_SECRET` (32+ random characters), `ADMIN_EMAIL`, and `ADMIN_PASSWORD` (12+ characters). Keep `COOKIE_SECURE=false` for localhost. Use `COOKIE_SECURE=true` behind HTTPS in production.

Start services and download the local models:

```powershell
docker compose up --build -d
docker compose exec ollama ollama pull qwen3:4b
docker compose exec ollama ollama pull nomic-embed-text
```

Open <http://localhost:5173> for officers. Sign in with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`, or choose **Explore as guest**. Open <http://localhost:5174> for citizens. OTP delivery uses local mock mode by default; the six-digit code is written to the API logs. Configure an approved SMS provider before production use. Guest accounts receive separate synthetic samples and their data is isolated and purged when the 24-hour session expires.

Government staff can request access from the officer sign-in page using an address in `GOV_EMAIL_DOMAINS`. An administrator reviews requests in **Staff access requests**. Approval creates a one-time invitation link that expires after 24 hours; deliver it through an approved secure channel. Staff set a 12-character-minimum password when accepting the invitation.

Use `docker compose stop ollama` to see the model-unavailable message. Restore it with `docker compose start ollama`. Model downloads may take time and several gigabytes.

## Working features

- Argon2 password hashes, short-lived signed access tokens, rotating refresh tokens in HttpOnly cookies, login rate limiting, role checks, logout, and per-account data scoping.
- Government-domain staff access requests, admin-only review, one-time 24-hour invitations and account activation with a new password.
- Guest sandbox records, separate for every guest session, with expiration cleanup.
- Dashboard, case queue with search/filter/sort/pagination, case workspace, notes, assignment, status changes, citizens, document review, knowledge library, audit activity and officer guide.
- PDF/image upload with size and content checks, random storage names outside the web root, OCR extraction, preview, review, deletion, and indexed text.
- Ollama token streaming, case/general modes, per-case conversation history, clear/regenerate/copy, voice input/output, and citations restricted to verified document/knowledge sources. Retrieved document text is treated as untrusted data in the prompt.
- English/Kannada/Hindi interface text, persistent dark mode, keyboard focus styles, responsive layouts, loading skeletons, empty states and error states.
- Citizen service search, phone OTP and guest access, consent-based request submission, request tracking, uploads, messages, notifications, callback and office visit requests, feedback, case-scoped assistant chat and browser speech support.
- Citizen records are private to their account; officers can process citizen submissions. Citizen assistant retrieval uses verified shared knowledge and verified documents on that citizen's selected case.
- Localhost-only Docker port bindings, strict CORS, security headers, and `.env` exclusion from Git.

The starter does not submit applications to government systems. Guest samples are synthetic. Production use needs HTTPS, reviewed official sources, policy/legal review, operational backups, malware scanning, and organization-managed identity lifecycle.

## Tests and audits

With backend requirements and backend/requirements-dev.txt installed:

```powershell
python -m pytest backend/tests -q
pip-audit -r backend/requirements.txt
```

Frontends:

```powershell
cd frontend
npm ci
npm run build
npm audit
cd ..\citizen-frontend
npm ci
npm run build
npm audit
```

## Git

The repository is initialized on `main`. After creating a remote repository:

```powershell
git remote add origin https://github.com/YOUR-ORG/YOUR-REPO.git
git push -u origin main
```

`.env`, uploaded files, build output and scratch `work/` are ignored.
