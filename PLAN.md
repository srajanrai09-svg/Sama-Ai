# Sama AI Citizen Portal Plan

## Current repository

- `frontend/` is the existing officer dashboard, served on port 5173.
- `backend/app/main.py` is the shared FastAPI service and SQLAlchemy schema.
- `docker-compose.yml` runs one API, one pgvector database and one Ollama service.
- Cases currently scope records with `owner_id`; roles include officer, admin and guest. The citizen role and OTP authentication do not exist yet.
- Officer login uses Argon2 hashes, short-lived JWT access cookies and rotating refresh cookies. Guest sessions are isolated and expire after 24 hours.
- Document upload, review, chat and account scoping already use the shared API. Case lists currently show only records owned by the current account, so citizen-created requests need a deliberate officer visibility rule.

## Architecture decisions

- Add `citizen-frontend/` as a separate React + TypeScript app on port 5174. Keep the officer app in `frontend/` on port 5173 and the API/database/Ollama services shared.
- Add a shared authentication model with roles `citizen`, `officer`, `admin` and `guest`. Preserve email/password officer login. Add phone OTP for citizens with hashed, expiring, one-use codes, rate limits, and a local-only mock delivery provider that writes codes to API logs.
- Keep citizen records private by default. Citizens can read and mutate only cases they own. Officers can process citizen submissions. Guests remain isolated in their own sandbox and never see production accounts.
- Add a `source` field to cases. Citizen submissions are created with source `Citizen portal` and appear in the officer queue. Case messages and citizen-visible status notes are separate from internal officer notes.
- Use shared, officer-managed knowledge sources for public service guidance. Keep citizen uploads private to their case. Only verified sources enter assistant retrieval.
- Store files under random server-side names outside the served frontend directories. Keep allowed MIME/signature checks, size limits and authenticated file access.
- Keep local SMS/email as mock notification hooks; do not claim a real message or call was sent. The office phone button uses a `tel:` link. Callback and appointment requests create database records for officers.
- Do not collect Aadhaar or other national identifiers. Add explicit consent before citizen personal data is submitted.
- Preserve the existing visual identity while building a mobile-first citizen interface with large targets, accessible labels, visible focus, optional large text, persistent language choice, 19 language choices, and RTL layout for Urdu, Sindhi and Kashmiri.
- Keep local demo records clearly marked as synthetic and guest-scoped. Never place synthetic records in shared citizen or officer production data.

## Implementation sequence

1. Extend database models and additive migrations for citizen profiles, OTP challenges, case source, case messages, drafts, callbacks, appointments, notifications and feedback.
2. Add OTP request/verify, citizen session, profile, services catalog, drafts, request creation/tracking, upload, messaging, callback, appointment, notification and receipt endpoints. Add explicit role and ownership checks to every route.
3. Update officer queue visibility for citizen submissions; display source, public messages, document requests, callback tasks and appointments. Keep internal notes private from citizens.
4. Add `citizen-frontend/` with public home/services/FAQ/assistant, OTP login, guest explore, application flow with draft/consent/uploads/review/submit, tracking/messages/status, profile, callback, visit booking and feedback.
5. Add the second Vite Compose service and explicit CORS origin for port 5174. Add portal links in both apps.
6. Complete the 19-language selector and RTL handling, translate the citizen UI, and send the selected language into the assistant prompt and browser speech APIs where supported.
7. Add automated backend tests for OTP expiry/rate limits, role separation, cross-citizen access, case creation/visibility, uploads, messages/status, callbacks, and appointments. Build and audit both frontends and backend dependencies.
8. Start Docker Compose, pull both Ollama models, exercise model available/unavailable behavior, and verify the complete citizen-to-officer-to-citizen request cycle. Record anything the local environment prevents verifying.

## Safety and acceptance checks

- A citizen cannot read another citizen's case, documents, messages, drafts, notifications, appointments or callbacks.
- An officer can see and process submitted citizen cases, and the citizen sees only public status updates and messages.
- Citizen guest changes stay within that guest's own sandbox and expire with the guest session.
- OTPs are never stored or logged in plaintext outside explicit local mock delivery; production delivery secrets come only from `.env`.
- UI text is rendered as text, not injected HTML. Cookies remain HttpOnly and Secure in HTTPS deployments, SameSite Lax, and CORS is restricted to the two local frontends.
- No app button is presented as successful unless its API action has completed. External SMS/phone calls are identified as mock or device-dialer actions.
