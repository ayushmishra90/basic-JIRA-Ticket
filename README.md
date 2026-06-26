# Ticket System (Golang)

A small backend service for a ticket system. Users can register, log in, create
tickets, view **only their own** tickets, and move a ticket through its
lifecycle. Authentication is JWT-based and every ticket is scoped to its owner.

Built with the Go standard library plus a single well-known dependency for JWTs.

---

## Submission links

> Fill these in before submitting.

- **GitHub repository:** `https://github.com/<you>/ticket-system`
- **Deployed application URL:** `https://<your-app>.onrender.com`
- **Public health check:** `https://<your-app>.onrender.com/health`

---

## Tech stack & design

- **Language:** Go 1.22
- **Router:** standard-library `net/http` (Go 1.22 method-aware `ServeMux`) — no
  third-party web framework.
- **JWT:** [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) —
  HS256, validated with explicit signing-method checking (alg-confusion safe).
- **Password hashing:** PBKDF2-HMAC-SHA256 (RFC 8018) with a per-user random
  salt, 210,000 iterations, and constant-time verification. Implemented over the
  standard library's vetted `crypto/hmac` + `crypto/sha256` primitives, which
  keeps the dependency footprint minimal. bcrypt/argon2 are equally valid
  choices; the storage format is self-describing (`pbkdf2-sha256$iter$salt$hash`)
  so the scheme can evolve without breaking existing records.
- **Storage:** in-memory, guarded by a `sync.RWMutex`. The assignment explicitly
  permits this. The store is small and isolated behind plain methods, so moving
  to SQLite/Postgres later would not touch the HTTP layer.

### Project structure

```
.
├── main.go                     # config, wiring, graceful shutdown
├── internal/
│   ├── models/                 # User, Ticket, status enum + transition rules
│   ├── auth/                    # password hashing (PBKDF2) + JWT manager
│   ├── store/                   # thread-safe in-memory persistence
│   └── api/                     # routing, auth middleware, handlers, helpers
├── Dockerfile                  # multi-stage build -> small non-root image
├── .env.example
└── README.md
```

---

## API reference

All request and response bodies are JSON. Protected endpoints require an
`Authorization: Bearer <token>` header.

| Method | Endpoint                  | Auth | Purpose                       |
| ------ | ------------------------- | :--: | ----------------------------- |
| GET    | `/health`                 |  No  | Health check                  |
| POST   | `/auth/register`          |  No  | Register a user               |
| POST   | `/auth/login`             |  No  | Log in, returns a JWT         |
| POST   | `/tickets`                | Yes  | Create a ticket               |
| GET    | `/tickets`                | Yes  | List the caller's tickets     |
| GET    | `/tickets/{id}`           | Yes  | Get one of the caller's tickets |
| PATCH  | `/tickets/{id}/status`    | Yes  | Update one ticket's status    |

### `GET /health`
`200 OK`
```json
{ "status": "ok" }
```

### `POST /auth/register`
Request:
```json
{ "email": "ayush@example.com", "password": "s3cret-pw" }
```
- `201 Created` → `{ "id": 1, "email": "ayush@example.com" }`
- `400 Bad Request` — missing email/password or malformed body
- `409 Conflict` — email already registered

### `POST /auth/login`
Request:
```json
{ "email": "ayush@example.com", "password": "s3cret-pw" }
```
- `200 OK` → `{ "token": "<jwt>" }`
- `400 Bad Request` — missing fields
- `401 Unauthorized` — wrong email or password

### `POST /tickets`
Request:
```json
{ "title": "Login is broken", "description": "Throws 500 on submit" }
```
- `201 Created` → the created ticket (see ticket shape below); new tickets start as `open`
- `400 Bad Request` — missing `title`
- `401 Unauthorized` — missing/invalid token

### `GET /tickets`
- `200 OK` → JSON array of the caller's tickets (`[]` if none)

### `GET /tickets/{id}`
- `200 OK` → the ticket
- `400 Bad Request` — non-numeric id
- `404 Not Found` — ticket does not exist **or** belongs to another user

### `PATCH /tickets/{id}/status`
Request:
```json
{ "status": "in_progress" }
```
- `200 OK` → the updated ticket
- `400 Bad Request` — status not one of `open`, `in_progress`, `closed`
- `404 Not Found` — ticket does not exist or belongs to another user
- `409 Conflict` — disallowed transition (e.g. reopening a closed ticket)

### Ticket shape
```json
{
  "id": 1,
  "title": "Login is broken",
  "description": "Throws 500 on submit",
  "status": "open",
  "user_id": 1,
  "created_at": "2026-01-01T10:00:00Z",
  "updated_at": "2026-01-01T10:00:00Z"
}
```

### Status flow

```
open  ->  in_progress  ->  closed
```

Transitions are **forward-only and sequential**:

- `open → in_progress` ✅
- `in_progress → closed` ✅
- `closed → *` ❌ (terminal; a closed ticket cannot be reopened)
- `open → closed` ❌ (cannot skip `in_progress`)
- any backward move ❌

---

## Running locally

### With Go

```bash
go run .
# service on http://localhost:8080
curl http://localhost:8080/health
```

### With Docker

```bash
docker build -t ticket-system .
docker run -p 8080:8080 ticket-system
curl http://localhost:8080/health
# {"status":"ok"}
```

### Quick end-to-end example

```bash
BASE=http://localhost:8080

# register + login
curl -s -XPOST $BASE/auth/register -d '{"email":"ayush@example.com","password":"s3cret-pw"}'
TOKEN=$(curl -s -XPOST $BASE/auth/login \
  -d '{"email":"ayush@example.com","password":"s3cret-pw"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

# create, list, fetch
curl -s -XPOST $BASE/tickets -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Login is broken","description":"500 on submit"}'
curl -s $BASE/tickets -H "Authorization: Bearer $TOKEN"
curl -s $BASE/tickets/1 -H "Authorization: Bearer $TOKEN"

# advance status: open -> in_progress -> closed
curl -s -XPATCH $BASE/tickets/1/status -H "Authorization: Bearer $TOKEN" -d '{"status":"in_progress"}'
curl -s -XPATCH $BASE/tickets/1/status -H "Authorization: Bearer $TOKEN" -d '{"status":"closed"}'
```

---

## Environment variables

| Variable     | Required | Default                         | Notes                                            |
| ------------ | :------: | ------------------------------- | ------------------------------------------------ |
| `PORT`       |    No    | `8080`                          | Listen port. Hosting platforms that inject their own `PORT` work transparently. |
| `JWT_SECRET` | In prod  | dev fallback (with a warning)   | Secret used to sign JWTs. Set a long random value in any real deployment. |

Copy `.env.example` to `.env` for local use. Generate a secret with
`openssl rand -hex 32`.

---

## Assumptions

- **In-memory storage:** all data is lost on restart (permitted by the brief).
- **Account identifier:** either `email` or `username` is accepted in the
  register/login body and treated as the same identifier; it is normalized to
  lowercase. Examples use `email`.
- **Login response field** is `token`.
- **Cross-user access returns `404`** (not `403`) so the existence of another
  user's ticket is not disclosed; the effect (no access) is the same.
- **Invalid status transitions return `409 Conflict`**; an unrecognized status
  string returns `400 Bad Request`.
- **JWTs expire after 24 hours** and are signed with HS256.
- The status flow is strictly sequential; `open → closed` is rejected because
  the required flow lists `open → in_progress → closed`.
