# socratic-mandate-llm.md
socratic llm implementation

# Socratic Mandate LLM Shell

A production-ready, five-pillar AI safety guardrail framework for LLM applications.

## Overview

The Socratic Mandate LLM Shell implements five pillars of AI safety:

| Pillar | Name | Purpose |
|--------|------|---------|
| I–II | Cognitive Integrity & Human Safety | Detects emotional dependency, manipulation attempts, and crisis indicators |
| III | Tiered Consent Gateway | Escalates consent requirements based on topic sensitivity |
| IV | Zero-Trust Data Exclusivity | PII redaction, prompt injection detection, immutable audit logs |
| V | Mandatory Organizational Accountability | Automated escalation to legal/security/ethics teams |

## Quick Start

### Local Development (Docker)

```bash
# Clone and start
git clone <repo>
cd socratic-llm
docker-compose up

# Test the API
curl -X POST http://localhost:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello, how are you?"}'
```

### Local Development (Python)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Run the server
AUTH_ENABLED=false python socratic_app.py

# Run tests
pytest -v tests/
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ENABLED` | `true` | Enable/disable authentication |
| `JWT_SECRET` | - | Secret key for JWT tokens (required in production) |
| `LLM_PROVIDER` | `stub` | LLM provider: `stub`, `openai`, `anthropic`, `ollama` |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model name |
| `ANTHROPIC_API_KEY` | - | Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | Anthropic model name |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name |
| `STORAGE_BACKEND` | `memory` | Storage: `memory` or `postgres` |
| `POSTGRES_DSN` | - | PostgreSQL connection string |
| `RATE_LIMIT_RPM` | `60` | Rate limit (requests per minute) |
| `REQUEST_TIMEOUT` | `30` | HTTP request timeout (seconds) |
| `MODEL_TIMEOUT` | `25` | LLM inference timeout (seconds) |
| `LOG_LEVEL` | `INFO` | Logging level |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |

## API Reference

### Chat

```http
POST /v1/chat
```

Full five-pillar guarded LLM interaction.

**Request:**
```json
{
  "text": "Your message here",
  "user_id": "optional-user-id",
  "session_id": "optional-session-id",
  "client_metadata": {}
}
```

**Response:**
```json
{
  "content": "LLM response",
  "metadata": {
    "intake_id": "uuid",
    "consent_level": "DEFAULT",
    "policies_applied": [],
    "model_id": "openai:gpt-4o",
    "latency_ms": 234.5
  }
}
```

### Consent Management

```http
POST /v1/consent
GET /v1/consent/{user_id}
DELETE /v1/consent/{user_id}
```

Manage user consent levels: `DEFAULT`, `SENSITIVE`, `RESEARCH`, `FORENSIC`.

### Audit Logs

```http
GET /v1/audit/tail?limit=10&offset=0
POST /v1/audit/search
GET /v1/audit/intake/{intake_id}
```

Query the immutable, hash-chained audit log.

### Health Checks

```http
GET /health    # Detailed health status
GET /ready     # Kubernetes readiness probe
```

## Authentication

### API Key Authentication

```bash
curl -X POST http://localhost:8000/v1/chat \
  -H "X-API-Key: sk-socratic-your-key-here" \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello"}'
```

### JWT Authentication

```bash
curl -X POST http://localhost:8000/v1/chat \
  -H "Authorization: Bearer eyJhbG..." \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello"}'
```

### Roles

| Role | Permissions |
|------|-------------|
| `user` | Chat, manage own consent |
| `operator` | User + audit log access |
| `admin` | Operator + API key management, consent for all users |

## LLM Providers

### OpenAI

```bash
LLM_PROVIDER=openai \
OPENAI_API_KEY=sk-your-key \
OPENAI_MODEL=gpt-4o \
python socratic_app.py
```

### Anthropic

```bash
LLM_PROVIDER=anthropic \
ANTHROPIC_API_KEY=sk-ant-your-key \
ANTHROPIC_MODEL=claude-sonnet-4-20250514 \
python socratic_app.py
```

### Ollama (Local)

```bash
# Start Ollama
ollama serve
ollama pull llama3.2

# Run with Ollama
LLM_PROVIDER=ollama \
OLLAMA_MODEL=llama3.2 \
python socratic_app.py
```

### Docker with Ollama

```bash
docker-compose --profile ollama up
```

## Deployment

### Docker Compose (Production)

```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/

# Check status
kubectl -n socratic get pods

# View logs
kubectl -n socratic logs -l app.kubernetes.io/name=socratic-llm -f
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Application                      │
├─────────────────────────────────────────────────────────────┤
│  Auth Middleware → Rate Limit → Timeout → Audit Logging     │
├─────────────────────────────────────────────────────────────┤
│                   SocraticLLMSystem                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Consent   │  │ Zero-Trust  │  │    Cognitive        │  │
│  │   Gateway   │→ │   Filter    │→ │  Integrity Guard    │  │
│  │  (Pillar 3) │  │ (Pillar 4)  │  │   (Pillars 1-2)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         ↓                ↓                    ↓              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    LLM Provider                          ││
│  │    OpenAI │ Anthropic │ Ollama │ vLLM │ llama.cpp       ││
│  └─────────────────────────────────────────────────────────┘│
│         ↓                ↓                    ↓              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Policy    │  │  Immutable  │  │    Escalation       │  │
│  │   Engine    │  │ Audit Logger│  │      Engine         │  │
│  │             │  │ (Pillar 4)  │  │    (Pillar 5)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         ↓                 ↓                    ↓
    ┌─────────┐      ┌──────────┐       ┌────────────┐
    │Response │      │PostgreSQL│       │ Slack/PD/  │
    │         │      │  (WORM)  │       │  Webhooks  │
    └─────────┘      └──────────┘       └────────────┘
```

## Safety Features

### PII Redaction

Automatically redacts:
- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers
- IP addresses

### Crisis Detection

Detects and responds to:
- Suicidal ideation
- Self-harm mentions
- Emotional dependency patterns

### Prompt Injection Detection

Flags attempts to:
- Override system instructions
- Extract system prompts
- Manipulate AI behavior

### Audit Chain Integrity

- Hash-chained append-only logs
- WORM (Write-Once-Read-Many) storage
- Tamper-evident record keeping
