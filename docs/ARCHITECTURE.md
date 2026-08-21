# RedOS Security Platform - Architecture Documentation

## Canonical Architecture: Python/FastAPI + MongoDB

This document defines the canonical architecture contracts for Agent 1 and Agent 2.
All APIs, authentication, RBAC, and data flows must conform to these specifications.

### 1. Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| API Framework | FastAPI | 0.104+ |
| Database | MongoDB | 6.0+ |
| ODM | Motor (async driver) | 3.+ |
| Auth | JWT (JSON Web Tokens) | 9.0+ |
| Structured Logging | structlog | 23.1+ |
| Migration | Custom MongoDB JSON-schema migrations | N/A |
| Deployment | Docker + Docker Compose | 20.10+ |
| Observability | Prometheus + structlog | 0.0.1+ |

### 2. API Contracts

All endpoints follow the pattern: `GET/POST/PUT/DELETE /api/v1/{resource}`

#### Authentication Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/login` | Authenticate user and return JWT | Public |
| POST | `/api/v1/auth/register` | Register new user | Public |
| GET | `/api/v1/auth/me` | Get current user profile | Bearer JWT |

#### Organization Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/organizations` | List organizations user belongs to | Bearer JWT |
| POST | `/api/v1/organizations` | Create new organization | Bearer JWT |
| GET | `/api/v1/organizations/{id}` | Get organization details | Bearer JWT |
| PUT | `/api/v1/organizations/{id}` | Update organization | Bearer JWT + Org Owner |

#### Project Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/projects` | List projects in organization | Bearer JWT |
| POST | `/api/v1/projects` | Create project in organization | Bearer JWT |
| GET | `/api/v1/projects/{id}` | Get project details | Bearer JWT |
| PUT | `/api/v1/projects/{id}` | Update project | Bearer JWT + Org Member |

#### Target Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/targets` | List targets in organization | Bearer JWT |
| POST | `/api/v1/targets` | Create target in organization | Bearer JWT |
| GET | `/api/v1/targets/{id}` | Get target details | Bearer JWT |
| DELETE | `/api/v1/targets/{id}` | Delete target | Bearer JWT + Org Admin |

#### Attack Campaign Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/attack-campaigns` | List campaigns in organization | Bearer JWT |
| POST | `/api/v1/attack-campaigns` | Create campaign | Bearer JWT |
| GET | `/api/v1/attack-campaigns/{id}` | Get campaign details | Bearer JWT |

#### Execution Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/executions` | List executions with filtering | Bearer JWT |
| POST | `/api/v1/executions` | Start new execution | Bearer JWT |
| GET | `/api/v1/executions/{id}` | Get execution status | Bearer JWT |
| POST | `/api/v1/executions/{id}/stream` | SSE stream for execution | Bearer JWT |

#### Finding Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/findings` | List findings with filtering | Bearer JWT |
| POST | `/api/v1/findings` | Create finding | Bearer JWT |
| GET | `/api/v1/findings/{id}` | Get finding details | Bearer JWT |

#### Evidence Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/evidence` | List evidence with filtering | Bearer JWT |
| GET | `/api/v1/evidence/{id}` | Get evidence by ID | Bearer JWT |
| DELETE | `/api/v1/evidence/{id}` | Delete evidence | Bearer JWT + Admin |

#### Attack Graph Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/attack-graph` | Get attack graph for execution | Bearer JWT |

#### Remediation Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/remediation` | List remediation actions | Bearer JWT |
| POST | `/api/v1/remediation` | Generate remediation | Bearer JWT |

#### Regression Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/regression` | List regression tests | Bearer JWT |
| POST | `/api/v1/regression` | Create regression test | Bearer JWT |

### 3. Authentication & Authorization

#### JWT Token Claims
```json
{
  "sub": "user_id",
  "email": "user@example.com",
  "role": "admin|user|viewer",
  "organizationId": "org_oid",
  "iat": 1700000000,
  "exp": 1700003600
}
```

#### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| `admin` | Full access to all resources in organization |
| `user` | Create/read own resources, read organization resources |
| `viewer` | Read-only access, no creation capabilities |

#### Tenant Isolation
- All queries filter by `organization_id` from JWT
- Cross-organization access returns 403 Forbidden
- Example query pattern:
  ```python
  db.targets.find({"organization_id": user_org_id, ...})
  ```

### 4. Data Model Schemas

All schemas use MongoDB JSON Schema validation. Key collections:

#### users
- `email` (unique, indexed)
- `passwordHash` (bcrypt, min 60 chars)
- `role` (enum: admin/user/viewer)
- `organizationId` (ObjectId, foreign key)
- `createdAt`, `updatedAt` (timestamps)

#### organizations
- `name` (unique, required)
- `description`
- `createdAt`, `updatedAt`

#### projects
- `name` (required)
- `organizationId` (required, indexed)
- `description`
- `createdAt`, `updatedAt`

#### targets
- `name` (required)
- `organizationId` (required, indexed)
- `projectId` (optional, foreign key)
- `status` (enum: active/paused/archived)
- `createdAt`, `updatedAt`

#### executions
- `campaignId` (required, foreign key)
- `targetId` (required, foreign key)
- `status` (enum: pending/running/success/failure/timed_out/cancelled/indeterminate)
- `startedAt`, `completedAt` (timestamps)
- `exitCode`, `output` (JSON)

#### findings
- `executionId` (required, foreign key)
- `title` (required, max 200 chars)
- `severity` (enum: LOW/MEDIUM/HIGH/CRITICAL)
- `description`
- `discoveredAt`, `reproducedAt`
- `status` (enum: active/resolved/rejected)

#### evidence
- `findingId` (required, foreign key)
- `type` (enum: model_output/retrieved_document/tool_call/execution_trace)
- `content` (the actual evidence data)
- `metadata` (key-value pairs)
- `createdAt`

#### audit_logs
- `userId` (required)
- `action` (required: login, logout, finding_create, etc.)
- `resourceType` (required: organization/project/target/campaign/execution/finding/evidence/api-key)
- `resourceId` (required)
- `details` (JSON, optional)
- `ipAddress`, `userAgent`
- `createdAt`

### 5. Tenancy Isolation Pattern

```
User
  ↓ (authenticated with organizationId)
Organization A
  ↓ (project_id filter)
  Project A
    ↓ (target_id filter)
    Target A
      ↓ (execution_id filter)
      Execution A
        ↓ (finding_id filter)
        Finding A
          ↓ (evidence_id filter)
          Evidence A
```

**Cross-organization access is prohibited** at the database query level and middleware level. All API endpoints accept an `organization_id` parameter (extracted from JWT) and filter queries accordingly.

### 6. Execution Workflow

```
User → Create Target → Launch Attack → Live Execution → Evidence → Finding
   ↓                      ↓                ↓              ↓              ↓
Attack Graph ← Remediation ← Regression ← Updated Result
```

#### Step-by-Step Flow

1. **Create Target** - POST `/api/v1/targets` with org context
2. **Launch Attack** - POST `/api/v1/attack-campaigns` + POST `/api/v1/executions`
3. **Live Execution** - WebSocket/SSE streaming at `/api/v1/executions/{id}/stream`
4. **Evidence Collection** - Auto-collected during execution, stored at `/api/v1/evidence`
5. **Finding Generation** - POST `/api/v1/findings` with severity and title
6. **Attack Graph** - Generated from evidence path: PDF → RAG → Agent → DB → PII
7. **Remediation** - POST `/api/v1/remediation` with finding context
8. **Regression** - POST `/api/v1/regression` with test cases

### 7. Security Hardening

#### Input Validation
- All string fields have max length limits
- Enum fields validated against allowed values
- ObjectId validation before database operations
- JSON payload size limited to 10MB

#### Output Sanitization
- Model output HTML stripped (script tags, event handlers)
- Document content sanitized before display
- JSON output validated against schema

#### Rate Limiting
- 100 requests per 15 minutes per IP
- Stricter limits on write endpoints (10/15min)
- Authentication endpoints: 5/15min

#### Secrets Management
- Master key via `MASTER_KEY` environment variable
- JWT secret via `JWT_SECRET` environment variable
- Database credentials via `MONGODB_URI`
- Never committed to version control

#### Audit Logging
- Every API request logged with userId, action, resourceType, resourceId
- IP address and user agent captured
- Sensitive actions (deletion, permission changes) marked explicitly
- Logs stored in `audit_logs` collection with JSON validator

### 8. Observability

#### Metrics (Prometheus)
- `http_requests_total` - total request count
- `http_request_duration_seconds` - request latency histogram
- `active_executions` - currently running executions
- `findings_by_severity` - count by severity level
- `api_key_rotations` - how many times keys have been rotated

#### Structured Logging
All logs follow this structure:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "logger": "security.platform",
  "message": "Execution started",
  "organization_id": "org_oid",
  "execution_id": "exec_oid",
  "request_id": "req_12345",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0..."
}
```

#### Tracing
- OpenTelemetry-compatible spans
- Correlation IDs passed through all service boundaries
- Execution timeline: target → campaign → execution → findings → evidence

### 9. Deployment

#### Docker Configuration
```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY security/ ./security/

# Set environment
ENV PYTHONUNBUFFERED=1
ENV MONGODB_URI=mongodb://localhost:27017
ENV JWT_SECRET=change-me-in-production
ENV MASTER_KEY=change-me-in-production

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import pymongo; pymongo.MongoClient().admin.command('ping')"

USER appuser

CMD ["uvicorn", "security.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - mongo
      - redis
    environment:
      - MONGODB_URI=mongodb://mongo:27017/security_analysis
      - JWT_SECRET=${JWT_SECRET}
      - MASTER_KEY=${MASTER_KEY}

  mongo:
    image: mongo:6.0
    volumes:
      - mongo_data:/data/db
    ports:
      - "27017:27017"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  mongo_data:
```

#### Rolling Deployment Strategy
1. New container starts with v2
2. Health checks pass
3. Load balancer redirects new traffic to v2
4. Old v1 containers drained gracefully
5. Zero-downtime update

### 9. Migration System

#### MongoDB Schema Migrations
Since this uses MongoDB (not SQL), migrations are handled through JSON schema validators and migration scripts.

**Migration Format:**
```python
# security/migrations/002_add_finding_status.py
"""Add status field to findings collection"""

from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
db = client["security_analysis"]

def up():
    """Add status field with default value"""
    db["findings"].update_many(
        {"status": {"$exists": False}},
        {"$set": {"status": "active"}}
    )
    # Add validator for status field
    db.command({
        "collMod": "findings",
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["executionId", "title", "severity", "status"],
                "properties": {
                    "status": {
                        "bsonType": "string",
                        "enum": ["active", "resolved", "rejected"]
                    }
                }
            }
        }
    })

def down():
    """Remove status field"""
    db["findings"].update_many(
        {},
        {"$unset": {"status": ""}}
    )
    db.command({
        "collMod": "findings",
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["executionId", "title", "severity"]
            }
        }
    })
```

**Running Migrations:**
```bash
python security/migrations/002_add_finding_status.py up
```

### 10. API Error Responses

Standard error format:
```json
{
  "error": " descriptive error message ",
  "code": "ERROR_CODE",
  "path": "/api/v1/targets",
  "method": "POST",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Common error codes:
- `AUTH_FAILED` - Invalid credentials or missing token
- `AUTHORIZED` - Insufficient permissions
- `VALIDATION_FAILED` - Request body validation error
- `NOT_FOUND` - Resource doesn't exist
- `CONFLICT` - Resource already exists
- `ORG_MISMATCH` - User doesn't belong to organization
- `RATE_LIMITED` - Too many requests

### 11. Frontend Integration

The React frontend (`platform/web/`) must call all APIs at:
`http://localhost:8000/api/v1/`

Example API calls:
```javascript
// Auth
const resp = await fetch('/api/v1/auth/login', { method: 'POST', body: json })
const { token } = await resp.json()

// Organizations
const orgs = await fetch('/api/v1/organizations', { headers: { Authorization: `Bearer ${token}` } })

// Targets
const targets = await fetch('/api/v1/targets', { 
  headers: { Authorization: `Bearer ${token}` } 
})

// Executions with streaming
const evtSource = new EventSource(`/api/v1/executions/${id}/stream?token=${token}`)
evtSource.onmessage = (e) => updateExecution(e.data)
```

### 12. Threat Model

#### Attack Surface
1. API endpoints - protected by JWT + RBAC
2. MongoDB directly - accessed only through application layer
3. File uploads (evidence) - limited size, sandboxed storage
4. WebSocket connections - authenticated, origin-checked
5. Redis broker - authenticated connection required

#### Data Classification
- **Public**: Non-sensitive metadata, organization listings
- **Internal**: Target details, execution status, finding descriptions
- **Confidential**: PII in evidence, model outputs, user passwords
- **Restricted** - Master keys, JWT secrets, admin operations

#### Security Controls
- JWT expiration: 7 days max, configurable
- Password hashing: bcrypt with 12+ rounds
- Input sanitization: All string fields validated
- Output filtering: HTML/JS stripped from model outputs
- Rate limiting: Per-IP and per-organization buckets
- Audit trail: Every action logged with immutable timestamp

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-08-20 | Initial architecture documentation |