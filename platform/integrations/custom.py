# RedOS Custom APIs Integration

## Overview

Integration with custom APIs for extended functionality, third-party services, and
proprietary systems. RedOS provides a unified framework for connecting to external APIs
with consistent authentication, error handling, and audit logging.

## API Client Configuration

```yaml
# RedOS custom APIs config
custom_apis:
  - name: "salesforce"
    base_url: "https://api.salesforce.com/services/data/v57.0"
    auth:
      type: "oauth2"
      client_id: "client_id_xxx"
      client_secret: "client_secret_xxx"
      token_url: "https://login.salesforce.com/services/oauth2/token"
    endpoints:
      - name: "create_lead"
        method: "POST"
        path: "/sobjects/Lead"
        authentication: "oauth2"
      - name: "query_leads"
        method: "GET"
        path: "/sobjects/Lead/query"
        authentication: "oauth2"
      - name "update_case"
        method: "PATCH"
        path: "/sobjects/Case/{id}"
        authentication: "oauth2"

  - name: "slack"
    base_url: "https://api.slack.com/api"
    auth:
      type: "bot_token"
      bot_token: "xoxb-123456789012-three"
    endpoints:
      - name: "send_message"
        method: "POST"
        path: "/chat.postMessage"
        authentication: "bot_token"
      - name: "post_reaction"
        method: "POST"
        path: "/reactions.add"
        authentication: "bot_token"
```

### RedOS Custom API Client

```python
from redos.integrations.custom import CustomAPIClient

# Initialize with configuration
client = CustomAPIClient(
    api_config={
        "salesforce": {
            "base_url": "https://api.salesforce.com/services/data/v57.0",
            "auth_type": "oauth2",
            "client_id": os.getenv("SF_CLIENT_ID"),
            "client_secret": os.getenv("SF_CLIENT_SECRET"),
        },
        "slack": {
            "base_url": "https://api.slack.com/api",
            "auth_type": "bot_token",
            "bot_token": os.getenv("SLACK_BOT_TOKEN"),
        },
    }
)

# Call Salesforce endpoint
result = client.call(
    api_name="salesforce",
    endpoint_name="create_lead",
    data={
        "FirstName": "John",
        "LastName": "Doe",
        "Email": "john.doe@example.com",
        "Company": "Example Corp",
        "Description": "Security findings follow-up",
    }
)
print(f"Lead created: {result.get('id')}")

# Query Salesforce leads
results = client.call(
    api_name="salesforce",
    endpoint_name="query_leads",
    params={
        "query": "SELECT Id, Name, Email, Company FROM Lead WHERE Company = 'Example Corp'",
    }
)
print(f"Found {len(results['records'])} leads")

# Send Slack message
slack_result = client.call(
    api_name="slack",
    endpoint_name="send_message",
    data={
        "channel": "#security-alerts",
        "text": "🚨 Critical finding detected: Prompt injection via RAG",
        "attachments": [
            {
                "title": "Critical Finding",
                "text": "Prompt injection via retrieved context - CRITICAL severity",
                "color": "danger",
            }
        ]
    }
)
```

### Authentication Schemes Supported

| Auth Type | Flow | Example |
|-----------|------|---------|
| `oauth2` | Authorization Code Grant | Salesforce, Google, Microsoft |
| `bot_token` | Bot User Token | Slack, Discord, Telegram |
| `api_key` | Simple API Key | Stripe, Twilio, custom services |
| `http_auth` | HTTP Basic/Auth | Legacy systems, internal APIs |
| `jwt` | JWT Bearer Token | Custom microservices, enterprise |

## OAuth2 Flow

```python
from redos.integrations.custom import CustomAPIClient
import webbrowser
import flask
from flask import Flask, request, session, redirect, url_for

# OAuth2 configuration
oauth_config = {
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "authorize_url": "https://provider.com/oauth/authorize",
    "token_url": "https://provider.com/oauth/token",
    "redirect_uri": "http://localhost:8080/callback",
    "scope": "read write",
}

# Start OAuth flow
app = Flask(__name__)
app.secret_key = "super_secret"

@app.route("/login")
def login():
    """Redirect to provider for authorization"""
    params = {
        "response_type": "code",
        "client_id": oauth_config["client_id"],
        "redirect_uri": oauth_config["redirect_uri"],
        "scope": oauth_config["scope"],
        "state": generate_state(),  # CSRF protection
    }
    auth_url = f"{oauth_config['authorize_url']}?{urlencode(params)}"
    return redirect(auth_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback and exchange code for token"""
    code = request.args.get("code")
    state = request.args.get("state")
    
    # Validate state (CSRF protection)
    if not validate_state(state, session.get("oauth_state")):
        abort(400, "Invalid state parameter")
    
    # Exchange code for token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": oauth_config["client_id"],
        "client_secret": oauth_config["client_secret"],
        "redirect_uri": oauth_config["redirect_uri"],
    }
    
    token_response = requests.post(
        oauth_config["token_url"],
        data=token_data
    )
    
    tokens = token_response.json()
    
    # Store tokens in session
    session["access_token"] = tokens["access_token"]
    session["refresh_token"] = tokens.get("refresh_token")
    session["expires_at"] = datetime.utcnow() + timedelta(seconds=tokens["expires_in"])
    
    return redirect(url_for("index"))

# Make API calls with token
@app.route("/api/data")
def api_data():
    access_token = session.get("access_token")
    if not access_token or is_expired(session.get("expires_at")):
        return redirect(url_for("login"))
    
    result = client.call(
        api_name="custom",
        endpoint_name="get_data",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    return jsonify(result)
```

### Rate Limiting & Quotas

| Limit Type | Default | Configurable | Window |
|-----------|---------|------------|--------|
| Requests per minute | 60 | Org policy | 1 minute |
| Requests per hour | 1,000 | Org policy | 1 hour |
| Requests per day | 10,000 | Org policy | 24 hours |
| Concurrent connections | 10 | Org policy | - |

### Error Handling

```python
from redos.integrations.custom import CustomAPIClient
from redos.exceptions import APIError, RateLimitError, AuthenticationError

client = CustomAPIClient(...)

try:
    result = client.call(
        api_name="salesforce",
        endpoint_name="get_sensitive_data",
    )
except AuthenticationError as e:
    # Token expired or invalid
    print(f"Authentication failed: {e}")
    # Refresh token or re-authenticate
except RateLimitError as e:
    # Wait and retry
    print(f"Rate limited: {e}")
    print(f"Retry after: {e.retry_after} seconds")
except APIError as e:
    # API returned error response
    print(f"API error: {e.status_code} - {e.message}")
except Exception as e:
    # Network error or unexpected
    print(f"Unexpected error: {e}")
```

### Custom API Error Types

```python
from redos.integrations.custom import CustomAPIClient
from redos.integrations.custom import (
    APIError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ServerError,
)

client = CustomAPIClient(...)

try:
    result = client.call(...)
except NotFoundError as e:
    # Resource not found (404)
    print(f"Resource not found: {e.resource_id}")
    
except ServerError as e:
    # Server error (5xx) - retryable
    print(f"Server error: {e.status_code}")
    # Auto-retry with exponential backoff
    if e.retryable:
        retry_after = e.retry_after or 5
        time.sleep(retry_after)
        result = client.call(...)
```

### Audit Logging for Custom APIs

```json
{
  "user_id": "user_oid",
  "action": "api_call",
  "resource_type": "custom_api",
  "resource_id": "api_name/endpoint_name",
  "details": {
    "api_name": "salesforce",
    "endpoint": "create_lead",
    "http_method": "POST",
    "http_status": 201,
    "response_time_ms": 245,
    "records_affected": 1,
    "organization_id": "org_oid",
    "campaign_id": "camp_oid"
  },
  "ip_address": "192.168.1.1",
  "user_agent": "RedOS Platform",
  "created_at": "2024-01-15T10:30:00Z"
}
```

## API Client Methods

### `call(api_name, endpoint_name, **kwargs)`

Main method for calling any configured API.

```python
result = client.call(
    api_name="salesforce",
    endpoint_name="create_lead",
    data={"name": "John Doe"},
    headers={"X-Custom-Header": "value"},
    params={"account_id": "acc_123"},
    timeout=30,
    retry=True,  # Auto-retry on transient failures
    retry_count=3,  # Max retry attempts
    retry_delay=5,  # Initial delay in seconds
)
```

### `call_batch(api_name, endpoints)`

Batch call multiple endpoints.

```python
endpoints = [
    {"endpoint_name": "get_lead_1", "params": {"lead_id": "1"}},
    {"endpoint_name": "get_lead_2", "params": {"lead_id": "2"}},
    {"endpoint_name": "get_lead_3", "params": {"lead_id": "3"}},
]

results = client.call_batch(api_name="salesforce", endpoints=endpoints)
```

### `refresh_token(api_name)`

Refresh OAuth2 token when it expires.

```python
result = client.refresh_token(api_name="salesforce")
new_token = result.get("access_token")
```

### `list_endpoints(api_name)`

List all available endpoints for an API.

```python
endpoints = client.list_endpoints(api_name="salesforce")
for endpoint in endpoints['endpoints']:
    print(f"• {endpoint['name']}: {endpoint['method']} {endpoint['path']}")
```

## Pre-Configured API Integrations

| API | Purpose | Authentication | Endpoints |
|-----|---------|----------------|-----------|
| **Salesforce** | CRM integration, case management | OAuth2 | 15+ sobject endpoints |
| **Slack** | Team notifications, alerts | Bot token | 20+ chat endpoints |
| **Twilio** | SMS alerts, voice calls | API key | Messaging, voice endpoints |
| **Stripe** | Billing, incident payments | API key | 20+ payment endpoints |
| **GitHub** | PR integration, findings | OAuth2 | 100+ API endpoints |
| **GitLab** | Merge request integration | OAuth2 | 100+ API endpoints |
| **ServiceNow** | Incident management | OAuth2 | 100+ table endpoints |
| **Splunk** | Log analysis, SIEM integration | OAuth2 | Search, results endpoints |
| **PagerDuty** | Incident response | API key | Events, incidenct endpoints |
| **Zendesk** | Ticketing system | OAuth2 | Tickets, users endpoints |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CUSTOM_APIS_CONFIG` | - | Path to YAML config file |
| `API_CLIENT_TIMEOUT` | `30` | Request timeout (seconds) |
| `API_CLIENT_RETRY` | `true` | Auto-retry enabled |
| `API_CLIENT_RETRY_COUNT` | `3` | Max retry attempts |
| `API_CLIENT_RETRY_DELAY` | `5` | Initial retry delay (seconds) |
| `API_CLIENT_VERIFY_SSL` | `true` | SSL verification |
| `API_PROXY_URL` | - | HTTP proxy URL |

## Security Considerations

### API Key Management

```python
from redos.integrations.custom import CustomAPIClient
import os

# Never hardcode API keys
client = CustomAPIClient(
    api_config={
        "salesforce": {
            "client_id": os.environ["SF_CLIENT_ID"],
            "client_secret": os.environ["SF_CLIENT_SECRET"],
        }
    )
)
```

### Token Scoping

```python
# Request minimal OAuth scopes
oauth_config = {
    "scope": "read:findings write:findings",  # Minimal scope
    # Not: "full_access" which has broader permissions
}
```

### API Response Validation

```python
from redos.integrations.custom import CustomAPIClient
from pydantic import BaseModel, Field

class LeadSchema(BaseModel):
    id: str = Field(..., description="Lead ID")
    first_name: str = Field(..., description="First name")
    last_name: str = Field(..., description="Last name")
    email: str = Field(..., description="Email address")
    company: str = Field(..., description="Company")
    created_at: datetime = Field(..., description="Creation timestamp")

client = CustomAPIClient(...)
result = client.call(api_name="salesforce", endpoint_name="create_lead", data=data)

# Validate response
lead = LeadSchema.model_validate(result)
print(f"Validated lead: {lead.id}")
```

## Fallback & Circuit Breaker

```python
from redos.integrations.custom import CustomAPIClient
from redos.integrations.custom import CircuitBreaker, fallback_chain

# Configure circuit breaker
breaker = CircuitBreaker(
    failure_threshold=5,  # Open circuit after 5 failures
    recovery_timeout=60,  # Wait 60s before retrying
    success_threshold=3,  # Close circuit after 3 successes
)

# Define fallback chain
primary = CustomAPIClient(config="salesforce")
fallback = CustomAPIClient(config="custom_fallback")

chain = fallback_chain(
    primary,
    fallback,
    circuit_breaker=breaker
)

# Use chain
try:
    result = chain.call(api_name="salesforce", endpoint_name="get_data")
except Exception as e:
    # Circuit breaker open - using fallback
    result = fallback.call(api_name="custom_fallback", endpoint_name="get_data")
```