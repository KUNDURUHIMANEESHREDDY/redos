# RedOS Identity Module

## Identity Provider Integration

```python
from redos.identity import ServiceIdentityManager, TokenManager, IdentityMigrator
import asyncio

async def main():
    org_id = "org_456"
    
    # 1. Create service identity for CI pipeline
    identity_mgr = ServiceIdentityManager(org_id=org_id)
    
    ci_identity = await identity_mgr.create_identity(
        name="ci-pipeline",
        type="ci_cd",
        scopes=[
            "findings:create",
            "findings:view",
            "campaigns:start",
            "campaigns:view",
            "evidence:view",
        ],
        expires_at="2025-01-15T00:00:00Z",
    )
    
    print(f"CI Identity created: {ci_identity.id}")
    print(f"API Key: {ci_identity.api_key}")
    print(f"Expires: {ci_identity.expires_at}")
    
    # 2. Create scoped token for dashboard access
    token_mgr = TokenManager(org_id=org_id)
    
    scoped_token = await token_mgr.create_scoped_token(
        identity_id=ci_identity.id,
        scopes=["findings:view", "campaigns:view"],
        expires_in_minutes=120,
        purpose="dashboard_access",
    )
    
    print(f"Scoped token: {scoped_token.id}")
    print(f"Expires in: {scoped_token.expires_in_minutes} minutes")
    print(f"Can view findings: {scoped_token.has_scope('findings:view')}")
    print(f"Can create campaigns: {scoped_token.has_scope('campaigns:create')}")
    
    # Use token for API call
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:8000/api/v1/findings",
            headers={"Authorization": f"Bearer {scoped_token.token}"},
        )
        print(f"API response status: {response.status_code}")
        print(f"Findings count: {len(response.json())}")
    
    # 3. Identity migration example
    # migrator = IdentityMigrator(
    #     source_idp="keycloak_source",
    #     target_idp="okta_target",
    #     org_id=org_id,
    # )
    # results = await migrator.migrate_users(
    #     user_emails=["alice@example.com", "bob@example.com"],
    # )
    # print(f"Migrated: {results['migrated']}, Skipped: {results['skipped']}")

if __name__ == "__main__":
    asyncio.run(main())
```

## OIDC Integration

```python
import requests
import json

# OIDC login flow
def oidc_login(provider_config):
    """Initiate OIDC authentication flow"""
    # Redirect to identity provider
    auth_url = f"{provider_config['issuer_url']}/protocol/openid-connect/auth"
    params = {
        "response_type": "code",
        "client_id": provider_config["client_id"],
        "redirect_uri": provider_config["redirect_uri"],
        "scope": " ".join(provider_config["scopes"]),
        "state": generate_csrf_token(),
    }
    redirect_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    return redirect_url

# Callback handler
def oidc_callback(request):
    """Handle OIDC callback and exchange code for token"""
    code = request.query.get("code")
    state = request.query.get("state")
    
    # Verify state (CSRF protection)
    if not verify_state(state, request.session.get("oauth_state")):
        raise AuthenticationError("Invalid state parameter")
    
    # Exchange code for token
    token_response = requests.post(
        provider_config["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": provider_config["client_id"],
            "client_secret": provider_config["client_secret"],
            "redirect_uri": provider_config["redirect_uri"],
        },
    )
    tokens = token_response.json()
    
    # Store tokens in session
    request.session["access_token"] = tokens["access_token"]
    request.session["refresh_token"] = tokens.get("refresh_token")
    request.session["expires_at"] = datetime.utcnow() + timedelta(seconds=tokens["expires_in"])
    
    return redirect("/dashboard")

# SAML attribute mapping
def saml_attribute_mapping():
    """Map SAML attributes to RedOS identities"""
    mapping = {
        "email": "email",
        "full_name": "full_name", 
        "organization_id": "organization_id",
        "role": "role",
    }
    return mapping

# SSO login flow
def sso_login(request):
    """SSO login using various providers"""
    provider = request.query.get("provider")
    
    if provider == "keycloak":
        return oidc_login(keycloak_config)
    elif provider == "okta":
        return saml_login_okta(request)
    elif provider == "azure_ad":
        return saml_login_azure(request)
    elif provider == "google":
        return oidc_login(google_config)
    
    raise ValueError(f"Unsupported identity provider: {provider}")
```

## Organization Identity Policies

```python
from redos.identity import IdentityPolicyManager

policy_mgr = IdentityPolicyManager(org_id="org_456")

# Get organization identity policies
policies = await policy_mgr.get_policies()
print(f"Identity policies: {json.dumps(policies, indent=2)}")

# Check if user requires MFA
requires_mfa = await policy_mgr.requires_mfa(user_role="org_admin")
print(f"Org admin requires MFA: {requires_mfa}")

# Check session timeout
session_timeout = await policy_mgr.get_session_timeout()
print(f"Session timeout: {session_timeout} minutes")

# Check MFA configuration
mfa_config = await policy_mgr.get_mfa_config()
print(f"MFA enabled: {mfa_config['enabled']}")
print(f"MFA methods: {mfa_config['methods']}")
```

## Scoped Token Operations

```python
from redos.identity import TokenManager

token_mgr = TokenManager(org_id="org_456")

# Create token with specific permissions
token = await token_mgr.create_scoped_token(
    identity_id="identity_abc123",
    scopes=["findings:view", "campaigns:view", "evidence:download"],
    expires_in_minutes=480,  # 8 hours
    purpose="full_access_dashboard",
)

# Token operations
print(f"Token ID: {token.id}")
print(f"Token: {token.token}")
print(f"Expires in: {token.expires_in_minutes} minutes")
print(f"Scopes: {token.scopes}")

# Check if token has specific scope
print(f"Has findings:view: {token.has_scope('findings:view')}")
print(f"Has campaigns:create: {token.has_scope('campaigns:create')}")

# Revoke token early if needed
await token_mgr.revoke(token.id)
print(f"Token {token.id} revoked")

# Refresh expired tokens (if refresh token available)
# new_token = await token_mgr.refresh(token.refresh_token_id)
```

## Enterprise Identity API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/identity/providers` | List identity providers |
| `POST` | `/api/v1/identity/providers` | Register identity provider |
| `GET` | `/api/v1/identity/me` | Get current user identity |
| `POST` | `/api/v1/identity/refresh` | Refresh authentication |
| `GET` | `/api/v1/identity/service-accounts` | List service identities |
| `POST` | `/api/v1/identity/service-accounts` | Create service identity |
| `POST` | `/api/v1/identity/service-accounts/{id}/rotate` | Rotate service API key |
| `POST` | `/api/v1/identity/service-accounts/{id}/revoke` | Revoke service identity |
| `GET` | `/api/v1/identity/tokens` | List active tokens |
| `POST` | `/api/v1/identity/tokens/{id}/revoke` | Revoke token |

## Example: Full Identity Flow

```python
import asyncio
from redos.identity import ServiceIdentityManager, TokenManager

async def identity_demo():
    org_id = "org_456"
    
    # Step 1: Authenticate via OIDC/SSO
    # (User logs in through identity provider)
    
    # Step 2: Create service identity for automation
    identity_mgr = ServiceIdentityManager(org_id=org_id)
    identity = await identity_mgr.create_identity(
        name="autogpt-runner",
        type="automation",
        scopes=["findings:create", "campaigns:start", "evidence:view"],
        expires_at="2025-12-31T23:59:59Z",
    )
    
    # Step 2: Create scoped token for specific operation
    token_mgr = TokenManager(org_id=org_id)
    token = await token_mgr.create_scoped_token(
        identity_id=identity.id,
        scopes=["findings:create", "campaigns:start"],
        expires_in_minutes=60,
        purpose="autogpt_execution",
    )
    
    # Step 3: Use token for API calls
    # (All API calls include: Authorization: Bearer {token})
    
    # Step 4: Monitor and rotate as needed
    # (Revoke and recreate if security concern)
    
    print("Identity flow complete")
    print(f"Identity: {identity.id}")
    print(f"Token: {token.id}")

asyncio.run(identity_demo())
```