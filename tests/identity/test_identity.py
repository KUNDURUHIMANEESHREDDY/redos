# Tests for Identity Functionality

"""Test RedOS enterprise identity integrations."""

import asyncio
from redos.identity import ServiceIdentityManager, TokenManager


async def test_service_identities():
    """Test service identity creation and token scoping."""
    
    org_id = "org_456"
    
    # 1. Create service identity
    identity_mgr = ServiceIdentityManager(org_id=org_id)
    
    identity = await identity_mgr.create_identity(
        name="ci-pipeline",
        type="ci_cd",
        scopes=["findings:create", "findings:view", "campaigns:start"],
        expires_at="2025-12-31T23:59:59Z",
    )
    
    print(f"✅ Service identity created: {identity.id}")
    print(f"   API Key: {identity.api_key[:20]}...")
    print(f"   Expires: {identity.expires_at}")
    
    # 2. Create scoped token
    token_mgr = TokenManager(org_id=org_id)
    
    token = await token_mgr.create_scoped_token(
        identity_id=identity.id,
        scopes=["findings:view", "campaigns:view"],
        expires_in_minutes=120,
        purpose="dashboard_access",
    )
    
    print(f"✅ Scoped token created: {token.id}")
    print(f"   Expires in: {token.expires_in_minutes} minutes")
    print(f"   Scopes: {token.scopes}")
    
    # 3. Verify token has correct scopes
    assert token.has_scope("findings:view"), "Missing findings:view scope"
    assert not token.has_scope("campaigns:create"), "Should not have create scope"
    print("✅ Token scope verification passed")
    
    # 4. Test token revocation
    await token_mgr.revoke(token.id)
    print("✅ Token revoked successfully")


async def test_identity_policies():
    """Test organization identity policies."""
    
    from redos.identity import IdentityPolicyManager
    
    org_id = "org_456"
    policy_mgr = IdentityPolicyManager(org_id=org_id)
    
    # 1. Get identity policies
    policies = await policy_mgr.get_policies()
    print(f"✅ Retrieved {len(policies.get('policies', []))} policies")
    
    # 2. Check MFA requirement for org admin
    requires_mfa = await policy_mgr.requires_mfa(user_role="org_admin")
    print(f"✅ Org admin MFA required: {requires_mfa}")
    
    # 3. Check session timeout
    session_timeout = await policy_mgr.get_session_timeout()
    print(f"✅ Session timeout: {session_timeout} minutes")
    
    # 4. Check MFA configuration
    mfa_config = await policy_mgr.get_mfa_config()
    print(f"✅ MFA enabled: {mfa_config['enabled']}")
    print(f"✅ MFA methods: {mfa_config['methods']}")


async def main():
    await test_service_identities()
    print()
    await test_identity_policies()


if __name__ == "__main__":
    asyncio.run(main())