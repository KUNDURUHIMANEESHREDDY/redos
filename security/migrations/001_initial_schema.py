"""
Initial MongoDB schema migration for RedOS Security Platform

This migration creates the initial document schemas for all collections.
Run with: alembic upgrade head
or manually: python security/migrations/001_initial_schema.py
"""

import json
from datetime import datetime

# MongoDB collection initializations
INITIAL_SCHEMA = {
    "users": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["email", "passwordHash", "role", "organizationId"],
                "properties": {
                    "email": {
                        "bsonType": "string",
                        "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                    },
                    "passwordHash": {
                        "bsonType": "string",
                        "minLength": 60,
                        "maxLength": 255,
                    },
                    "role": {
                        "bsonType": "string",
                        "enum": ["admin", "user", "viewer"],
                    },
                    "organizationId": {
                        "bsonType": "objectId",
                    },
                    "name": {
                        "bsonType": "string",
                        "maxLength": 100,
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                    "updatedAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"email": 1}, "unique": True},
            {"key": {"role": 1}},
            {"key": {"organizationId": 1}},
        ],
    },
    "organizations": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["name"],
                "properties": {
                    "name": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "description": {
                        "bsonType": "string",
                        "maxLength": 500,
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                    "updatedAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"name": 1}, "unique": True},
        ],
    },
    "projects": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["name", "organizationId"],
                "properties": {
                    "name": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "description": {
                        "bsonType": "string",
                        "maxLength": 500,
                    },
                    "organizationId": {
                        "bsonType": "objectId",
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                    "updatedAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"name": 1}, "unique": False},
            {"key": {"organizationId": 1}},
        ],
    },
    "targets": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["name", "organizationId"],
                "properties": {
                    "name": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "description": {
                        "bsonType": "string",
                        "maxLength": 500,
                    },
                    "organizationId": {
                        "bsonType": "objectId",
                    },
                    "projectId": {
                        "bsonType": "objectId",
                    },
                    "status": {
                        "bsonType": "string",
                        "enum": ["active", "paused", "archived"],
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                    "updatedAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"name": 1}, "unique": False},
            {"key": {"organizationId": 1}},
            {"key": {"status": 1}},
        ],
    },
    "attack_campaigns": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["name", "organizationId"],
                "properties": {
                    "name": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "description": {
                        "bsonType": "string",
                        "maxLength": 500,
                    },
                    "organizationId": {
                        "bsonType": "objectId",
                    },
                    "projectId": {
                        "bsonType": "objectId",
                    },
                    "status": {
                        "bsonType": "string",
                        "enum": ["planning", "running", "paused", "completed"],
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                    "updatedAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"name": 1}, "unique": False},
            {"key": {"organizationId": 1}},
            {"key": {"status": 1}},
        ],
    },
    "executions": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["campaignId", "targetId"],
                "properties": {
                    "campaignId": {
                        "bsonType": "objectId",
                    },
                    "targetId": {
                        "bsonType": "objectId",
                    },
                    "status": {
                        "bsonType": "string",
                        "enum": ["running", "completed", "failed", "cancelled"],
                    },
                    "startedAt": {
                        "bsonType": "date",
                    },
                    "completedAt": {
                        "bsonType": "date",
                    },
                    "exitCode": {
                        "bsonType": "int",
                    },
                    "output": {
                        "bsonType": "string",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"campaignId": 1}},
            {"key": {"targetId": 1}},
            {"key": {"status": 1}},
            {"key": {"startedAt": -1}},
        ],
    },
    "findings": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["executionId", "title", "severity"],
                "properties": {
                    "executionId": {
                        "bsonType": "objectId",
                    },
                    "title": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "severity": {
                        "bsonType": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    },
                    "description": {
                        "bsonType": "string",
                        "maxLength": 1000,
                    },
                    "discoveredAt": {
                        "bsonType": "date",
                    },
                    "reproducedAt": {
                        "bsonType": "date",
                    },
                    "status": {
                        "bsonType": "string",
                        "enum": ["active", "resolved", "rejected"],
                    },
                },
            }
        },
        "indexes": [
            {"key": {"executionId": 1}},
            {"key": {"severity": 1}},
            {"key": {"status": 1}},
            {"key": {"discoveredAt": -1}},
        ],
    },
    "evidence": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["findingId", "type", "content"],
                "properties": {
                    "findingId": {
                        "bsonType": "objectId",
                    },
                    "type": {
                        "bsonType": "string",
                        "enum": ["model_output", "retrieved_document", "tool_call", "execution_trace"],
                    },
                    "content": {
                        "bsonType": "string",
                    },
                    "metadata": {
                        "bsonType": "object",
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"findingId": 1}},
            {"key": {"type": 1}},
            {"key": {"createdAt": -1}},
        ],
    },
    "api_keys": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["keyHash", "organizationId", "name", "permissions"],
                "properties": {
                    "keyHash": {
                        "bsonType": "string",
                        "minLength": 60,
                    },
                    "organizationId": {
                        "bsonType": "objectId",
                    },
                    "name": {
                        "bsonType": "string",
                        "minLength": 1,
                        "maxLength": 200,
                    },
                    "permissions": {
                        "bsonType": "array",
                        "items": {
                            "bsonType": "string",
                            "enum": ["read", "write", "admin"],
                        },
                    },
                    "lastUsed": {
                        "bsonType": "date",
                    },
                    "expiresAt": {
                        "bsonType": "date",
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"keyHash": 1}, "unique": True},
            {"key": {"organizationId": 1}},
            {"key": {"expiresAt": 1}},
        ],
    },
    "audit_logs": {
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["userId", "action", "resourceType", "resourceId"],
                "properties": {
                    "userId": {
                        "bsonType": "objectId",
                    },
                    "action": {
                        "bsonType": "string",
                    },
                    "resourceType": {
                        "bsonType": "string",
                        "enum": [
                            "organization",
                            "project",
                            "target",
                            "campaign",
                            "execution",
                            "finding",
                            "evidence",
                            "api-key",
                        ],
                    },
                    "resourceId": {
                        "bsonType": "objectId",
                    },
                    "details": {
                        "bsonType": "object",
                    },
                    "ipAddress": {
                        "bsonType": "string",
                    },
                    "userAgent": {
                        "bsonType": "string",
                    },
                    "createdAt": {
                        "bsonType": "date",
                    },
                },
            }
        },
        "indexes": [
            {"key": {"userId": 1}},
            {"key": {"action": 1}},
            {"key": {"resourceType": 1}},
            {"key": {"createdAt": -1}},
        ],
    },
}


def up():
    """Apply initial schema - create collections with validators and indexes"""
    from pymongo import MongoClient
    
    client = MongoClient("mongodb://localhost:27017")
    db = client["security_analysis"]
    
    for collection_name, schema_def in INITIAL_SCHEMA.items():
        collection = db[collection_name]
        
        # Set collection validator
        if collection.count_documents({}) == 0:
            # Collection is empty, set validator
            try:
                collection.command({
                    "collMod": collection_name,
                    "validator": schema_def["validator"],
                })
            except Exception:
                pass  # Validator might already be set
            
            # Create indexes
            for idx in schema_def["indexes"]:
                try:
                    collection.create_index(idx["key"], unique=idx.get("unique", False))
                except Exception:
                    pass  # Index might already exist
    
    print("✅ Initial MongoDB schema applied successfully")


def down():
    """Revert initial schema - drop collections and validators"""
    from pymongo import MongoClient
    
    client = MongoClient("mongodb://localhost:27017")
    db = client["security_analysis"]
    
    # Drop all collections created by this migration
    collections = ["audit_logs", "api_keys", "evidence", "findings", "executions",
                   "attack_campaigns", "targets", "projects", "organizations", "users"]
    
    for collection_name in collections:
        try:
            db[collection_name].drop()
            print(f"  Dropped collection: {collection_name}")
        except Exception as e:
            print(f"  Error dropping {collection_name}: {e}")
    
    print("✅ Initial MongoDB schema reverted successfully")


if __name__ == "__main__":
    import sys
    if sys.argv[1] == "up":
        up()
    elif sys.argv["down"]:
        down()
    else:
        print("Usage: python migrations/001_initial_schema.py [up|down]")