# Production secrets - managed via Docker secrets, never env vars in image
# This file documents expected secrets, not values
JWT_SECRET_FILE=/run/secrets/jwt_secret
MONGODB_URI_FILE=/run/secrets/mongodb_uri
# Resource limits enforced via compose deploy.limits
# Filesystem: read_only + tmpfs /tmp
# Capabilities: cap_drop ALL, add minimal
# Health checks: all services
