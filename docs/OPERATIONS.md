# RedOS Security Platform - Operations Documentation

## Deployment

### Production Docker Deployment

```bash
# 1. Pull latest image
docker pull redos/security-platform:latest

# 2. Start with docker-compose
docker-compose -f docker-compose.prod.yml up -d

# 3. Verify health
docker ps
# Should show: api, mongo, redis all running

# 4. Check logs
docker logs redos-api-1
# Should show no errors on startup
```

### Environment Configuration

Create `.env` file (never commit to version control):

```env
# Database
MONGODB_URI=mongodb://mongo:27017/security_analysis

# Authentication
JWT_SECRET=your-256-bit-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080  # 7 days

# Master key for encrypted secrets
MASTER_KEY=your-32-byte-master-key-here-minimum-32

# Server
HOST=0.0.0.0
PORT=8000

# CORS
CORS_ORIGINS=https://your-frontend-domain.com,http://localhost:5173

# Rate limiting
RATE_LIMIT_DEFAULT=100  # requests per 15 minutes
RATE_LIMIT_WRITE=10     # requests per 15 minutes for write endpoints

# Security
MASTER_KEY_ROTATION_DAYS=90
SECRET_KEY_ROTATION_DAYS=30
```

### Service Dependencies

```yaml
# docker-compose.yml shows the service graph:
#                          +-----------------+
#                          |   React Frontend|
+--------------------+                  +-----------------+
|                      |                  |                 |
|  +----------------+  |                  |  +------------+  |
|  |  API Gateway  |<-------------->|  |  Browser   |  |
|  +----------------+                  +------------+  |
|          |                               ^           |
|          |                               |           |
|  +----------------+   +----------+  |  +--------+  |
|  |   MongoDB     |   |  Redis   |  |  | Worker |  |
|  +----------------+   +----------+  |  +--------+  |
|          |                               |           |
|          +-----------+-----------+---+-----------+
|                      |
|  +-----------------+
|  |  Monitoring   |
|  +-----------------+
|      +- Prometheus
|      +- Grafana
|      +- Loki (logs)
```

### Database Management

#### Backup

```bash
# Daily backup using mongodump
docker exec redos-mongo-1 mongodump \
  --uri="mongodb://localhost:27017/security_analysis" \
  --out=/backups/$(date +%Y-%m-%d)

# Or using Docker volume
docker volume inspect mongo_data
# Backup the named volume
docker run --rm -v mongo_data:/backup \
  -v /local/backups:/backup \
  alpine tar czf /backup/mongo_$(date +%Y%m%d).tar.gz /data/db
```

#### Restore

```bash
# Restore from mongodump
docker exec -i redos-mongo-1 mongorestore \
  --uri="mongodb://localhost:27017/security_analysis" \
  /backups/2024-01-15/

# Or from compressed dump
gunzip -c mongo_20240115.tar.gz | docker exec -i redos-mongo-1 mongorestore
```

#### Migration

```bash
# Apply new migration script
python security/migrations/003_add_new_field.py up

# Verify schema
python -c "
from pymongo import MongoClient
client = MongoClient('mongodb://localhost:27017')
db = client['security_analysis']
# Check collection validator
result = db.command('listCollections', filter={'name': 'findings'})
print(result)
"
```

### Redis Management

#### Backup

```bash
# Redis RDB snapshot (automatic with save configuration)
docker exec redos-redis-1 redis-cli BGSAVE

# Manual snapshot
docker exec redos-redis-1 redis-cli SAVE

# Copy the RDB file
docker cp redos-redis-1:/dump/dump.rdb /local/backups/redis_$(date +%Y%m%d).rdb
```

#### Restore

```bash
# Stop Redis temporarily
docker stop redos-redis-1

# Replace data file
docker cp /local/backups/redis_20240115.rdb redos-redis-1:/dump/dump.rdb

# Restart Redis
docker start redos-redis-1

# Verify data
docker exec redos-redis-1 redis-cli DBSIZE
```

#### Cluster Operations

```bash
# Redis restart without data loss
docker restart redos-redis-1

# Check Redis health
docker exec redos-redis-1 redis-cli PING

# Monitor Redis metrics
docker exec redos-redis-1 redis-cli INFO memory
docker exec redos-redis-1 redis-cli CLIENT LIST
```

### API Restart & Rolling Update

#### Single Service Restart

```bash
# Restart only the API container
docker restart redos-api-1

# Wait for health check
sleep 5
docker inspect -f '{{.Health.Status}}' redos-api-1
```

#### Rolling Deployment (Zero Downtime)

```bash
# 1. Pull new image
docker pull redos/security-platform:new-version

# 2. Start new container with v2
docker run -d \
  --name redos-api-2 \
  --env-file .env \
  redos/security-platform:new-version

# 3. Verify new version is healthy
sleep 10
docker inspect -f '{{.Health.Status}}' redos-api-2

# 3. Shift traffic (using load balancer or docker network)
# ... configure reverse proxy to point to new container

# 4. Stop old container
docker stop redos-api-1
docker rm redos-api-1

# 5. Rename new container
docker rename redos-api-2 redos-api-1
```

### Worker Scaling

#### Horizontal Scaling

```bash
# Check current worker count
docker service ls  # if using swarm
# Or with docker-compose
docker ps | grep redos-worker

# Scale workers up
docker-compose up -d --scale redos-worker=5

# Scale workers down
docker-compose up -d --scale redos-worker=2

# Verify all workers are running
docker ps | grep redos-worker
```

#### Worker Crash Recovery

```bash
# If a worker crashes, it should automatically restart
# Celery + Supervisor handles this

# Check worker status
docker exec redos-worker-1 celery -A security.workers.celery_app status

# Restart a specific worker
docker restart redos-worker-1

# Check if jobs were recovered
docker exec redos-worker-1 celery -A security.workers.celery_app inspect active
```

### Health Checks

#### API Health Endpoint

```
GET /api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "redis": "connected",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Docker Health Check

```yaml
# In docker-compose.yml
api:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
    interval: 30s
    timeout: 5s
    start_period: 10s
    retries: 3
```

#### MongoDB Health

```bash
# Verify MongoDB is responding
mongosh --eval "db.adminCommand('ping')"

# Check replica set status
mongosh --eval "rs.status()"
```

#### Redis Health

```bash
redis-cli PING
# Should return: PONG

redis-cli INFO server | grep redis_version
# Should show version number
```

### Monitoring & Alerting

#### Prometheus Metrics Endpoint

```
GET /metrics
```

Key metrics to monitor:
- `http_requests_total` - total HTTP request count
- `http_request_duration_seconds` - request latency (histogram)
- `active_executions` - currently running executions gauge
- `findings_by_severity` - findings count by severity
- `api_auth_failures` - authentication failure count
- `api_rate_limit_exceeded` - rate limit violation count

#### Grafana Dashboard Panels

1. **Request Rate**
   - Title: "RedOS API Request Rate"
   - Query: `rate(http_requests_total[5m])`
   - Threshold: Alert on sudden spikes

2. **Execution Duration**
   - Title: "Execution Processing Time"
   - Query: `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`
   - Threshold: Alert if > 5s average

3. **Active Executions**
   - Title: "Concurrent Executions"
   - Query: `avg(active_executions)`
   - Threshold: Alert if > 10� (configurable)

4. **Authentication Failures**
   - Title: "Auth Failures"
   - Query: `rate(api_auth_failures[5m])`
   - Threshold: Alert on brute force attempts

5. **Error Rate**
   - Title: "API Error Rate"
   - Query: `rate(http_requests_total{status=~"5.."}[5m])`
   - Threshold: Alert if > 1% of total requests

#### Alert Rules

```yaml
# alerting.rules.yml
groups:
- name: redos-alerts
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[1m]) > 0.05
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High API error rate detected"
      description: "5xx errors are > 5% of total requests for 2 minutes"

  - alert: ExecutionFailures
    expr: sum(rate(executions_failed_total[5m])) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Many execution failures"
      description: "More than 10 executions failed in 5 minutes"

  - alert: AuthBruteForce
    expr: rate(api_auth_failures[1m]) > 5
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Possible brute force attack"
      description: "More than 5 auth failures in 1 minute"
```

### Backup & Restore Procedures

#### Daily Backup Schedule

```cron
# MongoDB backup - every day at 2 AM
0 2 * * * /usr/local/bin/mongo-backup.sh

# Redis backup - every hour
0 * * * * /usr/local/bin/redis-backup.sh
```

#### Backup Script: mongo-backup.sh

```bash
#!/bin/bash
set -e

BACKUP_DIR="/backups/mongo"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Run mongodump
mongodump \
  --uri="mongodb://localhost:27017/security_analysis" \
  --out="${BACKUP_DIR}/dump_${DATE}"

# Clean old backups
find "${BACKUP_DIR}" -name "dump_*" -type d -mtime +${RETENTION_DAYS} -delete

# Verify backup
if [ -d "${BACKUP_DIR}/dump_${DATE}" ]; then
  echo "✅ MongoDB backup completed: ${DATE}"
else
  echo "❌ MongoDB backup failed"
  exit 1
fi
```

#### Backup Script: redis-backup.sh

```bash
#!/bin/bash
set -e

BACKUP_DIR="/backups/redis"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=7

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Create Redis RDB snapshot
docker exec redis redis-cli BGSAVE

# Wait for snapshot and copy
sleep 2
docker cp redis:/dump/dump.rdb "${BACKUP_DIR}/dump_${DATE}.rdb"

# Clean old backups
find "${BACKUP_DIR}" -name "dump_*.rdb" -mtime +${RETENTION_DAYS} -delete

echo "✅ Redis backup completed: ${DATE}"
```

#### Restore Procedure

```bash
# 1. Stop the application
docker stop redos-api-1

# 2. Restore MongoDB
docker cp /backups/mongo/dump_2024-01-15/ redos-mongo-1:/dump/
docker exec redos-mongo-1 mongorestore /dump/2024-01-15/

# 3. Restore Redis
docker cp /backups/redis/dump_2024-01-15.rdb redos-redis-1:/dump/dump.rdb
docker restart redos-redis-1

# 4. Start the application
docker start redos-api-1

# 5. Verify data integrity
docker exec redos-mongo-1 mongosh --eval "
  db = db.getSiblingDB('security_analysis');
  print('Users:', db.users.countDocuments({}));
  print('Organizations:', db.organizations.countDocuments({}));
  print('Findings:', db.findings.countDocuments({}));
"
```

### Troubleshooting

#### Common Issues

1. **API won't start**
   - Check `.env` file exists and has required variables
   - Verify MongoDB is running: `docker stats mongo`
   - Check JWT_SECRET and MASTER_KEY are set
   - Logs: `docker logs redos-api-1`

2. **Authentication fails**
   - Ensure JWT_SECRET matches between services
   - Check token is sent in `Authorization: Bearer <token>` header
   - Verify token hasn't expired (7 days default)
   - Validate organization_id exists in JWT payload

3. **Database connection errors**
   - Verify MONGODB_URI is correct
   - Check MongoDB container is healthy: `docker ps`
   - Network connectivity: `docker network inspect redos_default`
   - Connection pool exhausted: increase `MAX_POOL_SIZE` in code

4. **Worker jobs not processing**
   - Check Redis is running and reachable
   - Verify Celery broker URL in `.env`
   - Check worker: `docker logs redos-worker-1`
   - Look for: connection refused, queue name mismatches

5. **Frontend can't connect to API**
   - Verify CORS_ORIGINS includes frontend domain
   - Check API is running on port 8000
   - Verify no firewall blocking port
   - Check browser console for CORS errors

6. **Evidence uploads failing**
   - Check `MAX_FILE_SIZE` environment variable
   - Verify `STORAGE_PROVIDER` configuration
   - Ensure `MINIO_ENDPOINT` or `S3_BUCKET` is set
   - Check logs for storage-related errors

#### Emergency Recovery

```bash
# Full stack restart
docker-compose down
docker volume rm redos_mongo_data
docker volume rm redos_redis_data
docker-compose up -d

# Wait for services to initialize
sleep 30

# Verify all services
docker ps
curl http://localhost:8000/api/v1/health
```

### Required Deliverables Checklist

- [ ] **ARCHITECTURE.md** - Created and updated
- [ ] **DEPLOYMENT.md** - Created (this document)
- [ ] **THREAT_MODEL.md** - To be created
- [ ] **SECURITY_MODEL.md** - To be created
- [ ] **OPERATIONS.md** - Created (this document)
- [ ] **e2e/tests/** - End-to-end test suite
- [ ] **tenancy/tests/** - Multi-tenant isolation tests
- [ ] **api/tests/** - API contract tests
- [ ] **workers/tests/** - Worker/queue tests
- [ ] **security/tests/** - Security hardening tests
- [ ] **deployment/tests/** - Deployment procedure tests

### Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-08-20 | Initial operations documentation |